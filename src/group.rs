//! Группа воркеров с автоматической ротацией кредов.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::sync::mpsc;

use crate::config::TurnParams;
use crate::creds;
use crate::dispatcher::Dispatcher;
use crate::session;
use crate::stats::Stats;

pub async fn worker_group(
    group_id: usize,
    hash_index: usize,
    tp: TurnParams,
    peer: std::net::SocketAddr,
    dispatcher: Arc<Dispatcher>,
    local_port: String,
    use_tcp: bool,
    get_config: bool,
    config_tx: Option<mpsc::Sender<String>>,
    worker_ids: Vec<usize>,
    initial_delay: Duration,
    cycle_duration: Duration,
    global_shutdown: Arc<AtomicBool>,
    global_pause: Arc<AtomicBool>,
    stats: Arc<Stats>,
    app_id: String,
    app_secret: String,
    device_id: String,
    password: String,
) {
    // Фазовый сдвиг
    if !initial_delay.is_zero() {
        log::info!(
            "[ГРУППА #{}] Фазовый сдвиг: {:?}",
            group_id,
            initial_delay
        );
        tokio::select! {
            _ = tokio::time::sleep(initial_delay) => {}
            _ = wait_shutdown(&global_shutdown) => { return; }
        }
    }

    let mut cycle_number = 0u64;
    let mut config_sent = !get_config;
    let mut prev_batch: Option<(Arc<AtomicBool>, Vec<tokio::task::JoinHandle<()>>)> = None;

    loop {
        if global_shutdown.load(Ordering::Relaxed) {
            // Убиваем предыдущий батч если есть
            if let Some((bs, handles)) = prev_batch.take() {
                bs.store(true, Ordering::Relaxed);
                for h in handles { let _ = tokio::time::timeout(Duration::from_secs(3), h).await; }
            }
            return;
        }

        // Doze-mode пауза: убиваем воркеров и ждём RESUME
        if global_pause.load(Ordering::Relaxed) {
            if let Some((bs, handles)) = prev_batch.take() {
                bs.store(true, Ordering::Relaxed);
                for h in handles { let _ = tokio::time::timeout(Duration::from_secs(3), h).await; }
            }
            log::info!("[ГРУППА #{}] Пауза (Doze)", group_id);
            loop {
                if global_shutdown.load(Ordering::Relaxed) { return; }
                if !global_pause.load(Ordering::Relaxed) {
                    log::info!("[ГРУППА #{}] Возобновление — новые креды", group_id);
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }

        // Получаем креды ДО убийства старого батча (бесшовная ротация)
        let hash = tp.hashes[hash_index % tp.hashes.len()].clone();

        log::info!(
            "[ГРУППА #{}] Цикл {}: запрос кредов (хеш: {}...)",
            group_id,
            cycle_number,
            &hash[..std::cmp::min(8, hash.len())]
        );

        let creds_result = creds::get_creds_with_fallback(
            &tp,
            &hash,
            &global_shutdown,
            &stats,
            &app_id,
            &app_secret,
        )
        .await;

        let creds = match creds_result {
            Ok(c) => c,
            Err(e) => {
                if global_shutdown.load(Ordering::Relaxed) {
                    return;
                }
                log::error!("[ГРУППА #{}] Ошибка кредов: {}", group_id, e);
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                    _ = wait_shutdown(&global_shutdown) => { return; }
                }
                continue;
            }
        };

        log::info!(
            "[ГРУППА #{}] Креды OK, TURN: {}, {} воркеров",
            group_id,
            creds.turn_url,
            worker_ids.len()
        );

        // ТЕПЕРЬ убиваем старый батч (креды уже готовы — минимальный простой)
        if let Some((bs, handles)) = prev_batch.take() {
            bs.store(true, Ordering::Relaxed);
            for h in handles {
                let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
            }
        }

        // Создаём новый batch
        let batch_shutdown = Arc::new(AtomicBool::new(false));
        let config_needed = Arc::new(AtomicBool::new(!config_sent));

        let mut handles = Vec::new();

        for (i, &wid) in worker_ids.iter().enumerate() {
            let tp_c = tp.clone();
            let creds_c = creds.clone();
            let disp_c = dispatcher.clone();
            let lp = local_port.clone();
            let batch_sd = batch_shutdown.clone();
            let global_sd = global_shutdown.clone();
            let st = stats.clone();
            let dev = device_id.clone();
            let pwd = password.clone();
            let cn = config_needed.clone();

            let ctx = if !config_sent {
                config_tx.clone()
            } else {
                None
            };

            // Stagger: 500мс между воркерами
            let worker_delay = Duration::from_millis((i as u64) * 500);

            let handle = tokio::spawn(async move {
                if !worker_delay.is_zero() {
                    tokio::select! {
                        _ = tokio::time::sleep(worker_delay) => {}
                        _ = wait_shutdown_combined(&batch_sd, &global_sd) => { return; }
                    }
                }

                let should_get_config = cn
                    .compare_exchange(true, false, Ordering::SeqCst, Ordering::Relaxed)
                    .is_ok();

                // Retry loop: воркер переподключается при ошибке вместо тихой смерти
                let mut attempt = 0u32;
                loop {
                    if batch_sd.load(Ordering::Relaxed) || global_sd.load(Ordering::Relaxed) {
                        return;
                    }

                    let combined_shutdown = Arc::new(AtomicBool::new(false));

                    let cs = combined_shutdown.clone();
                    let bs = batch_sd.clone();
                    let gs = global_sd.clone();
                    let shutdown_watcher = tokio::spawn(async move {
                        loop {
                            if bs.load(Ordering::Relaxed) || gs.load(Ordering::Relaxed) {
                                cs.store(true, Ordering::Relaxed);
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    });

                    // Конфиг запрашиваем только при первой попытке
                    let get_conf = should_get_config && attempt == 0;

                    let result = session::run_session(
                        &tp_c,
                        peer,
                        &disp_c,
                        &lp,
                        use_tcp,
                        get_conf,
                        &ctx,
                        wid,
                        &creds_c,
                        &dev,
                        &pwd,
                        &combined_shutdown,
                        &st,
                    )
                    .await;

                    shutdown_watcher.abort();

                    match result {
                        Ok(()) => {
                            // Штатное завершение (таймаут чтения) — ретрай
                        }
                        Err(e) => {
                            if batch_sd.load(Ordering::Relaxed) || global_sd.load(Ordering::Relaxed) {
                                return;
                            }
                            // Ошибка квоты или кредов — не ретраим
                            if e.contains("TURN квота") || e.contains("Креды мертвы") || e.contains("FATAL_AUTH") {
                                log::error!("[ВОРКЕР #{}] Фатальная ошибка: {}", wid, e);
                                return;
                            }
                            attempt += 1;
                            log::warn!("[ВОРКЕР #{}] Ошибка (попытка {}): {}", wid, attempt, e);
                        }
                    }

                    // Пауза перед ретраем с джиттером (от 5 до 15 сек), чтобы размазать переподключения
                    if batch_sd.load(Ordering::Relaxed) || global_sd.load(Ordering::Relaxed) {
                        return;
                    }
                    let r_delay = rand::Rng::gen_range(&mut rand::thread_rng(), 5..16);
                    let retry_delay = Duration::from_secs(r_delay);
                    tokio::select! {
                        _ = tokio::time::sleep(retry_delay) => {}
                        _ = wait_shutdown_combined(&batch_sd, &global_sd) => { return; }
                    }
                }
            });

            handles.push(handle);
        }

        if !config_sent && config_needed.load(Ordering::Relaxed) == false {
            config_sent = true;
        }

        // Сохраняем батч для бесшовной ротации
        prev_batch = Some((batch_shutdown.clone(), handles));

        // Ждём TTL
        tokio::select! {
            _ = tokio::time::sleep(cycle_duration) => {
                log::info!("[ГРУППА #{}] TTL {:?} истёк, ротация", group_id, cycle_duration);
            }
            _ = wait_shutdown(&global_shutdown) => {
                if let Some((bs, handles)) = prev_batch.take() {
                    bs.store(true, Ordering::Relaxed);
                    for h in handles {
                        let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
                    }
                }
                return;
            }
        }

        cycle_number += 1;

        if !config_sent {
            if config_needed.load(Ordering::Relaxed) == false {
                config_sent = true;
            }
        }
    }
}

async fn wait_shutdown(shutdown: &Arc<AtomicBool>) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_shutdown_combined(a: &Arc<AtomicBool>, b: &Arc<AtomicBool>) {
    loop {
        if a.load(Ordering::Relaxed) || b.load(Ordering::Relaxed) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}