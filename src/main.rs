mod config;
mod creds;
mod dispatcher;
mod group;
mod protocol;
mod session;
mod split_tunnel;
mod stats;
mod stun;
mod timing;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Result};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use config::CliArgs;
use dispatcher::Dispatcher;
use group::worker_group;
use split_tunnel::modify_config_for_split_tunnel;
use stats::Stats;
use timing::{compute_group_timing, validate_schedule};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let cli = CliArgs::parse();

    if cli.peer_addr.is_empty() || cli.vk_hashes.is_empty() {
        bail!("Нужны --peer и --vk");
    }

    let hash_count = cli.vk_hashes.split(',').filter(|s| !s.trim().is_empty()).count().max(1);
    let workers_per_group: usize = 8;
    let num_groups = (cli.total_workers / workers_per_group).max(1);
    // Каждая группа привязывается к хешу через g % hash_count

    if !validate_schedule(num_groups) {
        bail!("Расписание групп содержит конфликты!");
    }

    let peer: SocketAddr = cli.peer_addr.parse()?;

    let tp = config::TurnParams {
        host: cli.turn_host.clone(),
        port: cli.turn_port.clone(),
        hashes: cli
            .vk_hashes
            .split(',')
            .filter_map(|h| {
                let h = h.trim();
                let h = h.split(|c: char| c == '/' || c == '?' || c == '#')
                    .next()
                    .unwrap_or(h);
                if h.is_empty() {
                    None
                } else {
                    Some(h.to_string())
                }
            })
            .collect(),
        secondary_hash: cli.secondary_hash.clone(),
        sni: cli.sni.clone(),
    };

    if tp.hashes.is_empty() {
        bail!("Нет валидных хешей VK");
    }

    let local_conn = UdpSocket::bind(&cli.listen).await?;
    let local_addr = local_conn.local_addr()?;
    let local_port = local_addr.port().to_string();

    let global_shutdown = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Stats::new());

    // Логирование конфигурации
    log::info!("═══════════════════════════════════════");
    log::info!("VK App: {}", cli.vk_app_id);
    log::info!(
        "Воркеров: {} (групп: {}, по {})",
        num_groups * workers_per_group,
        num_groups,
        workers_per_group
    );
    log::info!("Расписание ротаций:");
    for g in 0..num_groups {
        let (phase, cycle) = compute_group_timing(g);
        log::info!(
            "  Группа {}: фаза={}с, цикл={}с ({}мин)",
            g + 1,
            phase,
            cycle,
            cycle / 60
        );
    }
    log::info!("Хешей: {}", tp.hashes.len());
    log::info!("Слушаю: {} | Пир: {}", cli.listen, cli.peer_addr);
    log::info!("Протокол: {}", if cli.use_tcp { "TCP" } else { "UDP" });
    log::info!("═══════════════════════════════════════");

    // Статистика
    let stats_handle = {
        let stats = stats.clone();
        let gs = global_shutdown.clone();
        tokio::spawn(async move { stats.run_loop(gs).await })
    };

    // Диспетчер
    let dispatcher = Dispatcher::new(local_conn, global_shutdown.clone(), stats.clone()).await;

    // Канал конфигурации
    let (config_tx, mut config_rx) = mpsc::channel::<String>(1);
    let split_tunnel = false; // Kotlin app handles split tunneling itself
    let peer_ip = peer.ip();
    let config_handle = tokio::spawn(async move {
        if let Some(raw_conf) = config_rx.recv().await {
            if raw_conf.is_empty() {
                return;
            }
            let final_conf = if split_tunnel {
                modify_config_for_split_tunnel(&raw_conf, peer_ip)
            } else {
                raw_conf
            };

            eprintln!();
            eprintln!("╔══════════════ WireGuard Конфиг ══════════════╗");
            for line in final_conf.lines() {
                eprintln!("║ {:<44} ║", line);
            }
            eprintln!("╚══════════════════════════════════════════════╝");

            if let Err(e) = tokio::fs::write("wg-turn.conf", format!("{}\n", final_conf)).await {
                log::error!("Ошибка сохранения конфига: {}", e);
            } else {
                log::info!("Конфиг сохранён в wg-turn.conf");
            }
        }
    });

    // Обработка сигналов
    let gs_signal = global_shutdown.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        log::info!("Сигнал завершения получен");
        gs_signal.store(true, Ordering::Relaxed);
    });

    // STDIN слушатель для Doze-mode: PAUSE/RESUME/STOP
    let global_pause = Arc::new(AtomicBool::new(false));
    let gs_stdin = global_shutdown.clone();
    let gp_stdin = global_pause.clone();
    tokio::spawn(async move {
        let stdin = tokio::io::BufReader::new(tokio::io::stdin());
        use tokio::io::AsyncBufReadExt;
        let mut lines = stdin.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            match line.trim() {
                "PAUSE" => {
                    log::info!("[STDIN] PAUSE — Doze-mode, воркеры замораживаются");
                    gp_stdin.store(true, Ordering::Relaxed);
                }
                "RESUME" => {
                    log::info!("[STDIN] RESUME — выход из Doze, воркеры возобновляются");
                    gp_stdin.store(false, Ordering::Relaxed);
                }
                "STOP" => {
                    log::info!("[STDIN] STOP — завершение");
                    gs_stdin.store(true, Ordering::Relaxed);
                    break;
                }
                _ => {}
            }
        }
    });

    // Запуск групп воркеров
    let mut group_handles = Vec::new();
    let mut worker_id_counter = 1usize;

    for g in 0..num_groups {
        let (phase_offset, cycle_secs) = compute_group_timing(g);

        let mut worker_ids = Vec::with_capacity(workers_per_group);
        for _ in 0..workers_per_group {
            worker_ids.push(worker_id_counter);
            worker_id_counter += 1;
        }

        let is_first = g == 0;
        let tp_c = tp.clone();
        let disp_c = dispatcher.clone();
        let lp = local_port.clone();
        let gs = global_shutdown.clone();
        let st = stats.clone();
        let app_id = cli.vk_app_id.clone();
        let app_secret = cli.vk_app_secret.clone();
        let dev_id = cli.device_id.clone();
        let pwd = cli.password.clone();
        let use_tcp = cli.use_tcp;

        let ctx = if is_first {
            Some(config_tx.clone())
        } else {
            None
        };

        let gp = global_pause.clone();

        let handle = tokio::spawn(async move {
            worker_group(
                g + 1,
                g % hash_count,
                tp_c,
                peer,
                disp_c,
                lp,
                use_tcp,
                is_first,
                ctx,
                worker_ids,
                std::time::Duration::from_secs(phase_offset),
                std::time::Duration::from_secs(cycle_secs),
                gs,
                gp,
                st,
                app_id,
                app_secret,
                dev_id,
                pwd,
            )
            .await;
        });

        group_handles.push(handle);
    }

    drop(config_tx);

    for h in group_handles {
        let _ = h.await;
    }

    global_shutdown.store(true, Ordering::Relaxed);
    let _ = config_handle.await;
    stats_handle.abort();

    log::info!("Все воркеры завершены");
    Ok(())
}