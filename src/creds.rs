use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::sync::Semaphore;

use crate::config::TurnParams;
use crate::stats::Stats;

static VK_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

#[derive(Clone, Debug)]
pub struct Credentials {
    pub user: String,
    pub pass: String,
    pub turn_url: String,
}

pub async fn get_creds_with_fallback(
    tp: &TurnParams,
    hash: &str,
    shutdown: &Arc<AtomicBool>,
    stats: &Arc<Stats>,
    app_id: &str,
    app_secret: &str,
) -> Result<Credentials, String> {
    match get_unique_vk_creds(hash, 5, shutdown, stats, app_id, app_secret).await {
        Ok(c) => Ok(c),
        Err(e) => {
            if !tp.secondary_hash.is_empty() && hash != tp.secondary_hash {
                log::warn!("Основной хеш не сработал, пробую запасной");
                get_unique_vk_creds(&tp.secondary_hash, 3, shutdown, stats, app_id, app_secret)
                    .await
            } else {
                Err(e)
            }
        }
    }
}

async fn get_unique_vk_creds(
    hash: &str,
    max_retries: usize,
    shutdown: &Arc<AtomicBool>,
    stats: &Arc<Stats>,
    app_id: &str,
    app_secret: &str,
) -> Result<Credentials, String> {
    let mut last_err = String::new();

    for attempt in 0..max_retries {
        if shutdown.load(Ordering::Relaxed) {
            return Err("shutdown".into());
        }

        let _permit = VK_SEMAPHORE
            .acquire()
            .await
            .map_err(|e| format!("semaphore: {}", e))?;

        // Выполняем блокирующий HTTP в spawn_blocking
        let hash_owned = hash.to_string();
        let app_id_owned = app_id.to_string();
        let app_secret_owned = app_secret.to_string();

        let result = tokio::task::spawn_blocking(move || {
            get_vk_creds_once(&hash_owned, &app_id_owned, &app_secret_owned)
        })
        .await
        .map_err(|e| format!("spawn_blocking: {}", e))?;

        drop(_permit);

        match result {
            Ok(creds) => return Ok(creds),
            Err(e) => {
                stats.creds_errors.fetch_add(1, Ordering::Relaxed);
                last_err = e.clone();

                if e.contains("9000") || e.contains("call not found") {
                    return Err(format!("Хеш мёртв: {}", e));
                }

                let backoff = if e.contains("flood") || e.contains("Flood") {
                    let secs = std::cmp::min(5 * (attempt + 1), 60);
                    Duration::from_secs(secs as u64)
                } else {
                    let base = std::cmp::min(1u64 << std::cmp::min(attempt, 5), 30);
                    let jitter = rand::thread_rng().gen_range(0..1000);
                    Duration::from_secs(base) + Duration::from_millis(jitter)
                };

                if shutdown.load(Ordering::Relaxed) {
                    return Err("shutdown".into());
                }

                tokio::time::sleep(backoff).await;
            }
        }
    }

    Err(format!("Исчерпаны {} попыток: {}", max_retries, last_err))
}

fn get_vk_creds_once(hash: &str, app_id: &str, app_secret: &str) -> Result<Credentials, String> {
    let ok_app_key = "CGMMEJLGDIHBABABA";
    let timeout = Duration::from_secs(15);

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .user_agent("Mozilla/5.0")
        .build();

    let do_post =
        |url: &str, body: &str| -> Result<serde_json::Value, String> {
            let resp = agent
                .post(url)
                .set("Content-Type", "application/x-www-form-urlencoded")
                .send_string(body)
                .map_err(|e| format!("HTTP POST {}: {}", url, e))?;

            let text = resp
                .into_string()
                .map_err(|e| format!("Read response: {}", e))?;

            let val: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("JSON parse: {}", e))?;

            if val.get("error").is_some() {
                return Err(format!("API error: {}", val["error"]));
            }

            Ok(val)
        };

    let get_str = |val: &serde_json::Value, keys: &[&str]| -> Result<String, String> {
        let mut current = val;
        for &k in keys {
            current = current.get(k).ok_or_else(|| format!("Key '{}' not found", k))?;
        }
        current
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "Value is not a string".into())
    };

    // Step 1: anonymous token
    let body1 = format!(
        "client_secret={}&client_id={}&scopes=audio_anonymous%2Cvideo_anonymous%2Cphotos_anonymous%2Cprofile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id={}",
        app_secret, app_id, app_id
    );
    let r1 = do_post("https://login.vk.ru/?act=get_anonym_token", &body1)?;
    let t1 = get_str(&r1, &["data", "access_token"])?;

    // Step 2: messages token
    let body2 = format!(
        "client_id={}&token_type=messages&payload={}&client_secret={}&version=1&app_id={}",
        app_id, t1, app_secret, app_id
    );
    let r2 = do_post("https://login.vk.ru/?act=get_anonym_token", &body2)?;
    let t2 = get_str(&r2, &["data", "access_token"])?;

    // Step 3: call token
    let body3 = format!(
        "vk_join_link=https://vk.com/call/join/{}&name=123&access_token={}",
        hash, t2
    );
    let r3 = do_post(
        "https://api.vk.ru/method/calls.getAnonymousToken?v=5.264",
        &body3,
    )?;
    let t3 = get_str(&r3, &["response", "token"])?;

    // Step 4: OK anonymous login
    let device_uuid = uuid::Uuid::new_v4();
    let body4 = format!(
        "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22{}%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key={}",
        device_uuid, ok_app_key
    );
    let r4 = do_post("https://calls.okcdn.ru/fb.do", &body4)?;
    let t4 = get_str(&r4, &["session_key"])?;

    // Step 5: join conversation
    let body5 = format!(
        "joinLink={}&isVideo=false&protocolVersion=5&anonymToken={}&method=vchat.joinConversationByLink&format=JSON&application_key={}&session_key={}",
        hash, t3, ok_app_key, t4
    );
    let r5 = do_post("https://calls.okcdn.ru/fb.do", &body5)?;

    let ts = r5
        .get("turn_server")
        .ok_or("turn_server не найден")?;

    let user = get_str(ts, &["username"])?;
    let pass = get_str(ts, &["credential"])?;

    if user.is_empty() || pass.is_empty() {
        return Err("Пустые credentials".into());
    }

    let urls = ts
        .get("urls")
        .and_then(|v| v.as_array())
        .ok_or("Нет TURN urls")?;

    if urls.is_empty() {
        return Err("Пустой массив TURN urls".into());
    }

    let turn_url_raw = urls[0].as_str().ok_or("TURN URL не строка")?;
    let clean = turn_url_raw.split('?').next().unwrap_or(turn_url_raw);
    let turn_addr = clean
        .trim_start_matches("turns:")
        .trim_start_matches("turn:")
        .to_string();

    Ok(Credentials {
        user,
        pass,
        turn_url: turn_addr,
    })
}