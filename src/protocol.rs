//! Протокол общения с сервером (GETCONF / READY).

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Запрос конфигурации через DTLS-соединени��.
pub async fn request_config<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    local_port: &str,
    device_id: &str,
    password: &str,
) -> Result<Option<String>, String> {
    let payload = format!("GETCONF:{}|{}|{}", local_port, device_id, password);
    stream
        .write_all(payload.as_bytes())
        .await
        .map_err(|e| format!("Send GETCONF: {}", e))?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        stream.read(&mut buf),
    )
    .await
    .map_err(|_| "GETCONF timeout".to_string())?
    .map_err(|e| format!("Read config: {}", e))?;

    let resp = String::from_utf8_lossy(&buf[..n]).to_string();

    if resp == "NOCONF" {
        return Ok(None);
    }

    if resp.starts_with("DENIED:") {
        let reason = resp.trim_start_matches("DENIED:");
        return match reason {
            "wrong_password" => Err("FATAL_AUTH: неверный пароль".into()),
            "expired" => Err("FATAL_AUTH: пароль истёк".into()),
            "device_mismatch" => Err("FATAL_AUTH: другое устройство".into()),
            _ => Err(format!("FATAL_AUTH: {}", reason)),
        };
    }

    Ok(Some(resp))
}

/// Отправка READY и ожидание READY_OK.
pub async fn send_ready<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> Result<(), String> {
    let mut buf = vec![0u8; 64];
    for attempt in 0..4 {
        stream
            .write_all(b"READY")
            .await
            .map_err(|e| format!("Send READY: {}", e))?;

        if let Ok(res) = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await {
            let n = res.map_err(|e| format!("Read READY_OK: {}", e))?;
            let resp = String::from_utf8_lossy(&buf[..n]);
            if resp == "READY_OK" {
                return Ok(());
            }
        }
    }
    Err("READY_OK timeout after retries".to_string())
}