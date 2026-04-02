use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct Stats {
    pub active_connections: AtomicI32,
    pub total_bytes_up: AtomicI64,
    pub total_bytes_down: AtomicI64,
    pub creds_errors: AtomicI64,
}

impl Stats {
    pub fn new() -> Self {
        Stats {
            active_connections: AtomicI32::new(0),
            total_bytes_up: AtomicI64::new(0),
            total_bytes_down: AtomicI64::new(0),
            creds_errors: AtomicI64::new(0),
        }
    }

    pub async fn run_loop(&self, shutdown: Arc<AtomicBool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            if shutdown.load(Ordering::Relaxed) {
                return;
            }

            let active = self.active_connections.load(Ordering::Relaxed);
            let up = self.total_bytes_up.load(Ordering::Relaxed);
            let down = self.total_bytes_down.load(Ordering::Relaxed);
            let cred_errs = self.creds_errors.load(Ordering::Relaxed);
            let total_mb = (up + down) as f64 / (1024.0 * 1024.0);

            log::info!(
                "[СТАТИСТИКА] Активных: {} | Ошибок ВК: {} | Трафик: {:.2} МБ",
                active,
                cred_errs,
                total_mb
            );
        }
    }
}