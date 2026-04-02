use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};

use crate::stats::Stats;

const READ_BUF_SIZE: usize = 1600;
const RETURN_BUF: usize = 384;

pub struct WorkerSlot {
    pub id: usize,
    pub send_tx: mpsc::Sender<Vec<u8>>,
}

pub struct Dispatcher {
    workers: RwLock<Vec<Arc<WorkerSlot>>>,
    rr_index: AtomicUsize,
    pub return_tx: mpsc::Sender<Vec<u8>>,
    client_addr: RwLock<Option<std::net::SocketAddr>>,
    stats: Arc<Stats>,
}

impl Dispatcher {
    pub async fn new(
        local_conn: UdpSocket,
        shutdown: Arc<AtomicBool>,
        stats: Arc<Stats>,
    ) -> Arc<Self> {
        let (return_tx, return_rx) = mpsc::channel(RETURN_BUF);

        let local = Arc::new(local_conn);

        let disp = Arc::new(Dispatcher {
            workers: RwLock::new(Vec::new()),
            rr_index: AtomicUsize::new(0),
            return_tx,
            client_addr: RwLock::new(None),
            stats,
        });

        // Read loop
        let d = disp.clone();
        let l = local.clone();
        let gs = shutdown.clone();
        tokio::spawn(async move {
            Self::read_loop(d, l, gs).await;
        });

        // Write loop
        let d = disp.clone();
        let l = local.clone();
        let gs = shutdown.clone();
        tokio::spawn(async move {
            Self::write_loop(d, l, return_rx, gs).await;
        });

        disp
    }

    async fn read_loop(self: Arc<Self>, local: Arc<UdpSocket>, shutdown: Arc<AtomicBool>) {
        let mut buf = vec![0u8; READ_BUF_SIZE];
        loop {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }

            let result = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                local.recv_from(&mut buf),
            )
            .await;

            let (n, addr) = match result {
                Ok(Ok((n, addr))) => (n, addr),
                Ok(Err(_e)) => {
                    if shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
                Err(_) => continue, // timeout
            };

            {
                let mut ca = self.client_addr.write().await;
                *ca = Some(addr);
            }

            self.stats
                .total_bytes_up
                .fetch_add(n as i64, Ordering::Relaxed);

            let pkt = buf[..n].to_vec();

            let workers = self.workers.read().await;
            let nw = workers.len();
            if nw == 0 {
                continue;
            }

            let start = self.rr_index.load(Ordering::Relaxed) % nw;
            let mut sent = false;
            for i in 0..nw {
                let idx = (start + i) % nw;
                match workers[idx].send_tx.try_send(pkt.clone()) {
                    Ok(_) => {
                        self.rr_index.store((idx + 1) % nw, Ordering::Relaxed);
                        sent = true;
                        break;
                    }
                    Err(_) => continue,
                }
            }
            if !sent {
                self.rr_index.store((start + 1) % nw, Ordering::Relaxed);
            }
        }
    }

    async fn write_loop(
        self: Arc<Self>,
        local: Arc<UdpSocket>,
        mut return_rx: mpsc::Receiver<Vec<u8>>,
        shutdown: Arc<AtomicBool>,
    ) {
        loop {
            tokio::select! {
                pkt = return_rx.recv() => {
                    match pkt {
                        Some(data) => {
                            let addr = {
                                let ca = self.client_addr.read().await;
                                *ca
                            };
                            if let Some(addr) = addr {
                                let _ = local.send_to(&data, addr).await;
                                self.stats.total_bytes_down.fetch_add(data.len() as i64, Ordering::Relaxed);
                            }
                        }
                        None => return,
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                    if shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                }
            }
        }
    }

    pub async fn register(&self, slot: Arc<WorkerSlot>) {
        let mut workers = self.workers.write().await;
        log::info!(
            "[ДИСП] Воркер #{} зарегистрирован (всего: {})",
            slot.id,
            workers.len() + 1
        );
        workers.push(slot);
    }

    pub async fn unregister(&self, slot_id: usize) {
        let mut workers = self.workers.write().await;
        workers.retain(|w| w.id != slot_id);
        log::info!(
            "[ДИСП] Воркер #{} отключён (осталось: {})",
            slot_id,
            workers.len()
        );
    }
}