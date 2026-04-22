use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

pub struct LocalForwardHandle {
    pub listen_addr: SocketAddr,
    stats: Arc<LocalForwardStats>,
    task: JoinHandle<()>,
}

impl LocalForwardHandle {
    pub fn last_activity_unix(&self) -> i64 {
        self.stats.last_activity_unix.load(Ordering::Relaxed)
    }

    pub fn active_connections(&self) -> usize {
        self.stats.active_connections.load(Ordering::Relaxed)
    }

    pub async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

struct LocalForwardStats {
    last_activity_unix: AtomicI64,
    active_connections: AtomicUsize,
}

impl LocalForwardStats {
    fn new() -> Self {
        Self {
            last_activity_unix: AtomicI64::new(now_unix()),
            active_connections: AtomicUsize::new(0),
        }
    }

    fn mark_activity(&self) {
        self.last_activity_unix.store(now_unix(), Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct LocalForwardManager;

impl LocalForwardManager {
    pub async fn start(
        &self,
        listen_addr: SocketAddr,
        upstream_addr: String,
    ) -> Result<LocalForwardHandle> {
        let listener = TcpListener::bind(listen_addr).await?;
        let bound = listener.local_addr()?;
        let stats = Arc::new(LocalForwardStats::new());

        let listener_stats = Arc::clone(&stats);
        let task = tokio::spawn(async move {
            loop {
                let accepted = listener.accept().await;
                let (mut inbound, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        warn!(error = %err, "ztna listener accept failed");
                        continue;
                    }
                };
                listener_stats.mark_activity();

                let upstream = upstream_addr.clone();
                let connection_stats = Arc::clone(&listener_stats);
                tokio::spawn(async move {
                    connection_stats
                        .active_connections
                        .fetch_add(1, Ordering::Relaxed);
                    connection_stats.mark_activity();
                    match TcpStream::connect(&upstream).await {
                        Ok(mut outbound) => {
                            if let Err(err) = copy_bidirectional(&mut inbound, &mut outbound).await
                            {
                                debug!(peer = %peer, error = %err, "ztna proxy stream ended with error");
                            }
                            connection_stats.mark_activity();
                        }
                        Err(err) => {
                            debug!(peer = %peer, error = %err, upstream = %upstream, "ztna proxy failed to connect upstream");
                            connection_stats.mark_activity();
                        }
                    }
                    connection_stats
                        .active_connections
                        .fetch_sub(1, Ordering::Relaxed);
                });
            }
        });

        Ok(LocalForwardHandle {
            listen_addr: bound,
            stats,
            task,
        })
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
