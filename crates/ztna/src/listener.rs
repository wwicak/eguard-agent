use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

pub struct LocalForwardHandle {
    pub listen_addr: SocketAddr,
    task: JoinHandle<()>,
}

impl LocalForwardHandle {
    pub async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
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

                let upstream = upstream_addr.clone();
                tokio::spawn(async move {
                    match TcpStream::connect(&upstream).await {
                        Ok(mut outbound) => {
                            if let Err(err) = copy_bidirectional(&mut inbound, &mut outbound).await
                            {
                                debug!(peer = %peer, error = %err, "ztna proxy stream ended with error");
                            }
                        }
                        Err(err) => {
                            debug!(peer = %peer, error = %err, upstream = %upstream, "ztna proxy failed to connect upstream");
                        }
                    }
                });
            }
        });

        Ok(LocalForwardHandle {
            listen_addr: bound,
            task,
        })
    }
}
