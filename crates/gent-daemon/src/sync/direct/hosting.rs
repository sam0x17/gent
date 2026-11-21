//! Publish a fresh listener identity when the machine's interface addresses change.
use super::*;
use crate::store::direct::HelperOffer;
use std::net::IpAddr;
use tokio::sync::watch;

pub(super) struct Hosting {
    offer: watch::Receiver<Option<HelperOffer>>,
    task: Option<JoinHandle<()>>,
}

impl Hosting {
    pub(super) fn start(
        store: SharedStore,
        id: EndpointId,
        node: String,
        settings: config::Transport,
        counters: Arc<iroh_relay::server::Metrics>,
        wakeup: Arc<Notify>,
    ) -> Self {
        let (publisher, offer) = watch::channel(None);
        let task = matches!(settings.helper, config::Direct::Auto).then(|| {
            tokio::spawn(async move {
                let mut service: Option<helper_service::HelperService> = None;
                let mut last_ips = Vec::new();
                loop {
                    if let Ok(ips) = tokio::task::spawn_blocking(interface_addresses).await
                        && (service.is_none() || ips != last_ips)
                    {
                        if let Some(old) = service.take() {
                            old.shutdown().await;
                        }
                        last_ips.clone_from(&ips);
                        let listener = helper_service::ListenerConfig {
                            advertised_ips: ips,
                            port: settings.helper_port,
                            public_address: settings.helper_public_address,
                            udp: settings.udp,
                        };
                        match helper_service::HelperService::start(
                            store.clone(),
                            id,
                            node.clone(),
                            listener,
                            counters.clone(),
                        )
                        .await
                        {
                            Ok(new) => {
                                publisher.send_replace(Some(new.offer().clone()));
                                service = Some(new);
                                wakeup.notify_one();
                            }
                            Err(error) => {
                                if publisher.send_replace(None).is_some() {
                                    wakeup.notify_one();
                                }
                                eprintln!("Gent cluster helper listener unavailable: {error}");
                            }
                        }
                    }
                    tokio::time::sleep(BACKOFF).await;
                }
            })
        });
        Self { offer, task }
    }

    pub(super) fn offer(&self) -> Option<HelperOffer> {
        self.offer.borrow().clone()
    }
}

impl Drop for Hosting {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn interface_addresses() -> Vec<IpAddr> {
    let mut ips: Vec<_> = netdev::get_interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback())
        .flat_map(|i| i.ipv4.into_iter().map(|net| IpAddr::V4(net.addr())))
        .collect();
    ips.sort_unstable();
    ips.dedup();
    ips
}
