//! Fair allocation of a bounded number of helper sockets, independent of cloud
//! reconciliation. One alias is tried per registration, across all peer pairs.
use super::*;
use std::sync::Weak;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, watch};

const REGISTRATION_WINDOW: Duration = Duration::from_secs(8);

pub(super) struct Slot {
    offer: Arc<HelperOffer>,
    available: watch::Sender<bool>,
    bound: Arc<Mutex<Option<Arc<Auxiliary>>>>,
    last_good: Instant,
    worker: JoinHandle<()>,
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.available.send_replace(false);
        self.worker.abort();
    }
}
impl Slot {
    pub(super) fn get(&self) -> Option<Arc<Auxiliary>> {
        self.bound.lock().expect("helper endpoint poisoned").clone()
    }
}

#[derive(Default)]
pub(super) struct Helpers {
    pub(super) active: BTreeMap<String, Slot>,
    pub(super) draining: Vec<Slot>,
    offers: BTreeMap<String, HelperOffer>,
    attempts: BTreeMap<String, (u64, usize)>,
    sequence: u64,
    last_rotation: Option<Instant>,
}

impl Helpers {
    pub(super) fn update(&mut self, offers: BTreeMap<String, HelperOffer>, wakeup: &Notify) {
        self.offers = offers;
        self.attempts.retain(|id, _| self.offers.contains_key(id));
        self.draining.retain(|slot| {
            slot.get().is_some_and(|a| {
                a.prune();
                a.keep_direct()
            })
        });
        for (id, mut slot) in std::mem::take(&mut self.active) {
            let aux = slot.get();
            if let Some(aux) = &aux {
                aux.prune();
            }
            if self
                .offers
                .get(&id)
                .is_some_and(|o| same_service(&slot.offer, o))
                && !slot.worker.is_finished()
            {
                if aux.is_some_and(|a| a.registration().is_some()) {
                    slot.last_good = Instant::now();
                }
                self.active.insert(id, slot);
            } else {
                slot.available.send_replace(false);
                if let Some(aux) = aux {
                    if aux.withdraw_registration() {
                        wakeup.notify_one();
                    }
                    if aux.keep_direct() && self.draining.len() < MAX_HELPERS {
                        self.draining.push(slot);
                    }
                }
            }
        }
    }

    pub(super) fn allocate(&mut self, factory: &Factory) {
        // An offer returning after an idle expiry can reuse its existing UDP
        // socket, including the proved connection and its TLS registration.
        let mut index = 0;
        while index < self.draining.len() {
            let slot = &self.draining[index];
            if self.active.len() < MAX_HELPERS
                && self
                    .offers
                    .get(&slot.offer.helper_node)
                    .is_some_and(|o| same_service(o, &slot.offer))
            {
                let mut slot = self.draining.swap_remove(index);
                slot.available.send_replace(true);
                slot.last_good = Instant::now();
                if let Some(aux) = slot.get()
                    && aux.update_registration()
                {
                    factory.wakeup.notify_one();
                }
                self.active.insert(slot.offer.helper_node.clone(), slot);
            } else {
                index += 1;
            }
        }
        let crowded = self.offers.len() > self.active.len();
        if self
            .last_rotation
            .is_none_or(|t| t.elapsed() >= REGISTRATION_WINDOW)
        {
            let mut stale: Vec<_> = self
                .active
                .iter()
                .filter(|(_, s)| {
                    (crowded || s.offer.urls.len() > 1)
                        && s.last_good.elapsed() >= REGISTRATION_WINDOW
                        && s.get()
                            .is_none_or(|a| a.registration().is_none() && !a.in_use())
                })
                .map(|(id, s)| (s.last_good, id.clone()))
                .collect();
            stale.sort();
            for (_, id) in stale.into_iter().take(2) {
                self.active.remove(&id);
                self.last_rotation = Some(Instant::now());
            }
        }
        let mut waiting: Vec<_> = self
            .offers
            .keys()
            .filter(|id| !self.active.contains_key(*id))
            .collect();
        waiting.sort_by_key(|id| self.attempts.get(*id).map(|(seq, _)| *seq));
        for id in waiting {
            if self.active.len() + self.draining.len() >= MAX_HELPERS {
                break;
            }
            let offer = &self.offers[id];
            // A repeated signed description of one TLS service must never create
            // another registration for this identity, even under another node ID.
            if self
                .active
                .values()
                .chain(&self.draining)
                .any(|s| s.offer.generation == offer.generation)
            {
                continue;
            }
            let (seq, next) = self.attempts.entry(id.clone()).or_default();
            let alias = offer.urls[*next % offer.urls.len()].clone();
            *next = next.wrapping_add(1);
            self.sequence += 1;
            *seq = self.sequence;
            self.active
                .insert(id.clone(), factory.start(Arc::new(offer.clone()), alias));
        }
    }
}

pub(super) struct Factory {
    key: SecretKey,
    udp: bool,
    store: SharedStore,
    metrics: Arc<Metrics>,
    wakeup: Arc<Notify>,
    incoming: Arc<Semaphore>,
    files: Arc<Semaphore>,
    owners: Mutex<BTreeMap<[u8; 32], Weak<AsyncMutex<()>>>>,
}
impl Factory {
    fn start(&self, offer: Arc<HelperOffer>, alias: RelayUrl) -> Slot {
        let bound = Arc::new(Mutex::new(None));
        let (available, mut active) = watch::channel(true);
        let (ready, config) = (bound.clone(), offer.clone());
        let key = self.key.clone();
        let store = self.store.clone();
        let metrics = self.metrics.clone();
        let wake = self.wakeup.clone();
        let (incoming, files) = (self.incoming.clone(), self.files.clone());
        let udp = self.udp;
        let url = alias;
        let owner = {
            let mut owners = self.owners.lock().expect("helper socket owners poisoned");
            owners.retain(|_, v| v.strong_count() > 0);
            let weak = owners.entry(offer.generation).or_default();
            weak.upgrade().unwrap_or_else(|| {
                let owner = Arc::new(AsyncMutex::new(()));
                *weak = Arc::downgrade(&owner);
                owner
            })
        };
        let worker = tokio::spawn(async move {
            let permit = owner.lock_owned().await;
            let aux = loop {
                if let Ok(aux) = Auxiliary::bind(
                    key.clone(),
                    config.clone(),
                    &url,
                    udp,
                    store.clone(),
                    metrics.clone(),
                    active.clone(),
                )
                .await
                {
                    break Arc::new(aux);
                }
                tokio::time::sleep(RETRY).await;
            };
            let _lease = SocketLease(aux.endpoint.clone(), Some(permit));
            let mut status = aux.endpoint.home_relay_status();
            let mut report = aux.endpoint.net_report();
            *ready.lock().expect("helper endpoint poisoned") = Some(aux.clone());
            let watch = async {
                loop {
                    if aux.update_registration() {
                        wake.notify_one();
                    }
                    tokio::select! {
                        changed=active.changed()=>{
                            if changed.is_err() {break;}
                            let enable=*active.borrow_and_update();
                            if enable {
                                aux.endpoint.insert_relay(url.clone(),Arc::new(aux.relay_config.clone())).await;
                            } else { aux.endpoint.remove_relay(&url).await; }
                        }
                        s=status.updated() => if s.is_err() {break},
                        r=report.updated() => if r.is_err() {break},
                    }
                }
            };
            tokio::select! { _=watch=>{}, _=aux.clone().listen(incoming,files)=>{} }
        });
        Slot {
            offer,
            available,
            bound,
            last_good: Instant::now(),
            worker,
        }
    }
}

// Finish closing the previous socket before another alias of this TLS
// service is allowed to register the same local endpoint ID.
struct SocketLease(Endpoint, Option<OwnedMutexGuard<()>>);
impl Drop for SocketLease {
    fn drop(&mut self) {
        let ep = self.0.clone();
        let permit = self.1.take();
        tokio::spawn(async move {
            ep.close().await;
            drop(permit);
        });
    }
}

impl Factory {
    pub(super) fn new(
        key: SecretKey,
        udp: bool,
        store: SharedStore,
        metrics: Arc<Metrics>,
        wakeup: Arc<Notify>,
    ) -> Self {
        Self {
            key,
            udp,
            store,
            metrics,
            wakeup,
            incoming: Arc::new(Semaphore::new(quic::MAX_LINKS)),
            files: Arc::new(Semaphore::new(2)),
            owners: Mutex::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn saturated_pool_rotates_failed_slots_without_restarting_the_others() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir()?;
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700))?;
        config::initialize(home.path(), "helper-slot-test")?;
        let store = Arc::new(Mutex::new(Store::open(home.path())?));
        let notify = Arc::new(Notify::new());
        let factory = Factory::new(
            SecretKey::generate(),
            false,
            store,
            Arc::default(),
            notify.clone(),
        );
        // Run the allocator without yielding to its background bind tasks.
        let offers: BTreeMap<_, _> = (0..=MAX_HELPERS)
            .map(|n| {
                let node = format!("test-{n:02}");
                (
                    node.clone(),
                    HelperOffer {
                        helper_node: node,
                        urls: vec![
                            "https://127.0.0.1:7001/".parse().unwrap(),
                            "https://127.0.0.1:7002/".parse().unwrap(),
                        ],
                        cert_der: vec![n as u8],
                        generation: [n as u8; 32],
                        qad_port: None,
                    },
                )
            })
            .collect();
        let mut helpers = Helpers::default();
        helpers.update(offers.clone(), &notify);
        helpers.allocate(&factory);
        assert_eq!(helpers.active.len(), MAX_HELPERS);
        assert!(!helpers.active.contains_key("test-16"));
        let workers: BTreeSet<_> = helpers.active.values().map(|s| s.worker.id()).collect();
        for slot in helpers.active.values_mut() {
            slot.last_good = Instant::now() - REGISTRATION_WINDOW;
        }
        helpers.allocate(&factory);
        assert!(helpers.active.contains_key("test-16"));
        assert_eq!(helpers.active.len(), MAX_HELPERS);
        assert_eq!(
            helpers
                .active
                .values()
                .filter(|s| workers.contains(&s.worker.id()))
                .count(),
            MAX_HELPERS - 2
        );
        assert!(helpers.attempts.values().any(|(_, alias)| *alias == 2));
        let chosen = helpers.sequence;
        helpers.allocate(&factory);
        assert_eq!(chosen, helpers.sequence);
        let mut duplicate = offers["test-16"].clone();
        duplicate.helper_node = "another-name".into();
        helpers.update(
            [
                ("another-name".into(), duplicate),
                ("test-16".into(), offers["test-16"].clone()),
            ]
            .into(),
            &notify,
        );
        helpers.allocate(&factory);
        assert_eq!(helpers.active.len(), 1);
        Ok(())
    }
}
