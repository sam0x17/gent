//! Pair-specific helper routes. Primary QUIC stays on its own endpoint and pool.
use super::*;
use crate::store::direct::{HelperCandidate, HelperOffer, HelperRegistration};
use auxiliary::{Application, Auxiliary, Kind};
use iroh::{RelayUrl, Watcher};
use proof::{PathKind, Proof, Sample};

mod auxiliary;
mod proof;
mod registry;
use registry::{Factory, Helpers, Slot};
#[cfg(test)]
mod tests;

const MAX_HELPERS: usize = 16;
const SHORTLIST: usize = 3;
const ATTEMPT: Duration = Duration::from_millis(1600);
const RETRY: Duration = Duration::from_secs(4);
const SAMPLE_TTL: Duration = Duration::from_secs(30);

pub(super) struct Routes {
    primary: BTreeSet<RelayUrl>,
    wakeup: Arc<Notify>,
    helpers: Mutex<Helpers>,
    factory: Factory,
    winners: Mutex<BTreeMap<EndpointId, Winner>>,
}
#[derive(Clone)]
struct Winner {
    helper: String,
    generation: [u8; 32],
    selected: Instant,
}

impl Routes {
    pub(super) fn new(
        key: SecretKey,
        primary_relays: Vec<RelayUrl>,
        udp: bool,
        store: SharedStore,
        metrics: Arc<Metrics>,
        wakeup: Arc<Notify>,
    ) -> Self {
        Self {
            factory: Factory::new(key, udp, store, metrics, wakeup.clone()),
            primary: primary_relays.into_iter().collect(),
            wakeup,
            helpers: Mutex::default(),
            winners: Mutex::default(),
        }
    }

    /// Reconciles the authenticated offer snapshot. Binding, registration and
    /// network measurements run independently of the scheduler and send path.
    pub(super) async fn refresh(&self, offers: Vec<HelperOffer>) {
        let offers = offers
            .into_iter()
            .filter(|o| !o.urls.is_empty() && !o.urls.iter().any(|u| self.primary.contains(u)))
            .map(|o| (o.helper_node.clone(), o))
            .collect();
        let mut helpers = self.helpers.lock().expect("helper endpoints poisoned");
        helpers.update(offers, &self.wakeup);
        helpers.allocate(&self.factory);
    }

    pub(super) fn registrations(&self) -> Vec<HelperRegistration> {
        self.helpers
            .lock()
            .expect("helper endpoints poisoned")
            .active
            .values()
            .filter_map(|s| s.get()?.registration())
            .collect()
    }

    pub(super) async fn chat(
        &self,
        peer: EndpointId,
        candidates: &[HelperCandidate],
    ) -> Option<Arc<quic::Link>> {
        match tokio::time::timeout(
            ATTEMPT + Duration::from_millis(100),
            self.select(peer, Kind::Chat, candidates),
        )
        .await
        .ok()??
        {
            Application::Chat(link) => Some(link),
            _ => None,
        }
    }
    pub(super) async fn file(
        &self,
        peer: EndpointId,
        candidates: &[HelperCandidate],
    ) -> Option<Connection> {
        match tokio::time::timeout(
            ATTEMPT + Duration::from_millis(100),
            self.select(peer, Kind::File, candidates),
        )
        .await
        .ok()??
        {
            Application::File(conn) => Some(conn),
            _ => None,
        }
    }

    async fn select(
        &self,
        peer: EndpointId,
        kind: Kind,
        candidates: &[HelperCandidate],
    ) -> Option<Application> {
        let (active, draining) = {
            let helpers = self.helpers.lock().expect("helper endpoints poisoned");
            (
                helpers
                    .active
                    .values()
                    .filter_map(Slot::get)
                    .collect::<Vec<_>>(),
                helpers
                    .draining
                    .iter()
                    .filter_map(Slot::get)
                    .collect::<Vec<_>>(),
            )
        };
        // A surviving connection can have upgraded since its last use. Prove
        // the new path on that same connection even if registrations were lost.
        let mut direct = futures_util::stream::FuturesUnordered::new();
        for aux in active.iter().chain(&draining) {
            if let Some(live) = aux.lookup(peer, kind)
                && live.proof.selected() == Some(PathKind::Direct)
            {
                if live
                    .proof
                    .cached()
                    .is_some_and(|s| s.kind() == PathKind::Direct)
                {
                    return Some(live.application);
                }
                direct.push(aux.attempt(peer, kind, None));
            }
        }
        let winner = self
            .winners
            .lock()
            .expect("helper winners poisoned")
            .get(&peer)
            .cloned();
        let mut ranked = Vec::new();
        for aux in &active {
            if aux.cooling(peer, kind) {
                continue;
            }
            let Some(local) = aux.registration() else {
                continue;
            };
            let Some((score, url)) = candidates
                .iter()
                .filter_map(|c| legs(&aux.offer, &local, c))
                .min_by_key(|(score, _)| *score)
            else {
                continue;
            };
            let incumbent = winner.as_ref().is_some_and(|w| {
                w.helper == aux.offer.helper_node && w.generation == aux.offer.generation
            });
            ranked.push((score, incumbent, aux, url));
        }
        ranked.sort_by_key(|(score, _, _, _)| *score);
        if ranked.len() > SHORTLIST {
            if let Some(i) = ranked.iter().position(|r| r.1)
                && i >= SHORTLIST
            {
                ranked.swap(i, SHORTLIST - 1);
            }
            ranked.truncate(SHORTLIST);
        }

        // Reuse the measured winner until its sample expires or its path
        // changes. A lost registration immediately removes it from this list.
        if direct.is_empty()
            && let Some((_, _, aux, _)) = ranked.iter().find(|r| r.1)
            && winner.is_some_and(|w| w.selected.elapsed() < SAMPLE_TTL)
            && let Some(live) = aux.lookup(peer, kind)
            && live.proof.cached().is_some()
        {
            return Some(live.application);
        }
        let mut tries = futures_util::stream::FuturesUnordered::new();
        for (_, incumbent, aux, url) in ranked {
            tries.push(async move {
                let (_, sample) = aux.attempt(peer, kind, Some(url.clone())).await?;
                Some((incumbent, aux, url, sample))
            });
        }

        // Leave time in the caller's delivery deadline for the signed receipt.
        // A blackholed challenger cannot hold up an already verified route.
        let mut deadline = Instant::now() + ATTEMPT + Duration::from_millis(50);
        let mut verified = Vec::new();
        while !direct.is_empty() || !tries.is_empty() {
            tokio::select! {
                Some(outcome) = direct.next(), if !direct.is_empty() => {
                    if let Some((app,_)) = outcome { return Some(app); }
                }
                Some(outcome) = tries.next(), if !tries.is_empty() => {
                    if let Some((incumbent,aux,url,sample)) = outcome {
                        if let Some(live)=aux.lookup(peer,kind)
                            && live.proof.cached().is_some_and(|s| s.kind()==PathKind::Direct) {
                            return Some(live.application);
                        }
                        if verified.is_empty() {
                            deadline=deadline.min(Instant::now()+Duration::from_millis(150));
                        }
                        verified.push((sample.rtt,incumbent,aux,url));
                    }
                }
                _=tokio::time::sleep_until(deadline)=>break,
            }
        }
        let mut eligible: Vec<_> = verified
            .into_iter()
            .filter_map(|(rtt, incumbent, aux, url)| {
                let live = aux.lookup(peer, kind)?;
                let sample = live.proof.cached()?;
                (sample.kind() == PathKind::Helper
                    && aux.registration().is_some_and(|r| r.url == url))
                .then_some((rtt, incumbent, &aux.offer, live.application))
            })
            .collect();
        eligible.sort_by_key(|r| r.0);
        let best = eligible.first()?.0;
        let chosen = eligible
            .iter()
            .position(|(rtt, incumbent, _, _)| *incumbent && !worth_switching(*rtt, best))
            .unwrap_or(0);
        let (_, _, offer, app) = eligible.swap_remove(chosen);
        let mut winners = self.winners.lock().expect("helper winners poisoned");
        winners.retain(|_, w| w.selected.elapsed() < SAMPLE_TTL * 4);
        if winners.len() < quic::MAX_LINKS * MAX_HELPERS || winners.contains_key(&peer) {
            winners.insert(
                peer,
                Winner {
                    helper: offer.helper_node.clone(),
                    generation: offer.generation,
                    selected: Instant::now(),
                },
            );
        }
        Some(app)
    }
}

fn same_service(a: &HelperOffer, b: &HelperOffer) -> bool {
    a.helper_node == b.helper_node
        && a.generation == b.generation
        && a.qad_port == b.qad_port
        && a.urls.len() == b.urls.len()
        && a.urls.iter().all(|url| b.urls.contains(url))
}

fn legs(
    offer: &HelperOffer,
    live: &HelperRegistration,
    candidate: &HelperCandidate,
) -> Option<(u64, RelayUrl)> {
    let local = &candidate.local;
    let remote = &candidate.remote;
    (same_service(offer, &candidate.offer)
        && live.url == local.url
        && [live, local, remote].iter().all(|r| {
            r.helper_node == offer.helper_node
                && r.generation == offer.generation
                && offer.urls.contains(&r.url)
        }))
    .then(|| {
        (
            u64::from(live.rtt_ms) + u64::from(remote.rtt_ms),
            live.url.clone(),
        )
    })
}

fn worth_switching(current: Duration, next: Duration) -> bool {
    next + (current / 5).max(Duration::from_millis(2)) < current
}

fn registration_changed(
    old: Option<&HelperRegistration>,
    new: Option<&HelperRegistration>,
) -> bool {
    match (old, new) {
        (Some(a), Some(b)) => {
            a.url != b.url
                || a.generation != b.generation
                || a.rtt_ms.abs_diff(b.rtt_ms) > (a.rtt_ms / 5).max(2)
        }
        (None, None) => false,
        _ => true,
    }
}
