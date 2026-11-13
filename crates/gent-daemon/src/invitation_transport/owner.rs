//! Bounded owner-side polling. Never retain Store's mutex over network I/O.
//! Noise state is memory-only; durable attempt reservations survive its loss.
use super::{Envelope, Mailbox, Side};
use crate::store::{
    Store,
    invitations::{PendingSession, Session},
};
use anyhow::{Context, Result, ensure};
use futures_util::{StreamExt, stream};
use gent_crypto::invitation::{
    SignedOffer,
    channel::{Hello, SESSION_LIFETIME},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::Instant,
};

type SharedStore = Arc<Mutex<Store>>;
const MAX_SESSIONS: usize = 8;
const MAX_PER_INVITATION: usize = 2;
const IDLE_SECONDS: u64 = 30;

async fn local<T: Send + 'static>(
    store: SharedStore,
    operation: impl FnOnce(&mut Store) -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(move || {
        let mut guard = store
            .lock()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
        operation(&mut guard)
    })
    .await?
}

enum Phase {
    Claim(PendingSession),
    Ready(Session),
}
struct Live {
    phase: Option<Phase>,
    next: u64,
    outgoing: Option<Envelope>,
    started: Instant,
    last_input: Instant,
    supersedes: bool,
    _permit: OwnedSemaphorePermit,
}
struct Owner {
    offer: SignedOffer,
    mailbox: Mailbox,
    live: BTreeMap<String, Live>,
    checked: BTreeSet<String>,
    retry_at: Instant,
    retry_delay: Duration,
}
impl Owner {
    fn new(offer: SignedOffer, bearer: &str) -> Result<Self> {
        Ok(Self {
            mailbox: Mailbox::new(&offer, Side::Owner, bearer)?,
            offer,
            live: BTreeMap::new(),
            checked: BTreeSet::new(),
            retry_at: Instant::now(),
            retry_delay: Duration::ZERO,
        })
    }

    async fn advance(&self, store: SharedStore, attempt: &str, live: &mut Live) -> Result<bool> {
        if live.outgoing.is_none() {
            let limit = if live.next == 1 {
                gent_crypto::MAX_REQUEST_BYTES + 38
            } else {
                super::protocol::MAX_WIRE_BYTES
            };
            let Some(envelope) = self.mailbox.get_limit(attempt, live.next, limit).await? else {
                return Ok(false);
            };
            // Taking the phase BEFORE local work also handles cancellation: a
            // lost future cannot leave a channel with uncertain receive counters.
            let phase = live.phase.take().context("closed invitation attempt")?;
            let accepting = matches!(phase, Phase::Claim(_));
            let Envelope::Frames(frames) = envelope else {
                anyhow::bail!("unexpected invitation handshake")
            };
            let (phase, frames) = local(store.clone(), move |store| {
                let (session, response) = match phase {
                    Phase::Claim(pending) => {
                        let mut session = store.accept_invitation(pending, &frames)?;
                        let response = store.invitation_claim_receipt(&mut session)?;
                        (session, response)
                    }
                    Phase::Ready(mut session) => {
                        let response = store.invitation_call(&mut session, &frames)?;
                        (session, response)
                    }
                };
                // Keep session ownership within this one returned state.
                Ok((Phase::Ready(session), response))
            })
            .await?;
            live.phase = Some(phase);
            live.supersedes = accepting;
            live.outgoing = Some(Envelope::Frames(frames));
            live.last_input = Instant::now();
        }
        let offer = self.offer.clone();
        local(store, move |store| store.invitation_live(&offer)).await?;
        self.mailbox
            .put(
                attempt,
                live.next,
                live.outgoing.as_ref().expect("cached response"),
            )
            .await?;
        live.outgoing = None;
        live.next += 1;
        Ok(true)
    }

    async fn tick(&mut self, store: SharedStore, slots: Arc<Semaphore>) -> Result<bool> {
        let mut progressed = false;
        let mut error = None;
        let attempts: Vec<_> = self.live.keys().cloned().collect();
        for attempt in attempts {
            let Some(mut live) = self.live.remove(&attempt) else {
                continue;
            };
            if live.started.elapsed() >= Duration::from_secs(SESSION_LIFETIME)
                || live.last_input.elapsed() >= Duration::from_secs(IDLE_SECONDS)
            {
                continue;
            }
            match self.advance(store.clone(), &attempt, &mut live).await {
                Ok(value) => progressed |= value,
                Err(e) => {
                    if super::fatal(&e) || super::invalid_message(&e) {
                        live.phase = None;
                    }
                    error = Some(e);
                }
            }
            if live.supersedes {
                // The journal has accepted the SAME saved node/key/name. Its
                // new session supersedes old established sessions, so cancelled
                // callers don't occupy every slot until their idle timeout.
                self.live
                    .retain(|_, old| !matches!(old.phase, Some(Phase::Ready(_))));
                live.supersedes = false;
            }
            if live.phase.is_some() && live.next < super::protocol::MAX_MESSAGES_PER_SIDE {
                self.live.insert(attempt, live);
            }
        }
        if self.live.len() < MAX_PER_INVITATION
            && self.checked.len() < super::protocol::MAX_ATTEMPTS
            && let Ok(permit) = slots.try_acquire_owned()
        {
            let attempts = self.mailbox.attempts().await?;
            if let Some(attempt) = attempts
                .keys()
                .find(|a| !self.checked.contains(*a))
                .cloned()
            {
                let id = self.offer.offer.id.clone();
                let a = attempt.clone();
                if local(store.clone(), move |s| s.invitation_attempt_seen(&id, &a)).await? {
                    self.checked.insert(attempt);
                    return Ok(true);
                }
                let envelope = match self.mailbox.get_limit(&attempt, 0, 57).await {
                    Ok(envelope) => envelope,
                    Err(e) if super::invalid_message(&e) => {
                        self.checked.insert(attempt);
                        return Ok(true);
                    }
                    Err(e) => return Err(e),
                };
                if let Some(envelope) = envelope {
                    self.checked.insert(attempt.clone());
                    // Only a successfully authenticated Hello spends the native
                    // budget; malformed candidates are bounded locally as well.
                    let Envelope::Handshake(noise) = envelope else {
                        return Ok(true);
                    };
                    let hello = Hello {
                        attempt: attempt.clone(),
                        noise: noise.to_vec(),
                    };
                    let id = self.offer.offer.id.clone();
                    if let Ok((pending, reply)) =
                        local(store, move |s| s.begin_invitation(&id, &hello)).await
                    {
                        let started = Instant::now();
                        self.live.insert(
                            attempt,
                            Live {
                                phase: Some(Phase::Claim(pending)),
                                next: 0,
                                outgoing: Some(Envelope::Handshake(
                                    reply
                                        .try_into()
                                        .map_err(|_| anyhow::anyhow!("invalid handshake reply"))?,
                                )),
                                started,
                                last_input: started,
                                supersedes: false,
                                _permit: permit,
                            },
                        );
                    }
                    progressed = true;
                }
            }
        }
        if let Some(error) = error {
            return Err(error);
        }
        Ok(progressed)
    }
}

/// Separate from normal sync, so invitation latency cannot delay agent traffic.
/// Dropping the worker aborts it, including on unexpected daemon exit paths.
pub struct Worker(JoinHandle<()>);
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl Worker {
    pub async fn stop(mut self) {
        self.0.abort();
        let _ = (&mut self.0).await;
    }
}
pub fn start(store: SharedStore) -> Worker {
    Worker(tokio::spawn(run(store)))
}
async fn run(store: SharedStore) {
    let mut scheduler = Scheduler::new();
    loop {
        let progressed = scheduler.tick(store.clone()).await.unwrap_or(false);
        tokio::time::sleep(if progressed {
            Duration::from_millis(25)
        } else if scheduler.owners.is_empty() {
            Duration::from_secs(1)
        } else {
            Duration::from_millis(250)
        })
        .await;
    }
}
struct Scheduler {
    owners: BTreeMap<String, Owner>,
    slots: Arc<Semaphore>,
    cursor: usize,
    bearer_hash: Option<[u8; 32]>,
}
impl Scheduler {
    fn new() -> Self {
        Self {
            owners: BTreeMap::new(),
            slots: Arc::new(Semaphore::new(MAX_SESSIONS)),
            cursor: 0,
            bearer_hash: None,
        }
    }
    async fn tick(&mut self, store: SharedStore) -> Result<bool> {
        let (jobs, bearer) = match local(store.clone(), |store| {
            let jobs = store.invitation_jobs()?;
            let bearer = if jobs.is_empty() {
                None
            } else {
                Some(store.invitation_bearer()?)
            };
            Ok((jobs, bearer))
        })
        .await
        {
            Ok(jobs) => jobs,
            Err(e) => {
                self.owners.clear();
                return Err(e);
            }
        };
        self.owners
            .retain(|id, owner| jobs.iter().any(|j| &j.offer.id == id && j == &owner.offer));
        let bearer_hash = bearer
            .as_ref()
            .map(|b| <[u8; 32]>::from(Sha256::digest(b.as_bytes())));
        if bearer_hash != self.bearer_hash {
            for owner in self.owners.values_mut() {
                owner.mailbox = Mailbox::new(
                    &owner.offer,
                    Side::Owner,
                    bearer.as_deref().context("missing invitation bearer")?,
                )?;
            }
            self.bearer_hash = bearer_hash;
        }
        for offer in jobs {
            if !self.owners.contains_key(&offer.offer.id) {
                self.owners.insert(
                    offer.offer.id.clone(),
                    Owner::new(
                        offer,
                        bearer.as_deref().context("missing invitation bearer")?,
                    )?,
                );
            }
        }
        ensure!(self.owners.len() <= 128, "too many active invitations");
        let ids: Vec<_> = self.owners.keys().cloned().collect();
        let begin = self.cursor.min(ids.len());
        let end = (begin + 8).min(ids.len());
        self.cursor = if end == ids.len() { 0 } else { end };
        let work: Vec<_> = ids[begin..end]
            .iter()
            .filter_map(|id| {
                if self.owners[id].retry_at > Instant::now() {
                    return None;
                }
                Some((id.clone(), self.owners.remove(id).expect("selected owner")))
            })
            .collect();
        let mut work = stream::iter(work)
            .map(|(id, mut owner)| {
                let store = store.clone();
                let slots = self.slots.clone();
                async move {
                    let result = owner.tick(store, slots).await;
                    (id, owner, result)
                }
            })
            .buffer_unordered(4);
        let mut progressed = self.cursor != 0;
        while let Some((id, mut owner, result)) = work.next().await {
            let pause = match result {
                Ok(value) => {
                    progressed |= value;
                    owner.retry_delay = Duration::ZERO;
                    if value {
                        Duration::ZERO
                    } else if owner.live.is_empty() {
                        Duration::from_secs(1)
                    } else {
                        Duration::from_millis(250)
                    }
                }
                Err(_) => {
                    owner.retry_delay = (owner.retry_delay * 2)
                        .max(Duration::from_millis(500))
                        .min(Duration::from_secs(10));
                    owner.retry_delay
                }
            };
            owner.retry_at = Instant::now() + pause;
            self.owners.insert(id, owner);
        }
        Ok(progressed)
    }
}

#[cfg(test)]
mod tests;
