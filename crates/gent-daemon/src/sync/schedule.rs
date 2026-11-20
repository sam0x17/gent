//! Exact local dirty sets; relay hints never advance stream cursors.
use super::*;
use gent_protocol::transport_watch::{Interest, MAX_INTERESTS};

#[derive(Default)]
pub(super) struct Hints(Mutex<State>);
#[derive(Default)]
struct State {
    interests: Vec<Interest>,
    dirty: BTreeSet<Vec<u8>>,
    full: bool,
    control: bool,
    reconnected: bool,
}
impl Hints {
    pub(super) fn subscribe(&self, streams: &[Stream]) {
        let interests: Vec<_> = streams
            .iter()
            .take(MAX_INTERESTS)
            .map(|s| Interest {
                mailbox: URL_SAFE_NO_PAD.encode(&s.group),
                outgoing: s.outgoing,
            })
            .collect();
        let mut state = self.0.lock().expect("sync hints poisoned");
        if state.interests != interests {
            state.interests = interests;
            state.full = true;
        }
    }
    pub(super) fn interests(&self) -> Vec<Interest> {
        self.0
            .lock()
            .expect("sync hints poisoned")
            .interests
            .clone()
    }
    pub(super) fn all(&self) {
        let mut state = self.0.lock().expect("sync hints poisoned");
        state.full = true;
        state.control = true;
    }
    pub(super) fn reconnected(&self) {
        let mut state = self.0.lock().expect("sync hints poisoned");
        state.full = true;
        state.control = true;
        state.reconnected = true;
    }
    pub(super) fn take_reconnected(&self) -> bool {
        std::mem::take(&mut self.0.lock().expect("sync hints poisoned").reconnected)
    }
    pub(super) fn control(&self) -> bool {
        std::mem::take(&mut self.0.lock().expect("sync hints poisoned").control)
    }
    pub(super) fn changed(&self, streams: &[Interest]) -> bool {
        let mut state = self.0.lock().expect("sync hints poisoned");
        let mut changed = false;
        for stream in streams {
            if state.interests.contains(stream)
                && let Ok(group) = URL_SAFE_NO_PAD.decode(&stream.mailbox)
            {
                changed |= state.dirty.insert(group);
            }
        }
        changed
    }
    pub(super) fn take(&self) -> (bool, BTreeSet<Vec<u8>>) {
        let mut state = self.0.lock().expect("sync hints poisoned");
        (
            std::mem::take(&mut state.full),
            std::mem::take(&mut state.dirty),
        )
    }
}

pub(super) struct Schedule {
    next_full: Instant,
    pending: BTreeSet<Vec<u8>>,
    peer_repair: BTreeSet<Vec<u8>>,
    cursor: usize,
    pub(super) timed_repair: bool,
}
impl Default for Schedule {
    fn default() -> Self {
        Self {
            next_full: Instant::now(),
            pending: BTreeSet::new(),
            peer_repair: BTreeSet::new(),
            cursor: 0,
            timed_repair: false,
        }
    }
}

pub(super) struct Selection {
    pub(super) streams: Vec<Stream>,
    pub(super) peers: BTreeSet<Vec<u8>>,
}

impl Schedule {
    pub(super) fn select(
        &mut self,
        streams: &[Stream],
        hints: &Hints,
        work: &MailboxWork,
        retries: &BTreeMap<Vec<u8>, Retry>,
        connected: bool,
    ) -> Selection {
        let now = Instant::now();
        let (full, dirty) = hints.take();
        // A reconnect, explicit hint or follow-up to an active transfer can
        // carry a waiting message. Fetch those without a conditional preflight.
        self.timed_repair = now >= self.next_full
            && !full
            && dirty.is_empty()
            && self.pending.is_empty()
            && retries.is_empty();
        self.pending.extend(dirty);
        self.pending.extend(work.ready.iter().cloned());
        if full || now >= self.next_full {
            self.pending.extend(streams.iter().map(|s| s.group.clone()));
            self.peer_repair.extend(
                streams
                    .iter()
                    .filter(|s| {
                        s.outgoing && !s.configuration && work.unconfirmed_data.contains(&s.group)
                    })
                    .map(|s| s.group.clone()),
            );
            // Small deterministic per-process jitter avoids synchronized scans.
            self.next_full = now
                + Duration::from_secs(if connected {
                    30 + u64::from(std::process::id() % 7)
                } else {
                    5
                });
        }
        // A partial peer batch can drain its uploaded suffix on the next turn.
        // Re-read the durable receipt before scheduling another attempt.
        self.peer_repair
            .retain(|g| work.unconfirmed_data.contains(g) && streams.iter().any(|s| &s.group == g));
        self.pending.extend(self.peer_repair.iter().cloned());
        self.pending.extend(
            retries
                .iter()
                .filter(|(_, r)| r.at <= now)
                .map(|(g, _)| g.clone()),
        );
        self.pending
            .retain(|g| streams.iter().any(|s| &s.group == g));
        let selected: Vec<_> = streams
            .iter()
            .enumerate()
            .cycle()
            .skip(self.cursor.min(streams.len()))
            .take(streams.len())
            .filter(|(_, s)| {
                self.pending.contains(&s.group) && retries.get(&s.group).is_none_or(|r| r.at <= now)
            })
            .take(32)
            .map(|(index, s)| (index, s.clone()))
            .collect();
        if let Some((last, _)) = selected.last() {
            self.cursor = (last + 1) % streams.len();
        }
        let mut peers = BTreeSet::new();
        for (_, s) in &selected {
            self.pending.remove(&s.group);
            let repair = self.peer_repair.remove(&s.group)
                || (retries.contains_key(&s.group) && work.unconfirmed_data.contains(&s.group));
            if s.outgoing && !s.configuration && (repair || work.ready.contains(&s.group)) {
                peers.insert(s.group.clone());
            }
        }
        Selection {
            streams: selected.into_iter().map(|(_, s)| s).collect(),
            peers,
        }
    }
    pub(super) fn again(&mut self, group: Vec<u8>) {
        self.pending.insert(group);
    }
    pub(super) fn peer_progress(&mut self, group: Vec<u8>) {
        self.peer_repair.insert(group);
    }
    pub(super) fn next_full(&self) -> Instant {
        self.next_full
    }
    pub(super) fn has_ready(&self, retries: &BTreeMap<Vec<u8>, Retry>) -> bool {
        let now = Instant::now();
        self.pending
            .iter()
            .any(|g| retries.get(g).is_none_or(|r| r.at <= now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn uploaded_streams_wait_for_work_receipt_hint_reconnect_or_safety_deadline() {
        let streams = [Stream {
            group: vec![1],
            outgoing: true,
            configuration: true,
        }];
        let hints = Hints::default();
        hints.subscribe(&streams);
        let mut schedule = Schedule::default();
        let retries = BTreeMap::new();
        let mut select = |queued, connected| {
            schedule
                .select(
                    &streams,
                    &hints,
                    &MailboxWork {
                        ready: queued,
                        ..Default::default()
                    },
                    &retries,
                    connected,
                )
                .streams
                .len()
        };
        assert_eq!(select(BTreeSet::new(), true), 1);
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(select(BTreeSet::new(), true), 0);
        assert_eq!(select(BTreeSet::from([vec![1]]), true), 1);
        assert_eq!(select(BTreeSet::new(), true), 0);
        assert!(hints.changed(&hints.interests()));
        assert_eq!(select(BTreeSet::new(), true), 1);
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(select(BTreeSet::new(), true), 1);
        hints.all();
        assert_eq!(select(BTreeSet::new(), false), 1);
        tokio::time::advance(Duration::from_secs(4)).await;
        assert_eq!(select(BTreeSet::new(), false), 0);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(select(BTreeSet::new(), false), 1);
        hints.reconnected();
        assert!(hints.take_reconnected());
        assert!(!hints.take_reconnected());
        assert_eq!(select(BTreeSet::new(), true), 1);
    }
    #[test]
    fn repair_retries_uploaded_peer_batches_until_durably_confirmed() {
        let stream = Stream {
            group: vec![1],
            outgoing: true,
            configuration: false,
        };
        let streams = std::slice::from_ref(&stream);
        let hints = Hints::default();
        hints.subscribe(streams);
        let mut work = MailboxWork::default();
        work.unconfirmed_data.insert(stream.group.clone());
        let mut schedule = Schedule::default();
        let select = |s: &mut Schedule, w: &MailboxWork| {
            s.select(streams, &hints, w, &BTreeMap::new(), true)
        };
        assert!(select(&mut schedule, &work).peers.contains(&stream.group));
        // A sleeping recipient and a successful cloud upload incur no extra turn.
        assert!(select(&mut schedule, &work).streams.is_empty());
        hints.changed(&hints.interests());
        let hint = select(&mut schedule, &work);
        assert_eq!(hint.streams.len(), 1);
        assert!(hint.peers.is_empty());
        schedule.next_full = Instant::now();
        assert!(select(&mut schedule, &work).peers.contains(&stream.group));
        hints.reconnected();
        assert!(select(&mut schedule, &work).peers.contains(&stream.group));
        // Successful peer batches resume immediately while ciphertext remains.
        schedule.peer_progress(stream.group.clone());
        assert!(select(&mut schedule, &work).peers.contains(&stream.group));
        schedule.peer_progress(stream.group.clone());
        work.unconfirmed_data.clear();
        assert!(select(&mut schedule, &work).streams.is_empty());
    }

    #[test]
    fn continuously_queued_peers_cannot_starve_later_streams() {
        let streams: Vec<_> = (0..100)
            .map(|i| Stream {
                group: vec![i],
                outgoing: true,
                configuration: false,
            })
            .collect();
        let work = MailboxWork {
            ready: streams.iter().map(|s| s.group.clone()).collect(),
            ..Default::default()
        };
        let hints = Hints::default();
        let mut schedule = Schedule::default();
        let mut seen = BTreeSet::new();
        for _ in 0..4 {
            let selected = schedule
                .select(&streams, &hints, &work, &BTreeMap::new(), true)
                .streams;
            assert_eq!(selected.len(), 32);
            seen.extend(selected.into_iter().map(|s| s.group));
        }
        assert_eq!(seen.len(), 100);
    }
    #[test]
    fn exact_stream_hints_ignore_other_nodes_and_full_scan_recovers_lost_hints() {
        let streams: Vec<_> = (0..3)
            .map(|i| Stream {
                group: vec![i],
                outgoing: false,
                configuration: false,
            })
            .collect();
        let hints = Hints::default();
        hints.subscribe(&streams);
        let mut schedule = Schedule::default();
        let retries = BTreeMap::new();
        assert_eq!(
            schedule
                .select(&streams, &hints, &MailboxWork::default(), &retries, true)
                .streams
                .len(),
            3
        );
        assert!(
            schedule
                .select(&streams, &hints, &MailboxWork::default(), &retries, true)
                .streams
                .is_empty()
        );
        assert!(!hints.changed(&[Interest {
            mailbox: URL_SAFE_NO_PAD.encode([99]),
            outgoing: false
        }]));
        hints.changed(&[Interest {
            mailbox: URL_SAFE_NO_PAD.encode([1]),
            outgoing: false,
        }]);
        assert_eq!(
            schedule
                .select(&streams, &hints, &MailboxWork::default(), &retries, true)
                .streams[0]
                .group,
            vec![1]
        );
        schedule.next_full = Instant::now();
        assert_eq!(
            schedule
                .select(&streams, &hints, &MailboxWork::default(), &retries, true)
                .streams
                .len(),
            3
        );
    }
}
