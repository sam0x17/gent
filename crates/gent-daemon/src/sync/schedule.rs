//! Exact local dirty sets; relay hints never advance stream cursors.
use super::*;
use gent_protocol::transport_watch::{Interest, MAX_INTERESTS};
use std::collections::BTreeSet;

#[derive(Default)]
pub(super) struct Hints(Mutex<State>);
#[derive(Default)]
struct State {
    interests: Vec<Interest>,
    dirty: BTreeSet<Vec<u8>>,
    full: bool,
    control: bool,
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
    cursor: usize,
}
impl Default for Schedule {
    fn default() -> Self {
        Self {
            next_full: Instant::now(),
            pending: BTreeSet::new(),
            cursor: 0,
        }
    }
}
impl Schedule {
    pub(super) fn select(
        &mut self,
        streams: &[Stream],
        hints: &Hints,
        queued: BTreeSet<Vec<u8>>,
        retries: &BTreeMap<Vec<u8>, Retry>,
        connected: bool,
    ) -> Vec<Stream> {
        let now = Instant::now();
        let (full, dirty) = hints.take();
        self.pending.extend(dirty);
        self.pending.extend(queued);
        self.pending.extend(
            streams
                .iter()
                .filter(|s| s.configuration)
                .map(|s| s.group.clone()),
        );
        if full || now >= self.next_full {
            self.pending.extend(streams.iter().map(|s| s.group.clone()));
            // Small deterministic per-process jitter avoids synchronized scans.
            self.next_full = now
                + Duration::from_secs(if connected {
                    30 + u64::from(std::process::id() % 7)
                } else {
                    5
                });
        }
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
        for (_, s) in &selected {
            self.pending.remove(&s.group);
        }
        selected.into_iter().map(|(_, s)| s).collect()
    }
    pub(super) fn again(&mut self, group: Vec<u8>) {
        self.pending.insert(group);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuously_queued_peers_cannot_starve_later_streams() {
        let streams: Vec<_> = (0..100)
            .map(|i| Stream {
                group: vec![i],
                outgoing: true,
                configuration: false,
            })
            .collect();
        let queued = streams
            .iter()
            .map(|s| s.group.clone())
            .collect::<BTreeSet<_>>();
        let hints = Hints::default();
        let mut schedule = Schedule::default();
        let mut seen = BTreeSet::new();
        for _ in 0..4 {
            let selected =
                schedule.select(&streams, &hints, queued.clone(), &BTreeMap::new(), true);
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
                .select(&streams, &hints, BTreeSet::new(), &retries, true)
                .len(),
            3
        );
        assert!(
            schedule
                .select(&streams, &hints, BTreeSet::new(), &retries, true)
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
            schedule.select(&streams, &hints, BTreeSet::new(), &retries, true)[0].group,
            vec![1]
        );
        schedule.next_full = Instant::now();
        assert_eq!(
            schedule
                .select(&streams, &hints, BTreeSet::new(), &retries, true)
                .len(),
            3
        );
    }
}
