//! STREAM frames, unlike QUIC byte counters, exclude discovery, pings and ACKs.
use super::{Connection, health::TransportPath};
use iroh::TransportAddr;

#[derive(Default, Clone, Copy, PartialEq, Eq)]
struct Counts {
    total: u64,
    ip: u64,
    relay: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Ip,
    Relay,
    Mixed,
    Unknown,
}

impl Counts {
    fn lost_since(self, old: Self) -> bool {
        self.total < old.total || self.ip < old.ip || self.relay < old.relay
    }

    fn since(self, old: Self) -> Kind {
        if self.lost_since(old) {
            return Kind::Unknown;
        }
        let (total, ip, relay) = (
            self.total - old.total,
            self.ip - old.ip,
            self.relay - old.relay,
        );
        // Path snapshots can race with arrival or a disappearing path. Attribute
        // frames only when every connection-wide STREAM frame is accounted for.
        match (total, ip, relay) {
            (0, _, _) => Kind::Unknown,
            (n, i, 0) if n == i => Kind::Ip,
            (n, 0, r) if n == r => Kind::Relay,
            (n, i, r) if i > 0 && r > 0 && i.checked_add(r) == Some(n) => Kind::Mixed,
            _ => Kind::Unknown,
        }
    }
}

#[derive(Default, Clone, Copy)]
pub(super) struct Frames {
    tx: Counts,
    rx: Counts,
}

impl Frames {
    pub(super) fn read(conn: &Connection) -> Self {
        let totals = conn.stats();
        let mut snapshot = Self::default();
        snapshot.tx.total = totals.frame_tx.stream;
        snapshot.rx.total = totals.frame_rx.stream;
        for path in conn.paths().iter() {
            let (tx, rx) = match path.remote_addr() {
                TransportAddr::Ip(_) => (&mut snapshot.tx.ip, &mut snapshot.rx.ip),
                TransportAddr::Relay(_) => (&mut snapshot.tx.relay, &mut snapshot.rx.relay),
                _ => continue,
            };
            let stats = path.stats();
            *tx += stats.frame_tx.stream;
            *rx += stats.frame_rx.stream;
        }
        snapshot
    }

    pub(super) fn exchange(self, old: Self, helper: Option<&str>) -> TransportPath {
        let kind = match (self.tx.since(old.tx), self.rx.since(old.rx)) {
            (Kind::Unknown, _) | (_, Kind::Unknown) => Kind::Unknown,
            (tx, rx) if tx == rx => rx,
            _ => Kind::Mixed,
        };
        transport(kind, helper)
    }

    pub(super) fn received(self, old: Self, helper: Option<&str>) -> TransportPath {
        // A stream may be buffered before accept_bi or the next framed read. A
        // single path across the entire receive history still identifies it.
        if self.rx.lost_since(old.rx) {
            return TransportPath::QuicUnknown;
        }
        let lifetime = self.rx.since(Counts::default());
        let kind = match lifetime {
            Kind::Ip | Kind::Relay => lifetime,
            Kind::Mixed if old.rx == Counts::default() => Kind::Mixed,
            // Once there are multiple receive paths, counts per socket do not
            // identify which frames in the read buffer belong to this batch.
            _ => Kind::Unknown,
        };
        transport(kind, helper)
    }
}

fn transport(kind: Kind, helper: Option<&str>) -> TransportPath {
    match (kind, helper) {
        (Kind::Ip, _) => TransportPath::DirectQuic,
        (Kind::Relay, Some(id)) => TransportPath::ClusterHelper {
            helper_id: id.to_owned(),
        },
        (Kind::Relay, None) => TransportPath::ConfiguredRelay,
        (Kind::Mixed, _) => TransportPath::QuicMixed,
        (Kind::Unknown, _) => TransportPath::QuicUnknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use TransportPath::*;

    fn counts(total: u64, ip: u64, relay: u64) -> Counts {
        Counts { total, ip, relay }
    }

    #[test]
    fn exchange_accounts_for_both_directions_before_naming_a_route() {
        let old = Frames::default();
        let ip = counts(3, 3, 0);
        let relay = counts(4, 0, 4);
        let mixed = counts(5, 3, 2);
        for (tx, rx, expected) in [
            (ip, ip, DirectQuic),
            (
                relay,
                relay,
                ClusterHelper {
                    helper_id: "h".into(),
                },
            ),
            (ip, relay, QuicMixed),
            (relay, ip, QuicMixed),
            (ip, mixed, QuicMixed),
            (mixed, mixed, QuicMixed),
            (Counts::default(), ip, QuicUnknown),
            (relay, Counts::default(), QuicUnknown),
            (mixed, counts(4, 2, 1), QuicUnknown),
            (counts(2, 1, 2), ip, QuicUnknown),
        ] {
            assert_eq!(Frames { tx, rx }.exchange(old, Some("h")), expected);
        }
        assert_eq!(
            Frames {
                tx: relay,
                rx: relay
            }
            .exchange(old, None),
            ConfiguredRelay
        );
        // Prior traffic on another path need not have carried this exchange.
        let switched = counts(7, 3, 4);
        assert_eq!(
            Frames {
                tx: switched,
                rx: switched
            }
            .exchange(Frames { tx: ip, rx: ip }, None),
            ConfiguredRelay
        );
    }

    #[test]
    fn any_counter_regression_invalidates_its_direction_independently() {
        let prior = counts(10, 7, 3);
        let old = Frames {
            tx: prior,
            rx: prior,
        };
        let progressed = counts(11, 8, 3);
        for reset in [
            counts(9, 7, 3),   // connection total regressed
            counts(12, 6, 6),  // IP regressed while relay grew
            counts(12, 10, 2), // relay regressed while IP grew
            counts(12, 12, 0), // a vanished relay now looks IP-only over the lifetime
        ] {
            assert_eq!(
                Frames {
                    tx: reset,
                    rx: progressed
                }
                .exchange(old, None),
                QuicUnknown
            );
            let inbound = Frames {
                tx: progressed,
                rx: reset,
            };
            assert_eq!(inbound.exchange(old, Some("h")), QuicUnknown);
            assert_eq!(inbound.received(old, Some("h")), QuicUnknown);
        }
        let outbound_reset = Frames {
            tx: Counts::default(),
            rx: counts(4, 4, 0),
        };
        let before = Frames {
            tx: prior,
            rx: counts(3, 3, 0),
        };
        assert_eq!(outbound_reset.exchange(before, None), QuicUnknown);
        assert_eq!(outbound_reset.received(before, None), DirectQuic);
    }

    #[test]
    fn inbound_uses_receive_history_when_the_batch_was_already_buffered() {
        let observed = |rx| Frames {
            tx: Counts::default(),
            rx,
        };
        let ip = observed(counts(4, 4, 0));
        let relay = observed(counts(4, 0, 4));
        let mixed = observed(counts(5, 4, 1));
        assert_eq!(ip.received(ip, Some("h")), DirectQuic);
        assert_eq!(relay.received(relay, None), ConfiguredRelay);
        assert_eq!(
            relay.received(relay, Some("h")),
            ClusterHelper {
                helper_id: "h".into()
            }
        );
        assert_eq!(mixed.received(Frames::default(), Some("h")), QuicMixed);
        assert_eq!(mixed.received(ip, Some("h")), QuicUnknown);
        assert_eq!(mixed.received(mixed, Some("h")), QuicUnknown);
        let partial = observed(counts(4, 3, 0));
        assert_eq!(partial.received(partial, None), QuicUnknown);
        // Connection and path counters can be read on either side of new
        // traffic. Subtracting two inconsistent snapshots can mimic a path.
        assert_eq!(
            observed(counts(1, 2, 1)).received(observed(counts(0, 2, 0)), None),
            QuicUnknown
        );
        assert_eq!(
            Frames::default().received(Frames::default(), None),
            QuicUnknown
        );
    }
}
