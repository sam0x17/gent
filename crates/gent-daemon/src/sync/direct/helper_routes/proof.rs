//! A nonce echo on the application connection, independent of its stream lanes.
//! Each endpoint measures its own round trip before admitting application work.
use super::*;
use iroh::{TransportAddr, endpoint::PathId};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, broadcast};

const REQUEST: u8 = 1;
const RESPONSE: u8 = 2;
const SIZE: usize = 50;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(super) enum PathKind {
    Direct,
    Helper,
}

impl PathKind {
    fn code(self) -> u8 {
        match self {
            Self::Direct => 1,
            Self::Helper => 2,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Selected {
    kind: PathKind,
    id: PathId,
}

fn selected(conn: &Connection, offer: &HelperOffer) -> Option<Selected> {
    let paths = conn.paths();
    let path = paths.iter().find(|p| p.is_selected())?;
    let kind = match path.remote_addr() {
        TransportAddr::Ip(_) => PathKind::Direct,
        TransportAddr::Relay(url) if offer.urls.contains(url) => PathKind::Helper,
        _ => return None,
    };
    Some(Selected {
        kind,
        id: path.id(),
    })
}

#[derive(Clone, Copy)]
struct Frames {
    total: [u64; 2],
    path: [u64; 2],
}

impl Frames {
    fn snapshot(conn: &Connection, id: PathId) -> Option<Self> {
        let paths = conn.paths();
        let path = paths.iter().find(|p| p.id() == id)?.stats();
        let total = conn.stats();
        Some(Self {
            total: [total.frame_tx.datagram, total.frame_rx.datagram],
            path: [path.frame_tx.datagram, path.frame_rx.datagram],
        })
    }

    fn carried_echo(self, before: Self) -> bool {
        (0..2).all(|i| {
            let delta = self.total[i].checked_sub(before.total[i]);
            delta.is_some_and(|n| n > 0) && self.path[i].checked_sub(before.path[i]) == delta
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct Sample {
    route: Selected,
    pub(super) rtt: Duration,
    pub(super) at: Instant,
}
impl Sample {
    pub(super) fn kind(self) -> PathKind {
        self.route.kind
    }
}

#[derive(Default)]
struct History {
    last: Option<Sample>,
    rtts: std::collections::VecDeque<Duration>,
}

impl History {
    fn record(&mut self, route: Selected, at: Instant, rtt: Duration) -> Sample {
        if self
            .last
            .is_none_or(|s| s.route != route || s.at.elapsed() > SAMPLE_TTL * 3)
        {
            self.rtts.clear();
        }
        if self.rtts.len() == 3 {
            self.rtts.pop_front();
        }
        self.rtts.push_back(rtt);
        let mut sorted: Vec<_> = self.rtts.iter().copied().collect();
        sorted.sort_unstable();
        let sample = Sample {
            route,
            at,
            rtt: sorted[sorted.len() / 2],
        };
        self.last = Some(sample);
        sample
    }
}

pub(super) struct Proof {
    pub(super) conn: Connection,
    offer: Arc<HelperOffer>,
    tag: [u8; 32],
    responses: broadcast::Sender<[u8; SIZE]>,
    history: Mutex<History>,
    serial: AsyncMutex<()>,
    responder: JoinHandle<()>,
}

impl Drop for Proof {
    fn drop(&mut self) {
        self.responder.abort();
        self.conn.close(0u32.into(), b"helper route released");
    }
}

impl Proof {
    pub(super) fn start(
        conn: Connection,
        offer: Arc<HelperOffer>,
        active: tokio::sync::watch::Receiver<bool>,
    ) -> Self {
        let tag = Sha256::new()
            .chain_update(b"gent/helper-path/1")
            .chain_update(offer.generation)
            .chain_update(offer.helper_node.as_bytes())
            .finalize()
            .into();
        let (responses, _) = broadcast::channel(4);
        let responder = tokio::spawn(respond(
            conn.clone(),
            offer.clone(),
            tag,
            responses.clone(),
            active,
        ));
        Self {
            conn,
            offer,
            tag,
            responses,
            history: Mutex::default(),
            serial: AsyncMutex::new(()),
            responder,
        }
    }

    pub(super) fn selected(&self) -> Option<PathKind> {
        selected(&self.conn, &self.offer).map(|p| p.kind)
    }

    pub(super) fn cached(&self) -> Option<Sample> {
        let last = self.history.lock().expect("path sample poisoned").last?;
        (last.at.elapsed() < SAMPLE_TTL
            && Some(last.route) == selected(&self.conn, &self.offer)
            && self.conn.close_reason().is_none())
        .then_some(last)
    }

    pub(super) async fn measure(&self) -> Option<Sample> {
        let _guard = self.serial.lock().await;
        if let Some(sample) = self.cached() {
            return Some(sample);
        }
        let mut replies = self.responses.subscribe();
        // Retry once for a lost datagram or asymmetry during direct cutover.
        for wait in [Duration::from_millis(350), Duration::from_millis(850)] {
            let route = selected(&self.conn, &self.offer)?;
            let mut request = [0; SIZE];
            request[0] = REQUEST;
            request[1..33].copy_from_slice(&self.tag);
            request[33] = route.kind.code();
            request[34..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
            let before = Frames::snapshot(&self.conn, route.id)?;
            let at = Instant::now();
            self.conn.send_datagram(request.to_vec().into()).ok()?;
            let response = tokio::time::timeout(wait, async {
                loop {
                    let reply = replies.recv().await.ok()?;
                    if reply[34..] == request[34..] {
                        return Some(reply);
                    }
                }
            })
            .await;
            if let Ok(Some(reply)) = response
                && reply[33] == route.kind.code()
                && Some(route) == selected(&self.conn, &self.offer)
                && Frames::snapshot(&self.conn, route.id)?.carried_echo(before)
            {
                let sample = self.history.lock().expect("path sample poisoned").record(
                    route,
                    at,
                    at.elapsed(),
                );
                return Some(sample);
            }
        }
        None
    }
}

async fn respond(
    conn: Connection,
    offer: Arc<HelperOffer>,
    tag: [u8; 32],
    replies: broadcast::Sender<[u8; SIZE]>,
    mut active: tokio::sync::watch::Receiver<bool>,
) {
    let mut paths = conn.paths_stream();
    loop {
        if !*active.borrow() && selected(&conn, &offer).is_none_or(|s| s.kind != PathKind::Direct) {
            conn.close(0u32.into(), b"withdrawn helper");
            return;
        }
        let packet = tokio::select! {
            result=active.changed()=>{ if result.is_err() {break;} continue; }
            path=paths.next(),if !*active.borrow()=>{ if path.is_none(){break;} continue; }
            result=conn.read_datagram()=>match result { Ok(p)=>p, Err(_)=>break }
        };
        let Ok(mut frame) = <[u8; SIZE]>::try_from(packet.as_ref()) else {
            continue;
        };
        if frame[1..33] != tag {
            continue;
        }
        match frame[0] {
            REQUEST => {
                let Some(path) = selected(&conn, &offer) else {
                    continue;
                };
                frame[0] = RESPONSE;
                frame[33] = path.kind.code();
                if conn.send_datagram(frame.to_vec().into()).is_err() {
                    break;
                }
            }
            RESPONSE => {
                let _ = replies.send(frame);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_requires_all_echo_datagrams_on_the_selected_path_in_both_directions() {
        let before = Frames {
            total: [3, 8],
            path: [2, 5],
        };
        assert!(
            Frames {
                total: [5, 9],
                path: [4, 6]
            }
            .carried_echo(before)
        );
        for after in [
            Frames {
                total: [5, 9],
                path: [3, 6],
            },
            Frames {
                total: [5, 9],
                path: [4, 5],
            },
            Frames {
                total: [3, 9],
                path: [2, 6],
            },
            Frames {
                total: [1, 9],
                path: [0, 6],
            },
        ] {
            assert!(!after.carried_echo(before));
        }
    }
}
