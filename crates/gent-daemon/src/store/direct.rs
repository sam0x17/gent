//! Direct endpoint keys are bound to node identities by authenticated MLS records.
//! A socket key never grants authority beyond the current signed membership.
use super::*;
use crate::messages::Event;
use gent_crypto::stream::{Packet, Receipt};
use iroh::{EndpointAddr, EndpointId, TransportAddr};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    pub endpoint: EndpointAddr,
    pub expires_at: i64,
}
impl Address {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.endpoint.addrs.len() <= 16 && self.expires_at >= 0,
            "invalid direct address"
        );
        for addr in &self.endpoint.addrs {
            match addr {
                TransportAddr::Ip(addr) => ensure!(
                    addr.port() != 0 && !addr.ip().is_unspecified() && !addr.ip().is_multicast(),
                    "invalid direct IP"
                ),
                TransportAddr::Relay(url) => ensure!(
                    url.scheme() == "https"
                        && url.host_str().is_some()
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.query().is_none()
                        && url.fragment().is_none(),
                    "invalid direct relay"
                ),
                _ => anyhow::bail!("unsupported direct transport address"),
            }
        }
        Ok(())
    }
}
pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS direct_peers(peer TEXT PRIMARY KEY REFERENCES network_links(peer) ON DELETE CASCADE,peer_key BLOB NOT NULL,endpoint TEXT NOT NULL,address BLOB NOT NULL,expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS direct_advertised(peer TEXT PRIMARY KEY REFERENCES network_links(peer) ON DELETE CASCADE,endpoint TEXT NOT NULL,expires_at INTEGER NOT NULL);")?;
    Ok(())
}
impl StoreSession<'_> {
    pub(super) fn receive_direct(&self, peer: &str, address: Address) -> Result<()> {
        address.validate()?;
        if address.expires_at <= self.timestamp {
            return Ok(());
        }
        ensure!(
            address.expires_at <= self.timestamp + 600,
            "direct address expiry too far ahead"
        );
        let node = self
            .state
            .state()
            .nodes
            .get(peer)
            .context("unknown direct peer")?;
        self.state
            .authorize_node(peer, &node.signing_key, self.timestamp as u64)?;
        self.db.execute("INSERT INTO direct_peers VALUES(?1,?2,?3,?4,?5) ON CONFLICT(peer) DO UPDATE SET peer_key=excluded.peer_key,endpoint=excluded.endpoint,address=excluded.address,expires_at=excluded.expires_at",
            params![peer,node.signing_key.as_slice(),address.endpoint.id.to_string(),serde_json::to_vec(&address)?,address.expires_at])?;
        Ok(())
    }
}
impl Store {
    pub(crate) fn direct_allowed(&self, endpoint: EndpointId) -> Result<()> {
        ensure!(
            matches!(self.direct_settings()?.direct, config::Direct::Auto),
            "direct transport disabled"
        );
        let state = self.identity.state(&self.db)?;
        let mut query=self.db.prepare("SELECT d.peer,d.peer_key FROM direct_peers d JOIN network_links l ON l.peer=d.peer AND l.peer_key=d.peer_key WHERE d.endpoint=?1 AND d.expires_at>?2")?;
        for row in query.query_map(params![endpoint.to_string(), now()], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })? {
            let (peer, key) = row?;
            if state
                .authorize_node(
                    &peer,
                    &key.try_into()
                        .map_err(|_| anyhow::anyhow!("invalid direct peer key"))?,
                    now() as u64,
                )
                .is_ok()
            {
                return Ok(());
            }
        }
        anyhow::bail!("unrecognized direct endpoint")
    }
    pub(crate) fn direct_settings(&self) -> Result<config::Transport> {
        config::load(&self.home)?.transport()
    }
    pub(crate) fn advertise_direct(&mut self, endpoint: EndpointAddr) -> Result<()> {
        if matches!(self.direct_settings()?.direct, config::Direct::Off) {
            return Ok(());
        }
        let tx = self.db.unchecked_transaction()?;
        let session = self.network_session(&tx, self.identity.state(&tx)?);
        let address = Address {
            endpoint,
            expires_at: session.timestamp + 180,
        };
        address.validate()?;
        let advertised = serde_json::to_string(&address.endpoint)?;
        let peers = tx
            .prepare("SELECT peer FROM network_links ORDER BY peer")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for peer in peers {
            if session.wire_version(&peer)? < 5 {
                continue;
            }
            let recent:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM direct_advertised WHERE peer=?1 AND endpoint=?2 AND expires_at>?3)",params![peer,advertised,session.timestamp+90],|r|r.get(0))?;
            if recent {
                continue;
            }
            let queued:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM network_events WHERE peer=?1 AND cancelled=0 AND json_extract(CAST(body AS TEXT),'$.event.kind')='direct')",[&peer],|r|r.get(0))?;
            if queued {
                continue;
            }
            session.queue(
                &peer,
                uuid::Uuid::new_v4(),
                Event::Direct {
                    address: address.clone(),
                },
                None,
            )?;
            tx.execute("INSERT INTO direct_advertised VALUES(?1,?2,?3) ON CONFLICT(peer) DO UPDATE SET endpoint=excluded.endpoint,expires_at=excluded.expires_at",params![peer,advertised,address.expires_at])?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Current, pinned data-link identity for an authenticated session route.
    pub(crate) fn session_peer(&self, group: &[u8], outgoing: bool) -> Result<String> {
        ensure!(
            matches!(self.direct_settings()?.direct, config::Direct::Auto),
            "direct transport disabled"
        );
        self.data_peer(&self.db, group, outgoing)
    }

    pub(crate) fn direct_target(&self, group: &[u8]) -> Result<Option<EndpointAddr>> {
        let peer = self.session_peer(group, true)?;
        let address:Option<Vec<u8>>=self.db.query_row("SELECT d.address FROM direct_peers d JOIN network_links l ON l.peer=d.peer AND l.peer_key=d.peer_key WHERE d.peer=?1 AND d.expires_at>?2",params![peer,now()],|r|r.get(0)).optional()?;
        address
            .map(|bytes| {
                serde_json::from_slice::<Address>(&bytes)
                    .map(|a| a.endpoint)
                    .map_err(Into::into)
            })
            .transpose()
    }
    pub(crate) fn direct_receive(
        &mut self,
        endpoint: EndpointId,
        group: &[u8],
        packets: Vec<Packet>,
    ) -> Result<Receipt> {
        let peer = self.session_peer(group, false)?;
        let allowed:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM direct_peers d JOIN network_links l ON l.peer=d.peer AND l.peer_key=d.peer_key WHERE d.peer=?1 AND d.endpoint=?2 AND d.expires_at>?3)",params![peer,endpoint.to_string(),now()],|r|r.get(0))?;
        ensure!(allowed, "unrecognized direct endpoint");
        self.receive_session_packets(group, packets)
    }

    pub(crate) fn node_session_receive(
        &mut self,
        peer: &str,
        group: &[u8],
        packets: Vec<Packet>,
    ) -> Result<Receipt> {
        ensure!(
            self.session_peer(group, false)? == peer,
            "session peer mismatch"
        );
        self.receive_session_packets(group, packets)
    }

    fn receive_session_packets(&mut self, group: &[u8], packets: Vec<Packet>) -> Result<Receipt> {
        let next = self.data_next(group)?;
        if let Some(first) = packets.first() {
            // A restored reader cannot accept a suffix whose prefix it lost.
            ensure!(first.group() == group, "session group mismatch");
            ensure!(
                first.sequence() <= next,
                "session prefix missing; mailbox reconciliation required"
            );
        }
        for packet in packets {
            ensure!(
                packet.group() == group,
                "direct packet belongs to another stream"
            );
            self.data_receive(&packet)?;
        }
        self.transport_receipt(group, false)
    }
}
