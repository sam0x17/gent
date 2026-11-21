//! Direct endpoint keys are bound to node identities by authenticated MLS records.
//! A socket key never grants authority beyond the current signed membership.
use super::*;
use crate::messages::Event;
use gent_crypto::stream::{Packet, Receipt};
use iroh::{EndpointAddr, EndpointId, TransportAddr};
use serde::{Deserialize, Serialize};
mod channel;
mod helpers;
pub(crate) use channel::{HelperAuthority, HelperChannel, HelperPeer};
pub(super) use helpers::CertificateCache;
pub(crate) use helpers::{HelperCandidate, HelperOffer, HelperRegistration};

pub(crate) enum NativeTarget {
    Advertised(EndpointAddr),
    HelperOnly(EndpointId),
}

impl NativeTarget {
    pub(crate) fn id(&self) -> EndpointId {
        match self {
            Self::Advertised(address) => address.id,
            Self::HelperOnly(id) => *id,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    pub endpoint: EndpointAddr,
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) offer: Option<HelperOffer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) registrations: Vec<HelperRegistration>,
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
        CREATE TABLE IF NOT EXISTS direct_advertised(peer TEXT PRIMARY KEY REFERENCES network_links(peer) ON DELETE CASCADE,endpoint TEXT NOT NULL,expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS direct_local(singleton INTEGER PRIMARY KEY CHECK(singleton=1),peer TEXT NOT NULL,peer_key BLOB NOT NULL,endpoint TEXT NOT NULL,address BLOB NOT NULL,expires_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS direct_endpoint ON direct_peers(endpoint);
        CREATE VIEW IF NOT EXISTS direct_sources AS
            SELECT d.peer,d.peer_key,d.endpoint,d.address,d.expires_at,0 AS local
            FROM direct_peers d JOIN network_links l ON d.peer=l.peer AND d.peer_key=l.peer_key
            UNION ALL SELECT peer,peer_key,endpoint,address,expires_at,1 FROM direct_local;")?;
    Ok(())
}
pub(super) fn address(
    db: &Connection,
    peer: &str,
    key: &[u8],
    timestamp: i64,
) -> Result<Option<EndpointAddr>> {
    let bytes: Option<Vec<u8>> = db.query_row(
        "SELECT d.address FROM direct_peers d JOIN network_links l
         ON l.peer=d.peer AND l.peer_key=d.peer_key WHERE d.peer=?1 AND d.peer_key=?2 AND d.expires_at>?3",
        params![peer,key,timestamp], |row| row.get(0)
    ).optional()?;
    bytes
        .map(|b| Ok(serde_json::from_slice::<Address>(&b)?.endpoint))
        .transpose()
}

impl StoreSession<'_> {
    pub(super) fn native_target(&self, peer: &str) -> Result<Option<NativeTarget>> {
        self.require_local_membership()?;
        let Some(source) = self.helper_source(peer, false)? else {
            return Ok(None);
        };
        if peer == self.identity.node.id()
            || !self
                .endpoint_binding(source.address.endpoint.id, false)?
                .is_some_and(|(node, _)| node == peer)
        {
            return Ok(None);
        }
        Ok(Some(if source.expires_at > self.timestamp {
            NativeTarget::Advertised(source.address.endpoint)
        } else {
            NativeTarget::HelperOnly(source.address.endpoint.id)
        }))
    }
    pub(super) fn direct_address(&self, peer: &str) -> Result<Option<EndpointAddr>> {
        let node = self
            .state
            .state()
            .nodes
            .get(peer)
            .context("unknown direct peer")?;
        self.state
            .authorize_node(peer, &node.signing_key, self.timestamp as u64)?;
        address(self.db, peer, &node.signing_key, self.timestamp)
    }

    pub(super) fn receive_direct(&self, peer: &str, mut address: Address) -> Result<()> {
        address.validate()?;
        ensure!(
            address.expires_at <= self.timestamp + 600,
            "direct address expiry too far ahead"
        );
        let link_key: Vec<u8> = self.db.query_row(
            "SELECT peer_key FROM network_links WHERE peer=?1",
            [peer],
            |r| r.get(0),
        )?;
        super::network::active_peer(&self.state, peer, &link_key, self.timestamp)?;
        ensure!(
            peer != self.identity.node.id(),
            "remote direct address claimed local identity"
        );
        address.validate_helpers(peer, self.timestamp, None)?;
        if address.expires_at <= self.timestamp {
            // MLS records arrive in order. Even a delayed replacement ends the
            // old endpoint's authority to keep an established helper session.
            self.db.execute(
                "DELETE FROM direct_peers WHERE peer=?1 AND endpoint<>?2",
                params![peer, address.endpoint.id.to_string()],
            )?;
            // A delayed same-endpoint withdrawal/rotation also supersedes a
            // retained service. An aged record can remove earlier evidence,
            // but cannot introduce a new service, registration, or locator.
            if let Some(old) = self.helper_source(peer, false)? {
                let mut retained = old.address;
                if retained.offer != address.offer {
                    retained.offer = None;
                }
                retained.registrations.retain(|r| {
                    address.registrations.iter().any(|new| {
                        r.helper_node == new.helper_node
                            && r.generation == new.generation
                            && r.url == new.url
                    })
                });
                retained.expires_at = address.expires_at.min(old.expires_at);
                self.db.execute(
                    "UPDATE direct_peers SET address=?2, expires_at=?3 WHERE peer=?1",
                    params![peer, serde_json::to_vec(&retained)?, retained.expires_at],
                )?;
            }
            return Ok(());
        }
        self.db.execute("INSERT INTO direct_peers VALUES(?1,?2,?3,?4,?5) ON CONFLICT(peer) DO UPDATE SET peer_key=excluded.peer_key,endpoint=excluded.endpoint,address=excluded.address,expires_at=excluded.expires_at",
            params![peer,link_key,address.endpoint.id.to_string(),serde_json::to_vec(&address)?,address.expires_at])?;
        Ok(())
    }
}
impl Store {
    pub(crate) fn direct_allowed(&self, endpoint: EndpointId) -> Result<()> {
        self.direct_binding(endpoint, true).map(|_| ())
    }
    /// A live authenticated session can outlive an idle address advertisement.
    /// Removal, authority expiry and key replacement still end its admission.
    pub(crate) fn direct_binding(
        &self,
        endpoint: EndpointId,
        fresh: bool,
    ) -> Result<(String, gent_crypto::PublicKey)> {
        ensure!(
            matches!(self.direct_settings()?.direct, config::Direct::Auto),
            "direct transport disabled"
        );
        let tx = self.db.unchecked_transaction()?;
        let session = self.network_session(&tx, self.identity.state(&tx)?);
        session.require_local_membership()?;
        session
            .endpoint_binding(endpoint, fresh)?
            .context("unrecognized direct endpoint")
    }
    pub(crate) fn direct_settings(&self) -> Result<config::Transport> {
        config::load(&self.home)?.transport()
    }
    #[cfg(test)]
    pub(crate) fn advertise_direct(&mut self, endpoint: EndpointAddr) -> Result<()> {
        self.advertise_direct_with_helpers(endpoint, None, vec![])
    }
    pub(crate) fn advertise_direct_with_helpers(
        &mut self,
        endpoint: EndpointAddr,
        offer: Option<HelperOffer>,
        registrations: Vec<HelperRegistration>,
    ) -> Result<()> {
        if matches!(self.direct_settings()?.direct, config::Direct::Off) {
            return Ok(());
        }
        let tx = self.db.unchecked_transaction()?;
        let session = self.network_session(&tx, self.identity.state(&tx)?);
        session.require_local_membership()?;
        let mut address = Address {
            endpoint,
            expires_at: session.timestamp + 180,
            offer,
            registrations,
        };
        address.validate()?;
        let local_id = self.identity.node.id();
        address.validate_helpers(local_id, session.timestamp, Some(&self.direct_certs))?;
        tx.execute(
            "INSERT INTO direct_local VALUES(1,?1,?2,?3,?4,?5)
            ON CONFLICT(singleton) DO UPDATE SET peer=excluded.peer,peer_key=excluded.peer_key,
                endpoint=excluded.endpoint,address=excluded.address,expires_at=excluded.expires_at
            WHERE direct_local.expires_at<=?6 OR direct_local.peer<>excluded.peer
                OR direct_local.peer_key<>excluded.peer_key
                OR json_remove(CAST(direct_local.address AS TEXT),'$.expires_at')
                   <>json_remove(CAST(excluded.address AS TEXT),'$.expires_at')",
            params![
                local_id,
                self.identity.node.public_key().as_slice(),
                address.endpoint.id.to_string(),
                serde_json::to_vec(&address)?,
                address.expires_at,
                session.timestamp + 90
            ],
        )?;
        let plain = serde_json::to_string(&address.endpoint)?;
        let mut topology = address.topology();
        let peers = tx
            .prepare("SELECT peer,peer_key FROM network_links ORDER BY peer")?
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, gent_crypto::PublicKey>(1)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (peer, key) in peers {
            let version = session.wire_version(&peer)?;
            if version < 5 {
                continue;
            }
            let advertised = if version >= crate::messages::wire::HELPERS_VERSION {
                topology.recipient_key = address.offer.as_ref().map(|_| key);
                topology.encode(&plain)?
            } else {
                plain.clone()
            };
            let previous: Option<(String, i64)> = tx
                .query_row(
                    "SELECT endpoint,expires_at FROM direct_advertised WHERE peer=?1",
                    [&peer],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((saved, expiry)) = previous {
                if saved == advertised && expiry > session.timestamp + 90 {
                    continue;
                }
                if saved == advertised
                    || (version >= crate::messages::wire::HELPERS_VERSION
                        && topology.passive_withdrawal(&saved, &session, &self.direct_certs)?)
                {
                    let active: bool = tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM network_events WHERE peer=?1 AND cancelled=0)
                         OR EXISTS(SELECT 1 FROM node_presence WHERE peer=?1 AND
                           (issued_at>=?2 OR verified_at>=?2))",
                        params![peer, session.timestamp - 30],
                        |r| r.get(0),
                    )?;
                    if !active {
                        continue;
                    }
                }
            }
            let queued:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM network_events WHERE peer=?1 AND cancelled=0 AND json_extract(CAST(body AS TEXT),'$.event.kind')='direct')",[&peer],|r|r.get(0))?;
            if queued
                || super::network::active_peer(&session.state, &peer, &key, session.timestamp)
                    .is_err()
            {
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

    pub(crate) fn direct_target(&self, group: &[u8]) -> Result<Option<NativeTarget>> {
        ensure!(
            matches!(self.direct_settings()?.direct, config::Direct::Auto),
            "direct transport disabled"
        );
        let peer: String = self.db.query_row(
            "SELECT peer FROM network_links WHERE outgoing=?1",
            [group],
            |row| row.get(0),
        )?;
        self.network_session(&self.db, self.identity.state(&self.db)?)
            .native_target(&peer)
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
