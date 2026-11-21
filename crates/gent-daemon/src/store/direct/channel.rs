//! A native grant belongs to one uninterrupted registration. The locator's
//! signed deadline controls enrollment; only a live grant and a new peer
//! signature on the application connection can authorize work after it.
use super::*;
use gent_crypto::PublicKey;
use std::{ops::RangeInclusive, sync::Arc};
use tokio::{sync::watch, time::Instant};

pub(crate) type HelperAuthority = (HelperOffer, EndpointId, PublicKey, i64);
type Binding = (String, PublicKey);

#[derive(Clone)]
pub(crate) struct HelperChannel {
    pub local: EndpointId,
    pub peer: EndpointId,
    pub offer: Arc<HelperOffer>,
    pub operator: (EndpointId, PublicKey),
    pub lease: watch::Receiver<Option<Instant>>,
}

impl HelperChannel {
    fn live(&self) -> bool {
        self.lease.has_changed().is_ok()
            && self.lease.borrow().is_some_and(|end| end > Instant::now())
    }
}

#[derive(Clone)]
pub(crate) struct HelperPeer {
    channel: HelperChannel,
    peer: Binding,
    certificate: RangeInclusive<i64>,
}

impl HelperPeer {
    pub(crate) fn live(&self) -> bool {
        self.channel.live()
    }

    pub(crate) fn endpoint(&self) -> EndpointId {
        self.channel.peer
    }
}

impl StoreSession<'_> {
    fn service_source(&self, offer: &HelperOffer) -> Result<Option<helpers::Source>> {
        let Some(source) = self.helper_source(&offer.helper_node, false)? else {
            return Ok(None);
        };
        if !source
            .address
            .offer
            .as_ref()
            .is_some_and(|current| current.matches_service(offer))
            || !self
                .endpoint_binding(source.address.endpoint.id, false)?
                .is_some_and(|(node, key)| node == offer.helper_node && key == source.key)
        {
            return Ok(None);
        }
        Ok(Some(source))
    }

    fn channel_binding(&self, channel: &HelperChannel) -> Result<Binding> {
        ensure!(channel.live(), "helper registration expired");
        let source = self
            .service_source(&channel.offer)?
            .context("helper offer superseded")?;
        ensure!(
            (source.address.endpoint.id, source.key) == channel.operator,
            "helper identity changed"
        );
        let own = self
            .endpoint_binding(channel.local, false)?
            .context("local endpoint withdrawn")?;
        ensure!(
            own.0 == self.identity.node.id() && own.1 == self.identity.node.public_key(),
            "local endpoint changed"
        );
        let peer = self
            .endpoint_binding(channel.peer, false)?
            .context("peer endpoint withdrawn")?;
        ensure!(peer.0 != own.0, "expected a remote peer");
        Ok(peer)
    }

    pub(in crate::store) fn authorize_helper_peer(
        &self,
        pin: &HelperPeer,
        expected: Option<&str>,
    ) -> Result<()> {
        // Both the native session entry point and the file transaction check
        // current local transport policy before delegating here.
        ensure!(
            pin.certificate.contains(&self.timestamp),
            "helper certificate expired"
        );
        let binding = self.channel_binding(&pin.channel)?;
        ensure!(
            binding == pin.peer && expected.is_none_or(|peer| peer == binding.0),
            "helper session peer changed"
        );
        ensure!(pin.live(), "helper registration expired");
        Ok(())
    }

    fn channel_transcript(
        &self,
        channel: &HelperChannel,
        peer: &Binding,
        challenge: [u8; 32],
        local_signs: bool,
    ) -> Result<[u8; 32]> {
        // The caller derives challenge from the connection exporter, ALPN and
        // a fresh nonce. Ordering distinguishes the two signatures.
        let local = (
            self.identity.node.id(),
            self.identity.node.public_key(),
            channel.local,
        );
        let remote = (peer.0.as_str(), peer.1, channel.peer);
        let (signer, recipient) = if local_signs {
            (local, remote)
        } else {
            (remote, local)
        };
        Ok(Sha256::digest(serde_json::to_vec(&(
            &self.state.state().cluster_id,
            signer,
            recipient,
            &channel.offer.helper_node,
            channel.operator,
            channel.offer.generation,
            challenge,
        ))?)
        .into())
    }
}

impl Store {
    fn helper_session<T>(&self, f: impl FnOnce(&StoreSession<'_>) -> Result<T>) -> Result<T> {
        ensure!(
            matches!(self.direct_settings()?.direct, config::Direct::Auto),
            "direct transport disabled"
        );
        let tx = self.db.unchecked_transaction()?;
        let s = self.network_session(&tx, self.identity.state(&tx)?);
        s.require_local_membership()?;
        f(&s)
    }

    pub(crate) fn helper_authority(
        &self,
        offer: &HelperOffer,
    ) -> Result<Option<(EndpointId, PublicKey, i64)>> {
        self.helper_session(|s| {
            let Some(src) = s.service_source(offer)? else {
                return Ok(None);
            };
            Ok(self
                .direct_certs
                .window(offer, &offer.helper_node)?
                .contains(&s.timestamp)
                .then_some((src.address.endpoint.id, src.key, src.expires_at)))
        })
    }

    pub(crate) fn helper_admission(
        &self,
        id: EndpointId,
        offer: &HelperOffer,
    ) -> Result<(Binding, i64)> {
        self.host_registration(id, offer, true)
    }

    pub(crate) fn helper_renewal(
        &self,
        id: EndpointId,
        offer: &HelperOffer,
    ) -> Result<(Binding, i64)> {
        self.host_registration(id, offer, false)
    }

    fn host_registration(
        &self,
        id: EndpointId,
        offer: &HelperOffer,
        fresh: bool,
    ) -> Result<(Binding, i64)> {
        self.helper_session(|s| {
            ensure!(
                matches!(self.direct_settings()?.helper, config::Direct::Auto)
                    && offer.helper_node == self.identity.node.id(),
                "not the active helper operator"
            );
            let host = s
                .service_source(offer)?
                .context("local helper offer changed")?;
            let window = self.direct_certs.window(offer, &offer.helper_node)?;
            ensure!(window.contains(&s.timestamp), "helper certificate expired");
            let mut end = (*window.end()).min(i64::try_from(s.state.state().expires_at)?);
            let binding = s
                .endpoint_binding(id, fresh)?
                .context("unknown helper client")?;
            if fresh {
                ensure!(
                    s.endpoint_binding(id, false)?.as_ref() == Some(&binding),
                    "ambiguous helper client"
                );
                let client = s
                    .helper_source(&binding.0, true)?
                    .context("client locator expired")?;
                end = end.min(client.expires_at).min(host.expires_at);
                if binding.0 != offer.helper_node {
                    let (topology, expires): (String, i64) = s.db.query_row(
                        "SELECT endpoint,expires_at FROM direct_advertised WHERE peer=?1",
                        [&binding.0],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )?;
                    ensure!(
                        serde_json::from_str::<helpers::Topology>(&topology)?.published_service(
                            host.address.endpoint.id,
                            offer,
                            binding.1
                        ),
                        "helper was not advertised to client"
                    );
                    end = end.min(expires);
                }
            }
            ensure!(s.timestamp < end, "helper authority expired");
            Ok((binding, end))
        })
    }

    pub(crate) fn sign_helper_peer(
        &self,
        channel: &HelperChannel,
        challenge: [u8; 32],
    ) -> Result<[u8; 64]> {
        self.helper_session(|s| {
            let peer = s.channel_binding(channel)?;
            ensure!(
                self.direct_certs
                    .window(&channel.offer, &channel.offer.helper_node)?
                    .contains(&s.timestamp),
                "helper certificate expired"
            );
            self.identity
                .node
                .sign_helper_channel(&s.channel_transcript(channel, &peer, challenge, true)?)
        })
    }

    pub(crate) fn verify_helper_peer(
        &self,
        channel: &HelperChannel,
        challenge: [u8; 32],
        signature: &[u8],
    ) -> Result<HelperPeer> {
        self.helper_session(|s| {
            let peer = s.channel_binding(channel)?;
            let certificate = self
                .direct_certs
                .window(&channel.offer, &channel.offer.helper_node)?;
            ensure!(
                certificate.contains(&s.timestamp),
                "helper certificate expired"
            );
            gent_crypto::verify_helper_channel(
                &peer.1,
                &s.channel_transcript(channel, &peer, challenge, false)?,
                signature,
            )?;
            Ok(HelperPeer {
                channel: channel.clone(),
                peer,
                certificate,
            })
        })
    }

    pub(crate) fn authorize_helper_peer(
        &self,
        pin: &HelperPeer,
        expected: Option<&str>,
    ) -> Result<()> {
        self.helper_session(|s| s.authorize_helper_peer(pin, expected))
    }

    pub(crate) fn helper_receive(
        &mut self,
        pin: &HelperPeer,
        group: &[u8],
        packets: Vec<Packet>,
    ) -> Result<Receipt> {
        let peer = self.data_peer(&self.db, group, false)?;
        self.authorize_helper_peer(pin, Some(&peer))?;
        self.receive_session_packets(group, packets)
    }
}
