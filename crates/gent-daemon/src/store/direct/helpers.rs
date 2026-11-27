//! A helper speaks for its own service. Each endpoint speaks only for its own
//! registration; routing joins these three independently expiring records.
use super::*;
use iroh::RelayUrl;
use std::{cell::RefCell, collections::VecDeque, net::IpAddr, ops::RangeInclusive};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

const MAX_ALIASES: usize = 8;
const MAX_DER: usize = 8192;
const MAX_REGISTRATIONS: usize = 16;
const MAX_CACHED_CERTIFICATES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HelperOffer {
    pub helper_node: String,
    pub urls: Vec<RelayUrl>,
    #[serde(with = "certificate_bytes")]
    pub cert_der: Vec<u8>,
    pub generation: [u8; 32],
    pub qad_port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HelperRegistration {
    pub helper_node: String,
    pub url: RelayUrl,
    pub generation: [u8; 32],
    pub rtt_ms: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HelperCandidate {
    pub offer: HelperOffer,
    pub local: HelperRegistration,
    pub remote: HelperRegistration,
}

/// Memoize only the public certificate's parsed validity and verified SANs.
/// Every lookup still checks the current signing authority, link and deadline.
#[derive(Default)]
pub(in crate::store) struct CertificateCache(RefCell<VecDeque<(HelperOffer, RangeInclusive<i64>)>>);

impl CertificateCache {
    fn valid_at(&self, offer: &HelperOffer, owner: &str, timestamp: i64) -> Result<bool> {
        Ok(self.window(offer, owner)?.contains(&timestamp))
    }

    pub(super) fn window(&self, offer: &HelperOffer, owner: &str) -> Result<RangeInclusive<i64>> {
        ensure!(
            offer.helper_node == owner,
            "helper offer belongs to another node"
        );
        let mut cache = self.0.borrow_mut();
        if let Some((_, validity)) = cache.iter().find(|(saved, _)| saved == offer) {
            return Ok(validity.clone());
        }
        let validity = offer.certificate_window()?;
        if cache.len() == MAX_CACHED_CERTIFICATES {
            cache.pop_front();
        }
        cache.push_back((offer.clone(), validity.clone()));
        Ok(validity)
    }
}

mod certificate_bytes {
    use super::*;
    use serde::{Deserializer, Serializer, de, ser};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        if bytes.is_empty() || bytes.len() > MAX_DER {
            return Err(ser::Error::custom("invalid helper certificate length"));
        }
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(d)?;
        if value.is_empty() || value.len() > MAX_DER.div_ceil(3) * 4 {
            return Err(de::Error::custom("invalid helper certificate length"));
        }
        let bytes = STANDARD.decode(value).map_err(de::Error::custom)?;
        if bytes.len() > MAX_DER {
            return Err(de::Error::custom("invalid helper certificate length"));
        }
        Ok(bytes)
    }
}

fn helper_ip(url: &RelayUrl) -> Result<IpAddr> {
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/"
            && url.port_or_known_default().is_some_and(|port| port != 0),
        "invalid helper URL"
    );
    let host = url.host_str().context("missing helper IP")?;
    let ip: IpAddr = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .context("expected a numeric helper IP")?;
    ensure!(
        !ip.is_unspecified()
            && !ip.is_multicast()
            && !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast()),
        "invalid helper IP"
    );
    Ok(ip)
}

impl HelperOffer {
    pub(super) fn matches_service(&self, other: &Self) -> bool {
        self.helper_node == other.helper_node
            && self.generation == other.generation
            && self.cert_der == other.cert_der
            && self.qad_port == other.qad_port
            && self.urls.len() == other.urls.len()
            && self.urls.iter().all(|url| other.urls.contains(url))
    }

    pub(super) fn certificate_window(&self) -> Result<RangeInclusive<i64>> {
        ensure!(
            (1..=MAX_ALIASES).contains(&self.urls.len())
                && self.qad_port != Some(0)
                && (1..=MAX_DER).contains(&self.cert_der.len()),
            "invalid helper offer bounds"
        );
        ensure!(
            Sha256::digest(&self.cert_der).as_slice() == self.generation,
            "helper certificate generation mismatch"
        );
        let (rest, cert) = parse_x509_certificate(&self.cert_der)
            .map_err(|_| anyhow::anyhow!("invalid helper certificate"))?;
        ensure!(rest.is_empty(), "trailing helper certificate bytes");
        ensure!(!cert.is_ca(), "expected a helper end-entity certificate");
        let san = cert
            .subject_alternative_name()?
            .context("helper certificate lacks IP aliases")?;
        let mut unique = BTreeSet::new();
        for url in &self.urls {
            let ip = helper_ip(url)?;
            ensure!(unique.insert(url), "duplicate helper URL");
            ensure!(
                san.value.general_names.iter().any(|name| match (name, ip) {
                    (GeneralName::IPAddress(bytes), IpAddr::V4(ip)) => *bytes == ip.octets(),
                    (GeneralName::IPAddress(bytes), IpAddr::V6(ip)) => *bytes == ip.octets(),
                    _ => false,
                }),
                "helper URL missing from certificate"
            );
        }
        Ok(cert.validity().not_before.timestamp()..=cert.validity().not_after.timestamp())
    }

    fn best_registration(
        &self,
        registrations: &[HelperRegistration],
    ) -> Option<HelperRegistration> {
        registrations
            .iter()
            .filter(|r| {
                r.helper_node == self.helper_node
                    && r.generation == self.generation
                    && self.urls.contains(&r.url)
            })
            .min_by_key(|r| r.rtt_ms)
            .cloned()
    }
}

impl Address {
    pub(super) fn validate_helpers(
        &mut self,
        owner: &str,
        timestamp: i64,
        cache: Option<&CertificateCache>,
    ) -> Result<()> {
        if let Some(offer) = &mut self.offer {
            ensure!(offer.urls.len() <= MAX_ALIASES, "too many helper aliases");
            ensure!(
                offer.helper_node == owner,
                "helper offer belongs to another node"
            );
            offer.urls.sort();
            let valid = match cache {
                Some(cache) => cache.valid_at(offer, owner, timestamp)?,
                None => offer.certificate_window()?.contains(&timestamp),
            };
            if !valid {
                // A legitimate queued record can outlive its TLS certificate.
                // Consume the normal endpoint without installing that offer.
                self.offer = None;
            }
        }
        ensure!(
            self.registrations.len() <= MAX_REGISTRATIONS,
            "too many helper registrations"
        );
        self.registrations
            .sort_by(|a, b| (&a.helper_node, &a.url).cmp(&(&b.helper_node, &b.url)));
        let mut unique = BTreeSet::new();
        for reg in &self.registrations {
            let id = uuid::Uuid::parse_str(&reg.helper_node)?;
            ensure!(
                !id.is_nil() && id.to_string() == reg.helper_node && reg.rtt_ms <= 60_000,
                "invalid helper registration"
            );
            helper_ip(&reg.url)?;
            ensure!(
                unique.insert((&reg.helper_node, &reg.url)),
                "duplicate helper registration"
            );
        }
        Ok(())
    }

    pub(super) fn topology(&self) -> Topology {
        // RTT jitter and the renewal deadline do not create idle mailbox work.
        // An active refresh carries the latest measured RTT for each leg.
        let registrations = self
            .registrations
            .iter()
            .map(|leg| (leg.helper_node.clone(), leg.url.clone(), leg.generation))
            .collect();
        let service = self
            .offer
            .as_ref()
            .map(|o| (o.urls.clone(), o.generation, o.qad_port));
        Topology {
            recipient_key: None,
            endpoint: self.endpoint.clone(),
            service,
            registrations,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct Topology {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) recipient_key: Option<gent_crypto::PublicKey>,
    endpoint: EndpointAddr,
    service: Option<(Vec<RelayUrl>, [u8; 32], Option<u16>)>,
    registrations: BTreeSet<(String, RelayUrl, [u8; 32])>,
}

impl Topology {
    pub(super) fn published_service(
        &self,
        endpoint: EndpointId,
        offer: &HelperOffer,
        recipient_key: gent_crypto::PublicKey,
    ) -> bool {
        self.recipient_key == Some(recipient_key)
            && self.endpoint.id == endpoint
            && self
                .service
                .as_ref()
                .is_some_and(|(urls, generation, qad)| {
                    *generation == offer.generation
                        && *qad == offer.qad_port
                        && urls.len() == offer.urls.len()
                        && urls.iter().all(|url| offer.urls.contains(url))
                })
    }
    pub(super) fn encode(&self, plain: &str) -> Result<String> {
        if self.registrations.is_empty() && self.service.is_none() {
            return Ok(plain.to_owned());
        }
        Ok(serde_json::to_string(self)?)
    }

    /// A slot can disappear just because the helper's last advertisement aged
    /// out while idle. Defer that removal until there is traffic for this peer.
    pub(super) fn passive_withdrawal(
        &self,
        previous: &str,
        session: &StoreSession<'_>,
        cache: &CertificateCache,
    ) -> Result<bool> {
        let Ok(old) = serde_json::from_str::<Self>(previous) else {
            return Ok(false);
        };
        if self.endpoint != old.endpoint
            || self.service != old.service
            || !self.registrations.is_subset(&old.registrations)
        {
            return Ok(false);
        }
        for (node, url, generation) in old.registrations.difference(&self.registrations) {
            if session
                .current_offer(node, cache, true)?
                .is_some_and(|o| o.generation == *generation && o.urls.contains(url))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

pub(super) struct Source {
    pub(super) address: Address,
    pub(super) key: gent_crypto::PublicKey,
    pub(super) expires_at: i64,
}

impl StoreSession<'_> {
    pub(in crate::store) fn require_local_membership(&self) -> Result<()> {
        super::super::network::active_peer(
            &self.state,
            self.identity.node.id(),
            &self.identity.node.public_key(),
            self.timestamp,
        )
    }

    fn current_source(&self, node: &str, key: &[u8], local: bool) -> bool {
        local == (node == self.identity.node.id())
            && super::super::network::active_peer(&self.state, node, key, self.timestamp).is_ok()
    }

    pub(super) fn endpoint_binding(
        &self,
        endpoint: EndpointId,
        fresh: bool,
    ) -> Result<Option<(String, gent_crypto::PublicKey)>> {
        let mut q = self.db.prepare_cached("SELECT peer,peer_key,local FROM direct_sources WHERE endpoint=?1 AND (NOT ?2 OR expires_at>?3)")?;
        let mut rows = q.query(params![endpoint.to_string(), fresh, self.timestamp])?;
        let mut owner = None;
        while let Some(row) = rows.next()? {
            let peer: String = row.get(0)?;
            let key: gent_crypto::PublicKey = row.get(1)?;
            if self.current_source(&peer, &key, row.get(2)?) {
                ensure!(owner.is_none(), "ambiguous direct endpoint");
                owner = Some((peer, key));
            }
        }
        Ok(owner)
    }

    pub(super) fn helper_source(&self, peer: &str, fresh: bool) -> Result<Option<Source>> {
        let local = peer == self.identity.node.id();
        let mut stmt = self.db.prepare_cached("SELECT peer_key,address,expires_at FROM direct_sources WHERE peer=?1 AND local=?2 AND (NOT ?4 OR expires_at>?3)")?;
        let mut rows = stmt.query(params![peer, local, self.timestamp, fresh])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let key: gent_crypto::PublicKey = row.get(0)?;
        if !self.current_source(peer, &key, local) {
            return Ok(None);
        }
        Ok(Some(Source {
            key,
            address: serde_json::from_slice(row.get_ref(1)?.as_blob()?)?,
            expires_at: row.get(2)?,
        }))
    }

    fn current_offer(
        &self,
        peer: &str,
        cache: &CertificateCache,
        fresh: bool,
    ) -> Result<Option<HelperOffer>> {
        let Some(offer) = self
            .helper_source(peer, fresh)?
            .and_then(|s| s.address.offer)
        else {
            return Ok(None);
        };
        Ok(cache
            .valid_at(&offer, peer, self.timestamp)?
            .then_some(offer))
    }
}

impl Store {
    /// Only these offers may start new helper sockets without a native grant.
    #[cfg(test)]
    pub(crate) fn helper_offers(&self) -> Result<Vec<HelperOffer>> {
        let now = now();
        Ok(self
            .helper_authorities()?
            .into_iter()
            .filter(|(_, _, _, expires)| *expires > now)
            .map(|(offer, _, _, _)| offer)
            .collect())
    }

    /// Also returns expired locator deadlines for checking existing registrations.
    /// The signing identity and endpoint are checked against current membership.
    pub(crate) fn helper_authorities(&self) -> Result<Vec<HelperAuthority>> {
        if matches!(self.direct_settings()?.direct, config::Direct::Off) {
            return Ok(vec![]);
        }
        let tx = self.db.unchecked_transaction()?;
        let session = self.network_session(&tx, self.identity.state(&tx)?);
        session.require_local_membership()?;
        let mut stmt = tx.prepare_cached("SELECT peer,peer_key,local,json_extract(CAST(address AS TEXT),'$.offer'),endpoint,expires_at FROM direct_sources ORDER BY peer")?;
        let mut offers = Vec::new();
        let mut observed = BTreeSet::new();
        let mut ambiguous = BTreeSet::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let peer: String = row.get(0)?;
            let key = row.get::<_, gent_crypto::PublicKey>(1)?;
            if session.current_source(&peer, &key, row.get(2)?) {
                let endpoint: EndpointId = row.get_ref(4)?.as_str()?.parse()?;
                if !observed.insert(endpoint) {
                    ambiguous.insert(endpoint);
                }
                let Some(json) = row.get::<_, Option<String>>(3)? else {
                    continue;
                };
                let offer: HelperOffer = serde_json::from_str(&json)?;
                if self
                    .direct_certs
                    .valid_at(&offer, &peer, session.timestamp)?
                {
                    offers.push((offer, endpoint, key, row.get(5)?));
                }
            }
        }
        offers.retain(|(_, id, _, _)| !ambiguous.contains(id));
        Ok(offers)
    }

    #[cfg(test)]
    pub(crate) fn helper_candidates(&self, target: EndpointId) -> Result<Vec<HelperCandidate>> {
        self.helper_legs(target, true)
    }

    /// Historical matching legs only order probes on already-authorized slots.
    pub(crate) fn helper_hints(&self, target: EndpointId) -> Result<Vec<HelperCandidate>> {
        self.helper_legs(target, false)
    }

    fn helper_legs(&self, target: EndpointId, fresh: bool) -> Result<Vec<HelperCandidate>> {
        if matches!(self.direct_settings()?.direct, config::Direct::Off) {
            return Ok(vec![]);
        }
        let tx = self.db.unchecked_transaction()?;
        let session = self.network_session(&tx, self.identity.state(&tx)?);
        session.require_local_membership()?;
        let me = self.identity.node.id();
        let Some((peer, _)) = session
            .endpoint_binding(target, fresh)?
            .filter(|(node, _)| node != me)
        else {
            return Ok(vec![]);
        };
        let (Some(local), Some(remote)) = (
            session.helper_source(me, fresh)?,
            session.helper_source(&peer, fresh)?,
        ) else {
            return Ok(vec![]);
        };
        let mut candidates = Vec::new();
        let helpers: BTreeSet<_> = local
            .address
            .registrations
            .iter()
            .map(|leg| leg.helper_node.as_str())
            .collect();
        for helper in helpers {
            let Some(offer) = session.current_offer(helper, &self.direct_certs, fresh)? else {
                continue;
            };
            if let (Some(local), Some(remote)) = (
                offer.best_registration(&local.address.registrations),
                offer.best_registration(&remote.address.registrations),
            ) {
                candidates.push(HelperCandidate {
                    offer,
                    local,
                    remote,
                });
            }
        }
        candidates.sort_by_key(|c| c.local.rtt_ms + c.remote.rtt_ms);
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_helper_certificate_rechecks_time_origin_and_exact_aliases() {
        let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let start = params.not_before.unix_timestamp();
        let end = params.not_after.unix_timestamp();
        let cert = params
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        let der = cert.der().to_vec();
        let mut offer = HelperOffer {
            helper_node: uuid::Uuid::new_v4().to_string(),
            urls: vec!["https://127.0.0.1/".parse().unwrap()],
            generation: Sha256::digest(&der).into(),
            cert_der: der,
            qad_port: None,
        };
        let cache = CertificateCache::default();
        for (time, valid) in [
            (start, true),
            (end, true),
            (end + 1, false),
            (start - 1, false),
        ] {
            assert_eq!(
                cache.valid_at(&offer, &offer.helper_node, time).unwrap(),
                valid
            );
        }
        assert!(cache.valid_at(&offer, "other", start).is_err());
        let original = offer.clone();
        offer.urls[0] = "https://192.0.2.1/".parse().unwrap();
        assert!(cache.valid_at(&offer, &offer.helper_node, start).is_err());
        assert_eq!(cache.0.borrow().len(), 1);
        for port in 1..=MAX_CACHED_CERTIFICATES {
            offer.urls[0] = format!("https://127.0.0.1:{port}/").parse().unwrap();
            assert!(cache.valid_at(&offer, &offer.helper_node, start).unwrap());
        }
        let entries = cache.0.borrow();
        assert_eq!(entries.len(), MAX_CACHED_CERTIFICATES);
        assert!(entries.iter().all(|(saved, _)| saved != &original));
    }
}
