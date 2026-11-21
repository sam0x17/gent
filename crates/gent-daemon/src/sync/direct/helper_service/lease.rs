//! A native grant belongs to one admitted relay connection and alias. The
//! caller proves its endpoint key. Pinned HTTPS authenticates the helper reply.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::stream;
use http::{HeaderMap, header};
use http_body::Frame;
use http_body_util::StreamBody;
use iroh::{SecretKey, Signature};
use std::time::{SystemTime, UNIX_EPOCH};

const PATH: &str = "/gent/helper-lease/1";
const HEADER: &str = "x-gent-helper-lease";
const REQUEST_BYTES: usize = 32 + 32 + 32 + 64;
const RESPONSE_BYTES: usize = 32 + 32 + 4;
const TTL: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub(in crate::sync::direct) struct Grant {
    pub(in crate::sync::direct) until: Instant,
    scope: [u8; 32],
    token: [u8; 32],
}

impl std::fmt::Debug for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grant")
            .field("until", &self.until)
            .finish_non_exhaustive()
    }
}

pub(in crate::sync::direct) fn deadline(expiry: i64) -> Option<Instant> {
    let now = Instant::now();
    let remaining = Duration::from_secs(expiry.try_into().ok()?)
        .checked_sub(SystemTime::now().duration_since(UNIX_EPOCH).ok()?)?;
    now.checked_add(remaining)
}

pub(super) fn alias<'a>(headers: &HeaderMap, offer: &'a HelperOffer) -> Option<&'a RelayUrl> {
    let authority = headers
        .get(header::HOST)?
        .to_str()
        .ok()?
        .parse::<http::uri::Authority>()
        .ok()?;
    offer.urls.iter().find(|url| {
        url.host_str() == Some(authority.host())
            && url.port_or_known_default() == Some(authority.port_u16().unwrap_or(443))
    })
}

fn scope(id: EndpointId, offer: &HelperOffer, alias: &RelayUrl) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"gent/helper-lease/request/1\0")
        .chain_update(id.as_bytes())
        .chain_update(offer.generation)
        .chain_update(Sha256::digest(offer.helper_node.as_bytes()))
        .chain_update(Sha256::digest(alias.as_str().as_bytes()))
        .finalize()
        .into()
}

fn message(scope: [u8; 32], token: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(scope)
        .chain_update(token)
        .chain_update(nonce)
        .finalize()
        .into()
}

fn random() -> Result<[u8; 32]> {
    let mut value = [0; 32];
    getrandom::fill(&mut value)?;
    ensure!(value != [0; 32], "invalid random value");
    Ok(value)
}

struct Challenge {
    id: EndpointId,
    token: [u8; 32],
    nonce: [u8; 32],
}

impl Challenge {
    fn signed(key: &SecretKey, scope: [u8; 32], token: [u8; 32], nonce: [u8; 32]) -> String {
        let signature = key.sign(&message(scope, &token, &nonce));
        let mut bytes = Vec::with_capacity(REQUEST_BYTES);
        bytes.extend_from_slice(key.public().as_bytes());
        bytes.extend_from_slice(&token);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&signature.to_bytes());
        STANDARD.encode(bytes)
    }

    fn verify(headers: &HeaderMap, offer: &HelperOffer, alias: &RelayUrl) -> Option<Self> {
        let wire = headers.get(HEADER)?.as_bytes();
        if wire.len() != REQUEST_BYTES.div_ceil(3) * 4 {
            return None;
        }
        let mut bytes = [0; REQUEST_BYTES];
        if STANDARD.decode_slice(wire, &mut bytes).ok()? != bytes.len() {
            return None;
        }
        let id = EndpointId::from_bytes(bytes[..32].try_into().ok()?).ok()?;
        let token = bytes[32..64].try_into().ok()?;
        let nonce = bytes[64..96].try_into().ok()?;
        let signature = Signature::try_from(&bytes[96..]).ok()?;
        id.verify(
            &message(scope(id, offer, alias), &token, &nonce),
            &signature,
        )
        .ok()?;
        Some(Self { id, token, nonce })
    }
}

impl Session {
    fn accepts_challenge(&self, alias: &RelayUrl, request: &Challenge, now: Instant) -> bool {
        self.alias == *alias
            && !self.retired
            && self.settled <= now
            && now < self.until
            && if request.token == [0; 32] {
                self.predecessor.is_none()
            } else {
                self.token == request.token
                    || self
                        .predecessor
                        .is_some_and(|(token, until)| token == request.token && now < until)
            }
    }
    fn reply(
        &mut self,
        alias: &RelayUrl,
        request: &Challenge,
        now: Instant,
        authority_until: Instant,
    ) -> Option<[u8; RESPONSE_BYTES]> {
        if !self.accepts_challenge(alias, request, now) {
            return None;
        }
        let mut until = authority_until.min(now + TTL);
        let bootstrap = request.token == [0; 32];
        let continuation = !bootstrap && request.token == self.token;
        if !continuation {
            // Bootstrap and recovery can only return the remaining existing grant.
            until = until.min(self.until);
        }
        let millis: u32 = until
            .checked_duration_since(now)?
            .as_millis()
            .try_into()
            .ok()?;
        if millis == 0 {
            return None;
        }
        if continuation || self.token == [0; 32] {
            let next = random().ok()?;
            if continuation {
                self.predecessor = Some((self.token, self.until));
            }
            self.token = next;
        }
        self.until = until;
        let mut reply = [0; RESPONSE_BYTES];
        reply[..32].copy_from_slice(&request.nonce);
        reply[32..64].copy_from_slice(&self.token);
        reply[64..].copy_from_slice(&millis.to_be_bytes());
        Some(reply)
    }
}

impl Admission {
    async fn answer(&self, alias: &RelayUrl, request: Challenge) -> Option<[u8; RESPONSE_BYTES]> {
        let (connection, pinned_binding) = {
            let state = self.registrations.lock().unwrap();
            let session = state.live.get(&request.id)?;
            if state.closed || !session.accepts_challenge(alias, &request, Instant::now()) {
                return None;
            }
            (session.connection, session.binding.clone())
        };
        let bootstrap = request.token == [0; 32];
        let (binding, expiry) = self
            .bindings(vec![request.id], bootstrap, &self.auth_slots)
            .await
            .ok()?
            .remove(&request.id)?;
        if binding != pinned_binding {
            return None;
        }

        let mut state = self.registrations.lock().unwrap();
        if state.closed {
            return None;
        }
        let session = state.live.get_mut(&request.id)?;
        let now = Instant::now();
        if session.connection != connection {
            return None;
        }
        session.reply(alias, &request, now, deadline(expiry)?)
    }
}

pub(super) fn install(handlers: &mut Handlers, admission: Arc<Admission>) {
    handlers.insert(
        (http::Method::GET, PATH),
        Box::new(move |req, res| {
            let gate = admission.clone();
            let proof = alias(req.headers(), &gate.offer).and_then(|alias| {
                Challenge::verify(req.headers(), &gate.offer, alias)
                    .map(|proof| (alias.clone(), proof))
            });
            let body = stream::once(async move {
                let reply = match proof {
                    Some((alias, proof)) => gate.answer(&alias, proof).await,
                    None => None,
                };
                let bytes = reply.unwrap_or([0; RESPONSE_BYTES]).to_vec();
                Ok::<_, std::convert::Infallible>(Frame::data(bytes.into()))
            });
            Ok(res
                .header(header::CACHE_CONTROL, "no-store")
                .header(header::CONNECTION, "close")
                .header(header::CONTENT_LENGTH, RESPONSE_BYTES)
                .body::<BytesBody>(Box::new(StreamBody::new(Box::pin(body))))?)
        }),
    );
}

pub(in crate::sync::direct) async fn renew(
    key: &SecretKey,
    offer: &HelperOffer,
    alias: &RelayUrl,
    previous: Option<&Grant>,
) -> Result<Grant> {
    let start = Instant::now();
    let scope = scope(key.public(), offer, alias);
    ensure!(
        alias.scheme() == "https"
            && offer.urls.contains(alias)
            && Sha256::digest(&offer.cert_der).as_slice() == offer.generation,
        "unrecognized helper alias"
    );
    let mut stop = start + ESTABLISH;
    let mut token = [0; 32];
    if let Some(grant) = previous {
        ensure!(
            grant.scope == scope && start < grant.until,
            "inactive helper grant"
        );
        stop = stop.min(grant.until);
        token = grant.token;
    }
    let nonce = random()?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_der(&offer.cert_der)?)
        .build()?;
    let exchange = async {
        let mut response = client
            .get(alias.join(PATH)?)
            .header(HEADER, Challenge::signed(key, scope, token, nonce))
            .send()
            .await?
            .error_for_status()?;
        ensure!(
            response.content_length() == Some(RESPONSE_BYTES as u64),
            "invalid helper reply length"
        );
        let mut bytes = Vec::with_capacity(RESPONSE_BYTES);
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                chunk.len() <= RESPONSE_BYTES - bytes.len(),
                "oversized helper reply"
            );
            bytes.extend_from_slice(&chunk);
        }
        ensure!(
            bytes.len() == RESPONSE_BYTES && bytes[..32] == nonce,
            "helper lease denied"
        );
        let token = bytes[32..64].try_into()?;
        let ttl = Duration::from_millis(u32::from_be_bytes(bytes[64..].try_into()?).into());
        let until = start + ttl;
        let now = Instant::now();
        ensure!(
            token != [0; 32] && ttl <= TTL && now < until && now < stop,
            "inactive helper reply"
        );
        Ok(Grant {
            scope,
            token,
            until,
        })
    };
    time::timeout_at(stop, exchange).await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_bind_the_alias_helper_generation_and_request_fields() -> Result<()> {
        let key = SecretKey::generate();
        let (mut offer, _) = identity(
            "h".into(),
            vec![Ipv4Addr::LOCALHOST.into()],
            7842,
            None,
            false,
        )?;
        let alias = offer.urls[0].clone();
        let signed = Challenge::signed(&key, scope(key.public(), &offer, &alias), [1; 32], [2; 32]);
        let mut headers = HeaderMap::new();
        headers.insert(HEADER, signed.parse()?);
        assert!(Challenge::verify(&headers, &offer, &alias).is_some());
        assert!(Challenge::verify(&headers, &offer, &"https://127.0.0.1:443/".parse()?).is_none());
        offer.helper_node.push('2');
        assert!(Challenge::verify(&headers, &offer, &alias).is_none());
        offer.helper_node.pop();
        offer.generation[0] ^= 1;
        assert!(Challenge::verify(&headers, &offer, &alias).is_none());
        offer.generation[0] ^= 1;
        for offset in [0, 32, 64, 96] {
            let mut bytes = STANDARD.decode(&signed)?;
            bytes[offset] ^= 1;
            headers.insert(HEADER, STANDARD.encode(bytes).parse()?);
            assert!(Challenge::verify(&headers, &offer, &alias).is_none());
        }
        Ok(())
    }

    #[test]
    fn replay_cannot_advance_or_revive_a_grant_or_its_predecessor() -> Result<()> {
        let alias: RelayUrl = "https://127.0.0.1:7842/".parse()?;
        let id = SecretKey::generate().public();
        let request = ClientRequest::new(
            id,
            Default::default(),
            http::Request::new(()).into_parts().0,
        );
        let t = Instant::now();
        let initial_expiry = t + Duration::from_secs(30);
        let mut session = Session {
            connection: request.connection_id(),
            binding: ("test".into(), [0; 32]),
            alias: alias.clone(),
            settled: t,
            until: initial_expiry,
            token: [0; 32],
            predecessor: None,
            retired: false,
        };
        let mut challenge = Challenge {
            id,
            token: [0; 32],
            nonce: [1; 32],
        };
        let end = t + TTL * 3;
        let first = session.reply(&alias, &challenge, t, end).unwrap();
        assert_eq!(session.until, initial_expiry);
        let second = session
            .reply(&alias, &challenge, t + Duration::from_secs(1), end)
            .unwrap();
        assert_eq!(first[..64], second[..64]);
        assert_eq!(session.until, initial_expiry);
        challenge.token = session.token;
        let next = t + Duration::from_secs(2);
        let lost = session.reply(&alias, &challenge, next, end).unwrap();
        assert_eq!(session.until, next + TTL);
        let recovered = session
            .reply(&alias, &challenge, next + Duration::from_secs(1), end)
            .unwrap();
        assert_eq!(lost[..64], recovered[..64]);
        assert_eq!(session.until, next + TTL);
        assert!(
            session
                .reply(&alias, &challenge, initial_expiry, end)
                .is_none()
        );
        challenge.token = session.token;
        let authority_expiry = initial_expiry + Duration::from_secs(10);
        session
            .reply(&alias, &challenge, initial_expiry, authority_expiry)
            .unwrap();
        assert_eq!(session.until, authority_expiry);
        challenge.token = session.token;
        assert!(
            session
                .reply(&alias, &challenge, authority_expiry, end)
                .is_none()
        );
        Ok(())
    }
}
