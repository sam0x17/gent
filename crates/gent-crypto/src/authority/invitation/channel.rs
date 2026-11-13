//! Stateful Noise transport. Reconnection requires a new handshake. Do not
//! persist a session or rewind its counters; retry durable application IDs.
use super::*;
use snow::{Builder, HandshakeState, TransportState};
mod resolver;

pub const PATTERN: &str = "Noise_NKpsk0_25519_ChaChaPoly_SHA256";
pub const SESSION_LIFETIME: u64 = 5 * 60;
pub const MAX_MESSAGE_BYTES: usize = gent_protocol::MAX_FRAME_BYTES;
pub const MAX_SESSION_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SESSION_MESSAGES: usize = 4096;
pub const MAX_NOISE_BYTES: usize = 65_535;
const HEADER_BYTES: usize = 9;
const TAG_BYTES: usize = 16;
const CHUNK_BYTES: usize = MAX_NOISE_BYTES - HEADER_BYTES - TAG_BYTES;
const MAX_FRAGMENTS: usize = MAX_MESSAGE_BYTES.div_ceil(CHUNK_BYTES);
const HANDSHAKE_BYTES: usize = 48;
const PROLOGUE_DOMAIN: &[u8] = b"gent/invitation-channel/v1\0";

/// Only an opaque attempt ID and an empty-payload Noise handshake are public.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub attempt: String,
    pub noise: Vec<u8>,
}

pub struct Initiator {
    offer: SignedOffer,
    noise: HandshakeState,
    started: u64,
}

pub struct PendingClaim {
    channel: Channel,
}

/// Exposed only after the initiator signs its claim or the responder's admission
/// callback succeeds. The caller must still check live invitation state and
/// restrict every pairing operation to `node()` and `offer()`.
pub struct Channel {
    offer: SignedOffer,
    node: Option<ClaimedNode>,
    handshake: Digest,
    noise: Option<TransportState>,
    expires: u64,
    clock: u64,
    sent_bytes: usize,
    received_bytes: usize,
    sent_messages: usize,
    received_messages: usize,
}

fn builder<'a>() -> Builder<'a> {
    Builder::with_resolver(
        PATTERN.parse().expect("fixed Noise pattern"),
        Box::new(resolver::Resolver),
    )
}
fn prologue(offer: &SignedOffer, attempt: &str) -> Result<Vec<u8>> {
    id(attempt)?;
    ensure!(
        Uuid::parse_str(attempt)?.get_version_num() == 4,
        "invalid attempt ID"
    );
    signing_input(PROLOGUE_DOMAIN, &(offer, attempt), MAX_OFFER_BYTES + 128)
}
fn read_handshake(noise: &mut HandshakeState, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() == HANDSHAKE_BYTES, "invalid handshake length");
    ensure!(
        noise.read_message(bytes, &mut [])? == 0,
        "handshake payload is forbidden"
    );
    Ok(())
}
fn write_handshake(noise: &mut HandshakeState) -> Result<Vec<u8>> {
    let mut bytes = vec![0; HANDSHAKE_BYTES];
    let n = noise.write_message(&[], &mut bytes)?;
    ensure!(n == bytes.len(), "invalid handshake length");
    Ok(bytes)
}

impl Initiator {
    /// The invitation must have come from protected transfer, never a relay
    /// directory. Login/account/endpoint preflight is the CLI's responsibility.
    pub fn start(invitation: &Invitation, now: u64) -> Result<(Self, Hello)> {
        let offer = invitation.offer();
        offer.verify(&offer.offer.anchor, now)?;
        let attempt = Uuid::new_v4().to_string();
        let prologue = prologue(offer, &attempt)?;
        let mut noise = builder()
            .prologue(&prologue)?
            .psk(0, &invitation.psk)?
            .remote_public_key(&offer.offer.responder_key)?
            .build_initiator()?;
        let hello = Hello {
            attempt,
            noise: write_handshake(&mut noise)?,
        };
        Ok((
            Self {
                offer: offer.clone(),
                noise,
                started: now,
            },
            hello,
        ))
    }

    pub fn finish(
        mut self,
        reply: &[u8],
        node: &NodeIdentity,
        name: &str,
        now: u64,
    ) -> Result<(Channel, Vec<Vec<u8>>)> {
        read_handshake(&mut self.noise, reply)?;
        let mut channel = Channel::new(self.offer, self.noise, self.started)?;
        let claim = SignedClaim::create(&channel.offer, channel.handshake, node, name, now)?;
        let plaintext = Zeroizing::new(encode(&claim, MAX_REQUEST_BYTES)?);
        let ciphertext = channel.seal(&plaintext, now)?;
        channel.node = Some(claim.claim.node);
        Ok((channel, ciphertext))
    }
}

impl OwnerInvitation {
    /// The runtime must reject revoked/consumed offers and bound concurrent
    /// attempts before calling this. A handshake by itself performs no admission.
    pub fn respond(&self, hello: &Hello, now: u64) -> Result<(PendingClaim, Vec<u8>)> {
        let offer = self.invitation.offer();
        offer.verify(&offer.offer.anchor, now)?;
        let prologue = prologue(offer, &hello.attempt)?;
        let mut noise = builder()
            .prologue(&prologue)?
            .psk(0, &self.invitation.psk)?
            .local_private_key(self.private.as_ref())?
            .build_responder()?;
        read_handshake(&mut noise, &hello.noise)?;
        let reply = write_handshake(&mut noise)?;
        let channel = Channel::new(offer.clone(), noise, now)?;
        Ok((PendingClaim { channel }, reply))
    }
}

impl PendingClaim {
    /// `admit` must atomically check current owner authority, expiry/revocation,
    /// and the saved single-node claim. It runs only after the claim's signature
    /// and channel binding pass. No response-capable channel escapes on failure.
    pub fn accept(
        mut self,
        frames: &[Vec<u8>],
        now: u64,
        admit: impl FnOnce(&SignedOffer, &ClaimedNode) -> Result<()>,
    ) -> Result<Channel> {
        ensure!(
            frames.len() == 1 && frames[0].len() <= MAX_REQUEST_BYTES + HEADER_BYTES + TAG_BYTES,
            "invitation claim too large"
        );
        let bytes = self.channel.open(frames, now)?;
        let claim: SignedClaim = decode(&bytes, MAX_REQUEST_BYTES)
            .map_err(|_| anyhow::anyhow!("invalid invitation claim"))?;
        claim.verify(&self.channel.offer, self.channel.handshake, now)?;
        admit(&self.channel.offer, &claim.claim.node)?;
        self.channel.node = Some(claim.claim.node);
        Ok(self.channel)
    }
}

impl Channel {
    fn new(offer: SignedOffer, noise: HandshakeState, now: u64) -> Result<Self> {
        let handshake = noise
            .get_handshake_hash()
            .try_into()
            .context("invalid handshake hash")?;
        let expires = offer.offer.expires_at.min(
            now.checked_add(SESSION_LIFETIME)
                .context("session timestamp overflow")?,
        );
        Ok(Self {
            offer,
            node: None,
            handshake,
            noise: Some(noise.into_transport_mode()?),
            expires,
            clock: now,
            sent_bytes: 0,
            received_bytes: 0,
            sent_messages: 0,
            received_messages: 0,
        })
    }
    pub fn offer(&self) -> &SignedOffer {
        &self.offer
    }
    pub fn node(&self) -> &ClaimedNode {
        self.node
            .as_ref()
            .expect("channel exposed only after claim")
    }
    pub fn handshake_hash(&self) -> Digest {
        self.handshake
    }

    fn time(&mut self, now: u64) -> Result<()> {
        ensure!(
            now >= self.clock,
            "invitation channel clock moved backwards"
        );
        fresh(self.offer.offer.issued_at, self.expires, now)?;
        self.clock = now;
        Ok(())
    }
    /// Any error closes the channel. Resend cached ciphertext at the transport
    /// layer or reconnect and retry the durable application operation ID.
    pub fn seal(&mut self, bytes: &[u8], now: u64) -> Result<Vec<Vec<u8>>> {
        let mut noise = self.noise.take().context("invitation channel is closed")?;
        self.time(now)?;
        ensure!(
            bytes.len() <= MAX_MESSAGE_BYTES,
            "invitation message too large"
        );
        ensure!(
            self.sent_messages < MAX_SESSION_MESSAGES
                && self.sent_bytes + bytes.len() <= MAX_SESSION_BYTES,
            "invitation session send budget exhausted; reconnect"
        );
        let mut frames = Vec::with_capacity(bytes.len().div_ceil(CHUNK_BYTES).max(1));
        let mut offset = 0;
        loop {
            let end = (offset + CHUNK_BYTES).min(bytes.len());
            let mut plaintext = Zeroizing::new(Vec::with_capacity(HEADER_BYTES + end - offset));
            plaintext.push(1);
            plaintext.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            plaintext.extend_from_slice(&(offset as u32).to_be_bytes());
            plaintext.extend_from_slice(&bytes[offset..end]);
            let mut ciphertext = vec![0; plaintext.len() + TAG_BYTES];
            let n = noise.write_message(&plaintext, &mut ciphertext)?;
            ensure!(n == ciphertext.len(), "invalid encrypted fragment length");
            frames.push(ciphertext);
            offset = end;
            if offset == bytes.len() {
                break;
            }
        }
        self.sent_messages += 1;
        self.sent_bytes += bytes.len();
        self.noise = Some(noise);
        Ok(frames)
    }

    /// Authenticating the entire bounded message precedes exposing any bytes.
    /// Duplicate detection belongs outside this function; a replay closes it.
    pub fn open(&mut self, frames: &[Vec<u8>], now: u64) -> Result<Zeroizing<Vec<u8>>> {
        let mut noise = self.noise.take().context("invitation channel is closed")?;
        self.time(now)?;
        ensure!(
            !frames.is_empty()
                && frames.len() <= MAX_FRAGMENTS
                && frames
                    .iter()
                    .all(|f| (HEADER_BYTES + TAG_BYTES..=MAX_NOISE_BYTES).contains(&f.len())),
            "invalid encrypted invitation frame bounds"
        );
        ensure!(
            self.received_messages < MAX_SESSION_MESSAGES,
            "invitation receive budget exhausted; reconnect"
        );
        let mut output = Zeroizing::new(Vec::new());
        let mut total = None;
        for frame in frames {
            let mut plaintext = Zeroizing::new(vec![0; frame.len() - TAG_BYTES]);
            let n = noise.read_message(frame, &mut plaintext)?;
            ensure!(
                n == plaintext.len() && plaintext[0] == 1,
                "invalid invitation fragment"
            );
            let length =
                u32::from_be_bytes(plaintext[1..5].try_into().expect("bounded header")) as usize;
            let offset =
                u32::from_be_bytes(plaintext[5..9].try_into().expect("bounded header")) as usize;
            ensure!(length <= MAX_MESSAGE_BYTES, "invitation message too large");
            if let Some(total) = total {
                ensure!(length == total, "conflicting invitation fragment length");
            } else {
                ensure!(
                    frames.len() == length.div_ceil(CHUNK_BYTES).max(1)
                        && self.received_bytes + length <= MAX_SESSION_BYTES,
                    "invalid fragment count or exhausted invitation receive budget"
                );
                total = Some(length);
                output.reserve_exact(length);
            }
            ensure!(
                offset == output.len() && offset <= length,
                "invalid invitation fragment offset"
            );
            let expected = (length - offset).min(CHUNK_BYTES);
            ensure!(
                plaintext.len() == HEADER_BYTES + expected,
                "invalid invitation fragment size"
            );
            output.extend_from_slice(&plaintext[HEADER_BYTES..]);
        }
        ensure!(Some(output.len()) == total, "incomplete invitation message");
        self.received_messages += 1;
        self.received_bytes += output.len();
        self.noise = Some(noise);
        Ok(output)
    }
}

pub(super) fn public_key(private: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private)).to_bytes()
}
pub(super) fn validate_public_key(key: &[u8; 32]) -> Result<()> {
    // Contributory behavior depends only on the public point. This fixed scalar
    // checks shape/low-order points; it never participates in a real handshake.
    let secret = x25519_dalek::StaticSecret::from([0x53; 32]);
    ensure!(
        secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(*key))
            .was_contributory(),
        "noncontributory invitation public key"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
