//! Noise N wraps a fresh record key separately for each enrolled node. The
//! record is ChaCha20-Poly1305 encrypted; only unrestricted nodes receive the
//! next write capability. All key envelopes have the same size.
//!
//! The Ed25519->X25519 conversion follows ed25519-dalek's documented matching
//! public/private conversions. Static recipient keys do not provide forward
//! secrecy against later compromise of that node's identity key.
use super::*;
use crate::configuration_log::WriteCapability;
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use gent_protocol::configuration_log::MAX_CIPHERTEXT_BYTES;

const NOISE: &str = "Noise_N_25519_ChaChaPoly_SHA256";
const DOMAIN: &[u8] = b"gent/configuration-envelope/v1\0";
const WRAPPED_BYTES: usize = 65 + 48;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    recipients: BTreeMap<String, String>,
    nonce: [u8; 12],
    ciphertext: String,
}

fn context(header: &Header) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_jcs::to_vec(header)?);
    Ok(bytes)
}

/// Encrypt a prepared signed candidate. Publication must still pass the
/// service's CAS; this does not advance a local authority checkpoint.
pub fn seal(state: &SignedState, next: &WriteCapability) -> Result<Vec<u8>> {
    let peer = state
        .state
        .peer
        .as_ref()
        .context("missing peer authority")?;
    peer.validate(&state.state)?;
    ensure!(
        peer.header.next_write_key == next.public_key(),
        "wrong next write capability"
    );
    let aad = context(&peer.header)?;
    let mut key = Zeroizing::new([0; 32]);
    getrandom::fill(key.as_mut())?;
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce)?;
    let plaintext = Zeroizing::new(state.encode()?);
    let ciphertext = ChaCha20Poly1305::new((&*key).into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("configuration encryption failed"))?;
    let mut recipients = BTreeMap::new();
    for (id, member) in &state.state.nodes {
        let verifying = VerifyingKey::from_bytes(&member.signing_key)?;
        ensure!(!verifying.is_weak(), "weak recipient key");
        let public = verifying.to_montgomery().to_bytes();
        let mut noise = snow::Builder::with_resolver(
            NOISE.parse()?,
            Box::new(crate::authority::noise::Resolver),
        )
        .prologue(&aad)?
        .remote_public_key(&public)?
        .build_initiator()?;
        let mut secret = Zeroizing::new([0; 65]);
        secret[..32].copy_from_slice(&*key);
        if member.can_configure {
            secret[32..64].copy_from_slice(next.secret().as_ref());
            secret[64] = 1;
        }
        let mut wrapped = [0; WRAPPED_BYTES];
        let length = noise.write_message(secret.as_ref(), &mut wrapped)?;
        ensure!(
            length == WRAPPED_BYTES && noise.is_handshake_finished(),
            "incomplete key envelope"
        );
        recipients.insert(id.clone(), STANDARD.encode(wrapped));
    }
    let bytes = serde_json::to_vec(&Envelope {
        version: 1,
        recipients,
        nonce,
        ciphertext: STANDARD.encode(ciphertext),
    })?;
    ensure!(
        bytes.len() <= MAX_CIPHERTEXT_BYTES,
        "configuration envelope too large"
    );
    Ok(bytes)
}

/// Verified plaintext and the next log checkpoint. Save these fields in one
/// endpoint transaction, including the newly rotated write capability.
pub struct OpenedCommit {
    pub state: VerifiedState,
    pub head: Head,
    pub capability: Option<WriteCapability>,
}

pub fn open(
    node: &NodeIdentity,
    previous: &VerifiedState,
    head: &Head,
    commit: &Commit,
) -> Result<OpenedCommit> {
    ensure!(
        &commit.header.previous == head && commit.header.cluster == previous.anchor().cluster_id,
        "wrong configuration log checkpoint"
    );
    crate::configuration_log::verify(commit)?;
    let bytes = STANDARD.decode(&commit.ciphertext)?;
    ensure!(
        bytes.len() <= MAX_CIPHERTEXT_BYTES,
        "configuration envelope too large"
    );
    let envelope: Envelope = serde_json::from_slice(&bytes)?;
    ensure!(
        envelope.version == 1 && envelope.recipients.len() <= 1024,
        "invalid configuration envelope"
    );
    let wrapped = STANDARD.decode(
        envelope
            .recipients
            .get(node.id())
            .context("node excluded from configuration")?,
    )?;
    ensure!(wrapped.len() == WRAPPED_BYTES, "invalid key envelope");
    let aad = context(&commit.header)?;
    let scalar = Zeroizing::new(node.key.to_scalar_bytes());
    let mut noise =
        snow::Builder::with_resolver(NOISE.parse()?, Box::new(crate::authority::noise::Resolver))
            .prologue(&aad)?
            .local_private_key(scalar.as_ref())?
            .build_responder()?;
    let mut secret = Zeroizing::new([0; 65]);
    ensure!(
        noise.read_message(&wrapped, secret.as_mut())? == 65 && noise.is_handshake_finished(),
        "invalid record key"
    );
    let ciphertext = STANDARD.decode(&envelope.ciphertext)?;
    ensure!(
        ciphertext.len() <= MAX_STATE_BYTES + 16,
        "encrypted state too large"
    );
    let plaintext = Zeroizing::new(
        ChaCha20Poly1305::new_from_slice(&secret[..32])?
            .decrypt(
                (&envelope.nonce).into(),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("configuration authentication failed"))?,
    );
    let signed = SignedState::decode(&plaintext)?;
    let member = signed
        .state
        .nodes
        .get(node.id())
        .context("node not enrolled in committed state")?;
    ensure!(
        member.signing_key == node.public_key(),
        "recipient key changed"
    );
    ensure!(
        envelope.recipients.keys().eq(signed.state.nodes.keys()),
        "configuration recipient set mismatch"
    );
    let capability = if member.can_configure {
        ensure!(secret[64] == 1, "administrator capability missing");
        let capability = WriteCapability::from_secret(secret[32..64].try_into()?);
        ensure!(
            capability.public_key() == commit.header.next_write_key,
            "capability rotation mismatch"
        );
        Some(capability)
    } else {
        ensure!(
            secret[64] == 0 && secret[32..64] == [0; 32],
            "restricted node received a write capability"
        );
        None
    };
    let mut state = previous.clone();
    let head = state.advance_committed(signed, commit, head)?;
    Ok(OpenedCommit {
        state,
        head,
        capability,
    })
}
