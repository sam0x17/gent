//! Small node-to-node bootstrap messages, before an MLS link exists. Each
//! payload has a fresh AEAD key wrapped to the recipient with Noise N. Static
//! recipient keys have the same compromise limitations as configuration wraps.
use super::*;
use crate::stream::Packet;
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};

const MAX_BYTES: usize = 600 * 1024;
const NOISE: &str = "Noise_N_25519_ChaChaPoly_SHA256";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    wrapped: String,
    nonce: [u8; 12],
    ciphertext: String,
}

fn context(group: &[u8], sender: &PublicKey, recipient: &PublicKey) -> Result<Vec<u8>> {
    ensure!(group.len() == 16, "invalid direct bootstrap identity");
    let mut aad = b"gent/direct-bootstrap/v1\0".to_vec();
    aad.extend_from_slice(group);
    aad.extend_from_slice(sender);
    aad.extend_from_slice(recipient);
    Ok(aad)
}

pub fn seal(
    node: &NodeIdentity,
    recipient: &PublicKey,
    group: &[u8],
    bytes: &[u8],
) -> Result<Packet> {
    ensure!(bytes.len() <= MAX_BYTES, "bootstrap message too large");
    let public = VerifyingKey::from_bytes(recipient)?;
    ensure!(!public.is_weak(), "weak bootstrap recipient");
    let aad = context(group, &node.public_key(), recipient)?;
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(key.as_mut())?;
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce)?;
    let ciphertext = ChaCha20Poly1305::new((&*key).into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: bytes,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("bootstrap encryption failed"))?;
    let mut noise =
        snow::Builder::with_resolver(NOISE.parse()?, Box::new(crate::authority::noise::Resolver))
            .prologue(&aad)?
            .remote_public_key(&public.to_montgomery().to_bytes())?
            .build_initiator()?;
    let mut wrapped = [0; 80];
    ensure!(
        noise.write_message(key.as_ref(), &mut wrapped)? == 80 && noise.is_handshake_finished(),
        "incomplete bootstrap encryption"
    );
    node.sign_stream_packet(
        group,
        0,
        [0; 32],
        &serde_json::to_vec(&Envelope {
            wrapped: STANDARD.encode(wrapped),
            nonce,
            ciphertext: STANDARD.encode(ciphertext),
        })?,
    )
}

pub fn open(
    node: &NodeIdentity,
    sender: &PublicKey,
    packet: &Packet,
) -> Result<Zeroizing<Vec<u8>>> {
    packet.verify(sender)?;
    ensure!(
        packet.sequence() == 0 && packet.ciphertext().len() <= MAX_BYTES * 4 / 3 + 1024,
        "invalid bootstrap packet"
    );
    let aad = context(packet.group(), sender, &node.public_key())?;
    let envelope: Envelope = serde_json::from_slice(packet.ciphertext())?;
    let wrapped = STANDARD.decode(&envelope.wrapped)?;
    ensure!(wrapped.len() == 80, "invalid bootstrap key envelope");
    let secret = Zeroizing::new(node.key.to_scalar_bytes());
    let mut noise =
        snow::Builder::with_resolver(NOISE.parse()?, Box::new(crate::authority::noise::Resolver))
            .prologue(&aad)?
            .local_private_key(secret.as_ref())?
            .build_responder()?;
    let mut key = Zeroizing::new([0; 32]);
    ensure!(
        noise.read_message(&wrapped, key.as_mut())? == 32 && noise.is_handshake_finished(),
        "invalid bootstrap key"
    );
    let ciphertext = STANDARD.decode(envelope.ciphertext)?;
    ensure!(
        ciphertext.len() <= MAX_BYTES + 16,
        "bootstrap message too large"
    );
    Ok(Zeroizing::new(
        ChaCha20Poly1305::new((&*key).into())
            .decrypt(
                (&envelope.nonce).into(),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("bootstrap decryption failed"))?,
    ))
}
