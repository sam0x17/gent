//! Ephemeral, end-to-end encrypted payloads on the live peer watch. The caller
//! selects the authorized directional data group and validates exchange freshness.
use super::{Provider, load_group};
use anyhow::{Context, Result, ensure};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;
use zeroize::Zeroizing;

pub(crate) const MAGIC: &[u8; 5] = b"GNST\x01";
const NONCE: usize = 24;
const TAG: usize = 16;
const MAX_PLAIN: usize = 128 * 1024;
pub(crate) const MAX_WIRE_BYTES: usize = MAGIC.len() + NONCE + TAG + MAX_PLAIN;

fn cipher(db: &Connection, group: &[u8]) -> Result<XChaCha20Poly1305> {
    let provider = Provider::new(db);
    let mls = load_group(&provider, group)?;
    ensure!(mls.members().count() == 2, "expected a two-node Stats link");
    // RFC 9420 section 8.5 binds the exported secret to the current epoch.
    // The two stream directions have separate MLS groups and exporter keys.
    let key =
        Zeroizing::new(mls.export_secret(provider.crypto(), "gent/stats/wss/v1", group, 32)?);
    Ok(XChaCha20Poly1305::new_from_slice(&key)?)
}

pub(crate) fn seal(db: &Connection, group: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        (1..=MAX_PLAIN).contains(&plaintext.len()),
        "invalid Stats payload length"
    );
    let mut nonce = [0; NONCE];
    getrandom::fill(&mut nonce)?;
    let encrypted = cipher(db, group)?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: MAGIC,
            },
        )
        .map_err(|_| anyhow::anyhow!("could not encrypt Stats payload"))?;
    let mut wire = Vec::with_capacity(MAGIC.len() + NONCE + encrypted.len());
    wire.extend_from_slice(MAGIC);
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&encrypted);
    Ok(wire)
}

pub(crate) fn open(db: &Connection, group: &[u8], wire: &[u8]) -> Result<Vec<u8>> {
    let body = wire
        .strip_prefix(MAGIC)
        .context("unsupported Stats frame")?;
    ensure!(
        body.len() > NONCE + TAG && wire.len() <= MAX_WIRE_BYTES,
        "invalid Stats frame length"
    );
    let (nonce, encrypted) = body.split_at(NONCE);
    cipher(db, group)?
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: encrypted,
                aad: MAGIC,
            },
        )
        .map_err(|_| anyhow::anyhow!("invalid Stats ciphertext"))
}
