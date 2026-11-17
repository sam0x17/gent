//! Admission to an opaque ordered log. This authenticates possession of the
//! current write capability, not node policy or encrypted state contents.
//! Endpoints must additionally verify the node signature and prior authority.
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use gent_protocol::configuration_log::{Commit, Head, Header, MAX_CIPHERTEXT_BYTES, Receipt};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const ADMISSION_DOMAIN: &[u8] = b"gent/configuration-admission/v1\0";
const RECORD_DOMAIN: &[u8] = b"gent/configuration-record/v1\0";
const INTENT_DOMAIN: &[u8] = b"gent/configuration-intent/v1\0";

/// Short-lived capability, never exposed through Debug or implicit serialization.
pub struct WriteCapability(SigningKey);

impl WriteCapability {
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut())?;
        Ok(Self::from_secret(&seed))
    }

    pub fn from_secret(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Endpoint encrypted storage/envelopes only.
    pub fn secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.0.as_bytes())
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn seal(&self, header: Header, ciphertext: &[u8]) -> Result<Commit> {
        ensure!(
            header.previous.write_key == self.public_key(),
            "wrong write capability"
        );
        ensure!(header.valid(), "invalid configuration header");
        ensure!(
            (16..=MAX_CIPHERTEXT_BYTES).contains(&ciphertext.len()),
            "invalid ciphertext size"
        );
        let mut commit = Commit {
            header,
            ciphertext: STANDARD.encode(ciphertext),
            signature: Vec::new(),
        };
        commit.signature = self.0.sign(&admission_input(&commit)?).to_bytes().to_vec();
        verify(&commit)?;
        Ok(commit)
    }
}

/// The caller persists a fresh random salt with the pending operation and
/// includes it only in endpoint-encrypted content. Reuse it for every rebase.
pub fn intent(salt: &[u8; 32], operation: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(INTENT_DOMAIN);
    hash.update(salt);
    hash.update(operation);
    hash.finalize().into()
}

fn ciphertext(commit: &Commit) -> Result<Vec<u8>> {
    ensure!(
        commit.ciphertext.len() <= MAX_CIPHERTEXT_BYTES.div_ceil(3) * 4,
        "ciphertext too large"
    );
    let bytes = STANDARD.decode(&commit.ciphertext)?;
    ensure!(
        (16..=MAX_CIPHERTEXT_BYTES).contains(&bytes.len())
            && STANDARD.encode(&bytes) == commit.ciphertext,
        "invalid ciphertext encoding"
    );
    Ok(bytes)
}

fn admission_input(commit: &Commit) -> Result<Vec<u8>> {
    let mut input = ADMISSION_DOMAIN.to_vec();
    input.extend(serde_jcs::to_vec(&commit.header)?);
    input.extend(Sha256::digest(ciphertext(commit)?));
    Ok(input)
}

pub fn validate_write_key(key: &[u8; 32]) -> Result<()> {
    let key = VerifyingKey::from_bytes(key)?;
    ensure!(!key.is_weak(), "weak configuration admission key");
    Ok(())
}

/// Verify against the header's key. The service must separately compare the
/// *entire* previous head with its durable head within serialized admission.
pub fn verify(commit: &Commit) -> Result<Receipt> {
    ensure!(commit.header.valid(), "invalid configuration header");
    validate_write_key(&commit.header.next_write_key)?;
    let key = VerifyingKey::from_bytes(&commit.header.previous.write_key)?;
    key.verify_strict(
        &admission_input(commit)?,
        &Signature::from_slice(&commit.signature)?,
    )?;
    let mut hash = Sha256::new();
    hash.update(RECORD_DOMAIN);
    hash.update(serde_jcs::to_vec(commit)?);
    Ok(Receipt {
        cluster: commit.header.cluster.clone(),
        origin: commit.header.origin.clone(),
        operation: commit.header.operation.clone(),
        intent: commit.header.intent,
        head: Head {
            sequence: commit.header.previous.sequence + 1,
            digest: hash.finalize().into(),
            write_key: commit.header.next_write_key,
        },
    })
}
