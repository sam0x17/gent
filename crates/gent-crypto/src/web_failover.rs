//! A configuration writer may carry web state without disclosing its keys.
use anyhow::{Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use gent_protocol::{configuration_log::Head, hosted_mcp::valid_id, web_failover::Admission};

fn input(proof: &Admission) -> Result<Vec<u8>> {
    let mut bytes = b"gent/web-carrier-admission/v1\0".to_vec();
    bytes.extend(serde_jcs::to_vec(&(
        proof.version,
        &proof.cluster,
        &proof.node,
        &proof.web,
        &proof.head,
        proof.expires_at,
        proof.body_hash,
    ))?);
    Ok(bytes)
}

pub fn sign(secret: &[u8; 32], mut proof: Admission) -> Result<Admission> {
    let key = SigningKey::from_bytes(secret);
    ensure!(
        key.verifying_key().to_bytes() == proof.head.write_key,
        "web admission key mismatch"
    );
    proof.signature = key.sign(&input(&proof)?).to_bytes().to_vec();
    Ok(proof)
}

pub fn verify(proof: &Admission, current: &Head, now: u64) -> Result<()> {
    ensure!(
        proof.version == 1
            && valid_id(&proof.cluster)
            && valid_id(&proof.node)
            && valid_id(&proof.web)
            && proof.node != proof.web
            && proof.head == *current
            && proof.expires_at > now
            && proof.expires_at <= now.saturating_add(60),
        "web admission is stale or invalid"
    );
    let key = VerifyingKey::from_bytes(&current.write_key)?;
    ensure!(!key.is_weak(), "invalid admission key");
    key.verify_strict(&input(proof)?, &Signature::from_slice(&proof.signature)?)?;
    Ok(())
}
