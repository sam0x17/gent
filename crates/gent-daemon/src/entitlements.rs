//! Bounded offline access. Only the hosted account authority signs leases.
use crate::config::{self, Config};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use gent_protocol::service::{
    AccountPlan, ENTITLEMENT_LEASE_SECONDS, ENTITLEMENT_PUBLIC_KEY, SignedEntitlements,
};
use std::{
    fs,
    io::Read,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const FIXTURE_AUTHORITY: bool = cfg!(feature = "test-entitlements");

const FILE: &str = "account-entitlements.json";

fn check(signed: &SignedEntitlements, cfg: &Config, now: u64, public_key: &[u8; 32]) -> Result<()> {
    let lease = &signed.lease;
    ensure!(
        lease.node_id == cfg.node.id
            && lease.cluster_id == cfg.cluster.id
            && cfg
                .service
                .as_ref()
                .is_some_and(|s| s.account_id == lease.account_id)
            && lease.valid_until > now
            && lease.valid_until <= now.saturating_add(ENTITLEMENT_LEASE_SECONDS + 60),
        "expired or mismatched Gent account entitlement"
    );
    let key = VerifyingKey::from_bytes(public_key)?;
    key.verify_strict(
        &lease.signing_bytes(),
        &Signature::from_slice(&STANDARD.decode(&signed.signature)?)?,
    )?;
    Ok(())
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub fn install(home: &Path, cfg: &Config, signed: &SignedEntitlements) -> Result<()> {
    check(signed, cfg, now()?, ENTITLEMENT_PUBLIC_KEY)?;
    config::write_private(&home.join(FILE), &serde_json::to_vec(signed)?)
}

pub fn clear(home: &Path) -> Result<()> {
    match fs::remove_file(home.join(FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub fn paid(home: &Path, cfg: &Config) -> bool {
    #[cfg(any(test, feature = "test-entitlements"))]
    if cfg.service.as_ref().is_none_or(|s| {
        reqwest::Url::parse(&s.origin).is_ok_and(|url| !crate::backend::ACCOUNT.contains(&url))
    }) && fs::read_to_string(home.join("test-entitlement")).is_ok_and(|id| id == cfg.node.id)
    {
        return true;
    }
    let read = || -> Result<bool> {
        let mut data = Vec::new();
        fs::File::open(home.join(FILE))?
            .take(2049)
            .read_to_end(&mut data)?;
        ensure!(data.len() <= 2048, "invalid entitlement size");
        let signed: SignedEntitlements =
            serde_json::from_slice(&data).context("invalid entitlement")?;
        check(&signed, cfg, now()?, ENTITLEMENT_PUBLIC_KEY)?;
        Ok(signed.lease.plan == AccountPlan::Pro)
    };
    read().unwrap_or(false)
}

#[cfg(any(test, feature = "test-entitlements"))]
pub fn grant_test(home: &Path, cfg: &Config) {
    config::write_private(&home.join("test-entitlement"), cfg.node.id.as_bytes()).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use gent_protocol::service::Entitlements;

    #[test]
    fn scope_expiry_and_plan_are_signed() {
        let mut cfg = config::fresh("billing-fixture").unwrap();
        let account = uuid::Uuid::new_v4().to_string();
        cfg.service = Some(config::ServiceConfig {
            origin: "https://api.gent.link".into(),
            account_id: account.clone(),
        });
        let lease = Entitlements {
            plan: AccountPlan::Pro,
            account_id: account,
            cluster_id: cfg.cluster.id.clone(),
            node_id: cfg.node.id.clone(),
            valid_until: 1_900,
        };
        let key = SigningKey::from_bytes(&[92; 32]);
        let signed = SignedEntitlements {
            signature: STANDARD.encode(key.sign(&lease.signing_bytes()).to_bytes()),
            lease,
        };
        let pk = key.verifying_key().to_bytes();
        assert!(check(&signed, &cfg, 1_000, &pk).is_ok());
        assert!(check(&signed, &cfg, 1_900, &pk).is_err());
        assert!(check(&signed, &cfg, 1, &pk).is_err());
        assert!(check(&signed, &cfg, 1_000, ENTITLEMENT_PUBLIC_KEY).is_err());
        let mut changed = signed.clone();
        changed.lease.plan = AccountPlan::Free;
        assert!(check(&changed, &cfg, 1_000, &pk).is_err());
        for field in ["node", "cluster", "account"] {
            let mut other = cfg.clone();
            let different = uuid::Uuid::new_v4().to_string();
            match field {
                "node" => other.node.id = different,
                "cluster" => other.cluster.id = different,
                _ => other.service.as_mut().unwrap().account_id = different,
            }
            assert!(check(&signed, &other, 1_000, &pk).is_err());
        }
    }
}
