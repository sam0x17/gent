//! An intentionally bounded RS256 private_key_jwt profile. Keys are imported
//! by the local owner, never selected from JWT URLs or embedded key material.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io::Read, path::Path};

pub(crate) const TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
pub(crate) const MAX_LIFETIME: u64 = 300;
pub(crate) const CLOCK_SKEW: u64 = 30;
const MAX_JWKS: usize = 64 * 1024;
#[cfg(test)]
pub(crate) mod tests;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    pub client_id: String,
    keys: Vec<Key>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    kty: String,
    kid: String,
    n: String,
    e: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    usage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_ops: Option<Vec<String>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Jwks {
    keys: Vec<Key>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    typ: Option<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}
impl Audience {
    fn exact(&self, issuer: &str, token: &str) -> bool {
        let value = match self {
            Self::Single(value) => value,
            Self::Multiple(values) if values.len() == 1 => &values[0],
            _ => return false,
        };
        value == issuer || value == token
    }
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    iat: u64,
    nbf: Option<u64>,
    jti: String,
}

fn text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
fn decode(value: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(value)?;
    ensure!(
        URL_SAFE_NO_PAD.encode(&bytes) == value,
        "noncanonical assertion encoding"
    );
    Ok(bytes)
}
impl Policy {
    pub(crate) fn equivalent(&self, other: &Self) -> bool {
        self.client_id == other.client_id
            && self.keys.len() == other.keys.len()
            && self.keys.iter().all(|key| other.keys.contains(key))
    }
    pub(crate) fn key_ids(&self) -> Vec<&str> {
        self.keys.iter().map(|key| key.kid.as_str()).collect()
    }
    pub(crate) fn load(path: &Path, client_id: &str) -> Result<Self> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take((MAX_JWKS + 1) as u64)
            .read_to_end(&mut bytes)?;
        Self::from_jwks(&bytes, client_id)
    }
    pub(crate) fn from_jwks(bytes: &[u8], client_id: &str) -> Result<Self> {
        ensure!(bytes.len() <= MAX_JWKS, "client JWKS is too large");
        let jwks: Jwks = serde_json::from_slice(bytes).context("invalid public client JWKS")?;
        let policy = Self {
            client_id: client_id.into(),
            keys: jwks.keys,
        };
        policy.validate()?;
        Ok(policy)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let id = url::Url::parse(&self.client_id)?;
        ensure!(
            self.client_id.len() <= 2048
                && id.as_str() == self.client_id
                && id.scheme() == "https"
                && id.host_str().is_some()
                && id.username().is_empty()
                && id.password().is_none()
                && id.path() != "/"
                && id.query().is_none()
                && id.fragment().is_none(),
            "assertion client ID must be an exact HTTPS URL with a path and no credentials, query or fragment"
        );
        ensure!(
            !self.keys.is_empty() && self.keys.len() <= 8,
            "pin 1-8 public RSA keys"
        );
        let mut kids = BTreeSet::new();
        for key in &self.keys {
            ensure!(
                key.kty == "RSA"
                    && text(&key.kid, 128)
                    && kids.insert(&key.kid)
                    && key.alg.as_deref().is_none_or(|v| v == "RS256")
                    && key.usage.as_deref().is_none_or(|v| v == "sig")
                    && key.key_ops.as_ref().is_none_or(|v| v == &["verify"]),
                "invalid RSA signing key metadata"
            );
            ensure!(key.n.len() <= 683 && key.e.len() <= 4, "oversized RSA key");
            let n = decode(&key.n)?;
            ensure!(
                (256..=512).contains(&n.len())
                    && n[0] & 0x80 != 0
                    && n[n.len() - 1] & 1 != 0
                    && decode(&key.e)? == [1, 0, 1],
                "use an RSA 2048-4096 bit key with exponent 65537"
            );
        }
        Ok(())
    }
    /// Returns the replay identifier and its last possible acceptance time.
    /// The registry consumes it in the same transaction as the token request.
    pub(crate) fn verify(&self, raw: &str, resource: &str, now: u64) -> Result<(String, u64)> {
        ensure!(raw.len() <= 4096, "client assertion too large");
        let parts: Vec<_> = raw.split('.').collect();
        ensure!(parts.len() == 3, "invalid client assertion");
        let header: Header = serde_json::from_slice(&decode(parts[0])?)?;
        ensure!(
            header.alg == "RS256" && header.typ.as_deref().is_none_or(|v| v == "JWT"),
            "unsupported assertion header"
        );
        let key = self
            .keys
            .iter()
            .find(|k| k.kid == header.kid)
            .context("unknown assertion key")?;
        let signature = decode(parts[2])?;
        signature::RsaPublicKeyComponents {
            n: decode(&key.n)?,
            e: decode(&key.e)?,
        }
        .verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &signature,
        )
        .map_err(|_| anyhow::anyhow!("invalid assertion signature"))?;
        let claims: Claims = serde_json::from_slice(&decode(parts[1])?)?;
        let issuer = resource
            .strip_suffix("/mcp")
            .context("invalid assertion resource")?;
        ensure!(
            claims.iss == self.client_id
                && claims.sub == self.client_id
                && claims.aud.exact(issuer, &format!("{issuer}/oauth/token"))
                && claims.exp > now
                && claims.exp > claims.iat
                && claims.exp - claims.iat <= MAX_LIFETIME
                && claims.iat <= now.saturating_add(CLOCK_SKEW)
                && claims.nbf.is_none_or(|v| v <= now && v < claims.exp)
                && text(&claims.jti, 128),
            "invalid assertion claims"
        );
        Ok((claims.jti, claims.exp))
    }
}
