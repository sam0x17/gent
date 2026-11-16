//! A manually transferred 256-bit code authenticates encrypted bootstrap data.
//! Never send the code, or its encryption key, to the routing service. This is
//! deliberately not a short password scheme and has no human-chosen passwords.
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

mod names;

pub struct Code {
    secret: Zeroizing<[u8; 32]>,
    names: Option<(String, String)>,
}

impl Code {
    pub fn generate() -> Result<Self> {
        let mut secret = Zeroizing::new([0; 32]);
        getrandom::fill(secret.as_mut())
            .map_err(|_| anyhow::anyhow!("pairing randomness unavailable"))?;
        Ok(Self {
            secret,
            names: None,
        })
    }

    pub fn named(cluster: &str, node: &str) -> Result<Self> {
        names::validate(cluster)?;
        names::validate(node)?;
        let mut code = Self::generate()?;
        code.names = Some((cluster.into(), node.into()));
        Ok(code)
    }

    pub fn names(&self) -> Option<(&str, &str)> {
        self.names
            .as_ref()
            .map(|(cluster, node)| (cluster.as_str(), node.as_str()))
    }

    pub fn parse(value: &str) -> Result<Self> {
        ensure!(value.len() <= 1024, "invalid pairing code");
        let (names, raw) = if let Some(raw) = value.strip_prefix("gent2-") {
            let mut parts = raw.split('.');
            let cluster = names::decode(parts.next().unwrap_or_default())?;
            let node = names::decode(parts.next().unwrap_or_default())?;
            let secret = parts.next().unwrap_or_default();
            ensure!(parts.next().is_none(), "invalid pairing code");
            (Some((cluster, node)), secret)
        } else {
            (
                None,
                value
                    .strip_prefix("gent1-")
                    .ok_or_else(|| anyhow::anyhow!("invalid pairing code"))?,
            )
        };
        ensure!(raw.len() == 43, "invalid pairing code");
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(raw)
                .map_err(|_| anyhow::anyhow!("invalid pairing code"))?,
        );
        let mut secret = Zeroizing::new([0; 32]);
        ensure!(
            bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes.as_slice()) == raw,
            "invalid pairing code"
        );
        secret.copy_from_slice(&bytes);
        Ok(Self { secret, names })
    }

    pub fn expose(&self) -> Zeroizing<String> {
        let secret = URL_SAFE_NO_PAD.encode(self.secret.as_slice());
        Zeroizing::new(match &self.names {
            Some((cluster, node)) => format!(
                "gent2-{}.{}.{secret}",
                names::encode(cluster),
                names::encode(node)
            ),
            None => format!("gent1-{secret}"),
        })
    }

    pub fn id(&self) -> String {
        let mut hash = Sha256::new();
        if let Some(names) = &self.names {
            hash.update(b"gent/pairing-lookup/v2\0");
            hash.update(serde_json::to_vec(names).expect("string tuple"));
        } else {
            hash.update(b"gent/pairing-lookup/v1\0");
        }
        hash.update(self.secret.as_slice());
        format!("{:x}", hash.finalize())
    }

    fn key(&self) -> Zeroizing<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(b"gent/pairing-encryption/v1\0");
        hash.update(self.secret.as_slice());
        Zeroizing::new(hash.finalize().into())
    }

    fn context(&self, account: &str, cluster: &str, created: u64, response: bool) -> Vec<u8> {
        // All variable fields are length-framed by JSON; direction prevents reflection.
        if let Some(names) = &self.names {
            return serde_json::to_vec(&(
                "gent/pairing-capsule/v2",
                self.id(),
                account,
                cluster,
                created,
                response,
                names,
            ))
            .expect("string tuple");
        }
        serde_json::to_vec(&(
            "gent/pairing-capsule/v1",
            self.id(),
            account,
            cluster,
            created,
            response,
        ))
        .expect("string tuple")
    }

    pub fn seal(
        &self,
        account: &str,
        cluster: &str,
        created: u64,
        response: bool,
        plaintext: &[u8],
    ) -> Result<String> {
        ensure!(
            plaintext.len() <= 192 * 1024 - 28,
            "pairing capsule too large"
        );
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce)
            .map_err(|_| anyhow::anyhow!("pairing randomness unavailable"))?;
        let key = self.key();
        let cipher = ChaCha20Poly1305::new((&*key).into());
        let aad = self.context(account, cluster, created, response);
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("pairing encryption failed"))?;
        Ok(URL_SAFE_NO_PAD.encode([nonce.as_slice(), &ciphertext].concat()))
    }

    pub fn open(
        &self,
        account: &str,
        cluster: &str,
        created: u64,
        response: bool,
        value: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            value.len() <= gent_protocol::service::pairing::MAX_CAPSULE,
            "pairing capsule too large"
        );
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| anyhow::anyhow!("invalid pairing capsule"))?;
        ensure!(bytes.len() >= 28, "invalid pairing capsule");
        let key = self.key();
        let cipher = ChaCha20Poly1305::new((&*key).into());
        let aad = self.context(account, cluster, created, response);
        cipher
            .decrypt(
                bytes[..12].into(),
                Payload {
                    msg: &bytes[12..],
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| anyhow::anyhow!("pairing code or encrypted approval does not match"))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod legacy_tests {
    use super::*;

    #[test]
    fn code_authenticates_both_directions_and_every_binding() {
        let code = Code::generate().unwrap();
        let restored = Code::parse(&code.expose()).unwrap();
        assert_eq!(code.id(), restored.id());
        let packet = code
            .seal("account", "cluster", 42, true, b"private invitation")
            .unwrap();
        assert_eq!(
            &*restored
                .open("account", "cluster", 42, true, &packet)
                .unwrap(),
            b"private invitation"
        );
        for (account, cluster, created, response) in [
            ("other", "cluster", 42, true),
            ("account", "other", 42, true),
            ("account", "cluster", 43, true),
            ("account", "cluster", 42, false),
        ] {
            assert!(
                code.open(account, cluster, created, response, &packet)
                    .is_err()
            );
        }
        assert!(
            Code::generate()
                .unwrap()
                .open("account", "cluster", 42, true, &packet)
                .is_err()
        );
        let mut bytes = URL_SAFE_NO_PAD.decode(&packet).unwrap();
        bytes[12] ^= 1;
        assert!(
            code.open(
                "account",
                "cluster",
                42,
                true,
                &URL_SAFE_NO_PAD.encode(bytes)
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_short_codes_and_bounds_before_decoding() {
        for value in ["123456", "gent1-password", "gent1-", ""] {
            assert!(Code::parse(value).is_err());
        }
        let code = Code::generate().unwrap();
        assert!(code.open("a", "c", 1, false, "").is_err());
        assert!(
            code.open("a", "c", 1, false, &"x".repeat(256 * 1024 + 1))
                .is_err()
        );
        assert!(code.seal("a", "c", 1, false, &vec![0; 192 * 1024]).is_err());
    }
}
