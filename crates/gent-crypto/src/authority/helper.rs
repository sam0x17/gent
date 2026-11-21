use super::*;

const DOMAIN: &[u8] = b"gent/native-helper-peer/v1\0";

impl NodeIdentity {
    /// Authenticate a challenge on one native QUIC connection.
    pub fn sign_helper_channel(&self, transcript: &Digest) -> Result<[u8; 64]> {
        Ok(self
            .key
            .sign(&signing_input(DOMAIN, transcript, 256)?)
            .to_bytes())
    }
}

pub fn verify_helper_channel(key: &PublicKey, transcript: &Digest, signature: &[u8]) -> Result<()> {
    verify(key, DOMAIN, transcript, signature, 256)
}
