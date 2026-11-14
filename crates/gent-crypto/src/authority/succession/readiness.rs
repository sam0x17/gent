//! Successor readiness, authenticated before the current owner stops signing.
//! Receipts prove installed configuration origins. The successor's signatures
//! additionally attest that its runtime checked the required local data links.
use super::*;
use crate::stream::Receipt;

pub const MAX_READINESS_BYTES: usize = 1536 * 1024;
const NODE_DOMAIN: &[u8] = b"gent/owner-readiness/v1\0";
const KEY_DOMAIN: &[u8] = b"gent/owner-readiness-key/v1\0";
const GRANT_DOMAIN: &[u8] = b"gent/owner-readiness-grant/v1\0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub reader: String,
    pub grant: Digest,
    pub receipt: Receipt,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Readiness {
    pub version: u32,
    pub candidate: Digest,
    pub issued_at: u64,
    pub expires_at: u64,
    pub peers: Vec<Peer>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedReadiness {
    pub readiness: Readiness,
    pub node_signature: Vec<u8>,
    pub key_signature: Vec<u8>,
}

fn grant_digest(grant: &SignedConfigurationGrant) -> Result<Digest> {
    digest(GRANT_DOMAIN, grant, MAX_CONFIGURATION_GRANT_BYTES)
}

impl SignedReadiness {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.readiness.peers.len() <= 1023,
            "too many readiness peers"
        );
        encode(self, MAX_READINESS_BYTES)
    }

    pub fn decode(wire: &[u8]) -> Result<Self> {
        let report: Self = decode(wire, MAX_READINESS_BYTES)?;
        report.encode()?;
        Ok(report)
    }

    /// Grants must come from the current owner's independently saved approvals.
    /// Their order matches the report's canonical ascending reader order.
    pub fn verify(
        &self,
        state: &VerifiedState,
        candidate: &SignedOwnerCandidate,
        grants: &[SignedConfigurationGrant],
        now: u64,
    ) -> Result<()> {
        candidate.verify(state, now)?;
        let r = &self.readiness;
        ensure!(
            r.version == 1
                && r.candidate == candidate.digest()?
                && r.issued_at >= candidate.candidate.issued_at
                && r.expires_at == candidate.candidate.expires_at,
            "readiness belongs to another candidate or approval window"
        );
        fresh(r.issued_at, r.expires_at, now)?;
        let expected: Vec<_> = state
            .state()
            .nodes
            .keys()
            .filter(|id| id.as_str() != candidate.candidate.node.id)
            .collect();
        ensure!(
            r.peers.len() == expected.len() && grants.len() == expected.len(),
            "readiness must cover every enrolled peer exactly once"
        );
        let mut groups = BTreeSet::new();
        for ((peer, reader), grant) in r.peers.iter().zip(expected).zip(grants) {
            ensure!(
                &peer.reader == reader,
                "readiness peers are missing, duplicated or unordered"
            );
            grant.verify_owner_candidate(candidate)?;
            grant.verify_initial(state, now)?;
            let g = &grant.grant;
            ensure!(
                g.reader == peer.reader
                    && peer.grant == grant_digest(grant)?
                    && peer.receipt.group() == g.group
                    && peer.receipt.sequence() == 0
                    && peer.receipt.digest() == g.origin
                    && groups.insert(g.group.as_slice()),
                "readiness does not match the approved configuration origin"
            );
            peer.receipt.verify(&g.reader_key)?;
        }
        verify(
            &candidate.candidate.node.signing_key,
            NODE_DOMAIN,
            r,
            &self.node_signature,
            MAX_READINESS_BYTES,
        )?;
        verify(
            &candidate.candidate.owner_key,
            KEY_DOMAIN,
            r,
            &self.key_signature,
            MAX_READINESS_BYTES,
        )?;
        self.encode()?;
        Ok(())
    }
}

impl NodeIdentity {
    /// The trusted runtime must check durable local links and keys before signing.
    pub fn sign_owner_readiness(
        &self,
        state: &VerifiedState,
        key: &OwnerKey,
        candidate: &SignedOwnerCandidate,
        connections: &[(SignedConfigurationGrant, Receipt)],
        now: u64,
    ) -> Result<SignedReadiness> {
        ensure!(
            candidate.candidate.node.id == self.id()
                && candidate.candidate.node.signing_key == self.public_key()
                && candidate.candidate.owner_key == key.public_key(),
            "readiness requires the candidate's node and owner keys"
        );
        let mut ordered: Vec<_> = connections.iter().collect();
        ordered.sort_by(|a, b| a.0.grant.reader.cmp(&b.0.grant.reader));
        let peers = ordered
            .iter()
            .map(|(grant, receipt)| {
                Ok(Peer {
                    reader: grant.grant.reader.clone(),
                    grant: grant_digest(grant)?,
                    receipt: receipt.clone(),
                })
            })
            .collect::<Result<_>>()?;
        let readiness = Readiness {
            version: 1,
            candidate: candidate.digest()?,
            issued_at: now,
            expires_at: candidate.candidate.expires_at,
            peers,
        };
        let signed = SignedReadiness {
            node_signature: self
                .key
                .sign(&signing_input(
                    NODE_DOMAIN,
                    &readiness,
                    MAX_READINESS_BYTES,
                )?)
                .to_bytes()
                .to_vec(),
            key_signature: key
                .0
                .sign(&signing_input(KEY_DOMAIN, &readiness, MAX_READINESS_BYTES)?)
                .to_bytes()
                .to_vec(),
            readiness,
        };
        let grants: Vec<_> = ordered.iter().map(|(g, _)| g.clone()).collect();
        signed.verify(state, candidate, &grants, now)?;
        Ok(signed)
    }
}
