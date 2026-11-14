//! Private, authenticated node control traffic. No step can stop signing or
//! activate an owner; those operations require separate local owner consent.
use gent_crypto::{Checkpoint, TrustAnchor, succession::SignedOwnerCandidate};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub id: Uuid,
    pub anchor: TrustAnchor,
    pub base: Checkpoint,
    pub source: String,
    pub successor: String,
    pub expires_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u8,
    pub plan: Plan,
    pub origin: String,
    pub target: String,
    pub candidate: Option<SignedOwnerCandidate>,
    pub step: Step,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    Begin,
    Candidate,
    Offer,
    Package {
        package: String,
    },
    Prepared {
        reader: String,
        packet: String,
    },
    Grant {
        reader: String,
        grant: Box<gent_crypto::SignedConfigurationGrant>,
    },
    Invitation {
        packet: String,
        grant: Box<gent_crypto::SignedConfigurationGrant>,
    },
    Confirmed {
        receipt: gent_crypto::stream::Receipt,
    },
    Ready {
        report: gent_crypto::succession::readiness::SignedReadiness,
    },
}

impl Envelope {
    pub(crate) fn id(&self) -> Uuid {
        let (step, reader) = match &self.step {
            Step::Begin => ("begin", ""),
            Step::Candidate => ("candidate", ""),
            Step::Offer => ("offer", ""),
            Step::Package { .. } => ("package", ""),
            Step::Prepared { reader, .. } => ("prepared", reader.as_str()),
            Step::Grant { reader, .. } => ("grant", reader.as_str()),
            Step::Invitation { .. } => ("invitation", ""),
            Step::Confirmed { .. } => ("confirmed", ""),
            Step::Ready { .. } => ("ready", ""),
        };
        gent_crypto::scoped_id(
            b"gent/owner-preparation-event/v1\0",
            &[
                self.plan.id.as_bytes(),
                self.origin.as_bytes(),
                self.target.as_bytes(),
                step.as_bytes(),
                reader.as_bytes(),
            ],
        )
    }
}
