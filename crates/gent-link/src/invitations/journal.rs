//! Persist the exact invocation before network I/O. An uncertain call must be
//! resolved before accepting a new action, including after a process restart.
use super::*;
use gent_crypto::{
    NodeIdentity,
    invitation::{ClaimedNode, Purpose, SignedOffer},
};
use gent_daemon::store::invitations::{Action, Invocation};
use std::collections::BTreeMap;

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_OPERATIONS: usize = 8192;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u8,
    offer: SignedOffer,
    name: String,
    node: Option<ClaimedNode>,
    session: String,
    bearer: String,
    operations: BTreeMap<String, Invocation>,
    pending: Option<String>,
    receipt: Option<Value>,
    superseded: Vec<String>,
}
pub(super) struct Journal {
    path: PathBuf,
    saved: Saved,
    _lock: std::fs::File,
}
fn digest(action: &Action) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_jcs::to_vec(action)?)))
}
impl Journal {
    pub fn open(
        home: &Path,
        offer: &SignedOffer,
        name: &str,
        session: &str,
        replace: bool,
    ) -> Result<Self> {
        config::label(name)?;
        let directory = home.join("auth");
        config::private_dir(&directory)?;
        let lock = managed_file::lock(&directory.join("invitation-join.lock"))?;
        let path = directory.join("invitation-join.json");
        let snapshot = private(&path)?;
        let mut saved: Saved = match snapshot.text.as_deref() {
            Some(text) => serde_json::from_str(text).map_err(|_| {
                anyhow::anyhow!("invalid invitation join journal; restore it from backup")
            })?,
            None => {
                ensure!(
                    !config::path(home).exists() && !config::pending_join(home)?.exists(),
                    "invitation join journal is missing; existing node state was preserved"
                );
                Saved {
                    version: 1,
                    offer: offer.clone(),
                    name: name.into(),
                    node: None,
                    session: session.into(),
                    bearer: auth::invitation_candidate()?,
                    operations: BTreeMap::new(),
                    pending: None,
                    receipt: None,
                    superseded: Vec::new(),
                }
            }
        };
        ensure!(
            saved.version == 1
                && saved.name == name
                && saved.operations.len() <= MAX_OPERATIONS
                && saved.superseded.len() <= 16
                && gent_protocol::service::invitations::credential_created_at(&saved.bearer)
                    .is_some(),
            "invalid invitation join journal or changed node name"
        );
        saved.offer.fingerprint()?;
        for (key, invocation) in &saved.operations {
            ensure!(
                gent_protocol::service::invitations::valid_attempt(&invocation.id)
                    && digest(&invocation.action)? == *key,
                "invalid saved invitation invocation"
            );
            invocation.encode()?;
        }
        ensure!(
            saved
                .pending
                .as_ref()
                .is_none_or(|key| saved.operations.contains_key(key)),
            "pending invitation invocation is missing"
        );
        if saved.offer != *offer {
            ensure!(
                replace,
                "a different invitation is already staged; use --continue to replace it while preserving this node"
            );
            let old = &saved.offer.offer;
            let new = &offer.offer;
            ensure!(
                old.anchor == new.anchor
                    && old.issuer_id == new.issuer_id
                    && old.issuer_key == new.issuer_key
                    && old.service == new.service
                    && old.can_configure == new.can_configure
                    && saved.node.is_some()
                    && saved.receipt.is_none()
                    && !saved.superseded.contains(&new.id)
                    && saved.superseded.len() < 16,
                "replacement invitation changes the pinned owner, service, privileges or completed join"
            );
            if let Purpose::Continue { node } = &new.purpose {
                ensure!(
                    saved.node.as_ref() == Some(node),
                    "continuation invitation belongs to another node"
                );
            }
            saved.superseded.push(old.id.clone());
            saved.offer = offer.clone();
            saved.operations.clear();
            saved.pending = None;
            saved.bearer = auth::invitation_candidate()?;
            saved.session = session.into();
        }
        ensure!(
            saved.session == session,
            "invitation exchange is pinned to the original login; obtain a replacement invitation and use --continue"
        );
        let journal = Self {
            path,
            saved,
            _lock: lock,
        };
        journal.save()?;
        Ok(journal)
    }
    fn save(&self) -> Result<()> {
        let text = serde_json::to_string(&self.saved)?;
        ensure!(
            text.len() <= MAX_BYTES,
            "invitation join journal capacity reached"
        );
        private(&self.path)?.write(&text)
    }
    pub fn bearer(&self) -> &str {
        &self.saved.bearer
    }
    pub fn node(&self) -> Option<&ClaimedNode> {
        self.saved.node.as_ref()
    }
    pub fn bind(&mut self, node: &NodeIdentity, name: &str) -> Result<()> {
        let claim = ClaimedNode {
            id: node.id().into(),
            key: node.public_key(),
            name: name.into(),
        };
        ensure!(
            name == self.saved.name && self.saved.node.as_ref().is_none_or(|saved| *saved == claim),
            "staged invitation identity changed"
        );
        if let Purpose::Continue { node } = &self.saved.offer.offer.purpose {
            ensure!(
                *node == claim,
                "continuation requires the original staged node identity"
            );
        }
        self.saved.node = Some(claim);
        self.save()
    }
    pub fn pending(&self) -> Option<Invocation> {
        self.saved
            .pending
            .as_ref()
            .and_then(|key| self.saved.operations.get(key))
            .cloned()
    }
    pub fn receipt(&self) -> Option<&Value> {
        self.saved.receipt.as_ref()
    }
    pub fn reserve(&mut self, action: Action) -> Result<Invocation> {
        let key = digest(&action)?;
        ensure!(
            self.saved
                .pending
                .as_ref()
                .is_none_or(|pending| *pending == key),
            "resolve the pending invitation invocation before sending another"
        );
        if !self.saved.operations.contains_key(&key) {
            ensure!(
                self.saved.operations.len() < MAX_OPERATIONS,
                "invitation invocation capacity reached"
            );
            self.saved.operations.insert(
                key.clone(),
                Invocation {
                    id: Uuid::new_v4().to_string(),
                    action,
                },
            );
        }
        self.saved.pending = Some(key.clone());
        self.save()?;
        Ok(self.saved.operations[&key].clone())
    }
    pub fn complete(&mut self, invocation: &Invocation, value: &Value) -> Result<()> {
        let key = digest(&invocation.action)?;
        ensure!(
            self.saved.pending.as_ref() == Some(&key)
                && self
                    .saved
                    .operations
                    .get(&key)
                    .is_some_and(|saved| saved.id == invocation.id),
            "invitation completion does not match pending invocation"
        );
        if matches!(invocation.action, Action::Finish) {
            ensure!(
                value["finished"] == true
                    && value["invitation"] == self.saved.offer.offer.id
                    && self.node().is_some_and(|node| value["node"] == node.id),
                "invalid invitation completion receipt"
            );
            self.saved.receipt = Some(value.clone());
        }
        self.saved.pending = None;
        self.save()
    }
}
