//! Host and optional user namespaces. OAuth grants pin one host-reported user;
//! reauthorization can recover the same user/conversation without sharing it
//! with another user. The host remains responsible for metadata provenance.
use super::*;

pub(crate) struct BindingKeys {
    pub(crate) conversation: String,
    pub(crate) subject: Option<String>,
}
impl From<&str> for BindingKeys {
    fn from(conversation: &str) -> Self {
        Self {
            conversation: conversation.into(),
            subject: None,
        }
    }
}
impl From<&String> for BindingKeys {
    fn from(conversation: &String) -> Self {
        Self::from(conversation.as_str())
    }
}

pub(super) fn subject_key(key: &str, conversation: &str) -> Result<()> {
    metadata_key(key)?;
    ensure!(
        key.contains('/') && key != conversation && key != "claudecode/toolUseId",
        "subject key must be a distinct host-owned user metadata field"
    );
    Ok(())
}

fn identity<'a>(meta: &'a Value, key: &str) -> Result<&'a str> {
    meta.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty() && s.len() <= 512 && !s.chars().any(char::is_control))
        .context("required host identity metadata is missing or invalid")
}

impl Registry {
    pub(crate) fn credential(&self, permit: &Permit, meta: &Value) -> Result<String> {
        directory_check(&self.directory())?;
        let _lock = managed_file::lock(&self.directory().join("state.lock"))?;
        let mut state = self.read()?;
        let now = auth::now()?;
        let client = Self::client(&state, permit, now)?;
        conversation_key(&client.conversation_key)?;
        let conversation = identity(meta, &client.conversation_key)?;
        let subject = client
            .subject_key
            .as_ref()
            .map(|key| -> Result<_> {
                let value = identity(meta, key)?;
                // Client UUIDs and hashes have fixed encodings; NUL is forbidden
                // in metadata, so these domain-separated tuples are unambiguous.
                Ok(digest(&format!(
                    "gent-gateway-subject-v1\0{}\0{value}",
                    permit.client
                )))
            })
            .transpose()?;
        let pin = if let Some(subject) = &subject {
            let (grant, _) = permit
                .oauth
                .as_ref()
                .context("user binding requires an OAuth grant")?;
            state
                .oauth
                .as_ref()
                .context("missing OAuth state")?
                .check_subject(grant, subject)?
        } else {
            false
        };
        let key = match &subject {
            Some(subject) => digest(&format!(
                "gent-gateway-binding-v2\0{subject}\0{conversation}"
            )),
            None => digest(conversation), // preserve all existing unscoped identities
        };
        let credential = if let Some(value) = client.bindings.get(&key) {
            value.clone()
        } else {
            ensure!(
                client.bindings.len() < MAX_CLIENT_BINDINGS
                    && state
                        .clients
                        .values()
                        .map(|c| c.bindings.len())
                        .sum::<usize>()
                        < MAX_BINDINGS,
                "gateway conversation capacity reached"
            );
            config::secret()
        };
        if pin || state.clock != now || !client.bindings.contains_key(&key) {
            if pin {
                state
                    .oauth
                    .as_mut()
                    .unwrap()
                    .bind_subject(&permit.oauth.as_ref().unwrap().0, subject.unwrap())?;
            }
            state.clock = now;
            state
                .clients
                .get_mut(&permit.client)
                .expect("client checked")
                .bindings
                .insert(key, credential.clone());
            // First-use subject pin and credential allocation commit together.
            self.save(&state)?;
        }
        Ok(credential)
    }
}
