//! Explicit conversations for hosts without stable per-chat metadata. A handle
//! selects an existing binding only within its authenticated connector/grant.
use super::*;

// Kept in the existing binding policy slot so export retries cannot silently
// switch identity modes. Registry v8/export v6 make older readers reject it.
pub(crate) const KEY: &str = "gent/explicit-conversation";
pub(crate) const URL_KEY: &str = "gent/url-conversation";
const PREFIX: &str = "gent_h1.";

#[derive(Clone)]
pub(crate) enum Conversation {
    Metadata(Value),
    Handle(String),
}

impl From<Value> for Conversation {
    fn from(value: Value) -> Self {
        Self::Metadata(value)
    }
}

impl From<&Value> for Conversation {
    fn from(value: &Value) -> Self {
        Self::Metadata(value.clone())
    }
}

pub(super) fn enabled(client: &Client) -> bool {
    matches!(client.conversation_key.as_str(), KEY | URL_KEY)
}

fn key(permit: &Permit, handle: &str) -> Result<String> {
    ensure!(
        handle.strip_prefix(PREFIX).is_some_and(hash),
        "invalid conversation handle"
    );
    let grant = permit
        .oauth
        .as_ref()
        .map_or("static", |(id, _)| id.as_str());
    Ok(digest(&format!(
        "gent-explicit-conversation-v1\0{}\0{grant}\0{handle}",
        permit.client
    )))
}

impl Registry {
    pub(crate) async fn open_conversation_remote(&self, permit: Permit) -> Result<Value> {
        self.blocking(move |registry| registry.open_conversation(&permit))
            .await
    }

    fn open_conversation(&self, permit: &Permit) -> Result<Value> {
        directory_check(&self.directory())?;
        let _lock = managed_file::lock(&self.directory().join("state.lock"))?;
        let mut state = self.read()?;
        let now = auth::now()?;
        let client = Self::client(&state, permit, now)?;
        ensure!(
            enabled(client),
            "this connector requires host conversation metadata"
        );
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
        let handle = format!("{PREFIX}{}", config::secret());
        let key = key(permit, &handle)?;
        let client = state.clients.get_mut(&permit.client).unwrap();
        ensure!(
            !client.bindings.contains_key(&key),
            "conversation handle collision"
        );
        client.bindings.insert(key, config::secret().into());
        state.clock = now;
        self.save(&state)?;
        Ok(json!({
            "conversation": handle,
            "next": "Retain this handle in this chat and pass conversation on every Gent tool call. Register this chat with gent_register. Do not open another handle for a follow-up, reconnect, or uncertain send. Never copy a handle from another chat.",
            "scope": "this authenticated connector and OAuth authorization; a new authorization needs a new conversation"
        }))
    }

    pub(super) fn conversation_credential(
        &self,
        permit: &Permit,
        conversation: &Conversation,
    ) -> Result<String> {
        match conversation {
            Conversation::Metadata(meta) => self.credential(permit, meta),
            Conversation::Handle(handle) => {
                directory_check(&self.directory())?;
                let _lock = managed_file::lock(&self.directory().join("state.lock"))?;
                let mut state = self.read()?;
                let now = auth::now()?;
                let client = Self::client(&state, permit, now)?;
                ensure!(
                    enabled(client),
                    "explicit handles are disabled for this connector"
                );
                let credential = client
                    .bindings
                    .get(&key(permit, handle)?)
                    .context("conversation unavailable for this connector or authorization")?
                    .credential()?
                    .to_owned();
                if state.clock != now {
                    state.clock = now;
                    self.save(&state)?;
                }
                Ok(credential)
            }
        }
    }
}

#[cfg(test)]
mod tests;
