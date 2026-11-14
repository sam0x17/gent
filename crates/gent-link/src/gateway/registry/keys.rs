//! Signing key changes commit to the registry before updating its private
//! export. The recorded preimage permits an exact retry after either write,
//! while an expected revision prevents stale commands from restoring old keys.
use super::*;
use crate::gateway::assertion::Policy;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Update {
    pub(super) revision: u64,
    pub(super) pending_export: Option<String>,
}

pub(crate) struct MetadataSnapshot {
    pub(crate) registration: oauth::Registration,
    pub(crate) revision: u64,
    pub(crate) pending: bool,
}

impl Registry {
    pub(crate) async fn metadata_snapshot(
        &self,
        id: String,
        resource: String,
    ) -> Result<MetadataSnapshot> {
        self.blocking(move |registry| {
            let state = registry.read()?;
            let now = auth::now()?;
            let client = state.clients.get(&id).context("unknown metadata client")?;
            ensure!(
                now >= state.clock && !client.revoked && now < client.expires_at,
                "inactive metadata client"
            );
            let registration = client
                .oauth
                .as_ref()
                .filter(|r| r.resource == resource && r.assertion.is_some())
                .context("metadata requires a signed client for this resource")?;
            Ok(MetadataSnapshot {
                registration: registration.clone(),
                revision: client.key_update.as_ref().map_or(0, |u| u.revision),
                pending: client
                    .key_update
                    .as_ref()
                    .is_some_and(|u| u.pending_export.is_some()),
            })
        })
        .await
    }

    pub(crate) async fn apply_metadata_keys(
        &self,
        id: String,
        policy: Policy,
        expected: u64,
    ) -> Result<u64> {
        self.blocking(move |registry| {
            let result = registry.set_verified_signing_keys(&id, policy, expected)?;
            result["key_revision"]
                .as_u64()
                .context("missing key revision")
        })
        .await
    }

    pub(crate) fn signing_registration(&self, id: &str) -> Result<oauth::Registration> {
        let state = self.read()?;
        let client = state.clients.get(id).context("unknown gateway client ID")?;
        let registration = client
            .oauth
            .as_ref()
            .filter(|r| r.assertion.is_some())
            .context("this client does not use signed OAuth authentication")?;
        Ok(registration.clone())
    }
    pub(crate) fn signing_keys(&self, id: &str) -> Result<Value> {
        let state = self.read()?;
        self.keys_summary(&state, id)
    }
    fn keys_summary(&self, state: &State, id: &str) -> Result<Value> {
        let client = state.clients.get(id).context("unknown gateway client ID")?;
        let policy = client
            .oauth
            .as_ref()
            .and_then(|r| r.assertion.as_ref())
            .context("this client does not use signed OAuth authentication")?;
        Ok(
            json!({"client":id,"oauth_client_id":policy.client_id,"key_ids":policy.key_ids(),
            "key_revision":client.key_update.as_ref().map_or(0, |u| u.revision),
            "export_pending":client.key_update.as_ref().is_some_and(|u| u.pending_export.is_some()),
            "credential_file":client.export,"revoked":client.revoked,"expires_at":client.expires_at}),
        )
    }
    pub(crate) fn set_signing_keys(&self, id: &str, jwks: &Path, expected: u64) -> Result<Value> {
        self.update_signing_keys(id, expected, |client| Policy::load(jwks, client))
    }
    pub(crate) fn set_verified_signing_keys(
        &self,
        id: &str,
        policy: Policy,
        expected: u64,
    ) -> Result<Value> {
        self.update_signing_keys(id, expected, |client| {
            ensure!(
                policy.client_id == client,
                "imported metadata belongs to a different OAuth client"
            );
            policy.validate()?;
            Ok(policy)
        })
    }
    fn update_signing_keys(
        &self,
        id: &str,
        expected: u64,
        load: impl FnOnce(&str) -> Result<Policy>,
    ) -> Result<Value> {
        directory_check(&self.directory())?;
        let _lock = managed_file::lock(&self.directory().join("state.lock"))?;
        let mut state = self.read()?;
        let now = auth::now()?;
        ensure!(now >= state.clock, "gateway clock moved backward");
        let client = state.clients.get(id).context("unknown gateway client ID")?;
        let old = client
            .oauth
            .as_ref()
            .and_then(|r| r.assertion.as_ref())
            .context("this client does not use signed OAuth authentication")?;
        let policy = load(&old.client_id)?;
        let revision = client.key_update.as_ref().map_or(0, |u| u.revision);
        let same = old.equivalent(&policy);
        let retry = expected.checked_add(1) == Some(revision) && same;
        ensure!(
            expected == revision || retry,
            "signing key revision changed; inspect keys show before a new update"
        );
        if !retry {
            ensure!(
                !client.revoked && now < client.expires_at,
                "inactive gateway client"
            );
        }
        if !same {
            ensure!(
                client
                    .key_update
                    .as_ref()
                    .is_none_or(|u| u.pending_export.is_none()),
                "finish the pending key export with the same keys and original expected revision"
            );
            let original = snapshot(&client.export)?;
            let text = original
                .text
                .as_deref()
                .context("private export is missing; restore it before changing keys")?;
            let exported: Export =
                serde_json::from_str(text).context("invalid private gateway export")?;
            ensure!(
                exported == self.key_export(id, client),
                "private export differs from the current registration"
            );
            let next = revision
                .checked_add(1)
                .context("signing key revision exhausted")?;
            original.verify()?;
            let client = state.clients.get_mut(id).unwrap();
            client.oauth.as_mut().unwrap().assertion = Some(policy);
            client.key_update = Some(Update {
                revision: next,
                pending_export: Some(digest(text)),
            });
            client.keys_updated = true;
            state.version = 5;
            state.clock = now;
            self.save(&state)?;
        }
        let pending = state.clients[id]
            .key_update
            .as_ref()
            .is_some_and(|u| u.pending_export.is_some());
        if pending {
            self.finish_key_export(&mut state, id).context("signing keys are committed; private export is pending; retry with the same keys and original expected revision")?;
        } else {
            self.finish_key_export(&mut state, id)?;
        }
        self.keys_summary(&state, id)
    }
    fn key_export(&self, id: &str, client: &Client) -> Export {
        let revision = client.key_update.as_ref().map_or(0, |u| u.revision);
        Export {
            version: if revision > 0 { 4 } else { 3 },
            registry: self.id.clone(),
            cluster: self.cluster.clone(),
            node: self.node.clone(),
            client: id.into(),
            name: client.name.clone(),
            conversation_key: client.conversation_key.clone(),
            token: None,
            created_at: client.created_at,
            expires_at: client.expires_at,
            oauth: client.oauth.clone(),
            mtls: client.mtls.clone(),
            key_revision: revision,
        }
    }
    fn finish_key_export(&self, state: &mut State, id: &str) -> Result<()> {
        let client = &state.clients[id];
        let desired = self.key_export(id, client);
        let current = snapshot(&client.export)?;
        let text = current
            .text
            .as_deref()
            .context("private key export is missing; restore the previous export and retry")?;
        let pending = client
            .key_update
            .as_ref()
            .and_then(|u| u.pending_export.as_deref());
        let matches = serde_json::from_str::<Export>(text).is_ok_and(|value| value == desired);
        ensure!(
            matches || pending.is_some_and(|hash| hash == digest(text)),
            "private export changed; restore the previous export and retry the key update"
        );
        if !matches {
            current.write(&(serde_json::to_string(&desired)? + "\n"))?;
        }
        if pending.is_some() {
            state
                .clients
                .get_mut(id)
                .unwrap()
                .key_update
                .as_mut()
                .unwrap()
                .pending_export = None;
            self.save(state)?;
        }
        Ok(())
    }
}
