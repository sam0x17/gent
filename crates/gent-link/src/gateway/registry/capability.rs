//! Copyable connector URLs. Rotation retains conversation bindings and has a
//! private recovery journal so interruption cannot lose the replacement secret.
use super::*;

const EXPORT: &str = "web-connector.json";
const PENDING: &str = "url-rotation.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rotation {
    previous_hash: String,
    replacement: Export,
}

pub(crate) fn create(home: &Path) -> Result<()> {
    add_client(
        home,
        "web",
        conversations::URL_KEY,
        &home.join(EXPORT),
        8760,
        None,
        None,
    )?;
    Ok(())
}

impl Registry {
    pub(crate) async fn authenticate_url_remote(&self, token: String) -> Result<Permit> {
        self.blocking(move |registry| {
            let permit = registry.authenticate_peer(&token, None, Peer::default())?;
            let state = registry.read()?;
            let client = Self::client(&state, &permit, auth::now()?)?;
            ensure!(
                client.conversation_key == conversations::URL_KEY,
                "credential is not a connector URL"
            );
            Ok(permit)
        })
        .await
    }
}

fn read_export(path: &Path) -> Result<Export> {
    let snapshot = snapshot(path)?;
    serde_json::from_str(
        snapshot
            .text
            .as_deref()
            .context("connector URL is missing")?,
    )
    .map_err(|_| anyhow::anyhow!("invalid connector URL record"))
}

fn recover(registry: &Registry, state: &mut State) -> Result<()> {
    let pending = snapshot(&registry.directory().join(PENDING))?;
    let Some(text) = &pending.text else {
        return Ok(());
    };
    let rotation: Rotation = serde_json::from_str(text)
        .map_err(|_| anyhow::anyhow!("invalid connector URL rotation"))?;
    let value = &rotation.replacement;
    let token = value.token.as_deref().context("connector URL is missing")?;
    let new_hash = digest(token);
    let client = state
        .clients
        .get_mut(&value.client)
        .context("connector is missing")?;
    ensure!(
        value.registry == registry.id
            && value.cluster == registry.cluster
            && value.node == registry.node
            && value.version == 7
            && value.conversation_key == conversations::URL_KEY
            && client.conversation_key == conversations::URL_KEY
            && token_id(token)? == value.client
            && value.name == client.name
            && value.oauth.is_none()
            && value.mtls.is_none()
            && value.subject_key.is_none()
            && value.key_revision == 0
            && client.export == registry.home.join(EXPORT)
            && (client.token_hash.as_ref() == Some(&rotation.previous_hash)
                || client.token_hash.as_ref() == Some(&new_hash)),
        "connector URL rotation does not match this node"
    );
    // A revoke during a pending rotation stays revoked.
    client.token_hash = Some(new_hash);
    client.created_at = value.created_at;
    client.expires_at = value.expires_at;
    let now = auth::now()?;
    ensure!(
        now >= state.clock
            && value.created_at <= now
            && value.expires_at.checked_sub(value.created_at) == Some(MAX_LIFETIME),
        "invalid connector URL rotation lifetime"
    );
    state.clock = now;
    registry.save(state)?;
    snapshot(&registry.home.join(EXPORT))?.write(&(serde_json::to_string(value)? + "\n"))?;
    pending.remove()?;
    Ok(())
}

/// Only explicit owner setup/show/rotate calls may return this secret.
pub(crate) fn url(home: &Path, base: &str, rotate: bool) -> Result<String> {
    let normalized = managed_file::normalize(home)?;
    let home = normalized.as_path();
    let registry = Registry::open(home)?;
    let _lock = managed_file::lock(&registry.directory().join("state.lock"))?;
    let mut state = registry.read()?;
    let was_pending = snapshot(&registry.directory().join(PENDING))?
        .text
        .is_some();
    recover(&registry, &mut state)?;
    let path = home.join(EXPORT);
    let mut value = read_export(&path)?;
    let client = state
        .clients
        .get(&value.client)
        .context("connector is missing")?;
    ensure!(
        value.version == 7
            && value.registry == registry.id
            && value.cluster == registry.cluster
            && value.node == registry.node
            && value.conversation_key == conversations::URL_KEY
            && client.conversation_key == conversations::URL_KEY
            && client.export == path
            && !client.revoked
            && value.token.as_deref().map(digest) == client.token_hash,
        "connector URL is revoked or its private record changed"
    );
    let now = auth::now()?;
    ensure!(now >= state.clock, "gateway clock moved backward");
    if rotate && !was_pending {
        let previous_hash = client
            .token_hash
            .clone()
            .context("missing connector credential")?;
        value.token = Some(format!("gent_g1.{}.{}", value.client, config::secret()));
        value.created_at = now;
        value.expires_at = now + MAX_LIFETIME;
        snapshot(&registry.directory().join(PENDING))?.write(
            &(serde_json::to_string(&Rotation {
                previous_hash,
                replacement: value,
            })? + "\n"),
        )?;
        recover(&registry, &mut state)?;
        value = read_export(&path)?;
    }
    ensure!(
        now < value.expires_at,
        "connector URL expired; use gent node web rotate NAME"
    );
    let token = value.token.as_deref().context("connector URL is missing")?;
    token_id(token)?;
    Ok(format!("{base}/mcp/{token}"))
}

pub(crate) fn revoke(home: &Path) -> Result<Value> {
    let registry = Registry::open(home)?;
    let export = read_export(&home.join(EXPORT))?;
    ensure!(
        export.registry == registry.id && export.conversation_key == conversations::URL_KEY,
        "connector does not belong to this node"
    );
    registry.revoke(&export.client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn interrupted_rotation_recovers_before_and_after_registry_commit() {
        for committed in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let home = root.path().join("node");
            config::initialize(&home, "web").unwrap();
            create(&home).unwrap();
            let registry = Registry::open(&home).unwrap();
            let old = read_export(&home.join(EXPORT)).unwrap();
            let old_token = old.token.clone().unwrap();
            let permit = registry.authenticate(&old_token).unwrap();
            let chat = registry
                .open_conversation_remote(permit.clone())
                .await
                .unwrap();
            let binding = registry
                .credential_remote(
                    permit,
                    Conversation::Handle(chat["conversation"].as_str().unwrap().into()),
                )
                .await
                .unwrap();
            let mut replacement = old;
            let new_token = format!("gent_g1.{}.{}", replacement.client, config::secret());
            replacement.token = Some(new_token.clone());
            if committed {
                let mut state = registry.read().unwrap();
                state
                    .clients
                    .get_mut(&replacement.client)
                    .unwrap()
                    .token_hash = Some(digest(&new_token));
                registry.save(&state).unwrap();
            }
            snapshot(&registry.directory().join(PENDING))
                .unwrap()
                .write(
                    &(serde_json::to_string(&Rotation {
                        previous_hash: digest(&old_token),
                        replacement,
                    })
                    .unwrap()
                        + "\n"),
                )
                .unwrap();
            let recovered = url(&home, "https://example.invalid", true).unwrap();
            assert!(recovered.ends_with(&new_token));
            assert!(registry.authenticate(&old_token).is_err());
            let permit = registry.authenticate_url_remote(new_token).await.unwrap();
            assert_eq!(
                registry
                    .credential_remote(
                        permit,
                        Conversation::Handle(chat["conversation"].as_str().unwrap().into())
                    )
                    .await
                    .unwrap(),
                binding
            );
            assert!(!registry.directory().join(PENDING).exists());
        }
    }
}
