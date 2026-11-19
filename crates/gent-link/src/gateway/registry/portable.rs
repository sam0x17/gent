//! A web registry checkpoint preserves opaque handles across carrier changes.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    state: State,
    export: Export,
    pub(crate) management: Option<String>,
}

pub(crate) fn capture(home: &Path) -> Result<Checkpoint> {
    let registry = Registry::open(home)?;
    let _lock = managed_file::lock(&registry.directory().join("state.lock"))?;
    let mut state = registry.read()?;
    capability::recover(&registry, &mut state)?;
    let export = capability::read_export(&home.join("web-connector.json"))?;
    ensure!(
        state.clients.len() == 1
            && state.clients.contains_key(&export.client)
            && export.version == 7
            && export.registry == state.id
            && export.cluster == state.cluster
            && export.node == state.node,
        "portable web registry does not match its connector"
    );
    for client in state.clients.values_mut() {
        ensure!(
            client.conversation_key == conversations::URL_KEY
                && client.oauth.is_none()
                && client.mtls.is_none(),
            "only named web connectors use cluster failover"
        );
        client.export = PathBuf::from("web-connector.json");
    }
    let management = management(home)?;
    Ok(Checkpoint {
        state,
        export,
        management,
    })
}

pub(crate) fn management(home: &Path) -> Result<Option<String>> {
    let marker = snapshot(&home.join("gateway/management.json"))?;
    marker
        .text
        .as_deref()
        .map(|text| {
            let id: String = serde_json::from_str(text)?;
            ensure!(uuid(&id), "invalid web management request");
            Ok(id)
        })
        .transpose()
}

pub(crate) fn mark_management(home: &Path) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    snapshot(&home.join("gateway/management.json"))?.write(&serde_json::to_string(&id)?)?;
    Ok(id)
}

pub(crate) fn restore(home: &Path, checkpoint: &mut Checkpoint) -> Result<()> {
    let cfg = node_home::inspect(home)?;
    let state = &mut checkpoint.state;
    ensure!(
        state.cluster == cfg.cluster.id
            && state.node == cfg.node.id
            && checkpoint.export.registry == state.id
            && checkpoint.export.cluster == state.cluster
            && checkpoint.export.node == state.node
            && checkpoint.export.version == 7
            && state.clients.len() == 1,
        "web registry checkpoint scope mismatch"
    );
    let client = state
        .clients
        .get_mut(&checkpoint.export.client)
        .context("web connector missing")?;
    ensure!(
        client.conversation_key == conversations::URL_KEY
            && client.oauth.is_none()
            && client.mtls.is_none()
            && checkpoint.export.token.as_deref().map(digest) == client.token_hash,
        "web connector credential mismatch"
    );
    client.export = home.join("web-connector.json");
    state.validate()?;
    config::private_dir(&home.join("gateway"))?;
    let _lock = managed_file::lock(&home.join("gateway/state.lock"))?;
    snapshot(&home.join("gateway/state.json"))?.write(&serde_json::to_string(state)?)?;
    snapshot(&home.join("web-connector.json"))?
        .write(&serde_json::to_string(&checkpoint.export)?)?;
    if let Some(id) = &checkpoint.management {
        ensure!(uuid(id), "invalid web management request");
        snapshot(&home.join("gateway/management.json"))?.write(&serde_json::to_string(id)?)?;
    } else {
        let file = snapshot(&home.join("gateway/management.json"))?;
        if file.text.is_some() {
            file.remove()?;
        }
    }
    config::edit_local(home, |cfg| cfg.set_gateway_registry(state.id.clone()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn existing_url_handle_and_rotated_credentials_survive_a_different_home() {
        let root = tempfile::tempdir().unwrap();
        let a = root.path().join("a");
        let b = root.path().join("b");
        let cfg = config::initialize(&a, "test").unwrap();
        capability::create(&a).unwrap();
        let registry = Registry::open(&a).unwrap();
        let export = capability::read_export(&a.join("web-connector.json")).unwrap();
        let token = export.token.unwrap();
        let permit = registry
            .authenticate_url_remote(token.clone())
            .await
            .unwrap();
        let handle = registry
            .open_conversation_remote(permit.clone())
            .await
            .unwrap()["conversation"]
            .as_str()
            .unwrap()
            .to_owned();
        let key = registry
            .credential_remote(permit, Conversation::Handle(handle.clone()))
            .await
            .unwrap();
        let mut checkpoint = capture(&a).unwrap();
        config::private_dir(&b).unwrap();
        config::save(&b, &cfg).unwrap();
        restore(&b, &mut checkpoint).unwrap();
        let second = Registry::open(&b).unwrap();
        let permit = second.authenticate_url_remote(token.clone()).await.unwrap();
        assert_eq!(
            second
                .credential_remote(permit, Conversation::Handle(handle.clone()))
                .await
                .unwrap(),
            key
        );
        capability::url(&a, "https://example.invalid", true).unwrap();
        let mut rotated = capture(&a).unwrap();
        restore(&b, &mut rotated).unwrap();
        assert!(second.authenticate_url_remote(token).await.is_err());
        let new_token = capability::read_export(&b.join("web-connector.json"))
            .unwrap()
            .token
            .unwrap();
        let permit = second.authenticate_url_remote(new_token).await.unwrap();
        assert_eq!(
            second
                .credential_remote(permit, Conversation::Handle(handle))
                .await
                .unwrap(),
            key
        );
    }
}
