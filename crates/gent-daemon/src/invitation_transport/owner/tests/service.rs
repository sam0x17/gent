//! Explicit opt-in proof against local account/relay Workers. Authentication is
//! the harness's synthetic GitHub account; all Noise/MLS enrollment is native.
use super::*;
use gent_protocol::service::invitations::{Exchange, Registration, Scope};
use reqwest::{Client, Method};
use serde::Deserialize;
use std::path::PathBuf;
use std::{io::Read, os::unix::fs::PermissionsExt};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Auth {
    account_origin: String,
    relay_origin: String,
    account_id: String,
    owner_session: String,
    join_session: String,
    output: PathBuf,
}
impl Auth {
    async fn api(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        joining: bool,
    ) -> Result<Value> {
        let bearer = if joining {
            &self.join_session
        } else {
            &self.owner_session
        };
        let mut request = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?
            .request(method, format!("{}{path}", self.account_origin))
            .bearer_auth(bearer);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await?;
        ensure!(
            response.status().is_success(),
            "local account fixture request failed ({})",
            response.status()
        );
        let bytes = crate::sync::bounded(response, 8192).await?;
        if bytes.is_empty() {
            Ok(Value::Null)
        } else {
            Ok(serde_json::from_slice(&bytes)?)
        }
    }
}
fn credential(prefix: &str) -> String {
    format!("{prefix}.{}.{}", now(), config::secret())
}

struct ServicePeer {
    inner: NativePeer,
    auth: Arc<Auth>,
    transport: String,
}
impl Peer for ServicePeer {
    async fn prepare_node(&mut self, node: &NodeIdentity, name: &str) -> Result<()> {
        self.inner.prepare_node(node, name).await
    }
    async fn call(&mut self, action: PairingOp) -> Result<Value> {
        self.inner.call(action).await
    }
    async fn prepare_service(&mut self, service: &ServiceRelay) -> Result<()> {
        self.inner.prepare_service(service).await
    }
    async fn provision_service(
        &mut self,
        runtime: &Path,
        _home: &Path,
        service: &ServiceRelay,
    ) -> Result<()> {
        let mut cfg = config::load(runtime)?;
        self.auth
            .api(
                Method::PUT,
                &format!("/v1/clusters/{}/nodes/{}", cfg.cluster.id, cfg.node.id),
                Some(json!({"transport_token":self.transport})),
                true,
            )
            .await?;
        cfg.cluster.local_only = false;
        cfg.service = Some(service.account.clone());
        cfg.relay = Some(config::RelayConfig {
            endpoint: service.relay_endpoint.clone(),
            credential_file: "relay.key".into(),
        });
        config::write_private(&runtime.join("relay.key"), self.transport.as_bytes())?;
        config::save(runtime, &cfg)
    }
}

#[tokio::test]
#[ignore = "requires local account/relay Workers and GENT_TEST_INVITATION_AUTH_FILE"]
async fn workers_enroll_native_node_and_recover_completed_receipt_after_owner_restart() {
    let input =
        std::env::var_os("GENT_TEST_INVITATION_AUTH_FILE").expect("private local proof input");
    let metadata = fs::symlink_metadata(&input).unwrap();
    assert!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o077 == 0
    );
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(&input)
        .unwrap()
        .take(8193)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 8192);
    let auth: Arc<Auth> = Arc::new(serde_json::from_slice(&bytes).unwrap());
    for origin in [&auth.account_origin, &auth.relay_origin] {
        let url = reqwest::Url::parse(origin).unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
    }
    assert_ne!(auth.owner_session, auth.join_session);
    config::private_dir(&auth.output).unwrap();
    let owner_home = auth.output.join("owner");
    let joined_home = auth.output.join("joined");
    assert!(!owner_home.exists() && !joined_home.exists());
    let mut cfg = config::initialize(&owner_home, "native-invitation-owner").unwrap();
    cfg.cluster.local_only = false;
    cfg.service = Some(config::ServiceConfig {
        origin: format!("{}/", auth.account_origin),
        account_id: auth.account_id.clone(),
    });
    cfg.relay = Some(config::RelayConfig {
        endpoint: format!("{}/", auth.relay_origin),
        credential_file: "relay.key".into(),
    });
    let owner_transport = credential("gent_t1");
    config::write_private(&owner_home.join("relay.key"), owner_transport.as_bytes()).unwrap();
    config::save(&owner_home, &cfg).unwrap();
    auth.api(
        Method::PUT,
        &format!("/v1/clusters/{}", cfg.cluster.id),
        None,
        false,
    )
    .await
    .unwrap();
    auth.api(
        Method::PUT,
        &format!("/v1/clusters/{}/nodes/{}", cfg.cluster.id, cfg.node.id),
        Some(json!({"transport_token":owner_transport})),
        false,
    )
    .await
    .unwrap();
    let mut store = Store::open(&owner_home).unwrap();
    let owner_credential = config::read_private(&owner_home.join("owner.key")).unwrap();
    let invitation_bytes = store
        .create_invitation(&owner_credential, &Uuid::now_v7().to_string(), true, None)
        .unwrap();
    config::write_private(
        &auth.output.join("invitation.gent-invite"),
        &invitation_bytes,
    )
    .unwrap();
    let invitation = Invitation::decode(&invitation_bytes).unwrap();
    let id = invitation.offer().offer.id.clone();
    let registration = Registration {
        owner_node_id: cfg.node.id.clone(),
        routing_hash: format!("{:x}", Sha256::digest(*invitation.expose_routing_secret())),
        expires_at: invitation.offer().offer.expires_at,
    };
    auth.api(
        Method::PUT,
        &format!("/v1/clusters/{}/invitations/{id}", cfg.cluster.id),
        Some(serde_json::to_value(registration).unwrap()),
        false,
    )
    .await
    .unwrap();
    store.activate_invitation(&owner_credential, &id).unwrap();
    let join_token = credential("gent_j1");
    let exchange = Exchange {
        routing_secret: invitation
            .expose_routing_secret()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        join_token: join_token.clone(),
    };
    let scope: Scope = serde_json::from_value(
        auth.api(
            Method::POST,
            &format!("/v1/invitations/{id}/session"),
            Some(serde_json::to_value(exchange).unwrap()),
            true,
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(scope.invitation_id, id);
    assert_eq!(scope.cluster_id, cfg.cluster.id);
    assert_eq!(scope.side, Side::Join);
    config::write_private(&auth.output.join("join.key"), join_token.as_bytes()).unwrap();
    let shared = Arc::new(Mutex::new(store));
    let worker = start(shared.clone());
    let mut peer = ServicePeer {
        inner: NativePeer {
            client: Joining::new(invitation, &join_token).unwrap(),
            ids: BTreeMap::new(),
        },
        auth: auth.clone(),
        transport: credential("gent_t1"),
    };
    let result = pairing::join(
        &joined_home,
        pairing::Options {
            replace_node: None,
            cluster: &cfg.cluster.id,
            name: "native-invitation-joined",
            relay_endpoint: None,
        },
        &mut peer,
    )
    .await
    .unwrap();
    assert_eq!(result["joined"], true);
    let joined = config::load(&joined_home).unwrap();
    assert_ne!(peer.transport, owner_transport);
    let finish = Invocation {
        id: Uuid::new_v4().to_string(),
        action: Action::Finish,
    };
    let receipt = peer.inner.client.invoke(&finish).await.unwrap();
    worker.stop().await;
    *shared.lock().unwrap() = Store::open(&owner_home).unwrap();
    let worker = start(shared);
    let keys = fs::read(joined_home.join("identity.key")).unwrap();
    assert_eq!(&keys[..8], b"GENTKEY2");
    let node =
        NodeIdentity::from_secret_bytes(&joined.node.id, keys[8..40].try_into().unwrap()).unwrap();
    let mut resumed =
        Joining::new(Invitation::decode(&invitation_bytes).unwrap(), &join_token).unwrap();
    resumed.prepare_node(&node, &joined.node.name).unwrap();
    assert_eq!(resumed.invoke(&finish).await.unwrap(), receipt);
    worker.stop().await;
    let report = json!({"result":"passed", "cluster_id":cfg.cluster.id, "invitation_id":id,
        "owner_node":cfg.node.id, "joined_node":joined.node.id,
        "owner_credential_hash":format!("{:x}", Sha256::digest(owner_transport.as_bytes())),
        "joined_credential_hash":format!("{:x}", Sha256::digest(peer.transport.as_bytes())),
        "join_credential_hash":format!("{:x}", Sha256::digest(join_token.as_bytes()))});
    config::write_private(
        &auth.output.join("report.json"),
        &serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}
