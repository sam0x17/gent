use super::*;
use crate::pairing::{self, Peer};
use std::os::unix::fs::PermissionsExt;

#[path = "directory_push_tests.rs"]
mod directory_push_tests;
#[path = "owner_activation_tests.rs"]
mod owner_activation_tests;
#[path = "owner_preparation_tests.rs"]
mod owner_preparation_tests;
#[path = "removal_tests.rs"]
mod removal_tests;
#[path = "storage_tests.rs"]
mod storage_tests;

struct OwnerPeer<'a>(&'a mut Store, String);
impl Peer for OwnerPeer<'_> {
    async fn call(&mut self, action: PairingOp) -> Result<Value> {
        self.0.execute(Request::Owner {
            credential: self.1.clone(),
            action: OwnerOp::Pair {
                cluster_id: self.0.config.cluster.id.clone(),
                action,
            },
        })
    }
}
struct Mesh {
    homes: Vec<tempfile::TempDir>,
    stores: Vec<Store>,
}
impl Mesh {
    async fn new() -> Self {
        let homes: Vec<_> = (0..3)
            .map(|_| {
                let home = tempfile::tempdir().unwrap();
                std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                home
            })
            .collect();
        let mut cfg = config::initialize(homes[0].path(), "mesh-test").unwrap();
        cfg.relay = Some(config::RelayConfig {
            endpoint: "https://relay.example".into(),
            credential_file: "relay.key".into(),
        });
        config::write_private(
            &homes[0].path().join("relay.key"),
            config::secret().as_bytes(),
        )
        .unwrap();
        config::save(homes[0].path(), &cfg).unwrap();
        crate::entitlements::grant_test(homes[0].path(), &cfg);
        let mut stores = vec![Store::open(homes[0].path()).unwrap()];
        for home in &homes[1..] {
            let credential = config::read_private(&homes[0].path().join("owner.key")).unwrap();
            pairing::join(
                home.path(),
                pairing::Options {
                    replace_node: None,
                    cluster: &cfg.cluster.id,
                    name: "peer",
                    relay_endpoint: None,
                },
                &mut OwnerPeer(&mut stores[0], credential),
            )
            .await
            .unwrap();
            let store = Store::open(home.path()).unwrap();
            crate::entitlements::grant_test(home.path(), &store.config);
            stores.push(store);
        }
        let mut mesh = Self { homes, stores };
        for _ in 0..10 {
            mesh.round(false);
        }
        mesh
    }
    fn count(&self, i: usize, table: &str) -> usize {
        self.stores[i]
            .db
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
    fn reopen(&mut self, i: usize) {
        self.stores[i] = Store::open(self.homes[i].path()).unwrap();
    }
    fn round(&mut self, maintain: bool) {
        for i in 0..self.stores.len() {
            if maintain {
                self.stores[i].mesh_tick().unwrap();
            }
            let streams = self.stores[i].sync_streams().unwrap();
            for stream in streams.into_iter().filter(|s| s.outgoing) {
                let target = (0..self.stores.len()).find(|j| {
                    *j != i
                        && self.stores[*j]
                            .sync_streams()
                            .unwrap()
                            .iter()
                            .any(|s| !s.outgoing && s.group == stream.group)
                });
                let Some(j) = target else { continue };
                let group = &stream.group;
                let packet = if stream.configuration {
                    self.stores[i].sync_prepare(group).unwrap();
                    let next = self.stores[j].sync_next(group).unwrap();
                    self.stores[i].sync_outgoing(group, next).unwrap()
                } else {
                    self.stores[i].data_prepare(group).unwrap();
                    let next = self.stores[j].data_next(group).unwrap();
                    self.stores[i].data_outgoing(group, next).unwrap()
                };
                if let Some(packet) = packet {
                    if stream.configuration {
                        self.stores[j].sync_receive(&packet).unwrap();
                    } else {
                        self.stores[j].data_receive(&packet).unwrap();
                    }
                }
            }
        }
    }
    fn import(&self, target: usize, sender: usize, envelope: MeshEnvelope) -> Result<()> {
        let store = &self.stores[target];
        let tx = store.db.unchecked_transaction()?;
        store
            .network_session(&tx, store.identity.state(&tx)?)
            .import_mesh(self.stores[sender].identity.node.id(), envelope)?;
        tx.commit()?;
        Ok(())
    }
    fn envelope(&self, signal: MeshSignal) -> MeshEnvelope {
        let origin = &self.stores[1].identity.node;
        let target = &self.stores[2].identity.node;
        let state = self.stores[0].identity.state(&self.stores[0].db).unwrap();
        MeshEnvelope {
            origin: origin.id().into(),
            target: target.id().into(),
            origin_key: origin.public_key(),
            target_key: target.public_key(),
            link: link_id(&state, origin.id(), target.id()).unwrap(),
            signal,
        }
    }
}

#[tokio::test]
async fn mesh_offer_and_owner_forwarding_roll_back_and_resume_without_new_packages() {
    let mut mesh = Mesh::new().await;
    let packages = mesh.count(1, "key_packages");
    mesh.stores[1].db.execute_batch("CREATE TRIGGER fail_offer BEFORE INSERT ON network_events BEGIN SELECT RAISE(ABORT,'offer failure'); END;").unwrap();
    assert!(mesh.stores[1].mesh_tick().is_err());
    assert_eq!(mesh.count(1, "mesh_peers"), 0);
    assert_eq!(mesh.count(1, "key_packages"), packages + 1);
    mesh.reopen(1);
    mesh.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_offer;")
        .unwrap();
    mesh.stores[1].mesh_tick().unwrap();
    assert_eq!(mesh.count(1, "key_packages"), packages + 1);
    for _ in 0..4 {
        mesh.round(false);
    }
    assert!(mesh.count(0, "mesh_jobs") > 0);
    let events = mesh.count(0, "network_events");
    mesh.stores[0].db.execute_batch("CREATE TRIGGER fail_forward BEFORE UPDATE OF done ON mesh_jobs BEGIN SELECT RAISE(ABORT,'forward failure'); END;").unwrap();
    mesh.stores[0].mesh_tick().unwrap();
    assert_eq!(mesh.count(0, "network_events"), events);
    assert_eq!(
        mesh.stores[0]
            .db
            .query_row("SELECT SUM(done) FROM mesh_jobs", [], |r| r
                .get::<_, usize>(0))
            .unwrap(),
        0
    );
    mesh.reopen(0);
    mesh.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_forward; UPDATE mesh_jobs SET retry_at=0;")
        .unwrap();
    for _ in 0..20 {
        mesh.round(true);
    }
    for i in 0..3 {
        assert_eq!(mesh.count(i, "network_links"), 2);
    }
    assert_eq!(mesh.count(1, "key_packages"), packages + 1);
}

#[tokio::test]
async fn mesh_rejects_forged_routes_packages_welcomes_and_conflicting_signals() {
    let mut mesh = Mesh::new().await;
    // An enrolled owner key package cannot impersonate the claimed peer.
    let owner = &mesh.stores[0];
    let package = OrderedEndpoint::open_runtime(&owner.home, &owner.identity.node)
        .unwrap()
        .key_package(Uuid::new_v4(), now() as u64)
        .unwrap();
    let offer = mesh.envelope(MeshSignal::Offer {
        key_package: STANDARD.encode(package),
    });
    assert!(mesh.import(0, 2, offer.clone()).is_err());
    assert!(mesh.import(2, 1, offer.clone()).is_err());
    mesh.import(0, 1, offer.clone()).unwrap();
    mesh.import(0, 1, offer.clone()).unwrap();
    assert_eq!(mesh.count(0, "mesh_jobs"), 1);
    let mut conflict = offer.clone();
    conflict.signal = MeshSignal::Offer {
        key_package: "changed".into(),
    };
    assert!(mesh.import(0, 1, conflict).is_err());
    let mut bad_link = offer.clone();
    bad_link.link = Uuid::new_v4();
    assert!(mesh.import(0, 1, bad_link).is_err());
    mesh.stores[2].mesh_tick().unwrap();
    mesh.import(2, 0, offer).unwrap();
    mesh.stores[2].mesh_tick().unwrap();
    let error: String = mesh.stores[2]
        .db
        .query_row("SELECT error FROM mesh_jobs", [], |r| r.get(0))
        .unwrap();
    assert!(
        error.contains("key package belongs to another node"),
        "{error}"
    );
    assert_eq!(mesh.count(2, "network_links"), 1);
    // A valid owner-signed Welcome still cannot claim the other peer's identity.
    let outgoing: Vec<u8> = mesh.stores[0]
        .db
        .query_row(
            "SELECT outgoing FROM network_links WHERE peer=?1",
            [mesh.stores[2].identity.node.id()],
            |r| r.get(0),
        )
        .unwrap();
    let packet = mesh.stores[0].data_outgoing(&outgoing, 0).unwrap().unwrap();
    let welcome = mesh.envelope(MeshSignal::Welcome {
        packet: STANDARD.encode(packet.encode().unwrap()),
    });
    mesh.import(2, 0, welcome).unwrap();
    mesh.stores[2].mesh_tick().unwrap();
    assert_eq!(mesh.count(2, "streams"), 3);
    assert_eq!(mesh.count(2, "network_links"), 1);
}

#[tokio::test]
async fn mesh_discards_bootstrap_overtaken_by_revocation() {
    let mut mesh = Mesh::new().await;
    let envelope = mesh.envelope(MeshSignal::Offer {
        key_package: "unused".into(),
    });
    mesh.import(0, 1, envelope.clone()).unwrap();
    let origin = mesh.stores[1].identity.node.id().to_owned();
    let owner = &mesh.stores[0];
    let state = owner.identity.state(&owner.db).unwrap();
    let update = state
        .revoke_node(
            &owner.identity.signing_owner(&owner.db).unwrap(),
            &origin,
            now() as u64,
        )
        .unwrap();
    for i in [0, 2] {
        let s = &mesh.stores[i];
        let tx = s.db.unchecked_transaction().unwrap();
        s.identity.apply(&tx, update.clone()).unwrap();
        tx.commit().unwrap();
    }
    mesh.stores[0].mesh_tick().unwrap();
    assert_eq!(
        mesh.stores[0]
            .db
            .query_row("SELECT done FROM mesh_jobs", [], |r| r.get::<_, usize>(0))
            .unwrap(),
        1
    );
    mesh.import(2, 0, envelope).unwrap();
    mesh.stores[2].mesh_tick().unwrap();
    assert_eq!(mesh.count(2, "mesh_jobs"), 0);
    assert_eq!(mesh.count(2, "mesh_peers"), 0);
    assert_eq!(mesh.count(2, "network_links"), 1);
}
