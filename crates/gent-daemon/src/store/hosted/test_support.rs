//! Isolated enrolled Store fixtures, shared without importing test drivers.
use crate::{
    config, runtime,
    store::{Store, now},
};
use gent_crypto::{NodeIdentity, VerifiedState};
use gent_protocol::{AgentOp, Effect, Permission, Request, Rule, Selector};
use std::{fs, os::unix::fs::PermissionsExt};

pub(in crate::store::hosted) struct Pair {
    pub(in crate::store::hosted) homes: [tempfile::TempDir; 2],
    pub(in crate::store::hosted) parent: Store,
    pub(in crate::store::hosted) child: Store,
    pub(in crate::store::hosted) state: VerifiedState,
    pub(in crate::store::hosted) agents: [String; 3],
    pub(in crate::store::hosted) keys: [String; 3],
}

impl Pair {
    pub(in crate::store::hosted) fn new() -> Self {
        let homes = std::array::from_fn(|_| {
            let home = tempfile::tempdir().unwrap();
            fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
            home
        });
        let mut cfg = config::initialize(homes[0].path(), "hosted-import-test").unwrap();
        cfg.policy.rules = [Permission::Enumerate, Permission::Send, Permission::Receive]
            .map(|permission| Rule {
                actor: Selector::All,
                peer: Selector::All,
                permission,
                effect: Effect::Allow,
            })
            .into();
        config::save(homes[0].path(), &cfg).unwrap();
        crate::entitlements::grant_test(homes[0].path(), &cfg);
        let mut parent = Store::open(homes[0].path()).unwrap();
        let state = parent.identity.state(&parent.db).unwrap();
        let node = NodeIdentity::generate().unwrap();
        let request = node
            .request_enrollment(state.anchor(), state.checkpoint(), "web", now() as u64)
            .unwrap();
        let update = state
            .enroll(
                &*parent.identity.signing_owner(&parent.db).unwrap(),
                &request,
                request.fingerprint().unwrap(),
                now() as u64,
            )
            .unwrap();
        let tx = parent.db.transaction().unwrap();
        let state = parent.identity.apply(&tx, update).unwrap();
        tx.commit().unwrap();
        runtime::install_joined(homes[1].path(), &node, &state).unwrap();
        let mut child = Store::open(homes[1].path()).unwrap();
        crate::entitlements::grant_test(homes[1].path(), &child.config);
        let keys = std::array::from_fn(|_| config::secret());
        let agents = std::array::from_fn(|i| {
            let store = if i == 0 { &mut parent } else { &mut child };
            store
                .execute(Request::Agent {
                    credential: keys[i].clone(),
                    action: AgentOp::Register {
                        name: format!("fixture-{i}"),
                        provider: "test".into(),
                    },
                })
                .unwrap()["agent"]["id"]
                .as_str()
                .unwrap()
                .into()
        });
        Self {
            homes,
            parent,
            child,
            state,
            agents,
            keys,
        }
    }
}
