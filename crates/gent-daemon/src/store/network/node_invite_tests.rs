use super::*;
use gent_crypto::invitation::{Invitation, Purpose};

#[tokio::test]
async fn named_node_requests_require_delegation_and_survive_lost_replies() {
    let mut pair = Pair::new().await;
    let account = Uuid::new_v4().to_string();
    for i in 0..2 {
        let cfg = &mut pair.stores[i].config;
        cfg.cluster.local_only = false;
        cfg.service = Some(config::ServiceConfig {
            origin: "https://accounts.example/".into(),
            account_id: account.clone(),
        });
        config::save(pair.homes[i].path(), cfg).unwrap();
    }
    let joined = pair.stores[1].identity.node.id().to_string();
    pair.owner(
        0,
        OwnerOp::DelegateConfiguration {
            node_id: joined.clone(),
            allow: false,
        },
    )
    .unwrap();
    pair.pump();
    let id = Uuid::now_v7().to_string();
    let action = OwnerOp::NodeInvite {
        request_id: id.clone(),
        name: "third-node".into(),
        can_configure: false,
        activate: false,
    };
    assert!(pair.owner(1, action.clone()).is_err());
    pair.owner(
        0,
        OwnerOp::DelegateConfiguration {
            node_id: joined.clone(),
            allow: true,
        },
    )
    .unwrap();
    pair.pump();
    assert_eq!(pair.owner(1, action.clone()).unwrap()["state"], "pending");
    pair.pump();
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_node_invite_reply BEFORE INSERT ON network_events BEGIN SELECT RAISE(ABORT,'lost invitation reply'); END;").unwrap();
    assert!(pair.stores[0].process_node_invites().is_err());
    assert_eq!(
        pair.stores[0]
            .db
            .query_row("SELECT COUNT(*) FROM invitations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_node_invite_reply;")
        .unwrap();
    pair.reopen(0);
    pair.reopen(1);
    pair.stores[0].process_node_invites().unwrap();
    pair.pump();
    let reply = pair.owner(1, action.clone()).unwrap();
    let invitation = Invitation::decode(
        &STANDARD
            .decode(reply["private_invitation"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(
        matches!(&invitation.offer().offer.purpose, Purpose::NamedNode { name, .. } if name == "third-node")
    );
    assert!(!invitation.offer().offer.can_configure);
    assert_eq!(pair.owner(1, action).unwrap(), reply);
    assert!(
        pair.owner(
            1,
            OwnerOp::NodeInvite {
                request_id: id.clone(),
                name: "changed".into(),
                can_configure: false,
                activate: false
            }
        )
        .is_err()
    );
    let activate = OwnerOp::NodeInvite {
        request_id: id,
        name: "third-node".into(),
        can_configure: false,
        activate: true,
    };
    assert_eq!(pair.owner(1, activate.clone()).unwrap()["state"], "pending");
    pair.pump();
    pair.stores[0].process_node_invites().unwrap();
    pair.pump();
    assert_eq!(pair.owner(1, activate.clone()).unwrap()["active"], true);
    pair.owner(
        0,
        OwnerOp::DelegateConfiguration {
            node_id: joined,
            allow: false,
        },
    )
    .unwrap();
    pair.pump();
    assert!(pair.owner(1, activate).is_err());
    assert!(pair.stores[0].invitation_live(invitation.offer()).is_err());
}
