use super::*;
use crate::gateway::registry::{Conversation, conversations::KEY};

#[tokio::test]
async fn explicit_conversations_survive_refresh_but_never_cross_oauth_authorizations() {
    for signed in [false, true] {
        let f = Fixture::with_binding(signed, None, KEY);
        let first = f.grant();
        let other = f.grant();
        let handle = f
            .registry
            .open_conversation_remote(f.permit(&first))
            .await
            .unwrap();
        let conversation = Conversation::Handle(handle["conversation"].as_str().unwrap().into());
        let original = f
            .registry
            .credential_remote(f.permit(&first), conversation.clone())
            .await
            .unwrap();
        assert!(
            f.registry
                .credential_remote(f.permit(&other), conversation.clone())
                .await
                .is_err()
        );
        let refreshed = f.registry.exchange(&f.refresh(&first), RESOURCE).unwrap();
        let reopened = Registry::open(&f.home).unwrap();
        assert_eq!(
            reopened
                .credential_remote(f.permit(&refreshed), conversation.clone())
                .await
                .unwrap(),
            original
        );
        assert!(
            reopened
                .credential_remote(f.permit(&refreshed), json!({KEY:handle["conversation"]}))
                .await
                .is_err()
        );
        let permit = f.permit(&refreshed);
        reopened.revoke(&f.client).unwrap();
        assert!(
            reopened
                .credential_remote(permit, conversation)
                .await
                .is_err()
        );
    }
}
