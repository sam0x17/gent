use super::*;

#[test]
fn file_delegation_survives_refresh_but_follows_grant_revocation_and_user_scope() {
    for scoped in [false, true] {
        let f = Fixture::with_subject(false, scoped.then_some("test/subject"));
        let initial = f.grant();
        let meta = if scoped {
            json!({"test/conversation":"same","test/subject":"alice"})
        } else {
            json!({"test/conversation":"same"})
        };
        let permit = f.permit(&initial);
        let credential = f.registry.credential(&permit, &meta).unwrap();
        let origin = RESOURCE.strip_suffix("/mcp").unwrap();
        let target = DownloadTarget {
            file: Uuid::new_v4().to_string(),
            origin: origin.into(),
            expires_at: auth::now().unwrap() + 3600,
        };
        let (ticket, _) = f
            .registry
            .issue_download_local(&permit, &meta, &credential, &target)
            .unwrap();
        assert_eq!(
            f.registry
                .check_download_local(&ticket, origin)
                .unwrap()
                .credential,
            credential
        );
        let refreshed = f.registry.exchange(&f.refresh(&initial), RESOURCE).unwrap();
        assert!(
            f.registry
                .authenticate_at(initial["access_token"].as_str().unwrap(), Some(RESOURCE))
                .is_err()
        );
        assert_eq!(
            Registry::open(&f.home)
                .unwrap()
                .check_download_local(&ticket, origin)
                .unwrap()
                .credential,
            credential
        );
        if scoped {
            let bob = f.grant();
            let bob_meta = json!({"test/conversation":"same","test/subject":"bob"});
            let bob_key = f.registry.credential(&f.permit(&bob), &bob_meta).unwrap();
            assert_ne!(bob_key, credential);
            assert!(
                f.registry
                    .issue_download_local(&f.permit(&refreshed), &bob_meta, &bob_key, &target)
                    .is_err()
            );
            let (id, _) = permit.oauth.as_ref().unwrap();
            let mut state = f.registry.read().unwrap();
            state
                .oauth
                .as_mut()
                .unwrap()
                .grants
                .get_mut(id)
                .unwrap()
                .subject = Some(Subject::Bound("0".repeat(64)));
            f.registry.save(&state).unwrap();
            assert!(f.registry.check_download_local(&ticket, origin).is_err());
        } else {
            // Reuse of a spent refresh token revokes this family. Reauthorizing
            // the same agent cannot revive a download delegated by the old grant.
            assert!(f.registry.exchange(&f.refresh(&initial), RESOURCE).is_err());
            assert!(f.registry.check_download_local(&ticket, origin).is_err());
            let new = f.grant();
            assert_eq!(
                f.registry.credential(&f.permit(&new), &meta).unwrap(),
                credential
            );
            assert!(f.registry.check_download_local(&ticket, origin).is_err());
        }
    }
}
