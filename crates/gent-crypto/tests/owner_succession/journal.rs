use super::*;
use gent_crypto::succession::journal::{
    MAX_BYTES, MAX_ENTRIES, MAX_MANIFEST_BYTES, Manifest, PAGE_BYTES,
};

#[test]
fn journal_commitment_binds_authorization_checkpoint_candidate_and_page_position() {
    let (owner, nodes, state) = fixture();
    let next = OwnerKey::generate().unwrap();
    let candidate = nodes[1]
        .prepare_owner_candidate(&state, &next, &uuid::Uuid::new_v4().to_string(), NOW)
        .unwrap();
    let body = vec![42; 2 * PAGE_BYTES + 7];
    let manifest = Manifest::new(&candidate, 12, &body).unwrap();
    let authorization = state
        .authorize_owner_candidate_with_journal(&owner, &candidate, manifest.digest().unwrap(), NOW)
        .unwrap();
    manifest.verify(&state, &candidate, &authorization).unwrap();
    assert_eq!(
        Manifest::decode(&manifest.encode().unwrap()).unwrap(),
        manifest
    );
    for index in (0..3).rev() {
        let chunk = &body[index * PAGE_BYTES..body.len().min((index + 1) * PAGE_BYTES)];
        manifest.verify_page(index, chunk).unwrap();
        assert!(
            manifest
                .verify_page(index, &chunk[..chunk.len() - 1])
                .is_err()
        );
        let mut bad = chunk.to_vec();
        bad[0] ^= 1;
        assert!(manifest.verify_page(index, &bad).is_err());
    }
    assert!(manifest.verify_page(3, &[]).is_err());
    let mut reordered = manifest.clone();
    reordered.pages.swap(0, 1);
    assert!(reordered.verify_page(0, &body[..PAGE_BYTES]).is_err());
    for change in 0..4 {
        let mut bad = manifest.clone();
        match change {
            0 => bad.candidate[0] ^= 1,
            1 => bad.base.state_hash[0] ^= 1,
            2 => bad.entries += 1,
            _ => bad.pages[0].digest[0] ^= 1,
        }
        assert!(bad.verify(&state, &candidate, &authorization).is_err());
    }
    let other = nodes[1]
        .prepare_owner_candidate(&state, &next, &uuid::Uuid::new_v4().to_string(), NOW)
        .unwrap();
    assert!(manifest.verify(&state, &other, &authorization).is_err());
    let mut tampered = authorization.clone();
    tampered.transition.successor.as_mut().unwrap().journal = Some([9; 32]);
    assert!(
        state
            .verify_owner_authorization(&candidate, &tampered)
            .is_err()
    );
    let successor = state
        .accept_owner_authorization(&next, &candidate, &authorization, NOW)
        .unwrap();
    successor.verified_checkpoint(state.anchor()).unwrap();
}

#[test]
fn optional_journal_preserves_legacy_bytes_but_cannot_authorize_a_manifest() {
    let (owner, nodes, state) = fixture();
    let next = OwnerKey::generate().unwrap();
    let candidate = nodes[1]
        .prepare_owner_candidate(&state, &next, &uuid::Uuid::new_v4().to_string(), NOW)
        .unwrap();
    let original = state
        .authorize_owner_candidate(&owner, &candidate, NOW)
        .unwrap();
    let wire = original.encode().unwrap();
    assert!(!String::from_utf8(wire.clone()).unwrap().contains("journal"));
    assert_eq!(
        SignedOwnerTransition::decode(&wire)
            .unwrap()
            .encode()
            .unwrap(),
        wire
    );
    let manifest = Manifest::new(&candidate, 0, b"[]").unwrap();
    assert!(manifest.verify(&state, &candidate, &original).is_err());
    assert!(
        state
            .authorize_owner_candidate_with_journal(&owner, &candidate, [0; 32], NOW)
            .is_err()
    );
}

#[test]
fn journal_manifest_rejects_invalid_limits_and_noncanonical_encoding() {
    let (_, nodes, state) = fixture();
    let next = OwnerKey::generate().unwrap();
    let candidate = nodes[1]
        .prepare_owner_candidate(&state, &next, &uuid::Uuid::new_v4().to_string(), NOW)
        .unwrap();
    let manifest = Manifest::new(&candidate, 0, b"[]").unwrap();
    assert!(Manifest::new(&candidate, 0, b"").is_err());
    assert!(Manifest::new(&candidate, MAX_ENTRIES + 1, b"[]").is_err());
    for change in 0..9 {
        let mut bad = manifest.clone();
        match change {
            0 => bad.version += 1,
            1 => bad.entries = MAX_ENTRIES + 1,
            2 => bad.bytes = MAX_BYTES + 1,
            3 => bad.pages.clear(),
            4 => bad.pages[0].bytes += 1,
            5 => bad.pages[0].digest = [0; 32],
            6 => bad.base.state_hash = [0; 32],
            7 => bad.candidate = [0; 32],
            _ => bad.bytes = 0,
        }
        assert!(bad.validate().is_err());
        assert!(Manifest::decode(&serde_jcs::to_vec(&bad).unwrap()).is_err());
    }
    let mut wire = manifest.encode().unwrap();
    wire.push(b' ');
    assert!(Manifest::decode(&wire).is_err());
    let mut value = serde_json::to_value(&manifest).unwrap();
    value["extra"] = serde_json::json!(true);
    assert!(Manifest::decode(&serde_jcs::to_vec(&value).unwrap()).is_err());
    assert!(Manifest::decode(&vec![b' '; MAX_MANIFEST_BYTES + 1]).is_err());
    // Maximum manifest can be checked without allocating an 80 MiB body.
    let mut maximum = manifest.clone();
    maximum.bytes = MAX_BYTES;
    maximum.entries = MAX_ENTRIES;
    maximum.pages = vec![
        journal::Page {
            bytes: PAGE_BYTES,
            digest: [1; 32]
        };
        MAX_BYTES / PAGE_BYTES
    ];
    maximum.validate().unwrap();
    assert!(maximum.encode().unwrap().len() < MAX_MANIFEST_BYTES);
}
