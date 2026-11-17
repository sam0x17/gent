use gent_crypto::configuration_log::{WriteCapability, intent, verify};
use gent_protocol::configuration_log::{Head, Header, MAX_SEQUENCE};
use uuid::Uuid;

fn header(writer: &WriteCapability, next: &WriteCapability) -> Header {
    Header {
        version: 1,
        cluster: Uuid::new_v4().to_string(),
        origin: Uuid::new_v4().to_string(),
        operation: Uuid::new_v4().to_string(),
        intent: intent(&[1; 32], b"private edit"),
        previous: Head {
            sequence: 41,
            digest: [2; 32],
            write_key: writer.public_key(),
        },
        next_write_key: next.public_key(),
    }
}

#[test]
fn admission_binds_ciphertext_origin_intent_sequence_cluster_and_rotation() {
    let writer = WriteCapability::generate().unwrap();
    let next = WriteCapability::generate().unwrap();
    let record = writer.seal(header(&writer, &next), &[7; 128]).unwrap();
    let receipt = verify(&record).unwrap();
    assert_eq!(receipt.head.sequence, 42);
    assert_eq!(receipt.head.write_key, next.public_key());
    assert_eq!(verify(&record).unwrap(), receipt);
    let mut mutations = Vec::new();
    let mut changed = record.clone();
    changed.header.cluster = Uuid::new_v4().to_string();
    mutations.push(changed);
    let mut changed = record.clone();
    changed.header.origin = Uuid::new_v4().to_string();
    mutations.push(changed);
    let mut changed = record.clone();
    changed.header.operation = Uuid::new_v4().to_string();
    mutations.push(changed);
    let mut changed = record.clone();
    changed.header.intent[0] ^= 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.header.previous.sequence += 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.header.previous.digest[0] ^= 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.header.next_write_key = WriteCapability::generate().unwrap().public_key();
    mutations.push(changed);
    let mut changed = record.clone();
    changed.ciphertext.replace_range(..1, "A");
    mutations.push(changed);
    let mut changed = record.clone();
    changed.signature[0] ^= 1;
    mutations.push(changed);
    for changed in mutations {
        assert!(verify(&changed).is_err());
    }
}

#[test]
fn retired_capability_cannot_sign_a_commit_against_the_new_head() {
    let old = WriteCapability::generate().unwrap();
    let current = WriteCapability::generate().unwrap();
    let future = WriteCapability::generate().unwrap();
    let first = old.seal(header(&old, &current), &[7; 128]).unwrap();
    let mut update = header(&current, &future);
    update.previous = verify(&first).unwrap().head;
    assert!(old.seal(update.clone(), &[8; 128]).is_err());
    assert!(verify(&current.seal(update, &[8; 128]).unwrap()).is_ok());
}

#[test]
fn capacity_boundaries_and_weak_keys_are_rejected() {
    let writer = WriteCapability::generate().unwrap();
    let next = WriteCapability::generate().unwrap();
    let mut h = header(&writer, &next);
    h.previous.sequence = MAX_SEQUENCE;
    assert!(writer.seal(h, &[1; 16]).is_err());
    let mut h = header(&writer, &next);
    h.next_write_key = writer.public_key();
    assert!(writer.seal(h, &[1; 16]).is_err());
    let mut h = header(&writer, &next);
    h.next_write_key = [0; 32];
    h.next_write_key[0] = 1; // Edwards identity
    assert!(writer.seal(h, &[1; 16]).is_err());
    assert!(writer.seal(header(&writer, &next), &[1; 15]).is_err());
    let mut record = writer.seal(header(&writer, &next), &[1; 16]).unwrap();
    record.ciphertext.push('=');
    assert!(verify(&record).is_err());
    assert_ne!(
        intent(&[1; 32], b"private edit"),
        intent(&[2; 32], b"private edit")
    );
}
