use gent_crypto::{
    NodeIdentity,
    stream::{MAX_CIPHERTEXT_BYTES, MAX_PACKET_BYTES, MAX_SEQUENCE, Packet},
};
use serde_json::json;

#[test]
fn signatures_bind_ciphertext_group_sequence_and_predecessor() {
    let node = NodeIdentity::generate().unwrap();
    let other = NodeIdentity::generate().unwrap();
    let origin = node
        .sign_stream_packet(b"opaque group", 0, [0; 32], b"MLS Welcome")
        .unwrap();
    let packet = node
        .sign_stream_packet(
            origin.group(),
            1,
            origin.digest().unwrap(),
            b"MLS ciphertext",
        )
        .unwrap();
    packet.verify(&node.public_key()).unwrap();
    assert!(packet.verify(&other.public_key()).is_err());
    let wire = packet.encode().unwrap();
    assert_eq!(packet, Packet::decode(&wire).unwrap());
    assert!(!String::from_utf8(wire).unwrap().contains(node.id()));
    for (field, value) in [
        ("group", json!("b3RoZXI=")),
        ("sequence", json!(2)),
        ("previous", json!(vec![1; 32])),
        ("ciphertext", json!("b3RoZXI=")),
        ("signature", json!("b3RoZXI=")),
    ] {
        let mut changed = serde_json::to_value(&packet).unwrap();
        changed[field] = value;
        let changed: Packet = serde_json::from_value(changed).unwrap();
        assert!(
            changed.verify(&node.public_key()).is_err(),
            "accepted changed {field}"
        );
    }
}

#[test]
fn packet_wire_is_canonical_bounded_and_versioned() {
    let node = NodeIdentity::generate().unwrap();
    let packet = node
        .sign_stream_packet(b"group", 0, [0; 32], b"ciphertext")
        .unwrap();
    let mut wire = packet.encode().unwrap();
    wire.push(b' ');
    assert!(Packet::decode(&wire).is_err());
    let wire = String::from_utf8(packet.encode().unwrap()).unwrap();
    let duplicate = wire.replacen('{', "{\"sequence\":0,", 1);
    assert!(Packet::decode(duplicate.as_bytes()).is_err());
    let mut value = serde_json::to_value(&packet).unwrap();
    value["extra"] = json!(true);
    assert!(Packet::decode(&serde_jcs::to_vec(&value).unwrap()).is_err());
    value.as_object_mut().unwrap().remove("extra");
    value["version"] = json!(2);
    assert!(Packet::decode(&serde_jcs::to_vec(&value).unwrap()).is_err());
    assert!(Packet::decode(&vec![0; MAX_PACKET_BYTES + 1]).is_err());
    assert!(
        node.sign_stream_packet(b"group", 0, [1; 32], b"bad origin")
            .is_err()
    );
    assert!(
        node.sign_stream_packet(b"group", 1, [0; 32], b"bad predecessor")
            .is_err()
    );
    assert!(
        node.sign_stream_packet(b"group", MAX_SEQUENCE + 1, [1; 32], b"overflow")
            .is_err()
    );
    assert!(
        node.sign_stream_packet(&[0; 257], 0, [0; 32], b"group too long")
            .is_err()
    );
    assert!(
        node.sign_stream_packet(b"group", 0, [0; 32], &vec![0; MAX_CIPHERTEXT_BYTES + 1])
            .is_err()
    );
}
