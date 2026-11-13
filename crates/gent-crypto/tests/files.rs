use gent_crypto::files::{
    CHUNK_BYTES, FileGrant, MAX_CHUNKS, MAX_FILE_BYTES, MAX_GRANT_BYTES, TAG_BYTES, seal,
};
use serde_json::{Value, json};
use uuid::Uuid;

fn wire(grant: &FileGrant) -> Value {
    serde_json::from_slice(&grant.encode_private().unwrap()).unwrap()
}

fn decode(value: &Value) -> anyhow::Result<FileGrant> {
    FileGrant::decode_private(&serde_json::to_vec(value).unwrap())
}

#[test]
fn matches_independent_python_chacha20poly1305_vectors() {
    let vectors: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/file_objects_v1.json")).unwrap();
    let hex = |s: &str| {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    for vector in vectors {
        let grant = decode(&vector["grant"]).unwrap();
        let ciphertext = hex(vector["ciphertext_hex"].as_str().unwrap());
        let plaintext = hex(vector["plaintext_hex"].as_str().unwrap());
        assert_eq!(
            *grant
                .decrypt_chunk(vector["index"].as_u64().unwrap() as u32, &ciphertext)
                .unwrap(),
            plaintext
        );
        if grant.chunk_count() == 1 {
            assert_eq!(*grant.open(&[ciphertext]).unwrap(), plaintext);
        }
    }
}

#[test]
fn empty_boundary_and_maximum_files_round_trip() {
    for size in [
        0,
        1,
        CHUNK_BYTES - 1,
        CHUNK_BYTES,
        CHUNK_BYTES + 1,
        MAX_FILE_BYTES,
    ] {
        let bytes: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
        let file = seal("frame-猫.png", "image/png", &bytes).unwrap();
        let grant = file.grant();
        assert_eq!(grant.descriptor().byte_length, size as u64);
        assert!(grant.chunk_count() <= MAX_CHUNKS);
        assert_eq!(file.chunks().len(), size.div_ceil(CHUNK_BYTES).max(1));
        assert_eq!(
            file.chunks().iter().map(Vec::len).sum::<usize>(),
            size + file.chunks().len() * TAG_BYTES
        );
        for (index, chunk) in file.chunks().iter().enumerate() {
            assert_eq!(chunk.len(), grant.ciphertext_len(index as u32).unwrap());
        }
        let received = FileGrant::decode_private(&grant.encode_private().unwrap()).unwrap();
        assert_eq!(*received.open(file.chunks()).unwrap(), bytes);
        assert!(grant.ciphertext_len(grant.chunk_count()).is_err());
        assert!(grant.decrypt_chunk(u32::MAX, &[]).is_err());
        if size == 0 {
            assert_eq!(file.chunks()[0].len(), TAG_BYTES);
            assert!(grant.open(&[]).is_err());
        }
    }
    assert!(
        seal(
            "huge.bin",
            "application/octet-stream",
            &vec![0; MAX_FILE_BYTES + 1]
        )
        .is_err()
    );
}

#[test]
fn new_transfers_use_independent_ids_keys_and_ciphertext() {
    let a = seal("same.bin", "application/octet-stream", b"same bytes").unwrap();
    let b = seal("same.bin", "application/octet-stream", b"same bytes").unwrap();
    assert_ne!(a.grant().descriptor().id, b.grant().descriptor().id);
    assert_ne!(wire(a.grant())["key"], wire(b.grant())["key"]);
    assert_ne!(a.chunks(), b.chunks());
    assert_eq!(a.grant().descriptor().sha256, b.grant().descriptor().sha256);
    assert_eq!(
        a.grant().encode_private().unwrap(),
        a.grant().encode_private().unwrap()
    );
    assert!(a.grant().open(b.chunks()).is_err());
    let public = serde_json::to_value(a.grant().descriptor()).unwrap();
    assert_eq!(public.as_object().unwrap().len(), 5);
    assert!(public.get("key").is_none());
}

#[test]
fn storage_manifest_contains_only_ciphertext_metadata() {
    let sealed = seal(
        "private-filename.png",
        "image/png",
        b"private image content",
    )
    .unwrap();
    let manifest = sealed.transport_manifest(12345).unwrap();
    manifest.validate().unwrap();
    let encoded = serde_json::to_string(&manifest).unwrap();
    for private in [
        "private-filename.png",
        "image/png",
        "private image content",
        &sealed.grant().descriptor().sha256,
    ] {
        assert!(!encoded.contains(private));
    }
    assert_eq!(
        manifest.ciphertext_bytes(),
        sealed.grant().ciphertext_bytes()
    );
    assert_eq!(manifest.chunks.len(), sealed.chunks().len());
    assert!(sealed.transport_manifest(0).is_err());
}

#[test]
fn every_chunk_binds_its_manifest_position_and_key() {
    let bytes = vec![42; CHUNK_BYTES * 2 + 17];
    let sealed = seal("original.bin", "application/octet-stream", &bytes).unwrap();
    let grant = sealed.grant();
    let original = wire(grant);
    for (field, value) in [
        ("id", json!(Uuid::new_v4().to_string())),
        ("name", json!("replaced.bin")),
        ("media_type", json!("image/png")),
        ("byte_length", json!(bytes.len() + 1)),
        ("sha256", json!("0".repeat(64))),
    ] {
        let mut changed = original.clone();
        changed["manifest"][field] = value;
        let changed = decode(&changed).unwrap();
        assert!(
            changed.decrypt_chunk(0, &sealed.chunks()[0]).is_err(),
            "accepted {field}"
        );
    }
    let mut changed = original;
    changed["key"][0] = json!((changed["key"][0].as_u64().unwrap() + 1) % 256);
    assert!(decode(&changed).unwrap().open(sealed.chunks()).is_err());
    let mut reordered = sealed.chunks().to_vec();
    reordered.swap(0, 1);
    assert!(grant.open(&reordered).is_err());
    assert!(grant.open(&sealed.chunks()[..2]).is_err());
    assert!(
        grant
            .open(&[sealed.chunks(), sealed.chunks()].concat())
            .is_err()
    );
    let mut duplicated = sealed.chunks().to_vec();
    duplicated[1] = duplicated[0].clone();
    assert!(grant.open(&duplicated).is_err());
    for index in 0..sealed.chunks().len() {
        let mut changed = sealed.chunks()[index].clone();
        changed[0] ^= 1;
        assert!(grant.decrypt_chunk(index as u32, &changed).is_err());
        let mut truncated = sealed.chunks()[index].clone();
        truncated.pop();
        assert!(grant.decrypt_chunk(index as u32, &truncated).is_err());
    }
}

#[test]
fn grants_are_bounded_strict_and_do_not_echo_secret_parse_input() {
    let file = seal("ok.bin", "application/octet-stream", b"x").unwrap();
    let original = wire(file.grant());
    for (field, value) in [
        ("id", json!("00000000-0000-0000-0000-000000000000")),
        ("id", json!("FFFFFFFF-FFFF-4FFF-8FFF-FFFFFFFFFFFF")),
        ("id", json!("ffffffff-ffff-4fff-0fff-ffffffffffff")),
        ("name", json!("../secret")),
        ("name", json!("a\\b")),
        ("name", json!("..")),
        ("name", json!("\u{0000}")),
        ("name", json!("x".repeat(129))),
        ("name", json!("  ")),
        ("media_type", json!("text/plain\r\nX-Header: value")),
        ("media_type", json!("text/plain; charset=utf-8")),
        ("media_type", json!("image/png/extra")),
        ("media_type", json!("image/")),
        ("byte_length", json!(MAX_FILE_BYTES + 1)),
        ("byte_length", json!(-1)),
        ("sha256", json!("f".repeat(63))),
        ("sha256", json!("F".repeat(64))),
        ("extra", json!(true)),
    ] {
        let mut changed = original.clone();
        changed["manifest"][field] = value;
        assert!(decode(&changed).is_err(), "accepted invalid {field}");
    }
    for (field, value) in [
        ("version", json!(2)),
        ("key", json!(vec![0; 31])),
        ("extra", json!(true)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(decode(&changed).is_err());
    }
    let encoded = String::from_utf8(file.grant().encode_private().unwrap().to_vec()).unwrap();
    let duplicate = encoded.replacen('{', &format!("{{\"key\":{},", original["key"]), 1);
    assert!(FileGrant::decode_private(duplicate.as_bytes()).is_err());
    let duplicate = encoded.replacen("\"name\":", "\"name\":\"first\",\"name\":", 1);
    assert!(FileGrant::decode_private(duplicate.as_bytes()).is_err());
    assert!(FileGrant::decode_private(&vec![b' '; MAX_GRANT_BYTES + 1]).is_err());
    let mut changed = original;
    changed["key"] = json!("PRIVATE-INPUT-MUST-NOT-APPEAR");
    let error = decode(&changed).err().unwrap().to_string();
    assert_eq!(error, "invalid file grant");
}
