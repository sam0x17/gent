use super::*;

fn fixture() -> (age::x25519::Identity, Manifest, Vec<u8>) {
    let body = vec![0x61; 65_536];
    let entries = ["config.toml", "identity.key", "state.sqlite3"]
        .into_iter()
        .map(|path| Entry {
            path: path.into(),
            kind: Kind::File,
            bytes: body.len() as u64,
            sha256: Some(format!("{:x}", Sha256::digest(&body))),
        })
        .collect();
    (
        age::x25519::Identity::generate(),
        Manifest {
            version: 1,
            archive_id: uuid::Uuid::new_v4().to_string(),
            created_at: 1,
            source_home: "/source".into(),
            node_id: uuid::Uuid::new_v4().to_string(),
            cluster_id: uuid::Uuid::new_v4().to_string(),
            entries,
            exclusions: vec![],
        },
        body.repeat(3),
    )
}

fn payload(key: &age::x25519::Identity, manifest: &Manifest, body: &[u8], sign: bool) -> Vec<u8> {
    let bytes = serde_jcs::to_vec(manifest).unwrap();
    let mut output = Vec::from(MAGIC.as_slice());
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(&bytes);
    let mut mac = authenticator(key);
    mac.update(&bytes);
    let tag: [u8; 32] = if sign {
        mac.finalize().into_bytes().into()
    } else {
        [0; 32]
    };
    output.extend_from_slice(&tag);
    output.extend_from_slice(body);
    output
}

fn encrypted(path: &Path, recipient: &age::x25519::Recipient, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    let mut writer =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
            .unwrap()
            .wrap_output(&mut file)
            .unwrap();
    writer.write_all(bytes).unwrap();
    writer.finish().unwrap();
}

#[test]
fn valid_age_encryption_cannot_forge_archive_origin_or_payload_integrity() {
    let folder = tempfile::tempdir().unwrap();
    let archive = folder.path().join("archive.age");
    let (key, manifest, body) = fixture();
    let recipient = key.to_public();
    let correct = payload(&key, &manifest, &body, true);
    encrypted(&archive, &recipient, &correct);
    assert_eq!(
        read(&archive, &key, None).unwrap().archive_id,
        manifest.archive_id
    );
    // The file is ordinary age: its standard decryptor recovers the container.
    assert_eq!(
        age::decrypt(&key, &fs::read(&archive).unwrap()).unwrap(),
        correct
    );
    encrypted(
        &archive,
        &recipient,
        &payload(&key, &manifest, &body, false),
    );
    assert!(
        read(&archive, &key, None)
            .unwrap_err()
            .to_string()
            .contains("origin authentication")
    );
    let mut changed = body.clone();
    changed[100] ^= 1;
    for bad in [
        changed,
        body[..body.len() - 1].to_vec(),
        [body.as_slice(), b"extra"].concat(),
    ] {
        encrypted(&archive, &recipient, &payload(&key, &manifest, &bad, true));
        assert!(read(&archive, &key, None).is_err());
    }
    let mut oversized = Vec::from(MAGIC.as_slice());
    oversized.extend_from_slice(&((MAX_MANIFEST + 1) as u32).to_be_bytes());
    encrypted(&archive, &recipient, &oversized);
    assert!(
        read(&archive, &key, None)
            .unwrap_err()
            .to_string()
            .contains("manifest length")
    );
}

#[test]
fn authenticated_unsafe_manifests_never_write_outside_staging() {
    let folder = tempfile::tempdir().unwrap();
    let archive = folder.path().join("archive.age");
    let staging = folder.path().join("staging");
    fs::create_dir(&staging).unwrap();
    let (key, manifest, body) = fixture();
    for name in [
        "../escaped",
        "/absolute",
        "recovery-required.json",
        "x/../escaped",
        "x/y",
        "config.toml/child",
    ] {
        let mut bad = manifest.clone();
        bad.entries[0].path = name.into();
        bad.entries.sort_by(|a, b| a.path.cmp(&b.path));
        encrypted(
            &archive,
            &key.to_public(),
            &payload(&key, &bad, &body, true),
        );
        assert!(read(&archive, &key, Some(&staging)).is_err());
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
        assert!(!folder.path().join("escaped").exists());
    }
    let mut bad = manifest;
    bad.entries.push(bad.entries[0].clone());
    encrypted(
        &archive,
        &key.to_public(),
        &payload(&key, &bad, &body, true),
    );
    assert!(read(&archive, &key, Some(&staging)).is_err());
    assert_eq!(fs::read_dir(staging).unwrap().count(), 0);
}
