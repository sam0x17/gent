use gent_crypto::NodeIdentity;
use gent_daemon::{
    config,
    encrypted::{EncryptedEndpoint, ordered::OrderedEndpoint},
    recovery::{MARKER, ensure_active},
    replica::Replica,
    store::Store,
};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};

fn refused<T>(result: anyhow::Result<T>) {
    let error = result.err().expect("recovery state must stay offline");
    assert!(error.to_string().contains("offline recovery directory"));
}

fn snapshot(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if entry.file_type().unwrap().is_dir() {
            files.insert(format!("{name}/"), vec![]);
            for (child, bytes) in snapshot(&entry.path()) {
                files.insert(format!("{name}/{child}"), bytes);
            }
        } else {
            files.insert(name, fs::read(entry.path()).unwrap());
        }
    }
    files
}

#[test]
fn guard_checks_presence_ancestors_aliases_and_missing_children() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("extracted");
    let sibling = directory.path().join("fresh");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("nested")).unwrap();
    let marker = root.join(MARKER);
    for contents in [b"".as_slice(), b"invalid JSON", b"{\"recovered\":true}"] {
        fs::write(&marker, contents).unwrap();
        refused(ensure_active(&root));
        refused(ensure_active(&root.join("nested")));
        refused(ensure_active(&root.join("missing/profile")));
        refused(ensure_active(&root.join("nested/../missing")));
        ensure_active(&sibling).unwrap();
        assert!(!sibling.exists());
    }
    fs::remove_file(&marker).unwrap();
    // A dangling symlink is still a guard, never an absent marker.
    symlink("absent", &marker).unwrap();
    refused(ensure_active(&root));
    fs::remove_file(&marker).unwrap();
    fs::create_dir(&marker).unwrap();
    refused(ensure_active(&root));
    let alias = directory.path().join("alias");
    symlink(root.join("nested"), &alias).unwrap();
    refused(ensure_active(&alias));
    refused(ensure_active(&alias.join("new/profile")));
    fs::remove_dir(&marker).unwrap();
    ensure_active(&alias).unwrap();
    ensure_active(&root.join("missing/profile")).unwrap();
    assert!(!root.join("missing").exists());
    // An unreadable/non-directory marker parent fails closed.
    fs::write(root.join("file"), b"not a directory").unwrap();
    assert!(ensure_active(&root.join("file/child")).is_err());
}

#[test]
fn saved_configuration_keys_and_databases_cannot_activate_or_change() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
    let cfg = config::initialize(home, "archived").unwrap();
    drop(Store::open(home).unwrap());
    let identity = NodeIdentity::generate().unwrap();
    drop(EncryptedEndpoint::open(home, &identity).unwrap());
    drop(Replica::open(home).unwrap());
    config::write_private(&home.join(MARKER), b"{\"version\":1}").unwrap();
    let before = snapshot(home);
    refused(config::load(home));
    refused(config::save(home, &cfg));
    refused::<()>(config::edit_local(home, |_| panic!("must not edit")));
    refused(config::initialize(home, "replacement"));
    refused(Store::open(home));
    refused(EncryptedEndpoint::open(home, &identity));
    refused(OrderedEndpoint::open(home, &identity));
    refused(OrderedEndpoint::open_runtime(home, &identity));
    refused(Replica::open(home));
    assert_eq!(snapshot(home), before);
    let missing = home.join("nested/profile");
    refused(config::initialize(&missing, "new"));
    refused(EncryptedEndpoint::open(&missing, &identity));
    refused(Replica::open(&missing));
    assert!(!home.join("nested").exists());
}

#[tokio::test]
async fn daemon_and_rpc_refuse_before_locks_or_socket_access() {
    use gent_protocol::{OwnerOp, Request, file_objects::IncomingFile};
    use std::os::unix::net::UnixListener;
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
    config::write_private(&home.join(MARKER), b"{}").unwrap();
    let listener = UnixListener::bind(home.join("daemon.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    refused(gent_daemon::run(home).await);
    refused(
        gent_daemon::request(
            home,
            Request::Owner {
                credential: "private".into(),
                action: OwnerOp::Status,
            },
        )
        .await,
    );
    refused(
        gent_daemon::receive_file(
            home,
            "private".into(),
            IncomingFile {
                request_id: uuid::Uuid::new_v4().to_string(),
                source_id: "source".into(),
                name: "private.txt".into(),
                media_type: "text/plain".into(),
            },
            b"private body",
        )
        .await,
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(!home.join("daemon.lock").exists());
    assert_eq!(fs::read_dir(home).unwrap().count(), 2);
}
