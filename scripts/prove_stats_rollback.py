"""Deliver a pending candidate message across a downgrade on both supported Stable baselines."""

import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
STABLE_READERS = {
    "rollback-floor": "7fe14a8bfc5765790a598e05e94c69d82607bc68",
    "stable": "2e07f9214f1e119c4c181fe135c12c32f569e38c",
}
DAEMON = Path("crates/gent-daemon/src")


def append(tree, path, source):
    with (tree / DAEMON / path).open("a") as dest:
        dest.write("\n" + source + "\n")


def run_test(tree, name, env):
    target = Path(env["CARGO_TARGET_DIR"]) / tree.name
    subprocess.run(
        ["cargo", "test", "--locked", "--offline", "-p", "gent-daemon", "--lib",
         name, "--", "--exact"],
        cwd=tree, env={**env, "CARGO_TARGET_DIR": str(target)}, check=True,
    )


def main():
    with tempfile.TemporaryDirectory(prefix="gent-stats-rollback-") as tmp:
        root = Path(tmp)
        candidate = root / "candidate"
        shutil.copytree(ROOT, candidate, ignore=shutil.ignore_patterns(".git", "target"),
                        copy_function=shutil.copy)

        stage = root / "fixture"
        stage.mkdir(mode=0o700)
        env = os.environ.copy()
        env.update(GENT_STATS_FIXTURE=str(stage), TMPDIR=str(root))
        env.setdefault("CARGO_TARGET_DIR", str(root / "target"))
        env.setdefault("CARGO_PROFILE_TEST_DEBUG", "0")

        # Both builds use their actual transport. These additions only expose
        # the existing private paired-store and in-memory watch test drivers.
        append(candidate, "sync.rs", """
#[cfg(test)]
pub(crate) use notifications::wss::tests::capture_ordinary_push;
""")
        append(candidate, "sync/notifications/wss/tests.rs", """
pub(crate) async fn capture_ordinary_push(store: &SharedStore, stream: Stream) -> Vec<u8> {
    let route = Wss::default();
    let mut socket = Connection::open(&route);
    let work = attempt(&route, store, &stream);
    let push = socket.next_send().await.unwrap();
    drop(socket);
    assert!(work.await.unwrap().1.is_none());
    push
}
""")
        append(candidate, "store/network/tests.rs", """
#[tokio::test]
async fn prepare_stats_rollback() -> Result<()> {
    use gent_protocol::transport_wss::{Frame, Kind};
    let dir = std::path::PathBuf::from(std::env::var_os("GENT_STATS_FIXTURE").unwrap());
    let mut pair = Pair::new().await;
    directory_push_tests::negotiate(&mut pair);
    let group = pair.group();
    let baseline = pair.stores[1].transport_receipt(&group, false)?;
    pair.stores[0].transport_confirm(&group, false, Some(&baseline))?;
    let sent = pair.send(vec![])?;
    let source = Uuid::parse_str(pair.stores[0].identity.node.id())?;
    let stats = pair.stores[0].next_stats_send()?.context("waiting for a negotiated Stats peer")?;
    let push = Frame { kind: Kind::Push, peer: source, id: Uuid::new_v4(), payload: &stats.wire };
    std::fs::write(dir.join("stats"), push.encode()?)?;
    let stream = crate::sync::Stream { group: group.clone(), outgoing: true, configuration: false };
    let [writer, reader] = pair.stores;
    let pending = crate::sync::capture_ordinary_push(&Arc::new(std::sync::Mutex::new(writer)), stream).await;
    let ordinary = Frame::decode(&pending)?;
    assert_eq!(ordinary.kind, Kind::Push);
    assert_eq!(ordinary.peer, stats.peer);
    // A live relay rewrites the outer destination UUID to the authenticated source.
    std::fs::write(dir.join("ordinary"), Frame { peer: source, ..ordinary }.encode()?)?;
    assert_eq!(reader.transport_receipt(&group, false)?, baseline);
    std::fs::write(dir.join("metadata"), serde_json::to_vec(&(
        baseline.sequence(), group, &pair.keys[1], &sent["message_id"]
    ))?)?;
    drop(reader);
    let [_, home] = pair.homes;
    std::fs::rename(home.path(), dir.join("receiver"))?;
    Ok(())
}
""")
        consume = """
#[tokio::test]
async fn consume_stats_rollback() -> Result<()> {
    use crate::store::Store;
    use gent_protocol::{AgentOp, Request, Response};
    let dir = std::path::PathBuf::from(std::env::var_os("GENT_STATS_FIXTURE").unwrap());
    let (before, group, credential, message_id): (u64, Vec<u8>, String, String) =
        serde_json::from_slice(&std::fs::read(dir.join("metadata"))?)?;
    let store = Arc::new(Mutex::new(Store::open(&dir.join("receiver"))?));
    let mut socket = Connection::open(&Wss::default());
    for (file, expected) in [("stats", Kind::Unavailable), ("ordinary", Kind::Receipt)] {
        let bytes = std::fs::read(dir.join(file))?;
        let request = Frame::decode(&bytes)?;
        socket.received(&bytes, &store)?;
        let reply = tokio::time::timeout(Duration::from_secs(10), socket.next_send()).await??;
        let frame = Frame::decode(&reply)?;
        assert_eq!((frame.kind, frame.peer, frame.id), (expected, request.peer, request.id));
        let sequence = store.lock().unwrap().transport_receipt(&group, false)?.sequence();
        if expected == Kind::Unavailable {
            assert!(frame.payload.is_empty());
            assert_eq!(sequence, before);
        } else {
            assert!(sequence > before);
        }
    }
    let Response::Ok(inbox) = store.lock().unwrap().handle(Request::Agent { credential, action: AgentOp::Inbox })
        else { anyhow::bail!("could not read fixture inbox") };
    assert_eq!(inbox.as_array().unwrap().len(), 1);
    assert_eq!(inbox[0]["id"], message_id);
    std::fs::write(dir.join("passed"), b"v11 received the queued message")?;
    Ok(())
}
"""
        run_test(candidate, "store::network::tests::prepare_stats_rollback", env)
        for label, revision in STABLE_READERS.items():
            tree = root / label
            tree.mkdir()
            with tempfile.TemporaryFile() as archive:
                subprocess.run(["git", "archive", revision], cwd=ROOT, stdout=archive, check=True)
                archive.seek(0)
                with tarfile.open(fileobj=archive) as files:
                    files.extractall(tree, filter="data")
            append(tree, "sync/notifications/wss/tests.rs", consume)
            replica = root / (label + "-fixture")
            shutil.copytree(stage, replica)
            run_test(tree, "sync::notifications::wss::tests::consume_stats_rollback",
                     {**env, "GENT_STATS_FIXTURE": str(replica)})
            print(label, revision, (replica / "passed").read_text(), flush=True)


if __name__ == "__main__":
    main()
