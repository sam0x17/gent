//! Private, read-only local readiness channel; never exposes host credentials.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

fn metadata(path: &Path) -> Result<fs::Metadata> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.file_type().is_socket()
            && meta.nlink() == 1
            && meta.uid() == rustix::process::geteuid().as_raw()
            && meta.mode() & 0o077 == 0,
        "gateway readiness socket must be private and owned by this user"
    );
    Ok(meta)
}

pub(super) struct Server {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
}

impl Server {
    /// Caller holds gateway/runtime.lock throughout the server's lifetime.
    pub(super) fn bind(home: &Path) -> Result<Self> {
        let path = home.join("gateway/control.sock");
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                metadata(&path)?;
                fs::remove_file(&path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let meta = metadata(&path)?;
        Ok(Self {
            listener,
            path,
            identity: (meta.dev(), meta.ino()),
        })
    }

    pub(super) async fn serve(&self, address: std::net::SocketAddr, origin: &str) -> Result<()> {
        self.serve_status(|| {
            json!({"version":1, "process_id":std::process::id(),
            "listen":address,"origin":origin})
        })
        .await
    }

    pub(super) async fn serve_status(&self, status: impl Fn() -> Value) -> Result<()> {
        loop {
            let (mut stream, _) = self.listener.accept().await?;
            if stream.peer_cred()?.uid() != rustix::process::geteuid().as_raw() {
                continue;
            }
            let mut value = status();
            value["build"] = serde_json::to_value(crate::build_info::current())?;
            let bytes = serde_json::to_vec(&value)?;
            let _ =
                tokio::time::timeout(Duration::from_millis(200), stream.write_all(&bytes)).await;
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if metadata(&self.path).is_ok_and(|meta| (meta.dev(), meta.ino()) == self.identity) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(crate) async fn probe(home: &Path) -> Result<Value> {
    let path = home.join("gateway/control.sock");
    metadata(&path)?;
    let stream = UnixStream::connect(path).await?;
    let peer = stream.peer_cred()?;
    ensure!(
        peer.uid() == rustix::process::geteuid().as_raw(),
        "gateway process belongs to another user"
    );
    let mut bytes = Vec::new();
    stream.take(4097).read_to_end(&mut bytes).await?;
    ensure!(bytes.len() <= 4096, "invalid gateway readiness response");
    let value: Value =
        serde_json::from_slice(&bytes).context("invalid gateway readiness response")?;
    ensure!(
        value["version"] == 1
            && value["process_id"].as_u64().is_some_and(|pid| pid > 0)
            && peer
                .pid()
                .is_none_or(|pid| value["process_id"].as_i64() == Some(i64::from(pid)))
            && valid_transport(&value)
            && value["origin"].as_str().is_some(),
        "invalid gateway readiness response"
    );
    Ok(value)
}

fn valid_transport(value: &Value) -> bool {
    if value["transport"] != "hosted_bridge" {
        return value["listen"]
            .as_str()
            .is_some_and(|s| s.parse::<std::net::SocketAddr>().is_ok());
    }
    value["listen"].is_null()
        && value["connected"].is_boolean()
        && value["endpoint"]
            .as_str()
            .and_then(|s| url::Url::parse(s).ok())
            .is_some_and(|url| {
                value["origin"].as_str() == Some(url.origin().ascii_serialization().as_str())
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && gent_protocol::hosted_mcp::route(url.path())
                        .is_some_and(|(_, _, path)| path == "/mcp")
            })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hosted_readiness_reports_the_connection_without_a_local_listener() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("gateway")).unwrap();
        let server = Server::bind(root.path()).unwrap();
        let task = tokio::spawn(async move {
            server.serve_status(|| json!({"version":1,"process_id":std::process::id(),"listen":null,
                "transport":"hosted_bridge","connected":true,"origin":"https://mcp.gent.link",
                "endpoint":"https://mcp.gent.link/clusters/629ec806-dc35-4c93-a174-38133d5b99f7/nodes/f84ce64e-2200-40b0-bc1d-cd64295d9c85/mcp"})).await
        });
        let value = probe(root.path()).await.unwrap();
        assert_eq!(value["connected"], true);
        assert_eq!(value["build"], json!(crate::build_info::current()));
        let mut invalid = value;
        invalid["endpoint"] = json!("https://other.example/mcp");
        assert!(!valid_transport(&invalid));
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn readiness_matches_the_process_and_cleanup_preserves_replaced_paths() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        fs::create_dir(root.path().join("gateway")).unwrap();
        let server = Server::bind(root.path()).unwrap();
        let address = "127.0.0.1:8787".parse().unwrap();
        let task =
            tokio::spawn(async move { server.serve(address, "http://127.0.0.1:8787").await });
        let value = tokio::time::timeout(Duration::from_secs(1), probe(root.path()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(value["process_id"], std::process::id());
        assert_eq!(value["listen"], "127.0.0.1:8787");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(!root.path().join("gateway/control.sock").exists());

        let server = Server::bind(root.path()).unwrap();
        fs::remove_file(&server.path).unwrap();
        fs::write(&server.path, b"preserve unrelated file").unwrap();
        drop(server);
        assert_eq!(
            fs::read(root.path().join("gateway/control.sock")).unwrap(),
            b"preserve unrelated file"
        );
        assert!(Server::bind(root.path()).is_err());
        assert!(probe(root.path()).await.is_err());
    }

    #[tokio::test]
    async fn stale_private_sockets_recover_but_links_and_shared_sockets_are_refused() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        fs::create_dir(root.path().join("gateway")).unwrap();
        let path = root.path().join("gateway/control.sock");
        let old = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        drop(old);
        let server = Server::bind(root.path()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(probe(root.path()).await.is_err());
        assert!(Server::bind(root.path()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        drop(server);
        let destination = root.path().join("keep");
        fs::write(&destination, b"keep").unwrap();
        std::os::unix::fs::symlink(&destination, &path).unwrap();
        assert!(Server::bind(root.path()).is_err());
        assert_eq!(fs::read(destination).unwrap(), b"keep");
    }
}
