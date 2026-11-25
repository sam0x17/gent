//! Ciphertext object transport for trusted endpoint code. Service acknowledgments
//! are availability hints, never agent permission or delivery receipts. The caller
//! must bind objects/deadlines to authorized messages and authenticate downloaded
//! bytes with the private FileGrant before exposing plaintext.
use crate::{
    config::RelayConfig,
    sync::{Relay, bounded},
};
use anyhow::{Result, ensure};
use gent_protocol::file_objects::{MAX_MANIFEST_BYTES, Manifest, Snapshot, valid_id};
use reqwest::{StatusCode, Url, header};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Clone)]
pub struct FileRelay {
    relay: Relay,
}

impl FileRelay {
    /// Uses the existing private relay credential and origin validation. HTTP is
    /// restricted to explicitly allowed loopback development endpoints.
    pub fn open(settings: &RelayConfig, home: &Path) -> Result<Self> {
        Ok(Self {
            relay: Relay::open(settings, home)?,
        })
    }

    pub(crate) fn from_relay(relay: Relay) -> Self {
        Self { relay }
    }

    fn route(&self, id: &str, index: Option<u32>) -> Result<Url> {
        ensure!(valid_id(id), "invalid file object ID");
        let mut route = format!("v1/objects/{id}");
        if let Some(index) = index {
            route.push_str(&format!("/{index}"));
        }
        Ok(self.relay.origin.join(&route)?)
    }

    pub async fn reserve(&self, id: &str, manifest: &Manifest) -> Result<Snapshot> {
        manifest.validate().map_err(anyhow::Error::msg)?;
        let body = serde_json::to_vec(manifest)?;
        ensure!(
            body.len() <= MAX_MANIFEST_BYTES,
            "object manifest too large"
        );
        let response = self
            .relay
            .client
            .put(self.route(id, None)?)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "object reservation failed ({})",
            response.status()
        );
        let snapshot = snapshot(response).await?;
        ensure!(
            snapshot.manifest == *manifest,
            "relay changed object reservation"
        );
        Ok(snapshot)
    }

    pub async fn status(&self, id: &str) -> Result<Option<Snapshot>> {
        let response = self.relay.client.get(self.route(id, None)?).send().await?;
        if matches!(response.status(), StatusCode::NOT_FOUND | StatusCode::GONE) {
            return Ok(None);
        }
        ensure!(
            response.status() == StatusCode::OK,
            "object status failed ({})",
            response.status()
        );
        Ok(Some(snapshot(response).await?))
    }

    pub async fn put(&self, id: &str, manifest: &Manifest, index: u32, bytes: &[u8]) -> Result<()> {
        verify_chunk(manifest, index, bytes)?;
        let response = self
            .relay
            .client
            .put(self.route(id, Some(index))?)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "object chunk upload failed ({})",
            response.status()
        );
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            stored: bool,
            index: u32,
            complete: bool,
        }
        let stored: Stored = serde_json::from_slice(&bounded(response, 1024).await?)?;
        ensure!(
            stored.stored && stored.index == index,
            "invalid object storage acknowledgment"
        );
        // The complete hint is deliberately not a file/agent delivery result.
        let _ = stored.complete;
        Ok(())
    }

    pub async fn get(&self, id: &str, manifest: &Manifest, index: u32) -> Result<Option<Vec<u8>>> {
        manifest.validate().map_err(anyhow::Error::msg)?;
        let chunk = manifest
            .chunks
            .get(index as usize)
            .ok_or_else(|| anyhow::anyhow!("invalid file chunk index"))?;
        let response = self
            .relay
            .client
            .get(self.route(id, Some(index))?)
            .send()
            .await?;
        if matches!(response.status(), StatusCode::NOT_FOUND | StatusCode::GONE) {
            return Ok(None);
        }
        ensure!(
            response.status() == StatusCode::OK,
            "object chunk fetch failed ({})",
            response.status()
        );
        let bytes = bounded(response, chunk.bytes as usize).await?;
        verify_chunk(manifest, index, &bytes)?;
        Ok(Some(bytes))
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        let response = self
            .relay
            .client
            .delete(self.route(id, None)?)
            .send()
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "object deletion failed ({})",
            response.status()
        );
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Deleted {
            deleted: bool,
        }
        let result: Deleted = serde_json::from_slice(&bounded(response, 1024).await?)?;
        ensure!(result.deleted, "invalid object deletion acknowledgment");
        Ok(())
    }
}

async fn snapshot(response: reqwest::Response) -> Result<Snapshot> {
    let result: Snapshot =
        serde_json::from_slice(&bounded(response, MAX_MANIFEST_BYTES + 2048).await?)?;
    result.validate().map_err(anyhow::Error::msg)?;
    Ok(result)
}

pub(crate) fn verify_chunk(manifest: &Manifest, index: u32, bytes: &[u8]) -> Result<()> {
    manifest.validate().map_err(anyhow::Error::msg)?;
    let chunk = manifest
        .chunks
        .get(index as usize)
        .ok_or_else(|| anyhow::anyhow!("invalid file chunk index"))?;
    ensure!(
        bytes.len() == chunk.bytes as usize
            && format!("{:x}", Sha256::digest(bytes)) == chunk.sha256,
        "file ciphertext does not match manifest"
    );
    Ok(())
}
