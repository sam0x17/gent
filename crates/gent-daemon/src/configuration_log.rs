//! Ordered configuration transport. No network operation holds the Store lock.
//! Migration activation and trusted joining remain separate control-plane work.
use crate::{
    access, config,
    store::Store,
    sync::{Relay, bounded},
};
use anyhow::{Result, ensure};
use gent_protocol::configuration_log::{Bootstrap, Commit, Head, MAX_COMMIT_BYTES, Receipt};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

pub struct ConfigurationRelay {
    relay: Relay,
}

impl ConfigurationRelay {
    pub fn open(settings: &config::RelayConfig, home: &Path) -> Result<Self> {
        Ok(Self {
            relay: Relay::open(settings, home)?,
        })
    }

    pub(crate) fn from_relay(relay: Relay) -> Self {
        Self { relay }
    }

    async fn get<T: DeserializeOwned>(&self, path: &str, limit: usize) -> Result<Option<T>> {
        let response = self
            .relay
            .client
            .get(
                self.relay
                    .origin
                    .join(&format!("v1/configuration/{path}"))?,
            )
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure!(
            response.status() == StatusCode::OK,
            "configuration relay read failed ({})",
            response.status()
        );
        Ok(Some(serde_json::from_slice(
            &bounded(response, limit).await?,
        )?))
    }

    async fn publish(&self, commit: &Commit) -> Result<Option<Receipt>> {
        let response = self
            .relay
            .client
            .put(self.relay.origin.join("v1/configuration/commits")?)
            .json(commit)
            .send()
            .await?;
        if response.status() == StatusCode::CONFLICT {
            return Ok(None);
        }
        ensure!(
            response.status() == StatusCode::OK,
            "configuration relay write failed ({})",
            response.status()
        );
        let receipt: Receipt = serde_json::from_slice(&bounded(response, 4096).await?)?;
        ensure!(
            receipt.cluster == commit.header.cluster
                && receipt.origin == commit.header.origin
                && receipt.operation == commit.header.operation
                && receipt.intent == commit.header.intent,
            "configuration retry receipt mismatch"
        );
        Ok(Some(receipt))
    }

    async fn receive(&self, store: Arc<Mutex<Store>>, sequence: u64) -> Result<Receipt> {
        let commit: Commit = self
            .get(&format!("records/{sequence}"), MAX_COMMIT_BYTES)
            .await?
            .ok_or_else(|| anyhow::anyhow!("configuration log has a history gap"))?;
        ensure!(
            commit.header.previous.sequence + 1 == sequence,
            "configuration record sequence mismatch"
        );
        access::run(store, "configuration commit", move |store| {
            store.accept_configuration_commit(&commit)
        })
        .await
    }

    /// One bounded reconciliation pass, including discovery of a committed
    /// transition for nodes that were offline while migration happened.
    pub async fn sync_once(&self, store: Arc<Mutex<Store>>) -> Result<bool> {
        let Some(mut local) = access::run(store.clone(), "configuration checkpoint", |store| {
            store.configuration_log_head()
        })
        .await?
        else {
            let Some(bootstrap) = self.get::<Bootstrap>("bootstrap", 2048).await? else {
                access::run(store, "configuration discovery", |store| {
                    store.configuration_discovery(true);
                    Ok(())
                })
                .await?;
                return Ok(false);
            };
            access::run(store.clone(), "configuration discovery", |store| {
                store.configuration_discovery(false);
                Ok(())
            })
            .await?;
            ensure!(bootstrap.head.valid(), "invalid configuration bootstrap");
            let Some(commit) = self
                .get::<Commit>(
                    &format!("records/{}", bootstrap.head.sequence + 1),
                    MAX_COMMIT_BYTES,
                )
                .await?
            else {
                return Ok(false);
            };
            ensure!(
                commit.header.cluster == bootstrap.cluster
                    && commit.header.previous == bootstrap.head,
                "configuration migration bootstrap mismatch"
            );
            access::run(store, "configuration migration", move |store| {
                store.accept_configuration_commit(&commit)?;
                Ok(())
            })
            .await?;
            return Ok(true);
        };
        let remote: Head = self
            .get("head", 2048)
            .await?
            .ok_or_else(|| anyhow::anyhow!("configuration log has not been provisioned"))?;
        ensure!(
            remote.valid() && remote.sequence >= local.sequence,
            "configuration service head rolled back"
        );
        let mut progressed = false;
        for _ in 0..8 {
            if local.sequence == remote.sequence {
                break;
            }
            self.receive(store.clone(), local.sequence + 1).await?;
            local = access::run(store.clone(), "configuration checkpoint", |store| {
                store.configuration_log_head()
            })
            .await?
            .ok_or_else(|| anyhow::anyhow!("configuration checkpoint disappeared"))?;
            progressed = true;
        }
        if local.sequence < remote.sequence {
            return Ok(true);
        }
        ensure!(
            local == remote,
            "configuration service head conflicts with the saved checkpoint"
        );
        if let Some(migration) = access::run(store.clone(), "configuration migration", |store| {
            store.configuration_log_migration()
        })
        .await?
        {
            if let Some(receipt) = self.publish(&migration).await? {
                ensure!(
                    self.receive(store, receipt.head.sequence).await? == receipt,
                    "configuration receipt does not match the committed record"
                );
            }
            return Ok(true);
        }
        let pending = access::run(store.clone(), "configuration queue", |store| {
            store.queue_configuration_renewal()?;
            store.configuration_proposals()
        })
        .await?;
        for queued in pending {
            if let Some(receipt) = self
                .get::<Receipt>(&format!("operations/{}", queued.operation), 4096)
                .await?
            {
                let operation = queued.clone();
                let intent = access::run(store.clone(), "configuration retry", move |store| {
                    store.configuration_intent_for(&operation.origin, &operation.id)
                })
                .await?;
                ensure!(
                    receipt.operation == queued.operation && intent == Some(receipt.intent),
                    "configuration receipt has no matching durable intent"
                );
                ensure!(
                    self.receive(store.clone(), receipt.head.sequence).await? == receipt,
                    "configuration receipt does not match the committed record"
                );
            } else {
                let operation = queued.clone();
                if !access::run(store.clone(), "configuration authorization", move |store| {
                    store.validate_configuration_for(&operation)
                })
                .await?
                {
                    progressed = true;
                    continue;
                }
                let candidate =
                    access::run(store.clone(), "configuration proposal", move |store| {
                        store.prepare_configuration_for(&queued)
                    })
                    .await?;
                let Some(receipt) = self.publish(&candidate).await? else {
                    return Ok(true);
                };
                ensure!(
                    self.receive(store.clone(), receipt.head.sequence).await? == receipt,
                    "configuration receipt does not match the committed record"
                );
            }
            progressed = true;
        }
        Ok(progressed)
    }
}
