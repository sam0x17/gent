//! Native invitation mailbox transport. The caller supplies an independently
//! trusted signed offer; account-service responses cannot supply that trust.
//! This layer never advances Noise state. Retries send the same cached envelope.
use crate::{store::now, sync::bounded};
use anyhow::{Context, Result, ensure};
use gent_crypto::invitation::SignedOffer;
use gent_protocol::service::{self, invitations as protocol};
use protocol::Side;
use reqwest::{Client, StatusCode, Url, header};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;

pub mod wire;
use wire::Envelope;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    /// Join then owner, matching the service ledger. Availability hints only.
    pub next: [u64; 2],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listing {
    attempts: BTreeMap<String, Attempt>,
    expires_at: u64,
}

#[derive(Clone)]
pub struct Mailbox {
    client: Client,
    origin: Url,
    authorization: header::HeaderValue,
    invitation: String,
    side: Side,
    deadline: u64,
    clock: Arc<AtomicU64>,
}

impl Mailbox {
    /// `offer` must come from protected invitation transfer (join) or the local
    /// owner journal. Only a node transport bearer or invitation join bearer is
    /// accepted; an account login bearer must never be sent to the relay.
    pub fn new(offer: &SignedOffer, side: Side, bearer: &str) -> Result<Self> {
        let timestamp = now() as u64;
        offer.verify(&offer.offer.anchor, timestamp)?;
        let created = match side {
            Side::Owner => service::transport_created_at(bearer),
            Side::Join => protocol::credential_created_at(bearer),
        }
        .context("invalid invitation relay credential type")?;
        ensure!(
            created <= timestamp,
            "invitation credential is from the future"
        );
        let value = Zeroizing::new(format!("Bearer {bearer}"));
        let mut authorization = header::HeaderValue::from_str(&value)
            .map_err(|_| anyhow::anyhow!("invalid invitation relay credential"))?;
        authorization.set_sensitive(true);
        Ok(Self {
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(5))
                .build()?,
            origin: Url::parse(&offer.offer.service.relay_origin)?,
            authorization,
            invitation: offer.offer.id.clone(),
            side,
            deadline: offer.offer.expires_at,
            clock: Arc::new(AtomicU64::new(timestamp)),
        })
    }

    fn check_time(&self) -> Result<()> {
        let timestamp = now() as u64;
        let floor = self.clock.fetch_max(timestamp, Ordering::Relaxed);
        ensure!(
            timestamp >= floor && timestamp < self.deadline,
            "invitation expired or local clock moved backwards"
        );
        Ok(())
    }
    fn route(&self, suffix: &str) -> Result<Url> {
        self.check_time()?;
        Ok(self
            .origin
            .join(&format!("/v1/invitations/{}/{suffix}", self.invitation))?)
    }
    fn message_route(&self, attempt: &str, index: u64, side: Side) -> Result<Url> {
        ensure!(
            protocol::valid_attempt(attempt),
            "invalid invitation attempt ID"
        );
        ensure!(
            index < protocol::MAX_MESSAGES_PER_SIDE,
            "invitation sequence exhausted"
        );
        let side = match side {
            Side::Owner => "owner",
            Side::Join => "join",
        };
        self.route(&format!("{attempt}/{side}/{index}"))
    }
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        // Never include HTTP bodies, response headers, bearer values or URLs in
        // errors. The relay is untrusted and can reflect arbitrary input.
        let response = request
            .header(header::AUTHORIZATION, self.authorization.clone())
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("invitation relay request failed"))?;
        self.check_time()?;
        Ok(response)
    }
    pub async fn attempts(&self) -> Result<BTreeMap<String, Attempt>> {
        ensure!(
            self.side == Side::Owner,
            "only the owner may list invitation attempts"
        );
        let response = self.send(self.client.get(self.route("attempts")?)).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "invitation attempt listing failed ({})",
            response.status()
        );
        let bytes = bounded(response, 16 * 1024)
            .await
            .map_err(|_| anyhow::anyhow!("invalid invitation attempt listing"))?;
        self.check_time()?;
        let listing: Listing = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid invitation attempt listing"))?;
        ensure!(
            listing.expires_at == self.deadline && listing.attempts.len() <= protocol::MAX_ATTEMPTS,
            "invalid invitation attempt listing"
        );
        let mut messages = [0u64; 2];
        for (id, attempt) in &listing.attempts {
            ensure!(
                protocol::valid_attempt(id)
                    && attempt.next[0] > 0
                    && attempt
                        .next
                        .iter()
                        .all(|n| *n <= protocol::MAX_MESSAGES_PER_SIDE),
                "invalid invitation attempt position"
            );
            for (total, next) in messages.iter_mut().zip(attempt.next) {
                *total += next;
            }
        }
        ensure!(
            messages
                .iter()
                .all(|n| *n <= protocol::MAX_MESSAGES_PER_SIDE),
            "invalid invitation message totals"
        );
        Ok(listing.attempts)
    }
    /// Store own-direction bytes. Exact retry safety depends on retaining this
    /// envelope, rather than calling Channel::seal again for an uncertain PUT.
    pub async fn put(&self, attempt: &str, index: u64, envelope: &Envelope) -> Result<()> {
        let response = self
            .send(
                self.client
                    .put(self.message_route(attempt, index, self.side)?)
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(envelope.encode()?),
            )
            .await?;
        ensure!(
            response.status() == StatusCode::NO_CONTENT,
            "invitation upload failed ({})",
            response.status()
        );
        Ok(())
    }
    /// Fetch only the peer's direction. A missing entry is an availability hint,
    /// never an instruction to rewind a Noise counter or repeat a side effect.
    pub async fn get(&self, attempt: &str, index: u64) -> Result<Option<Envelope>> {
        let peer = match self.side {
            Side::Owner => Side::Join,
            Side::Join => Side::Owner,
        };
        let response = self
            .send(self.client.get(self.message_route(attempt, index, peer)?))
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure!(
            response.status() == StatusCode::OK,
            "invitation fetch failed ({})",
            response.status()
        );
        let bytes = bounded(response, protocol::MAX_WIRE_BYTES)
            .await
            .map_err(|_| anyhow::anyhow!("invalid invitation relay response"))?;
        self.check_time()?;
        Ok(Some(Envelope::decode(&bytes)?))
    }
}

#[cfg(test)]
mod tests;
