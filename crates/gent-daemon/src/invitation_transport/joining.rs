//! Joining-side session orchestration. The caller owns the staged identity and
//! durable operation IDs. Cancellation discards session state, never rewinds it.
use super::{CLAIM_RECEIPT, Envelope, Mailbox, Side, fatal};
use crate::{
    config,
    store::{invitations::Invocation, now},
};
use anyhow::{Context, Result, ensure};
use gent_crypto::{
    NodeIdentity,
    invitation::{
        Invitation, SignedOffer,
        channel::{Channel, Initiator},
    },
};
use gent_protocol::Response;
use serde_json::Value;
use std::time::Duration;
use tokio::time::Instant;

const ATTEMPTS_PER_CALL: usize = 3;
const WAIT: Duration = Duration::from_secs(30);
struct Live {
    attempt: String,
    channel: Channel,
    next: u64,
    last_used: Instant,
}
pub struct Joining {
    invitation: Invitation,
    mailbox: Mailbox,
    identity: Option<(NodeIdentity, String)>,
    live: Option<Live>,
    wait: Duration,
}
impl Joining {
    pub fn new(invitation: Invitation, bearer: &str) -> Result<Self> {
        let mailbox = Mailbox::new(invitation.offer(), Side::Join, bearer)?;
        Ok(Self {
            invitation,
            mailbox,
            identity: None,
            live: None,
            wait: WAIT,
        })
    }
    pub fn offer(&self) -> &SignedOffer {
        self.invitation.offer()
    }

    /// The supplied identity must already be saved by the staged join engine.
    /// No new key is generated here, including after interrupted requests.
    pub fn prepare_node(&mut self, node: &NodeIdentity, name: &str) -> Result<()> {
        config::label(name)?;
        if let Some((previous, previous_name)) = &self.identity {
            ensure!(
                previous.id() == node.id()
                    && previous.public_key() == node.public_key()
                    && previous_name == name,
                "invitation joining identity changed"
            );
        } else {
            self.identity = Some((
                NodeIdentity::from_secret_bytes(node.id(), &node.expose_secret())?,
                name.into(),
            ));
        }
        Ok(())
    }

    async fn open(&self) -> Result<Live> {
        let (node, name) = self
            .identity
            .as_ref()
            .context("invitation identity was not prepared")?;
        let (initiator, hello) = Initiator::start(&self.invitation, now() as u64)?;
        let request = Envelope::Handshake(
            hello
                .noise
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid joining handshake"))?,
        );
        let Envelope::Handshake(reply) =
            exchange(&self.mailbox, &hello.attempt, 0, &request, self.wait).await?
        else {
            anyhow::bail!("invalid invitation handshake reply")
        };
        let (mut channel, claim) = initiator.finish(&reply, node, name, now() as u64)?;
        let Envelope::Frames(receipt) = exchange(
            &self.mailbox,
            &hello.attempt,
            1,
            &Envelope::Frames(claim),
            self.wait,
        )
        .await?
        else {
            anyhow::bail!("invalid invitation claim receipt")
        };
        ensure!(
            channel.open(&receipt, now() as u64)?.as_slice() == CLAIM_RECEIPT,
            "invalid invitation claim receipt"
        );
        Ok(Live {
            attempt: hello.attempt,
            channel,
            next: 2,
            last_used: Instant::now(),
        })
    }

    /// Reconnection retries this exact invocation. Persist its ID/input before
    /// calling; a new process must supply those same application-level retries.
    pub async fn invoke(&mut self, request: &Invocation) -> Result<Value> {
        ensure!(
            super::protocol::valid_attempt(&request.id),
            "invitation operation ID must be UUIDv4"
        );
        let bytes = request.encode()?;
        let mut last_error = None;
        for _ in 0..ATTEMPTS_PER_CALL {
            self.mailbox.check_time()?;
            // Taking ownership makes dropped futures safe even after a PUT or
            // local encrypt/decrypt operation has advanced a Noise counter.
            let live = self
                .live
                .take()
                .filter(|l| l.last_used.elapsed() < Duration::from_secs(20));
            let mut live = match live {
                Some(live) => live,
                None => match self.open().await {
                    Ok(live) => live,
                    Err(e) if fatal(&e) => return Err(e),
                    Err(e) => {
                        last_error = Some(e);
                        continue;
                    }
                },
            };
            let result = async {
                let outgoing = Envelope::Frames(live.channel.seal(&bytes, now() as u64)?);
                let Envelope::Frames(response) = exchange(
                    &self.mailbox,
                    &live.attempt,
                    live.next,
                    &outgoing,
                    self.wait,
                )
                .await?
                else {
                    anyhow::bail!("unexpected invitation response")
                };
                let plaintext = live.channel.open(&response, now() as u64)?;
                let response: Response = serde_json::from_slice(&plaintext)
                    .map_err(|_| anyhow::anyhow!("invalid encrypted invitation response"))?;
                live.next += 1;
                live.last_used = Instant::now();
                Ok::<_, anyhow::Error>(response)
            }
            .await;
            match result {
                Ok(response) => {
                    self.live = Some(live);
                    return match response {
                        Response::Ok(value) => Ok(value),
                        Response::Error(message) => anyhow::bail!(
                            "owner refused invitation operation: {}",
                            message.chars().take(1024).collect::<String>()
                        ),
                    };
                }
                Err(e) if fatal(&e) => return Err(e),
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("invitation session unavailable")))
    }
}

async fn exchange(
    mailbox: &Mailbox,
    attempt: &str,
    index: u64,
    outgoing: &Envelope,
    wait: Duration,
) -> Result<Envelope> {
    // timeout drops in-flight HTTP work. Callers discard the whole attempt on
    // uncertainty; the owner journal recovers committed application effects.
    tokio::time::timeout(wait, async {
        let mut uploaded = false;
        loop {
            mailbox.check_time()?;
            if !uploaded {
                match mailbox.put(attempt, index, outgoing).await {
                    Ok(()) => uploaded = true,
                    Err(e) if fatal(&e) => return Err(e),
                    Err(_) => {}
                }
            }
            if uploaded {
                let limit = if index == 0 {
                    57
                } else if index == 1 {
                    4096
                } else {
                    super::protocol::MAX_WIRE_BYTES
                };
                match mailbox.get_limit(attempt, index, limit).await {
                    Ok(Some(envelope)) => return Ok(envelope),
                    Ok(None) => {}
                    Err(e) if fatal(&e) || super::invalid_message(&e) => return Err(e),
                    Err(_) => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .context("invitation response timed out; owner must be online")?
}

#[cfg(test)]
impl Joining {
    pub(super) fn short_wait(&mut self) {
        self.wait = Duration::from_secs(3);
    }
}
