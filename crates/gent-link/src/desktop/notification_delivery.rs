//! One account inbox row at a time, delivered over the running GUI's private pipes.
use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

pub(crate) struct Destination(mpsc::Sender<Delivery>);

struct Delivery {
    banner: Value,
    attempt: Uuid,
    result: oneshot::Sender<bool>,
}

pub(crate) struct Deliveries {
    inbox: mpsc::Receiver<Delivery>,
    pending: Option<(Uuid, oneshot::Sender<bool>)>,
}

pub(crate) fn channel() -> (Destination, Deliveries) {
    let (sender, inbox) = mpsc::channel(1);
    (
        Destination(sender),
        Deliveries {
            inbox,
            pending: None,
        },
    )
}

impl Destination {
    pub(crate) async fn display(&self, id: Uuid, title: &str, body: String) -> Result<()> {
        let (result, reply) = oneshot::channel();
        // The OS request ID is stable on retry. A late GUI reply can acknowledge
        // only its own attempt, even if another attempt is displaying the same row.
        let attempt = Uuid::new_v4();
        let banner =
            json!({"notification": {"id":id, "title":title, "body":body, "attempt":attempt}});
        self.0
            .send(Delivery {
                banner,
                attempt,
                result,
            })
            .await?;
        ensure!(
            tokio::time::timeout(Duration::from_secs(135), reply).await??,
            "macOS did not accept the notification"
        );
        Ok(())
    }
}

impl Deliveries {
    pub(crate) async fn next(&mut self) -> Value {
        loop {
            // The supervisor owns the sender for its entire lifetime.
            let delivery = self.inbox.recv().await.expect("desktop watch is running");
            if !delivery.result.is_closed() {
                self.pending = Some((delivery.attempt, delivery.result));
                return delivery.banner;
            }
        }
    }

    pub(crate) fn receive(&mut self, line: &str) -> bool {
        #[derive(Deserialize)]
        #[serde(tag = "op", rename_all = "snake_case")]
        enum Reply {
            NotificationResult { attempt: Uuid, accepted: bool },
        }
        let Ok(Reply::NotificationResult { attempt, accepted }) = serde_json::from_str(line) else {
            return false;
        };
        if let Some((_, result)) = self.pending.take_if(|(expected, _)| *expected == attempt) {
            let _ = result.send(accepted);
        }
        true
    }
}
