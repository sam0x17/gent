use super::{journal::Journal, *};
use gent_crypto::{NodeIdentity, invitation::SignedOffer};
use gent_daemon::{
    invitation_transport::joining::Joining,
    pairing::{self, Peer, ServiceRelay},
    store::invitations::{Action, Invocation},
};
use gent_protocol::PairingOp;

struct Remote {
    invitation: Option<Invitation>,
    offer: SignedOffer,
    client: Option<Joining>,
    journal: Journal,
    service: auth::Service,
    node: Option<NodeIdentity>,
    receipt_error: Option<String>,
}
impl Remote {
    async fn invoke(&mut self, request: &Invocation) -> Result<Value> {
        if self.client.is_none() {
            let invitation = self
                .invitation
                .as_ref()
                .context("invitation channel unavailable")?;
            invitation
                .offer()
                .verify(&self.offer.offer.anchor, auth::now()?)?;
            self.service
                .exchange_invitation(invitation, self.journal.bearer())
                .await?;
            let mut client = Joining::new(
                self.invitation.take().expect("invitation retained"),
                self.journal.bearer(),
            )?;
            let node = self
                .node
                .as_ref()
                .context("saved node identity was not prepared")?;
            client.prepare_node(
                node,
                &self
                    .journal
                    .node()
                    .context("missing saved node binding")?
                    .name,
            )?;
            self.client = Some(client);
        }
        let result = self
            .client
            .as_mut()
            .expect("channel opened")
            .invoke(request)
            .await?;
        if matches!(
            request.action,
            Action::Pair {
                action: PairingOp::Snapshot | PairingOp::Enroll { .. }
            }
        ) {
            let snapshot: pairing::Snapshot = serde_json::from_value(result.clone())?;
            ensure!(
                snapshot.anchor == self.offer.offer.anchor
                    && snapshot.writer == self.offer.offer.issuer_id
                    && snapshot.relay.is_none(),
                "invitation snapshot changed the pinned owner"
            );
            self.check_service(
                snapshot
                    .service
                    .as_ref()
                    .context("invitation snapshot is missing its service")?,
            )?;
        }
        self.journal.complete(request, &result)?;
        Ok(result)
    }
    async fn send(&mut self, action: Action) -> Result<Value> {
        if let Some(pending) = self.journal.pending() {
            let same = serde_jcs::to_vec(&pending.action)? == serde_jcs::to_vec(&action)?;
            let result = self.invoke(&pending).await?;
            if same {
                return Ok(result);
            }
        }
        let request = self.journal.reserve(action)?;
        self.invoke(&request).await
    }
    fn check_service(&self, service: &ServiceRelay) -> Result<()> {
        let binding = &self.offer.offer.service;
        ensure!(
            service.account.account_id == binding.account_id
                && auth::origin(&service.account.origin)? == auth::origin(&binding.account_origin)?
                && auth::origin(&service.relay_endpoint)? == auth::origin(&binding.relay_origin)?,
            "invitation service binding changed"
        );
        self.service.check_invitation_service(binding)
    }
}
impl Peer for Remote {
    async fn prepare_node(&mut self, node: &NodeIdentity, name: &str) -> Result<()> {
        self.journal.bind(node, name)?;
        self.node = Some(NodeIdentity::from_secret_bytes(
            node.id(),
            &node.expose_secret(),
        )?);
        Ok(())
    }
    async fn call(&mut self, action: PairingOp) -> Result<Value> {
        self.send(Action::Pair { action }).await
    }
    async fn published(&mut self, node: &NodeIdentity, name: &str) -> Result<()> {
        self.prepare_node(node, name).await?;
        if self.journal.receipt().is_none()
            && let Err(error) = self.send(Action::Finish).await
        {
            self.receipt_error = Some(error.to_string());
        }
        Ok(())
    }
    async fn prepare_service(&mut self, service: &ServiceRelay) -> Result<()> {
        self.check_service(service)?;
        self.service
            .require_cluster_owner(&self.offer.offer.anchor.cluster_id)
            .await
    }
    async fn provision_service(
        &mut self,
        runtime: &Path,
        home: &Path,
        service: &ServiceRelay,
    ) -> Result<()> {
        self.check_service(service)?;
        crate::cluster::provision_joined(runtime, home, &self.service, service).await
    }
}

pub async fn join(
    home: &Path,
    file: &Path,
    cluster: Option<&str>,
    name: &str,
    replace: bool,
) -> Result<Value> {
    let invitation = decode_file(file)?;
    let offer = invitation.offer().clone();
    ensure!(
        cluster.is_none_or(|cluster| cluster == offer.offer.anchor.cluster_id),
        "invitation belongs to a different cluster"
    );
    let home = managed_file::normalize(home)?;
    config::private_dir(&home)?;
    let service = auth::Service::open(&home).await?;
    service.check_invitation_service(&offer.offer.service)?;
    let journal = Journal::open(&home, &offer, name, &service.session_hash(), replace)?;
    let mut remote = Remote {
        invitation: Some(invitation),
        offer: offer.clone(),
        client: None,
        journal,
        service,
        node: None,
        receipt_error: None,
    };
    let mut result = pairing::join(
        &home,
        pairing::Options {
            cluster: &offer.offer.anchor.cluster_id,
            name,
            relay_endpoint: None,
        },
        &mut remote,
    )
    .await?;
    if let Some(receipt) = remote.journal.receipt() {
        result["invitation_receipt"] = receipt.clone();
    } else if let Some(error) = remote.receipt_error {
        // Configuration is committed. Receipt failure must not imply
        // this node can be discarded or initialized under a new key.
        let expired = auth::now()? >= offer.offer.expires_at;
        result["invitation_receipt_pending"] = json!(!expired);
        result["invitation_receipt_expired"] = json!(expired);
        result["invitation_receipt_error"] = json!(error);
        result["next"] = json!(if expired {
            "Node installed. The invitation expired before its completion receipt was saved. Run gent daemon install to use the installed node."
        } else {
            "Node installed. Rerun the same join command to retry its completion receipt before the invitation expires."
        });
    }
    Ok(result)
}
