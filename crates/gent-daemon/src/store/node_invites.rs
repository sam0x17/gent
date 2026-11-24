//! Named invitations requested by a local administrator on any configuration
//! node. Requests and private replies travel only over authenticated MLS links.
use super::*;
use crate::messages::Event;
use gent_crypto::invitation::Invitation;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    id: Uuid,
    origin: String,
    target: String,
    name: String,
    configure: bool,
    activate: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    spec: Spec,
    reply: Option<Value>,
}

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS node_invite_requests (
        origin TEXT NOT NULL,id TEXT NOT NULL,activate INTEGER NOT NULL,
        request TEXT NOT NULL CHECK(length(request)<=2048),
        response TEXT CHECK(length(response)<=262144),sent INTEGER NOT NULL DEFAULT 0,
        expires INTEGER NOT NULL,PRIMARY KEY(origin,id,activate));",
    )?;
    Ok(())
}

fn deadline(spec: &Spec, now: i64) -> Result<i64> {
    config::label(&spec.name)?;
    let issued =
        requests::issued(&spec.id.to_string()).context("node invitation request must be UUIDv7")?;
    let expiry = issued
        .checked_add(900)
        .context("invalid invitation deadline")?;
    ensure!(
        issued <= now + 60 && expiry > now,
        "node invitation request expired or is from the future"
    );
    Ok(expiry)
}

fn native_request(spec: &Spec) -> String {
    let mut bytes = *gent_crypto::scoped_id(
        b"gent/named-node-request/v1\0",
        &[spec.origin.as_bytes(), spec.id.as_bytes()],
    )
    .as_bytes();
    bytes[..6].copy_from_slice(&spec.id.as_bytes()[..6]);
    bytes[6] = (bytes[6] & 15) | 0x70;
    bytes[8] = (bytes[8] & 63) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}

impl StoreSession<'_> {
    fn invitation_writer(&self) -> Result<String> {
        if self.identity.can_administer(&self.state) {
            Ok(self.identity.node.id().into())
        } else {
            self.configuration_writer()
        }
    }
    fn authorize_inviter(&self, origin: &str) -> Result<()> {
        let node = self
            .state
            .state()
            .nodes
            .get(origin)
            .context("inviting node is not enrolled")?;
        self.state
            .authorize_node(origin, &node.signing_key, self.timestamp as u64)?;
        ensure!(
            origin == self.invitation_writer()? || node.can_configure,
            "this node cannot add other nodes"
        );
        Ok(())
    }

    fn save_node_invite(&self, spec: &Spec) -> Result<()> {
        let expires = deadline(spec, self.timestamp)?;
        self.authorize_inviter(&spec.origin)?;
        ensure!(
            spec.target == self.invitation_writer()?,
            "invitation signing owner changed"
        );
        self.db.execute(
            "DELETE FROM node_invite_requests WHERE expires<=?1",
            [self.timestamp],
        )?;
        let encoded = serde_json::to_string(spec)?;
        self.db.execute("INSERT INTO node_invite_requests(origin,id,activate,request,expires) SELECT ?1,?2,?3,?4,?5 WHERE (SELECT COUNT(*) FROM node_invite_requests)<128 ON CONFLICT DO NOTHING", params![spec.origin,spec.id.to_string(),spec.activate,encoded,expires])?;
        let saved: String = self.db.query_row("SELECT request FROM node_invite_requests WHERE origin=?1 AND id=?2 AND activate=?3", params![spec.origin,spec.id.to_string(),spec.activate], |r| r.get(0)).optional()?.context("node invitation request capacity reached")?;
        ensure!(saved == encoded, "node invitation request options changed");
        Ok(())
    }

    fn send_node_invite(&self, spec: &Spec, reply: Option<Value>) -> Result<()> {
        let response = reply.is_some();
        let target = if response { &spec.origin } else { &spec.target };
        let event = gent_crypto::scoped_id(
            b"gent/node-invite-event/v1\0",
            &[
                spec.origin.as_bytes(),
                spec.target.as_bytes(),
                spec.id.as_bytes(),
                &[spec.activate as u8, response as u8],
            ],
        );
        self.queue(
            target,
            event,
            Event::NodeInvite {
                envelope: Box::new(Envelope {
                    spec: spec.clone(),
                    reply,
                }),
            },
            None,
        )
    }

    pub(super) fn request_node_invite(
        &self,
        id: &str,
        name: &str,
        configure: bool,
        activate: bool,
    ) -> Result<Value> {
        if !self
            .state
            .state()
            .nodes
            .values()
            .any(|member| member.name == name)
        {
            require_pro(self.home, &self.config, "Inviting another node")?;
        }
        let spec = Spec {
            id: Uuid::parse_str(id).context("invalid node invitation request ID")?,
            origin: self.identity.node.id().into(),
            target: self.invitation_writer()?,
            name: name.into(),
            configure,
            activate,
        };
        self.save_node_invite(&spec)?;
        let response: Option<String> = self.db.query_row(
            "SELECT response FROM node_invite_requests WHERE origin=?1 AND id=?2 AND activate=?3",
            params![spec.origin, id, activate],
            |r| r.get(0),
        )?;
        if let Some(response) = response {
            return Ok(serde_json::from_str(&response)?);
        }
        if spec.origin != spec.target {
            self.send_node_invite(&spec, None)?;
        }
        Ok(json!({"state":"pending"}))
    }

    pub(super) fn receive_node_invite(&self, peer: &str, envelope: Envelope) -> Result<()> {
        let spec = envelope.spec;
        deadline(&spec, self.timestamp)?;
        self.authorize_inviter(&spec.origin)?;
        ensure!(
            spec.target == self.invitation_writer()?,
            "invitation writer changed"
        );
        if let Some(reply) = envelope.reply {
            ensure!(
                peer == spec.target && spec.origin == self.identity.node.id(),
                "unexpected invitation reply"
            );
            let expected: String = self.db.query_row("SELECT request FROM node_invite_requests WHERE origin=?1 AND id=?2 AND activate=?3", params![spec.origin,spec.id.to_string(),spec.activate], |r| r.get(0))?;
            ensure!(
                expected == serde_json::to_string(&spec)?,
                "invitation reply options changed"
            );
            let encoded = serde_json::to_string(&reply)?;
            ensure!(encoded.len() <= 262144, "invitation reply too large");
            if let Some(private) = reply["private_invitation"].as_str() {
                let invitation = Invitation::decode(&STANDARD.decode(private)?)?;
                invitation
                    .offer()
                    .verify_current(&self.state, self.timestamp as u64)?;
                ensure!(
                    matches!(&invitation.offer().offer.purpose, gent_crypto::invitation::Purpose::NamedNode { name, .. } if name == &spec.name)
                        && invitation.offer().offer.can_configure == spec.configure
                        && invitation.offer().offer.issuer_id == peer,
                    "invitation reply changed its signed authority"
                );
            } else {
                ensure!(
                    reply["error"].as_str().is_some_and(|e| e.len() <= 256),
                    "invalid invitation reply"
                );
            }
            let old: Option<String> = self.db.query_row("SELECT response FROM node_invite_requests WHERE origin=?1 AND id=?2 AND activate=?3", params![spec.origin,spec.id.to_string(),spec.activate], |r| r.get(0))?;
            ensure!(
                old.is_none_or(|old| old == encoded),
                "invitation reply changed"
            );
            self.db.execute("UPDATE node_invite_requests SET response=?4,sent=1 WHERE origin=?1 AND id=?2 AND activate=?3", params![spec.origin,spec.id.to_string(),spec.activate,encoded])?;
        } else {
            ensure!(
                peer == spec.origin && spec.target == self.identity.node.id(),
                "unexpected invitation request"
            );
            self.save_node_invite(&spec)?;
        }
        Ok(())
    }
}

impl Store {
    pub(super) fn process_node_invites(&mut self) -> Result<()> {
        let timestamp = now();
        self.db.execute(
            "DELETE FROM node_invite_requests WHERE expires<=?1",
            [timestamp],
        )?;
        if !self
            .identity
            .can_administer(&self.identity.state(&self.db)?)
        {
            return Ok(());
        }
        let rows = self.db.prepare("SELECT request,response FROM node_invite_requests WHERE sent=0 ORDER BY rowid LIMIT 8")?.query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut failure = None;
        for (encoded, saved) in rows {
            let spec: Spec = serde_json::from_str(&encoded)?;
            let state = self.identity.state(&self.db)?;
            let session = StoreSession {
                db: &self.db,
                home: &self.home,
                config: self.config.clone(),
                identity: &self.identity,
                state,
                timestamp,
            };
            if deadline(&spec, timestamp).is_err()
                || session.authorize_inviter(&spec.origin).is_err()
                || spec.target != session.invitation_writer()?
            {
                continue;
            }
            let reply = if let Some(saved) = saved {
                serde_json::from_str(&saved)?
            } else {
                let result = (|| -> Result<Value> {
                    let bytes = self.create_invitation_at(
                        &native_request(&spec),
                        spec.configure,
                        None,
                        None,
                        Some((&spec.name, &spec.origin)),
                        timestamp as u64,
                    )?;
                    if spec.activate {
                        let invitation = Invitation::decode(&bytes)?;
                        let credential = config::read_private(&self.home.join("owner.key"))?;
                        self.activate_invitation(&credential, &invitation.offer().offer.id)?;
                    }
                    Ok(
                        json!({"private_invitation":STANDARD.encode(bytes.as_slice()),"active":spec.activate}),
                    )
                })();
                match result {
                    Ok(value) => value,
                    Err(error) => {
                        failure.get_or_insert(error);
                        continue;
                    }
                }
            };
            let tx = self.db.unchecked_transaction()?;
            let session = StoreSession {
                db: &tx,
                home: &self.home,
                config: self.config.clone(),
                identity: &self.identity,
                state: self.identity.state(&tx)?,
                timestamp: now(),
            };
            session.authorize_inviter(&spec.origin)?;
            if spec.origin != spec.target {
                session.send_node_invite(&spec, Some(reply.clone()))?;
            }
            tx.execute("UPDATE node_invite_requests SET response=?4,sent=1 WHERE origin=?1 AND id=?2 AND activate=?3", params![spec.origin,spec.id.to_string(),spec.activate,serde_json::to_string(&reply)?])?;
            tx.commit()?;
            self.sync_wakeup.notify_one();
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }
}
