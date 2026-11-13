//! Signed membership and service cleanup intent share the owner transaction.
//! Service confirmation describes relay access only, never peer convergence.
use super::*;
use uuid::Uuid;

const MAX_REMOVALS: u64 = 8192;
const PAGE: usize = 100;

pub(crate) fn schema(db: &Connection, previous: i64) -> Result<()> {
    if previous >= 16 {
        ensure!(db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='node_removals')",
            [], |r| r.get::<_, bool>(0)
        )?, "node removal journal is missing; restore this node's state");
    } else {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS node_removals(
            node TEXT PRIMARY KEY CHECK(length(node)=36),
            cluster TEXT NOT NULL CHECK(length(cluster)=36),
            signing_key BLOB NOT NULL CHECK(length(signing_key)=32),
            revision INTEGER NOT NULL CHECK(revision>0),
            created_at INTEGER NOT NULL CHECK(created_at>0),
            service TEXT CHECK(length(service)<=4096),
            confirmed INTEGER NOT NULL DEFAULT 0 CHECK(confirmed IN (0,1)));
            CREATE INDEX IF NOT EXISTS node_removals_pending ON node_removals(confirmed,node);",
        )?;
    }
    Ok(())
}

fn identifier(id: &str) -> Result<()> {
    ensure!(
        Uuid::parse_str(id).is_ok_and(|u| !u.is_nil() && u.to_string() == id),
        "node ID must be a canonical UUID"
    );
    Ok(())
}

impl StoreSession<'_> {
    fn removal(&self, node: &str) -> Result<Value> {
        let (cluster, key, revision, created_at, service, confirmed):
            (String, Vec<u8>, u64, u64, Option<String>, bool) = self.db.query_row(
                "SELECT cluster,signing_key,revision,created_at,service,confirmed FROM node_removals WHERE node=?1",
                [node], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))
            ).optional()?.context("unknown node removal")?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid removed node key"))?;
        ensure!(
            cluster == self.config.cluster.id
                && revision <= self.state.checkpoint().revision
                && self.state.state().retired_nodes.contains(node)
                && self.state.state().retired_keys.contains(&key)
                && !self.state.state().nodes.contains_key(node),
            "node removal does not match signed membership"
        );
        let service: Option<config::ServiceConfig> =
            service.map(|s| serde_json::from_str(&s)).transpose()?;
        if let Some(pin) = &service {
            pin.validate()?;
        }
        Ok(
            json!({"node_id":node,"cluster_id":cluster,"signing_key":key,
            "revision":revision,"created_at":created_at,"service":service,
            "service_status":if service.is_none() { "not_configured" } else if confirmed { "confirmed" } else { "pending" },
            "membership_removed":true}),
        )
    }

    pub(super) fn remove_node(&mut self, node: &str) -> Result<Value> {
        self.identity.signing_owner()?;
        identifier(node)?;
        ensure!(
            node != self.identity.node.id(),
            "cannot remove the owner node; owner transfer is not implemented"
        );
        let exists: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM node_removals WHERE node=?1)",
            [node],
            |r| r.get(0),
        )?;
        if exists {
            return self.removal(node);
        }
        let member = self
            .state
            .state()
            .nodes
            .get(node)
            .context("unknown enrolled node")?;
        let key = member.signing_key;
        ensure!(
            self.db
                .query_row("SELECT COUNT(*) FROM node_removals", [], |r| r
                    .get::<_, u64>(0))?
                < MAX_REMOVALS,
            "node removal journal is full"
        );
        let disk = config::load_for_runtime(self.home)?;
        ensure!(
            disk.node.id == self.config.node.id
                && disk.cluster.id == self.config.cluster.id
                && disk.service == self.config.service,
            "node identity or service changed; restore the pinned configuration"
        );
        let service = self
            .config
            .service
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let update =
            self.state
                .revoke_node(self.identity.signing_owner()?, node, self.timestamp as u64)?;
        self.state = self.identity.apply(self.db, update)?;
        self.db.execute("INSERT INTO node_removals(node,cluster,signing_key,revision,created_at,service) VALUES(?1,?2,?3,?4,?5,?6)",
            params![node,self.config.cluster.id,key.as_slice(),self.state.checkpoint().revision,self.timestamp,service])?;
        let mut result = self.removal(node)?;
        result["applied"] = json!(true);
        Ok(result)
    }

    pub(super) fn node_removals(&self, after: Option<&str>, pending_only: bool) -> Result<Value> {
        self.identity.signing_owner()?;
        if let Some(id) = after {
            identifier(id)?;
        }
        let ids = self
            .db
            .prepare(
                "SELECT node FROM node_removals WHERE node>?1
            AND (?2=0 OR (service IS NOT NULL AND confirmed=0)) ORDER BY node LIMIT ?3",
            )?
            .query_map(params![after.unwrap_or(""), pending_only, PAGE + 1], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let next = if ids.len() > PAGE {
            ids.get(PAGE - 1).cloned()
        } else {
            None
        };
        let removals = ids
            .iter()
            .take(PAGE)
            .map(|id| self.removal(id))
            .collect::<Result<Vec<_>>>()?;
        Ok(json!({"removals":removals,"next":next,"limit":MAX_REMOVALS}))
    }

    pub(super) fn confirm_node_removal(&self, node: &str, revision: u64) -> Result<Value> {
        self.identity.signing_owner()?;
        identifier(node)?;
        let previous = self.removal(node)?;
        ensure!(
            previous["revision"] == revision && !previous["service"].is_null(),
            "node removal confirmation does not match its service intent"
        );
        self.db
            .execute("UPDATE node_removals SET confirmed=1 WHERE node=?1", [node])?;
        self.removal(node)
    }
}
