//! Directory metadata is separate from identity, replay records and message history.
use super::*;
use gent_protocol::directory::Entry;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS agent_activity(agent TEXT PRIMARY KEY REFERENCES agents(id),last_activity_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS directory_cleared(agent TEXT PRIMARY KEY REFERENCES agents(id));")?;
    Ok(())
}

pub(crate) fn remember_nodes(db: &Connection, state: &gent_crypto::ClusterState) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS directory_nodes(node TEXT PRIMARY KEY,name TEXT NOT NULL,revision INTEGER NOT NULL);")?;
    for (id, node) in &state.nodes {
        db.execute("INSERT INTO directory_nodes VALUES(?1,?2,?3) ON CONFLICT(node) DO UPDATE SET name=excluded.name,revision=excluded.revision WHERE excluded.revision>=directory_nodes.revision", params![id,node.name,state.revision])?;
    }
    Ok(())
}

pub(super) fn backfill_names(db: &Connection, state: &VerifiedState) -> Result<()> {
    let mut statement = db.prepare("SELECT state FROM authority_history ORDER BY revision")?;
    for row in statement.query_map([], |row| row.get::<_, Vec<u8>>(0))? {
        let signed = gent_crypto::SignedState::decode(&row?)?;
        signed.verified_checkpoint(state.anchor())?;
        remember_nodes(db, &signed.state)?;
    }
    remember_nodes(db, state.state())
}

impl StoreSession<'_> {
    pub(super) fn directory_entry(&self, agent: Agent) -> Result<Entry> {
        let node_name = self
            .state
            .state()
            .nodes
            .get(&agent.node_id)
            .map(|n| n.name.clone());
        let node_name = match node_name {
            Some(name) => Some(name),
            None => self
                .db
                .query_row(
                    "SELECT name FROM directory_nodes WHERE node=?1",
                    [&agent.node_id],
                    |r| r.get(0),
                )
                .optional()?,
        };
        Ok(Entry {
            last_activity_at: self.activity(&agent.id)?,
            retired: agent.revoked || !self.state.state().nodes.contains_key(&agent.node_id),
            agent,
            node_name,
        })
    }

    pub(super) fn directory(&self, who: Option<&Agent>) -> Result<Vec<Entry>> {
        let mut entries = Vec::new();
        for agent in self.all_agents()? {
            if who.is_some_and(|who| !self.config.policy.visible(who, &agent)) {
                continue;
            }
            let cleared: bool = self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM directory_cleared WHERE agent=?1)",
                [&agent.id],
                |r| r.get(0),
            )?;
            if !cleared {
                entries.push(self.directory_entry(agent)?);
            }
        }
        entries.sort_by(|a, b| {
            b.last_activity_at
                .cmp(&a.last_activity_at)
                .then_with(|| a.agent.id.cmp(&b.agent.id))
        });
        Ok(entries)
    }

    pub(super) fn resolve_agent(
        &self,
        who: Option<&Agent>,
        name: &str,
        node: Option<&str>,
        provider: Option<&str>,
    ) -> Result<Value> {
        config::label(name)?;
        Ok(serde_json::to_value(gent_protocol::directory::resolve(
            self.directory(who)?,
            name,
            node,
            provider,
        ))?)
    }

    pub(super) fn clear_retired_agents(&self, dry_run: bool) -> Result<Value> {
        let entries = self.directory(None)?;
        let retired: Vec<_> = entries.iter().filter(|entry| entry.retired).collect();
        if !dry_run {
            for entry in &retired {
                self.db.execute(
                    "INSERT OR IGNORE INTO directory_cleared VALUES(?1)",
                    [&entry.agent.id],
                )?;
            }
        }
        Ok(
            json!({"cleared":if dry_run {0} else {retired.len()},"eligible":retired.len(),"dry_run":dry_run,"scope":"local_directory","history_preserved":true}),
        )
    }

    pub(super) fn activity(&self, id: &str) -> Result<Option<i64>> {
        Ok(self
            .db
            .query_row(
                "SELECT last_activity_at FROM agent_activity WHERE agent=?1",
                [id],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub(super) fn save_activity(&self, id: &str, timestamp: i64) -> Result<bool> {
        ensure!(
            timestamp > 0 && timestamp <= self.timestamp.saturating_add(60),
            "invalid conversation activity timestamp"
        );
        Ok(self.db.execute("INSERT INTO agent_activity VALUES(?1,?2) ON CONFLICT(agent) DO UPDATE SET last_activity_at=excluded.last_activity_at WHERE excluded.last_activity_at>agent_activity.last_activity_at",params![id,timestamp])? > 0)
    }

    pub(super) fn observe_activity(&self, id: &str, timestamp: i64) -> Result<Value> {
        let agent = self.get_agent(id)?;
        ensure!(
            agent.node_id == self.identity.node.id() && !agent.revoked,
            "activity requires an active local agent"
        );
        if self.save_activity(id, timestamp)? {
            self.announce_activity(id)?;
        }
        Ok(json!({"last_activity_at":self.activity(id)?}))
    }
}
