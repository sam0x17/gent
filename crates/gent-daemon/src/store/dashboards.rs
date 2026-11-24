use super::*;
use crate::messages::{
    Event,
    dashboard::{display_board, encode_board, update_board},
    wire::DASHBOARD_VERSION,
};
use gent_protocol::dashboard::{Board, Kind};

pub(super) fn schema(db: &Connection) -> Result<()> {
    let tx = db.unchecked_transaction()?;
    let first_dashboard_schema = !tx.table_exists(None, "dashboards")?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS dashboards(agent TEXT PRIMARY KEY REFERENCES agents(id),revision INTEGER NOT NULL CHECK(revision>0),body TEXT,mutation TEXT);
    CREATE TABLE IF NOT EXISTS dashboard_sent(peer TEXT NOT NULL,agent TEXT NOT NULL, revision INTEGER NOT NULL,event TEXT NOT NULL,peer_key BLOB,PRIMARY KEY(peer,agent));
    CREATE TABLE IF NOT EXISTS hosted_dashboard_gates(agent TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,node TEXT NOT NULL,revision INTEGER NOT NULL);
    CREATE TRIGGER IF NOT EXISTS dashboard_forget_peer AFTER DELETE ON network_links BEGIN DELETE FROM dashboard_sent WHERE peer=OLD.peer;
        DELETE FROM metadata WHERE key='dashboard_discovery:' || OLD.peer; END;
    CREATE TRIGGER IF NOT EXISTS dashboard_forget_agent AFTER DELETE ON agents BEGIN DELETE FROM dashboard_sent WHERE agent=OLD.id; END;")?;
    if !tx
        .prepare("SELECT 1 FROM pragma_table_info('dashboard_sent') WHERE name='peer_key'")?
        .exists([])?
    {
        // Existing cursors have no proof of the recipient's current key.
        tx.execute("ALTER TABLE dashboard_sent ADD COLUMN peer_key BLOB", [])?;
        tx.execute(
            "UPDATE network_events SET retire_after=NULL,announcement=1
             WHERE id IN (SELECT event FROM dashboard_sent)",
            [],
        )?;
    }
    if first_dashboard_schema {
        // Established pre-V9 links can be completely idle when this receiver
        // upgrades. Discover their capabilities once, even with no local board.
        tx.execute_batch("INSERT OR IGNORE INTO presence_requests SELECT peer FROM network_links;
            INSERT OR REPLACE INTO metadata SELECT 'dashboard_discovery:' || peer,hex(peer_key) FROM network_links;")?;
    }
    tx.commit()?;
    Ok(())
}

impl StoreSession<'_> {
    fn board(&self, id: &str) -> Result<(u64, Option<Board>, Option<String>)> {
        let row = self
            .db
            .query_row(
                "SELECT revision,body,mutation FROM dashboards WHERE agent=?1",
                [id],
                |r| Ok((r.get(0)?, r.get::<_, Option<String>>(1)?, r.get(2)?)),
            )
            .optional()?;
        match row {
            None => Ok((0, None, None)),
            Some((revision, body, op)) => Ok((
                revision,
                body.map(|s| serde_json::from_str(&s)).transpose()?,
                op,
            )),
        }
    }
    pub(super) fn dashboard_get(&self, who: &Agent) -> Result<Value> {
        let (revision, board, _) = self.board(&who.id)?;
        Ok(json!({"revision":revision,"board":board.map(display_board)}))
    }
    pub(super) fn dashboard_mutate(&self, who: &Agent, mut op: AgentOp) -> Result<Value> {
        // A retry through an older daemon sees the same define fingerprint.
        if let AgentOp::DashboardDefine { board, .. } = &mut op {
            encode_board(board)?;
        }
        let (revision, previous, last) = self.board(&who.id)?;
        let mut fingerprint = hash(&serde_json::to_string(&op)?);
        if last.as_ref() == Some(&fingerprint) {
            return Ok(json!({"revision":revision}));
        }
        let (expected, next) = match op {
            AgentOp::DashboardDefine {
                expected_revision,
                board,
            } => (expected_revision, Some(board)),
            AgentOp::DashboardDelete { expected_revision } => (expected_revision, None),
            AgentOp::DashboardUpdate {
                expected_revision,
                mut values,
            } => {
                let board = update_board(
                    previous.context("define a dashboard before updating it")?,
                    &mut values,
                )?;
                fingerprint = hash(&serde_json::to_string(&AgentOp::DashboardUpdate {
                    expected_revision,
                    values,
                })?);
                if last.as_ref() == Some(&fingerprint) {
                    return Ok(json!({"revision":revision}));
                }
                (expected_revision, Some(board))
            }
            _ => unreachable!(),
        };
        ensure!(
            expected == revision,
            "dashboard revision conflict; read gent_dashboard_get"
        );
        let revision = revision.checked_add(1).context("revision exhausted")?;
        ensure!(
            revision <= MAX_REGISTRATION_GENERATION,
            "dashboard revision exhausted"
        );
        self.web_state_changed(&who.node_id)?;
        self.db.execute("INSERT INTO hosted_dashboard_gates SELECT ?1,node,revision FROM hosted_checkpoints
            WHERE node=?2 AND revision>durable ON CONFLICT(agent) DO UPDATE SET revision=excluded.revision",
            params![who.id,who.node_id])?;
        self.save_board(&who.id, revision, next.as_ref(), Some(&fingerprint))?;
        let peers = self
            .db
            .prepare("SELECT peer,peer_key FROM network_links")?
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (peer, key) in peers {
            if network::active_peer(&self.state, &peer, &key, self.timestamp).is_ok() {
                match self.wire_version(&peer)? {
                    v if v >= DASHBOARD_VERSION => self.dashboard_sync(&peer, &key)?,
                    1 => self.defer_dashboard_sync(&peer)?,
                    _ => {}
                }
            }
        }
        Ok(json!({"revision":revision}))
    }
    fn save_board(
        &self,
        agent: &str,
        revision: u64,
        board: Option<&Board>,
        mutation: Option<&str>,
    ) -> Result<()> {
        self.db.execute("INSERT INTO dashboards VALUES(?1,?2,?3,?4) ON CONFLICT(agent) DO UPDATE SET revision=excluded.revision,body=excluded.body,mutation=excluded.mutation",params![agent,revision,board.map(serde_json::to_string).transpose()?,mutation])?;
        Ok(())
    }
    pub(super) fn dashboard_receive(
        &self,
        agent: &str,
        revision: u64,
        board: Option<Board>,
    ) -> Result<()> {
        ensure!(
            (1..=MAX_REGISTRATION_GENERATION).contains(&revision),
            "invalid dashboard revision"
        );
        if let Some(b) = &board {
            b.validate().map_err(anyhow::Error::msg)?;
        }
        // A previous carrier can retain an edit which was never committed.
        // The caller verified the registration and the current remote carrier.
        if self
            .db
            .execute("DELETE FROM hosted_dashboard_gates WHERE agent=?1", [agent])?
            != 0
        {
            self.db
                .execute("DELETE FROM dashboards WHERE agent=?1", [agent])?;
            self.db
                .execute("DELETE FROM dashboard_sent WHERE agent=?1", [agent])?;
        }
        let (current, old, _) = self.board(agent)?;
        if revision > current {
            self.save_board(agent, revision, board.as_ref(), None)?;
        } else if revision == current {
            ensure!(old == board, "conflicting dashboard revision");
        }
        Ok(())
    }
    pub(super) fn dashboard_sync(&self, peer: &str, key: &[u8]) -> Result<()> {
        // Include hosted conversations whose current signed carrier is this node.
        let local: Vec<_> = self
            .state
            .state()
            .nodes
            .keys()
            .filter(|node| self.local_node(node))
            .collect();
        let mut query=self.db.prepare("SELECT d.agent,d.revision,d.body,
            EXISTS(SELECT 1 FROM network_events e WHERE e.id=s.event) AS pending FROM dashboards d
            JOIN agents a ON a.id=d.agent LEFT JOIN dashboard_sent s ON s.peer=?1 AND s.agent=d.agent
            WHERE a.node_id IN (SELECT value FROM json_each(?2)) AND a.revoked=0
            AND (s.peer_key IS NOT ?3 OR d.revision>s.revision)
            ORDER BY pending,d.agent LIMIT 9")?;
        let records = query
            .query_map(params![peer, serde_json::to_string(&local)?, key], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, bool>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (index, (id, revision, body, pending)) in records.into_iter().enumerate() {
            if index == 8 || pending {
                self.defer_dashboard_sync(peer)?;
                break;
            }
            let event = Event::Dashboard {
                agent: self.registration(&id)?,
                revision,
                board: body.map(|s| serde_json::from_str(&s)).transpose()?,
            };
            let event_id = uuid::Uuid::new_v4();
            // queue() also installs hosted durability gates. Its optional
            // work must not roll back the chat mutation or incoming proof.
            self.db.execute_batch("SAVEPOINT dashboard_event")?;
            if let Err(error) = self.queue(peer, event_id, event, None) {
                self.db
                    .execute_batch("ROLLBACK TO dashboard_event; RELEASE dashboard_event")?;
                if !error.is::<network::retention::QueueFull>() {
                    return Err(error);
                }
                self.defer_dashboard_sync(peer)?;
                break;
            }
            self.db.execute("INSERT INTO dashboard_sent(peer,agent,revision,event,peer_key) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(peer,agent) DO UPDATE SET revision=excluded.revision,event=excluded.event,peer_key=excluded.peer_key",params![peer,id,revision,event_id.to_string(),key])?;
            self.db.execute_batch("RELEASE dashboard_event")?;
        }
        Ok(())
    }

    fn defer_dashboard_sync(&self, peer: &str) -> Result<()> {
        // One durable request per peer. Presence honors the ordinary probe
        // interval and confirms the codec before retrying the latest boards.
        self.db
            .execute("INSERT OR IGNORE INTO presence_requests VALUES(?1)", [peer])?;
        Ok(())
    }
    pub(super) fn dashboards(&self, after: Option<&str>) -> Result<Value> {
        let members = self.state.state().nodes.keys().collect::<Vec<_>>();
        let mut query = self.db.prepare(
            "SELECT a.id,a.name,d.revision,d.body FROM dashboards d
            JOIN agents a ON a.id=d.agent WHERE d.body IS NOT NULL AND a.revoked=0
            AND a.node_id IN (SELECT value FROM json_each(?2)) AND a.id>?1
            AND NOT EXISTS(SELECT 1 FROM hosted_dashboard_gates g WHERE g.agent=a.id)
            ORDER BY a.id LIMIT 33",
        )?;
        let mut records = query.query(params![
            after.unwrap_or(""),
            serde_json::to_string(&members)?
        ])?;
        let mut rows = Vec::new();
        let mut next = None;
        while let Some(row) = records.next()? {
            if rows.len() == 32 {
                next = rows
                    .last()
                    .and_then(|r: &Value| r["agent"].as_str())
                    .map(str::to_owned);
                break;
            }
            let board = serde_json::from_str::<Board>(&row.get::<_, String>(3)?)?;
            rows.push(json!({"agent":row.get::<_,String>(0)?,"chat":row.get::<_,String>(1)?,"revision":row.get::<_,u64>(2)?,"board":display_board(board)}));
        }
        Ok(json!({"rows":rows,"next":next}))
    }
    pub(super) fn dashboard_click(
        &mut self,
        id: &str,
        expected: u64,
        key: &str,
        request_id: &str,
    ) -> Result<Value> {
        let (revision, board, _) = self.board(id)?;
        ensure!(
            revision == expected
                && !self.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM hosted_dashboard_gates WHERE agent=?1)",
                    [id],
                    |r| r.get::<_, bool>(0)
                )?,
            "dashboard changed; refresh before clicking"
        );
        let button = board
            .and_then(|b| {
                b.widgets
                    .into_iter()
                    .find(|w| w.id == key && w.kind == Kind::Button)
            })
            .context("button no longer available")?;
        let node = self.identity.node.id().to_string();
        self.db.execute("INSERT OR IGNORE INTO metadata VALUES('desktop_callback_credential',lower(hex(randomblob(32))))",[])?;
        let credential: String = self.db.query_row(
            "SELECT value FROM metadata WHERE key='desktop_callback_credential'",
            [],
            |r| r.get(0),
        )?;
        let sender = self.agent(
            &node,
            &credential,
            AgentOp::Register {
                name: "Gent Desktop".into(),
                provider: "desktop".into(),
            },
            files::ExportStep::Reserve,
        )?;
        let sender = self.get_agent(
            sender["agent"]["id"]
                .as_str()
                .context("desktop identity unavailable")?,
        )?;
        let text = format!(
            "Dashboard action {} ({key}) selected in Gent Desktop:\n{}",
            button.label,
            button.value.as_str().context("invalid button")?
        );
        self.send(
            &sender,
            id,
            request_id,
            text,
            vec![],
            SendContext::default(),
        )
    }
}
