//! Carrier-local references. The portable board, including its revision, stays V9-readable.
use super::*;

use gent_protocol::dashboard::{HtmlProbe, HtmlProjection, MAX_HTML_BYTES};
use iroh::{EndpointAddr, EndpointId};

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS dashboard_html(
            agent TEXT PRIMARY KEY REFERENCES dashboards(agent) ON DELETE CASCADE,
            revision INTEGER NOT NULL, file TEXT NOT NULL REFERENCES file_objects(id) ON DELETE CASCADE,
            sha256 TEXT NOT NULL);
         CREATE TRIGGER IF NOT EXISTS dashboard_html_clear AFTER UPDATE ON dashboards
            BEGIN DELETE FROM dashboard_html WHERE agent=OLD.agent; END;"
    )?;
    Ok(())
}

impl StoreSession<'_> {
    pub(super) fn attach_board_html(&self, who: &Agent, revision: u64, id: &str) -> Result<()> {
        let (sha256, _) = self.board_html_file(who, id)?;
        self.db.execute(
            "INSERT INTO dashboard_html(agent,revision,file,sha256) VALUES(?1,?2,?3,?4)",
            params![who.id, revision, id, sha256],
        )?;
        Ok(())
    }

    pub(super) fn board_html_file(&self, who: &Agent, id: &str) -> Result<(String, String)> {
        self.require_local_membership()?;
        ensure!(
            !who.revoked && self.local_node(&who.node_id),
            "board unavailable"
        );
        self.require_web_lease(&who.node_id)?;
        let grant = self.accessible_file(who, id)?;
        let descriptor = grant.descriptor();
        ensure!(
            descriptor.media_type.eq_ignore_ascii_case("text/html")
                && (1..=MAX_HTML_BYTES as u64).contains(&descriptor.byte_length),
            "dashboard attachment requires a text/html file of 1–65536 bytes"
        );
        let bytes = self.objects()?.read(id)?;
        let html = std::str::from_utf8(&bytes).context("dashboard attachment requires UTF-8")?;
        Ok((descriptor.sha256.clone(), html.to_owned()))
    }
}

impl StoreSession<'_> {
    fn visible_board_chat(&self, probe: &HtmlProbe) -> Result<Agent> {
        let who = self.get_agent(&probe.agent.to_string())?;
        ensure!(!who.revoked && self.db.prepare_cached(
            "SELECT 1 FROM dashboards d WHERE agent=?1 AND revision=?2 AND body IS NOT NULL
             AND NOT EXISTS(SELECT 1 FROM hosted_dashboard_gates WHERE agent=d.agent)"
        )?.exists(params![who.id, probe.revision])?, "board unavailable");
        Ok(who)
    }

    fn html_projection(&self, probe: &HtmlProbe) -> Result<HtmlProjection> {
        let who = self.visible_board_chat(probe)?;
        ensure!(self.local_node(&who.node_id), "board unavailable");
        let (file, pin): (String, String) = self.db.query_row(
            "SELECT file,sha256 FROM dashboard_html WHERE agent=?1 AND revision=?2",
            params![who.id, probe.revision],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (sha256, html) = self.board_html_file(&who, &file)?;
        ensure!(sha256 == pin, "board attachment changed");
        Ok(HtmlProjection {
            agent: probe.agent,
            revision: probe.revision,
            static_html: (probe.known_sha256.as_ref() != Some(&sha256)).then_some(html),
            sha256,
            expires_at: self.objects()?.status(&file)?.expires_at,
        })
    }
}

impl Store {
    // Check again after network I/O. A stale replica, replacement carrier or
    // expired endpoint binding cannot authorize a response from the old route.
    pub(crate) fn board_target(
        &self,
        owner: &str,
        probes: &[HtmlProbe],
    ) -> Result<(EndpointAddr, [u8; 32])> {
        self.require_owner_credential(owner)?;
        ensure!(
            matches!(self.direct_settings()?.direct, config::Direct::Auto),
            "board transport unavailable"
        );
        let tx = self.db.unchecked_transaction()?;
        let mut s = self.network_session(&tx, self.identity.state(&tx)?);
        s.timestamp = requests::diagnostic_clock(&tx, now())?;
        let mut peers = BTreeSet::new();
        for probe in probes {
            let who = s.visible_board_chat(probe)?;
            peers.insert(s.state.transport_host(&who.node_id)?);
        }
        ensure!(peers.len() == 1, "expected one board carrier");
        let peer = peers.pop_first().unwrap();
        let Some(direct::NativeTarget::Advertised(address)) = s.native_target(peer)? else {
            anyhow::bail!("board carrier unavailable")
        };
        Ok((address, s.state.checkpoint().state_hash))
    }

    pub(crate) fn serve_board_html(
        &self,
        endpoint: EndpointId,
        checkpoint: [u8; 32],
        probes: &[HtmlProbe],
    ) -> Result<Vec<HtmlProjection>> {
        self.direct_allowed(endpoint)?;
        let tx = self.db.unchecked_transaction()?;
        let mut s = self.network_session(&tx, self.identity.state(&tx)?);
        s.timestamp = requests::diagnostic_clock(&tx, now())?;
        if s.state.checkpoint().state_hash != checkpoint {
            return Ok(Vec::new());
        }
        Ok(probes
            .iter()
            .filter_map(|probe| s.html_projection(probe).ok())
            .collect())
    }
}
