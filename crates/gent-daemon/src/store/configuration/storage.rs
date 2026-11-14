//! Keep immutable retry evidence and status fields, without another policy copy.
//! Call mutations inside the proposal/result or maintenance transaction.
use super::*;
use serde::{Deserialize, Serialize};
pub(in crate::store) mod handoff;

const CLEAN_BATCH: usize = 8;
const MAX_RECORDS: u64 = 65536;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_REASON_BYTES: usize = 1024;
// Includes JSON escaping of a rejection (up to six bytes per input byte).
const RESULT_RESERVE: usize = 8192;
const MAX_AGENT_RECORDS: u64 = 8192;
const MAX_PER_AGENT: u64 = 1024;
const MAX_AGENT_PENDING: u64 = 64;
const MAX_AGENT_BYTES: u64 = 16 * 1024 * 1024;

fn agent_usage(db: &Connection, administrator: &str) -> Result<(u64, u64, u64, u64)> {
    Ok(db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(json_extract(edit,'$.administrator')=?1),0),
        COALESCE(SUM(json_extract(edit,'$.administrator')=?1 AND result IS NULL),0),
        COALESCE(SUM(length(CAST(origin AS BLOB))+length(CAST(id AS BLOB))+length(CAST(writer AS BLOB))+
        length(CAST(fingerprint AS BLOB))+length(edit)+COALESCE(length(result),?2)),0)
        FROM configuration_edits WHERE CASE WHEN json_valid(edit) THEN json_extract(edit,'$.op') END IN ('agent_permissions','agent_permission_rules','agent_groups')",
        params![administrator, RESULT_RESERVE], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?)
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Summary {
    CreateGroup {
        name: String,
    },
    DeleteGroup {
        name: String,
    },
    GroupMembers {
        group: String,
        members: Vec<String>,
        action: gent_protocol::administration::GroupAction,
    },
    GrantGroupAdmin {
        grant_id: String,
    },
    RevokeGroupAdmin {
        grant_id: String,
    },
    AgentGroups {
        administrator: String,
        request_id: String,
        changes: Vec<gent_protocol::administration::GroupChange>,
    },
    Policy,
    Replace,
    RenameNode {
        name: String,
    },
    Renew,
    GrantRelay {
        grant_id: String,
    },
    RevokeRelay {
        grant_id: String,
    },
    GrantPermissionAdmin {
        grant_id: String,
    },
    RevokePermissionAdmin {
        grant_id: String,
    },
    AgentPermissions {
        administrator: String,
        request_id: String,
        changes: Vec<gent_protocol::administration::PermissionChange>,
    },
    AgentPermissionRules {
        administrator: String,
        request_id: String,
        changes: Vec<gent_protocol::administration::PermissionRuleChange>,
    },
}

impl From<&ConfigurationEdit> for Summary {
    fn from(edit: &ConfigurationEdit) -> Self {
        match edit {
            ConfigurationEdit::CreateGroup { name } => Self::CreateGroup { name: name.clone() },
            ConfigurationEdit::DeleteGroup { name } => Self::DeleteGroup { name: name.clone() },
            ConfigurationEdit::GroupMembers {
                group,
                members,
                action,
            } => Self::GroupMembers {
                group: group.clone(),
                members: members.clone(),
                action: *action,
            },
            ConfigurationEdit::GrantGroupAdmin { grant_id, .. } => Self::GrantGroupAdmin {
                grant_id: grant_id.clone(),
            },
            ConfigurationEdit::RevokeGroupAdmin { grant_id } => Self::RevokeGroupAdmin {
                grant_id: grant_id.clone(),
            },
            ConfigurationEdit::AgentGroups {
                administrator,
                request_id,
                changes,
            } => Self::AgentGroups {
                administrator: administrator.clone(),
                request_id: request_id.clone(),
                changes: changes.clone(),
            },
            ConfigurationEdit::Policy { .. } => Self::Policy,
            ConfigurationEdit::Replace { .. } => Self::Replace,
            ConfigurationEdit::RenameNode { name } => Self::RenameNode { name: name.clone() },
            ConfigurationEdit::Renew => Self::Renew,
            ConfigurationEdit::GrantRelay { grant_id, .. } => Self::GrantRelay {
                grant_id: grant_id.clone(),
            },
            ConfigurationEdit::RevokeRelay { grant_id } => Self::RevokeRelay {
                grant_id: grant_id.clone(),
            },
            ConfigurationEdit::GrantPermissionAdmin { grant_id, .. } => {
                Self::GrantPermissionAdmin {
                    grant_id: grant_id.clone(),
                }
            }
            ConfigurationEdit::RevokePermissionAdmin { grant_id } => Self::RevokePermissionAdmin {
                grant_id: grant_id.clone(),
            },
            ConfigurationEdit::AgentPermissions {
                administrator,
                request_id,
                changes,
            } => Self::AgentPermissions {
                administrator: administrator.clone(),
                request_id: request_id.clone(),
                changes: changes.clone(),
            },
            ConfigurationEdit::AgentPermissionRules {
                administrator,
                request_id,
                changes,
            } => Self::AgentPermissionRules {
                administrator: administrator.clone(),
                request_id: request_id.clone(),
                changes: changes.clone(),
            },
        }
    }
}

pub(super) fn schema(db: &Connection) -> Result<()> {
    let tx = db.unchecked_transaction()?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS configuration_edits(origin TEXT NOT NULL,id TEXT NOT NULL,writer TEXT NOT NULL,fingerprint TEXT NOT NULL,edit BLOB NOT NULL,result BLOB,PRIMARY KEY(origin,id));")?;
    let columns = tx
        .prepare("PRAGMA table_info(configuration_edits)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|c| c == "compact") {
        tx.execute_batch("ALTER TABLE configuration_edits ADD COLUMN compact INTEGER NOT NULL DEFAULT 0 CHECK(compact IN (0,1))")?;
    }
    tx.execute_batch(
        "CREATE INDEX IF NOT EXISTS configuration_edits_format ON configuration_edits(compact)",
    )?;
    pending::schema(&tx, 0)?;
    super::routing::schema(&tx, 0)?;
    tx.commit()?;
    Ok(())
}

struct Usage {
    records: u64,
    pending: u64,
    legacy: u64,
    bytes: u64,
    reserved: u64,
}

fn usage(db: &Connection) -> Result<Usage> {
    Ok(db.query_row("SELECT COUNT(*),COALESCE(SUM(result IS NULL),0),COALESCE(SUM(compact=0),0),
        COALESCE(SUM(length(CAST(origin AS BLOB))+length(CAST(id AS BLOB))+length(CAST(writer AS BLOB))+
        length(CAST(fingerprint AS BLOB))+length(edit)+COALESCE(length(result),0)),0)
        FROM configuration_edits", [], |r| {
        let pending: u64 = r.get(1)?;
        let bytes: u64 = r.get(3)?;
        Ok(Usage { records: r.get(0)?, pending, legacy: r.get(2)?, bytes,
            reserved: bytes.saturating_add(pending.saturating_mul(RESULT_RESERVE as u64)) })
    })?)
}

pub(in crate::store) fn status(db: &Connection) -> Result<Value> {
    let used = usage(db)?;
    let (agent_records, _, _, agent_bytes) = agent_usage(db, "")?;
    Ok(
        json!({"records":used.records,"pending":used.pending,"legacy_records":used.legacy,
        "stored_bytes":used.bytes,"reserved_bytes":used.reserved,"max_records":MAX_RECORDS,
        "max_reserved_bytes":MAX_BYTES,"pending_result_reservation_bytes":RESULT_RESERVE,
        "cleanup_batch_limit":CLEAN_BATCH,"pending_payloads":pending::status(db)?,"retired_inputs":super::routing::retired_status(db)?,"agent_administration":{"records":agent_records,"reserved_bytes":agent_bytes,
        "max_records":MAX_AGENT_RECORDS,"max_reserved_bytes":MAX_AGENT_BYTES,"max_records_per_agent":MAX_PER_AGENT,
        "max_pending_per_agent":MAX_AGENT_PENDING}}),
    )
}

pub(super) fn result_size(result: &[u8]) -> Result<()> {
    ensure!(
        result.len() <= RESULT_RESERVE,
        "configuration result exceeds reserved space"
    );
    Ok(())
}

pub(super) fn rejection_reason(mut reason: String) -> String {
    if reason.len() > MAX_REASON_BYTES {
        let mut end = MAX_REASON_BYTES;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        reason.truncate(end);
    }
    reason
}

pub(super) fn insert(
    db: &Connection,
    origin: &str,
    id: &str,
    writer: &str,
    fingerprint: &str,
    edit: &ConfigurationEdit,
    result: Option<&[u8]>,
) -> Result<()> {
    if let Some(result) = result {
        result_size(result)?;
    }
    let summary = serde_json::to_vec(&Summary::from(edit))?;
    clean(db, false)?;
    let used = usage(db)?;
    let bytes = [
        origin.len(),
        id.len(),
        writer.len(),
        fingerprint.len(),
        summary.len(),
        result.map_or(RESULT_RESERVE, <[u8]>::len),
    ]
    .into_iter()
    .fold(0u64, |total, size| total.saturating_add(size as u64));
    ensure!(
        used.records < MAX_RECORDS && used.reserved.saturating_add(bytes) <= MAX_BYTES,
        "configuration edit history quota exhausted; inspect gent history status; clean legacy bodies with gent history clean; retry records remain retained"
    );
    if let Some((administrator, _)) = administration::edit_identity(edit) {
        // Keep agent requests from consuming the owner history budget. Retained
        // audit records and retries cannot be evicted to admit new mutations.
        let (records, own, pending, reserved) = agent_usage(db, administrator)?;
        ensure!(
            records < MAX_AGENT_RECORDS
                && own < MAX_PER_AGENT
                && (result.is_some() || pending < MAX_AGENT_PENDING)
                && reserved.saturating_add(bytes) <= MAX_AGENT_BYTES,
            "agent administration history capacity exhausted; inspect gent history status"
        );
    }
    db.execute("INSERT INTO configuration_edits(origin,id,writer,fingerprint,edit,result,compact) VALUES(?1,?2,?3,?4,?5,?6,1)",
        params![origin,id,writer,fingerprint,summary,result])?;
    Ok(())
}

pub(in crate::store) fn clean(db: &Connection, dry_run: bool) -> Result<Value> {
    let rows = db.prepare("SELECT rowid,fingerprint,edit,origin,id,result IS NULL FROM configuration_edits WHERE compact=0 ORDER BY rowid LIMIT ?1")?
        .query_map([CLEAN_BATCH], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,bool>(5)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut removed = 0u64;
    for (row, expected, body, origin, id, is_pending) in &rows {
        let edit: ConfigurationEdit =
            serde_json::from_slice(body).context("invalid legacy configuration edit")?;
        // Rejected historical edits may be invalid policies. Verify their retry
        // identity without imposing today's admission rules on their contents.
        ensure!(
            fingerprint(&edit)? == *expected,
            "legacy configuration edit fingerprint mismatch"
        );
        let summary = serde_json::to_vec(&Summary::from(&edit))?;
        removed += body.len().saturating_sub(summary.len()) as u64;
        if !dry_run {
            if *is_pending {
                pending::retain(db, origin, id, &edit)?;
            }
            db.execute(
                "UPDATE configuration_edits SET edit=?1,compact=1 WHERE rowid=?2",
                params![summary, row],
            )?;
        }
    }
    let due: u64 = db.query_row(
        "SELECT COUNT(*) FROM configuration_edits WHERE compact=0",
        [],
        |r| r.get(0),
    )?;
    Ok(
        json!({"records_compacted":rows.len(),"body_bytes_removed":removed,
        "more_due":if dry_run {due.saturating_sub(rows.len() as u64)} else {due},"batch_limit":CLEAN_BATCH}),
    )
}

pub(super) fn describe(body: &[u8], compact: bool, status: &mut Value) -> Result<()> {
    let summary: Summary = if compact {
        serde_json::from_slice(body)?
    } else {
        Summary::from(&serde_json::from_slice::<ConfigurationEdit>(body)?)
    };
    match summary {
        Summary::RenameNode { name }
        | Summary::CreateGroup { name }
        | Summary::DeleteGroup { name } => status["name"] = name.into(),
        Summary::GroupMembers {
            group,
            members,
            action,
        } => {
            status["group"] = group.into();
            status["members"] = json!(members);
            status["action"] = json!(action);
        }
        Summary::AgentGroups {
            administrator,
            request_id,
            changes,
        } => {
            status["administrator"] = administrator.into();
            status["agent_request_id"] = request_id.into();
            status["changes"] = json!(changes);
            status["group_membership"] = true.into();
        }
        Summary::GrantGroupAdmin { grant_id }
        | Summary::RevokeGroupAdmin { grant_id }
        | Summary::GrantRelay { grant_id }
        | Summary::RevokeRelay { grant_id }
        | Summary::GrantPermissionAdmin { grant_id }
        | Summary::RevokePermissionAdmin { grant_id } => status["grant_id"] = grant_id.into(),
        Summary::AgentPermissions {
            administrator,
            request_id,
            changes,
        } => {
            status["administrator"] = administrator.into();
            status["agent_request_id"] = request_id.into();
            status["changes"] = json!(changes);
        }
        Summary::AgentPermissionRules {
            administrator,
            request_id,
            changes,
        } => {
            status["administrator"] = administrator.into();
            status["agent_request_id"] = request_id.into();
            status["changes"] = json!(changes);
            status["selector_rules"] = true.into();
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests;
