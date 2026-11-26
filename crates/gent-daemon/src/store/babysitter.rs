//! A provider failure is eligible once, after its backoff and before native input.
use super::*;
use gent_protocol::notifications::{Event, Failure, Notice, Scope};
use gent_protocol::wake::VERIFIED_BLOCKED_MAX_AGE_SECS;
use uuid::Uuid;

const ROUTINE_MAX_AGE_SECS: i64 = 2 * 60 * 60;
pub(super) enum Window {
    Routine,
    VerifiedBlocked,
}

impl Window {
    fn seconds(&self) -> i64 {
        match self {
            Self::Routine => ROUTINE_MAX_AGE_SECS,
            Self::VerifiedBlocked => VERIFIED_BLOCKED_MAX_AGE_SECS,
        }
    }
}

pub(super) fn schema(db: &Connection) -> Result<()> {
    let tx = rusqlite::Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS babysitter_preferences(
            agent TEXT PRIMARY KEY, enabled INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS babysitter_attempts(
            agent TEXT PRIMARY KEY, goal TEXT NOT NULL, turn TEXT NOT NULL,
            failed_at INTEGER NOT NULL, reason TEXT NOT NULL, delay INTEGER NOT NULL,
            due INTEGER NOT NULL, attempt TEXT, claimed_at INTEGER, submitted INTEGER NOT NULL DEFAULT 0
        );",
    )?;
    if !tx
        .prepare("SELECT 1 FROM pragma_table_info('babysitter_attempts') WHERE name='valid_until'")?
        .exists([])?
    {
        // Outstanding claims from older daemons keep the routine cutoff.
        tx.execute(
            "ALTER TABLE babysitter_attempts ADD COLUMN valid_until INTEGER",
            [],
        )?;
    }
    tx.commit()?;
    Ok(())
}
struct Previous {
    goal: String,
    turn: String,
    failed_at: i64,
    reason: String,
    delay: i64,
    claimed_at: Option<i64>,
}

fn delay(previous: i64, last: Option<i64>, failed: i64) -> i64 {
    if last.is_some_and(|t| failed >= t && failed - t <= 300) {
        (previous.saturating_mul(2)).clamp(15, 3600)
    } else {
        0
    }
}
impl StoreSession<'_> {
    fn enabled(&self, who: &Agent) -> Result<bool> {
        Ok(!self.home.join("babysitter-disabled").try_exists()? && self.babysitter_allowed(who)?)
    }
    pub(super) fn babysitter_allowed(&self, who: &Agent) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT COALESCE((SELECT enabled FROM babysitter_preferences WHERE agent=?1),1)",
            [&who.id],
            |r| r.get(0),
        )?)
    }
    pub(super) fn babysit(&self, who: &Agent, setting: Option<bool>) -> Result<Value> {
        if let Some(on) = setting {
            self.db.execute("INSERT INTO babysitter_preferences VALUES(?1,?2) ON CONFLICT(agent) DO UPDATE SET enabled=excluded.enabled",params![who.id,on])?;
            if !on {
                self.db.execute(
                    "UPDATE babysitter_chat_attempts SET cancelled=1 WHERE agent=?1",
                    [&who.id],
                )?;
                self.db.execute(
                    "UPDATE babysitter_attempts SET submitted=1 WHERE agent=?1",
                    [&who.id],
                )?;
            }
        }
        Ok(json!({"enabled":self.enabled(who)?}))
    }
    pub(super) fn babysitter_claim(
        &self,
        who: &Agent,
        goal: &str,
        turn: Uuid,
        failed: i64,
        reason: Failure,
        window: Window,
    ) -> Result<Value> {
        let no = json!({"claim":null});
        if !self.enabled(who)? || self.chat_claimed_turn(who, turn)? {
            return Ok(no);
        }
        ensure!(
            goal.len() == 64 && goal.bytes().all(|c| c.is_ascii_hexdigit()) && !turn.is_nil(),
            "invalid host failure identity"
        );
        let now = self.timestamp;
        if failed <= 0 || failed < now.saturating_sub(window.seconds()) || failed > now {
            return Ok(no);
        }
        let turn = turn.to_string();
        let reason = serde_json::to_string(&reason)?;
        let previous = self.db.query_row(
            "SELECT goal,turn,failed_at,delay,claimed_at,reason FROM babysitter_attempts WHERE agent=?1",
            [&who.id],
            |row| Ok(Previous {
                goal:row.get(0)?, turn:row.get(1)?, failed_at:row.get(2)?,
                delay:row.get(3)?, claimed_at:row.get(4)?, reason:row.get(5)?,
            }),
        ).optional()?;
        if let Some(p) = previous
            .as_ref()
            .filter(|p| p.goal == goal && p.turn == turn)
        {
            if p.failed_at != failed || p.reason != reason {
                return Ok(no);
            }
        } else {
            if previous.as_ref().is_some_and(|p| p.failed_at > failed) {
                return Ok(no);
            }
            let wait = previous
                .filter(|p| p.goal == goal)
                .map_or(0, |p| delay(p.delay, p.claimed_at, failed));
            self.db.execute(
                "INSERT OR REPLACE INTO babysitter_attempts(agent,goal,turn,failed_at,reason,delay,due)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![who.id,goal,turn,failed,reason,wait,failed.saturating_add(wait)],
            )?;
        }
        let id = Uuid::new_v4().to_string();
        let changed = self.db.execute(
            "UPDATE babysitter_attempts SET attempt=?2,claimed_at=?3,valid_until=?4
             WHERE agent=?1 AND attempt IS NULL AND submitted=0 AND due<=?3",
            params![who.id, id, now, failed.saturating_add(window.seconds())],
        )?;
        Ok(json!({"claim":(changed==1).then_some(id)}))
    }
    pub(super) fn babysitter_check(&self, who: &Agent, id: Uuid) -> Result<bool> {
        Ok(self.enabled(who)?
            && self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM babysitter_attempts WHERE agent=?1 AND attempt=?2
             AND submitted=0 AND claimed_at BETWEEN ?3-30 AND ?3
             AND failed_at BETWEEN ?3-?4 AND ?3 AND ?3<=COALESCE(valid_until,failed_at+?5))",
                params![
                    who.id,
                    id.to_string(),
                    self.timestamp,
                    VERIFIED_BLOCKED_MAX_AGE_SECS,
                    ROUTINE_MAX_AGE_SECS
                ],
                |r| r.get::<_, bool>(0),
            )?)
    }
    pub(super) fn babysitter_submitted(
        &self,
        who: &Agent,
        attempt: Uuid,
        scope: Option<Scope>,
    ) -> Result<Value> {
        let (submitted, reason): (bool, String) = self.db.query_row(
            "SELECT submitted,reason FROM babysitter_attempts WHERE agent=?1 AND attempt=?2",
            params![who.id, attempt.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if !submitted {
            self.enqueue_notice(
                &Notice {
                    id: attempt,
                    created_at: self.timestamp,
                    event: Event::GoalResumed {
                        chat: Uuid::parse_str(&who.id)?,
                        node: Uuid::parse_str(&who.node_id)?,
                        reason: serde_json::from_str(&reason)?,
                    },
                },
                scope,
            )?;
            self.db.execute(
                "UPDATE babysitter_attempts SET submitted=1 WHERE agent=?1",
                [&who.id],
            )?;
            self.db.execute(
                "UPDATE usage_tracking SET goal_submitted=goal_submitted+1 WHERE singleton=1",
                [],
            )?;
        }
        Ok(json!({"submitted":true}))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recurring_failures_back_off_from_the_last_submission() {
        let mut wait = 0;
        for expected in [15, 30, 60, 120, 240, 480, 960, 1920, 3600, 3600] {
            wait = delay(wait, Some(10000), 10005);
            assert_eq!(wait, expected)
        }
        assert_eq!(delay(wait, Some(10000), 10301), 0);
    }
}
