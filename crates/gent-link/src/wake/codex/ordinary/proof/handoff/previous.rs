//! Attribute a late command to the immediately preceding terminal turn.
use super::*;

pub(in crate::wake::codex::ordinary::proof) struct Previous {
    pub(super) turn: Uuid,
    first_start: i64,
    last_start: i64,
}

fn command(line: &[u8], thread: &str) -> Option<(Uuid, i64, i64)> {
    let row: Row = serde_json::from_slice(line).ok()?;
    let p = &row.payload;
    let owner = p.turn_id.as_deref()?;
    let id = Uuid::parse_str(owner).ok()?;
    let (start, end) = (p.started_at_ms?, p.completed_at_ms?);
    (start <= end && terminal_command(line, thread, id) && row.work(thread, owner))
        .then_some((id, start, end))
}

pub(in crate::wake::codex::ordinary::proof) fn observe(
    previous: &mut Option<Previous>,
    line: &[u8],
    failed: &Failed,
) -> bool {
    let Some((id, start, end)) = command(line, &failed.thread) else {
        return false;
    };
    if id == failed.turn || end.div_euclid(1000) < failed.ended {
        return false;
    }
    previous
        .get_or_insert(Previous {
            turn: id,
            first_start: start,
            last_start: start,
        })
        .include(id, start)
}

impl Previous {
    fn include(&mut self, id: Uuid, start: i64) -> bool {
        if self.turn != id {
            return false;
        }
        self.first_start = self.first_start.min(start);
        self.last_start = self.last_start.max(start);
        true
    }

    pub(in crate::wake::codex::ordinary::proof) fn belongs_to(
        &self,
        turn: Uuid,
        started: i64,
        ended: i64,
        child_started: i64,
    ) -> bool {
        self.turn == turn
            && started <= self.first_start.div_euclid(1000)
            && self.last_start.div_euclid(1000) <= ended
            && ended <= child_started
    }

    pub(super) fn confirm(
        mut self,
        rows: &mut ReverseLines<'_>,
        line: &mut Vec<u8>,
        failed: &Failed,
        deadline: Instant,
    ) -> Result<bool> {
        // Completions from this owner can also arrive between the two turns.
        let Some(p) = completion(rows, line, &failed.thread, self.turn, deadline, |line| {
            command(line, &failed.thread).is_some_and(|(id, start, end)| {
                end.div_euclid(1000) <= failed.started && self.include(id, start)
            })
        })?
        else {
            return Ok(false);
        };
        Ok(p.started_at
            .zip(p.completed_at)
            .is_some_and(|(start, end)| self.belongs_to(self.turn, start, end, failed.started)))
    }
}
