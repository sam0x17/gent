//! Verify the provider block before an independent ordinary admission.
use super::*;
use std::time::Instant;

pub(in crate::wake::codex) fn confirm(
    rows: &mut ReverseLines<'_>,
    line: &mut Vec<u8>,
    snapshot: &Value,
    previous: &[Value],
    mut newer_start: i64,
    deadline: Instant,
    direct: &mut Vec<DirectInput>,
) -> Result<bool> {
    let goal: Goal = serde_json::from_value(snapshot.clone())?;
    // Outside the operator task, at precisely the boundary where the goal
    // retry would require an older terminal record.
    if !rows.previous(line)? {
        return Ok(false);
    }
    let boundary: Value = serde_json::from_slice(line)?;
    let p = &boundary["payload"];
    if boundary["type"] != "event_msg"
        || p["type"] != "thread_settings_applied"
        || p["thread_id"] != goal.thread_id
        || !p["thread_settings"].is_object()
    {
        return Ok(false);
    }
    let mut queue = queued_exec::Queue::default();
    let mut older: HashSet<_> = previous
        .iter()
        .filter_map(|turn| turn["id"].as_str())
        .collect();
    for turn in previous {
        let Some(times) = Completed::read(turn) else {
            return Ok(false);
        };
        if Instant::now() >= deadline
            || times.ended > newer_start
            || turn["rootTurnId"] != turn["id"]
            || !older.remove(times.id.as_str())
            || !rows.previous(line)?
        {
            return Ok(false);
        }
        let terminal: Record = serde_json::from_slice(line)?;
        if let Some(reason) = terminal_failure(turn) {
            if times.ended != goal.updated_at
                || times.started < goal.created_at
                || !queue.bound()
                || !terminal.matches_failure(
                    &goal.thread_id,
                    &Failed {
                        turn: turn.clone(),
                        reason,
                    },
                )
                || !provider_stop(rows, line, &goal, turn, true, true)?
            {
                return Ok(false);
            }
            direct.extend(queue.steers);
            return Ok(Instant::now() < deadline);
        }
        if turn["status"] != "completed"
            || turn.get("error") != Some(&Value::Null)
            || times.started < goal.updated_at
            || !terminal.completes_turn(&times.id, times.started, times.ended, None)
            || !queued::confirm(
                rows,
                line,
                &goal.thread_id,
                &times,
                queued::Source::Drained(&mut queue),
                Some(goal.updated_at),
                &older,
            )?
        {
            return Ok(false);
        }
        newer_start = times.started;
    }
    Ok(false)
}
