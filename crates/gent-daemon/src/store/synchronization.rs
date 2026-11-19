//! Read-only transport progress for the local owner; never claims peer delivery.
use super::*;

impl Store {
    pub(super) fn synchronization_status(&self) -> Result<Value> {
        let state = self.identity.state(&self.db)?;
        let timestamp = requests::diagnostic_clock(&self.db, now())?;
        let mut queued = 0u64;
        let mut query = self.db.prepare(
            "SELECT l.peer,l.peer_key,COUNT(e.id) FROM network_links l
             LEFT JOIN network_events e ON e.peer=l.peer GROUP BY l.peer,l.peer_key",
        )?;
        for row in query.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, u64>(2)?,
            ))
        })? {
            let (peer, key, count) = row?;
            let key = key.as_slice().try_into().context("invalid peer key")?;
            if state.authorize_node(&peer, &key, timestamp as u64).is_ok()
                && state.transport_host(&peer).is_ok_and(|host| host == peer)
            {
                queued = queued.saturating_add(count);
            }
        }
        Ok(self.sync_health.status(
            self.config.relay.is_some(),
            state.require_fresh(timestamp as u64).is_ok(),
            queued,
        ))
    }
}
