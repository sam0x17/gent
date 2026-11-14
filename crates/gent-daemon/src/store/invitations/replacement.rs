use super::*;

impl Store {
    /// An unconsumed offer targets the current old key. After enrollment, only
    /// its durably claimed replacement (or an explicit continuation) can retry.
    pub(super) fn invitation_replacement(
        &self,
        record: &Record,
        state: &VerifiedState,
        timestamp: u64,
    ) -> Result<()> {
        let offer = &record.offer.offer;
        let Some(target) = &offer.replaces else {
            return Ok(());
        };
        if let Some(old) = state.state().nodes.get(&target.id) {
            ensure!(
                matches!(offer.purpose, Purpose::NewNode)
                    && old.signing_key == target.signing_key
                    && (!offer.can_configure || old.can_configure)
                    && record.history_floor.is_none()
                    && record
                        .claim
                        .as_ref()
                        .is_none_or(|node| !state.state().nodes.contains_key(&node.id)),
                "replacement invitation target or configuration privileges changed"
            );
        } else {
            let node = record
                .claim
                .as_ref()
                .or(match &offer.purpose {
                    Purpose::Continue { node } => Some(node),
                    Purpose::NewNode => None,
                })
                .context("replacement target was already retired by another enrollment")?;
            state.authorize_node(&node.id, &node.key, timestamp)?;
            ensure!(
                removals::replacement_target(&self.db, state, &node.id, &node.key)?.as_ref()
                    == Some(target),
                "replacement invitation differs from the committed replacement"
            );
            let member = &state.state().nodes[&node.id];
            ensure!(
                member.name == node.name && member.can_configure == offer.can_configure,
                "replacement invitation identity or configuration privileges changed"
            );
        }
        Ok(())
    }
}
