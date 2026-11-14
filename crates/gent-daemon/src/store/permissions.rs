use super::*;

impl StoreSession<'_> {
    fn permission_summary(&self, actor: &Agent, peer: &Agent) -> Value {
        json!({
            "actor":actor.id,"peer":peer.id,
            "policy":self.config.policy.relationship(actor,peer),
            "scope":"current policy only; actual operations recheck authority, exchanges, quotas, relay grants and delivery state",
            "reply_requires":"an accepted unexpired received message with remaining exchange capacity; relay messages use relay_respond"
        })
    }
    pub(super) fn permission_check(&self, actor: &Agent, peer: &str) -> Result<Value> {
        let peer = self.get_agent(peer)?;
        ensure!(self.config.policy.visible(actor, &peer), UNAVAILABLE);
        // No rule positions, selectors, group names, membership lists, other
        // agents, policy counts or cluster revision metadata enter the result.
        Ok(self.permission_summary(actor, &peer))
    }
    pub(super) fn permission_explain(&self, actor: &str, peer: &str) -> Result<Value> {
        let actor = self.get_agent(actor)?;
        let peer = self.get_agent(peer)?;
        let mut value = self.permission_summary(&actor, &peer);
        value["authority"] = json!({
            "revision":self.state.checkpoint().revision,
            "expires_at":self.state.state().expires_at,
            "fresh":self.state.require_fresh(self.timestamp as u64).is_ok()
        });
        let outgoing = self.config.policy.trace(&actor, &peer);
        let incoming = self.config.policy.trace(&peer, &actor);
        let indices: std::collections::BTreeSet<_> = outgoing
            .iter()
            .chain(&incoming)
            .flat_map(|t| t.matching_rules.iter().copied())
            .collect();
        value["traces"] = json!({"actor_to_peer":outgoing,"peer_to_actor":incoming});
        value["matching_rules"] = json!(
            indices
                .into_iter()
                .map(|index| json!({"index":index,"rule":self.config.policy.rules[index]}))
                .collect::<Vec<_>>()
        );
        value["revoked"] = json!({"actor":actor.revoked,"peer":peer.revoked});
        Ok(value)
    }
}
