//! Signed chat transport delegation preserves logical node and key identities.
use super::*;

impl ClusterState {
    pub(super) fn transport_host(&self, node: &str) -> Result<&str> {
        let (node, member) = self.nodes.get_key_value(node).context("node unavailable")?;
        let Some(parent) = &member.hosted_by else {
            return Ok(node);
        };
        ensure!(parent != node, "node cannot host itself");
        let (parent, host) = self
            .nodes
            .get_key_value(parent)
            .context("hosting parent unavailable")?;
        ensure!(host.hosted_by.is_none(), "hosting parent must be native");
        Ok(parent)
    }

    pub(super) fn require_no_hosted_children(&self, node: &str) -> Result<()> {
        ensure!(
            !self
                .nodes
                .values()
                .any(|member| member.hosted_by.as_deref() == Some(node)),
            "remove hosted children before removing or replacing their parent"
        );
        Ok(())
    }
}

pub(super) fn verify_step(previous: &ClusterState, next: &ClusterState) -> Result<()> {
    for (id, member) in &previous.nodes {
        if member.hosted_by.is_some()
            && let Some(replacement) = next.nodes.get(id)
        {
            ensure!(
                replacement.hosted_by.is_some(),
                "a hosted node cannot become a native node"
            );
        }
    }
    Ok(())
}

impl VerifiedState {
    /// Resolve a live logical node to its native transport host. This does not
    /// check freshness or authenticate the host's key.
    pub fn transport_host(&self, node: &str) -> Result<&str> {
        self.state().transport_host(node)
    }

    /// Check only the signed transport mapping. The caller must first use
    /// authorize_node on this same verified state to authenticate the carrier's
    /// exact node key and check freshness at the current wall-clock time.
    /// Hosting permits chat transport only, never configuration operations,
    /// and does not replace per-chat permission checks.
    pub fn authorize_chat_carrier(
        &self,
        logical_node: &str,
        authenticated_node: &str,
    ) -> Result<()> {
        ensure!(
            self.transport_host(logical_node)? == authenticated_node,
            "unauthorized chat carrier"
        );
        Ok(())
    }

    /// Assign a native parent using existing configuration signing authority.
    /// Repeating the same mapping is allowed and changes no configuration grants.
    pub fn host_node(
        &self,
        owner: &(impl peer::ConfigurationSigner + ?Sized),
        node_id: &str,
        parent: &str,
        now: u64,
    ) -> Result<SignedState> {
        self.require_fresh(now)?;
        self.revise(owner, now, |state| {
            let member = state.nodes.get_mut(node_id).context("node unavailable")?;
            member.hosted_by = Some(parent.into());
            // Validate every relationship: hosting a node that already hosts
            // children would otherwise introduce a chain indirectly.
            for node in state.nodes.keys() {
                state.transport_host(node)?;
            }
            Ok(())
        })
    }
}
