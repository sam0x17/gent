//! Display metadata and deterministic, permission-filtered name resolution.
use crate::Agent;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    #[serde(flatten)]
    pub agent: Agent,
    #[serde(default)]
    pub node_name: Option<String>,
    #[serde(default)]
    pub last_activity_at: Option<i64>,
    #[serde(default)]
    pub retired: bool,
}

#[derive(Serialize)]
pub struct Resolution {
    pub status: &'static str,
    pub reason: &'static str,
    pub selected: Option<Entry>,
    pub candidates: Vec<Entry>,
}

pub fn resolve(
    entries: Vec<Entry>,
    name: &str,
    node: Option<&str>,
    provider: Option<&str>,
) -> Resolution {
    let equal = |a: &str, b: &str| a.trim().to_lowercase() == b.trim().to_lowercase();
    let explicit_id = uuid::Uuid::parse_str(name).is_ok();
    let mut candidates: Vec<_> = entries
        .into_iter()
        .filter(|entry| {
            !entry.agent.revoked
                && !entry.retired
                && (entry.agent.id == name || (!explicit_id && equal(&entry.agent.name, name)))
                && node.is_none_or(|node| {
                    entry.agent.node_id == node
                        || entry
                            .node_name
                            .as_deref()
                            .is_some_and(|label| equal(label, node))
                })
                && provider.is_none_or(|provider| equal(&entry.agent.provider, provider))
        })
        .collect();
    candidates.sort_by(|a, b| {
        b.last_activity_at
            .cmp(&a.last_activity_at)
            .then_with(|| a.agent.id.cmp(&b.agent.id))
    });
    let (status, reason) = match candidates.as_slice() {
        [] => ("unavailable", "no_visible_exact_match"),
        [_] => ("selected", "unique_exact_match"),
        [first, second, ..]
            if candidates
                .iter()
                .all(|entry| entry.last_activity_at.is_some())
                && first.last_activity_at > second.last_activity_at =>
        {
            ("selected", "most_recent_activity")
        }
        _ => ("ambiguous", "activity_unknown_or_tied"),
    };
    let selected = (status == "selected").then(|| candidates[0].clone());
    Resolution {
        status,
        reason,
        selected,
        candidates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(id: &str, activity: Option<i64>) -> Entry {
        Entry {
            agent: Agent {
                id: id.into(),
                node_id: id.into(),
                name: "rtao".into(),
                provider: "codex".into(),
                last_seen: 999999,
                revoked: false,
            },
            node_name: Some(id.into()),
            last_activity_at: activity,
            retired: false,
        }
    }
    #[test]
    fn duplicate_names_use_conversation_activity_and_keep_unknowns_ambiguous() {
        let entries = vec![entry("older", Some(100)), entry("newer", Some(200))];
        assert_eq!(
            resolve(entries.clone(), "RTAO", None, None)
                .selected
                .unwrap()
                .agent
                .id,
            "newer"
        );
        assert_eq!(
            resolve(entries.clone(), "rtao", Some("older"), None)
                .selected
                .unwrap()
                .agent
                .id,
            "older"
        );
        assert_eq!(
            resolve(entries.clone(), "rta", None, None).status,
            "unavailable"
        );
        assert_eq!(
            resolve(entries, "rtao", None, Some("claude-code")).status,
            "unavailable"
        );
        assert_eq!(
            resolve(
                vec![entry("a", Some(100)), entry("b", None)],
                "rtao",
                None,
                None
            )
            .status,
            "ambiguous"
        );
        assert_eq!(
            resolve(
                vec![entry("a", Some(100)), entry("b", Some(100))],
                "rtao",
                None,
                None
            )
            .status,
            "ambiguous"
        );
        let mut retired = entry("retired", Some(999));
        retired.retired = true;
        assert_eq!(
            resolve(vec![entry("active", None), retired], "rtao", None, None)
                .selected
                .unwrap()
                .agent
                .id,
            "active"
        );
    }
}
