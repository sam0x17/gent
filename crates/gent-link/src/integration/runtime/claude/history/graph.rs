//! Resolve native ancestry independently of asynchronous JSONL write order.
//! Only identifiers and completion evidence are retained, never message text.
use anyhow::{Result, ensure};
use std::collections::{BTreeMap, VecDeque};

struct Node {
    parent: Option<String>,
    completion: Option<bool>,
    position: usize,
}

#[derive(Default)]
pub(super) struct Graph {
    nodes: BTreeMap<String, Node>,
}

impl Graph {
    pub(super) fn add(
        &mut self,
        id: &str,
        parent: Option<&str>,
        completion: Option<bool>,
        position: usize,
    ) -> Result<()> {
        ensure!(
            !self.nodes.contains_key(id),
            "native history has duplicate identities"
        );
        self.nodes.insert(
            id.into(),
            Node {
                parent: parent.map(str::to_owned),
                completion,
                position,
            },
        );
        Ok(())
    }

    pub(super) fn completed(
        &self,
        durations: &[(Option<String>, usize)],
        last_request: usize,
    ) -> Result<()> {
        let mut children = BTreeMap::<&str, Vec<&str>>::new();
        let mut ready = VecDeque::new();
        for (id, node) in &self.nodes {
            if let Some(parent) = &node.parent {
                ensure!(
                    self.nodes.contains_key(parent),
                    "native history parent is unavailable"
                );
                children.entry(parent).or_default().push(id);
            } else {
                ready.push_back(id.as_str());
            }
        }
        let mut nearest = BTreeMap::<&str, Option<&str>>::new();
        let mut latest = None;
        while let Some(id) = ready.pop_front() {
            let node = &self.nodes[id];
            let mut ancestor = node.parent.as_deref().and_then(|parent| nearest[parent]);
            if let Some(complete) = node.completion {
                ensure!(
                    ancestor == latest.map(|(id, _, _)| id),
                    "native history has an unresolved branch"
                );
                latest = Some((id, complete, node.position));
                ancestor = Some(id);
            }
            nearest.insert(id, ancestor);
            ready.extend(children.get(id).into_iter().flatten().copied());
        }
        ensure!(
            nearest.len() == self.nodes.len(),
            "native history contains a cycle"
        );
        ensure!(
            latest.is_some_and(|(id, ended, position)| ended
                && position > last_request
                && durations
                    .iter()
                    .any(|(parent, at)| parent.as_deref() == Some(id) && *at > position)),
            "native history has no completed final turn"
        );
        Ok(())
    }
}
