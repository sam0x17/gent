//! Local reports about host execution. These are not execution grants or proof
//! that external side effects happened exactly once.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkState {
    Started,
    Completed,
    Abandoned,
    RetryApproved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkResolution {
    Completed,
    Abandoned,
    RetryApproved,
}

impl From<WorkResolution> for WorkState {
    fn from(value: WorkResolution) -> Self {
        match value {
            WorkResolution::Completed => Self::Completed,
            WorkResolution::Abandoned => Self::Abandoned,
            WorkResolution::RetryApproved => Self::RetryApproved,
        }
    }
}
