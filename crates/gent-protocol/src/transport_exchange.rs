//! Bounded, versioned multiplexing of the existing idempotent mailbox operations.
use serde::{Deserialize, Serialize};
pub const VERSION: u8 = 1;
pub const MAX_OPERATIONS: usize = 16;
pub const MAX_BYTES: usize = 4 * 1024 * 1024;
pub const ROUTE: &str = "/v2/exchange";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body: String,
}
impl Operation {
    pub fn valid(&self) -> bool {
        let parts: Vec<_> = self.path.split('/').collect();
        if !(4..=6).contains(&parts.len())
            || !parts[0].is_empty()
            || parts[1..3] != ["v1", "mailboxes"]
        {
            return false;
        }
        let mailbox = parts[3];
        if mailbox.is_empty()
            || mailbox.len() > 384
            || !mailbox
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return false;
        }
        if self.method != "GET" && self.method != "PUT" {
            return false;
        }
        if self.method == "GET" && !self.body.is_empty() {
            return false;
        }
        let sequence = |s: &str| {
            s.parse::<u64>()
                .is_ok_and(|n| n <= (1 << 53) - 2 && n.to_string() == s)
        };
        match parts.len() {
            4 => self.method == "GET",
            5 => {
                sequence(parts[4])
                    || parts[4] == "checkpoint"
                    || (parts[4] == "state" && self.method == "GET")
                    || (parts[4] == "retire" && self.method == "PUT")
            }
            6 => parts[4] == "batch" && sequence(parts[5]),
            _ => false,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u8,
    pub operations: Vec<Operation>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultItem {
    pub status: u16,
    pub body: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u8,
    pub results: Vec<ResultItem>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exchange_cannot_route_outside_opaque_mailboxes() {
        for path in [
            "/v1/mailboxes/a/0",
            "/v1/mailboxes/a/batch/10",
            "/v1/mailboxes/a/checkpoint",
            "/v1/mailboxes/a/retire",
        ] {
            assert!(
                Operation {
                    method: "PUT".into(),
                    path: path.into(),
                    body: String::new()
                }
                .valid()
            );
        }
        for path in [
            "https://elsewhere/v1/mailboxes/a/0",
            "/v1/mailboxes/../0",
            "/v1/mailboxes/a/01",
            "/v1/mailboxes/a/0?other",
            "/v1/configuration/commits",
        ] {
            assert!(
                !Operation {
                    method: "PUT".into(),
                    path: path.into(),
                    body: String::new()
                }
                .valid()
            );
        }
    }
}
