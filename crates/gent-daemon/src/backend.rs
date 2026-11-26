//! The two release channels share a hosted authority. Persist its stable origin
//! in identity records and resolve only the network destination for each role.
use crate::release_channel::{self, ReleaseChannel};
use anyhow::Result;
use reqwest::Url;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

pub const ACCOUNT: HostedOrigin = HostedOrigin {
    stable: "https://api.gent.link",
    beta: "https://beta-api.gent.link",
};
pub const RELAY: HostedOrigin = HostedOrigin {
    stable: "https://relay.gent.link",
    beta: "https://beta-relay.gent.link",
};
pub const MCP: HostedOrigin = HostedOrigin {
    stable: "https://mcp.gent.link",
    beta: "https://beta-mcp.gent.link",
};

#[derive(Clone, Copy)]
pub struct HostedOrigin {
    pub stable: &'static str,
    pub beta: &'static str,
}

impl HostedOrigin {
    pub fn contains(self, pin: &Url) -> bool {
        pin.as_str()
            .strip_suffix('/')
            .is_some_and(|s| s == self.stable || s == self.beta)
    }

    pub fn identity(self, pin: Url) -> Url {
        self.select(pin, ReleaseChannel::Stable)
    }

    fn select(self, pin: Url, channel: ReleaseChannel) -> Url {
        if !self.contains(&pin) {
            return pin;
        }
        let origin = match channel {
            ReleaseChannel::Stable => self.stable,
            ReleaseChannel::Beta => self.beta,
        };
        Url::parse(origin).expect("fixed HTTPS origin")
    }

    pub fn destination(self, home: &Path, pin: Url) -> Result<Url> {
        if self.contains(&pin) {
            Ok(self.select(pin, release_channel::current(home)?))
        } else {
            Ok(pin)
        }
    }

    /// A relay or bridge configured by a different account authority keeps
    /// its own pin, even if it happens to use a first-party transport hostname.
    pub fn transport(self, home: &Path, account: Option<&str>, pin: Url) -> Result<TransportRoute> {
        let managed = self.contains(&pin)
            && account
                .map(Url::parse)
                .transpose()?
                .is_some_and(|url| ACCOUNT.contains(&url));
        Ok(TransportRoute {
            role: self,
            pin,
            home: managed.then(|| home.to_owned()),
        })
    }
}

/// A long-lived native transport retains the configured pin. Only a verified
/// change to the cluster channel can move it between the fixed destinations.
#[derive(Clone)]
pub struct TransportRoute {
    role: HostedOrigin,
    pin: Url,
    home: Option<PathBuf>,
}

impl TransportRoute {
    /// Public identity stays fixed for clients with issuer- or URL-bound credentials.
    pub fn identity(&self) -> Url {
        if self.home.is_some() {
            self.role.identity(self.pin.clone())
        } else {
            self.pin.clone()
        }
    }

    pub fn destination(&self) -> Result<Url> {
        match &self.home {
            Some(home) => self.role.destination(home, self.pin.clone()),
            None => Ok(self.pin.clone()),
        }
    }

    pub async fn changed(&self, current: &Url) -> Url {
        if self.home.is_none() {
            return std::future::pending().await;
        }
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            if let Ok(next) = self.destination()
                && next != *current
            {
                return next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn existing_pins_follow_signed_changes_in_both_directions() -> Result<()> {
        use crate::{config, store::Store};
        use gent_protocol::{ConfigurationEdit, OwnerOp, Request, Response};

        let home = tempfile::tempdir()?;
        let home = &home.path().join("node");
        let stable = Url::parse(RELAY.stable)?;
        let beta = Url::parse(RELAY.beta)?;
        let managed = RELAY.transport(home, Some(ACCOUNT.stable), stable.clone())?;
        let staging = RELAY.transport(home, Some("https://staging.gent.link"), stable.clone())?;
        let custom = RELAY.transport(
            home,
            Some(ACCOUNT.stable),
            Url::parse("https://relay.example")?,
        )?;
        assert_eq!(managed.destination()?, stable);
        config::initialize(home, "test")?;
        let mut store = Store::open(home)?;
        let owner = config::read_private(&home.join("owner.key"))?;
        let mut previous = stable.clone();
        for (channel, expected) in [
            (ReleaseChannel::Beta, beta),
            (ReleaseChannel::Stable, stable.clone()),
        ] {
            let request = Request::Owner {
                credential: owner.clone(),
                action: OwnerOp::Configure {
                    request_id: uuid::Uuid::new_v4().to_string(),
                    edit: ConfigurationEdit::SetReleaseChannel { channel },
                },
            };
            assert!(matches!(store.handle(request), Response::Ok(_)));
            assert_eq!(managed.destination()?, expected);
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(20), managed.changed(&previous)).await?,
                expected
            );
            assert_eq!(staging.destination()?, stable);
            assert_eq!(custom.destination()?.host_str(), Some("relay.example"));
            previous = expected;
        }
        Ok(())
    }

    #[test]
    fn only_the_exact_pair_for_each_role_follows_the_channel() {
        for role in [ACCOUNT, RELAY, MCP] {
            for pin in [role.stable, role.beta].map(|s| Url::parse(s).unwrap()) {
                assert_eq!(
                    role.select(pin.clone(), ReleaseChannel::Stable)
                        .origin()
                        .ascii_serialization(),
                    role.stable
                );
                assert_eq!(
                    role.select(pin, ReleaseChannel::Beta)
                        .origin()
                        .ascii_serialization(),
                    role.beta
                );
            }
            for raw in [
                "https://staging.gent.link",
                "http://127.0.0.1:4000",
                "https://beta-api.gent.link.example",
                "https://api.gent.link:8443",
                "https://api.gent.link/path",
                "https://api.gent.link/?q",
                "https://user@api.gent.link",
                "http://api.gent.link",
            ] {
                let url = Url::parse(raw).unwrap();
                assert_eq!(role.select(url.clone(), ReleaseChannel::Beta), url);
            }
        }
        assert!(!ACCOUNT.contains(&Url::parse(RELAY.beta).unwrap()));
        assert!(!MCP.contains(&Url::parse(ACCOUNT.beta).unwrap()));
    }
}
