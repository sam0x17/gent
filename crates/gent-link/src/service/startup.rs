//! Report the user manager's startup boundary separately from unit enablement.
use super::{files::Platform, manager};
use anyhow::{Result, bail, ensure};
use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Trigger {
    Boot,
    Login,
    Disabled,
    Unknown,
}

#[derive(Serialize)]
pub(super) struct Startup {
    trigger: Trigger,
    linger: Option<bool>,
    error: Option<String>,
}

fn parse_linger(value: &[u8]) -> Result<bool> {
    match value {
        b"yes\n" | b"yes" => Ok(true),
        b"no\n" | b"no" => Ok(false),
        _ => bail!("loginctl did not report a recognized linger setting"),
    }
}

async fn linger(uid: u32) -> Result<bool> {
    let output = manager::output(
        "/usr/bin/loginctl",
        &[
            "show-user",
            &uid.to_string(),
            "--property=Linger",
            "--value",
        ],
        false,
    )
    .await?;
    ensure!(
        output.status.success(),
        "cannot inspect the user's linger setting"
    );
    parse_linger(&output.stdout)
}

fn classify(enabled: Option<bool>, platform: Platform, linger: Option<bool>) -> Trigger {
    match (enabled, platform, linger) {
        (Some(false), _, _) => Trigger::Disabled,
        (Some(true), Platform::Launchd, _) | (Some(true), Platform::Systemd, Some(false)) => {
            Trigger::Login
        }
        (Some(true), Platform::Systemd, Some(true)) => Trigger::Boot,
        _ => Trigger::Unknown,
    }
}

pub(super) async fn inspect(platform: Platform, uid: u32, enabled: Option<bool>) -> Startup {
    let (linger, error) = if platform == Platform::Systemd {
        match linger(uid).await {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error.to_string())),
        }
    } else {
        (None, None)
    };
    Startup {
        trigger: classify(enabled, platform, linger),
        linger,
        error,
    }
}

pub(super) async fn enable(uid: u32) -> Result<()> {
    if linger(uid).await? {
        return Ok(());
    }
    let output = manager::output(
        "/usr/bin/loginctl",
        &["--no-ask-password", "enable-linger", &uid.to_string()],
        true,
    )
    .await?;
    ensure!(
        output.status.success(),
        "cannot enable startup without login; an administrator can run `sudo loginctl enable-linger {uid}`, then retry `gent daemon install --linger`; this setting affects all services for this OS user"
    );
    ensure!(
        linger(uid).await?,
        "linger is still disabled after loginctl returned success"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_requires_both_unit_enablement_and_a_known_manager_boundary() {
        assert_eq!(
            classify(Some(true), Platform::Systemd, Some(true)),
            Trigger::Boot
        );
        assert_eq!(
            classify(Some(true), Platform::Systemd, Some(false)),
            Trigger::Login
        );
        assert_eq!(
            classify(Some(false), Platform::Systemd, Some(true)),
            Trigger::Disabled
        );
        assert_eq!(
            classify(None, Platform::Systemd, Some(true)),
            Trigger::Unknown
        );
        assert_eq!(
            classify(Some(true), Platform::Systemd, None),
            Trigger::Unknown
        );
        assert_eq!(
            classify(Some(true), Platform::Launchd, None),
            Trigger::Login
        );
        assert_eq!(
            classify(Some(false), Platform::Launchd, None),
            Trigger::Disabled
        );
    }

    #[test]
    fn missing_or_unrecognized_linger_output_cannot_claim_boot_startup() {
        assert!(parse_linger(b"yes\n").unwrap());
        assert!(!parse_linger(b"no\n").unwrap());
        for value in [
            b"".as_slice(),
            b"yes\nno\n",
            b"true\n",
            b"unknown\n",
            b" yes\n",
        ] {
            assert!(parse_linger(value).is_err());
        }
    }
}
