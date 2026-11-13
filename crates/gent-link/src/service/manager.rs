use super::files::Platform;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    path::Path,
    process::{Output, Stdio},
    time::Duration,
};
use tokio::process::Command;

#[derive(Default, Serialize)]
pub struct State {
    pub available: bool,
    pub loaded: bool,
    pub running: bool,
    pub enabled: bool,
    pub pid: Option<u32>,
    pub state: String,
    pub last_exit: Option<i32>,
    pub error: Option<String>,
    pub domain: Option<String>,
    #[serde(skip)]
    pub domains: Vec<String>,
}
pub async fn output(program: &str, args: &[&str], quiet: bool) -> Result<Output> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command.stdout(if quiet { Stdio::null() } else { Stdio::piped() });
    tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .with_context(|| format!("{program} timed out"))?
        .with_context(|| format!("cannot run {program}"))
}
async fn run(program: &str, args: &[&str]) -> Result<()> {
    let result = output(program, args, true).await?;
    ensure!(
        result.status.success(),
        "{program} {} failed: {}",
        args.first().unwrap_or(&""),
        String::from_utf8_lossy(&result.stderr)
            .chars()
            .take(4096)
            .collect::<String>()
            .trim()
    );
    Ok(())
}
pub async fn uid() -> Result<u32> {
    let result = output("/usr/bin/id", &["-u"], false).await?;
    ensure!(result.status.success(), "cannot determine current user");
    Ok(std::str::from_utf8(&result.stdout)?.trim().parse()?)
}
pub struct Manager {
    pub platform: Platform,
    pub uid: u32,
    pub label: String,
}
impl Manager {
    fn unit(&self) -> String {
        format!("{}.service", self.label)
    }
    pub async fn inspect(&self) -> State {
        match self.inspect_inner().await {
            Ok(state) => state,
            Err(error) => State {
                state: "unavailable".into(),
                error: Some(error.to_string()),
                ..Default::default()
            },
        }
    }
    async fn inspect_inner(&self) -> Result<State> {
        match self.platform {
            Platform::Systemd => {
                let probe = output(
                    "/usr/bin/systemctl",
                    &["--user", "show", "--property=Version", "--value"],
                    true,
                )
                .await?;
                ensure!(
                    probe.status.success(),
                    "systemd user manager is unavailable; use a user login session or gent daemon run"
                );
                let result=output("/usr/bin/systemctl",&["--user","show",&self.unit(),"--no-pager","--property=LoadState,ActiveState,SubState,MainPID,UnitFileState,ExecMainStatus"],false).await?;
                let text = String::from_utf8(result.stdout)?;
                ensure!(
                    text.lines().any(|s| s.starts_with("LoadState=")),
                    "cannot inspect Gent's systemd unit"
                );
                Ok(parse_systemd(&text))
            }
            Platform::Launchd => {
                let mut state = State {
                    state: "not_loaded".into(),
                    ..Default::default()
                };
                for domain in [format!("gui/{}", self.uid), format!("user/{}", self.uid)] {
                    if !output("/bin/launchctl", &["print", &domain], true)
                        .await?
                        .status
                        .success()
                    {
                        continue;
                    }
                    state.available = true;
                    if state.domain.is_none() {
                        state.domain = Some(domain.clone());
                    }
                    let target = format!("{domain}/{}", self.label);
                    let result = output("/bin/launchctl", &["print", &target], false).await?;
                    if result.status.success() {
                        let parsed = parse_launchd(&String::from_utf8(result.stdout)?);
                        state.domains.push(domain.clone());
                        state.loaded = true;
                        if parsed.pid.is_some() || state.pid.is_none() {
                            state.pid = parsed.pid;
                            state.running = parsed.running;
                            state.state = parsed.state;
                            state.last_exit = parsed.last_exit;
                            state.domain = Some(domain);
                        }
                    }
                }
                ensure!(
                    state.available,
                    "launchd user domain is unavailable; use a user login session or gent daemon run"
                );
                let domain = state.domain.as_deref().unwrap();
                let result = output("/bin/launchctl", &["print-disabled", domain], false).await?;
                ensure!(result.status.success(), "cannot inspect launchd enablement");
                let line = format!("\"{}\" => true", self.label);
                state.enabled = !String::from_utf8(result.stdout)?
                    .lines()
                    .any(|s| s.trim().trim_end_matches(',') == line);
                Ok(state)
            }
        }
    }
    pub async fn install(&self, path: &Path, changed: bool, before: &State) -> Result<()> {
        match self.platform {
            Platform::Systemd => {
                run("/usr/bin/systemctl", &["--user", "daemon-reload"]).await?;
                run(
                    "/usr/bin/systemctl",
                    &[
                        "--user",
                        "enable",
                        "--now",
                        path.to_str().context("service path is not UTF-8")?,
                    ],
                )
                .await?;
                if changed && before.running {
                    run("/usr/bin/systemctl", &["--user", "restart", &self.unit()]).await?;
                }
            }
            Platform::Launchd => {
                if changed && before.loaded {
                    self.stop(before).await?;
                }
                let domain = before
                    .domain
                    .as_deref()
                    .context("missing launchd user domain")?;
                run(
                    "/bin/launchctl",
                    &["enable", &format!("{domain}/{}", self.label)],
                )
                .await?;
                if !before.loaded || changed {
                    run(
                        "/bin/launchctl",
                        &[
                            "bootstrap",
                            domain,
                            path.to_str().context("service path is not UTF-8")?,
                        ],
                    )
                    .await?;
                } else if !before.running {
                    run(
                        "/bin/launchctl",
                        &["kickstart", &format!("{domain}/{}", self.label)],
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }
    pub async fn start(&self, path: &Path, before: &State, restart: bool) -> Result<()> {
        match self.platform {
            Platform::Systemd => {
                run("/usr/bin/systemctl", &["--user", "daemon-reload"]).await?;
                run(
                    "/usr/bin/systemctl",
                    &[
                        "--user",
                        if restart { "restart" } else { "start" },
                        &self.unit(),
                    ],
                )
                .await?;
            }
            Platform::Launchd => {
                if restart && before.loaded {
                    self.stop(before).await?;
                }
                let domain = before
                    .domain
                    .as_deref()
                    .context("missing launchd user domain")?;
                run(
                    "/bin/launchctl",
                    &["enable", &format!("{domain}/{}", self.label)],
                )
                .await?;
                if !before.loaded || restart {
                    run(
                        "/bin/launchctl",
                        &[
                            "bootstrap",
                            domain,
                            path.to_str().context("service path is not UTF-8")?,
                        ],
                    )
                    .await?;
                } else if !before.running {
                    run(
                        "/bin/launchctl",
                        &["kickstart", &format!("{domain}/{}", self.label)],
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }
    pub async fn stop(&self, before: &State) -> Result<()> {
        match self.platform {
            Platform::Systemd => {
                if before.loaded || before.pid.is_some() {
                    run("/usr/bin/systemctl", &["--user", "stop", &self.unit()]).await?;
                }
            }
            Platform::Launchd => {
                for domain in &before.domains {
                    run(
                        "/bin/launchctl",
                        &["bootout", &format!("{domain}/{}", self.label)],
                    )
                    .await?;
                }
                // bootout can return before launchd finishes removing the job
                // and its process. A following bootstrap must wait for both;
                // otherwise a rapid restart can fail with an I/O error.
                let until = tokio::time::Instant::now() + Duration::from_secs(10);
                loop {
                    let state = self.inspect().await;
                    ensure!(
                        state.available,
                        "launchd became unavailable while stopping Gent"
                    );
                    let process_alive = if let Some(pid) = before.pid {
                        output("/bin/kill", &["-0", &pid.to_string()], true)
                            .await?
                            .status
                            .success()
                    } else {
                        false
                    };
                    if !state.loaded && state.pid.is_none() && !process_alive {
                        break;
                    }
                    ensure!(
                        tokio::time::Instant::now() < until,
                        "launchd has not finished stopping Gent; inspect gent daemon status before retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        Ok(())
    }
    pub async fn uninstall(&self, before: &State) -> Result<()> {
        match self.platform {
            Platform::Systemd => {
                self.stop(before).await?;
                run("/usr/bin/systemctl", &["--user", "disable", &self.unit()]).await?;
            }
            Platform::Launchd => self.stop(before).await?,
        }
        Ok(())
    }
    pub async fn reload(&self) -> Result<()> {
        if self.platform == Platform::Systemd {
            run("/usr/bin/systemctl", &["--user", "daemon-reload"]).await?;
        }
        Ok(())
    }
    pub async fn journal(&self, lines: u32) -> Result<String> {
        let result = output(
            "/usr/bin/journalctl",
            &[
                "--user",
                "--unit",
                &self.unit(),
                "--no-pager",
                "--output=cat",
                "--lines",
                &lines.to_string(),
            ],
            false,
        )
        .await?;
        ensure!(result.status.success(), "cannot read daemon journal");
        Ok(String::from_utf8(result.stdout)?)
    }
}
fn parse_systemd(text: &str) -> State {
    let values: std::collections::BTreeMap<_, _> =
        text.lines().filter_map(|l| l.split_once('=')).collect();
    let value = |key| values.get(key).copied().unwrap_or("");
    let pid = value("MainPID").parse::<u32>().ok().filter(|n| *n != 0);
    State {
        available: true,
        loaded: value("LoadState") == "loaded",
        running: value("ActiveState") == "active" && pid.is_some(),
        enabled: matches!(value("UnitFileState"), "enabled" | "enabled-runtime"),
        pid,
        state: format!("{}/{}", value("ActiveState"), value("SubState")),
        last_exit: value("ExecMainStatus").parse().ok(),
        ..Default::default()
    }
}
fn parse_launchd(text: &str) -> State {
    // launchctl print may contain inherited environment values. Extract only
    // top-level lifecycle fields; never surface or log the full output.
    let mut state = State {
        loaded: true,
        state: "loaded".into(),
        ..Default::default()
    };
    for line in text.lines() {
        if !line.starts_with('\t') || line.starts_with("\t\t") {
            continue;
        }
        if let Some((key, value)) = line.trim().split_once(" = ") {
            match key {
                "state" => state.state = value.into(),
                "pid" => state.pid = value.parse().ok(),
                "last exit code" => state.last_exit = value.parse().ok(),
                _ => {}
            }
        }
    }
    state.running = state.state == "running" && state.pid.is_some();
    state
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manager_status_exposes_only_lifecycle_fields() {
        let state = parse_launchd(
            "x = {\n\tstate = running\n\tpid = 42\n\tenvironment = {\n\t\tTOKEN => secret-value\n\t\tpid = 99\n\t}\n\tlast exit code = 0\n}",
        );
        assert_eq!(state.pid, Some(42));
        assert!(state.running);
        assert!(
            !serde_json::to_string(&state)
                .unwrap()
                .contains("secret-value")
        );
        let state = parse_systemd(
            "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=12\nUnitFileState=enabled\nExecMainStatus=0\n",
        );
        assert!(state.running && state.enabled);
        assert_eq!(state.pid, Some(12));
        assert!(!parse_systemd("LoadState=not-found\nMainPID=0\n").loaded);
    }
}
