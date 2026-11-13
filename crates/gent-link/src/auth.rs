//! Native account login. Service credentials never grant cluster key authority.
use crate::managed_file::{self, Snapshot};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Subcommand;
use gent_protocol::service::{
    AuthConfig, CALLBACK_PATH, CodeExchange, ServiceSession, TokenExchange,
};
use reqwest::{Client, Method, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, timeout},
};

const DEFAULT_SERVICE: &str = "https://api.gent.link";

#[derive(Subcommand)]
pub enum Command {
    Status,
    /// Sign in with GitHub. SSH sessions use the device-code flow by default.
    Login {
        #[arg(long)]
        headless: bool,
        /// Print the browser URL without opening it; still uses a local callback.
        #[arg(long, conflicts_with = "headless")]
        no_browser: bool,
        /// Alternate Gent service origin. HTTPS is required except on loopback.
        #[arg(long)]
        service: Option<String>,
    },
    /// Stop using this session and revoke it at the service. Retry if offline.
    Logout,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u8,
    service: String,
    token: String,
    phase: Phase,
    session: Option<ServiceSession>,
}
#[derive(Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Pending,
    Active,
    Revoking,
}

fn origin(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("invalid service origin")?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "service must be an origin without credentials, path, query or fragment"
    );
    ensure!(
        url.scheme() == "https" || loopback(&url),
        "service requires HTTPS except on loopback"
    );
    Ok(url)
}
fn loopback(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
}
fn random() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).context("secure randomness unavailable")?;
    Ok(bytes)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn candidate() -> Result<String> {
    let secret = random()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Ok(format!("gent_s1.{}.{secret}", now()?))
}
fn read(path: &Path) -> Result<Option<Saved>> {
    let snapshot = Snapshot::read(path)?;
    snapshot.private()?;
    let value: Option<Saved> = match snapshot.text {
        Some(text) => serde_json::from_str(&text)
            .map_err(|_| anyhow::anyhow!("invalid saved Gent authentication"))?,
        None => None,
    };
    if let Some(value) = &value {
        ensure!(
            value.version == 1
                && gent_protocol::service::session_created_at(&value.token).is_some(),
            "invalid saved Gent authentication"
        );
        origin(&value.service)?;
    }
    Ok(value)
}
fn save(path: &Path, value: Option<&Saved>) -> Result<()> {
    let snapshot = Snapshot::read(path)?;
    snapshot.private()?;
    snapshot.write(&(serde_json::to_string(&value)? + "\n"))
}
fn client() -> Result<Client> {
    Ok(Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .user_agent("gent-link")
        .build()?)
}

async fn response(request: reqwest::RequestBuilder) -> Result<(StatusCode, Value)> {
    let mut response = request
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("could not reach the authentication service"))?;
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("could not read the authentication response"))?
    {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= 64 * 1024,
            "authentication response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid authentication response"))?
    };
    Ok((status, value))
}
fn success(status: StatusCode, value: Value) -> Result<Value> {
    ensure!(
        status.is_success(),
        "authentication request failed (HTTP {})",
        status.as_u16()
    );
    Ok(value)
}
async fn service_session(client: &Client, saved: &Saved) -> Result<Option<ServiceSession>> {
    let (status, value) = response(
        client
            .get(origin(&saved.service)?.join("v1/auth/session")?)
            .bearer_auth(&saved.token),
    )
    .await?;
    if status == StatusCode::UNAUTHORIZED {
        return Ok(None);
    }
    Ok(Some(
        serde_json::from_value(success(status, value)?)
            .map_err(|_| anyhow::anyhow!("invalid Gent session response"))?,
    ))
}

pub async fn execute(home: &Path, command: Command) -> Result<Value> {
    let directory = managed_file::normalize(&home.join("auth"))?;
    let path = directory.join("session.json");
    let client = client()?;
    if matches!(command, Command::Status) {
        let Some(saved) = read(&path)? else {
            return Ok(json!({"status":"signed_out"}));
        };
        if saved.phase == Phase::Revoking {
            return Ok(json!({"status":"revocation_pending","service":saved.service}));
        }
        return match service_session(&client, &saved).await {
            Ok(Some(session)) => {
                Ok(json!({"status":"active","service":saved.service,"account":session}))
            }
            Ok(None) => Ok(json!({"status":"signed_out","service":saved.service})),
            Err(_) => Ok(
                json!({"status":"unavailable","service":saved.service,"cached_account":saved.session}),
            ),
        };
    }
    managed_file::directory(&directory)?;
    let _lock = managed_file::lock(&directory.join("session.lock"))?;
    let mut saved = read(&path)?;
    if matches!(command, Command::Logout) {
        let Some(saved) = &mut saved else {
            return Ok(json!({"status":"signed_out"}));
        };
        saved.phase = Phase::Revoking;
        save(&path, Some(saved))?;
        let outcome = response(
            client
                .request(
                    Method::DELETE,
                    origin(&saved.service)?.join("v1/auth/session")?,
                )
                .bearer_auth(&saved.token),
        )
        .await;
        if !matches!(outcome, Ok((StatusCode::NO_CONTENT, _))) {
            return Ok(json!({"status":"revocation_pending","service":saved.service}));
        }
        save(&path, None)?;
        return Ok(json!({"status":"signed_out"}));
    }
    let Command::Login {
        headless,
        no_browser,
        service,
    } = command
    else {
        unreachable!()
    };
    let base = origin(
        service
            .as_deref()
            .or_else(|| saved.as_ref().map(|s| s.service.as_str()))
            .unwrap_or(DEFAULT_SERVICE),
    )?;
    if let Some(previous) = &mut saved {
        ensure!(
            origin(&previous.service)? == base,
            "sign out before switching Gent services"
        );
        ensure!(
            previous.phase != Phase::Revoking,
            "session revocation is pending; retry gent auth logout first"
        );
        if let Some(session) = service_session(&client, previous).await? {
            previous.phase = Phase::Active;
            previous.session = Some(session.clone());
            save(&path, Some(previous))?;
            return Ok(json!({"status":"active","service":base.as_str(),"account":session}));
        }
    }
    let (status, value) = response(client.get(base.join("v1/auth/config")?)).await?;
    let config: AuthConfig = serde_json::from_value(success(status, value)?)
        .map_err(|_| anyhow::anyhow!("invalid Gent authentication configuration"))?;
    ensure!(
        !config.github_client_id.is_empty()
            && config.github_client_id.len() <= 128
            && config
                .github_client_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.'),
        "invalid GitHub client ID"
    );
    let github = github_origin(&base)?;
    let device = headless || (!no_browser && std::env::var_os("SSH_CONNECTION").is_some());
    let credential = if device {
        Credential::Token(device_login(&client, &github, &config.github_client_id).await?)
    } else {
        let (code, verifier, redirect) =
            browser_login(&github, &config.github_client_id, no_browser).await?;
        Credential::Code {
            code,
            verifier,
            redirect,
        }
    };
    let pending = Saved {
        version: 1,
        service: base.to_string(),
        token: candidate()?,
        phase: Phase::Pending,
        session: None,
    };
    // Persist the service candidate before exchange. A lost response can be
    // recovered by status/login without retaining any GitHub credential.
    save(&path, Some(&pending))?;
    let exchange = match credential {
        Credential::Token(token) => {
            client
                .post(base.join("v1/auth/github/token")?)
                .json(&TokenExchange {
                    github_access_token: token,
                    session_token: pending.token.clone(),
                })
        }
        Credential::Code {
            code,
            verifier,
            redirect,
        } => client
            .post(base.join("v1/auth/github/code")?)
            .json(&CodeExchange {
                code,
                code_verifier: verifier,
                redirect_uri: redirect,
                session_token: pending.token.clone(),
            }),
    };
    let result = response(exchange).await;
    let session = match result {
        Ok((status, value)) if status.is_success() => serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("invalid Gent session response"))?,
        other => match service_session(&client, &pending).await? {
            Some(session) => session,
            None => {
                if let Ok((status, _)) = other {
                    bail!(
                        "GitHub sign-in was not accepted by Gent (HTTP {})",
                        status.as_u16()
                    );
                }
                bail!("sign-in response lost; run gent auth status before retrying");
            }
        },
    };
    let active = Saved {
        phase: Phase::Active,
        session: Some(session),
        ..pending
    };
    save(&path, Some(&active))?;
    Ok(json!({"status":"active","service":base.as_str(),"account":active.session}))
}

enum Credential {
    Token(String),
    Code {
        code: String,
        verifier: String,
        redirect: String,
    },
}
fn github_origin(service: &Url) -> Result<Url> {
    #[cfg(feature = "test-auth-provider")]
    if let Ok(value) = std::env::var("GENT_TEST_GITHUB_ORIGIN") {
        let url = origin(&value)?;
        ensure!(
            loopback(service) && loopback(&url),
            "test GitHub requires local service and provider origins"
        );
        return Ok(url);
    }
    let _ = service;
    Ok(Url::parse("https://github.com")?)
}

async fn device_login(client: &Client, github: &Url, client_id: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Device {
        device_code: String,
        user_code: String,
        verification_uri: String,
        expires_in: u64,
        interval: u64,
    }
    let (status, value) = response(
        client
            .post(github.join("login/device/code")?)
            .form(&[("client_id", client_id), ("scope", "")])
            .header("Accept", "application/json"),
    )
    .await?;
    let device: Device = serde_json::from_value(success(status, value)?)
        .map_err(|_| anyhow::anyhow!("invalid GitHub device response"))?;
    ensure!(
        device.verification_uri == github.join("login/device")?.as_str()
            && (1..=1800).contains(&device.expires_in)
            && (5..=60).contains(&device.interval)
            && !device.device_code.is_empty()
            && device.device_code.len() <= 256
            && device.user_code.len() <= 32
            && !device.user_code.is_empty()
            && device
                .user_code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid GitHub device authorization"
    );
    eprintln!(
        "Open {}\nEnter code: {}",
        device.verification_uri, device.user_code
    );
    let deadline = Instant::now() + Duration::from_secs(device.expires_in);
    let mut interval = device.interval;
    loop {
        ensure!(
            Instant::now() + Duration::from_secs(interval) < deadline,
            "GitHub device sign-in expired; retry gent auth login"
        );
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let (status, value) = response(
            client
                .post(github.join("login/oauth/access_token")?)
                .form(&[
                    ("client_id", client_id),
                    ("device_code", device.device_code.as_str()),
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ])
                .header("Accept", "application/json"),
        )
        .await?;
        let value = success(status, value)?;
        if let Some(token) = value["access_token"].as_str() {
            ensure!(value["token_type"] == "bearer", "invalid GitHub token type");
            return Ok(token.into());
        }
        match value["error"].as_str() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval = interval.saturating_add(5).min(300),
            Some("access_denied") => bail!("GitHub sign-in declined"),
            Some("expired_token") => bail!("GitHub device sign-in expired; retry gent auth login"),
            _ => bail!(
                "GitHub device sign-in failed; check that device flow is enabled for the Gent app"
            ),
        }
    }
}

async fn browser_login(
    github: &Url,
    client_id: &str,
    no_browser: bool,
) -> Result<(String, String, String)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let redirect = format!(
        "http://127.0.0.1:{}{CALLBACK_PATH}",
        listener.local_addr()?.port()
    );
    let state = URL_SAFE_NO_PAD.encode(random()?);
    let verifier = URL_SAFE_NO_PAD.encode(random()?);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut url = github.join("login/oauth/authorize")?;
    url.query_pairs_mut().extend_pairs([
        ("client_id", client_id),
        ("redirect_uri", redirect.as_str()),
        ("scope", ""),
        ("state", state.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    eprintln!("Open this URL to sign in:\n{url}");
    if !no_browser {
        let program = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        let _ = std::process::Command::new(program)
            .arg(url.as_str())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
    let code = timeout(Duration::from_secs(600), async {
        loop {
            let (stream, _) = listener.accept().await?;
            if let Ok(Ok(Some(code))) =
                timeout(Duration::from_secs(3), callback(stream, &redirect, &state)).await
            {
                return code;
            }
        }
    })
    .await
    .context("browser sign-in timed out; use gent auth login --headless on a remote machine")??;
    Ok((code, verifier, redirect))
}

async fn callback(
    mut stream: TcpStream,
    redirect: &str,
    state: &str,
) -> Result<Option<Result<String>>> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 1024];
    while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
        let n = stream.read(&mut buffer).await?;
        if n == 0 || bytes.len() + n > 8192 {
            return Ok(None);
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    let input = std::str::from_utf8(&bytes)?;
    let mut lines = input.split("\r\n");
    let request: Vec<_> = lines.next().unwrap_or("").split(' ').collect();
    let expected = Url::parse(redirect)?;
    let authority = format!(
        "127.0.0.1:{}",
        expected.port().context("missing callback port")?
    );
    let hosts: Vec<_> = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
        .collect();
    let value = if request.len() == 3
        && request[0] == "GET"
        && request[1].starts_with('/')
        && hosts.len() == 1
        && hosts[0].1.trim() == authority
    {
        callback_code(request[1], &expected, state)
    } else {
        None
    };
    let (status, text) = if value.is_some() {
        (
            "200 OK",
            "GitHub responded. Return to Gent to finish signing in.",
        )
    } else {
        ("400 Bad Request", "Invalid sign-in callback.")
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'\r\n\r\n{text}",
        text.len()
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(value)
}
fn callback_code(target: &str, expected: &Url, state: &str) -> Option<Result<String>> {
    let url = expected.join(target).ok()?;
    if url.origin() != expected.origin() || url.path() != CALLBACK_PATH || url.fragment().is_some()
    {
        return None;
    }
    let mut fields = BTreeMap::new();
    for (key, value) in url.query_pairs() {
        if fields
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return None;
        }
    }
    if fields.get("state").map(String::as_str) != Some(state) {
        return None;
    }
    if fields.contains_key("error") {
        return Some(Err(anyhow::anyhow!("GitHub sign-in declined")));
    }
    fields
        .get("code")
        .filter(|code| !code.is_empty() && code.len() <= 256)
        .map(|code| Ok(code.clone()))
}

pub fn print(value: &Value) {
    match value["status"].as_str() {
        Some("active") => println!(
            "Signed in as @{} ({})",
            value["account"]["github_login"]
                .as_str()
                .unwrap_or("unknown"),
            value["service"].as_str().unwrap_or("")
        ),
        Some("revocation_pending") => println!(
            "Signed out locally. Service revocation is pending; retry gent auth logout when connected."
        ),
        Some("unavailable") => {
            println!("Service unavailable; sign-in status could not be verified.")
        }
        _ => println!("Not signed in. Run gent auth login."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_saved_authentication_never_echoes_values() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("session.json");
        Snapshot::read(&path)
            .unwrap()
            .write(r#"{"version":"fixture-secret-do-not-print"}"#)
            .unwrap();
        let error = read(&path).err().expect("malformed credential accepted");
        assert!(!format!("{error:#}").contains("fixture-secret-do-not-print"));
    }
    #[test]
    fn service_origins_and_callbacks_reject_credential_redirection() {
        for bad in [
            "http://gent.link",
            "https://user:password@gent.link",
            "https://gent.link/path",
            "https://gent.link/?token=secret",
            "http://localhost:1234",
        ] {
            assert!(origin(bad).is_err());
        }
        let callback = Url::parse("http://127.0.0.1:1234/gent/github/callback").unwrap();
        let ok = "/gent/github/callback?state=expected&code=abcd";
        assert_eq!(
            callback_code(ok, &callback, "expected").unwrap().unwrap(),
            "abcd"
        );
        for bad in [
            "//foreign.invalid/gent/github/callback?state=expected&code=abcd",
            "/gent/github/callback?state=wrong&code=abcd",
            "/gent/github/callback?state=expected&state=expected&code=abcd",
            "/other?state=expected&code=abcd",
        ] {
            assert!(callback_code(bad, &callback, "expected").is_none());
        }
    }
}
