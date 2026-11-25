use super::STAGING_SERVICE;
use anyhow::{Result, bail, ensure};
use reqwest::{Request, header::HeaderValue};
use std::ffi::{OsStr, OsString};

pub(super) const ENV_VARS: [&str; 3] = [
    "GENT_STAGING_CF_ACCESS_JWT",
    "GENT_STAGING_CF_ACCESS_CLIENT_ID",
    "GENT_STAGING_CF_ACCESS_CLIENT_SECRET",
];

fn sensitive(value: &OsStr) -> Result<HeaderValue> {
    let bytes = value.as_encoded_bytes();
    ensure!(
        !bytes.is_empty() && bytes.iter().all(u8::is_ascii_graphic),
        "invalid staging Access credential"
    );
    let mut header = HeaderValue::from_bytes(bytes)?;
    header.set_sensitive(true);
    Ok(header)
}

// The auth client disables redirects. Inspect each built request since GitHub
// device login and the Gent account service share that client.
pub(super) fn authorize(
    request: &mut Request,
    env: impl Fn(&'static str) -> Option<OsString>,
) -> Result<()> {
    if request.url().origin().ascii_serialization() != STAGING_SERVICE {
        return Ok(());
    }
    let headers = request.headers_mut();
    match ENV_VARS.map(env) {
        [Some(jwt), None, None] => {
            headers.insert("cf-access-token", sensitive(&jwt)?);
        }
        [None, Some(id), Some(secret)] => {
            headers.insert("cf-access-client-id", sensitive(&id)?);
            headers.insert("cf-access-client-secret", sensitive(&secret)?);
        }
        _ => bail!(
            "set {} or both {} and {} for staging Access",
            ENV_VARS[0],
            ENV_VARS[1],
            ENV_VARS[2]
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::client;

    fn authorize_fixture(request: &mut Request, values: [Option<&str>; 3]) -> Result<()> {
        authorize(request, |name| {
            ENV_VARS
                .iter()
                .position(|k| *k == name)
                .and_then(|i| values[i].map(Into::into))
        })
    }

    #[test]
    fn staging_access_preserves_gent_bearer_and_redacts_headers() -> Result<()> {
        let client = client()?;
        for (values, expected) in [
            (
                [Some("fixture-jwt"), None, None],
                vec![("cf-access-token", "fixture-jwt")],
            ),
            (
                [None, Some("fixture-id"), Some("fixture-secret")],
                vec![
                    ("cf-access-client-id", "fixture-id"),
                    ("cf-access-client-secret", "fixture-secret"),
                ],
            ),
        ] {
            let mut request = client
                .post("https://staging.gent.link:443/v1/billing/browser/grant")
                .bearer_auth("gent-fixture")
                .build()?;
            authorize_fixture(&mut request, values)?;
            let headers = request.headers();
            assert_eq!(headers["authorization"], "Bearer gent-fixture");
            assert_eq!(headers.len(), expected.len() + 1);
            for (name, value) in expected {
                assert!(headers[name] == value);
                assert!(headers[name].is_sensitive());
                assert!(!format!("{request:?}").contains(value));
            }
        }
        Ok(())
    }

    #[test]
    fn other_origins_never_read_access_credentials() -> Result<()> {
        let client = client()?;
        for url in [
            "https://github.com/login/device/code",
            "https://github.com/login/oauth/access_token",
            "https://api.gent.link/v1/auth/session",
            "https://gent.link/account",
            "https://checkout.stripe.com/",
            "http://staging.gent.link/",
            "https://staging.gent.link:8443/",
            "https://staging.gent.link.example/",
            "https://staging.gent.link@example.org/",
            "http://127.0.0.1:8000/v1/auth/config",
        ] {
            let mut request = client.get(url).build()?;
            authorize(&mut request, |_| {
                panic!("read staging credentials for {url}")
            })?;
        }
        Ok(())
    }

    #[test]
    fn invalid_or_ambiguous_credentials_fail_without_disclosing_values() -> Result<()> {
        let client = client()?;
        for values in [
            [None, None, None],
            [None, Some("fixture-id"), None],
            [None, None, Some("fixture-secret")],
            [
                Some("fixture-jwt"),
                Some("fixture-id"),
                Some("fixture-secret"),
            ],
            [Some("fixture-jwt\r\nInjected: yes"), None, None],
            [None, Some("fixture-id"), Some("")],
        ] {
            let mut request = client.get(STAGING_SERVICE).build()?;
            let error = authorize_fixture(&mut request, values).unwrap_err();
            assert!(!format!("{error:#}").contains("fixture"));
        }
        Ok(())
    }
}
