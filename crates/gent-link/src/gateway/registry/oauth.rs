//! OAuth authorization-code grants share the registry transaction with host
//! revocation and agent bindings. Consent is an authenticated local-owner CLI
//! action; neither a public authorization URL nor a client secret grants it.
use super::*;
use crate::gateway::assertion;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};

pub(crate) const SCOPE: &str = "gent:agents";
const REQUEST_TTL: u64 = 600;
const CODE_TTL: u64 = 300;
const ACCESS_TTL: u64 = 900;
const GRANT_TTL: u64 = 30 * 24 * 3600;
const MAX_REQUESTS: usize = 64;
const MAX_GRANTS: usize = 128;
const MAX_PER_CLIENT: usize = 4;
const MAX_ASSERTIONS: usize = 1024;
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub(crate) struct Failure(pub &'static str);
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Failure {}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registration {
    pub resource: String,
    pub redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion: Option<assertion::Policy>,
}

fn url(value: &str, callback: bool) -> Result<url::Url> {
    ensure!(value.len() <= 2048, "OAuth URL is too long");
    let url = url::Url::parse(value).context("invalid OAuth URL")?;
    let loopback = url.host_str().is_some_and(|h| {
        h == "127.0.0.1"
                || h == "[::1]"
                // Claude Code preregisters localhost callbacks. Keep this
                // exception out of resource URLs and require a concrete port.
                || (callback && h == "localhost" && url.port().is_some_and(|p| p != 0))
    });
    ensure!(
        (url.scheme() == "https" || (url.scheme() == "http" && loopback))
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.as_str() == value,
        "OAuth URL must be canonical HTTPS or loopback HTTP; localhost is only allowed for callbacks with an explicit nonzero port"
    );
    Ok(url)
}
impl Registration {
    pub(crate) fn client_id<'a>(&'a self, local_id: &'a str) -> &'a str {
        self.assertion
            .as_ref()
            .map_or(local_id, |p| p.client_id.as_str())
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(policy) = &self.assertion {
            policy.validate()?;
        }
        let resource = url(&self.resource, false)?;
        ensure!(
            resource.path() == "/mcp" && resource.query().is_none(),
            "OAuth resource must name the exact /mcp endpoint"
        );
        ensure!(
            !self.redirect_uris.is_empty() && self.redirect_uris.len() <= 8,
            "configure 1-8 exact OAuth callbacks"
        );
        let mut unique = std::collections::BTreeSet::new();
        for redirect in &self.redirect_uris {
            let redirect_url = url(redirect, true)?;
            ensure!(
                unique.insert(redirect)
                    && !redirect_url
                        .query_pairs()
                        .any(|(key, _)| matches!(key.as_ref(), "code" | "state" | "iss" | "error")),
                "invalid OAuth callback parameters or duplicate callback"
            );
        }
        Ok(())
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Records {
    requests: BTreeMap<String, Authorization>,
    grants: BTreeMap<String, Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assertions: Option<BTreeMap<String, u64>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    client: String,
    resource: String,
    redirect: String,
    state: Option<String>,
    challenge: String,
    created_at: u64,
    expires_at: u64,
    decision: Option<bool>,
    code_secret: Option<String>,
    code_hash: Option<String>,
    code_expires_at: Option<u64>,
    grant: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    client: String,
    resource: String,
    created_at: u64,
    expires_at: u64,
    access_hash: String,
    access_expires_at: u64,
    refresh_key: String,
    refresh_generation: u32,
    revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject: Option<Subject>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Subject {
    Unbound,
    Bound(String),
}

fn challenge(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == value)
}
fn verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}
fn opaque(value: &str, limit: usize) -> bool {
    value.len() <= limit && !value.chars().any(char::is_control)
}
fn equal(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

impl Records {
    pub(super) fn check_subject(&self, id: &str, subject: &str) -> Result<bool> {
        match self.grants.get(id).and_then(|g| g.subject.as_ref()) {
            Some(Subject::Unbound) => Ok(true),
            Some(Subject::Bound(expected)) => {
                ensure!(
                    expected == subject,
                    "OAuth grant belongs to a different host user"
                );
                Ok(false)
            }
            None => anyhow::bail!("OAuth subject binding state is missing"),
        }
    }
    pub(super) fn bind_subject(&mut self, id: &str, subject: String) -> Result<()> {
        self.check_subject(id, &subject)?;
        self.grants.get_mut(id).unwrap().subject = Some(Subject::Bound(subject));
        Ok(())
    }
    pub(super) fn enable_assertions(&mut self) {
        self.assertions.get_or_insert_with(BTreeMap::new);
    }
    pub(super) fn validate(&self, state: &State) -> Result<()> {
        let signed = state
            .clients
            .values()
            .any(|c| c.oauth.as_ref().is_some_and(|r| r.assertion.is_some()));
        ensure!(
            signed == self.assertions.is_some(),
            "assertion replay state is missing or inconsistent"
        );
        if let Some(assertions) = &self.assertions {
            ensure!(
                assertions.len() <= MAX_ASSERTIONS
                    && assertions.iter().all(|(id, expires)| hash(id)
                        && *expires > 0
                        && *expires
                            <= state
                                .clock
                                .saturating_add(assertion::MAX_LIFETIME + assertion::CLOCK_SKEW)),
                "invalid assertion replay state"
            );
        }
        ensure!(
            self.requests.len() <= MAX_REQUESTS && self.grants.len() <= MAX_GRANTS,
            "OAuth capacity exceeded"
        );
        for (id, request) in &self.requests {
            let client = state
                .clients
                .get(&request.client)
                .context("OAuth client missing")?;
            let registration = client
                .oauth
                .as_ref()
                .context("OAuth registration missing")?;
            ensure!(
                uuid(id)
                    && registration.resource == request.resource
                    && registration.redirect_uris.contains(&request.redirect)
                    && challenge(&request.challenge)
                    && request.state.as_ref().is_none_or(|s| opaque(s, 2048))
                    && request.created_at <= state.clock
                    && request.expires_at.checked_sub(request.created_at) == Some(REQUEST_TTL),
                "invalid OAuth request record"
            );
            let approved = request.decision == Some(true);
            ensure!(
                request.code_hash.as_ref().is_none_or(|s| hash(s))
                    && request.code_secret.as_ref().is_none_or(|s| hash(s))
                    && request.grant.as_ref().is_none_or(|s| uuid(s))
                    && approved == request.code_hash.is_some()
                    && approved == request.code_expires_at.is_some()
                    && request.code_secret.is_some() == (approved && request.grant.is_none())
                    && (request.grant.is_none() || approved)
                    && request
                        .code_expires_at
                        .is_none_or(|t| t >= request.created_at && t <= request.expires_at),
                "invalid OAuth request decision"
            );
        }
        for (id, grant) in &self.grants {
            let client = state
                .clients
                .get(&grant.client)
                .context("OAuth client missing")?;
            ensure!(
                client.subject_key.is_some() == grant.subject.is_some(),
                "OAuth subject binding state is missing or inconsistent"
            );
            if let Some(Subject::Bound(subject)) = &grant.subject {
                ensure!(hash(subject), "invalid OAuth subject binding");
            }
            ensure!(
                uuid(id)
                    && client
                        .oauth
                        .as_ref()
                        .is_some_and(|r| r.resource == grant.resource)
                    && grant.created_at <= state.clock
                    && grant.created_at < grant.expires_at
                    && grant.expires_at <= client.expires_at
                    && grant.expires_at - grant.created_at <= GRANT_TTL
                    && grant.access_expires_at <= grant.expires_at
                    && hash(&grant.access_hash)
                    && hash(&grant.refresh_key),
                "invalid OAuth grant record"
            );
        }
        Ok(())
    }
    fn prune(&mut self, now: u64) {
        self.requests.retain(|_, r| now < r.expires_at);
        self.grants.retain(|_, g| now < g.expires_at);
        if let Some(assertions) = &mut self.assertions {
            assertions.retain(|_, expires| now < *expires);
        }
    }
}

fn parts<'a>(token: &'a str, prefix: &str) -> Result<(&'a str, &'a str)> {
    let mut pieces = token.split('.');
    ensure!(pieces.next() == Some(prefix), "invalid OAuth token");
    let id = pieces.next().context("invalid OAuth token")?;
    let secret = pieces.next().context("invalid OAuth token")?;
    ensure!(
        uuid(id) && hash(secret) && pieces.next().is_none(),
        "invalid OAuth token"
    );
    Ok((id, secret))
}

pub(super) fn access_permit(
    state: &State,
    token: &str,
    resource: &str,
    now: u64,
) -> Result<Permit> {
    let (id, _) = parts(token, "gent_a1")?;
    let grant = state
        .oauth
        .as_ref()
        .and_then(|o| o.grants.get(id))
        .context("unknown OAuth grant")?;
    let permit = Permit {
        client: grant.client.clone(),
        hash: digest(token),
        oauth: Some((id.into(), resource.into())),
        peer: Peer::default(),
    };
    check_access(state, &permit, now)?;
    Ok(permit)
}
pub(super) fn check_access(state: &State, permit: &Permit, now: u64) -> Result<()> {
    let (id, resource) = permit.oauth.as_ref().context("OAuth permit missing")?;
    let grant = state
        .oauth
        .as_ref()
        .and_then(|o| o.grants.get(id))
        .context("unknown OAuth grant")?;
    ensure!(
        grant.client == permit.client
            && grant.resource == *resource
            && !grant.revoked
            && now < grant.access_expires_at
            && now < grant.expires_at
            && equal(&grant.access_hash, &permit.hash),
        "inactive OAuth grant"
    );
    Ok(())
}

/// A delegated file link follows the grant's lifetime and revocation, across
/// ordinary access-token refresh. It grants no other OAuth or agent operation.
pub(super) fn download_scope(
    state: &State,
    client: &str,
    id: &str,
    resource: &str,
    now: u64,
) -> Result<(Option<String>, u64)> {
    let grant = state
        .oauth
        .as_ref()
        .and_then(|o| o.grants.get(id))
        .context("download grant unavailable")?;
    ensure!(
        grant.client == client
            && grant.resource == resource
            && !grant.revoked
            && now < grant.expires_at,
        "download grant inactive"
    );
    let scoped = state
        .clients
        .get(client)
        .context("download host unavailable")?
        .subject_key
        .is_some();
    let subject = match (scoped, &grant.subject) {
        (true, Some(Subject::Bound(value))) => Some(value.clone()),
        (false, None) => None,
        _ => anyhow::bail!("download user binding unavailable"),
    };
    Ok((subject, grant.expires_at))
}

pub(crate) type Parameters = BTreeMap<String, String>;
pub(crate) fn parameters(input: &str) -> Result<Parameters> {
    ensure!(input.len() <= 8192, "OAuth parameters too large");
    let mut fields = BTreeMap::new();
    // Reject malformed encoding rather than assigning lossy identities/URIs.
    let bytes = input.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'%' {
            ensure!(
                bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                    && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit),
                "invalid OAuth encoding"
            );
        }
    }
    for (key, value) in url::form_urlencoded::parse(bytes) {
        ensure!(
            !key.contains('\u{fffd}')
                && !value.contains('\u{fffd}')
                && opaque(&value, 4096)
                && fields.insert(key.to_string(), value.to_string()).is_none(),
            "invalid or duplicate OAuth parameter"
        );
    }
    Ok(fields)
}
fn required<'a>(p: &'a Parameters, key: &str) -> Result<&'a str> {
    p.get(key)
        .map(String::as_str)
        .context("required OAuth parameter missing")
}
fn scope(p: &Parameters) -> Result<()> {
    ensure!(
        p.get("scope").is_none_or(|s| s == SCOPE),
        "unsupported OAuth scope"
    );
    Ok(())
}
fn active_client<'a>(state: &'a State, id: &str, resource: &str, now: u64) -> Result<&'a Client> {
    ensure!(now >= state.clock, "gateway clock moved backward");
    let client = state.clients.get(id).context("unknown OAuth client")?;
    ensure!(
        !client.revoked
            && now < client.expires_at
            && client
                .oauth
                .as_ref()
                .is_some_and(|r| r.resource == resource),
        "inactive OAuth client or resource mismatch"
    );
    Ok(client)
}
fn registered_client<'a>(
    state: &'a State,
    id: &str,
    resource: &str,
    now: u64,
) -> Result<(&'a str, &'a Client)> {
    let (local, _) = state
        .clients
        .iter()
        .find(|(local, c)| c.oauth.as_ref().is_some_and(|r| r.client_id(local) == id))
        .context("unknown OAuth client")?;
    Ok((local, active_client(state, local, resource, now)?))
}
fn refresh(id: &str, grant: &Grant) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(grant.refresh_key.as_bytes()).expect("HMAC accepts key");
    mac.update(b"gent-oauth-refresh-v1\0");
    mac.update(id.as_bytes());
    mac.update(&grant.refresh_generation.to_be_bytes());
    format!(
        "gent_r1.{id}.{}.{:x}",
        grant.refresh_generation,
        mac.finalize().into_bytes()
    )
}
fn token_response(id: &str, grant: &Grant, access: String, now: u64) -> Value {
    json!({"access_token":access,"token_type":"Bearer","expires_in":grant.access_expires_at-now,
        "refresh_token":refresh(id,grant),"scope":SCOPE})
}

impl Registry {
    fn oauth_transaction<T>(&self, f: impl FnOnce(&mut State, u64) -> Result<T>) -> Result<T> {
        directory_check(&self.directory())?;
        let _lock = managed_file::lock(&self.directory().join("state.lock"))?;
        let mut state = self.read()?;
        let now = auth::now()?;
        ensure!(now >= state.clock, "gateway clock moved backward");
        let result = f(&mut state, now);
        // Revocation after a replay must commit even though the response is an
        // error. Closures validate inputs before changing successful records.
        state.clock = now;
        self.save(&state)?;
        result
    }
    pub(crate) async fn oauth_begin(&self, fields: Parameters, resource: String) -> Result<Value> {
        self.blocking(move |registry| registry.begin(&fields, &resource))
            .await
    }
    fn begin(&self, p: &Parameters, resource: &str) -> Result<Value> {
        ensure!(
            required(p, "response_type")? == "code"
                && required(p, "code_challenge_method")? == "S256"
                && challenge(required(p, "code_challenge")?)
                && required(p, "resource")? == resource,
            "invalid OAuth authorization parameters"
        );
        ensure!(
            !p.contains_key("client_secret")
                && !p.contains_key("access_token")
                && !p.contains_key("client_assertion")
                && !p.contains_key("client_assertion_type"),
            "credentials cannot appear in the authorization URL"
        );
        scope(p)?;
        let id = required(p, "client_id")?;
        let redirect = required(p, "redirect_uri")?;
        let state_param = p.get("state").cloned();
        ensure!(
            state_param.as_ref().is_none_or(|s| opaque(s, 2048)),
            "invalid OAuth state"
        );
        self.oauth_transaction(|state,now| {
            let (local,client)=registered_client(state,id,resource,now)?;
            let local=local.to_string();
            ensure!(client.oauth.as_ref().unwrap().redirect_uris.iter().any(|r|r==redirect),"unregistered OAuth callback");
            let name=client.name.clone();
            let records=state.oauth.get_or_insert_with(Records::default);
            records.prune(now);
            ensure!(records.requests.len()<MAX_REQUESTS && records.requests.values().filter(|r|r.client==local).count()<MAX_PER_CLIENT,
                "OAuth pending request capacity reached");
            let request=Uuid::new_v4().to_string();
            records.requests.insert(request.clone(),Authorization {client:local.clone(),resource:resource.into(),redirect:redirect.into(),
                state:state_param,challenge:required(p,"code_challenge")?.into(),created_at:now,expires_at:now+REQUEST_TTL,
                decision:None,code_secret:None,code_hash:None,code_expires_at:None,grant:None});
            Ok(json!({"request":request,"client":local,"oauth_client_id":id,"name":name,"redirect_uri":redirect,"expires_at":now+REQUEST_TTL}))
        })
    }
    pub(crate) fn oauth_requests(&self) -> Result<Value> {
        let state = self.read()?;
        let now = auth::now()?.max(state.clock);
        let requests:Vec<_>=state.oauth.iter().flat_map(|o|&o.requests).filter(|(_,r)|now<r.expires_at).map(|(id,r)| {
            json!({"request":id,"client":r.client,"oauth_client_id":state.clients[&r.client].oauth.as_ref().unwrap().client_id(&r.client),
                "name":state.clients[&r.client].name,"resource":r.resource,"redirect_uri":r.redirect,
                "expires_at":r.expires_at,"decision":r.decision,"redeemed":r.grant.is_some()})
        }).collect();
        Ok(json!({"requests":requests,"scope":SCOPE}))
    }
    pub(crate) fn oauth_decide(&self, id: &str, approve: bool) -> Result<Value> {
        self.oauth_transaction(|state,now| {
            let request=state.oauth.as_ref().and_then(|o|o.requests.get(id)).context("unknown OAuth request")?;
            ensure!(now<request.expires_at,"OAuth request expired");
            active_client(state,&request.client,&request.resource,now)?;
            ensure!(request.decision.is_none_or(|old|old==approve),"OAuth decision cannot be reversed");
            let request=state.oauth.as_mut().unwrap().requests.get_mut(id).unwrap();
            if request.decision.is_none() {
                request.decision=Some(approve);
                if approve {
                    let secret=config::secret();
                    request.code_hash=Some(digest(&format!("gent_c1.{id}.{secret}")));
                    request.code_secret=Some(secret);
                    request.code_expires_at=Some(request.expires_at.min(now+CODE_TTL));
                }
            }
            Ok(json!({"request":id,"approved":approve,"client":request.client,"redirect_uri":request.redirect,
                "next":"return to the authorization page and continue"}))
        })
    }
    pub(crate) async fn oauth_continue(
        &self,
        id: String,
        resource: String,
    ) -> Result<Option<String>> {
        self.blocking(move |registry| registry.continue_request(&id, &resource))
            .await
    }
    fn continue_request(&self, id: &str, resource: &str) -> Result<Option<String>> {
        self.oauth_transaction(|state, now| {
            let request = state
                .oauth
                .as_ref()
                .and_then(|o| o.requests.get(id))
                .context("unknown OAuth request")?;
            ensure!(
                request.resource == resource && now < request.expires_at && request.grant.is_none(),
                "OAuth request unavailable"
            );
            active_client(state, &request.client, resource, now)?;
            let Some(approved) = request.decision else {
                return Ok(None);
            };
            let mut redirect = url(&request.redirect, true)?;
            {
                let mut query = redirect.query_pairs_mut();
                if approved {
                    ensure!(now < request.code_expires_at.unwrap(), "OAuth code expired");
                    query.append_pair(
                        "code",
                        &format!("gent_c1.{id}.{}", request.code_secret.as_ref().unwrap()),
                    );
                } else {
                    query.append_pair("error", "access_denied");
                }
                if let Some(state) = &request.state {
                    query.append_pair("state", state);
                }
                query.append_pair(
                    "iss",
                    resource.strip_suffix("/mcp").context("invalid resource")?,
                );
            }
            Ok(Some(redirect.to_string()))
        })
    }
    pub(crate) async fn oauth_exchange(
        &self,
        fields: Parameters,
        resource: String,
        peer: Peer,
    ) -> Result<Value> {
        self.blocking(move |registry| registry.exchange_peer(&fields, &resource, &peer))
            .await
    }
    #[cfg(test)]
    fn exchange(&self, p: &Parameters, resource: &str) -> Result<Value> {
        self.exchange_peer(p, resource, &Peer::default())
    }
    fn exchange_peer(&self, p: &Parameters, resource: &str, peer: &Peer) -> Result<Value> {
        ensure!(
            required(p, "resource")? == resource,
            Failure("invalid_target")
        );
        scope(p).map_err(|_| Failure("invalid_scope"))?;
        let client_id = required(p, "client_id").map_err(|_| Failure("invalid_client"))?;
        let kind = required(p, "grant_type")?;
        ensure!(
            matches!(kind, "authorization_code" | "refresh_token"),
            Failure("unsupported_grant_type")
        );
        self.oauth_transaction(|state, now| {
            let (local, client) = registered_client(state, client_id, resource, now)
                .map_err(|_| Failure("invalid_client"))?;
            let local = local.to_string();
            let assertion = if let Some(policy) = &client.oauth.as_ref().unwrap().assertion {
                ensure!(
                    !p.contains_key("client_secret")
                        && p.get("client_assertion_type").map(String::as_str)
                            == Some(assertion::TYPE),
                    Failure("invalid_client")
                );
                Some(
                    policy
                        .verify(
                            required(p, "client_assertion")
                                .map_err(|_| Failure("invalid_client"))?,
                            resource,
                            now,
                        )
                        .map_err(|_| Failure("invalid_client"))?,
                )
            } else {
                ensure!(
                    !p.contains_key("client_assertion") && !p.contains_key("client_assertion_type"),
                    Failure("invalid_client")
                );
                let secret = required(p, "client_secret").map_err(|_| Failure("invalid_client"))?;
                ensure!(
                    client
                        .token_hash
                        .as_deref()
                        .is_some_and(|hash| equal(hash, &digest(secret))),
                    Failure("invalid_client")
                );
                None
            };
            if let Some(policy) = &client.mtls {
                policy
                    .verify(peer, now)
                    .map_err(|_| Failure("invalid_client"))?;
            }
            let client_expiry = client.expires_at;
            let subject_required = client.subject_key.is_some();
            if let Some((jti, expires)) = assertion {
                let replays = state
                    .oauth
                    .as_mut()
                    .and_then(|r| r.assertions.as_mut())
                    .context("assertion replay state missing")?;
                replays.retain(|_, expiry| now < *expiry);
                let id = digest(&format!("gent-oauth-assertion-v1\0{local}\0{jti}"));
                ensure!(!replays.contains_key(&id), Failure("invalid_client"));
                ensure!(
                    replays.len() < MAX_ASSERTIONS,
                    Failure("temporarily_unavailable")
                );
                replays.insert(id, expires);
            }
            match kind {
                "authorization_code" => {
                    let code = required(p, "code")?;
                    let (id, _) = parts(code, "gent_c1")?;
                    let verifier_text = required(p, "code_verifier")?;
                    ensure!(verifier(verifier_text), "invalid PKCE verifier");
                    let records = state.oauth.as_mut().context("no OAuth grants")?;
                    let request = records.requests.get_mut(id).context("unknown OAuth code")?;
                    ensure!(
                        request.client == local
                            && request.resource == resource
                            && request.redirect == required(p, "redirect_uri")?
                            && now < request.expires_at
                            && request.decision == Some(true)
                            && request
                                .code_hash
                                .as_ref()
                                .is_some_and(|h| equal(h, &digest(code)))
                            && equal(
                                &request.challenge,
                                &URL_SAFE_NO_PAD.encode(Sha256::digest(verifier_text))
                            ),
                        "invalid OAuth code binding"
                    );
                    if let Some(grant) = &request.grant {
                        if let Some(grant) = records.grants.get_mut(grant) {
                            grant.revoked = true;
                        }
                        anyhow::bail!("OAuth code replay revoked its grant");
                    }
                    ensure!(now < request.code_expires_at.unwrap(), "OAuth code expired");
                    ensure!(
                        records.grants.len() < MAX_GRANTS,
                        "OAuth grant capacity reached"
                    );
                    let grant_id = Uuid::new_v4().to_string();
                    let access = format!("gent_a1.{grant_id}.{}", config::secret());
                    let expires_at = (now + GRANT_TTL).min(client_expiry);
                    let grant = Grant {
                        client: local.clone(),
                        resource: resource.into(),
                        created_at: now,
                        expires_at,
                        access_hash: digest(&access),
                        access_expires_at: (now + ACCESS_TTL).min(expires_at),
                        refresh_key: config::secret(),
                        refresh_generation: 0,
                        revoked: false,
                        subject: subject_required.then_some(Subject::Unbound),
                    };
                    let response = token_response(&grant_id, &grant, access, now);
                    request.grant = Some(grant_id.clone());
                    request.code_secret = None;
                    records.grants.insert(grant_id, grant);
                    Ok(response)
                }
                "refresh_token" => {
                    let raw = required(p, "refresh_token")?;
                    let pieces: Vec<_> = raw.split('.').collect();
                    ensure!(
                        pieces.len() == 4
                            && pieces[0] == "gent_r1"
                            && uuid(pieces[1])
                            && hash(pieces[3]),
                        "invalid refresh token"
                    );
                    let generation = pieces[2].parse::<u32>()?;
                    ensure!(
                        generation.to_string() == pieces[2],
                        "invalid refresh generation"
                    );
                    let id = pieces[1];
                    let grant = state
                        .oauth
                        .as_mut()
                        .and_then(|o| o.grants.get_mut(id))
                        .context("unknown refresh grant")?;
                    ensure!(
                        !grant.revoked
                            && grant.client == local
                            && grant.resource == resource
                            && now < grant.expires_at,
                        "inactive refresh grant"
                    );
                    let current = grant.refresh_generation;
                    grant.refresh_generation = generation;
                    let expected = refresh(id, grant);
                    grant.refresh_generation = current;
                    ensure!(
                        equal(raw, &expected) && generation <= current,
                        "invalid refresh token"
                    );
                    if generation < current {
                        grant.revoked = true;
                        anyhow::bail!("refresh replay revoked its grant");
                    }
                    let next = current
                        .checked_add(1)
                        .context("refresh generation exhausted")?;
                    let access = format!("gent_a1.{id}.{}", config::secret());
                    grant.access_hash = digest(&access);
                    grant.access_expires_at = (now + ACCESS_TTL).min(grant.expires_at);
                    grant.refresh_generation = next;
                    Ok(token_response(id, grant, access, now))
                }
                _ => anyhow::bail!("unsupported OAuth grant"),
            }
        })
    }
}
