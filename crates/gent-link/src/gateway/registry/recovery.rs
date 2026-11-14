//! Owner-prepared bindings. A pending record reserves the conversation while
//! daemon registration and historical assignment commit outside the registry.
use super::*;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum Binding {
    Credential(String),
    Recovery(Recovered),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Recovered {
    version: u8,
    fingerprint: String,
    credential: String,
    completed: Option<Completed>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completed {
    agent_id: String,
    import_id: String,
}

impl From<String> for Binding {
    fn from(value: String) -> Self {
        Self::Credential(value)
    }
}

impl Binding {
    pub(super) fn valid(&self) -> bool {
        match self {
            Self::Credential(value) => hash(value),
            Self::Recovery(value) => {
                value.version == 1
                    && hash(&value.fingerprint)
                    && hash(&value.credential)
                    && value
                        .completed
                        .as_ref()
                        .is_none_or(|c| uuid(&c.agent_id) && uuid(&c.import_id))
            }
        }
    }

    pub(super) fn credential(&self) -> Result<&str> {
        match self {
            Self::Credential(value) => Ok(value),
            Self::Recovery(value) => {
                ensure!(
                    value.completed.is_some(),
                    "binding recovery is pending; rerun the same gent agent recover command"
                );
                Ok(&value.credential)
            }
        }
    }
}

// No raw host conversation/user metadata is persisted or returned. This ticket
// contains an endpoint secret and must not implement Debug or Serialize.
pub(crate) struct Ticket {
    client: String,
    key: String,
    fingerprint: String,
    pub(crate) credential: String,
}

fn client<'a>(state: &'a State, id: &str, now: u64) -> Result<&'a Client> {
    ensure!(now >= state.clock, "gateway clock moved backward");
    let client = state.clients.get(id).context("unknown recovery host")?;
    ensure!(
        !client.revoked && now < client.expires_at,
        "recovery host is inactive"
    );
    conversation_key(&client.conversation_key)?;
    Ok(client)
}

impl Registry {
    pub(crate) fn prepare_recovery(
        &self,
        client_id: &str,
        conversation: &str,
        subject: Option<&str>,
        request: &str,
    ) -> Result<Ticket> {
        bindings::identity_value(conversation)?;
        ensure!(hash(request), "invalid recovery request fingerprint");
        directory_check(&self.directory())?;
        let _lock = managed_file::lock(&self.directory().join("state.lock"))?;
        let mut state = self.read()?;
        let now = auth::now()?;
        let client = client(&state, client_id, now)?;
        ensure!(
            client.subject_key.is_some() == subject.is_some(),
            "supply --subject exactly when the gateway host requires user metadata"
        );
        let subject = subject
            .map(|value| {
                bindings::identity_value(value)
                    .map(|value| bindings::subject_hash(client_id, value))
            })
            .transpose()?;
        let key = bindings::binding_key(conversation, subject.as_deref());
        let fingerprint = digest(
            &json!([
                "gent-gateway-recovery-v1",
                self.id,
                self.cluster,
                self.node,
                client_id,
                key,
                request
            ])
            .to_string(),
        );
        let credential = match client.bindings.get(&key) {
            Some(Binding::Credential(_)) => anyhow::bail!(
                "recovery requires an unused gateway binding; use history import for an existing agent"
            ),
            Some(Binding::Recovery(saved)) => {
                ensure!(
                    saved.fingerprint == fingerprint,
                    "gateway recovery arguments changed"
                );
                saved.credential.clone()
            }
            None => {
                ensure!(
                    client.bindings.len() < MAX_CLIENT_BINDINGS
                        && state
                            .clients
                            .values()
                            .map(|c| c.bindings.len())
                            .sum::<usize>()
                            < MAX_BINDINGS,
                    "gateway conversation capacity reached"
                );
                config::secret()
            }
        };
        state
            .clients
            .get_mut(client_id)
            .expect("client checked")
            .bindings
            .entry(key.clone())
            .or_insert_with(|| {
                Binding::Recovery(Recovered {
                    version: 1,
                    fingerprint: fingerprint.clone(),
                    credential: credential.clone(),
                    completed: None,
                })
            });
        state.version = 7;
        state.clock = now;
        self.save(&state)?;
        Ok(Ticket {
            client: client_id.into(),
            key,
            fingerprint,
            credential,
        })
    }

    pub(crate) fn complete_recovery(&self, ticket: &Ticket, result: &Value) -> Result<()> {
        let completed = Completed {
            agent_id: result["agent"]["id"]
                .as_str()
                .filter(|s| uuid(s))
                .context("invalid recovered agent response")?
                .into(),
            import_id: result["history"]["import_id"]
                .as_str()
                .filter(|s| uuid(s))
                .context("invalid recovered history response")?
                .into(),
        };
        directory_check(&self.directory())?;
        let _lock = managed_file::lock(&self.directory().join("state.lock"))?;
        let mut state = self.read()?;
        let now = auth::now()?;
        client(&state, &ticket.client, now)?;
        let binding = state
            .clients
            .get_mut(&ticket.client)
            .expect("client checked")
            .bindings
            .get_mut(&ticket.key)
            .context("gateway recovery disappeared")?;
        let Binding::Recovery(saved) = binding else {
            anyhow::bail!("gateway recovery was replaced");
        };
        ensure!(
            saved.fingerprint == ticket.fingerprint && saved.credential == ticket.credential,
            "gateway recovery changed"
        );
        ensure!(
            saved
                .completed
                .as_ref()
                .is_none_or(|previous| previous == &completed),
            "gateway recovery identity changed"
        );
        saved.completed = Some(completed);
        state.clock = now;
        self.save(&state)
    }
}
