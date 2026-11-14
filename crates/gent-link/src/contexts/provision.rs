//! A primary-directory journal reserves a physical profile before setup. Node
//! enrollment keeps using its existing journals. No account bearer is copied.
use super::*;
use crate::{auth, cluster};
use gent_daemon::config::AccountSource;
use serde::{Deserialize, Serialize};
use std::fs;
use uuid::Uuid;

const JOURNAL: &str = "profile-setup.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Intent {
    New {
        name: String,
        local: bool,
    },
    Join {
        cluster: String,
        name: String,
        route: Value,
    },
}
impl Intent {
    fn key(&self) -> String {
        match self {
            Self::New { name, local } => format!("new:{local}:{name}"),
            Self::Join { cluster, .. } => format!("join:{cluster}"),
        }
    }
    fn validate(&self) -> Result<()> {
        let name = match self {
            Self::New { name, .. } | Self::Join { name, .. } => name,
        };
        config::label(name)?;
        if let Self::Join { cluster, route, .. } = self {
            ensure!(
                Uuid::parse_str(cluster).is_ok_and(|id| !id.is_nil() && id.to_string() == *cluster),
                "invalid joining cluster ID"
            );
            ensure!(
                serde_json::to_vec(route)?.len() <= 16384,
                "join routing metadata is too large"
            );
        }
        Ok(())
    }
    fn local(&self) -> bool {
        matches!(self, Self::New { local: true, .. })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    cluster: String,
    node: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    id: String,
    intent: Intent,
    source: Option<AccountSource>,
    initial: Option<Config>,
    complete: Option<Pin>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    id: String,
    cluster: String,
    node: String,
    jobs: Vec<Job>,
}

fn read(root: &Path, cfg: &Config) -> Result<Journal> {
    let snapshot = Snapshot::read(&root.join(JOURNAL))?;
    snapshot.private()?;
    let journal: Journal = match &snapshot.text {
        Some(text) => serde_json::from_str(text).map_err(|_| {
            anyhow::anyhow!("invalid profile setup journal; restore it from backup")
        })?,
        None => {
            ensure!(
                cfg.profile_setup()?.is_none(),
                "profile setup journal is missing; restore it from backup"
            );
            Journal {
                version: 1,
                id: Uuid::new_v4().to_string(),
                cluster: cfg.cluster.id.clone(),
                node: cfg.node.id.clone(),
                jobs: vec![],
            }
        }
    };
    ensure!(
        journal.version == 1
            && journal.cluster == cfg.cluster.id
            && journal.node == cfg.node.id
            && journal.jobs.len() <= Contexts::LIMIT,
        "profile setup journal belongs to another node or exceeds its limit"
    );
    ensure!(
        Uuid::parse_str(&journal.id).is_ok_and(|id| !id.is_nil() && id.to_string() == journal.id),
        "invalid profile journal identity"
    );
    match cfg.profile_setup()? {
        Some(id) => ensure!(id == journal.id, "profile setup journal identity changed"),
        None => ensure!(
            journal.jobs.is_empty(),
            "profile setup registry pin is missing; restore it"
        ),
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut keys = std::collections::BTreeSet::new();
    for job in &journal.jobs {
        job.intent.validate()?;
        ensure!(
            Uuid::parse_str(&job.id).is_ok_and(|id| !id.is_nil() && id.to_string() == job.id)
                && ids.insert(job.id.clone())
                && keys.insert(job.intent.key()),
            "invalid profile setup identity"
        );
        if let Some(source) = &job.source {
            source.validate()?;
        }
        ensure!(
            !job.intent.local() || job.source.is_none(),
            "local setup cannot share an account"
        );
        if matches!(
            &job.intent,
            Intent::New { local: false, .. } | Intent::Join { .. }
        ) && !matches!(&job.intent,Intent::Join {route,..} if route["kind"]=="ssh")
        {
            ensure!(
                job.source.is_some(),
                "service profile account source is missing"
            );
        }
        if let Some(pin) = &job.complete {
            for id in [&pin.cluster, &pin.node] {
                ensure!(
                    Uuid::parse_str(id).is_ok_and(|u| !u.is_nil() && u.to_string() == *id),
                    "invalid completed profile identity"
                );
            }
            if let Intent::Join { cluster, .. } = &job.intent {
                ensure!(
                    pin.cluster == *cluster,
                    "completed join belongs to another cluster"
                );
            }
        }
        ensure!(
            job.initial.is_some() == job.intent.local(),
            "invalid profile creation seed"
        );
        if let Some(initial) = &job.initial {
            initial.validate()?;
            ensure!(
                initial.version == 1
                    && initial.cluster.local_only
                    && initial.account_source()?.is_none(),
                "invalid local profile creation seed"
            );
            ensure!(
                matches!(&job.intent, Intent::New {name,..} if *name == initial.cluster.name)
                    && initial.service.is_none()
                    && initial.relay.is_none(),
                "local profile seed options changed"
            );
            if let Some(pin) = &job.complete {
                ensure!(
                    initial.cluster.id == pin.cluster && initial.node.id == pin.node,
                    "completed local seed changed"
                );
            }
        }
    }
    snapshot.verify()?;
    Ok(journal)
}
fn save(root: &Path, journal: &Journal) -> Result<()> {
    let snapshot = Snapshot::read(&root.join(JOURNAL))?;
    snapshot.private()?;
    snapshot.write(&(serde_json::to_string(journal)? + "\n"))
}

pub(super) fn pending(root: &Path, cfg: &Config) -> Result<Value> {
    let journal = read(root, cfg)?;
    Ok(json!(
        journal
            .jobs
            .iter()
            .filter(|j| j.complete.is_none())
            .map(|j| json!({"id":j.id,"intent":j.intent,
        "home":root.join("clusters").join(&j.id)}))
            .collect::<Vec<_>>()
    ))
}

pub(crate) enum Selection {
    Direct,
    Existing(PathBuf),
    Managed(Ticket),
}
pub(crate) struct Ticket {
    root: PathBuf,
    pub home: PathBuf,
    _lock: fs::File,
    journal: Journal,
    index: usize,
}

pub(crate) fn prepare(root: &Path, account_home: &Path, intent: Intent) -> Result<Selection> {
    intent.validate()?;
    let root = managed_file::normalize(root)?;
    if Snapshot::read(&config::path(&root))?.text.is_none() {
        return Ok(Selection::Direct);
    }
    inspect(&root)?;
    let lock = managed_file::lock(&root.join("profile-setup.lock"))?;
    let cfg = inspect(&root)?;
    // Finish the primary node's existing enrollment before reserving children.
    if cluster::installation(&root)?.is_some_and(|s| s.pending)
        || crate::invitations::installation(&root)?.is_some_and(|s| !s.complete)
        || config::pending_join(&root)?.exists()
    {
        return Ok(Selection::Direct);
    }
    let mut journal = read(&root, &cfg)?;
    let index = if let Some(index) = journal
        .jobs
        .iter()
        .position(|j| j.intent.key() == intent.key())
    {
        ensure!(
            journal.jobs[index].intent == intent,
            "profile setup options changed; rerun the original command"
        );
        index
    } else {
        let registry = registry(&root, &cfg)?;
        let mut existing = Vec::new();
        for (id, profile) in &registry.profiles {
            let Ok(current) = target(id, profile) else {
                continue;
            };
            let matches = match &intent {
                Intent::New { name, local } => {
                    current.cluster.local_only == *local
                        && (if *local {
                            current.cluster.name == *name
                        } else {
                            cluster::installation(&profile.home)?
                                .is_some_and(|i| i.owner && i.name == *name)
                        })
                }
                Intent::Join { cluster, name, .. } => {
                    if cluster == id {
                        ensure!(
                            current.node.name == *name,
                            "this cluster already has a local node; use gent cluster switch instead of joining again"
                        );
                    }
                    cluster == id
                }
            };
            if matches {
                existing.push(profile.home.clone());
            }
        }
        ensure!(
            existing.len() <= 1,
            "cluster name is ambiguous; select its ID with gent cluster switch"
        );
        if let Some(home) = existing.pop() {
            return Ok(Selection::Existing(home));
        }
        ensure!(
            journal.jobs.len() < Contexts::LIMIT
                && registry.profiles.len()
                    + journal.jobs.iter().filter(|j| j.complete.is_none()).count()
                    < Contexts::LIMIT,
            "cluster profile setup limit reached; finish pending setup before adding another profile"
        );
        let source = if intent.local() {
            None
        } else if matches!(&intent,Intent::Join {route,..} if route["kind"]=="ssh") {
            auth::source::optional(account_home)?
        } else {
            Some(auth::source::share(account_home)?)
        };
        let initial = match &intent {
            Intent::New { name, local: true } => Some(config::fresh(name)?),
            _ => None,
        };
        if cfg.profile_setup()?.is_none() {
            // Empty record first, pin second, jobs last. A crash at either of
            // the first two writes can resume without allocating an identity.
            save(&root, &journal)?;
            config::edit_local(&root, |cfg| cfg.set_profile_setup(journal.id.clone()))?;
        }
        journal.jobs.push(Job {
            id: Uuid::new_v4().to_string(),
            intent,
            source,
            initial,
            complete: None,
        });
        save(&root, &journal)?;
        journal.jobs.len() - 1
    };
    let home = root.join("clusters").join(&journal.jobs[index].id);
    ensure!(
        managed_file::normalize(&home)? == home,
        "profile setup directory changed"
    );
    let mut ticket = Ticket {
        root,
        home,
        _lock: lock,
        journal,
        index,
    };
    if ticket.journal.jobs[index].complete.is_none() {
        if ticket.journal.jobs[index].source.is_none()
            && !ticket.journal.jobs[index].intent.local()
            && let Some(source) = auth::source::optional(account_home)?
        {
            ticket.journal.jobs[index].source = Some(source);
            save(&ticket.root, &ticket.journal)?;
        }
        config::private_dir(ticket.home.parent().context("missing profiles directory")?)?;
        config::private_dir(&ticket.home)?;
        if let Some(source) = &ticket.journal.jobs[index].source {
            auth::source::link(&ticket.home, source)?;
        }
    } else {
        ticket.checked()?;
    }
    Ok(Selection::Managed(ticket))
}

impl Ticket {
    pub fn ready(&self) -> bool {
        self.journal.jobs[self.index].complete.is_some()
    }
    fn checked(&self) -> Result<Config> {
        let cfg = inspect(&self.home)?;
        let job = &self.journal.jobs[self.index];
        ensure!(
            auth::source::Location::open(&self.home)?.source == job.source,
            "profile account source does not match its setup record"
        );
        ensure!(
            cfg.account_source()? == job.source,
            "profile configuration lost its account source; restore it"
        );
        match &job.intent {
            Intent::New { local: true, .. } => {
                ensure!(cfg.cluster.local_only, "local profile transport changed")
            }
            Intent::New { name, local: false } => {
                let installed = cluster::installation(&self.home)?
                    .context("profile owner setup record is missing")?;
                ensure!(
                    installed.owner && installed.name == *name && !installed.pending,
                    "profile owner setup is incomplete or changed"
                );
            }
            Intent::Join {
                cluster,
                route,
                name,
            } => {
                ensure!(
                    cfg.cluster.id == *cluster,
                    "joined profile belongs to another cluster"
                );
                if route["kind"] == "invitation" {
                    let installed = crate::invitations::installation(&self.home)?
                        .context("profile invitation record is missing")?;
                    ensure!(
                        installed.complete
                            && installed.name == *name
                            && serde_json::to_value(&installed.offer.offer.anchor)?
                                == route["anchor"]
                            && installed.node.is_some_and(|node| node.id == cfg.node.id),
                        "profile invitation setup is incomplete or changed"
                    );
                }
            }
        }
        if let Some(pin) = &self.journal.jobs[self.index].complete {
            ensure!(
                cfg.cluster.id == pin.cluster && cfg.node.id == pin.node,
                "completed profile identity changed; restore its state"
            );
        }
        if let Some(initial) = &self.journal.jobs[self.index].initial {
            ensure!(
                cfg.cluster.id == initial.cluster.id && cfg.node.id == initial.node.id,
                "local profile identity changed"
            );
        }
        Ok(cfg)
    }
    pub fn initialize_local(&self) -> Result<()> {
        let Some(initial) = &self.journal.jobs[self.index].initial else {
            return Ok(());
        };
        if Snapshot::read(&config::path(&self.home))?.text.is_some() {
            self.checked()?;
            return Ok(());
        }
        let _service = config::state_lock(&self.home, "service.lock")?;
        let _daemon = config::state_lock(&self.home, "daemon.lock")?;
        if Snapshot::read(&config::path(&self.home))?.text.is_some() {
            self.checked()?;
            return Ok(());
        }
        ensure!(
            !self.ready()
                && !self.home.join("identity.key").exists()
                && !self.home.join("state.sqlite3").exists(),
            "profile configuration is missing; restore it before continuing"
        );
        config::binding(&self.home.join("owner.key"))?;
        config::save(&self.home, initial)
    }
    pub fn finish(&mut self, mut result: Value) -> Result<Value> {
        // Development SSH pairing has no service-provisioning callback. Seal
        // its local account reference before selecting the published profile.
        if !self.ready()
            && matches!(&self.journal.jobs[self.index].intent, Intent::Join {route,..} if route["kind"]=="ssh")
        {
            let cfg = inspect(&self.home)?;
            if cfg.service.is_none()
                && cfg.account_source()?.is_none()
                && let Some(source) = &self.journal.jobs[self.index].source
            {
                config::edit_local(&self.home, |cfg| cfg.set_account_source(source.clone()))?;
            }
        }
        let cfg = self.checked()?;
        let pin = Pin {
            cluster: cfg.cluster.id.clone(),
            node: cfg.node.id.clone(),
        };
        // Registration/selection is one local transaction. Saving completion
        // afterward is retryable if the final response or journal write is lost.
        config::edit_local(&self.root, |original| {
            let mut registry = registry(&self.root, original)?;
            let profile = ContextProfile {
                home: self.home.clone(),
                node_id: cfg.node.id.clone(),
            };
            if let Some(previous) = registry.profiles.get(&cfg.cluster.id) {
                ensure!(
                    previous == &profile,
                    "cluster is already registered with another profile"
                );
            } else {
                ensure!(
                    registry.profiles.len() < Contexts::LIMIT,
                    "cluster profile limit reached"
                );
                registry.profiles.insert(cfg.cluster.id.clone(), profile);
            }
            registry.active_cluster = cfg.cluster.id.clone();
            original.set_contexts(registry)
        })?;
        self.journal.jobs[self.index].complete = Some(pin);
        save(&self.root, &self.journal)?;
        result["profile"] = json!({"home":self.home,"cluster_id":cfg.cluster.id,"node_id":cfg.node.id,"selected":true});
        Ok(result)
    }
    pub fn existing_result(&self) -> Result<Value> {
        let cfg = self.checked()?;
        Ok(
            json!({"status":"configured","already_configured":true,"cluster":cfg.cluster,"node":cfg.node,
            "next":"gent daemon install"}),
        )
    }
}

#[cfg(test)]
mod tests;

fn select_existing(root: &Path, home: &Path, mut result: Value) -> Result<Value> {
    let cfg = inspect(home)?;
    super::switch(root, Some(cfg.cluster.id.clone()), false)?;
    result["profile"] =
        json!({"home":home,"cluster_id":cfg.cluster.id,"node_id":cfg.node.id,"selected":true});
    Ok(result)
}

pub(crate) async fn create(
    root: &Path,
    account_home: &Path,
    name: String,
    local: bool,
) -> Result<Value> {
    match prepare(
        root,
        account_home,
        Intent::New {
            name: name.clone(),
            local,
        },
    )? {
        Selection::Direct => {
            if local {
                Ok(json!(cluster::local(root, &name)?))
            } else {
                cluster::connect(root, Some(&name)).await
            }
        }
        Selection::Existing(home) => {
            let cfg = inspect(&home)?;
            let result = if local
                || cluster::installation(&home)?.is_some_and(|s| !s.pending && s.owner)
            {
                json!({"status":"configured","already_configured":true,"cluster":cfg.cluster,"node":cfg.node})
            } else {
                cluster::connect(&home, Some(&name)).await?
            };
            select_existing(root, &home, result)
        }
        Selection::Managed(mut ticket) => {
            let result = if ticket.ready() {
                ticket.existing_result()?
            } else if local {
                ticket.initialize_local()?;
                ticket.existing_result()?
            } else if cluster::installation(&ticket.home)?.is_some_and(|s| !s.pending) {
                ticket.existing_result()?
            } else {
                cluster::connect(&ticket.home, Some(&name)).await?
            };
            ticket.finish(result)
        }
    }
}

pub(crate) async fn join(
    root: &Path,
    account_home: &Path,
    args: crate::pairing::JoinArgs,
) -> Result<Value> {
    match prepare(root, account_home, args.intent()?)? {
        Selection::Direct => crate::pairing::join(root, args).await,
        Selection::Existing(home) => {
            let result = match args.existing(&home)? {
                Some(value) => value,
                None => crate::pairing::join(&home, args).await?,
            };
            select_existing(root, &home, result)
        }
        Selection::Managed(mut ticket) => {
            let result = match args.existing(&ticket.home)? {
                Some(value) => value,
                None => {
                    ensure!(
                        !ticket.ready(),
                        "completed join state is missing; restore it"
                    );
                    crate::pairing::join(&ticket.home, args).await?
                }
            };
            ticket.finish(result)
        }
    }
}

pub(crate) async fn install(
    root: &Path,
    account_home: &Path,
    local: Option<String>,
    mut options: crate::setup::Options,
    human: bool,
) -> Result<Value> {
    let Some(intent) = options.intent(local.as_deref(), human)? else {
        return crate::setup::install(account_home, local, options, human).await;
    };
    let selected = match prepare(root, account_home, intent.clone()) {
        Err(error)
            if error
                .downcast_ref::<auth::source::LoginRequired>()
                .is_some() =>
        {
            options.profile_login(account_home, human).await?;
            prepare(root, account_home, intent)?
        }
        result => result?,
    };
    match selected {
        Selection::Direct => crate::setup::install(root, local, options, human).await,
        Selection::Existing(home) => {
            let result = crate::setup::install(&home, local, options, human).await?;
            select_existing(root, &home, result)
        }
        Selection::Managed(mut ticket) => {
            ticket.initialize_local()?;
            let result = crate::setup::install(&ticket.home, local, options, human).await?;
            ticket.finish(result)
        }
    }
}
