use super::*;
use gent_crypto::invitation::{Invitation, Purpose};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    account: String,
    session: String,
    service: String,
    file: PathBuf,
    name: String,
    cluster: String,
}

pub(crate) fn pending(home: &Path) -> Result<Option<(PathBuf, String)>> {
    let path = home.join("auth/enrollment/pending-join.json");
    let Some(text) = storage::private(&path)?.text else {
        return Ok(None);
    };
    let saved: Pending = serde_json::from_str(&text)
        .map_err(|_| anyhow::anyhow!("invalid saved node invitation"))?;
    Ok(Some((saved.file, saved.name)))
}

pub async fn join(home: &Path, mut args: crate::pairing::JoinArgs) -> Result<Value> {
    if !args.code_route()? {
        return crate::node_home::provision::join(home, args).await;
    }
    ensure!(
        args.name.is_empty(),
        "the invitation code supplies the node name; omit --name"
    );
    let raw = match (&args.cluster, &args.code_file) {
        (Some(code), None) => Zeroizing::new(code.clone()),
        (None, Some(file)) => Zeroizing::new(
            storage::private(file)?
                .text
                .context("code file is missing")?,
        ),
        (None, None) => prompt("Node invitation code: ")?,
        _ => anyhow::bail!("supply either a code or --code-file"),
    };
    let code = Code::parse(raw.trim())?;
    let id = code.id();
    if crate::managed_file::Snapshot::read(&gent_daemon::config::path(home))?
        .text
        .is_some()
    {
        let saved = home
            .join("auth/enrollment")
            .join(format!("{id}.gent-invite"));
        ensure!(
            storage::private(&saved)?.text.is_some(),
            "this node is already enrolled; run gent node reset before joining with a new code"
        );
    }
    // The code authenticates encrypted bootstrap data; it never selects an origin.
    if io::stdin().is_terminal() && io::stderr().is_terminal() {
        auth::execute(
            home,
            auth::Command::Login {
                headless: true,
                no_browser: false,
                service: None,
            },
        )
        .await?;
    }
    let directory = storage::directory(home)?;
    let _lock = managed_file::lock(&directory.join("joining.lock"))?;
    let service = auth::Service::open(home).await?;
    let file = directory.join(format!("{id}.gent-invite"));
    let snapshot = storage::private(&file)?;
    if snapshot.text.is_none() {
        let record = service.pairing_read(&id).await.context("node invitation unavailable; check the code or run gent node add NAME on the existing node for a fresh invitation")?;
        ensure!(
            record.created_at <= auth::now()?.saturating_add(60)
                && record.expires_at > auth::now()?,
            "node invitation expired or is from the future"
        );
        let bytes = code.open(
            &service.session.account_id,
            &record.cluster_id,
            record.created_at,
            true,
            &record.capsule,
        )?;
        let invitation = Invitation::decode(&bytes)?;
        let offer = &invitation.offer().offer;
        ensure!(
            offer.anchor.cluster_id == record.cluster_id
                && offer.id == record.invitation_id
                && offer.issued_at == record.created_at
                && offer.expires_at == record.expires_at,
            "service changed the invitation binding"
        );
        invitation.offer().verify(&offer.anchor, auth::now()?)?;
        service.check_invitation_service(&offer.service)?;
        snapshot.write(std::str::from_utf8(&bytes).context("invalid invitation encoding")?)?;
    }
    let invitation = crate::invitations::decode_file(&file)?;
    let offer = &invitation.offer().offer;
    let Purpose::NamedNode { name, .. } = &offer.purpose else {
        anyhow::bail!("this code is not a named node invitation");
    };
    ensure!(
        offer.replaces.is_none(),
        "node code cannot replace an existing identity"
    );
    service.check_invitation_service(&offer.service)?;
    let journal = directory.join("pending-join.json");
    let snapshot = storage::private(&journal)?;
    if let Some(text) = &snapshot.text {
        let saved: Pending = serde_json::from_str(text)
            .map_err(|_| anyhow::anyhow!("invalid saved node invitation"))?;
        ensure!(
            saved.account == service.session.account_id
                && saved.session == service.session_hash()
                && saved.service == service.origin()?.as_str()
                && saved.file == file
                && saved.name == *name
                && saved.cluster == offer.anchor.cluster_id,
            "another node join is pending; resume its original code and login"
        );
    } else {
        storage::write(
            &journal,
            &Pending {
                account: service.session.account_id.clone(),
                session: service.session_hash(),
                service: service.origin()?.to_string(),
                file: file.clone(),
                name: name.clone(),
                cluster: offer.anchor.cluster_id.clone(),
            },
        )?;
    }
    drop(service);
    args.name.clone_from(name);
    let install = !args.no_daemon;
    let mut result = crate::node_home::provision::join(
        home,
        args.with_invitation(file, offer.anchor.cluster_id.clone()),
    )
    .await?;
    storage::private(&journal)?.remove()?;
    if install {
        let status = crate::service::execute(
            home,
            crate::DaemonCommand::Install {
                local: None,
                setup: crate::setup::Options::default(),
            },
        )
        .await
        .context("node enrolled; finish starting its daemon with gent daemon install")?;
        result["daemon"] = status["daemon"].clone();
    }
    result["pairing"] = json!("code_verified");
    result["next"] = json!(
        "Connect agents with gent integration install codex or gent integration install claude-code."
    );
    Ok(result)
}
