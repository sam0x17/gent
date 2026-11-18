use super::*;
use gent_crypto::invitation::{Invitation, Purpose};

#[cfg(test)]
mod tests;

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
    if let Some(native) = crate::invitations::installation(home)? {
        ensure!(
            native.name == saved.name && native.offer.offer.anchor.cluster_id == saved.cluster,
            "saved join destination disagrees with its identity journal; existing identity was preserved"
        );
        if crate::invitations::decode_file(&saved.file)?.offer() != &native.offer {
            // The native journal commits a replacement before this convenience
            // record. Recover that crash boundary using the exact signed offer.
            for (index, entry) in std::fs::read_dir(home.join("auth/enrollment"))?.enumerate() {
                ensure!(index < 512, "saved invitation cache exceeds capacity");
                let path = entry?.path();
                if path.extension().is_some_and(|ext| ext == "gent-invite")
                    && crate::invitations::decode_file(&path)?.offer() == &native.offer
                {
                    return Ok(Some((path, saved.name)));
                }
            }
            anyhow::bail!(
                "the current invitation file is missing; enter its code again; existing identity was preserved"
            );
        }
    }
    Ok(Some((saved.file, saved.name)))
}

pub async fn join(home: &Path, args: crate::pairing::JoinArgs) -> Result<Value> {
    let preference = args.discover_chats;
    let interactive = crate::setup::interactive(crate::ui::human() && !args.no_input);
    let finish = !args.no_daemon && (args.code_route()? || interactive);
    let mut result = join_inner(home, args).await?;
    if finish {
        crate::setup::after_join(home, &mut result, interactive, preference).await?;
    } else {
        crate::setup::discovery(home, &mut result, preference, interactive)?;
    }
    Ok(result)
}

async fn join_inner(home: &Path, mut args: crate::pairing::JoinArgs) -> Result<Value> {
    if !args.code_route()? {
        return crate::node_home::provision::join(home, args).await;
    }
    ensure!(
        args.name.is_empty(),
        "the invitation code supplies the node name; omit --name"
    );
    let resume = if args.cluster.is_none() && args.code_file.is_none() {
        pending(home)?
    } else {
        None
    };
    let code = if resume.is_some() {
        None
    } else {
        let raw = match (&args.cluster, &args.code_file) {
            (Some(code), None) => Zeroizing::new(code.clone()),
            (None, Some(file)) => Zeroizing::new(
                storage::private(file)?
                    .text
                    .context("code file is missing")?,
            ),
            (None, None) => {
                ensure!(
                    crate::setup::interactive(crate::ui::human() && !args.no_input),
                    "provide a node invitation code or --code-file for noninteractive joining"
                );
                prompt("Node invitation code: ")?
            }
            _ => anyhow::bail!("supply either a code or --code-file"),
        };
        Some(Code::parse(raw.trim())?)
    };
    let directory = home.join("auth/enrollment");
    let file = match (&code, resume) {
        (Some(code), _) => directory.join(format!("{}.gent-invite", code.id())),
        (None, Some((file, _))) => file,
        _ => unreachable!("code or saved invitation selected"),
    };
    if crate::managed_file::Snapshot::read(&gent_daemon::config::path(home))?
        .text
        .is_some()
    {
        ensure!(
            storage::private(&file)?.text.is_some()
                || crate::invitations::installation(home)?.is_some_and(|saved| !saved.complete),
            "this node is already enrolled; run gent node reset before joining with a new code"
        );
    }
    // The code authenticates encrypted bootstrap data; it never selects an origin.
    storage::directory(home)?;
    if crate::setup::interactive(crate::ui::human() && !args.no_input) {
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
    let _lock = managed_file::lock(&directory.join("joining.lock"))?;
    let service = auth::Service::open(home).await?;
    let snapshot = storage::private(&file)?;
    if snapshot.text.is_none() {
        let code = code
            .as_ref()
            .context("saved invitation is missing; enter its original code")?;
        let record = service.pairing_read(&code.id()).await.context("node invitation unavailable; check the code or run gent node add NAME on the existing node for a fresh invitation")?;
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
    if let Some((_, expected)) = code.as_ref().and_then(Code::names) {
        ensure!(
            expected == name,
            "invitation code and signed node name differ"
        );
    }
    service.check_invitation_service(&offer.service)?;
    let journal = directory.join("pending-join.json");
    let snapshot = storage::private(&journal)?;
    if let Some(text) = &snapshot.text {
        let saved: Pending = serde_json::from_str(text)
            .map_err(|_| anyhow::anyhow!("invalid saved node invitation"))?;
        ensure!(
            saved.account == service.session.account_id
                && saved.service == service.origin()?.as_str()
                && saved.name == *name
                && saved.cluster == offer.anchor.cluster_id,
            "a join for node {} is pending; run gent cluster join to resume it; this code names a different destination or account",
            saved.name
        );
    }
    // The native journal verifies the owner, cluster, privileges and exact
    // continuation key. A different code can never silently change identity.
    crate::invitations::prepare_code_join(home, invitation.offer(), name, &service.session_hash())?;
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
    drop(service);
    if io::stderr().is_terminal() {
        if let Some((cluster, _)) = code.as_ref().and_then(Code::names) {
            eprintln!("Joining cluster {cluster} as {name}...");
        } else {
            eprintln!("Joining as {name}...");
        }
    }
    args.name.clone_from(name);
    let mut result = crate::node_home::provision::join(
        home,
        args.with_invitation(file, offer.anchor.cluster_id.clone()),
    )
    .await.with_context(|| format!(
        "join for node {name} is saved; retry with gent cluster join; if the invitation expires, run gent node add {name} on an existing node and join with the fresh code"
    ))?;
    storage::private(&journal)?.remove()?;
    result["pairing"] = json!("code_verified");
    result["next"] = json!(
        "Connect chats with gent integration install codex or gent integration install claude-code."
    );
    Ok(result)
}
