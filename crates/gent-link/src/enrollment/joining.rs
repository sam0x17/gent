use super::*;
use gent_protocol::service::pairing::Registration;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    version: u8,
    code: String,
    cluster: String,
    account: String,
    service: String,
    session: String,
    name: String,
    created: u64,
    request: String,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

pub(crate) fn pending(home: &Path) -> Result<Option<(String, String)>> {
    let directory = home.join("auth/enrollment");
    if !directory.exists() {
        return Ok(None);
    }
    config::private_dir(&directory)?;
    let mut found = None;
    for (index, entry) in std::fs::read_dir(directory)?.enumerate() {
        ensure!(index < 128, "pairing journal exceeds capacity");
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("joining-") && n.ends_with(".json"))
        {
            let snapshot = storage::private(&path)?;
            let saved: Pending = serde_json::from_str(
                snapshot
                    .text
                    .as_deref()
                    .context("missing pairing request")?,
            )
            .map_err(|_| anyhow::anyhow!("invalid saved pairing request"))?;
            ensure!(
                found.is_none(),
                "multiple pending pairings; resume gent cluster join with an explicit cluster ID and node name"
            );
            found = Some((saved.cluster.clone(), saved.name.clone()));
        }
    }
    Ok(found)
}

async fn cluster(service: &auth::Service, selected: Option<&str>) -> Result<String> {
    let available = service.available_clusters().await?;
    if let Some(selected) = selected {
        ensure!(
            available.iter().any(|c| c.id == selected),
            "this account does not own the requested cluster"
        );
        return Ok(selected.into());
    }
    ensure!(
        !available.is_empty(),
        "No clusters yet. Create one on your first machine with gent cluster new NAME."
    );
    if available.len() == 1 {
        return Ok(available[0].id.clone());
    }
    eprintln!("Choose a cluster:");
    for (index, c) in available.iter().enumerate() {
        eprintln!("  {}. {}", index + 1, c.id);
    }
    let choice = prompt("Cluster number: ")?
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|n| available.get(n));
    Ok(choice
        .context("select a listed cluster, or pass its ID to gent cluster join")?
        .id
        .clone())
}

pub async fn join(root: &Path, home: &Path, args: crate::pairing::JoinArgs) -> Result<Value> {
    if !args.code_route()? {
        return crate::contexts::provision::join(root, home, args).await;
    }
    config::label(&args.name)?;
    ensure!(
        args.code_out.is_some() || io::stderr().is_terminal(),
        "run pairing in a terminal, or use --code-out PRIVATE_FILE for automation"
    );
    let directory = storage::directory(home)?;
    let _lock = managed_file::lock(&directory.join("joining.lock"))?;
    let service = auth::Service::open(home).await?;
    let selected = cluster(&service, args.cluster.as_deref()).await?;
    let journal = directory.join(format!("joining-{selected}.json"));
    let snapshot = storage::private(&journal)?;
    let mut saved: Option<Pending> = snapshot
        .text
        .as_deref()
        .map(|s| {
            serde_json::from_str(s).map_err(|_| anyhow::anyhow!("invalid saved pairing request"))
        })
        .transpose()?;
    if args.new_pairing {
        if let Some(old) = &saved {
            let old_code = Code::parse(&old.code)?;
            ensure!(
                !directory
                    .join(format!("{}.gent-invite", old_code.id()))
                    .exists(),
                "an invitation was already received; resume the original join before starting another pairing"
            );
            ensure!(
                auth::now()? >= old.created.saturating_add(LIFETIME),
                "the current code has not expired; resume its join"
            );
        }
        saved = None;
    }
    let pending = match saved {
        Some(value) => value,
        None => {
            let code = Code::generate()?;
            let created = auth::now()?;
            let request = Request {
                version: 1,
                name: args.name.clone(),
                service: service.origin()?.to_string(),
            };
            let value = Pending {
                version: 1,
                code: code.expose().to_string(),
                cluster: selected.clone(),
                account: service.session.account_id.clone(),
                service: service.origin()?.to_string(),
                session: service.session_hash(),
                name: args.name.clone(),
                created,
                request: code.seal(
                    &service.session.account_id,
                    &selected,
                    created,
                    false,
                    &serde_json::to_vec(&request)?,
                )?,
            };
            storage::write(&journal, &value)?;
            value
        }
    };
    ensure!(
        pending.version == 1
            && pending.cluster == selected
            && pending.account == service.session.account_id
            && pending.service == service.origin()?.as_str()
            && pending.session == service.session_hash()
            && pending.name == args.name,
        "saved pairing belongs to different options or login; use its original name, cluster and account session"
    );
    let code = Code::parse(&pending.code)?;
    let id = code.id();
    let file = directory.join(format!("{id}.gent-invite"));
    if !file.exists() {
        ensure!(
            auth::now()? < pending.created.saturating_add(LIFETIME),
            "pairing code expired before enrollment; rerun with --new-pairing"
        );
        let registered = service
            .pairing_create(
                &id,
                &Registration {
                    cluster_id: selected.clone(),
                    created_at: pending.created,
                    request: pending.request.clone(),
                },
            )
            .await?;
        check_record(&registered, &id, &selected, pending.created)?;
        ensure!(
            registered.request == pending.request,
            "pairing service changed encrypted request"
        );
        if let Some(path) = &args.code_out {
            storage::code_file(&managed_file::normalize(path)?, &code)?;
        } else {
            eprintln!(
                "Pairing code: {}\nOn an enrolled owner node, run gent cluster approve and enter this code.\nKeep it private. It expires in 15 minutes.",
                code.expose().as_str()
            );
        }
        eprintln!("Waiting for approval...");
        let mut record = registered;
        loop {
            ensure!(
                auth::now()? < pending.created.saturating_add(LIFETIME),
                "pairing expired; rerun with --new-pairing before an invitation is received"
            );
            check_record(&record, &id, &selected, pending.created)?;
            ensure!(
                record.request == pending.request,
                "pairing service changed encrypted request"
            );
            if let Some(response) = &record.response {
                let bytes =
                    code.open(&pending.account, &selected, pending.created, true, response)?;
                let invitation = gent_crypto::invitation::Invitation::decode(&bytes)?;
                ensure!(
                    invitation.offer().offer.anchor.cluster_id == selected
                        && invitation.offer().offer.replaces.is_none()
                        && matches!(
                            invitation.offer().offer.purpose,
                            gent_crypto::invitation::Purpose::NewNode
                        ),
                    "pairing approval has a different cluster or purpose"
                );
                service.check_invitation_service(&invitation.offer().offer.service)?;
                invitation
                    .offer()
                    .verify(&invitation.offer().offer.anchor, auth::now()?)?;
                storage::private(&file)?
                    .write(std::str::from_utf8(&bytes).context("invalid invitation encoding")?)?;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            record = service
                .pairing_read(&id)
                .await
                .context("pairing interrupted; rerun the same command to resume")?;
        }
    }
    drop(service); // Existing enrollment opens the same login lock.
    let mut result =
        crate::contexts::provision::join(root, home, args.with_invitation(file, selected)).await?;
    result["pairing"] = json!("code_verified");
    result["next"] = json!(
        "Run gent daemon install, then connect your agents with gent integration install codex or gent integration install claude-code."
    );
    Ok(result)
}
