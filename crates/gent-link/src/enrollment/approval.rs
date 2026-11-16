use super::*;
use gent_protocol::service::pairing::Approval;

#[derive(clap::Args)]
pub struct ApproveArgs {
    /// Read the secret pairing code from an owner-private file instead of a prompt.
    #[arg(long)]
    code_file: Option<PathBuf>,
    /// Approve the displayed node without an interactive confirmation.
    #[arg(long)]
    yes: bool,
    /// Give the node messaging access without permission to change cluster configuration.
    #[arg(long)]
    no_configure: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    session: String,
    cluster: String,
    node: String,
    request: String,
    can_configure: bool,
    response: String,
}

pub async fn approve(home: &Path, args: ApproveArgs) -> Result<Value> {
    let raw = match &args.code_file {
        Some(path) => Zeroizing::new(
            storage::private(path)?
                .text
                .context("pairing code file is missing")?,
        ),
        None => prompt("Pairing code from the new device: ")?,
    };
    let code = Code::parse(raw.trim())?;
    let id = code.id();
    let cfg = config::load(home)?;
    let directory = storage::directory(home)?.join("approvals");
    config::private_dir(&directory)?;
    let _lock = managed_file::lock(&directory.join("lock"))?;
    storage::clean_approvals(&directory, auth::now()?)?;
    let service = auth::Service::open(home).await?;
    let account = cfg
        .service
        .as_ref()
        .context("this node is not enrolled with a Gent service")?;
    ensure!(
        service.session.account_id == account.account_id
            && service.origin()? == auth::origin(&account.origin)?,
        "sign into this node's original account and service"
    );
    let record = service.pairing_read(&id).await?;
    check_record(&record, &id, &cfg.cluster.id, record.created_at)?;
    ensure!(
        record.created_at <= auth::now()?.saturating_add(60) && record.expires_at > auth::now()?,
        "pairing code expired or is from the future"
    );
    let bytes = code.open(
        &account.account_id,
        &cfg.cluster.id,
        record.created_at,
        false,
        &record.request,
    )?;
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid encrypted pairing request"))?;
    ensure!(
        request.version == 1 && auth::origin(&request.service)? == service.origin()?,
        "pairing request belongs to a different service"
    );
    config::label(&request.name)?;
    let path = directory.join(format!("{id}.json"));
    let snapshot = storage::private(&path)?;
    let saved: Option<Saved> = snapshot
        .text
        .as_deref()
        .map(|s| {
            serde_json::from_str(s).map_err(|_| anyhow::anyhow!("invalid pairing approval journal"))
        })
        .transpose()?;
    let session = service.session_hash();
    drop(service);
    let response = if let Some(saved) = saved {
        ensure!(
            saved.session == session
                && saved.cluster == cfg.cluster.id
                && saved.node == cfg.node.id
                && saved.request == record.request
                && saved.can_configure == !args.no_configure,
            "pairing approval options or login changed"
        );
        saved.response
    } else {
        ensure!(
            record.response.is_none(),
            "pairing was already approved elsewhere; resume enrollment on the new device"
        );
        eprintln!(
            "Device: {}\nCluster: {}\nConfiguration access: {}",
            request.name, cfg.cluster.name, !args.no_configure
        );
        ensure!(
            args.yes || prompt("Approve this device? [y/N] ")?.eq_ignore_ascii_case("y"),
            "pairing was not approved"
        );
        let invitation_file = directory.join(format!("{id}.gent-invite"));
        crate::invitations::create(
            home,
            crate::invitations::InviteArgs::pairing(invitation_file.clone(), !args.no_configure),
        )
        .await?;
        let invitation = storage::private(&invitation_file)?
            .text
            .context("missing locally created invitation")?;
        let response = code.seal(
            &account.account_id,
            &cfg.cluster.id,
            record.created_at,
            true,
            invitation.as_bytes(),
        )?;
        storage::write(
            &path,
            &Saved {
                session: session.clone(),
                cluster: cfg.cluster.id.clone(),
                node: cfg.node.id.clone(),
                request: record.request.clone(),
                can_configure: !args.no_configure,
                response: response.clone(),
            },
        )?;
        response
    };
    finish(home, &id, &record, &cfg, &session, &response, &request.name).await
}

async fn finish(
    home: &Path,
    id: &str,
    record: &Record,
    cfg: &gent_daemon::config::Config,
    session: &str,
    response: &str,
    name: &str,
) -> Result<Value> {
    let service = auth::Service::open(home).await?;
    ensure!(
        service.session_hash() == session,
        "sign-in changed during pairing approval; resume with the original login"
    );
    let result = service
        .pairing_approve(
            id,
            &Approval {
                owner_node_id: cfg.node.id.clone(),
                response: response.into(),
            },
        )
        .await?;
    check_record(&result, id, &cfg.cluster.id, record.created_at)?;
    ensure!(
        result.request == record.request && result.response.as_deref() == Some(response),
        "pairing service changed approved ciphertext"
    );
    Ok(
        json!({"approved":true,"device":name,"cluster":cfg.cluster.name,"expires_at":record.expires_at,"next":"The new device will finish enrollment through Gent. Start its daemon with gent daemon install."}),
    )
}
