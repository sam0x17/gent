use super::*;
use gent_protocol::service::pairing::Registration;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(clap::Args)]
pub struct AddArgs {
    /// Name assigned to the new node by this invitation.
    name: String,
    /// Enroll a messaging-only node without cluster configuration rights.
    #[arg(long)]
    no_configure: bool,
    /// Write the code to a private file instead of displaying it in a terminal.
    #[arg(long)]
    code_out: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    code: String,
    cluster: String,
    node: String,
    session: String,
    name: String,
    configure: bool,
    created: u64,
    registration: Option<Registration>,
}
impl Drop for Saved {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

pub async fn add(home: &Path, args: AddArgs) -> Result<Value> {
    config::label(&args.name)?;
    ensure!(
        args.code_out.is_some() || io::stderr().is_terminal(),
        "run node add in a terminal, or use --code-out PRIVATE_FILE"
    );
    let cfg = config::load(home)?;
    let directory = storage::directory(home)?.join("issued");
    config::private_dir(&directory)?;
    let _lock = managed_file::lock(&directory.join("lock"))?;
    for (index, entry) in std::fs::read_dir(&directory)?.enumerate() {
        ensure!(index < 512, "node invitation journal exceeds capacity");
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let snapshot = storage::private(&path)?;
            let saved: Saved = serde_json::from_str(
                snapshot
                    .text
                    .as_deref()
                    .context("missing node invitation journal")?,
            )
            .map_err(|_| anyhow::anyhow!("invalid node invitation journal"))?;
            if saved.created.saturating_add(LIFETIME) <= auth::now()? {
                snapshot.remove()?;
            }
        }
    }
    storage::clean_approvals(&directory, auth::now()?)?;
    let key = format!("{:x}", Sha256::digest(args.name.as_bytes()));
    let path = directory.join(format!("{key}.json"));
    let snapshot = storage::private(&path)?;
    let service = auth::Service::open(home).await?;
    let account = cfg
        .service
        .as_ref()
        .context("this node needs a service cluster")?;
    ensure!(
        service.session.account_id == account.account_id
            && service.origin()? == auth::origin(&account.origin)?,
        "sign into this node's original account and service"
    );
    let saved: Option<Saved> = snapshot
        .text
        .as_deref()
        .map(|s| {
            serde_json::from_str(s).map_err(|_| anyhow::anyhow!("invalid node invitation journal"))
        })
        .transpose()?;
    let mut saved = match saved {
        Some(value) if value.created.saturating_add(LIFETIME) > auth::now()? => value,
        _ => {
            let value = Saved {
                code: Code::named(&cfg.cluster.name, &args.name)?
                    .expose()
                    .to_string(),
                cluster: cfg.cluster.id.clone(),
                node: cfg.node.id.clone(),
                session: service.session_hash(),
                name: args.name.clone(),
                configure: !args.no_configure,
                created: auth::now()?,
                registration: None,
            };
            storage::write(&path, &value)?;
            value
        }
    };
    ensure!(
        saved.cluster == cfg.cluster.id
            && saved.node == cfg.node.id
            && saved.session == service.session_hash()
            && saved.name == args.name
            && saved.configure == !args.no_configure,
        "node invitation options or issuing login changed; resume with the original options"
    );
    let code = Code::parse(&saved.code)?;
    let file = directory.join(format!("{}.gent-invite", code.id()));
    drop(service);
    if saved.registration.is_none() {
        crate::invitations::create(
            home,
            crate::invitations::InviteArgs::pairing(
                file.clone(),
                saved.configure,
                saved.name.clone(),
            ),
        )
        .await?;
        let invitation = crate::invitations::decode_file(&file)?;
        let offer = &invitation.offer().offer;
        let capsule = code.seal(
            &account.account_id,
            &cfg.cluster.id,
            offer.issued_at,
            true,
            &invitation.encode()?,
        )?;
        saved.registration = Some(Registration {
            cluster_id: cfg.cluster.id.clone(),
            owner_node_id: cfg.node.id.clone(),
            invitation_id: offer.id.clone(),
            created_at: offer.issued_at,
            capsule,
        });
        storage::write(&path, &saved)?;
    }
    let registration = saved.registration.as_ref().expect("saved registration");
    let service = auth::Service::open(home).await?;
    ensure!(
        service.session_hash() == saved.session,
        "issuing login changed; resume with the original login"
    );
    let record = service.pairing_create(&code.id(), registration).await?;
    ensure!(
        record.cluster_id == registration.cluster_id
            && record.invitation_id == registration.invitation_id
            && record.created_at == registration.created_at
            && record.capsule == registration.capsule,
        "service changed the encrypted node invitation"
    );
    if let Some(path) = &args.code_out {
        storage::code_file(&managed_file::normalize(path)?, &code)?;
    } else {
        eprintln!(
            "Run on the new machine:\n  gent cluster join {}\nThis private code enrolls one node as {} and expires in 15 minutes.",
            code.expose().as_str(),
            args.name
        );
    }
    Ok(
        json!({"name":args.name,"cluster":cfg.cluster.name,"invitation":record.invitation_id,"expires_at":record.expires_at,"code_file":args.code_out,"next":"Run gent cluster join CODE on the new machine."}),
    )
}
