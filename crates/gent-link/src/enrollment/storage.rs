use super::*;

pub(super) fn private(path: &Path) -> Result<Snapshot> {
    let snapshot = Snapshot::read(path)?;
    snapshot.private()?;
    Ok(snapshot)
}

pub(super) fn directory(home: &Path) -> Result<PathBuf> {
    let directory = home.join("auth").join("enrollment");
    config::private_dir(&directory)?;
    Ok(directory)
}

pub(super) fn write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    private(path)?.write(&serde_json::to_string(value)?)
}

pub(super) fn code_file(path: &Path, code: &Code) -> Result<()> {
    let snapshot = private(path)?;
    let text = code.expose();
    ensure!(
        snapshot
            .text
            .as_ref()
            .is_none_or(|old| old.trim() == text.as_str()),
        "pairing code output already contains different data"
    );
    snapshot.write(&text)
}

pub(super) fn clean_approvals(directory: &Path, now: u64) -> Result<()> {
    for (index, entry) in std::fs::read_dir(directory)?.enumerate() {
        ensure!(index < 512, "pairing approval journal exceeds capacity");
        let path = entry?.path();
        let Some(id) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".gent-invite"))
        else {
            continue;
        };
        ensure!(
            gent_protocol::service::pairing::valid_id(id),
            "invalid pairing approval filename"
        );
        let invitation = private(&path)?;
        let decoded = gent_crypto::invitation::Invitation::decode(
            invitation
                .text
                .as_deref()
                .context("missing approval invitation")?
                .as_bytes(),
        )?;
        if decoded.offer().offer.expires_at <= now {
            private(&directory.join(format!("{id}.json")))?.remove()?;
            invitation.remove()?;
        }
    }
    ensure!(
        std::fs::read_dir(directory)?.take(510).count() < 510,
        "pairing approval journal is full; retry after outstanding invitations expire"
    );
    Ok(())
}
