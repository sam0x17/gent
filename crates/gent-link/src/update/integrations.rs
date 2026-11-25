//! Refresh only after the daemon has proved readiness. A host-file conflict
//! must not roll back a healthy daemon or stop durable message delivery.
use super::*;

pub(super) async fn refresh(home: &Path, installation: &Installation) {
    // A superseded daemon must not restore the previous module on macOS, where
    // current_exe can still name the replaced on-disk path.
    match install::inspect(&installation.binary).await {
        Ok(installed) if installed == build_info::current() => {}
        _ => return,
    }
    if let Err(err) = crate::service::adoption::refresh_legacy(home, &installation.binary).await {
        eprintln!("Gent managed gateway adoption pending: {err}");
    }
    let home = home.to_owned();
    let result =
        tokio::task::spawn_blocking(move || crate::integration::refresh::refresh(&home)).await;
    match result {
        Ok(Ok(report)) if report["blocked"] == 0 => {}
        Ok(Ok(_)) => eprintln!(
            "Gent integration refresh needs attention; inspect gent integration refresh --json."
        ),
        Ok(Err(error)) => eprintln!("Gent integration refresh pending: {error}"),
        Err(_) => eprintln!("Gent integration refresh task failed; the next check will retry."),
    }
}
