//! Publish the newly activated build to the node's account inbox.
use crate::build_info::Build;
use gent_protocol::{
    OwnerOp,
    notifications::{Event, Notice},
};
use std::path::Path;

pub(super) async fn installed(home: &Path, build: &Build) {
    #[cfg(feature = "test-updates")]
    if let Some(log) = std::env::var_os("GENT_TEST_UPDATE_NOTIFICATIONS") {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
        {
            let _ = writeln!(file, "{}", build.commit);
        }
        return;
    }
    if let Ok(cfg) = gent_daemon::config::load(home)
        && let Ok(node) = uuid::Uuid::parse_str(&cfg.node.id)
    {
        let notice = Notice {
            id: uuid::Uuid::new_v4(),
            created_at: chrono::Utc::now().timestamp(),
            event: Event::UpdateInstalled {
                node,
                commit: build.commit.clone(),
            },
        };
        let _ = crate::owner(
            home,
            OwnerOp::NotificationPut {
                notice,
                scope: crate::auth::notifications::scope(home),
            },
        )
        .await;
    }
}
