use super::*;
use std::os::unix::fs::MetadataExt;

#[test]
fn policy_migration_requires_its_own_running_job_and_preserves_overrides() -> Result<()> {
    let root = tempfile::tempdir()?;
    let home = root.path().join("node");
    config::private_dir(&home)?;
    let binary = root.path().join("gent");
    let uid = fs::metadata(&home)?.uid();
    for platform in [Platform::Systemd, Platform::Launchd] {
        let path = files::location(platform, &home, root.path(), None, Kind::Daemon)?;
        let service = Service {
            home: home.clone(),
            path: path.clone(),
            manager: Manager {
                platform,
                uid,
                label: Kind::Daemon.label(platform, &home),
            },
            kind: Kind::Daemon,
        };
        let current = Spec::new(platform, home.clone(), binary.clone())?;
        let mut legacy = serde_json::to_value(&current)?;
        legacy["version"] = json!(3);
        let legacy: Spec = serde_json::from_value(legacy)?;
        files::write(&path, &legacy)?;
        let overrides = path.with_extension("service.d");
        fs::create_dir(&overrides)?;
        let user_file = overrides.join("override.conf");
        fs::write(&user_file, "[Service]\nRestart=no\n")?;
        let mut state = State::default();
        assert!(!service.upgrade_running_policy(&binary, &state)?);
        state.running = true;
        state.pid = Some(std::process::id().wrapping_add(1));
        assert!(!service.upgrade_running_policy(&binary, &state)?);
        state.pid = Some(std::process::id());
        assert!(!service.upgrade_running_policy(&root.path().join("other-gent"), &state)?);
        assert_eq!(fs::read_to_string(&path)?, legacy.render()?);

        let lock = service.lock()?;
        assert!(service.upgrade_running_policy(&binary, &state).is_err());
        assert_eq!(fs::read_to_string(&path)?, legacy.render()?);
        drop(lock);
        let reload = platform == Platform::Systemd;
        assert_eq!(service.upgrade_running_policy(&binary, &state)?, reload);
        assert_eq!(fs::read_to_string(&path)?, current.render()?);
        let inode = fs::metadata(&path)?.ino();
        assert!(!service.upgrade_running_policy(&binary, &state)?);
        if reload {
            // Publication succeeded but a prior manager reload did not.
            state.need_reload = true;
            assert!(service.upgrade_running_policy(&binary, &state)?);
        }
        assert_eq!(fs::metadata(&path)?.ino(), inode);
        assert_eq!(fs::read_to_string(&user_file)?, "[Service]\nRestart=no\n");
    }
    Ok(())
}
