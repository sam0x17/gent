use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Systemd,
    Launchd,
}
impl Platform {
    pub fn native() -> Result<Self> {
        if cfg!(target_os = "linux") {
            Ok(Self::Systemd)
        } else if cfg!(target_os = "macos") {
            Ok(Self::Launchd)
        } else {
            anyhow::bail!("daemon services support macOS and Linux; use gent daemon run")
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    version: u8,
    pub platform: Platform,
    pub home: PathBuf,
    pub binary: PathBuf,
}
impl Spec {
    pub fn new(platform: Platform, home: PathBuf, binary: PathBuf) -> Result<Self> {
        let spec = Self {
            version: 1,
            platform,
            home,
            binary,
        };
        spec.validate()?;
        Ok(spec)
    }
    fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported Gent service format");
        for path in [&self.home, &self.binary] {
            ensure!(path.is_absolute(), "service paths must be absolute");
            let text = path.to_str().context("service paths must be UTF-8")?;
            ensure!(
                !text.chars().any(char::is_control),
                "service paths cannot contain control characters"
            );
        }
        Ok(())
    }
    pub fn label(&self) -> String {
        label(self.platform, &self.home)
    }
    pub fn render(&self) -> Result<String> {
        self.validate()?;
        let metadata = STANDARD.encode(serde_json::to_vec(self)?);
        let home = self.home.to_str().unwrap();
        let binary = self.binary.to_str().unwrap();
        Ok(match self.platform {
            Platform::Systemd => format!(
                "# gent-service-v1:{metadata}\n[Unit]\nDescription=Gent agent communication daemon\n\n[Service]\nType=simple\nExecStart=/usr/bin/env -- {} --home {} daemon run\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=10\nUMask=0077\n\n[Install]\nWantedBy=default.target\n",
                unit_arg(binary),
                unit_arg(home)
            ),
            Platform::Launchd => format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- gent-service-v1:{metadata} -->\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{}</string>\n<key>ProgramArguments</key><array><string>{}</string><string>--home</string><string>{}</string><string>daemon</string><string>run</string></array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>LimitLoadToSessionType</key><array><string>Background</string><string>Aqua</string></array>\n<key>ProcessType</key><string>Background</string>\n<key>ThrottleInterval</key><integer>3</integer>\n<key>ExitTimeOut</key><integer>10</integer>\n<key>Umask</key><integer>63</integer>\n<key>StandardOutPath</key><string>{}</string>\n<key>StandardErrorPath</key><string>{}</string>\n</dict></plist>\n",
                self.label(),
                xml(binary),
                xml(home),
                xml(&format!("{home}/daemon.log")),
                xml(&format!("{home}/daemon.log"))
            ),
        })
    }
}
pub fn label(platform: Platform, home: &Path) -> String {
    let digest = format!("{:x}", Sha256::digest(home.as_os_str().as_encoded_bytes()));
    match platform {
        Platform::Systemd => format!("gent-{}", &digest[..32]),
        Platform::Launchd => format!("link.gent.{}", &digest[..32]),
    }
}
pub fn unit_arg(text: &str) -> String {
    format!(
        "\"{}\"",
        text.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    )
}
fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Resolve aliases in existing parents so /tmp and /private/tmp select the
/// same service on macOS. Status can resolve an as-yet absent state directory.
pub fn normalize(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut clean = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                clean.pop();
            }
            Component::CurDir => {}
            other => clean.push(other),
        }
    }
    if let Ok(metadata) = fs::symlink_metadata(&clean) {
        ensure!(
            !metadata.file_type().is_symlink(),
            "Gent state directory cannot be a symlink"
        );
    }
    for ancestor in clean.ancestors() {
        if ancestor.exists() {
            let base = fs::canonicalize(ancestor)?;
            let suffix = clean.strip_prefix(ancestor)?;
            return Ok(if suffix.as_os_str().is_empty() {
                base
            } else {
                base.join(suffix)
            });
        }
    }
    anyhow::bail!("cannot resolve Gent state directory")
}
pub fn location(
    platform: Platform,
    home: &Path,
    user_home: &Path,
    xdg: Option<&Path>,
) -> Result<PathBuf> {
    ensure!(user_home.is_absolute(), "HOME must be absolute");
    let (folder, extension) = match platform {
        Platform::Systemd => {
            let config = xdg
                .map(PathBuf::from)
                .unwrap_or_else(|| user_home.join(".config"));
            ensure!(config.is_absolute(), "XDG_CONFIG_HOME must be absolute");
            (config.join("systemd/user"), "service")
        }
        Platform::Launchd => (user_home.join("Library/LaunchAgents"), "plist"),
    };
    Ok(folder.join(format!("{}.{extension}", label(platform, home))))
}
pub fn owned_regular(path: &Path, uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.uid() == uid
            && metadata.permissions().mode() & 0o077 == 0,
        "{} must be a private regular file owned by the current user",
        path.display()
    );
    Ok(())
}
pub fn read(path: &Path, platform: Platform, home: &Path, uid: u32) -> Result<Option<Spec>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    owned_regular(path, uid)?;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(128 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 128 * 1024, "Gent service file is too large");
    let text = String::from_utf8(bytes)?;
    let marker = match platform {
        Platform::Systemd => text
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("# gent-service-v1:")),
        Platform::Launchd => text
            .lines()
            .nth(1)
            .and_then(|l| l.strip_prefix("<!-- gent-service-v1:"))
            .and_then(|l| l.strip_suffix(" -->")),
    }
    .context("service file is not managed by Gent; preserve it and inspect the reported path")?;
    let spec: Spec = serde_json::from_slice(&STANDARD.decode(marker)?)?;
    ensure!(
        spec.platform == platform && spec.home == home,
        "service file belongs to another Gent state directory"
    );
    ensure!(
        spec.render()? == text,
        "Gent service file was edited; preserve those edits or restore the managed file before retrying"
    );
    Ok(Some(spec))
}
pub fn write(path: &Path, spec: &Spec) -> Result<()> {
    let parent = path.parent().context("missing service directory")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(spec.render()?.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_arguments_are_literal_and_metadata_round_trips() {
        let home = PathBuf::from("/tmp/a \"quote\" $cash %name & <xml> '");
        let binary = PathBuf::from("/tmp/bin\\ gent\"$%&");
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        for platform in [Platform::Systemd, Platform::Launchd] {
            let spec = Spec::new(platform, home.clone(), binary.clone()).unwrap();
            let path = dir.path().join("service");
            write(&path, &spec).unwrap();
            assert_eq!(
                read(&path, platform, &home, uid)
                    .unwrap()
                    .unwrap()
                    .render()
                    .unwrap(),
                spec.render().unwrap()
            );
        }
        assert_eq!(unit_arg("a \"$X%p\\"), "\"a \\\"$$X%%p\\\\\"");
        assert!(
            Spec::new(
                Platform::Systemd,
                PathBuf::from("/tmp/a\nExecStart=bad"),
                binary
            )
            .is_err()
        );
    }
    #[test]
    fn altered_foreign_shared_and_linked_service_files_are_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let path = dir.path().join("service");
        let spec = Spec::new(
            Platform::Systemd,
            dir.path().join("home"),
            PathBuf::from("/usr/bin/gent"),
        )
        .unwrap();
        write(&path, &spec).unwrap();
        let changed = fs::read_to_string(&path).unwrap() + "# local edit\n";
        fs::write(&path, &changed).unwrap();
        assert!(read(&path, spec.platform, &spec.home, uid).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), changed);
        write(&path, &spec).unwrap();
        assert!(read(&path, spec.platform, &dir.path().join("other"), uid).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&path, spec.platform, &spec.home, uid).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read(&link, spec.platform, &spec.home, uid).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&path, &link).unwrap();
        assert!(read(&path, spec.platform, &spec.home, uid).is_err());
    }
    #[test]
    fn directory_aliases_select_one_service_and_instances_are_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let a = normalize(&real.join("node")).unwrap();
        let b = normalize(&alias.join("node")).unwrap();
        assert_eq!(a, b);
        fs::create_dir(&a).unwrap();
        assert_eq!(normalize(&a).unwrap(), a);
        assert_eq!(normalize(&alias.join("node")).unwrap(), a);
        assert_eq!(label(Platform::Launchd, &a), label(Platform::Launchd, &b));
        assert_ne!(
            label(Platform::Launchd, &a),
            label(Platform::Launchd, &a.join("other"))
        );
        assert!(normalize(&alias).is_err());
    }
}
