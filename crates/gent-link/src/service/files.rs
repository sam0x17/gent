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

const MAX_SERVICE_BYTES: usize = 128 * 1024;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Daemon,
    Gateway,
}
impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Gateway => "gateway",
        }
    }
    pub fn lock(self) -> &'static str {
        match self {
            Self::Daemon => "service.lock",
            Self::Gateway => "gateway-service.lock",
        }
    }
    pub fn label(self, platform: Platform, home: &Path) -> String {
        let original = label(platform, home);
        match self {
            Self::Daemon => original,
            Self::Gateway => format!("{original}-gateway"),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<crate::gateway::Run>,
}
impl Spec {
    pub fn new(platform: Platform, home: PathBuf, binary: PathBuf) -> Result<Self> {
        let spec = Self {
            version: 1,
            platform,
            home,
            binary,
            gateway: None,
        };
        spec.validate()?;
        Ok(spec)
    }
    pub fn gateway(
        platform: Platform,
        home: PathBuf,
        binary: PathBuf,
        options: crate::gateway::Run,
    ) -> Result<Self> {
        let spec = Self {
            version: 2,
            platform,
            home,
            binary,
            gateway: Some(options),
        };
        spec.validate()?;
        Ok(spec)
    }
    pub fn kind(&self) -> Kind {
        if self.gateway.is_some() {
            Kind::Gateway
        } else {
            Kind::Daemon
        }
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            (self.version == 1 && self.gateway.is_none())
                || (self.version == 2 && self.gateway.is_some()),
            "unsupported Gent service format"
        );
        if let Some(options) = &self.gateway {
            options.service_arguments()?;
        }
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
        self.kind().label(self.platform, &self.home)
    }
    pub fn render(&self) -> Result<String> {
        self.validate()?;
        let metadata = STANDARD.encode(serde_json::to_vec(self)?);
        let home = self.home.to_str().unwrap();
        let binary = self.binary.to_str().unwrap();
        let args = if let Some(options) = &self.gateway {
            options.service_arguments()?
        } else {
            vec!["daemon".into(), "run".into()]
        };
        let command = if self.gateway.is_some() {
            args.iter()
                .map(|arg| unit_arg(arg))
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            "daemon run".into()
        };
        let arguments = [binary, "--home", home]
            .into_iter()
            .chain(args.iter().map(String::as_str))
            .map(|arg| format!("<string>{}</string>", xml(arg)))
            .collect::<String>();
        let description = if self.gateway.is_some() {
            "remote MCP gateway"
        } else {
            "chat communication daemon"
        };
        let log = xml(&format!("{home}/{}.log", self.kind().name()));
        let rendered = match self.platform {
            Platform::Systemd => format!(
                "# gent-service-v1:{metadata}\n[Unit]\nDescription=Gent {description}\n\n[Service]\nType=simple\nExecStart=/usr/bin/env -- {} --home {} {command}\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=10\nUMask=0077\n\n[Install]\nWantedBy=default.target\n",
                unit_arg(binary),
                unit_arg(home)
            ),
            Platform::Launchd => format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- gent-service-v1:{metadata} -->\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{}</string>\n<key>ProgramArguments</key><array>{arguments}</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>LimitLoadToSessionType</key><array><string>Background</string><string>Aqua</string></array>\n<key>ProcessType</key><string>Background</string>\n<key>ThrottleInterval</key><integer>3</integer>\n<key>ExitTimeOut</key><integer>10</integer>\n<key>Umask</key><integer>63</integer>\n<key>StandardOutPath</key><string>{log}</string>\n<key>StandardErrorPath</key><string>{log}</string>\n</dict></plist>\n",
                self.label()
            ),
        };
        ensure!(
            rendered.len() <= MAX_SERVICE_BYTES,
            "rendered Gent service file is too large"
        );
        Ok(rendered)
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
    kind: Kind,
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
    Ok(folder.join(format!("{}.{extension}", kind.label(platform, home))))
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
pub fn read(
    path: &Path,
    platform: Platform,
    home: &Path,
    uid: u32,
    kind: Kind,
) -> Result<Option<Spec>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    owned_regular(path, uid)?;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_SERVICE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_SERVICE_BYTES,
        "Gent service file is too large"
    );
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
        spec.platform == platform && spec.home == home && spec.kind() == kind,
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
    fn expansion_cannot_write_an_unreadable_service_or_replace_a_working_one() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("service");
        let options: crate::gateway::Run = serde_json::from_value(serde_json::json!({
            "listen":"127.0.0.1:8787", "client_metadata":[], "file_downloads":[],
            "file_origin":vec!["\"".repeat(4000); 8]
        }))
        .unwrap();
        for platform in [Platform::Systemd, Platform::Launchd] {
            let valid = Spec::new(platform, root.path().join("node"), "/bin/gent".into()).unwrap();
            write(&path, &valid).unwrap();
            let before = fs::read(&path).unwrap();
            // Individually valid arguments can expand in both metadata and native quoting.
            let oversized =
                Spec::gateway(platform, valid.home, valid.binary, options.clone()).unwrap();
            assert!(oversized.render().is_err());
            assert!(write(&path, &oversized).is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }
    }
    #[test]
    fn gateway_spec_is_separate_preserves_literal_flags_and_cannot_replace_daemon() {
        let options: crate::gateway::Run = serde_json::from_value(serde_json::json!({
            "listen":"127.0.0.1:8787", "origin":"https://gateway.example:8787",
            "tls_cert":"/private/cert ' $USER%h.pem", "tls_key":"/private/key & <config>.pem",
            "client_metadata":["owner-selected-client"], "file_origin":["client=https://files.example"],
            "file_downloads":["client"]
        })).unwrap();
        let root = tempfile::tempdir().unwrap();
        let uid = fs::metadata(root.path()).unwrap().uid();
        for platform in [Platform::Systemd, Platform::Launchd] {
            let daemon = Spec::new(platform, root.path().join("node"), "/bin/gent".into()).unwrap();
            let encoded = serde_json::to_value(&daemon).unwrap();
            assert_eq!(encoded["version"], 1);
            assert!(encoded.get("gateway").is_none());
            let gateway = Spec::gateway(
                platform,
                daemon.home.clone(),
                daemon.binary.clone(),
                options.clone(),
            )
            .unwrap();
            assert_ne!(daemon.label(), gateway.label());
            let path = root.path().join("service");
            write(&path, &gateway).unwrap();
            assert!(read(&path, platform, &daemon.home, uid, Kind::Daemon).is_err());
            let restored = read(&path, platform, &daemon.home, uid, Kind::Gateway)
                .unwrap()
                .unwrap();
            assert_eq!(restored.render().unwrap(), gateway.render().unwrap());
            assert_eq!(
                restored.gateway.unwrap().service_arguments().unwrap(),
                options.service_arguments().unwrap()
            );
            let mut invalid = options.clone();
            invalid = serde_json::from_value({
                let mut value = serde_json::to_value(invalid).unwrap();
                value["listen"] = "127.0.0.1:0".into();
                value
            })
            .unwrap();
            assert!(
                Spec::gateway(
                    platform,
                    daemon.home.clone(),
                    daemon.binary.clone(),
                    invalid
                )
                .is_err()
            );
        }
    }

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
                read(&path, platform, &home, uid, Kind::Daemon)
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
        assert!(read(&path, spec.platform, &spec.home, uid, Kind::Daemon).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), changed);
        write(&path, &spec).unwrap();
        assert!(
            read(
                &path,
                spec.platform,
                &dir.path().join("other"),
                uid,
                Kind::Daemon
            )
            .is_err()
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&path, spec.platform, &spec.home, uid, Kind::Daemon).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read(&link, spec.platform, &spec.home, uid, Kind::Daemon).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&path, &link).unwrap();
        assert!(read(&path, spec.platform, &spec.home, uid, Kind::Daemon).is_err());
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
