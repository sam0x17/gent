use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn git(root: &std::path::Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

// The first release cannot contain its own commit ID. Only the qualified
// baseline uses "self". Read its commit header directly, even in shallow Git
// installations. Other builds carry the qualified SHA as tracked source.
fn bootstrap_commit(root: &Path, head: Option<&str>) -> Option<String> {
    const BASE: &str = "49cf99a1d39e4bfa0f37c08636aea4e2e893cf97";
    let pin = include_str!("channel-v1-bootstrap.pin").trim();
    if pin == "self" {
        let object = git(
            root,
            &["--no-replace-objects", "cat-file", "commit", "HEAD"],
        )?;
        let header = object.split_once("\n\n")?.0;
        let mut parents = header
            .lines()
            .filter_map(|line| line.strip_prefix("parent "));
        return (parents.next() == Some(BASE) && parents.next().is_none())
            .then(|| head.map(str::to_owned))
            .flatten();
    }
    (pin.len() == 40
        && pin
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then(|| pin.to_owned())
}

fn build_desktop() {
    let source = "src/desktop/macos.swift";
    let main = "src/desktop/main.swift";
    let dashboard = "src/desktop/dashboard.swift";
    println!("cargo:rerun-if-changed={dashboard}");
    let tabs = "src/desktop/macos_tabs.swift";
    let management = "src/desktop/management.swift";
    println!("cargo:rerun-if-changed={management}");
    println!("cargo:rerun-if-changed={tabs}");
    println!("cargo:rerun-if-changed={source}");
    println!("cargo:rerun-if-changed={main}");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        _ => panic!("unsupported macOS architecture"),
    };
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let target = format!("{arch}-apple-macos11.0");
    build_app(
        &out,
        &target,
        &[
            source,
            tabs,
            management,
            dashboard,
            "src/desktop/notifications/Delivery.swift",
            main,
        ],
    );
}

fn swiftc(target: &str, sources: &[&str], output: &Path) {
    let ok = Command::new("xcrun")
        .args([
            "--sdk",
            "macosx",
            "swiftc",
            "-swift-version",
            "5",
            "-O",
            "-target",
            target,
        ])
        .args(sources)
        .arg("-o")
        .arg(output)
        .status()
        .expect("building Gent Desktop requires the Xcode command line tools");
    assert!(ok.success(), "could not compile {}", output.display());
}

fn build_app(out: &Path, target: &str, sources: &[&str]) {
    let app = out.join("Gent.app");
    if app.exists() {
        fs::remove_dir_all(&app).unwrap();
    }
    let contents = app.join("Contents");
    let bin = contents.join("MacOS");
    let resources = contents.join("Resources");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&resources).unwrap();
    let src = "src/desktop/notifications";
    println!("cargo:rerun-if-changed={src}");
    fs::copy(format!("{src}/Info.plist"), contents.join("Info.plist")).unwrap();
    swiftc(target, sources, &bin.join("GentDesktop"));

    let iconset = out.join("Inkling.iconset");
    fs::create_dir_all(&iconset).unwrap();
    for (name, pixels) in [
        ("16x16", 16),
        ("16x16@2x", 32),
        ("32x32", 32),
        ("32x32@2x", 64),
        ("128x128", 128),
        ("128x128@2x", 256),
        ("256x256", 256),
        ("256x256@2x", 512),
        ("512x512", 512),
    ] {
        let png = format!("../../assets/branding/inkling-{pixels}.png");
        println!("cargo:rerun-if-changed={png}");
        fs::copy(png, iconset.join(format!("icon_{name}.png"))).unwrap();
    }
    let ok = Command::new("/usr/bin/iconutil")
        .args(["-c", "icns"])
        .arg(&iconset)
        .arg("-o")
        .arg(resources.join("Inkling.icns"))
        .status()
        .unwrap();
    assert!(ok.success(), "could not package the Inkling icon");
    let ok = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--timestamp=none"])
        .arg(&app)
        .status()
        .unwrap();
    assert!(ok.success(), "could not sign Gent Desktop");
}

fn main() {
    build_desktop();
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    let root = root.canonicalize().unwrap();
    let commit = git(&root, &["rev-parse", "HEAD"])
        .filter(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    let dirty = git(
        &root,
        &["status", "--porcelain", "--untracked-files=normal"],
    )
    .is_none_or(|status| {
        // Cargo writes this checkout marker after fetching a Git dependency.
        status.lines().any(|line| line != "?? .cargo-ok")
    });
    // Track source files as well as Git refs: a commit after a local build must
    // refresh provenance even when Rust source bytes have not changed.
    if let Some(files) = git(&root, &["ls-files"]) {
        for path in files.lines() {
            println!("cargo:rerun-if-changed={}", root.join(path).display());
        }
    }
    for entry in ["HEAD", "index", "packed-refs"] {
        if let Some(path) = git(&root, &["rev-parse", "--git-path", entry]) {
            println!("cargo:rerun-if-changed={}", root.join(path).display());
        }
    }
    if let Some(reference) = git(&root, &["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git(&root, &["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
    println!(
        "cargo:rustc-env=GENT_COMMIT={}",
        commit.as_deref().unwrap_or("unknown")
    );
    println!(
        "cargo:rustc-env=GENT_BOOTSTRAP_COMMIT={}",
        bootstrap_commit(&root, commit.as_deref()).unwrap_or_default()
    );
    println!("cargo:rustc-env=GENT_DIRTY={dirty}");
    println!(
        "cargo:rustc-env=GENT_TARGET={}",
        env::var("TARGET").unwrap()
    );
}
