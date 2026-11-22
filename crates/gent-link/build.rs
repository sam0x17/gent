use std::{env, path::PathBuf, process::Command};

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

fn build_desktop() {
    let source = "src/desktop/macos.swift";
    let main = "src/desktop/main.swift";
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
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("GentDesktop");
    let ok = Command::new("xcrun")
        .args([
            "--sdk",
            "macosx",
            "swiftc",
            "-swift-version",
            "5",
            "-O",
            "-target",
        ])
        .arg(format!("{arch}-apple-macos11.0"))
        .args([source, main])
        .arg("-o")
        .arg(output)
        .status()
        .expect("building Gent Desktop requires the Xcode command line tools");
    assert!(ok.success(), "could not compile the AppKit companion");
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
    println!("cargo:rustc-env=GENT_DIRTY={dirty}");
    println!(
        "cargo:rustc-env=GENT_TARGET={}",
        env::var("TARGET").unwrap()
    );
}
