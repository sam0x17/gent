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

fn main() {
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
