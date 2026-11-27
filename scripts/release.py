"""Verify the tagged workspace, crates.io publication and matching GitHub Release."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time
import tomllib
from urllib.error import HTTPError
from urllib.request import Request, urlopen

CRATES = ("gent-protocol", "gent-crypto", "gent-daemon", "gent-link")
REPO = "sam0x17/gent"
REPOSITORY = f"https://github.com/{REPO}"
NOTES_END = "<!-- gent-release-notes:end -->"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def clean_head():
    require(not output("git", "status", "--porcelain"), "Release checkout must be clean")
    return output("git", "rev-parse", "HEAD")


def workspace_version():
    return tomllib.loads(Path("Cargo.toml").read_text())["workspace"]["package"]["version"]


def notes_path(version):
    return f"crates/gent-link/releases/{version}.md"


def release_notes(version, head):
    path = notes_path(version)
    entry = output("git", "ls-tree", head, "--", path)
    require(entry.startswith(("100644 blob ", "100755 blob ")), f"Missing regular file {path} in the release commit")
    notes = subprocess.check_output(["git", "show", f"{head}:{path}"], encoding="utf-8").strip("\n")
    require(NOTES_END not in notes, f"{path} contains the reserved release-body delimiter")
    # Headings, links and authoring instructions alone would leave About with no release news.
    visible = re.sub(r"<!--.*?(?:-->|$)", "", notes, flags=re.DOTALL)
    visible = re.sub(r"!?\[[^\]\n]*\]\([^)\n]*\)|https?://\S+", "", visible)
    lines = []
    for line in visible.splitlines():
        line = re.sub(r"^[-*+]\s+", "", line.strip())
        if (not line or line.startswith("#")
                or re.match(r"(?:TODO|TBD|FIXME|TK)\b", line, re.IGNORECASE)
                or line.startswith(("**Full Changelog**:", "Install this version with `cargo install "))
                or re.fullmatch(r"(?:coming soon|release notes|bug fixes and improvements)[.!]?", line, re.IGNORECASE)):
            continue
        lines.append(line)
    require(len(re.findall(r"[^\W\d_]+", " ".join(lines))) >= 3, f"Describe a user-visible change in {path}")
    return notes


def source():
    tag = os.environ["GITHUB_REF_NAME"]
    require(os.environ["GITHUB_REF_TYPE"] == "tag" and os.environ["GITHUB_REPOSITORY"] == REPO,
            "Select a version tag in the public Gent repository")
    version = workspace_version()
    require(tag == f"v{version}" and re.fullmatch(r'\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?', version),
            f"Tag {tag!r} must match the workspace version {version}")
    head = clean_head()
    require(head == output("git", "rev-parse", os.environ["GITHUB_SHA"] + "^{commit}"),
            "Checkout differs from the triggering revision")
    notes = release_notes(version, head)
    ref = f"refs/tags/{tag}"
    refs = {name: oid for oid, name in (line.split() for line in output(
        "git", "ls-remote", "origin", ref, ref + "^{}", "refs/heads/main",
        "refs/tags/stable", "refs/tags/stable^{}").splitlines())}
    require(ref in refs and refs.get(ref + "^{}", refs[ref]) == head, f"Remote {tag} no longer selects {head}")
    allowed = [refs.get("refs/heads/main"), refs.get("refs/tags/stable^{}", refs.get("refs/tags/stable"))]
    require(any(oid and subprocess.run(["git", "merge-base", "--is-ancestor", head, oid]).returncode == 0
                for oid in allowed), "The version tag must select a commit on public main or Stable")
    return version, head, notes


def archive_checksum(path, name, version, head):
    prefix = f"{name}-{version}/"
    with tarfile.open(path, "r:gz") as archive:
        vcs = json.load(archive.extractfile(prefix + ".cargo_vcs_info.json"))
        package = tomllib.loads(archive.extractfile(prefix + "Cargo.toml").read().decode())["package"]
    require(package["name"] == name and package["version"] == version and package["repository"] == REPOSITORY,
            f"{name}: Cargo.toml differs from the release identity")
    require(vcs["git"]["sha1"] == head and vcs["git"].get("dirty", False) is False
            and vcs["path_in_vcs"] == f"crates/{name}", f"{name}: archive has different source provenance")
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def package_hashes(version, head):
    metadata = json.loads(output("cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"))
    require({p["name"] for p in metadata["packages"]} == set(CRATES), "Unexpected release workspace members")
    for package in metadata["packages"]:
        require(package["version"] == version and package["publish"] == ["crates-io"],
                f"{package['name']}: unexpected workspace version or publish registry")
    directory = Path(metadata["target_directory"]) / "package"
    return {n: archive_checksum(directory / f"{n}-{version}.crate", n, version, head) for n in CRATES}


def read_url(url):
    return urlopen(Request(url, headers={"User-Agent": f"gent-release-ci ({REPOSITORY})"}), timeout=30)


def registry_status(name, version, checksum):
    # A transport or service failure must never look like an unpublished version.
    try:
        with read_url(f"https://index.crates.io/ge/nt/{name}") as response:
            rows = [row for line in response if (row := json.loads(line))["vers"] == version]
    except HTTPError as error:
        error.close()
        if error.code != 404:
            raise
        rows = []
    if not rows:
        # The API can already have accepted an upload while the sparse index
        # still returns a cached negative result. Do not upload it again.
        try:
            with read_url(f"https://crates.io/api/v1/crates/{name}/{version}") as response:
                accepted = json.load(response)["version"]
        except HTTPError as error:
            error.close()
            if error.code == 404:
                return "absent"
            raise
        require(accepted["num"] == version and accepted["crate"] == name and accepted["checksum"] == checksum
                and accepted["yanked"] is False, f"{name} {version}: conflicting version accepted by crates.io")
        return "accepted"
    require(len(rows) == 1 and rows[0]["name"] == name and rows[0]["yanked"] is False
            and rows[0]["cksum"] == checksum, f"{name} {version}: contradictory or yanked registry version")
    with read_url(f"https://static.crates.io/crates/{name}/{name}-{version}.crate") as archive:
        require(hashlib.file_digest(archive, "sha256").hexdigest() == checksum,
                f"{name} {version}: downloaded archive differs from tagged package")
    return "verified"


def registry_match(name, version, checksum, *, submitted=False):
    # Once an upload was submitted or observed via the API, even a subsequent
    # stale 404 cannot authorize another upload in this run.
    deadline = time.monotonic() + 180
    while True:
        status = registry_status(name, version, checksum)
        if status == "verified":
            return True
        submitted = submitted or status == "accepted"
        if not submitted:
            return False
        require(time.monotonic() < deadline, f"{name}: registry propagation timed out; retry the same tag")
        time.sleep(5)


def missing_crates(version, hashes):
    require(set(hashes) == set(CRATES) and all(re.fullmatch("[0-9a-f]{64}", h) for h in hashes.values()),
            "Incomplete release checksums")
    missing = []
    for name in CRATES:
        if not registry_match(name, version, hashes[name]):
            missing.append(name)
        elif missing:
            raise ValueError(f"{name} {version} exists before dependency {missing[0]}; inspect partial release")
    return missing


def links(version):
    return [f"https://crates.io/crates/{name}/{version}" for name in CRATES]


def github_releases():
    # Listing also detects accessible drafts with this tag. A 403 or service
    # failure propagates, instead of being mistaken for a missing release.
    pages = json.loads(output("gh", "api", "--paginate", "--slurp", f"repos/{REPO}/releases?per_page=100"))
    return [release for page in pages for release in page]


def existing_release(version, head, missing, releases, notes):
    tag = f"v{version}"
    found = [r for r in releases if r["tag_name"] == tag]
    if not found:
        return False
    require(len(found) == 1 and not missing, f"{tag}: duplicate release or incomplete registry publication")
    release = found[0]
    target = release["target_commitish"]
    require(not re.fullmatch("[a-fA-F0-9]{40}", target) or target.lower() == head,
            f"{tag}: existing GitHub Release targets another commit")
    published_links = re.findall(r"https://crates\.io/crates/[\w-]+/[\w.+-]+", release["body"] or "")
    require(not release["draft"] and release["prerelease"] == is_prerelease(version)
            and set(links(version)).issubset(published_links),
            f"{tag}: existing GitHub Release conflicts with the version or crate links")
    lines = release["body"].splitlines()
    end = next((i for i, line in enumerate(lines) if line.strip() == NOTES_END), None)
    if end is None:
        # Older releases use the generated changelog/crate footer without a delimiter.
        end = next((i for i, line in enumerate(lines) if line.strip().startswith("**Full Changelog**:")
                    or line.strip() == "### Published crates"), len(lines))
    authored = "\n".join(lines[:end])
    require(f"\n{notes}\n" in f"\n{authored}\n",
            f"{tag}: existing release must include the tagged notes from {notes_path(version)}; "
            "preserve maintainer edits when restoring them")
    return True


def is_prerelease(version):
    return "-" in version.split("+")[0]


def publish(version, head, hashes, missing):
    for name in missing:
        source()
        if registry_match(name, version, hashes[name]):
            continue
        # Cargo repackages a single crate during publication. Check that form
        # against the verified workspace package before any immutable upload.
        subprocess.run(["cargo", "package", "--locked", "--no-verify", "-p", name], check=True)
        directory = Path(os.environ["CARGO_TARGET_DIR"]) / "package"
        path = directory / f"{name}-{version}.crate"
        require(archive_checksum(path, name, version, head) == hashes[name],
                f"{name}: individual and workspace packages differ")
        subprocess.run(["cargo", "publish", "--locked", "--no-verify", "--registry", "crates-io", "-p", name],
                       check=True)
        registry_match(name, version, hashes[name], submitted=True)


def github_post(endpoint, payload):
    return json.loads(subprocess.check_output(
        ["gh", "api", "--method", "POST", f"repos/{REPO}/releases{endpoint}", "--input", "-"],
        input=json.dumps(payload), text=True))


def create_release(version, head, releases, notes):
    tag = f"v{version}"
    ancestors = set(output("git", "tag", "--merged", head, "--list", "v[0-9]*").splitlines())
    previous = next((r["tag_name"] for r in releases if not r["draft"] and r["tag_name"] != tag
                     and r["tag_name"] in ancestors), None)
    sections = [notes, NOTES_END]
    if previous:
        generated = github_post("/generate-notes", {"tag_name": tag, "target_commitish": head,
                                                    "previous_tag_name": previous})["body"]
        if generated.strip():
            sections.append(generated.strip())
    crates = "\n".join(f"- [{n} {version}]({url})" for n, url in zip(CRATES, links(version)))
    sections.extend([f"### Published crates\n\n{crates}",
                     f"Install this version with `cargo install --locked --version '={version}' gent-link`."])
    body = "\n\n".join(sections)
    source()
    release = github_post("", {"tag_name": tag, "target_commitish": head, "draft": False,
                               "prerelease": is_prerelease(version), "name": f"Gent {tag}", "body": body})
    print(release["html_url"])


def main(command):
    if command == "bootstrap-check":
        version, head = workspace_version(), clean_head()
        release_notes(version, head)
        hashes = package_hashes(version, head)
        pending = missing_crates(version, hashes)
        for name, checksum in hashes.items():
            print(name, version, head, checksum, "missing" if name in pending else "verified")
        return
    version, head, notes = source()
    if command == "source":
        return
    if command == "installed":
        installed = json.loads(output(str(Path(os.environ["RUNNER_TEMP"]) / "install/bin/gent"), "--json", "version"))
        require(all(installed.get(key) == value for key, value in {
            "package": "gent-link", "version": version, "commit": head, "dirty": False, "test_build": False
        }.items()), "Installed registry binary differs from tagged release")
        return
    if command == "plan":
        hashes = package_hashes(version, head)
        missing = missing_crates(version, hashes)
        existing_release(version, head, missing, github_releases(), notes)
        print(f"Verified {len(CRATES) - len(missing)} registry archives. Pending: {', '.join(missing) or 'none'}")
        with open(os.environ["GITHUB_OUTPUT"], "a") as out:
            print(f"hashes={json.dumps(hashes)}", f"publish={'true' if missing else 'false'}", sep="\n", file=out)
        return
    hashes = json.loads(os.environ["HASHES"])
    missing = missing_crates(version, hashes)
    if command == "publish":
        publish(version, head, hashes, missing)
    else:
        require(not missing, f"Missing crates at {version}: {', '.join(missing)}")
        if command == "release":
            releases = github_releases()
            if not existing_release(version, head, missing, releases, notes):
                create_release(version, head, releases, notes)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("bootstrap-check", "source", "plan", "publish", "verify", "installed", "release"))
    main(parser.parse_args().command)
