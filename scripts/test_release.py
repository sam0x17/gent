"""Offline fixtures for the public release workflow."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, call, patch
from urllib.error import HTTPError

import release as r


class ReleaseTest(unittest.TestCase):
    version = "0.1.0"
    sha = "a" * 40
    hashes = dict.fromkeys(r.CRATES, "b" * 64)

    def test_source_follows_annotated_tag_and_checks_remote_even_on_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path.cwd()
            self.addCleanup(os.chdir, original)
            os.chdir(directory)
            def git(*args):
                return subprocess.check_output(["git", *args], text=True, stderr=subprocess.DEVNULL).strip()
            git("init", "-b", "main")
            git("config", "user.name", "Release fixture")
            git("config", "user.email", "fixture@example.invalid")
            Path("Cargo.toml").write_text('[workspace.package]\nversion = "0.1.0"\n')
            git("add", "Cargo.toml")
            git("commit", "-m", "fixture")
            git("tag", "-a", "v0.1.0", "-m", "fixture")
            git("remote", "add", "origin", ".")
            env = {"GITHUB_REF_NAME": "v0.1.0", "GITHUB_REF_TYPE": "tag",
                   "GITHUB_REPOSITORY": r.REPO, "GITHUB_SHA": git("rev-parse", "refs/tags/v0.1.0")}
            with patch.dict(os.environ, env):
                self.assertEqual(r.source(), ("0.1.0", git("rev-parse", "HEAD")))
                with patch.dict(os.environ, GITHUB_REF_NAME="v0.1.0-rc.1"):
                    with self.assertRaisesRegex(ValueError, "workspace version"):
                        r.source()
                Path("untracked").touch()
                with self.assertRaisesRegex(ValueError, "clean"):
                    r.source()
                Path("untracked").unlink()
                git("commit", "--allow-empty", "-m", "later")
                git("tag", "-f", "v0.1.0")
                git("checkout", "--detach", env["GITHUB_SHA"])
                with self.assertRaisesRegex(ValueError, "no longer selects"):
                    r.source()

    def test_archive_checks_content_identity_and_cargo_provenance(self):
        name = r.CRATES[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.crate"
            def build(commit, dirty=False, root=f"crates/{name}", version="0.1.0"):
                with tarfile.open(path, "w:gz") as archive:
                    for filename, data in {
                        "Cargo.toml": f'[package]\nname="{name}"\nversion="{version}"\nrepository="{r.REPOSITORY}"',
                        ".cargo_vcs_info.json": json.dumps({"git": {"sha1": commit, "dirty": dirty}, "path_in_vcs": root}),
                    }.items():
                        info = tarfile.TarInfo(f"{name}-0.1.0/{filename}")
                        info.size = len(data.encode())
                        archive.addfile(info, io.BytesIO(data.encode()))
            build(self.sha)
            self.assertEqual(r.archive_checksum(path, name, self.version, self.sha), hashlib.sha256(path.read_bytes()).hexdigest())
            for args in [("c" * 40,), (self.sha, True), (self.sha, False, "other"), (self.sha, False, f"crates/{name}", "0.2.0")]:
                build(*args)
                with self.assertRaises(ValueError):
                    r.archive_checksum(path, name, self.version, self.sha)

    def test_registry_absence_requires_two_404s(self):
        def error(code):
            return HTTPError("https://fixture.invalid", code, "", {}, None)
        def lookup(*responses):
            with patch.object(r, "read_url", side_effect=responses):
                return r.registry_match(r.CRATES[0], self.version, self.hashes[r.CRATES[0]])
        self.assertFalse(lookup(error(404), error(404)))
        with self.assertRaises(HTTPError):
            lookup(error(403))
        data = {"num": self.version, "crate": r.CRATES[0], "checksum": "b" * 64, "yanked": False}
        with self.assertRaisesRegex(ValueError, "conflicting"):
            lookup(error(404), io.BytesIO(json.dumps({"version": data | {"checksum": "c" * 64}}).encode()))
        response = io.BytesIO(json.dumps({"version": data}).encode())
        with patch.object(r, "read_url", side_effect=[error(404), response]):
            self.assertEqual(r.registry_status(r.CRATES[0], self.version, self.hashes[r.CRATES[0]]), "accepted")

    def test_accepted_upload_waits_through_stale_404_without_resubmitting(self):
        name = r.CRATES[0]
        with (patch.object(r, "source"), patch.object(r, "archive_checksum", return_value=self.hashes[name]),
              patch.dict(os.environ, CARGO_TARGET_DIR="/unused"), patch.object(r.time, "sleep"),
              patch.object(r, "registry_status", side_effect=["absent", "accepted", "absent", "verified"]),
              patch.object(r.subprocess, "run") as run):
            r.publish(self.version, self.sha, self.hashes, [name])
            self.assertEqual([c.args[0][1] for c in run.call_args_list], ["package", "publish"])
        with (patch.object(r.time, "sleep"), patch.object(r.time, "monotonic", side_effect=[0, 1, 181]),
              patch.object(r, "registry_status", side_effect=["accepted", "absent"])):
            with self.assertRaisesRegex(ValueError, "timed out"):
                r.registry_match(name, self.version, self.hashes[name])

    def test_registry_rejects_yanks_corruption_and_wrong_download(self):
        data = b"published archive"
        checksum = hashlib.sha256(data).hexdigest()
        def check(content, **replace):
            row = dict(name=r.CRATES[0], vers=self.version, yanked=False, cksum=checksum)
            row.update(replace)
            with patch.object(r, "read_url", side_effect=[io.BytesIO(json.dumps(row).encode()), io.BytesIO(content)]):
                return r.registry_match(r.CRATES[0], self.version, checksum)
        self.assertTrue(check(data))
        for content, fields in [(data, {"yanked": True}), (data, {"cksum": "c" * 64}), (b"different", {})]:
            with self.assertRaises(ValueError):
                check(content, **fields)

    def test_partial_release_rechecks_all_crates_before_resuming(self):
        for count in range(5):
            with patch.object(r, "registry_match", side_effect=[True] * count + [False] * (4 - count)) as check:
                self.assertEqual(r.missing_crates(self.version, self.hashes), list(r.CRATES[count:]))
                self.assertEqual(check.call_count, 4)
        with patch.object(r, "registry_match", side_effect=[True, False, True, False]):
            with self.assertRaisesRegex(ValueError, "partial release"):
                r.missing_crates("0.2.0-rc.1", self.hashes)

    def test_publish_only_submits_missing_crates_and_stops_on_error(self):
        missing = list(r.CRATES[2:])
        with (patch.object(r, "source"), patch.object(r, "archive_checksum", return_value="b"*64),
              patch.dict(os.environ, CARGO_TARGET_DIR="/unused"), patch.object(r.subprocess, "run") as run,
              patch.object(r, "registry_match", side_effect=[False, True, False, True])):
            r.publish(self.version, self.sha, self.hashes, missing)
            self.assertEqual([c.args[0][-1] for c in run.call_args_list if c.args[0][1] == "publish"], missing)
        with (patch.object(r, "source"), patch.object(r, "archive_checksum", return_value="b"*64),
              patch.dict(os.environ, CARGO_TARGET_DIR="/unused"), patch.object(r, "registry_match", return_value=False),
              patch.object(r.subprocess, "run", side_effect=[None, subprocess.CalledProcessError(1, "publish")]) as run):
            with self.assertRaises(subprocess.CalledProcessError):
                r.publish(self.version, self.sha, self.hashes, missing)
            self.assertEqual(run.call_count, 2)

    def test_release_retry_and_prerelease_mismatches(self):
        version = "0.1.0-rc.1"
        release = {"tag_name": "v" + version, "target_commitish": self.sha, "draft": False, "prerelease": True, "body": "\n".join(r.links(version))}
        self.assertTrue(r.existing_release(version, self.sha, [], [release]))
        for changed in [{"draft": True}, {"prerelease": False}, {"body": ""}, {"target_commitish": "f"*40},
                        {"body": "\n".join(r.links(version + "0"))}]:
            with self.assertRaises(ValueError):
                r.existing_release(version, self.sha, [], [release | changed])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            r.existing_release(version, self.sha, [r.CRATES[-1]], [release])

    def test_first_release_and_subsequent_generated_notes(self):
        for releases in [[], [{"draft": False, "tag_name": "v0.1.0"}]]:
            post = Mock(side_effect=lambda endpoint, _: {"body": "Included changes"} if endpoint else {"html_url": "fixture"})
            with patch.object(r, "source"), patch.object(r, "output", return_value="v0.1.0"), patch.object(r, "github_post", post):
                r.create_release("0.2.0-rc.1", self.sha, releases)
            endpoint, payload = post.call_args.args
            self.assertEqual(endpoint, "")
            self.assertTrue(payload["prerelease"])
            self.assertFalse(payload["draft"])
            self.assertEqual(payload["target_commitish"], self.sha)
            self.assertTrue(all(url in payload["body"] for url in r.links("0.2.0-rc.1")))
            if releases:
                self.assertEqual(post.call_args_list[0], call("/generate-notes", {
                    "tag_name": "v0.2.0-rc.1", "target_commitish": self.sha, "previous_tag_name": "v0.1.0"}))
                self.assertIn("Included changes", payload["body"])
            else:
                self.assertEqual(post.call_count, 1)
                for phrase in ["first crates.io release", "Free includes Babysitter", "off by default",
                               "cargo install --locked gent-link", "gent update disable"]:
                    self.assertIn(phrase, payload["body"])


if __name__ == "__main__":
    unittest.main()
