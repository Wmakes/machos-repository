import datetime as dt
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("repository", Path(__file__).resolve().parents[1] / "tools/repository.py")
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
NOW = dt.datetime(2026, 10, 24, 12, tzinfo=dt.timezone.utc)


class RepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.key = Path(cls.keys.name) / "test.key"
        cls.pub = Path(cls.keys.name) / "test.pub"
        subprocess.run(["minisign", "-G", "-W", "-s", cls.key, "-p", cls.pub], check=True, stdout=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.packages = self.root / "packages"
        self.packages.mkdir()
        self.definitions = self.root / "definitions"
        self.definitions.mkdir()
        self.cfg = dict(github="Wmakes/machos-repository", branch="main", channel="stable", arch="x86_64", key=self.pub,
                        metadata_days=30, max_archive_bytes=2**21, max_unpacked_bytes=2**22, max_packages=400,
                        system_packages=["base"], definitions=self.definitions)
        self.previous = self.root / "stable.toml"
        self.stage = self.root / "stage"
        self.make("base", protected=True)
        self.make("app", deps=[("base", ">=1.0.0")])

    def signature(self, path, legacy=False):
        cmd = ["minisign", "-S", "-W", "-s", self.key, "-m", path, "-x", str(path) + ".sig", "-t", "temporary test fixture"]
        if legacy:
            cmd.append("-l")
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)

    def make(self, name, version="1.0.0", deps=(), protected=False, payload=None, alter=None):
        payload = payload if payload is not None else {"/opt/" + name: name.encode()}
        lines = ['format = 1', 'name = ' + json.dumps(name), 'version = ' + json.dumps(version), 'arch = "x86_64"', 'protected = ' + str(protected).lower()]
        for dependency, need in deps:
            lines += ['[[dependencies]]', 'name = ' + json.dumps(dependency), 'version = ' + json.dumps(need)]
        entries = []
        for path, data in payload.items():
            lines += ['[[files]]', 'path = ' + json.dumps(path), 'size = ' + str(len(data)), 'mode = 420', 'sha256 = ' + json.dumps(hashlib.sha256(data).hexdigest()), 'config = ' + str(path.startswith("/etc/")).lower()]
            entries.append(("files/" + path[1:], 0o644, data, tarfile.REGTYPE))
        entries.insert(0, ("manifest.toml", 0o644, ("\n".join(lines) + "\n").encode(), tarfile.REGTYPE))
        if alter:
            entries = alter(entries)
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for path, mode, data, kind in entries:
                member = tarfile.TarInfo(path)
                member.mode, member.size, member.type = mode, len(data), kind
                if kind == tarfile.SYMTYPE:
                    member.linkname = "/etc/shadow"
                tar.addfile(member, io.BytesIO(data))
        path = self.packages / f"{name}-{version}-x86_64.mpa"
        path.write_bytes(gzip.compress(raw.getvalue(), mtime=0))
        self.signature(path)
        (self.definitions / (name + ".toml")).write_text(f'name = "{name}"\ndescription = "Test package"\nlicense = "MIT"\nsource = "https://example.com/source"\n')
        return path

    def prepare(self, os_version="0.9.3", now=NOW):
        return r.prepare(self.packages, self.stage, os_version, self.cfg, self.previous, now)

    def signed(self, os_version="0.9.3", now=NOW):
        self.prepare(os_version, now)
        self.resign()
        return r.check(self.stage, self.cfg, self.previous, now)

    def resign(self):
        for path in list(self.stage.glob("index-r*.toml")) + [self.stage / "stable.toml"]:
            self.signature(path)

    def replace_index(self, before, after):
        index = next(self.stage.glob("index-r*.toml"))
        index.write_text(index.read_text().replace(before, after))
        catalog = self.stage / "stable.toml"
        old = r.load(catalog)
        catalog.write_text(catalog.read_text().replace(old["releases"][0]["sha256"], r.digest(index.read_bytes())).replace('size = ' + str(old["releases"][0]["size"]), 'size = ' + str(index.stat().st_size)))
        self.resign()

    def save_previous(self):
        shutil.copyfile(self.stage / "stable.toml", self.previous)
        shutil.copyfile(self.stage / "stable.toml.sig", Path(str(self.previous) + ".sig"))
        shutil.rmtree(self.stage)

    def test_signed_repository_roundtrip_and_sizes(self):
        stable, index, files = self.signed()
        self.assertEqual(stable["latest_os"], "0.9.3")
        self.assertEqual(index["system"], ["base"])
        self.assertEqual(index["packages"][0]["dependencies"], ["base >=1.0.0"])
        self.assertEqual(index["packages"][0]["installed_size"], 3)
        self.assertEqual(len(files), 8)
        self.assertNotIn("expires", index)  # The fresh signed catalogue endorses an index snapshot.

    def test_preparation_is_deterministic(self):
        self.prepare()
        second = self.root / "other"
        r.prepare(self.packages, second, "0.9.3", self.cfg, self.previous, NOW)
        for name in ("index-r1.toml", "stable.toml"):
            self.assertEqual((self.stage / name).read_bytes(), (second / name).read_bytes())

    def test_package_fixes_keep_old_versions_and_advance_revisions(self):
        self.signed()
        self.save_previous()
        self.make("app", "1.0.1", deps=[("base", ">=1.0.0")])
        stable, index, _ = self.signed(now=NOW + dt.timedelta(days=1))
        self.assertEqual((stable["revision"], index["revision"]), (2, 2))
        self.assertEqual(len(index["packages"]), 3)

    def test_new_os_retains_old_index_and_selects_latest(self):
        self.signed()
        self.save_previous()
        stable, index, _ = self.signed("0.9.4", NOW + dt.timedelta(days=1))
        self.assertEqual(stable["latest_os"], "0.9.4")
        self.assertEqual(len(stable["releases"]), 2)
        self.assertEqual(index["revision"], 1)

    def test_expired_previous_catalogue_can_be_renewed(self):
        self.signed()
        self.save_previous()
        self.signed(now=NOW + dt.timedelta(days=31))

    def test_unsigned_archive_is_rejected(self):
        next(self.packages.glob("app*.sig")).unlink()
        with self.assertRaises(ValueError):
            self.prepare()

    def test_wrong_signing_key_is_rejected(self):
        self.cfg["key"] = r.ROOT / "keys/official.pub"
        with self.assertRaises(subprocess.CalledProcessError):
            self.prepare()

    def test_modified_signed_archive_is_rejected(self):
        path = next(self.packages.glob("app*.mpa"))
        path.write_bytes(path.read_bytes() + b"modified")
        with self.assertRaises(subprocess.CalledProcessError):
            self.prepare()

    def test_trusted_comment_signature_is_checked(self):
        path = next(self.packages.glob("app*.sig"))
        path.write_text(path.read_text().replace("temporary test fixture", "modified trusted comment"))
        with self.assertRaises(subprocess.CalledProcessError):
            self.prepare()

    def test_legacy_signature_is_rejected(self):
        self.signature(next(self.packages.glob("app*.mpa")), legacy=True)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_payload_hash_and_modes_are_checked(self):
        for mode in (0o644, 0o755):
            with self.subTest(mode=mode):
                self.make("app", alter=lambda e: [e[0], (e[1][0], mode, b"tampered", e[1][3])])
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_duplicate_traversal_and_symlink_members_are_rejected(self):
        for kind in ("duplicate", "traversal", "symlink"):
            with self.subTest(kind=kind):
                def alter(entries):
                    if kind == "duplicate":
                        return entries + [entries[-1]]
                    name, mode, data, regular = entries[-1]
                    return [entries[0], ("files/../shadow" if kind == "traversal" else name, mode, data, tarfile.SYMTYPE if kind == "symlink" else regular)]
                self.make("app", alter=alter)
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_truncated_concatenated_and_oversized_gzip_is_rejected(self):
        path = next(self.packages.glob("app*.mpa"))
        original = path.read_bytes()
        for data in (original[:-5], original + original):
            path.write_bytes(data)
            self.signature(path)
            with self.assertRaises(ValueError):
                self.prepare()
        path.write_bytes(original)
        self.signature(path)
        self.cfg["max_unpacked_bytes"] = 1024
        with self.assertRaises(ValueError):
            self.prepare()

    def test_legacy_bootstrap_path_is_reserved(self):
        with self.assertRaises(ValueError):
            r.safe_path("/bin/mpm-bootstrap.tar", system=True)

    def test_boot_paths_are_reserved_for_system_packages(self):
        self.make("app", payload={"/boot/kernel.elf": b"kernel"})
        with self.assertRaises(ValueError):
            self.prepare()
        self.make("app")
        self.cfg["system_packages"].append("machos-kernel")
        self.make("machos-kernel", protected=True, payload={"/boot/kernel.elf": b"kernel"})
        self.signed()

    def test_missing_and_unprotected_system_packages_are_rejected(self):
        self.make("base", protected=False)
        with self.assertRaises(ValueError):
            self.prepare()
        for path in self.packages.glob("base*"):
            path.unlink()
        with self.assertRaises(ValueError):
            self.prepare()

    def test_missing_dependency_and_cycles_are_rejected(self):
        self.make("app", deps=[("absent", ">=1.0.0")])
        with self.assertRaises(ValueError):
            self.prepare()
        self.make("app", deps=[("base", ">=1.0.0")])
        self.make("base", deps=[("app", ">=1.0.0")], protected=True)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_latest_versions_must_form_a_coherent_repository(self):
        self.make("app", deps=[("base", "1.0.0")])
        self.make("base", "2.0.0", protected=True)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_cross_package_file_ownership_conflicts_are_rejected(self):
        self.make("app", payload={"/opt/base": b"takeover"})
        with self.assertRaises(ValueError):
            self.prepare()

    def test_package_versions_cannot_differ_only_in_build_metadata(self):
        self.make("app", "1.0.0+rebuild")
        with self.assertRaises(ValueError):
            self.prepare()

    def test_semver_numeric_prereleases_and_bounds(self):
        self.assertLess(r.version("1.0.0-2"), r.version("1.0.0-10"))
        self.assertLess(r.version("1.0.0-alpha"), r.version("1.0.0"))
        for value in ("1.0", "01.0.0", "1.0.0-01", "1.0.0-a..b", "1.0.0+x..y", "18446744073709551616.0.0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                r.version(value)

    def test_package_filename_must_match_identity(self):
        path = next(self.packages.glob("app*.mpa"))
        path.rename(self.packages / "misnamed.mpa")
        Path(str(path) + ".sig").rename(self.packages / "misnamed.mpa.sig")
        with self.assertRaises(ValueError):
            self.prepare()

    def test_expired_and_future_catalogues_are_rejected(self):
        self.signed()
        for now in (NOW - dt.timedelta(hours=1), NOW + dt.timedelta(days=31)):
            with self.assertRaises(ValueError):
                r.check(self.stage, self.cfg, self.previous, now)

    def test_signed_index_cannot_change_archive_hash_url_or_dependencies(self):
        for before, after in [('installed_size = 3', 'installed_size = 4'), ('https://github.com/', 'http://evil.example/'), ('base >=1.0.0', 'base >=2.0.0')]:
            with self.subTest(before=before):
                if self.stage.exists():
                    shutil.rmtree(self.stage)
                self.signed()
                self.replace_index(before, after)
                with self.assertRaises(ValueError):
                    r.check(self.stage, self.cfg, self.previous, NOW)

    def test_stale_revision_and_wrong_parent_are_rejected(self):
        self.signed()
        self.save_previous()
        self.signed(now=NOW + dt.timedelta(days=1))
        path = self.stage / "stable.toml"
        original = path.read_text()
        for before, after in [('revision = 2', 'revision = 1'), (r.digest(self.previous.read_bytes()), r.ZERO)]:
            path.write_text(original.replace(before, after))
            self.signature(path)
            with self.assertRaises(ValueError):
                r.check(self.stage, self.cfg, self.previous, NOW + dt.timedelta(days=1))

    def test_extra_unsigned_staging_file_is_rejected(self):
        self.signed()
        (self.stage / "extra.mpa").write_bytes(b"unlisted")
        with self.assertRaises(ValueError):
            r.check(self.stage, self.cfg, self.previous, NOW)

    def test_bundle_roundtrip_and_unsafe_members(self):
        self.signed(now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0))
        target = self.root / "submission-r1.tar"
        r.bundle(self.stage, target, self.cfg, self.previous)
        extracted = self.root / "extracted"
        r.extract(target, extracted, self.cfg)
        r.check(extracted, self.cfg, self.previous)
        for name, kind in (("../escape", tarfile.REGTYPE), ("link", tarfile.SYMTYPE), (".hidden", tarfile.REGTYPE)):
            unsafe = self.root / "unsafe.tar"
            with tarfile.open(unsafe, "w") as tar:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = "/etc/passwd"
                tar.addfile(member)
            with self.assertRaises(ValueError):
                r.extract(unsafe, self.root / "should-not-exist", self.cfg)

    def test_local_metadata_signing_uses_one_batch_and_canonical_sig_names(self):
        self.prepare()
        actual, calls = r.run, []
        def quiet(args, **kwargs):
            calls.append(args)
            return actual(args, stdout=subprocess.DEVNULL, **kwargs)
        with patch.object(r, "run", side_effect=quiet):
            r.sign(self.stage, self.key)
        self.assertEqual(len(calls), 1)
        self.assertFalse(list(self.stage.glob("*.minisig")))
        r.check(self.stage, self.cfg, self.previous, NOW)
        with self.assertRaises(ValueError):
            r.sign(self.stage, self.key)

    def test_failed_asset_upload_cannot_advertise_new_catalogue(self):
        self.signed(now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0))
        target = self.root / "submission-r1.tar"
        r.bundle(self.stage, target, self.cfg, self.previous)
        calls, actual = [], r.run
        def fake_run(args, **kwargs):
            if args[0] == "git":
                calls.append(tuple(args))
                return subprocess.CompletedProcess(args, 0, stdout="")
            return actual(args, **kwargs)
        def fake_gh(cfg, *args, **kwargs):
            if args[:2] == ("release", "view"):
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps(dict(assets=[], isDraft=True, isImmutable=False)))
            raise subprocess.CalledProcessError(1, args)
        env = dict(GITHUB_ACTIONS="true", GITHUB_REF="refs/heads/main", GITHUB_REPOSITORY=self.cfg["github"])
        with patch.dict(os.environ, env), patch.object(r, "run", side_effect=fake_run), patch.object(r, "gh", side_effect=fake_gh), self.assertRaises(subprocess.CalledProcessError):
            r.publish(target, self.cfg, self.previous)
        self.assertFalse(self.previous.exists())
        self.assertFalse(any(call[:2] in (("git", "commit"), ("git", "push")) for call in calls))

    def test_published_asset_replacement_is_refused(self):
        self.signed(now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0))
        target = self.root / "submission-r1.tar"
        r.bundle(self.stage, target, self.cfg, self.previous)
        calls, actual = [], r.run
        filename = "app-1.0.0-x86_64.mpa"
        def fake_run(args, **kwargs):
            if args[0] == "git":
                calls.append(tuple(args))
                return subprocess.CompletedProcess(args, 0, stdout="")
            return actual(args, **kwargs)
        def fake_gh(cfg, *args, **kwargs):
            if args[:2] == ("release", "view"):
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps(dict(assets=[dict(name=filename)], isDraft=False, isImmutable=False)))
            if args[:2] == ("release", "download"):
                (Path(args[args.index("--dir") + 1]) / filename).write_bytes(b"different published bytes")
                return subprocess.CompletedProcess(args, 0, stdout="")
            raise AssertionError("must not upload before replacement check fails")
        env = dict(GITHUB_ACTIONS="true", GITHUB_REF="refs/heads/main", GITHUB_REPOSITORY=self.cfg["github"])
        with patch.dict(os.environ, env), patch.object(r, "run", side_effect=fake_run), patch.object(r, "gh", side_effect=fake_gh), self.assertRaises(ValueError):
            r.publish(target, self.cfg, self.previous)
        self.assertFalse(self.previous.exists())

    def test_publication_cannot_drop_an_old_package_version(self):
        self.signed(now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0))
        old_index = (self.stage / "index-r1.toml").read_bytes()
        old_signature = (self.stage / "index-r1.toml.sig").read_bytes()
        self.save_previous()
        for path in self.packages.glob("app*"):
            path.unlink()
        self.make("app", "1.0.1", deps=[("base", ">=1.0.0")])
        self.signed(now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0))
        target = self.root / "submission-r2.tar"
        r.bundle(self.stage, target, self.cfg, self.previous)
        actual = r.run
        def fake_run(args, **kwargs):
            if args[0] == "git":
                return subprocess.CompletedProcess(args, 0, stdout="")
            return actual(args, **kwargs)
        def fake_gh(cfg, *args, **kwargs):
            if args[:2] == ("release", "view"):
                assets = [dict(name="index-r1.toml"), dict(name="index-r1.toml.sig")]
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps(dict(assets=assets, isDraft=False, isImmutable=False)))
            if args[:2] == ("release", "download"):
                dest = Path(args[args.index("--dir") + 1])
                (dest / "index-r1.toml").write_bytes(old_index)
                (dest / "index-r1.toml.sig").write_bytes(old_signature)
                return subprocess.CompletedProcess(args, 0, stdout="")
            raise AssertionError("must reject removed versions before upload")
        env = dict(GITHUB_ACTIONS="true", GITHUB_REF="refs/heads/main", GITHUB_REPOSITORY=self.cfg["github"])
        with patch.dict(os.environ, env), patch.object(r, "run", side_effect=fake_run), patch.object(r, "gh", side_effect=fake_gh), self.assertRaisesRegex(ValueError, "old package version"):
            r.publish(target, self.cfg, self.previous)

    def test_publishing_requires_main_branch_workflow(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), self.assertRaises(ValueError):
            r.publish(self.root / "absent.tar", self.cfg, self.previous)

    def test_publication_uploads_before_advertising_and_never_pushes_in_tests(self):
        self.signed(now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0))
        target = self.root / "submission-r1.tar"
        r.bundle(self.stage, target, self.cfg, self.previous)
        calls, actual = [], r.run
        def fake_run(args, **kwargs):
            if args[0] == "git":
                calls.append(tuple(args))
                return subprocess.CompletedProcess(args, 0, stdout="")
            return actual(args, **kwargs)
        def fake_gh(cfg, *args, **kwargs):
            calls.append(tuple(args))
            if args[:2] == ("release", "view"):
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps(dict(assets=[], isDraft=True, isImmutable=False)))
            return subprocess.CompletedProcess(args, 0, stdout="")
        env = dict(GITHUB_ACTIONS="true", GITHUB_REF="refs/heads/main", GITHUB_REPOSITORY=self.cfg["github"])
        with patch.dict(os.environ, env), patch.object(r, "run", side_effect=fake_run), patch.object(r, "gh", side_effect=fake_gh):
            r.publish(target, self.cfg, self.previous)
        uploaded = [i for i, call in enumerate(calls) if call[:2] == ("release", "upload")]
        push = next(i for i, call in enumerate(calls) if call[:2] == ("git", "push"))
        self.assertTrue(uploaded and max(uploaded) < push)
        self.assertEqual(r.load(self.previous)["revision"], 1)


if __name__ == "__main__":
    unittest.main()
