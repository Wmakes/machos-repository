#!/usr/bin/env python3
"""Prepare, sign, verify and publish the official stable MPM repository."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zlib

ROOT = Path(__file__).resolve().parents[1]
NAME = re.compile(r"[a-z][a-z0-9_-]{0,62}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2,})(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?\Z")
ZERO = "0" * 64


def require(condition, message):
    if not condition:
        raise ValueError(message)


def version(value):
    match = VERSION.fullmatch(value) if isinstance(value, str) else None
    require(match is not None, "invalid package version")
    core = tuple(int(part) for part in match[1].split("."))
    require(all(part < 2**64 for part in core), "version integer overflow")
    while len(core) > 3 and core[-1] == 0:
        core = core[:-1]
    pre = match[2]
    for part in (pre or "").split(".") if pre is not None else []:
        require(part and not (part.isdecimal() and len(part) > 1 and part[0] == "0"), "invalid prerelease")
    if match[3] is not None:
        require(all(match[3].split(".")), "empty build identifier")
    # Numeric prerelease identifiers sort below text; a final release sorts last.
    suffix = (1,) if pre is None else (0, tuple((0, int(p)) if p.isdecimal() else (1, p) for p in pre.split(".")))
    return core, suffix


def text(value):
    require(isinstance(value, str) and value.isascii() and all(32 <= ord(c) <= 126 and c not in '\\"' for c in value), "unsupported metadata string")
    return json.dumps(value)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit):
    require(path.is_file() and not path.is_symlink(), "not a regular file: " + str(path))
    require(path.stat().st_size <= limit, "file exceeds limit: " + str(path))
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "file grew past limit")
    return data


def load(path):
    return tomllib.loads(read(path, 2**20).decode("ascii"))


def config(path):
    cfg = load(path)
    require(cfg.get("format") == 1 and cfg.get("channel") == "stable" and cfg.get("arch") == "x86_64", "unsupported repository configuration")
    require(re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", cfg["github"]), "invalid GitHub repository")
    require(cfg["branch"] == "main", "catalogue branch must be main")
    require(1 <= cfg["metadata_days"] <= 30, "invalid metadata lifetime")
    require(1 <= cfg["max_archive_bytes"] <= 2**29 and 1 <= cfg["max_unpacked_bytes"] <= 2**29, "invalid archive limit")
    require(1 <= cfg["max_packages"] <= 400, "invalid package limit")
    require(cfg["system_packages"] and len(set(cfg["system_packages"])) == len(cfg["system_packages"]) and all(NAME.fullmatch(n) for n in cfg["system_packages"]), "invalid system package set")
    cfg["key"] = path.parent / cfg["public_key"]
    cfg["definitions"] = path.parent / cfg["package_definitions"]
    return cfg


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def verify(path, cfg):
    signature = Path(str(path) + ".sig")
    lines = read(signature, 1536).decode("ascii").splitlines()
    require(len(lines) == 4 and lines[0].startswith("untrusted comment: ") and lines[2].startswith("trusted comment: "), "invalid signature format")
    raw = base64.b64decode(lines[1], validate=True)
    require(len(raw) == 74 and raw[:2] == b"ED", "modern prehashed Minisign signatures required")
    run(["minisign", "-V", "-q", "-m", path, "-x", signature, "-p", cfg["key"]], stdout=subprocess.DEVNULL)


def safe_path(path, system=False):
    require(isinstance(path, str), "invalid payload path")
    text(path)
    parts = path.split("/")
    require(path.startswith(("/bin/", "/etc/", "/usr/", "/opt/", "/lib/", "/boot/")) and len(path) <= 240, "unsupported payload path")
    require(all(p not in ("", ".", "..") for p in parts[1:]) and not path.endswith(".mpm-new"), "unsafe payload path")
    require(path not in ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/machos.conf", "/bin/mpm-bootstrap.tar") and not path.startswith("/etc/mpm/"), "reserved payload path")
    require(not path.startswith("/boot/") or system, "only system packages may own boot files")


def unpack(data, cfg):
    decoder = zlib.decompressobj(31)
    raw = decoder.decompress(data, cfg["max_unpacked_bytes"] + 1)
    require(len(raw) <= cfg["max_unpacked_bytes"] and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, "oversized, truncated or trailing gzip data")
    require(len(raw) % 512 == 0, "unaligned tar archive")
    entries, offset = [], 0
    while offset + 512 <= len(raw):
        header = raw[offset:offset + 512]
        if header == bytes(512):
            require(offset + 1024 <= len(raw) and not any(raw[offset:]), "invalid tar terminator")
            return entries
        require(header[257:265] == b"ustar\x0000" and header[156] in (0, 48) and not any(header[345:500]), "only plain ustar regular files are supported")
        require(sum(header[:148]) + 256 + sum(header[156:]) == octal(header[148:156]), "tar checksum mismatch")
        name = header[:100].split(b"\0", 1)[0].decode("ascii")
        require(name and len(name) < 100, "invalid tar name")
        size, mode = octal(header[124:136]), octal(header[100:108])
        offset += 512
        require(offset + size <= len(raw), "truncated tar payload")
        entries.append((name, mode, raw[offset:offset + size]))
        require(len(entries) <= 513, "too many archive files")
        offset += (size + 511) // 512 * 512
    raise ValueError("missing tar terminator")


def octal(field):
    value = field.rstrip(b"\0 ").lstrip(b" ")
    require(value and all(48 <= c <= 55 for c in value), "invalid tar octal field")
    return int(value, 8)


def package(path, cfg):
    data = read(path, cfg["max_archive_bytes"])
    verify(path, cfg)
    entries = unpack(data, cfg)
    require(entries and entries[0][0] == "manifest.toml" and len(entries[0][2]) <= 65536, "manifest must be first and at most 64 KiB")
    source = entries[0][2]
    require(all(c in (9, 10, 13) or 32 <= c <= 126 for c in source) and b"\\" not in source, "unsupported manifest encoding")
    meta = tomllib.loads(source.decode("ascii"))
    require(set(meta) <= {"format", "name", "version", "arch", "protected", "dependencies", "files"}, "unknown manifest field")
    require(meta.get("format") == 1 and NAME.fullmatch(meta["name"]) and meta["arch"] == cfg["arch"], "invalid package identity")
    version(meta["version"])
    require(type(meta.get("protected", False)) is bool, "invalid protected flag")
    system = meta["name"] in cfg["system_packages"]
    require(not system or meta.get("protected", False), "system packages must be protected")
    inventory = meta["files"]
    require(1 <= len(inventory) <= 512 and len(entries) == len(inventory) + 1, "payload inventory mismatch")
    files = {}
    for item in inventory:
        require(set(item) <= {"path", "size", "mode", "sha256", "config"}, "unknown file field")
        dest = item["path"]
        safe_path(dest, system)
        if dest.startswith("/boot/"):
            owners = {"/boot/kernel.elf": "machos-kernel", "/boot/initrd.tar": "machos-kernel", "/boot/BOOTX64.EFI": "machos-boot"}
            require(owners.get(dest) == meta["name"] and meta.get("protected", False), "reserved boot artifact")
        require(dest not in files and DIGEST.fullmatch(item["sha256"]), "duplicate path or invalid hash")
        require(type(item["size"]) is int and item["size"] >= 0 and type(item["mode"]) is int and 0 <= item["mode"] <= 0o7777, "invalid size or mode")
        require(type(item.get("config", False)) is bool and (not item.get("config") or dest.startswith("/etc/")), "invalid config flag")
        files[dest] = item
    seen = set()
    for name, mode, contents in entries[1:]:
        require(name.startswith("files/"), "unexpected archive member")
        dest = "/" + name[6:]
        require(dest in files and dest not in seen, "duplicate or undeclared payload")
        item = files[dest]
        require(len(contents) == item["size"] and mode == item["mode"] and digest(contents) == item["sha256"], "payload size, mode or digest mismatch")
        seen.add(dest)
    dependencies = meta.get("dependencies", [])
    require(len(dependencies) <= 32, "too many dependencies")
    for dep in dependencies:
        require(set(dep) == {"name", "version"} and NAME.fullmatch(dep["name"]), "invalid dependency")
        version(dep["version"].removeprefix(">="))
    require(len({d["name"] for d in dependencies}) == len(dependencies), "duplicate dependency")
    filename = f'{meta["name"]}-{meta["version"]}-{cfg["arch"]}.mpa'
    require(path.name == filename, "expected archive filename: " + filename)
    definition = load(cfg["definitions"] / (meta["name"] + ".toml"))
    require(set(definition) == {"name", "description", "license", "source"} and definition["name"] == meta["name"], "invalid package description")
    require(0 < len(definition["description"]) <= 240 and definition["source"].startswith("https://"), "invalid package description/source")
    for value in definition.values():
        text(value)
    return dict(description=definition["description"], license=definition["license"], source=definition["source"], name=meta["name"], version=meta["version"], arch=meta["arch"], size=len(data), installed_size=sum(f["size"] for f in inventory), sha256=digest(data), protected=meta.get("protected", False), dependencies=dependencies, files=files, filename=filename)


def compatible(have, need):
    if need.startswith(">="):
        return version(have) >= version(need[2:])
    return version(have) == version(need)


def check_graph(packages, cfg):
    by_name, identities = {}, set()
    for p in packages:
        identity = p["name"], version(p["version"])
        require(identity not in identities, "duplicate package identity")
        identities.add(identity)
        by_name.setdefault(p["name"], []).append(p)
    require(set(cfg["system_packages"]) <= set(by_name), "missing required system packages")
    for group in by_name.values():
        group.sort(key=lambda p: version(p["version"]), reverse=True)
    for group in by_name.values():
        for dep in group[0]["dependencies"]:
            require(dep["name"] in by_name and compatible(by_name[dep["name"]][0]["version"], dep["version"]), "latest packages have incompatible dependencies")
    visited, active = set(), set()
    def visit(p):
        identity = p["name"], p["version"]
        require(identity not in active, "dependency cycle")
        if identity in visited:
            return
        active.add(identity)
        for dep in p["dependencies"]:
            candidates = [c for c in by_name.get(dep["name"], []) if compatible(c["version"], dep["version"])]
            require(candidates, "missing dependency: " + dep["name"])
            visit(candidates[0])
        active.remove(identity)
        visited.add(identity)
    for p in packages:
        visit(p)
    # Each supported version of one package must be disjoint from other packages.
    owners = {}
    for p in packages:
        for path in p["files"]:
            require(path not in owners or owners[path] == p["name"], "conflicting file ownership: " + path)
            owners[path] = p["name"]


def stamp(now):
    return now.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def moment(value):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value), "invalid UTC timestamp")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def header(now, days):
    return ["format = 1", 'channel = "stable"', "published = " + text(stamp(now)), "expires = " + text(stamp(now + dt.timedelta(days=days)))]


def emit(lines):
    return ("\n".join(lines) + "\n").encode("ascii")


def asset_url(cfg, os_version, filename):
    return f'https://github.com/{cfg["github"]}/releases/download/v{os_version}/{filename}'


def old_catalogue(path, cfg):
    if not path.exists():
        return None
    verify(path, cfg)
    value = load(path)
    require(value.get("format") == 1 and value.get("channel") == "stable" and value.get("revision", 0) > 0, "invalid previous catalogue")
    return value


def prepare(source, dest, os_version, cfg, previous, now=None):
    version(os_version)
    parsed_os = VERSION.fullmatch(os_version)
    require(parsed_os[2] is None and parsed_os[3] is None, "OS release must be a stable dotted numeric version")
    require(not dest.exists(), "output directory already exists")
    now = now or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    old = old_catalogue(previous, cfg)
    releases = {r["os_version"]: r for r in (old or {}).get("releases", [])}
    prior = releases.get(os_version)
    revision = (prior["revision"] if prior else 0) + 1
    paths = sorted(source.glob("*.mpa"))
    require(0 < len(paths) <= cfg["max_packages"], "invalid number of packages")
    require({p.name + ".sig" for p in paths} == {p.name for p in source.glob("*.sig")}, "missing or orphan package signatures")
    packages = [package(p, cfg) for p in paths]
    check_graph(packages, cfg)
    lines = header(now, cfg["metadata_days"])[:3] + ["os_version = " + text(os_version), "arch = " + text(cfg["arch"]), f"revision = {revision}", "system = [" + ", ".join(text(n) for n in cfg["system_packages"]) + "]"]
    for p in packages:
        lines += ["", "[[packages]]"]
        for key in ("name", "version", "arch", "sha256", "filename", "description", "license", "source"):
            lines.append(key + " = " + text(p[key]))
        for key in ("size", "installed_size"):
            lines.append(key + " = " + str(p[key]))
        lines += ["protected = " + str(p["protected"]).lower(), "url = " + text(asset_url(cfg, os_version, p["filename"])), "signature_url = " + text(asset_url(cfg, os_version, p["filename"] + ".sig")), "dependencies = [" + ", ".join(text(d["name"] + " " + d["version"]) for d in p["dependencies"]) + "]"]
    index = emit(lines)
    filename = f"index-r{revision}.toml"
    releases[os_version] = dict(os_version=os_version, revision=revision, size=len(index), sha256=digest(index), url=asset_url(cfg, os_version, filename), signature_url=asset_url(cfg, os_version, filename + ".sig"))
    lines = header(now, cfg["metadata_days"]) + [f'revision = {(old or {}).get("revision", 0) + 1}', "previous_sha256 = " + text(digest(previous.read_bytes()) if old else ZERO), "latest_os = " + text(max(releases, key=version))]
    for release in sorted(releases.values(), key=lambda r: version(r["os_version"])):
        lines += ["", "[[releases]]"] + [k + " = " + (str(v) if type(v) is int else text(v)) for k, v in release.items()]
    dest.mkdir(parents=True)
    (dest / filename).write_bytes(index)
    (dest / "stable.toml").write_bytes(emit(lines))
    for path in paths:
        shutil.copyfile(path, dest / path.name)
        shutil.copyfile(Path(str(path) + ".sig"), dest / (path.name + ".sig"))
    return filename


def freshness(meta, cfg, now):
    require(meta.get("format") == 1 and meta.get("channel") == "stable", "unsupported metadata")
    start, end = moment(meta["published"]), moment(meta["expires"])
    require(start <= now + dt.timedelta(minutes=5) and now < end and dt.timedelta(0) < end - start <= dt.timedelta(days=cfg["metadata_days"]), "metadata expired or invalid lifetime")
    require(type(meta["revision"]) is int and meta["revision"] > 0, "invalid metadata revision")


def check(stage, cfg, previous, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    stable_path = stage / "stable.toml"
    verify(stable_path, cfg)
    stable = load(stable_path)
    freshness(stable, cfg, now)
    require(set(stable) == {"format", "channel", "published", "expires", "revision", "previous_sha256", "latest_os", "releases"}, "unknown catalogue fields")
    old = old_catalogue(previous, cfg)
    require(stable["revision"] == (old or {}).get("revision", 0) + 1, "catalogue revision must increase by one")
    require(stable["previous_sha256"] == (digest(previous.read_bytes()) if old else ZERO), "catalogue does not follow current catalogue")
    records = stable["releases"]
    require(records and len(records) <= 256, "invalid release count")
    releases = {}
    for r in records:
        require(set(r) == {"os_version", "revision", "size", "sha256", "url", "signature_url"}, "invalid release record")
        version(r["os_version"])
        require(r["os_version"] not in releases and type(r["revision"]) is int and r["revision"] > 0 and type(r["size"]) is int and 0 < r["size"] <= 2**20 and DIGEST.fullmatch(r["sha256"]), "invalid release identity")
        expected = asset_url(cfg, r["os_version"], f'index-r{r["revision"]}.toml')
        require(r["url"] == expected and r["signature_url"] == expected + ".sig", "unexpected index URL")
        releases[r["os_version"]] = r
    require(stable["latest_os"] == max(releases, key=version), "latest OS is not the newest stable version")
    previous_releases = {r["os_version"]: r for r in (old or {}).get("releases", [])}
    require(set(previous_releases) <= set(releases), "cannot remove old OS releases")
    changed = [r for k, r in releases.items() if r != previous_releases.get(k)]
    require(len(changed) == 1, "publish exactly one OS repository revision at a time")
    record = changed[0]
    require(record["revision"] == previous_releases.get(record["os_version"], {}).get("revision", 0) + 1, "index revision must increase by one")
    name = f'index-r{record["revision"]}.toml'
    path = stage / name
    require(digest(read(path, 2**20)) == record["sha256"] and path.stat().st_size == record["size"], "index hash/size mismatch")
    verify(path, cfg)
    index = load(path)
    require(index.get("format") == 1 and index.get("channel") == "stable" and moment(index["published"]) <= now + dt.timedelta(minutes=5), "invalid index metadata")
    require(set(index) == {"format", "channel", "published", "os_version", "arch", "revision", "system", "packages"}, "unknown index fields")
    require(index["os_version"] == record["os_version"] and index["revision"] == record["revision"] and index["arch"] == cfg["arch"] and index["system"] == cfg["system_packages"], "index identity mismatch")
    require(index["published"] == stable["published"], "metadata lifetime mismatch")
    paths = sorted(stage.glob("*.mpa"))
    require(0 < len(paths) <= cfg["max_packages"] and len(paths) == len(index["packages"]), "index/package count mismatch")
    packages = [package(p, cfg) for p in paths]
    check_graph(packages, cfg)
    expected_files = {"stable.toml", "stable.toml.sig", name, name + ".sig"}
    for p, entry in zip(packages, index["packages"]):
        expected = {k: p[k] for k in ("name", "version", "arch", "sha256", "filename", "size", "installed_size", "protected", "description", "license", "source")}
        expected.update(url=asset_url(cfg, record["os_version"], p["filename"]), signature_url=asset_url(cfg, record["os_version"], p["filename"] + ".sig"), dependencies=[d["name"] + " " + d["version"] for d in p["dependencies"]])
        require(entry == expected, "index does not match signed archive")
        expected_files.update((p["filename"], p["filename"] + ".sig"))
    require({p.name for p in stage.iterdir()} == expected_files, "unexpected staging files")
    return stable, index, expected_files


def sign(stage, key):
    paths = sorted(stage.glob("index-r*.toml")) + [stage / "stable.toml"]
    require(len(paths) == 2, "stage must contain one index and catalogue")
    sign_files(paths, key)


def sign_files(paths, key):
    require(paths, "no files to sign")
    for path in paths:
        require(path.is_file() and not path.is_symlink(), "not a regular signing input")
        require(not Path(str(path) + ".minisig").exists() and not Path(str(path) + ".sig").exists(), "signature already exists")
    # One Minisign process handles the passphrase and signs the complete batch.
    run(["minisign", "-S", "-s", key, "-t", "MPM official stable repository", "-m", *paths])
    for path in paths:
        Path(str(path) + ".minisig").rename(Path(str(path) + ".sig"))


def bundle(stage, output, cfg, previous):
    stable, _, files = check(stage, cfg, previous)
    require(output.name == f'submission-r{stable["revision"]}.tar' and not output.exists(), "use a new submission-rREVISION.tar output")
    with tarfile.open(output, "w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(files):
            tar.add(stage / name, arcname=name, recursive=False)


def extract(bundle_path, dest, cfg):
    require(not dest.exists(), "extract destination already exists")
    maximum = cfg["max_packages"] * (cfg["max_archive_bytes"] + 1536) + 3 * 2**20
    require(bundle_path.stat().st_size <= maximum + 2**20, "submission exceeds limit")
    with tarfile.open(bundle_path, "r:") as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        require(len(members) <= cfg["max_packages"] * 2 + 4 and len(set(names)) == len(names), "duplicate or too many submission members")
        require(sum(m.size for m in members) <= maximum, "submission exceeds unpacked limit")
        for member in members:
            require(member.isfile() and re.fullmatch(r"[a-zA-Z0-9_.+-]+", member.name) and not member.name.startswith("."), "unsafe submission member")
            limit = cfg["max_archive_bytes"] if member.name.endswith(".mpa") else 2**20
            require(member.size <= limit, "submission member exceeds limit")
        dest.mkdir(parents=True)
        for member in members:
            with tar.extractfile(member) as source, (dest / member.name).open("xb") as target:
                shutil.copyfileobj(source, target)


def gh(cfg, *args, **kwargs):
    return run(["gh", *args, "--repo", cfg["github"]], **kwargs)


def submit(stage, cfg, previous):
    stable, index, _ = check(stage, cfg, previous)
    tag = "v" + index["os_version"]
    with tempfile.TemporaryDirectory() as temp:
        archive = Path(temp) / f'submission-r{stable["revision"]}.tar'
        bundle(stage, archive, cfg, previous)
        result = subprocess.run(["gh", "release", "view", tag, "--repo", cfg["github"]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode:
            gh(cfg, "release", "create", tag, "--draft", "--title", "MachOS " + index["os_version"], "--notes", "Official stable MPM packages.")
        gh(cfg, "release", "upload", tag, archive)
    gh(cfg, "workflow", "run", "publish.yml", "--ref", "main", "-f", "os_version=" + index["os_version"], "-f", "revision=" + str(stable["revision"]))


def publish(bundle_path, cfg, previous):
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_REF") == "refs/heads/main", "publication runs only in the main-branch workflow")
    require(os.environ.get("GITHUB_REPOSITORY", "").lower() == cfg["github"].lower(), "workflow repository differs from configuration")
    require(not run(["git", "status", "--porcelain"], capture_output=True, text=True).stdout.strip(), "working tree must be clean")
    with tempfile.TemporaryDirectory() as temp:
        stage = Path(temp) / "stage"
        extract(bundle_path, stage, cfg)
        stable, index, files = check(stage, cfg, previous)
        tag = "v" + index["os_version"]
        remote = json.loads(gh(cfg, "release", "view", tag, "--json", "assets,isDraft,isImmutable", capture_output=True, text=True).stdout)
        require(not remote.get("isImmutable"), "release must remain appendable for package fixes")
        assets = {a["name"]: a for a in remote["assets"]}
        names = files - {"stable.toml", "stable.toml.sig"}
        # Old revisions stay available, and versioned archives are never overwritten.
        require(len(set(assets) | names) <= 1000, "GitHub release asset limit reached")
        catalogue = old_catalogue(previous, cfg)
        old_record = next((entry for entry in (catalogue or {}).get("releases", []) if entry["os_version"] == index["os_version"]), None)
        if old_record:
            prior = f'index-r{old_record["revision"]}.toml'
            require(prior in assets and prior + ".sig" in assets, "previously advertised index is missing from the release")
            old_dir = Path(temp) / "old"
            old_dir.mkdir()
            gh(cfg, "release", "download", tag, "--pattern", prior, "--pattern", prior + ".sig", "--dir", old_dir)
            verify(old_dir / prior, cfg)
            old_bytes = read(old_dir / prior, 2**20)
            require(len(old_bytes) == old_record["size"] and digest(old_bytes) == old_record["sha256"], "previous index differs from signed catalogue")
            previous_index = load(old_dir / prior)
            for entry in previous_index["packages"]:
                frozen = ("name", "version", "arch", "sha256", "filename", "size", "installed_size", "protected", "dependencies", "url", "signature_url")
                require(any(all(p[k] == entry[k] for k in frozen) for p in index["packages"]), "old package version removed or changed")
        for name in sorted(names):
            if name in assets:
                old = Path(temp) / "asset"
                old.mkdir(exist_ok=True)
                gh(cfg, "release", "download", tag, "--pattern", name, "--dir", old)
                require(read(old / name, cfg["max_archive_bytes"]) == read(stage / name, cfg["max_archive_bytes"]), "refusing to replace published asset: " + name)
                (old / name).unlink()
            else:
                gh(cfg, "release", "upload", tag, stage / name)
        if remote["isDraft"]:
            gh(cfg, "release", "edit", tag, "--draft=false", "--latest=false")
        # Publish discovery last. Both signed files enter one Git commit.
        shutil.copyfile(stage / "stable.toml", previous)
        shutil.copyfile(stage / "stable.toml.sig", Path(str(previous) + ".sig"))
        run(["git", "add", "stable.toml", "stable.toml.sig"])
        run(["git", "commit", "-m", f'Publish stable repository revision {stable["revision"]}'])
        run(["git", "push", "origin", "HEAD:main"])
        submission = f'submission-r{stable["revision"]}.tar'
        if submission in assets:
            gh(cfg, "release", "delete-asset", tag, submission, "--yes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "repository.toml")
    parser.add_argument("--previous", type=Path, default=ROOT / "stable.toml")
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare", help="verify signed packages and generate unsigned metadata")
    prep.add_argument("--packages", type=Path, required=True)
    prep.add_argument("--os-version", required=True)
    prep.add_argument("--output", type=Path, required=True)
    signing = commands.add_parser("sign", help="sign metadata locally; Minisign prompts for the key password")
    signing.add_argument("stage", type=Path)
    signing.add_argument("--key", type=Path, required=True)
    package_signing = commands.add_parser("sign-packages", help="sign a package batch locally using one Minisign process")
    package_signing.add_argument("directory", type=Path)
    package_signing.add_argument("--key", type=Path, required=True)
    for name in ("check", "submit"):
        cmd = commands.add_parser(name)
        cmd.add_argument("stage", type=Path)
    packing = commands.add_parser("bundle")
    packing.add_argument("stage", type=Path)
    packing.add_argument("--output", type=Path, required=True)
    publishing = commands.add_parser("publish")
    publishing.add_argument("submission", type=Path)
    args = parser.parse_args()
    try:
        cfg = config(args.config.resolve())
        if args.command == "prepare":
            name = prepare(args.packages, args.output, args.os_version, cfg, args.previous)
            print("Prepared " + name + "; sign the metadata locally next.")
        elif args.command == "sign":
            sign(args.stage, args.key)
        elif args.command == "sign-packages":
            sign_files(sorted(args.directory.glob("*.mpa")), args.key)
        elif args.command == "check":
            check(args.stage, cfg, args.previous)
            print("Repository signatures, packages, dependencies and metadata are valid.")
        elif args.command == "bundle":
            bundle(args.stage, args.output, cfg, args.previous)
        elif args.command == "submit":
            submit(args.stage, cfg, args.previous)
        elif args.command == "publish":
            publish(args.submission, cfg, args.previous)
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, zlib.error, tarfile.TarError, subprocess.CalledProcessError) as error:
        parser.exit(1, "repository: " + str(error) + "\n")


if __name__ == "__main__":
    main()
