# Contributing packages

This repository publishes the official stable MachOS package collection. New
applications and fixes are proposed through pull requests and reviewed by the
maintainer. Contributors do not need a signing key. Only the maintainer signs
and publishes official packages.

Include the upstream source URL, exact source revision, license, dependencies,
build commands and supported MachOS version in your pull request. Prefer builds
from pinned source. Include required license notices in the package. Do not
submit private keys, prebuilt archives or generated repository metadata in a PR.
Package archives are release assets, not Git objects.

Add a definition in `packages/NAME.toml` containing `name`, `description`,
`license` and `source`. Use a short printable ASCII description and an HTTPS
source URL. Package names use lowercase letters, digits, hyphens or underscores
and start with a letter. Versions follow semantic versioning. Include the source
and build instructions needed to reproduce the package; do not introduce an
unreviewed binary download as a build step.

A package is a `.mpa` gzip-compressed plain ustar archive. Its first member is
`manifest.toml`; other members are regular files under `files/`, matching the
manifest's file inventory. Links, traversal, duplicate members, install scripts
and tar extensions are not supported. Archive names are
`NAME-VERSION-x86_64.mpa`; signatures are `NAME-VERSION-x86_64.mpa.sig`.
Dependencies use exact versions or `>=VERSION`. The public collection must have
compatible latest versions, no dependency cycles and no overlapping ownership
between different packages. Account databases and MPM trust/database files are
reserved. Only declared protected system packages may own `/boot` files.

Run `python3 -m unittest discover -s tests -v` before submitting changes. Tests
use disposable local signing keys and never access the maintainer's key. PR
checks have read-only permissions. Publication runs only from reviewed `main`
through the manually dispatched publishing workflow.

# Repository layout and discovery

Each stable OS version has one GitHub release, tagged `vX.Y.Z`. It contains all
published versions of that OS version's packages and signatures, plus signed
`index-r1.toml`, `index-r2.toml`, and subsequent index revisions. Fixes append new
package versions and a new index. Existing package files, signatures and index
snapshots must not be replaced or removed.

`stable.toml` and `stable.toml.sig` on `main` are the signed discovery catalogue.
They list every supported OS version's current index URL, index signature URL,
size and SHA-256, and identify the newest stable OS version. Each index lists
package names, descriptions, versions, architecture, download and signature URLs,
compressed/installed sizes, hashes, licenses, source URLs, dependencies and the
required system package set.

An MPM client verifies the catalogue before trusting any URL. It checks expiry,
UTC timestamps and the last accepted catalogue revision. It must reject older
revisions, or changed content at an already accepted revision. The repository
also chains each catalogue to its predecessor by SHA-256. After a refresh, the
client verifies the referenced index's hash, size and signature, then each
archive's hash and signature before installation. Package archives remain
individually verifiable offline. The catalogue supplies freshness for the index
snapshots; indexes themselves do not expire independently.

The catalogue expires after 30 days. Renew it by preparing and signing a new
revision, even when package contents have not changed. Clients must not silently
accept expired metadata or unsigned repository packages. A failed refresh keeps
the previously verified cache; installing from an expired catalogue is refused.
Signing prevents tampering and revision tracking prevents rollback after a
client has seen a newer revision; expiry bounds replay to a new client. GitHub
raw-file caches can briefly serve a mismatched catalogue/signature pair during
publication. Clients retry that pair and keep their prior verified cache; they
never bypass signature checks.

Refreshing uses the current OS version's index for ordinary package fixes.
The catalogue's `latest_os` identifies a full-system upgrade target. The MPM
system-upgrade implementation must resolve the complete protected system set,
stage and verify it before replacing files, coordinate boot/EFI changes and
recovery, and switch the recorded OS version only after a successful operation.
This repository produces that metadata; it does not implement the guest upgrader.

# Publishing

Install Python 3.11 or newer, Minisign and GitHub CLI. Set the eventual GitHub
repository name in `repository.toml` before signing the first catalogue. Keep the
same name in the MPM client. The repository's only signing material is the
public key in `keys/official.pub`; private keys stay encrypted on the maintainer's
machine. No private key or passphrase belongs in GitHub Actions secrets.

Build the `.mpa` files with the MachOS package builder and use the canonical
archive names above. Put the complete collection for that OS version, including
older published archive versions, in a local directory. If those existing
packages are already signed, leave their signatures unchanged. Sign only new
archives in a separate input directory:

```sh
python3 tools/repository.py sign-packages out/new-packages --key /path/to/encrypted.key
```

Combine the newly signed packages and old packages in `out/packages`, then:

```sh
git pull --ff-only
python3 tools/repository.py prepare --os-version 0.9.3 --packages out/packages --output out/stage
python3 tools/repository.py sign out/stage --key /path/to/encrypted.key
python3 tools/repository.py check out/stage
python3 tools/repository.py submit out/stage
```

The first command generates the package index and next discovery catalogue.
Preparation verifies every package signature against the official key, validates
archive contents and dependencies, and calculates index values from actual
archives. Signing runs locally in Minisign; it handles the password directly.
The check command verifies the signed stage again. Submit creates a draft release
when needed, uploads a submission bundle and dispatches the publishing workflow.
No GitHub account or token is needed for preparing, signing or checking locally.

The workflow independently repeats the checks, compares existing release assets,
uploads new assets, publishes a new draft release, and only then commits the
signed discovery catalogue to `main`. It never overwrites package/index assets.
The entire index revision must pass before discovery changes. Failed uploads or
failed catalogue pushes leave the previous catalogue in effect. Rerunning the
workflow can finish an interrupted publication because identical existing assets
are accepted. A stale submission must be prepared again against the current
catalogue. The submission bundle is deleted after successful publication.

Keep release immutability disabled: GitHub's immutable releases cannot accept
new package assets after publication. Integrity here comes from signed metadata,
versioned asset names and refusal to overwrite an existing asset. Do not manually
replace assets through the GitHub interface.

The publishing workflow needs permission to create releases and push the signed
catalogue to `main`. Its concurrency group serializes publication. Allow this
specific workflow to push if branch protection is enabled; PR checks still have
read-only permissions. The workflow signs nothing and never executes code from
package payloads. Publishing and branch permissions are configured by the owner;
these tools do not change repository settings automatically.

For an inspectable submission without uploading anything:

```sh
python3 tools/repository.py bundle out/stage --output out/submission-r1.tar
```

The number in that filename is the global catalogue revision, not the per-OS
index revision. Work remains local until an explicit `submit` command. Repository
packages retain their individual licenses; repository tooling is GPL-3.0-only.
