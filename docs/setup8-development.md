# Setup8 development selection and explicit user setup

The development candidate is **cachy-asahi-setup 0.3.0-1**, recipe
`packages/tools/cachy-asahi-setup8/PKGBUILD`. It is the same ALPM package name as
legacy0.1.0-7, so select one recipe/version; do not co-install or assemble both.
The inventory remains a development catalog, not an install list. Release
selection stays false. [Accepted evidence and limits](validation/setup8-migration-native-20261027.md)
cover the exact package inputs copied from Source5d0f5ae6331807704a8ebafc7922972629e0b96f.
A new whole canonical tree or composed system is not thereby native-qualified.

## Current source entrypoints

Run from a trusted checkout as the intended ordinary user:

```sh
python3 -B scripts/setup8/setup.py --help
python3 -B scripts/setup8/config_migrate.py --help
python3 -B scripts/setup8/setup.py activate --components fish zsh hyprland
```

The last command previews only. Add `--apply` to explicitly write setup changes.
Templates must already be installed and selected components are opt-in. The
migration source command imports its pinned sibling setup contract; it is not
invoked with Python isolated mode. The installed migration launcher separately
uses isolated Python and fixed `/usr/lib/cachy-asahi/setup8/` modules.

Legacy `scripts/setup/`, `packages/settings/cachy-asahi-setup/`, their tests and
all historical evidence remain unchanged for Setup7 fixtures. The original
migration engine already existed under `scripts/setup/config_migrate.py` and
has the same hash as the new namespace. The new namespace supplies the accepted
Setup8 status contract and the exact delivered engine/test identity without
rewriting the old helper used by accepted legacy package checks.

The [legacy setup guide](setup-tooling.md) and [original migration handoff](port/configuration-migrations.md)
retain their historical source paths. Use the `scripts/setup8/` paths here for
current development. The frozen package README/provenance and installed guide
also retain pre-run statements; they are historical input bytes. The linked
accepted-evidence document is the current qualification record. Rewriting those
packaged files would change the accepted0.3.0-1 recipe/payload identity.

## Installed commands and ownership

After a separately reviewed package installation, the public commands are
`cachy-asahi-setup`, `cachy-asahi-repository` and
`cachy-asahi-config-migrate`. No hook invokes them. The package does not apply
user configuration, install dependencies, select a login shell, enable services,
register a session or change Asahi boot/firmware/kernel/Mesa/audio protection.
The unchanged repository helper preserves explicit enrollment and signature
policy; configuration migration does not authorize repository trust changes.

For migration preview, supply an explicitly reviewed manifest and its raw SHA256:

```sh
cachy-asahi-config-migrate preview --manifest /absolute/reviewed.json --sha256 "$REVIEWED_SHA256"
```

`status` is read-only. Migration `apply` writes immediately; `recover` explicitly
finishes an interrupted migration. No default migration manifest/template roots
are installed. Retain the exact manifest/hash and immutable old/new roots across
recovery; a content hash is not release authentication. Conflicts or changed
owned content refuse rather than overwrite user bytes. Setup status identifies
migration-owned intent but does not certify its readiness. Package removal and
reinstall preserve homes, journals and ledgers; neither replays a migration.

## Recipe inspection and build selection

The generic `package_checks.py recipes` discovery currently scans only desktop,
shells and settings. It does not inspect this tools recipe. Inspect it explicitly:

```sh
python3 -I -B packages/tools/cachy-asahi-setup8/check-sync.py
python3 -I -B - <<'PY'
import importlib.util, json
from pathlib import Path
path = Path('scripts/checks/package_checks.py').resolve()
spec = importlib.util.spec_from_file_location('checks', path)
checks = importlib.util.module_from_spec(spec); spec.loader.exec_module(checks)
report = checks.recipe(Path('packages/tools/cachy-asahi-setup8/PKGBUILD'))
print(json.dumps(report, indent=2, sort_keys=True))
raise SystemExit(bool(report['errors']))
PY
```

Required dependencies remain `python>=3.11`, `gnupg` and `pacman`; nine template/
module dependencies remain optional. The static check is not an actual target
resolution, installation or Asahi compatibility test. The accepted recipe has20
inputs and ten installed payload files, no install script and no automatic hook.

For a future fresh build, choose this recipe explicitly with the existing builder:

```sh
python3 -B scripts/build/build.py packages/tools/cachy-asahi-setup8 \
  --image "$REVIEWED_ARM64_IMAGE_DIGEST" --output "$FRESH_OUTPUT" --mode native \
  --source-date-epoch "$SOURCE_DATE_EPOCH" \
  --expected-packages "$REVIEWED_IMAGE_PACKAGE_LOCK" \
  --reviewed-inputs "$REVIEWED_RECIPE_INPUTS"
```

The image digest, package lock and recipe input map must be independently reviewed;
the command is a build interface, not permission to publish or install. No build
is needed to restate the existing accepted evidence. Development inventory
selection does not retarget frozen native/composition/catalog locks, scheduled
workflows or a release. Those keep their exact legacy source/artifact identities
until their coordinator reviews a separate integration.

Current evidence is one generic native ARM4K host and disposable inert user
fixtures. The hosted setup source suite is93 registered/91 passed/2 skipped;
those skips do not establish installed shell coverage. Actual user profiles,
real shell modules, signed integrated lifecycle, native16K, both M2 sizes,
performance and supported release remain separate.
