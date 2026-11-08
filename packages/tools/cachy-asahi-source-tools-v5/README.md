# cachy-asahi-source-tools 0.4.0

Original MIT developer package for offline exact release source delivery. It runs from an arbitrary prefix: the launcher locates its private runtime relative to its own installed location. Python >=3.14 supplies bounded gzip/xz/zstd inspection. Explicit xz and zstd dependencies supply liblzma and libzstd for its extension modules. There are no pip libraries or external runtime commands. Build with `makepkg --cleanbuild --force` from the complete recipe directory; base-devel is the build environment, bubblewrap is a check dependency. No root privileges or system installation are needed to build or check it.

The six entrypoints forward the existing arguments without changing authority:

| Command | Existing operation |
| --- | --- |
| `cachy-asahi-source-tools mirror-export` | `release_source_mirror.py export` |
| `cachy-asahi-source-tools mirror-successor` | `release_source_mirror.py update` |
| `cachy-asahi-source-tools mirror-verify` | `release_source_mirror.py verify` |
| `cachy-asahi-source-tools mirror-list` | Verified release/package catalog and exact context pins |
| `cachy-asahi-source-tools build-context` | `mirror_consumer.py materialize` |
| `cachy-asahi-source-tools verify-context` | `mirror_consumer.py verify-context` |

Option names must be written in full. Each pin, selector and path option may appear only once, including equal-valued repeats and mixed `--option=value`/`--option value` forms. Duplicate or abbreviated options refuse before the private runtime is loaded. The existing `-h`/`--help` forms remain available.

Run any command with `--help` for required paths and SHA-256 pins. Export requires a caller-authenticated release.json digest plus a complete retained release directory. Fixed-SHA256 HTTPS recipes additionally require the exact retained-input descriptor/root/digest; cache verification is always offline. Verify requires bundle SHA-256 and selected release SHA-256. Successor requires the previous bundle, its SHA-256, previous head release digest, and complete next-release inputs. It retains all historical release objects and reports new/reused/retired/recovery counts without pruning. Verification can select any retained release by its exact digest.

`mirror-list --bundle mirror.tar --sha256 <authenticated-bundle-sha256> --release-sha256 <authenticated-release-sha256>` lists the selected release's packages and their exact `build-context` pins as deterministic JSON. It also lists retained release IDs and digests, so a recovery release can be selected explicitly. The entire mirror history is verified before any catalog is printed. A changed object anywhere in the history refuses; listing does not grant build, license, source-completeness or release approval. It reads only the caller-selected local bundle and creates no files.

Each `packages` row supplies `package`, `version`, `arch`, `package_sha256`, `recipe_sha256` and `srcinfo_sha256`; combine those values with the same bundle, `mirror_sha256` and `release_sha256` in `build-context`. This avoids manually inspecting retained tar members to discover the required pins.

`build-context` additionally requires exact package/version/architecture/archive/PKGBUILD/SRCINFO pins. It prepares a fresh context containing the recipe, notices, retained archive/BUILDINFO/provenance, verified HTTPS SRCDEST where applicable, and a held builder request. `verify-context` checks its caller-pinned selection.json. No command invokes a native builder, downloads sources, executes retained Python/PKGBUILD, or installs packages. All actual builder selectors stay NULL. Request generation and source custody do not establish a rebuild.

Current and retained legacy original recipe profiles are frozen v1 copies. Supported remote inputs are fixed-SHA256 HTTPS archives. Split packages, unsupported VCS/SKIP inputs and compressed source bundles refuse. Bundle objects are bounded to 64 MiB each, 512 MiB total and 16,384 objects; histories retain at most 256 releases and cumulative references are bounded. Package archive gzip/xz/zstd input is supported; source bundles remain uncompressed USTAR. Missing or altered source, license, cache, recipe or provenance bytes refuse. Full corresponding-source/dependency-source completeness and redistribution permission remain caller review responsibilities.

Package payload: one launcher, the unchanged eleven private helper/data files plus the new catalog helper, this guide, source provenance and payload map, MIT license and NOTICE. Helpers under usr/lib are 0644; only the launcher is 0755. The container entry script is retained as non-executable data whose exact digest is included in held builder requests. There are no hooks, services, configuration files, backup entries or dependencies on release-tools v1/v2. Removal deletes only the declared package files. User-created mirror and builder directories are not package-owned and remain after removal.

The package checks stage files into a private prefix, move it, hide the original checkout in a network-disabled bubblewrap mount namespace, and exercise exact two-package old/current mirror history, deterministic export, every rebuild context, and tamper/incomplete refusals. Retained source/archive fixtures are synthetic test evidence with real original recipe bytes; they are never executed. Native ARM build, ALPM installation, native16K, M2/hardware and release acceptance require separate qualification. Performance is not measured.

The catalog helper is original MIT project source, retained separately as `source_mirror_catalog.py` with exact SHA-256 in the recipe and installed payload map. The original eleven-file packed runtime, its source provenance and frozen recipe profiles remain byte-identical. Focused catalog tests cover real single-release and retained-history inputs, selected recovery/current package pins, refusal and context consumption. These checks do not invoke a native builder or install packages.

## Compare retained releases

The 0.5.0 recipe retains the verified `mirror-diff` and `context-info` workflows. The
maintained 0.2.0 package and its frozen native inputs remain separately tracked.

```sh
cachy-asahi-source-tools mirror-diff --bundle history/mirror.tar \
  --sha256 "$MIRROR_SHA256" --from-release-sha256 "$OLD_RELEASE_SHA256" \
  --to-release-sha256 "$NEW_RELEASE_SHA256"
```

The command authenticates the entire mirror history before reporting sorted
added, removed, changed, and unchanged packages. Each row contains both exact
build-context selectors and the changed version, architecture, archive, recipe,
SRCINFO, and source-profile fields. Reverse the release pins to inspect a
rollback; use the same pin twice to confirm no changes. Wrong pins or damaged
recovery objects refuse without a partial diff. Retained recipes stay inert.
The result does not assert installation, source completeness, legal approval,
Native/M2 compatibility, performance, or release acceptance.

## Inspect an inert build context

```sh
cachy-asahi-source-tools context-info --context moved-context \
  --selection-sha256 "$SELECTION_SHA256"
```

After full context verification, `context-info` reports its exact package, mirror
and release selectors; recipe and SRCINFO checksums; retained recipe/source
inputs; and the builder selector names held at NULL. It writes no context data
and starts no builder. A moved context uses the same caller-pinned selection.
The 0.5.0 recipe is an independently versioned, unselected development candidate;
0.2.0 Native inputs and the archived 0.3.0 diff candidate remain separately held.

## Prepare every package in one release

```sh
cachy-asahi-source-tools release-context --bundle history/mirror.tar \
  --sha256 "$MIRROR_SHA256" --release-sha256 "$RELEASE_SHA256" --output release-contexts
cachy-asahi-source-tools verify-release-context --context-set release-contexts \
  --manifest-sha256 "$MANIFEST_SHA256"
```

`release-context` verifies the complete retained mirror, prepares every package's
inert context, and publishes the set together with one pinned manifest. A failed
package leaves the final output absent; an existing destination is preserved.
Each manifest row has its exact package selectors, relative context directory
and child selection pin. The set retains its authenticated mirror, so a moved
set can be verified offline and checked for complete release coverage. Changing
the manifest pin alone cannot make a partial package set complete.

The mirror and aggregate context tree retain the existing independent bounds;
no per-package bound is multiplied by the package count. No builder starts and
all seven builder selectors remain NULL. The package adds no service or install
hook; removing package-owned files preserves the caller's context sets. Current
0.2.0 Native inputs and the archived 0.3.0/0.4.0 candidates remain separate.
