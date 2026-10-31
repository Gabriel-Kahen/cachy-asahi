# cachy-asahi-source-tools 0.1.0

Original MIT developer package for offline exact release source delivery. It runs from an arbitrary prefix: the launcher locates its private runtime relative to its own installed location. Python >=3.14 supplies bounded gzip/xz/zstd inspection. Explicit xz and zstd dependencies supply liblzma and libzstd for its extension modules. There are no pip libraries or external runtime commands. Build with `makepkg --cleanbuild --force` from the complete recipe directory; base-devel is the build environment, bubblewrap is a check dependency. No root privileges or system installation are needed to build or check it.

The five entrypoints forward the existing arguments without changing authority:

| Command | Existing operation |
| --- | --- |
| `cachy-asahi-source-tools mirror-export` | `release_source_mirror.py export` |
| `cachy-asahi-source-tools mirror-successor` | `release_source_mirror.py update` |
| `cachy-asahi-source-tools mirror-verify` | `release_source_mirror.py verify` |
| `cachy-asahi-source-tools build-context` | `mirror_consumer.py materialize` |
| `cachy-asahi-source-tools verify-context` | `mirror_consumer.py verify-context` |

Run any command with `--help` for required paths and SHA-256 pins. Export requires a caller-authenticated release.json digest plus a complete retained release directory. Fixed-SHA256 HTTPS recipes additionally require the exact retained-input descriptor/root/digest; cache verification is always offline. Verify requires bundle SHA-256 and selected release SHA-256. Successor requires the previous bundle, its SHA-256, previous head release digest, and complete next-release inputs. It retains all historical release objects and reports new/reused/retired/recovery counts without pruning. Verification can select any retained release by its exact digest.

`build-context` additionally requires exact package/version/architecture/archive/PKGBUILD/SRCINFO pins. It prepares a fresh context containing the recipe, notices, retained archive/BUILDINFO/provenance, verified HTTPS SRCDEST where applicable, and a held builder request. `verify-context` checks its caller-pinned selection.json. No command invokes a native builder, downloads sources, executes retained Python/PKGBUILD, or installs packages. All actual builder selectors stay NULL. Request generation and source custody do not establish a rebuild.

Current and retained legacy original recipe profiles are frozen v1 copies. Supported remote inputs are fixed-SHA256 HTTPS archives. Split packages, unsupported VCS/SKIP inputs and compressed source bundles refuse. Bundle objects are bounded to 64 MiB each, 512 MiB total and 16,384 objects; histories retain at most 256 releases and cumulative references are bounded. Package archive gzip/xz/zstd input is supported; source bundles remain uncompressed USTAR. Missing or altered source, license, cache, recipe or provenance bytes refuse. Full corresponding-source/dependency-source completeness and redistribution permission remain caller review responsibilities.

Package payload: one launcher, eleven private helper/data files, this guide, source provenance and payload map, MIT license and NOTICE. Helpers under usr/lib are 0644; only the launcher is 0755. The container entry script is retained as non-executable data whose exact digest is included in held builder requests. There are no hooks, services, configuration files, backup entries or dependencies on release-tools v1/v2. Removal deletes only the declared package files. User-created mirror and builder directories are not package-owned and remain after removal.

The package checks stage files into a private prefix, move it, hide the original checkout in a network-disabled bubblewrap mount namespace, and exercise exact two-package old/current mirror history, deterministic export, every rebuild context, and tamper/incomplete refusals. Retained source/archive fixtures are synthetic test evidence with real original recipe bytes; they are never executed. Native ARM build, ALPM installation, native16K, M2/hardware and release acceptance require separate qualification. Performance is not measured.
