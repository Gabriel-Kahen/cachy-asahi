# Repository CLI package native builds, 2026-10-15

[Run 38782193131](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38782193131)
succeeded with product Source `98fecf28a3cde63a9dd7531501c2187825349310` and
workflow `4cdadf02cc97e24d8dfa5146abd9b7a194ac04ac`. The retained originals
establish two native ARM builds of **cachy-asahi-setup 0.1.0-4** and one exact
archive comparison. Installed repository enrollment and package lifecycle remain
**NOT RUN** by this build-only job.

The ordinary hosted runner records Linux `aarch64`, ARM Neoverse-N2, UID/GID
1001:1001 and 4096-byte pages. Both builds record network `none`, native mode,
epoch 1791748800, and the same signed-input builder image:
`sha256:173e4b8f57026f63ad53d6670be7a31fb35d8c6e9082d03f737c5d4502e50178`.
The input lock is
`beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f` and the
341-package builder inventory is
`fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25`.

## Retained package and checks

Both original `cachy-asahi-setup-0.1.0-4-any.pkg.tar.xz` archives are **22632
bytes**, SHA-256
`c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a`.
Their actual compressed bytes compare equal locally. The retained comparison
also reports equal installed contents, PKGINFO and BUILDINFO, with no errors.
The two provenance records report successful build exits and distinct named
containers; all twenty declared output-file hashes match retained bytes.

All 29 recipe inputs match the exact product Source. Both archive payloads contain
exactly six regular files, owned by root:

| Installed path | Mode | Verified source |
| --- | --- | --- |
| `/usr/bin/cachy-asahi-setup` | 0755 | Unchanged canonical per-user helper |
| `/usr/bin/cachy-asahi-repository` | 0755 | Unchanged canonical repository enrollment CLI |
| `/usr/share/doc/cachy-asahi-setup/README.md` | 0644 | Selected recipe README |
| `/usr/share/doc/cachy-asahi-setup/repository-enrollment.md` | 0644 | Unchanged canonical repository guide |
| `/usr/share/licenses/cachy-asahi-setup/NOTICE` | 0644 | Selected recipe notice |
| `/usr/share/licenses/cachy-asahi-setup/LICENSE` | 0644 | Project MIT license |

The unchanged setup executable SHA-256 is
`3e652bff75f6202cd3c13c327e50a298f7b25149b3c5cb55cdf4912d35af5919`;
the new packaged repository executable is
`38db2d45955b569a4c74c3f31d6b6c79611126238e1bbe1e5cf819f81d0fb54f`.
Metadata declares `python>=3.11`, `gnupg`, and `pacman`, with the same three
optional template dependencies. There is no install script, hook, service or
package-owned `/etc` payload.

Three exported canonical-source/license synchronization logs pass. Each native
build reaches the recipe's successful `check()` phase, with three copied-source
pin checks and ten passing focused synchronization tests. The pinned check phase
also parses both Python executables and runs inert help for the setup command,
repository command, `enroll`, and `disable`; help output is redirected, rather
than exported as four separate reports. No enrollment/apply/disable action is
run by package construction. Earlier eleven real GPG/pacman-key trust fixtures
are separate source evidence and were not rerun by this job.

## Retention, cleanup and limits

This review reads the once-collected
[logs.zip](../../artifacts/development/repository-enrollment-run38782193131/logs.zip),
2305637 bytes, SHA-256
`955c35e3dea6b267109bb240d3fa96102a6e9602d4334eb7cb8e0cc53e87747e`.
ZIP CRC checks pass. All four ordinary `log_evidence.py` frames match their
declared compressed sizes and hashes: summary 3276 bytes, native 773589 bytes,
build-1 117634 bytes, and build-2 117645 bytes. They contain 102 regular files,
8118073 uncompressed bytes. Readable
[retention details](../../artifacts/development/repository-enrollment-package-20261015/native-run38782193131-review/retention.json)
and [local comparisons](../../artifacts/development/repository-enrollment-package-20261015/native-run38782193131-review/local-validation.json)
remain beside the decoded existing frames. No download, rebuild, helper replay or
new CI dispatch was performed for this review.

The run's cleanup result reports absence of its two recorded build containers
(`cachy-asahi-8061ae7781b299d5`, `cachy-asahi-7fd4224ec3e546f6`) and removal/absence
of the one recorded builder image, with cleanup PASS. This is the exported scoped
cleanup observation; host Docker daemon shutdown and retained input-cache deletion
are not established. It is not a claim that every host image, layer or process was
removed.

This accepts the finite generic ARM package build pair and reviewed delivery
payload. It does not accept a production endpoint/key, signed release repository,
installed 3→4 upgrade/remove/reinstall, installed trust enrollment, actual Asahi
dependency transaction, macOS installation, either M2 Air size, physical 16K-page
operation, abrupt-power-loss recovery, or performance. The historical setup3 and
frozen core/P0/full587 records remain separate; this document rewrites none of
them. Root owns package/default-lock/inventory adoption and the installed lifecycle
follow-on.
