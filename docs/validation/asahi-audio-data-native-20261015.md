# Asahi audio data: native package construction, 2026-10-15

[Run 38789569155](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38789569155)
completed successfully. Source `56b44dfde8d9b86ac9c48b830fa678ef1778232c`,
workflow `06cda83fb0515ba541629de52fd0dcdd42cb2180`, built two fresh native ARM
packages for each of two pinned data recipes: **four builds, two exact-byte
comparisons, PASS**. This is build-only development evidence. Runtime dependency
resolution, installation, activation, audio behavior and hardware validation were
**NOT RUN**; release selection remains false.

## Selected inputs and environment

- `asahi-audio` 4.1-2 uses upstream v4.1 revision
  `687d8cd0f6dc4b12fc0d9c3aebe360656de2882e`, source SHA-256
  `e2c3887fe20481675698ac8174f53b66276f75a2b3c0853daf9b1a70dda690c5`.
- `alsa-ucm-conf-asahi` 10-2 uses upstream v10 revision
  `1473329acab595dfef039f38c384ce16674d6b15`, source SHA-256
  `4cbf77e7113dbe3981c1aa271bc12f30c8af1ac3326db8e261ee8aa25cf37295`.
- The retained seven inputs per recipe in each build match the exact selected
  Source and its fixed input map. Preparation-time `NOT RUN` fields in packaged
  provenance remain historical and were not rewritten after this trial.
- The runner and local Docker server report `aarch64`; the CPU is Neoverse-N2,
  kernel `6.17.0-1022-azure`, page size 4,096 bytes. Four distinct container names
  used native `linux/arm64`, UID/GID 1001, network `none`, read-only roots,
  dropped capabilities, no-new-privileges and bounded resources. They share one
  machine and builder; this is not independent-machine reproduction.
- Signed-input bootstrap selected lock
  `beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f`:
  retained acquisition reports 501/501 objects passing, 249 signature records
  cover the rootfs plus 248 package inputs. The resulting 341-package inventory
  hash is `fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25`.
  Image ID was `sha256:27028b15995a733dc00958ffab70ff8d91e085d25baa185d0df1b1bf75e7ae0c`.
  These signatures authenticate bootstrap inputs; the new candidate archives are
  unsigned development outputs, with no target trust enrollment performed.

## Actual package results

Both builds of each row have the same archive size and SHA-256. All four
provenance records report exit 0 and `built-package-static-pass`; retained
comparison records report equal archive bytes, installed contents, `.PKGINFO`
and `.BUILDINFO`, with empty error lists. Package construction ran from
18:57:41 through 18:58:00 UTC, excluding bootstrap.

| Archive | Bytes per build | SHA-256 | Payload files / directories |
| --- | ---: | --- | ---: |
| `asahi-audio-4.1-2-aarch64.pkg.tar.xz` | 1,395,012 | `9adbdd1862d975bbbbb10e62f6c68ffad08bed8e32575f1681cbd40bbf533cfa` | 95 / 22 |
| `alsa-ucm-conf-asahi-10-2-any.pkg.tar.xz` | 9,836 | `b4eeab98e530489a9e4b5f0d46cf6946f556efedb76d4489be936bbbb8216ee4` | 48 / 17 |

Review of all four retained archives matches every declared payload path,
SHA-256, mode and owner against the selected payload map. Every payload file is
regular, root-owned mode 0644; directories are the exact ancestor set, root-owned
mode 0755. There are no symlinks, ELF files, executable-mode files, `.INSTALL`,
ALPM hooks, systemd units or udev rules in these two outputs. Forty retained
provenance-file digests and 28 copied recipe-input digests also verify.

The Asahi package contains 90 upstream FIR/graph/audio configuration files plus
five license/documentation files. Its mode-0644 Lua script is interpreted
runtime code; PipeWire/WirePlumber defaults could affect audio after a future
installation. The UCM package contains 43 upstream profiles plus five
license/documentation files. Full upstream MIT / BSD-3-Clause grants and separate
MIT packaging attribution are present and match the pinned payload bytes.

## Deliberately separate build-only policy

The ordinary protected-name and protected-payload guards were retained. Each
recipe is rejected by the generic checker for its protected name. Each exported
package report preserves `generic_guard_status = fail` and the exact generic
protected-error set: 10 errors for Asahi audio and 54 for UCM, including protected
directory members. The fixed-two build-only caller requires these exact sets,
all input hashes and the complete data payload; additional errors are not waived.
Its local `build-only-data-static-pass` does not constitute an ordinary overlay
or release-policy pass.

The staged entry script differs from the ordinary entry only by `--nodeps` on
the final construction command; its retained hash
`7b537f511d5312955431af81b203ea78352d5e172742a9686e437ac2bdc055ad`
verifies against that exact transformation. Logs explicitly warn that dependency
checks are skipped. The built `.PKGINFO` retains all runtime requirements:

- Asahi audio: `wireplumber>=0.5.2`, `pipewire>=1.0`, `bankstown>=1.1.0`,
  `lsp-plugins-lv2>=1.2.15`, `speakersafetyd`, `triforce-lv2>=0.2.0`.
- UCM: `alsa-ucm-conf>=1.2.7.2`.

The result honestly reports `DECLARED-BUT-NOT-RESOLVED`. Successful construction
with these dependencies bypassed does not demonstrate an installable transaction
or safe speaker operation. The upstream kernel prerequisite remains a separate
coordinated platform selection; this trial replaced no kernel or working stack.

## Retained evidence and cleanup

The once-collected `artifacts/development/asahi-audio-data-run38789569155/logs.zip`
is 20,095,549 bytes, SHA-256
`a83ba3c99636ed50933e208e4b03e419c1b067e341cd485530e3437c6f3eacd4`,
with passing ZIP CRCs. Only the dedicated retention-step frames were decoded,
avoiding the duplicate aggregate job log. All six ordinary `log_evidence.py`
frame sizes and hashes verify; [the artifact readout](../../artifacts/development/asahi-audio-data-run38789569155/READOUT.md)
lists them and points to decoded records.

Cleanup reports PASS and verifies absence of the exact four build containers and
one owned builder image. It is scoped to those Docker resources, not a claim
that all runner files, seeded cache objects or temporary GPG directories were
erased. The bundle intentionally excludes bootstrap `context/` and `gpg/`.
No host package installation, host trust change, service activation, audio probe,
M2/16K acceptance, performance measurement or full platform composition is
established. No recollection, rebuild or actor replay was used for this readout.
