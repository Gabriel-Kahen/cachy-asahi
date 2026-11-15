# Genuine historical Python 3.14.7 host upgrade analogue

This bounded successor runs the real standard Arch **x86_64**
`python 3.14.7-1` → source-built `3.14.8-1.1` → exact retained `3.14.7-1`
upgrade/rollback in a disposable private ALPM root. It leaves the completed
`../python314_candidate/` downgrade implementation and evidence unchanged.
This closes a host workflow gap; it does not qualify the protected Asahi ARM
transaction or either M2 machine.

## Exact historical inputs

A bounded retained-file check found only the host's different CachyOS
`3.14.7-2/x86_64_v3` cache. It was not substituted. Exactly two official URLs
were then acquired, both HTTP 200:

| Official material | Bytes | SHA-256 |
| --- | ---: | --- |
| [python-3.14.7-1-x86_64.pkg.tar.zst](https://archive.archlinux.org/packages/p/python/python-3.14.7-1-x86_64.pkg.tar.zst) | 14,184,166 | `8a350ce53aae01ae687f043b301931e411bf06333ba480b42b3b5432a0e6c79b` |
| [Detached signature](https://archive.archlinux.org/packages/p/python/python-3.14.7-1-x86_64.pkg.tar.zst.sig) | 310 | `ff4000fab52654e77a2de73ff242ea809b0b4fd2e17951a8375f575180c1ecae` |

The candidate remains the unchanged full-Tk second-run archive, SHA-256
`8474bf623e6efe46f02ef5dd65b7707b2f526a7a612661b33819920e451b016e`.
That project-built candidate has no original public package signature; it is
not represented as an upstream-signed Arch binary.

The historical package's original public signature is verified against the
disposable image's Arch keyring **before any TEST keys or signatures exist**.
Actual verification reports Jelle van der Waa, fingerprint
`E499C79F53C96A54E572FEE1C06086337C50773E`, with a good signature dated
August 10, 2026. This is package signature verification through the retained
keyring, not independent current revocation/signature-freshness or legal signoff.
The previously used official 3.14.9 provisioning archive is verified separately
by the unchanged provisioning helper; it is only setup context here.

The historical declared dependencies include `libnsl` and `libxcrypt`. Both are
already in the frozen November 9 image closure. Provisioning explicitly checks
the full declared dependency list with `pacman -T`; the actor additionally runs
real ALPM resolution and dependency-integrity checks. No dependency bypass,
provider substitution, version fallback or broad closure search is permitted.
Missing exact material, failed public verification or missing closure stops the
path with a retained blocker before runtime TEST signing.

## Run and actual workflow

```sh
python3 -I -B scripts/integration/python314_upgrade/acquire.py \
  --output "$PWD/work/python314-upgrade-inputs"
python3 -I -B -Werror::ResourceWarning \
  scripts/integration/python314_upgrade/test_upgrade.py -v
python3 -I -B -Werror::ResourceWarning \
  scripts/integration/python314_upgrade/run.py \
  --candidate /tmp/cachy-asahi-python314-tk-full-second-20261114/export/python-3.14.8-1.1-x86_64.pkg.tar.zst \
  --historical-dir "$PWD/work/python314-upgrade-inputs" \
  --output "$PWD/work/python314-upgrade-final"
```

Acquisition allows only the fixed pair, exact sizes/digests and official HTTPS
endpoints, with a 140-second total bound. Already retained exact inputs can be
supplied directly. There is no host package installation. System Python 3.12+
can orchestrate; provisioned container Python 3.14 reads the package archives.

The new actor subclasses the unchanged completed actor's finite helpers; its
new `run()` supplies the historical workflow, while the existing guarded entry,
deadline and checked private TEST-agent cleanup are reused. The controller pins
the borrowed source bytes and reuses its container/process/cleanup helpers.

1. Provision the same pinned Arch image and frozen verified repositories used
   by the completed downgrade lane. Copy that image into a private ALPM root.
2. Verify the public historical signature and dependency gate, then establish
   ephemeral TEST trust and form the exact 3.14.7 baseline. The initial private
   3.14.9→3.14.7 setup is recorded separately from the tested upgrade.
3. Create a caller symlink venv under 3.14.7, an operator-owned module and a full
   cp314 extension that refuses headers other than 3.14.7. Record all caller
   bytes, modes, UID/GID and symlink targets; run its arithmetic/version checks.
4. Perform the genuine TEST-signed ALPM 3.14.7→candidate3.14.8 upgrade. Check the
   complete inventory, every archive payload path/ownership, dependencies and
   retirement of historical-only files. Run the mandatory candidate runtime,
   headless Tcl, a fresh venv and newly compiled candidate-header C consumer.
   Also run the **unchanged pre-upgrade caller venv and 3.14.7-built extension**
   against the actual 3.14.8 private shared library.
5. Roll back using the exact retained 3.14.7 archive. Check the original complete
   inventory, payload/ownership/dependencies, candidate-only file retirement and
   actual 3.14.7 runtime/Tcl/caller extension. Caller state and the three edited/
   operator/vendor sentinels must remain unchanged across all three versions.

The existing venv's `pyvenv.cfg` remains its original caller-owned file; its
runtime version is established by actual interpreter/library observations.
This demonstrates one micro-version cp314 consumer, without claiming every
third-party extension or virtual environment is compatible.

Runtime isolation remains network-none, read-only image, only an owned Docker
volume/private tmpfs, no host bind mounts/bus/hardware mappings, no-new-privileges,
2 CPUs/4 GiB/256 PIDs and the same CHOWN/SYS_CHROOT-only copied-root contract.
No capability bypass or Docker init host-binary injection is used. Hooks are
masked and every local mutation uses `--noscriptlet` and mandatory TEST trust.
The existing 1800-second controller, 700-second actor and finite child/cleanup
bounds apply. Provisioning's HTTPS network route is separate from runtime.

## Evidence and limits

Actual final evidence is retained under ignored `work/python314-upgrade-final/`.
Its report binds input/controller hashes, original public-signature/closure
logs, actual ALPM versions, runtime maps, caller state and owned-resource cleanup.
`work/python314-upgrade-inputs/acquisition.json` records the bounded acquisition.
The first development run completed runtime behavior but exported an inherited
query-config copy with a stale aarch64 label. The new actor now recopies the
actual x86_64 query configuration; that earlier report is separate.

November 14, 2026: the corrected final run passes all 49 actor commands. The
complete inventory remains 157 packages at the historical baseline, candidate
upgrade and historical rollback. All 3,198 historical payload nodes and 3,191
candidate nodes pass exact archive/ownership/dependency checks. The preserved
caller reports its compiled extension as 3.14.7 while its actual runtime changes
3.14.7→3.14.8→3.14.7; arithmetic, headless Tcl, prefix and mapped-library checks
pass throughout. Caller bytes/modes/UID/GID/links and all three sentinels match.
Both exported configurations correctly declare x86_64. Private TEST state and
all four owned Docker resources are removed successfully.

Four isolated source controls exercise foreign-cache substitution, same-size
byte tamper, symlink refusal and isolated controller loading on Python 3.12/3.14.
The original core HOLD, full-Tk build, ABI/venv and 3.14.9 downgrade evidence stay
unchanged. Native ARM/16K, Asahi integration, M2, GUI, performance, historical
ALARM correspondence, source/legal/production trust/full-system/release gates
remain unqualified. No Main integration or publication occurs in this lane.
