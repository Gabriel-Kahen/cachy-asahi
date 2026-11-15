# Disposable Python candidate package lifecycle

This finite x86_64 host lane installs the exact full-Tk source-built
`python 3.14.8-1.1` archive into a **private copied ALPM root inside an owned
disposable Arch container**. It never installs packages on the host or enters
native/Root acceptance roles. It uses the existing finite process runner and
repository helpers for copied-root construction, strict inventory parsing,
payload state, ephemeral TEST keys/trust/signatures, hook masks and local
transactions. Original helper/recipe/source files are unchanged.

```sh
python3 -I -B -Werror::ResourceWarning \
  scripts/integration/python314_candidate/test_controller.py -v
python3 -I -B -Werror::ResourceWarning \
  scripts/integration/python314_candidate/run.py \
  --archive /tmp/cachy-asahi-python314-tk-full-second-20261114/export/python-3.14.8-1.1-x86_64.pkg.tar.zst \
  --output "$PWD/work/python314-lifecycle-run"
```

System Python 3.12 or newer can orchestrate; the actor's provisioned Python
3.14 supplies zstd archive reading. Docker and the pinned official Arch image
must already be available. Output must be fresh and private. The candidate is
the exact second full-Tk build, SHA-256
`8474bf623e6efe46f02ef5dd65b7707b2f526a7a612661b33819920e451b016e`.

## Boundaries and inputs

The base is
`archlinux@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae`.
Only the disposable provisioning container may acquire prerequisites. It uses
the frozen Arch `2026/11/09` core/extra databases with exact SHA-256 pins and
mandatory upstream package signatures. The provisioning phase uses the host
network route for those HTTPS acquisitions because bridge networking timed out
on this machine. It has no host mounts, Docker socket, bus or hardware device
mapping. It does not alter host trust or packages.

Before runtime starts, the controller retains and verifies the exact frozen
baseline `python 3.14.9-1` archive and upstream signature at the copied host
destination. Archive SHA-256 is
`e7b28e851f8f94bc4083774c4931741c5cf35573875e31d6ac52c2649da12c55`;
signature SHA-256 is
`9261278f2a855d6ae8f7b148ef84300030a120d11ddcf66e93835f705656925d`.
Missing or mismatched assets stop the run. They were reacquired through the
frozen repository; this does not imply the earlier disposed builder cache was
retained. The actual package transition is a **3.14.9→3.14.8 downgrade**, followed
by removal/reinstallation and exact 3.14.9 baseline restoration. It is not an
Asahi 3.14.7 upgrade.

The runtime actor has network `none`, a read-only image, 2 CPUs, 4 GiB memory
and swap ceiling, 256 PIDs, no-new-privileges, and only CHOWN/SYS_CHROOT
capabilities for private ownership fixtures and libalpm's copied-root ldconfig.
Its only explicit mount is its own Docker volume. Small HOME/runtime tmpfs and
standard Docker metadata/character devices are checked; no operator host files
are mounted. Docker `--init` is deliberately absent because this machine's
configuration injects a host binary mount. The existing process runner is a
subreaper and cleans command groups; outer cleanup removes the whole owned
container even when a Docker exec times out. Container main processes are
bounded sleeps used for live Docker-copy transport; no services are activated.

The controller has an 1800-second command scheduling deadline, 900-second
provisioning and 750-second actor command bounds. The actor has a 700-second
overall alarm and 90-second child bounds. The shared runner bounds output,
address space, files, CPU and descriptors. Cleanup has an independent budget
and addresses only the pre-registered nonce-owned containers/volume/image.

## Required real checks

- Sign candidate and rollback copies using fresh, one-day, private TEST keys.
  Before trusting the signer, require an actual ALPM unknown-key refusal with
  the entire private-root byte/mode/UID/GID/link snapshot unchanged.
- Create a structurally valid changed-payload archive with the original TEST
  signature. Require signature refusal and the same unchanged-state check.
- Use `Required TrustedOnly` local signatures, masked hooks and `--noscriptlet`.
  No dependency bypass is used. Run actual dependency checks; compare the whole
  package inventory and every archive path's bytes, modes, ownership and links
  against ALPM ownership. Previous-version-only files must disappear.
- Execute the installed candidate's mandatory runtime profile, private-prefix
  Tk import and headless Tcl 8.6.16 without loading GUI Tk, venv creation/runtime,
  and actual compile/import/arithmetic of the original full cp314 C fixture.
  Repeat the smoke after removal/reinstallation.
- Check removal deletes all candidate regular files/symlinks. Preserve an
  edited private `/etc` operator configuration, a UID/GID1000 edited startup
  file, and the existing package-owned Bash binary vendor sentinel throughout.
  These are unrelated operator/vendor files; Python-owned edits are not claimed
  to survive replacement.
- Restore the exact retained baseline archive; require the original full
  inventory, baseline payload/ownership/dependencies, retired-file absence and
  sentinels. ALPM install-time/log metadata is expected to change: this is not
  a byte-identical rollback of the entire database.

Private TEST agents/key homes must be retired successfully. Only public TEST
certificates, logs, receipts, payload maps and the exact upstream baseline
archive/signature are exported. The owned container/image/volume are removed.

## Evidence scope

Four controller safety tests pass under Python 3.12.13 and 3.14.7 with isolated
mode and ResourceWarning promoted to error. They exercise actual Docker
capability spelling, dangerous runtime contracts, bind-mount substitution and
precise owned-resource cleanup diagnostics. Real run reports are retained under
ignored `work/python314-lifecycle-*/`; failed attempts are not passing evidence.

Actual run `work/python314-lifecycle-11/report.json` passes all required real
checks with 53 actor commands. The complete inventory is 157 baseline packages,
157 after downgrade, 156 after removal, 157 after reinstallation and the exact
157-package baseline after restoration. All 3,191 candidate payload nodes and
3,198 baseline payload nodes match their archives and ownership. Both installed
and reinstalled runtime profiles, headless Tcl, private venv and compiled C
consumer pass; actual maps select `/scratch/system/usr/lib/libpython3.14.so.1.0`.
Both signature refusals preserve the full copied-root state. All three
sentinels, TEST private-state retirement and four owned Docker resource removals
pass. The exact baseline archive/signature remain retained with their hashes.

Early attempts retained a bridge timeout, capability-name normalization refusal,
stopped-container overlay-busy errors and mount-guard refusals. A bounded mount
observation identified Docker's standard character-device mounts and injected
init binary. Fixture corrections also addressed UID/mode ordering, the actual
package-owned vendor path and current pacman unknown-key wording. The standard
device mounts retain exact device-identity checks; the injected init binary was
removed. Review also added previous-version-file retirement, checked TEST agent
shutdown status, retained-destination baseline hashes and failure-status custody.

No native ARM, native 16K, supported Asahi/M2, full-system transaction, GUI,
performance, historical ALARM correspondence, source/signature freshness/legal,
production trust or release acceptance is established. Previous core HOLD,
full-Tk builder, ABI consumers and venv evidence remain separate and unchanged.
