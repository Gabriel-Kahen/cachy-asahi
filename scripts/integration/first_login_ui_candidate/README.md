# First-login UI: dependency-checked disposable host lifecycle

This opt-in integration runs the current pinned UI candidate with real retained
FirstLogin and genuine accepted Setup8 archives. It never installs on the host,
changes production trust, accesses the user's desktop or invokes old native
roles. It is x86_64 software evidence, not native ARM/M2/release acceptance.

Run from the repository root with existing exact archives and a new private
output directory:

```sh
python3 -I scripts/integration/first_login_ui_candidate/run.py \
  --first-login /private/retained/cachy-asahi-first-login-0.1.0-2-any.pkg.tar.zst \
  --setup /private/retained/cachy-asahi-setup-0.3.0-1-any.pkg.tar.xz \
  --fish /private/retained/cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.zst \
  --zsh /private/retained/cachy-asahi-zsh-config-0.1.0-1-any.pkg.tar.zst \
  --output /private/new-ui-candidate-run
python3 -I -B scripts/integration/first_login_ui_candidate/test_candidate.py
```

`inputs.json` binds every unchanged candidate recipe file and the exact input
bytes. FirstLogin is the retained 19,471-byte unsigned host assembly,
`d4b7291afedc2af95d89f3975c77c45e417125bf23818cbfd1dc7d53fb464839`.
Setup8 is the retained prior native 33,900-byte archive,
`8de3bd0cf2d9333b41925fecdef5cbfe2ec6d40c3424d90746182142e0c7dc47`,
from source `5d0f5ae6331807704a8ebafc7922972629e0b96f` / run 40490674681.
No original role/Reader is rerun and no new native credit is inferred. Fish/Zsh
archives supply only their exact delivered template bytes; those two project
template packages are not installed. No placeholder template is substituted.

Before execution, the existing pinned bounded archive DATA reader checks the
four archives with fixed byte/member/window/deadline limits. Unexpected package
controls/scripts, special backend files, hooks/services/autostart paths or
unexpected backend counts fail. The real backend implementation hashes must
equal the UI's exact check-only snapshots. No archive can enlarge the budgets.

The official local image must already exist as
`archlinux@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae`.
Only prerequisite acquisition has host networking. The frozen 2026/11/09
core/extra DBs are checked against exact SHA-256; official package signatures
remain Required. DB integrity here is the fixed hash, not a new DB-signature
claim. Packages are installed only inside this disposable image. The acquisition
DownloadUser/filesystem setting follows the existing finite host-builder seam;
the network-none local-file owner configuration omits download/user-switch
settings while retaining `Required TrustedOnly` for local packages.

Every actual build/lifecycle actor has two CPUs, 4 GiB memory/swap, 256 PIDs,
an init process, default Docker seccomp, all capabilities dropped and
`no-new-privileges`. Source build is UID/GID 1000 with read-only root and input
snapshot; root owners may write only their disposable container filesystem and
owned volumes for GPG/ALPM transactions. Root owner, unprivileged build and
unprivileged application operations are separate fixed commands. No capability
addition, privileged exec or seccomp override is used. The user process checks
actual zero effective/bounding capabilities, NNP=1 and seccomp=2.

A fresh one-day TEST signing key lives only in a private secret volume, never
in the unprivileged build actor or exported output. The owner explicitly imports
and locally certifies its public key in the image's private ALPM keyring.
FirstLogin/Setup8 and the newly built UI are TEST-signed and installed under
Required/TrustedOnly policy. This authenticates the disposable TEST signer, not
original upstream signatures or release trust. The unsigned UI must first be
refused without file changes. All 24 regular package files are checked against
the full archive/source manifests, modes, root UID/GID and ALPM ownership.

The source recipe runs ordinary dependency-checked `makepkg --noconfirm`, with
no `--nodeps`, `--nocheck`, prerequisite fallback or source mutation. The current
runtime GTK dependency genuinely brings bubblewrap through glycin. Docker's
default profile denies nested namespaces; the candidate's exact-profile probe
records that denial as NOT RUN. No tool is removed to conceal it. On this image,
23 bridge tests plus four delivery tests pass; one optional nested source-hidden
case is NOT RUN. Supported hosts still run that original case. These counts
must not be reported as 28 passes.

Separately, the Docker namespace itself supplies the mandatory outer isolation.
The installed real `/usr` backend performs inspect/preview, refuses stale edits
and explicitly applies while preserving user edits in a private home. Four
additional actual GTK controls load the installed `/usr` window implementation,
exercise its Preview/Apply buttons against the real installed backends, preserve
an existing edit and close with no worker. All 24 installed and archive-extracted
file hashes join. A moved copy then runs the
existing exact 11-control GTK child driver in private Xvfb/D-Bus/HOME/cache with
software rendering and no host bus/devices/network or checkout inputs. The
driver is an exact check-only copy; its final close/cancel case uses a deliberate
slow helper only in that user-owned moved copy. Original installed payloads
remain unchanged. No Fish/Zsh shell, compositor or physical input is launched.

Removal checks all 24 previously absent paths return to absent, the complete
official package/version inventory is restored, and all four private user-home
file digests remain unchanged. Shared desktop database caches inside the image
are ordinary package-manager effects; no full rootfs byte-restoration claim is
made. No autostart entry is installed. All unique owned containers, work/secret
volumes and derived images are then removed. Private output retains public TEST
key/signatures, package/logs, user test reports and cleanup outcomes; no signing
secret is exported. Inspect output before any later retention/publication.

The existing FDK Runner supplies process groups, bounded output and a
2,400-second controller deadline. Provisioning is at most 900 seconds, image
commits 120 seconds, source build 300 seconds, owner calls 240/180/90 seconds and
user GUI calls 150 seconds. Cancellation removes daemon-side container jobs;
cleanup has its own 180-second budget. Failed cleanup leaves HOLD. Defaults
include explicit owner/build umask 022 and private user umask 077: Docker exec's
observed umask 000 otherwise creates legitimately rejected unsafe test edits.
No actor can silently convert missing tools/materials or failed checks to PASS.

The earlier `--nodeps` assembly and ordinary host dependency HOLD remain
historical facts. Candidate check-only correction 5c51cb7b is separate from this
integration. Actual results and failed attempts are recorded in RESULTS.md;
native ARM, integrated target installation, original-provider/legal acceptance,
physical graphical login and both M2 Air gates remain separate.
