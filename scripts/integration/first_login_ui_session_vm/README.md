# First-login GTK in a real seat session — proposed x86 experiment

Status: **r1 held at PAM; r2 held at the strict ownership check before login.
Latest live-diagnostic/syncfs source passes controls; latest preparation/VM NOT RUN**.
Only this new directory is changed. The passed generic seat and NM actors, raw
inputs, reports and once-markers remain unchanged. This does not qualify ARM,
M2, physical displays/input, networking, suspend, performance or a release.

The fixture connects the installed first-login GTK application to the existing
real password/PAM tty1/active seat0 login. The ordinary UID1000 client starts a
private session D-Bus and real Xvfb server, loads the installed GTK4 window and
bridge, clicks Preview/Apply, checks read-only preview and preservation of an
existing Zsh configuration and a subsequent user edit, then repeats the action.
Cairo renders into the real X11 server; the probe reads/hash-checks its pixels
without exporting a screenshot. This is a headless GUI within the real TTY
login session, **not a graphical logind session or a display-manager trial**.

A separate guest-root actor installs all 128 additions with normal ALPM
`Required TrustedOnly`, checks exact 292-package inventory, dependencies,
ownership and installed project hashes, corroborates the live client PID with
login1, then removes all additions. Acceptance requires the original 164-package
inventory, dependencies, absence of package-owned non-directory paths, original
PAM/Polkit/udev policy and unrelated user data, and unchanged private user config.
The original seat parser must independently pass as well; generic seat success
alone cannot accept this journey. Normal package scriptlets/hooks run only in the
owned guest. Notably Fish/Zsh edit `/etc/shells`, fontconfig updates its cache,
GStreamer sets its guest helper capability, and PipeWire enables/disables its
**guest** user socket. Sysusers/account/cache residuals are reported; full
filesystem/account restoration is not claimed or manufactured by erasing them.

No private signing key is used. The fixture imports exact retained public keys
into `/run/ui-session/gnupg` and explicitly assigns ultimate **TEST-context**
ownertrust to the selected official signing primary identities and the ephemeral
project TEST certificate. This is a narrow, public-only reference trust setup,
not Arch's production web-of-trust enrollment or current revocation/freshness
acceptance. ALPM must still verify every detached signature; signature checks
are never disabled. This explicit trust decision requires Root review with the
other proposed inputs.

## Actual DATA intake

The frozen Nov09 core/extra metadata and actual pristine 164-package ALPM DB
resolved 128 additions through real x86 pacman16 `--sync --print --needed`:
three exact project packages and 125 official packages, zero baseline updates,
no provider prompt. `closure.json` binds every official filename/version/size,
archive SHA256 and detached-signature SHA256 to those exact catalogs. This x86
metadata route does not modify or bypass the existing ARM transaction guard.

Seventeen exact retained official archives supplied 14,691,658 bytes. The 108
missing pairs were fetched with at most four workers from only
`https://archive.archlinux.org/repos/2026/11/09/{core,extra}/os/x86_64/`, bounded
90 seconds/request and a 600-second HTTPS acquisition window, no retries/version
substitutions. All 125 archive and signature bytes matched frozen catalog pins.
Official archives total **141,176,555 bytes**, below the 256MiB budget; catalog
installed-size declarations total **651,126,896 bytes**.

The original retained `archlinux.gpg` is ASCII armor despite its filename. The
first pass preserved `gpgv`'s invalid-packet refusal. The corrected public-only
dearmor then verified **125/125** real detached signatures, exact PKGINFO
name/version/architecture, catalog dependency/license equality and BUILDINFO
metadata. Original keyring SHA256 is
`6e5e9373e4684d646f2274e2df54d7fea5f79bc0df981ad8cd7851d1d2454ba3`;
binary conversion SHA256 is
`f7af717a90821803e5c366032f3135c236c4100962716b3c1ed352f8b9330f51`.
The complete audit remains private:

`/tmp/cachy-asahi-first-login-ui-session-audit-20261114/audit.json`
1,644,645 bytes, SHA256
`f569165fa3d08a9d00ccc6912753572f7935a31cf050e8ade38f378f253028a1`.

`project.json` binds the three retained signed packages and public lifecycle
certificate (FPR `18E721CE9D7928221AD3163BA91B1AFC7142F94E`), plus actual
Fish/Zsh template archives used only as DATA. All three detached TEST signatures
also passed. No signing secret was accessed or reconstructed. `validation.json`
records exact provenance/report pins and scope. License/URL declarations and
BUILDINFO recipe digests do **not** establish corresponding source/notice/legal
acceptance; retained keyring verification does not establish current trust.

Reproduce the public DATA audit with Python3.14 (stdlib Zstandard reader):

```sh
python scripts/integration/first_login_ui_session_vm/audit.py \
  --intake /tmp/cachy-asahi-first-login-ui-session-archives-20261114 \
  --catalogs /tmp/cachy-asahi-first-login-ui-session-intake-20261114/db/sync \
  --keyring /tmp/cachy-asahi-first-login-ui-session-intake-20261114/official-keyring.gpg \
  --output /tmp/cachy-asahi-ui-session-audit-NEW
```

`intake.py --help` documents the separate explicit acquisition opt-in. Already
verified bytes should be reused; do not rerun downloads merely to replay evidence.

## Proposed constructor and Root-only first invocation

**The fresh corrected commands below have not been executed.** Root reviews source, pins and fresh
aggregate resource admission before running the constructor, and reviews its
result before first boot. No old marker is reset. Constructor output must be new.

```sh
python scripts/integration/first_login_ui_session_vm/prepare.py \
  --allow-prepare-ui-seat-reference \
  --official-intake /tmp/cachy-asahi-first-login-ui-session-archives-20261114 \
  --official-audit /tmp/cachy-asahi-first-login-ui-session-audit-20261114/audit.json \
  --official-keyring /tmp/cachy-asahi-first-login-ui-session-intake-20261114/official-keyring.gpg \
  --retained-ui /tmp/cachy-asahi-first-login-ui-candidate-final-20261114 \
  --output /tmp/cachy-asahi-ui-seat-preparation-NEW
```

The COPY-only tool derives from retained `cachy-nm-real-seat:ca3b06ea4aff9410`,
image `sha256:1f4922c557070c90e9af8dbc2099ba9df61cce352b1f86f214d84d6eb19bbee3`.
It reuses exact guest/kernel/initrd/modules and original generic assembly,
creating a fresh nonce, private credential and **3GiB logical sparse raw**. Expected
new disk allocation is about 1GiB raw plus about 300MiB temporary input/image data;
no large preparation occurred during intake. Assembly requires fresh≥4GiB free
and ≥6GiB MemAvailable, uses 2CPU/3GiB/256PIDs, a 1536MiB tmpfs, network-none,
read-only root/cap0/NNP and one owned writable output. Its 300-second assembly
limit and independent bounded cleanup retain failures, including ambiguous create.

Only the new actor changes the frozen seat actor's guest RAM 1536→2048MiB and
file-size/overlay bound 256→1024MiB. Runtime remains2CPU/3GiB/256PIDs, no NIC/KVM,
network-none, read-only host-container root, cap0/NNP and the original two owned
binds. Original serial/ACK/password-ECHO checks, signal handling, identity custody,
normal VT logout/QMP retirement and exact container cleanup remain mandatory.
The observer's wait extends 210→330 seconds for installation/GUI/removal; the
controller 420-second and actor 480-second global windows remain unchanged.
The ordinary GUI group reuses `scripts/virtual/owned_process.py` and must retire
naturally with `EMPTY_TWICE` (original group/session scope, not global absence).

After reviewing/re-hashing the new prepared output and image, Root alone runs:

```sh
python scripts/integration/first_login_ui_session_vm/boot.py \
  --allow-first-ui-seat-reference-boot \
  --prepared /tmp/cachy-asahi-ui-seat-preparation-NEW/prepared \
  --prepared-sha256 ROOT_REVIEWED_PREPARED_JSON_SHA256 \
  --tool-image ROOT_REVIEWED_TOOL_TAG \
  --tool-image-id sha256:ROOT_REVIEWED_IMAGE_ID \
  --output /tmp/cachy-asahi-ui-seat-first-boot-NEW
```

The adapter explicitly extends only the original parser with the UI acceptance
join, binding root-corroborated client session to the full independent seat proof.
Bounded user/root HOLDs stop the serial controller promptly. Runtime GTK/ALPM,
normal-hook residuals, full lifecycle timing and resources remain unverified until
that fresh Root actor executes.

Twenty-nine focused controls pass on Python3.12/3.14:

```sh
python -m unittest discover -s scripts/integration/first_login_ui_session_vm -p 'test_*.py' -v
```

These source/refusal controls and the real DATA signature audit do not substitute
for the proposed real-session GUI execution.


## Preserved r1 and the minimal sequencing/durability correction

Root's r1 constructor completed at
`/tmp/cachy-asahi-ui-seat-preparation-root-20261114-r1/`; prepared manifest
SHA256 `d5a5028ffe0b95bbd5ef00831bb8164c112a9280236d055b598e2b3e501eae06`,
raw SHA256 `41c4f529ed2ab32ef0574c3d80a7a69658d2fb30b0ea66dc6741af2461ed56fb`,
948,776,960 allocated bytes. Exact image
`cachy-ui-real-seat:74b920e8cb1916a6`, ID
`sha256:a32b1a18e29a6fcc57c2182b1a8ff26df72c4d1a1b6b4e8f350d8b0b413ff3c7`.
Root's first UI trial at `/tmp/cachy-asahi-ui-seat-first-boot-root-20261114-r1/`
closed with PAM authentication failure, all 41 real release acknowledgements and
ECHO-off readiness, **before profile entry**. Exact accepted plaintext was not
observed. This does not prove a policy/keyboard defect. The report is 1,310 bytes,
SHA256 `c95ecbd3850575fab71d95e863296e97a039cb9986598a7839e11a0a979a916f`;
QEMU retirement/exact owned container absence passed. No retry occurred.

Bounded passive DATA diagnosis preserved the original overlay SHA256
`58740526da3823902cb08383cb0dcb39103c8f853e01336ff2438611159c054d` and raw
before/after. In-memory comparisons found the prepared credential matched both
prepared and terminal account records; shadow/PAM/profile/helper bytes and owners
were unchanged. The disk retained exactly 164 baseline packages. Root receipts
under volatile `/run` did not survive; the retained disk journal lacked relevant
UI/PAM stages. No profile or opened session was observed. No credential,
password hash/salt, raw VT/input or raw journal content was exported. Sanitized
report: `/tmp/cachy-asahi-ui-seat-passive-diagnosis-20261114-r1/diagnosis.json`,
7,220 bytes, SHA256
`0f8ea01e577528d2d3235afe07b357cfbebac0562236d2127e6cb5b7752220ab`.
Original r1 source/image/input/marker/results remain immutable.

The correction serializes installation and login and preserves missing evidence;
**it is not an authentication repair**. PAM, accounts, credential generation,
keyboard delivery, policies, source imports/signature policy and actor resources
are unchanged. Only this new fixture directory changes:

- `receipts.py` writes sanitized stage/command/failure/installed/restored receipts
  under guest-private `/var/lib/cachy-asahi-ui-session-reference` (root:root 0700,
  files 0600, ≤4KiB each, at most 256 command receipts). Only fixed schemas,
  whitelisted stage/error/command labels, booleans/counts and identity digests
  are allowed; no argv/raw command output, key material or credentials.
- Directory creation is fsynced. Every atomic receipt update orders ordinary
  file write→file fsync→rename→directory fsync before the volatile runtime signal.
  Command output is used in memory only; raw stdout/stderr files are no longer
  retained. Public GPG import/trust decisions remain the reviewed original ones.
- Before `SEAT_LOGIN_READY`, the derived observer requires the durable root-owned
  regular single-link0600 installed receipt with exact fresh nonce/input pin,
  canonical 292-package inventory digest, and completed trusted ALPM/dependency/
  ownership/project-hash/preservation checks. A matching root-owned 0644 runtime
  signal must also exist; it is created only after private receipt durability,
  closing the rename-before-directory-fsync visibility window. Pending waits within the unchanged
  global window; stale/foreign/incomplete receipts or root HOLD fail immediately.
  A failed fixture service without a usable receipt also causes prompt HOLD.
- The original seat proof and root UI lifecycle must still pass; the parser joins
  the pre-login installed receipt to the independently returned root result.

The constructor copies only this additional helper into a fresh derived image
and raw. It must use a new output (for example
`/tmp/cachy-asahi-ui-seat-preparation-root-20261114-r2`) after Root review;
**do not reuse r1's raw, image or once-marker**. All previous resource/deadline
bounds remain unchanged. Pending/failed/foreign/stale gate and real temporary-file
fsync ordering/refusal controls pass; no corrected constructor/guest has run.


## r2 ownership HOLD and live diagnostic/filesystem flush correction

Root's fresh r2 image is
`sha256:f836e1485d51661b76723376a0aee2e762052dde0e35bf1ab4315e8f7f243b83`,
manifest `2c948fbfe2751ab39684f78e22296b1d8aa995c3062668f83c901af3e6c8dd0d`,
raw `912bf8744732271a12c9d334545f93a434301f563273b091d692c13d04d8a7ec`.
Its closed trial `/tmp/cachy-asahi-ui-seat-first-boot-root-20261114-r2/`
retained public import/trust/no-secret-key/normal trusted installation/exact
inventory/dependency command success, followed by **installed-ownership exit1**.
The gate admitted no login. Cleanup passed; the overlay is
`4211491fe565940c6f893a299f9f82aa6ed067a9574c948930fded2c10015223`.
No warnings were waived and no UI/PAM success is claimed for r2.

Two bounded passive readers preserved stage evidence but failed to parse empty
post-retirement descriptors. Root's subsequent DATA-only harvest at
`/tmp/cachy-asahi-ui-seat-passive-diagnosis-20261114-r4/` retained exact292 public
desc/mtree pairs (584 files),19,455 selected system path metadata records and3,141
differing-file hashes,5,874,115 exported bytes. Its observed scratch allocation
was1,602,215,936 bytes; scratch/container retired and originals were unchanged.
Forty-five metadata files and3,141 expected-nonempty package files were zero-length
in that terminal copy. These are **post-retirement facts, not proof of the live
Qkk cause or normal hook behavior**. The focused `ownership-fixture.json` binds an
actual GTK3 MTREE excerpt,7978→0-byte terminal stat/hash, and harvest pins. Test
warning lines constructed from that path exercise recognized formats; they are
not presented as captured r2 stderr. Unknown/empty metadata remains held.

The latest source correction makes the *next live* failure reviewable:

- The constructor reads exact supplied archives as DATA and binds small ownership
  index shards (archive numeric metadata/content hashes plus MTREE fields) in the
  input manifest. Only the128 exact input packages' system paths are eligible;
  user paths, shadow and key material are excluded. No package code is executed.
- Normal `pacman -Qkk` still runs under its original1MiB/timeout bound, using C
  output locale. Its actual exit is recorded before diagnostics. A nonzero exit,
  recognized warning, altered-file summary or unknown output remains HOLD.
  No output is silently accepted to obtain a successful install gate.
- At most64 known warnings and32 unknown-line records are persisted as root-only,
  fsynced ≤4KiB receipts. Known warnings retain package/path/category, pinned
  archive/MTREE expectations and bounded no-symlink-parent lstat/hash observations.
  Unknown content is represented only by stream/hash/bytecount. Overflow counts
  remain explicit; raw stdout/stderr, credentials and arbitrary user data are
  not retained. Hash observations share a10-second diagnostic budget.
- Actual guest `syncfs` follows trusted install/removal and precedes terminal
  PASS/HOLD publication. Failure is a strict `syncfs-refusal`; terminal PASS is
  impossible if flush fails. Private HOLD evidence alone no longer admits early
  emulator retirement: the observer also requires its matching post-flush runtime
  signal. Unhandled service failure still holds, without claiming flush success.

These changes fix observable/durable evidence only. They do not establish the
ownership/PAM cause, erase warnings, restore metadata to hide a mismatch, change
normal hooks, relax signature/ownership policy, or add a login/authentication
retry. Original policies/accounts/credentials/keyboard and all guest/controller
resource/deadline limits remain unchanged. Extra metadata/receipts fit within the
existing input/image budget; no new archives were acquired.

The new helper/source pins are recorded in `validation.json`. Twenty-nine controls
pass on Python3.12/3.14, including real retained metadata, strict known/unknown
warning refusal, protected path/symlink refusal, pinned index drift, post-flush
failure signaling, and syncfs failure preventing terminal PASS. Tests never call
host syncfs. No latest constructor/VM has run; Root must review fresh source,
image/input pins, storage and admission before another separate trial.
