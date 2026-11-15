# Finite recovery of the missing ARM Xvfb pair

The exact `xorg-server-xvfb-21.1.25-1-aarch64.pkg.tar.xz` pair remains
**HOLD_EXACT_XVFB_UNAVAILABLE**. No substitute was accepted, built or installed.

Expected archive: 705,376 bytes, SHA256
`9799e250607b6ebe1b143138fe7cf64366fc94127bb5fbaea6c456c68c2bf715`.
Expected signature: 566 bytes, SHA256
`62b1b083753f451ae512b37ee0478e47db63ef9f6dc10c5ef3e722d0f8ad4958`.
The initial six-pair receipt/404 and all five successfully acquired pairs were
hashed before and after this recovery and remain unchanged.

## Checked locations and actual outcome

Filename enumeration covered project worktrees/artifacts, `.cache`, private
project caches, `/tmp` and `/dev/shm`, excluding `.git`; it found only unrelated
x86_64 Xvfb 21.1.25-2. Bounded JSON/index searches and native574/core-lifecycle
public-carrier indexes found no exact Xvfb object. Historical BUILDINFO installed
lists mention the version but do not carry its archive. No archive payload or
Git object-store walk was used to manufacture a cache hit.

| Exact HTTPS location | Actual result |
| --- | --- |
| fl.us.mirror.archlinuxarm.org/aarch64/extra/… | HTTP 404 |
| de3.mirror.archlinuxarm.org/aarch64/extra/… | HTTP 404 |
| nj.us.mirror.archlinuxarm.org/aarch64/extra/… | TLS issuer refusal |
| mirror.archlinuxarm.org/aarch64/extra/… | TLS hostname refusal |
| dk.mirror.archlinuxarm.org/aarch64/extra/… | TLS hostname refusal |
| fr.mirror.archlinuxarm.org/aarch64/extra/… | TLS issuer refusal |
| de.mirror.archlinuxarm.org/aarch64/extra/… | TLS hostname refusal |
| tardis.tiny-vps.com/aarm/ | Connection refused |
| archlinuxarm.org/about/mirrors | Metadata read |
| archlinuxarm.org/public/js/mirrors.js | Metadata read, never executed |
| archlinuxarm.org/data/mirrors/list | Read-only empty-body POST: HTTP 404 |

The ellipsis is always the exact archive filename above. Denmark, France and
Berlin hosts came from the actual retained 2,640-byte
`pacman-mirrorlist-20260411-2-any.pkg.tar.xz`, observed only as bounded DATA.
HTTP mirrorlist declarations were upgraded to HTTPS; TLS was never relaxed.
The known Tardis archive's unavailable index supplied no payload path.

The finite recovery used **11 total HTTPS attempts, zero redirects, 15,703
response-body bytes, zero archive bytes**, within one 132.058-second window
(including time between stages). The 12-request/180-second budget was not reset
for the continuation. No error body was read; response-body accounting does not
pretend to measure TLS/framing overhead. An unused twelfth request was reserved
for a matching detached signature if an archive became available.

Private evidence root:
`/tmp/cachy-asahi-arm16k-ui-xvfb-recovery-20261115`.
Final receipt `final-recovery-receipt.json`: 1,855 bytes, SHA256
`4989e19f97c578d4e2b18c5c513f6865f4199dbc14f9fe10321efeeccdb9f9e3`.
[actual-result.json](actual-result.json) joins the separate stage/metadata receipts,
all source URLs/statuses and exact original/final receipt pins. Public HTML and
mirrorlist DATA stay private with their hashes. Four focused controls pass:

```sh
python -I -B -m unittest discover \
  -s scripts/port/arm16k-first-login-ui-inputs/xvfb_recovery -p 'test_*.py' -v
```

`recover.py --recover-exact-only --output NEW_PATH` implements the first finite
stage using the previous strict size/SHA/gpgv/metadata adapter. The actual later
metadata requests are separately recorded, and `finish_recovery.py` consumes
those retained receipts and the observed mirrorlist for the final three hosts,
inside the original deadline. These are explicit intake helpers, not permission
to replay the closed recovery. No package/signature was accepted by this scope;
the other 139 observations are not newly authenticated.

## Smallest proposed source-built alternative — not built

A new fixture package could own only the headless Xvfb component and keep the
existing common scripts/dependency stack. A distinct identity such as
`cachy-asahi-xvfb-reference 21.1.25-1.1` must replace the planner's root explicitly;
it would not recover, reproduce or inherit acceptance of ALARM 21.1.25-1.
An optional unversioned `xorg-server-xvfb` capability would describe its interface,
not the missing archive identity. No replacement selection is made here.

That proposal first needs exact official Xorg 21.1.25 source/signature/key pins,
source/license notices and an original reviewable recipe. No source was acquired
or assigned a fabricated hash here. The dependency baseline would retain all
111 versions and the catalog's libxfont2, libunwind, pixman, xorg-server-common,
xorg-xauth, libgl, nettle, libtirpc, systemd-libs, libxdmcp, sh, glibc and libxau
relations. Retained `xorg-server-common 21.1.25-1` supplies common scripts; their
actual namespace/ownership must be checked. Build only the Xvfb component rather
than adding a hardware Xorg server, while keeping the intended extension/GLX
profile explicit instead of silently dropping features to force a build.

A newly built aarch64 artifact would require its own hash, build/toolchain/source
custody, ELF16K and dynamic ABI audit, test signature and exact metadata preparation.
Only then could a separately admitted ARM fixture test actual Xvfb/GTK, stock
DBus/Polkit and the independently pinned input/seat kernel. No build, signing,
installation, daemon, guest/VM, native build, M2 or release acceptance occurred.
