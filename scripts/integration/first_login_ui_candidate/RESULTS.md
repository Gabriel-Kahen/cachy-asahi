# Actual dependency-checked UI lifecycle — 2026-11-14

**PASS finite x86_64 software scope.** UI 0.1.0-2 completed ordinary
dependency-checked makepkg, disposable TEST-signature installation, installed
`/usr` CLI and GTK window/buttons, archive-extracted/moved GTK recovery controls,
full ownership checks, removal and exact private-user-data preservation. No
host package/trust installation or native/M2/release acceptance is inferred.

The current candidate's executed source bytes match check-only correction
`5c51cb7bdb73419baa37ba90d5374c7c7fee6626`. No candidate source was changed by
this integration. Genuine Setup8 33,900/`8de3bd0c…` and retained FirstLogin
19,471/`d4b7291a…` input archives remain unchanged. The real delivered Fish/Zsh
templates came from the two pinned retained archives; they were not replaced
by fixture comments or installed as additional project packages.

Observed results:

- Official pinned Arch x86 image and frozen 2026/11/09 repository hashes used;
  official package signatures Required. Only prerequisite acquisition used
  networking, inside its owned disposable image.
- A fresh one-day TEST signer authenticated the exact two backend archives and
  new UI under ALPM `Required TrustedOnly`. The unsigned UI was first refused
  with exit 1 and no UI file installation. No production key/trust was used.
- Ordinary `makepkg --noconfirm` checked runtime and build/check dependencies;
  no `--nodeps`/`--nocheck` or dependency workaround. BUILDINFO records actual
  FirstLogin 0.1.0-2 and Setup8 0.3.0-1 among 302 installed build-image packages,
  plus the exact candidate PKGBUILD hash. The official baseline has 300 packages.
- **27 check cases PASS, one optional namespace case NOT RUN**: 23 bridge cases,
  four delivery cases, one explicit denied bwrap profile. GTK/glycin genuinely
  brings bubblewrap as a dependency. The real default-Docker denial command and
  stderr are in makepkg.log; no tool was removed or privilege granted. The
  original full source-hidden assertion still runs on supported hosts.
- Fresh installed `/usr` bridge/backend inspection and preview were read-only;
  stale user edits were refused, and explicit activation preserved an existing
  Zsh edit while adding real Fish/Zsh settings.
- **Four actual installed `/usr` GTK controls PASS**: mapped window/read-only
  inspect, Preview/no writes, Apply/real backend/edit preservation and idle
  close/no worker. This uses installed code directly, not the moved copy.
- **11 actual extracted/moved GTK controls PASS**, including actual preview/
  apply and stale-refusal buttons, original pending transaction recovery and
  controlled slow-helper cancellation on busy close. The latter replaces only
  the user-owned moved backend copy; installed backend files remain unchanged.
- All 24 ordinary installed/extracted payload file hashes join: Setup8 ten,
  FirstLogin six and UI eight. ALPM ownership is exact; modes/root UID/GID pass.
  Independent bounded DATA inspection verifies the UI archive's full eight
  source hashes/modes, BUILDINFO dependency identities and PKGBUILD binding.
- Actual user process effective/bounding capabilities are zero, NNP=1,
  seccomp=2. Inspected actors match two CPUs, 4 GiB memory/swap, 256 PIDs,
  network-none and default confinement. Build root is read-only; root package
  owners write only their disposable filesystem/volumes. There is no capability
  addition, privileged exec or seccomp bypass.
- Removal returns all 24 previously absent paths to absent and restores the
  exact 300-package baseline inventory. All four private-home file digest maps
  remain identical. No autostart file is delivered. This does not claim every
  shared desktop-cache byte/mtime in the disposable root is restored.
- All eight cleanup actions returned zero: four containers, two work/secret
  volumes and two derived images removed. The official base cache remains.
  Fresh signing secrets were not exported. Both actual GUI stderr logs are empty.
- Ten focused integration input/resource/source-visibility refusal controls PASS.

Final retained directory:
`/tmp/cachy-asahi-first-login-ui-candidate-final-20261114`.

| Relative file | Bytes | SHA-256 |
| --- | ---: | --- |
| `report.json` | 33762 | `17ba0ad93e206cd55d99c9b8c712b2139b7ec9f8e524b311a842ef974b885af3` |
| `build/cachy-asahi-first-login-ui-0.1.0-2-any.pkg.tar.zst` | 16905 | `869fb4f1dcf7fc26ff87594398eba8d15d4a8051e6feaf96d4b8fe457ccb4ea4` |
| `build/makepkg.log` | 2666 | `b73b024cc43740a5649590b418cf114f683ac2724254edd667ab9266bb4dba63` |
| `user/result.json` | 1682 | `958c3d3fb9577eb608367f13c2977fb2314a87aa8d1c5732700c112bc40adcbe` |
| `user/installed-gui.stdout` | 320 | `249ac647475c7b190bcbf83420d84758f8758b358134991219b25ee4119eaeb1` |
| `user/gui.stdout` | 882 | `930dc1ba1509400d3bf1c68f94cdc8be398eaac6b045568d5164b1fa26e41573` |
| `user/removal.json` | 131 | `7ad212175185d6a08241cc7afd658530446cd72c25554a2a70aa3a4f0d8bbaf4` |
| `archive-review.json` | 2190 | `b367c40cc8fa0770dc50b53dd67cf6f0acda5e0de8b064f7574e6bf7c5711721` |

Public TEST key/signatures and full24 payload manifest are under `public/`;
installed/removal receipts are `public/{installed,removed}.json`. The final
TEST fingerprint is `18E721CE9D7928221AD3163BA91B1AFC7142F94E`. It is an ephemeral
test identity, not an original-package or release signer. No reproducibility
claim follows from repeated diagnostic runs.

Earlier attempts remain separate under
`/tmp/cachy-asahi-first-login-ui-candidate-{first,second,third,fourth,fifth}-20261114`:

1. Fixed 8 MiB XZ decoder memory cap refused genuine Setup8 before Docker; fixed
   128 MiB window cap was then selected without changing inputs or decoded cap.
2. Network-none root with all capabilities dropped correctly could not chown a
   DownloadUser temporary cache. Local-file config now omits download settings,
   retains Required/TrustedOnly and requires no new privileges.
3. Ordinary build, signed install and 24-file ownership passed; a helper guard
   falsely classified Docker's empty former `/inputs` mountpoint as source.
   Guard now refuses source contents/active mounts; empty placeholders are safe.
4. Docker exec's observed umask 000 produced an unsafe mode-0666 synthetic edit;
   the application correctly refused a new apply ticket. Explicit private 077
   and public/build 022 umasks fix the diagnostic; production safety is unchanged.
5. PASS installed CLI plus extracted/moved GTK only. It did not test a GTK window
   loaded directly from installed `/usr`; the final run adds that distinct path.

The original 0.1.0-1 host `--nodeps` archive and ordinary dependency HOLD are
still historical facts. Runtime/source/provider authenticity beyond these exact
pins and disposable TEST trust, native ARM/signing lifecycle, integrated target
installation, physical graphical login, source/legal/release policy and both
M2 Air gates remain separate. No old role, Reader, native dispatch or shared
selector was edited or invoked.
