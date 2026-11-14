# Host delivery validation — 2026-11-14

`cachy-asahi-install-handoff 0.1.0-1` has an unsigned host package assembly and
actual archive/extracted-payload result. It has not been installed with pacman,
qualified on native ARM/16K, or exercised on either M2 Air size.

The package preserves the runtime/verifier/interface bodies from
`1c4c455b486fd0b0f1c7ae587130a2c05e7a9560`. Its new launcher only resolves its own
prefix and invokes fixed `/usr/bin/python3 -I -B` with the unchanged runtime CLI.
No runtime/verifier source or shared manifest/workflow was edited.

## Build and artifact

The existing CachyOS x86_64 host satisfied every declared dependency and check
dependency via `pacman -T`. No host dependency was installed. The successful
ordinary build command was:

```sh
INSTALL_HANDOFF_HIDE_CHECKOUT=/home/gabe/Documents/ChatGPT/cachy-asahi-install-handoff-parallel-20261114 \
  makepkg --cleanbuild --force --noconfirm
```

Dependency checking, source integrity checks and `check()` were enabled.
`--nodeps`, `--syncdeps`, dependency installation, skipped checks and privileged
installation were not used.

- Archive: `cachy-asahi-install-handoff-0.1.0-1-any.pkg.tar.zst`
- Bytes: `184625`
- SHA-256: `cf34935122855ca6aaa02f4c11987d53530e0e729c03698fa03aa1586ffac59e`
- Runtime receipt SHA-256: `335029521a25eb2627651a2c32c9e9c648f384ea15f62ca8d4084b1dcf4743f4`
- Payload: 39 files, including the exact 33-file private runtime.
- Runtime declaration: `arch=('any')`; this is not ARM/M2 execution evidence.

`check_sources.py --srcdir src --root <trusted-checkout>` independently compared
all committed runtime/interface and check-fixture bodies to the frozen Git
revision. The two generated runtime/source receipts are separately pinned by
the runtime inventory. The private and check-only snapshots have 33 and 36 files,
respectively. Test sources are not installed.

## Actual delivery checks

`makepkg check()` staged the actual `package()` payload. After building, the
following repeated those delivery controls against the **actual package archive**:

```sh
python -I -B -Werror::ResourceWarning test_package.py \
  --recipe-root <recipe-directory> --srcdir <recipe-directory>/src \
  --hide-checkout <trusted-checkout> \
  --archive <recipe-directory>/cachy-asahi-install-handoff-0.1.0-1-any.pkg.tar.zst
```

Both executions reported `PASS_HOST_PACKAGE_PAYLOAD_ONLY`. They checked exact
file paths, hashes, lengths and modes, moved the prefix, hid checkout/check
sources/producer data/private signing home, isolated the network to loopback,
and poisoned ambient Python lookup. Candidate and predecessor kits plus all 16
recovery archives had genuine disposable TEST signatures with no verifier mocks.
The fixed ALARM anchor was replaced only inside the explicit TEST driver;
production launcher policy remained unchanged and refused the TEST certificate.
The fixture's one exact Git-context request used the packaged source-lock commit,
without replacing any trust decision or signature verifier.

Changed and missing runtime files were refused before helper execution. Exact
payload-file removal preserved caller handoffs, receiver state and unrelated
caller files. That inverse is a file-level check, **not** an installed pacman
remove/upgrade lifecycle or boot/session recovery result. No install, removal,
service, trust, partition or boot hook is shipped.

Two failed build attempts remain recorded privately: source-integrity checking
caught a late test-body/checksum mismatch; then the caller-data snapshot test
incorrectly rejected a legitimate internal repository alias. Only the test and
its recipe checksum were corrected. Neither failure was bypassed, and no
runtime/verifier body was modified.

Native ARM/16K package builds and signed installed lifecycle, actual supported
Asahi installation/first login, independent production trust, both physical M2
Air sizes, boot/session recovery, performance and supported release acceptance
remain **NOT RUN / held**. The package remains opt-in and unselected.
