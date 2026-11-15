# Emulated ARM16K systemd reference, 2026-11-14

Root's first local boot **PASS** establishes a finite emulated ARM16K serial
PAM session. The actual report is
`/tmp/cachy-asahi-arm16k-first-boot-root-20261114/report.json`, 1,634 bytes,
SHA256 `36de34652c9d008b4edaa6e8d12e87d10d96fc62044ba9e30ea44793908efa4d`.
Its status is `PASS_EMULATED_ARM16K_SYSTEMD_SERIAL_PAM_SESSION_ONLY`.

The stock login/PAM path authenticated the fixture's ordinary `builder` user,
UID/GID1000. The session reported `PID1=systemd`, `ARCH=aarch64`,
`PAGESIZE=16384`, active logind and D-Bus, and matching XDG/loginctl session `c1`:
user1000, active, local, class `user`, type `tty`, service `login`.
Normal logout returned to the serial login prompt.

## Exact input and execution scope

The [constructor README](../../scripts/integration/arm16k_systemd_tcg_guest/README.md)
records preparation inputs and limits; its earlier `PREPARED_NOT_BOOTED` result
precedes this actual Root boot. Root's explicit authority is retained at
`artifacts/development/orchestrator-resume-20261114/Root-ARM16K-local-first-boot.ACTUAL-r1.json`,
848 bytes, SHA256
`3edf1a4f9670ea161b21d426a397538d8f9e28838db6c74e33b9d60b8bf11345`.
It binds source `61b6028a`, the prepared descriptor and exact tool image.

- Retained kernel `7.1.13-generic16k-managed-gui`: Image9,019,400 bytes,
  SHA256 `cd8053ebdb83302015efbad97ab1cc53fcd5a2353bf3f37ba208f4e6360946ec`;
  config SHA256 `e97d54d4852eceb6cba28c38f78d4a00aacbfdb0c1523cb96366590f7eaa915b`.
- Official ALARM2026.08 aarch64 rootfs:829,367,415 bytes,
  SHA256 `42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319`.
  Real whole-archive detached-signature verification requires fingerprint
  `68B3537F39A313B3E574D06777193F152BDBE6A6`.
- The dependency selection copies **111 whole packages from165 installed
  records**, including systemd261.2-1, PAM1.7.2-2 and pambase20260616-1, together
  with their package DB entries. This is neither frozen349 nor the current
  supported target composition; individual package signatures were not newly
  verified from separate archives.
- Prepared r5 descriptor:58,179 bytes, SHA256
  `f7b3073f58acce8ab5e21ff61f2182779d24046e1582cda6adb0a3db66b7036e`;
  raw ext4 SHA256 `f69d74fbb0043793c96424d0f91ad2f6fb2d8cf3a72fb94024ea9cc40dae4cd3`.
- Tool image:
  `sha256:ee1aa3da22a5d89dc1bc273fa818b1d996b7e62851f50d7b629144f6bba9f207`.

The actual guest used QEMU `virt`/TCG, two CPUs,1,536MiB, direct kernel boot,
virtio block and a private capped qcow2 overlay. There was no NIC, display,
KVM or passthrough. The rootless host container had a read-only root, no network,
devices or capabilities, and limits of2CPU/3GiB/256PIDs. Credentials remain
private and are not reproduced here.

## Retirement and remaining work

After normal PAM logout, Root requested **QMP emulator quit**. Guest poweroff
is **NOT QUALIFIED**. QEMU exited0, was reaped, reported `EMPTY_TWICE` process-group
census, complete output and no timeout/signals/errors. Ownership-checked cleanup
removed the exact owned container and verified absence; cleanup errors were empty.
The retained sanitized `serial.redacted.log` is29,137 bytes, SHA256
`284e11628862715167492ef8a23e1b4f76f9663d700ec0f4e34a31716df9324b`;
`qemu-retirement.json` is251 bytes, SHA256
`3db1d4c3bf4828eed2a0283a195008b2814ccbe6ef4b00b031d5bb6c44e9dd9f`.
Both are beside the report. The consumed first-boot attempt must not be replayed.

Next, separately admit the required package/session journeys against explicit
inputs and retain their own results. This reference does not establish the
current target transaction, native ARM/native16K, M2/Asahi hardware, GUI,
performance or release acceptance. No new actor ran while writing this note.
