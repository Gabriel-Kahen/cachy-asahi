# Emulated ARM16K virtio seat: actual r4 result

Root's fresh r4 trial on 2026-11-15 passed
`PASS_EMULATED_ARM16K_VIRTIO_SEAT_PAM_POLICY_ONLY`.
This qualifies the exact emulated software journey. GTK UI, native16K,
either M2 Air, performance and release acceptance remain unqualified.

The original 111-package reference was copied into a fresh image. Ordinary
trusted ALPM installed the 44 reviewed additions, producing exactly155 packages
with inventory SHA256
`0aca1977a11761df238ebbdeac6c6618a217e7122194d12f029eccae4d7c808d`.
The guest used its PL031 RTC through normal hctosys, with advancing current
time and no clock-setting command before signature checks.

Actual virtio MMIO GPU, keyboard and block devices negotiated VERSION_1.
Forty-one ordered keyboard release acknowledgements delivered login input;
password echo was disabled and credential values were not exported. Normal
tty1 PAM login produced a UID1000, active, local seat0 session. Stock
NetworkManager policy authorized `settings.modify.own` without a Polkit agent.
All six independent observer checks passed: bus credentials, logind session,
process/VT, GPU, keyboard and seat status. Normal VT/PAM logout preceded QMP
quit. QEMU exited0 without supervision signals, was reaped with EMPTY_TWICE,
and the owned container was removed and independently absent.

The exact source lock is19179 bytes, SHA256
`06153a9b191aac9f0c974334e6e60ca32b0230ca3581f6d1e404f2efc99b15ad`.
The tool image is
`sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a`.
The prepared descriptor is2304798 bytes, SHA256
`dca852180a1bb867c53ba989561565da6cbca603a22defb880aff9694195976a`.
Root's runtime admitted two CPUs,3GiB RAM and256 tasks, a readonly container
root, no network, no added capabilities or host devices, and retained the
canonical lease through same-FD/PIDFD and independent nonblocking conflict
checks before close-only release.

Original failed r1/r2/r3 roles remain closed HOLDs. The r3 private GPU receipt
proved that only the order of TAGS/CURRENT_TAGS changed. The correction compares
those two tag memberships separately while keeping every other GPU byte/field
exact; gained or lost tags still fail.128 fenced source controls passed.
No failed role was replayed or relabeled.

Durable Root retention is under
`artifacts/development/orchestrator-resume-20261114/Root-ARM155-boot-r4/`:

| Original record | Bytes | SHA256 |
| --- | ---: | --- |
| retained-readonly/report.json |15418|51bce478b33682d5f4bd01343db31882101c49aaa4973656b07a1f0e0d46422b|
| retained-readonly/serial.redacted.log |43931|fe3f9e30c71431e94aa32f812f3329510b21c1c234635e91abd68d97e8203ba9|
| retained-readonly/qemu-retirement.json |251|667ff0de667e21303b51ae90703badb30e76ab29dd246a6582cae4625ed2819f|
| Root-scoped-decision.ACTUAL-r1.json |1530|f07fbd4155f81e7683928d599d6cd0677ff6b63a3bcf0063e53bbc7fd8b5e52b|
