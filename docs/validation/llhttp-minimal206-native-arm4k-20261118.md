# Minimal206 llhttp 9.3.1 native build pair

On November 18, 2026, two clean, unprivileged, offline build containers built
`cachy-asahi-llhttp-reference 9.3.1-1` on a native AArch64 runner with
4,096-byte pages. Both recipe checks passed. Root accepted the build pair
and scoped cleanup for exact r12 Source `1604862d09fb04e471da03df2e2a98a5c05a77bf`.
[Public run 44263404780, attempt 1](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44263404780)
· [Pair job 134661977148](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44263404780/job/134661977148)

The signed root filesystem started with 165 packages. Provisioning produced
the exact 206-package inventory. All five inventory files matched the same
lock byte for byte, including the provisioned inventory and each build's
expected and observed inventories. Independent readback verified 417 pinned
inputs, 207 detached signature checks, and all 756 files listed in the inner
evidence manifest.

Both r12 packages and both packages from the original r11 run were
byte-identical 29,696-byte AArch64 XZ archives with SHA-256
`9e583b31361fbd3de5575b156053e8ca86f25f1e7b5762084681c39355e5361f`.
The packaged ELF has SONAME `libllhttp.so.9.3`. The r11 run remained on hold
because its derived-image removal used `--no-prune`, leaving dependent
child images. Docker then refused to remove the imported rootfs image
and exited 1. [Original r11 run 44257125471](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44257125471)

In r12, non-forced removal of the exact derived image allowed Docker to
remove its untagged ancestors. The imported image was then removed by
exact ID with `--no-prune`. Both commands exited zero and their process
groups were empty on two checks. The final derived-label, imported-label,
and imported-tag censuses were empty. The inventory and build containers
were absent, the controller and both services retired, and owned storage
was absent.

This closes the hosted build-only scope. Installation of this archive,
native 16 KiB execution, and physical M2 testing remain unrun. Release
promotion remains open.
