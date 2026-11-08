# Generic emulated ARM16K namespace validation — 2026-11-08

Root qualified one local **generic EMULATED16K unprivileged bwrap component**.
QEMU TCG ran an AArch64 guest on a Linux x86_64 host. The guest observed kernel
`7.1.13-generic16k-managed-gui` and 16,384-byte pages. The fixed bwrap operation
returned zero, with distinct user, mount and network namespaces, unchanged outer
identity, and verified child/QEMU group absence and scoped work cleanup.

| Evidence | Observed result |
| --- | --- |
| Outer before and after | Identical UID/EUID/GID/EGID 23001, no supplementary groups, NoNewPrivs=1, all five capability masks zero |
| Inside | UID/EUID/GID/EGID 23001, no supplementary groups, NoNewPrivs=1, all five capability masks zero |
| User/group maps | Both `[[23001,0,1]]`, read in the inner namespace |
| Kernel credential witness | One complete SCM_CREDENTIALS record projected the inside sender to original outer UID/GID 23001; sender PID, nonce and exact context matched |
| Namespace observations | User, mount and network links changed; PID namespace stayed unchanged |
| Completion | bwrap and QEMU exited zero; owned groups were absent and private work was retired |

The successful trial directly observed inner 23001 mapping to immediate-parent 0,
while the kernel witness established outer 23001. A self-read map describes its
immediate parent, so treating its second column as the original outer identity
was incorrect for this observed context. The retained evidence does not claim
all intermediate ancestor-map rows were captured, and does not assign a cause
to earlier namespace failures.

The runtime executed published PR414 head
[`071dc32391762fa51fbc245538ec8f6351049ef6`](https://github.com/Gabriel-Kahen/cachy-asahi/commit/071dc32391762fa51fbc245538ec8f6351049ef6)
before merge. [PR414](https://github.com/Gabriel-Kahen/cachy-asahi/pull/414) was
subsequently integrated as Main
`ccc8fa770c85035b687def27573a572914b17547`, with ordered parents
`d7588a3658be86819275652dd735704e786e2f79` and the tested head. Public Git raw
commit identities are retained without relabelling the trial as execution of the
merge commit.

## Bounded retained evidence

[Public evidence archive](records/platform-namespace-emulated16k-20261108.tar.gz):
**10,027 bytes**, SHA256
`1ce2fe1643a4b37e352381d00cf95a009ab4318fdf233c0602ccfe21e0c2f010`.
Its five ordinary members total 24,235 bytes: the untouched 15,883-byte UART
(SHA256 `74cc6dd98d7061805116118b51eb71ceddcb4d9be5708553471623b1566b8003`),
public report/Root-decision projections, public source/integration identities,
and a member hash inventory. Projections identify their original byte/hash
receipts; they are not verbatim copies of the private packets.

Private providers, rootfs/vendor binaries, host authority/lease/process details,
HTTP/authentication records and signed URLs are excluded. Evidence preparation
only copied allowlisted DATA and checked hashes, JSON, archive structure and
links; it executed no source or VM code.

This result does **not** admit native ARM execution, Source50's native platform
route, either M2 Air, package build/install lifecycle, performance gains or a
production release. The original host-policy matrix and historical failures
remain separate. Trial inputs remain explicitly bound; no default selector or
shared package/status manifest was changed.
