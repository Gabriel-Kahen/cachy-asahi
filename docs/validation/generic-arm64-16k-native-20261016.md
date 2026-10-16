# Generic ARM64 16 KiB kernel trial

[Actual38862416370](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38862416370)
is **FAIL**: native compilation passed, but QEMU timed out before userspace.
Source/workflow is `0909d8549cf2b9e8a2c4d4e47c2b4325581e6e6e`; the candidate
manifest is `b720276e3d66a7806940d50fbce2b25a34e2ae7346caaa693de284a0023c80ac`.

Both retained source/rootfs archives passed exact length and SHA256 checks on
their single acquisition attempts. Native Clang/LLD18 built
`7.1.13-generic16k-smoke`: Image4970504 bytes,
SHA256 `17e42bb2df09815b8b840b557c31f469f294ca99dc47e58cff84065a701f26aa`.
The complete generated configuration hash is
`237fd317c81bfe1cb4aa6a56b285a310061aa694f214ca7a306352f217225ffd`;
the selected fragment and Image header agree on16384-byte pages, with modules
disabled. This establishes a native build, not a working userspace or Apple boot.

The diskless TCG guest emitted kernel boot messages, then exhausted its180-second
budget. No uname/getconf/memory-smoke success markers or natural QEMU exit were
observed. All4934 UART bytes were retained; the last line enters unused-clock
cleanup but does not establish which operation stopped. The caller reports
input, VM and kernel workspace absence. Process retirement remains enforced by
the timeout cleanup source; independent PID absence was not exported.

The next opt-in diagnostic adds named initcall traces and printk timestamps,
with a bounded complete UART export. Its25 controls pass. It preserves the
timeouts, userspace acceptance markers, normal-exit requirement and cleanup
gates; it is not a proven boot repair.

The once-collected ZIP is133164 bytes,
SHA256 `cc0dd6c5c140c802568fdad177f1940cd48ad3f884c15e7b1de2dc318299ef85`.
Only the dedicated22-file public frame was decoded. No kernel/rootfs/initramfs
payload was exported. M2 hardware, Asahi platform integration, physical16KiB
execution and performance remain NOT RUN.
