# Generic ARM64 16 KiB kernel trial

[Diagnostic actual38864391246](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38864391246)
passes the native build, generic16KiB userspace smoke, natural QEMU exit0 and
three owned-workspace cleanup checks. Source/workflow is
`ba2e14c90f915d944d2cd54f4a408de8c85e504b`, manifest
`9a8eece98d98a523a867c3779c3c98e2f739aaaabea211d61aba5b7f06aa147d`.
Root independently checks all14 source identities, both config fragments,
the ordered once-only uname/getconf/memory-smoke/nonce markers and the retained
command/fixture/cleanup joins.

This profile adds KALLSYMS, printk timestamps and initcall tracing. Its Image is
5167112 bytes, SHA256
`4e0a0a7ca05569e4c7a827d9597b937c84c3c3fd0f9b8cf585df5af6e8b418f2`;
configuration SHA256
`32b8749857f457f567f1b77106724cc0bc13927d93d9779257b4741cc0f14b00`.
The guest executes retained ARM64 bash/uname/getconf and a static smoke program,
reports16384-byte pages and validates mmap/mprotect/munmap and file-offset
alignment. All24 declared public files total161539 bytes. The retained ZIP is
154238 bytes, SHA256
`5f71f1e29fb1bc80ff44ce2edc034aa9d9797536eba93f93e4df98e187ec733c`.
Independent PID absence was not exported; natural process completion and the
source-enforced retirement path remain the recorded process evidence.

The trace shows clock cleanup returning and `/init` executing. It does not
identify why the earlier profile timed out. This is a generic diagnostic-profile
software result, separate from the earlier failure, signed transactions, Asahi
platform integration, physical M2 execution and performance.

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

The opt-in diagnostic added named initcall traces and printk timestamps,
with a bounded complete UART export. Its25 controls pass. It preserves the
timeouts, userspace acceptance markers, normal-exit requirement and cleanup
gates; it is not a proven boot repair.

The once-collected ZIP is133164 bytes,
SHA256 `cc0dd6c5c140c802568fdad177f1940cd48ad3f884c15e7b1de2dc318299ef85`.
Only the dedicated22-file public frame was decoded. No kernel/rootfs/initramfs
payload was exported. M2 hardware, Asahi platform integration, physical16KiB
execution and performance remain NOT RUN.
