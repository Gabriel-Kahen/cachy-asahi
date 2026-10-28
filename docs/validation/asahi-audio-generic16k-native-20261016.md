# Bankstown and Triforce in a generic 16 KiB ARM guest

[Actual38873662542](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38873662542)
passes60 software correctness cases across120 plugin instances at16384-byte
pages, natural QEMU exit0 and scoped runtime/builder cleanup. Source/workflow
is`06a3cb5c0d899c245938d46f6e8cb5695faa2d6d`; manifest is
`195a7b8d1aa03d642f9cc8430a94f912bd398ebb255b49f71caeb7d2b58444d1`.

The native ARM job reconstructs the authenticated574-package image and freshly
compiles the unchanged C host with its installed GCC, headers and libraries.
The before/after inventory remains exact. It captures32 files and18 ELF
observations, including nine pinned system libraries and the existing
Bankstown1.1.0-4 and Triforce-LV2 0.3.2-3 binaries. No Rust packages are rebuilt.
Their archive SHA256 values remain respectively
`5ce529103e77d6cc509e270d925f9ecaa126d6a9b14302cdb41c14b72ed0d3af`
and`d123dca2cd67099dfe3e45af9edc7f61ba11bf650a482695350184badd7dfa3c`.
Both guest loaders join the selected URIs and captured library hashes.

The same-job diagnostic kernel rebuild produces the previously exercised Image
SHA256`4e0a0a7ca05569e4c7a827d9597b937c84c3c3fd0f9b8cf585df5af6e8b418f2`
and configuration SHA256
`32b8749857f457f567f1b77106724cc0bc13927d93d9779257b4741cc0f14b00`.
The diskless guest reports AArch64, kernel7.1.13-generic16k-smoke and16384-byte
pages; the mmap/mprotect/file-offset smoke passes. It uses the current captured
userspace rather than the earlier August rootfs.

Bankstown runs56 cases: j413/j415 data profiles, four rates from44.1 to96kHz and
seven fixtures. Triforce runs four48kHz fixtures. All36 repeat pairs have zero
repeat error and equal sample hashes. Eight pairs each exercise channel
exchange, sign reversal and wet-amount scaling; their held numerical bounds
pass. The largest scaling oracle error is2.2351741790771484e-08. All16 control
bindings and the silence, bypass, amount-zero, finite/range, nonzero-energy and
wet-energy checks pass. Root checks the public source/receipt/inventory/exit
joins; the worker replays the unchanged strict numerical metadata projection.

The runtime container's absence, private-data removal and outer created-image
absence are verified. Bootstrap retirement is normal completion. Kernel-work
removal is source-enforced by the successful workflow trap; no separate absence
receipt is exported. Full UART and private payload/ELF bytes are not exported;
complete marker ordering and ELF inspections are retained source-enforced
receipts. The UART tail contains the nonce PASS and powerdown. Per-sample C
comparisons executed in CI; passive local replay covers numerical metadata.
Interruption cleanup is not exercised.

The once-collected log ZIP is127375 bytes, SHA256
`463d33d4c397f9287710ce4bd97a3811d38a199679dc35ac3ceb07767ff2f33f`.
Only the dedicated bounded public frame is decoded. It contains result.json
(36382 bytes, SHA256`c1c4d05906a0aa39c60318a313c06910b1ad42d93da6ca82871ccda051eef1f2`)
and runtime.json(137804 bytes,
SHA256`490695cb7772e54471603949a56b6b088e7be4d990a9f330bebf955048026b5d`).

The earlier38870933012 bootstrap failure remains failed; its inner cause was
not exported. The successor adds the omitted exact public14 seed before build.
This result establishes generic16KiB software execution of the existing plugins.
Audio devices, acoustic safety, physical M2/Asahi behavior and performance remain
NOT RUN. Profile names do not establish either Mac model's hardware acceptance.
