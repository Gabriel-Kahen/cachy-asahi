# Advice-capable KSM diagnostic kernel build

Run [39340364029](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39340364029), source `80aa47304123106133832c11a9e4a405af5f1f67`, passed native build/configuration/header checks, original artifact collection and strict replay. Root accepted **ROOT_ACCEPTED_KSM_ADVICE_DIAGNOSTIC16K_BUILD_ONLY** for profile `KSM_ADVICE_GENERIC16K_DIAGNOSTIC_V1`.

Root independently joined all19 Git source blobs, the original API artifact digest, all26 exact ZIP members and their source-owned descriptor pins. The immutable kernel source revision is `94fb23346d522edf53722357c426a3e58030beea`; its262,965,559-byte archive has SHA256 `874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad`. The8,884,232-byte Image has SHA256 `039fbeaff5942de2317f47feec30a5c073691edf5f8cef8849b25d08006d4ddb`; the63,793-byte configuration has SHA256 `5f1f5e507586734c0955607960ceecfe822b5c908bfc1da9d29fe80ac627a8e9`.

Against an actual same-environment baseline, the only enabled-symbol changes are advice syscalls, KSM and XXHASH. ANON_VMA_NAME remains explicitly disabled when newly visible;16KiB pages are configured, while THP, PROC_PAGE_MONITOR and modules remain disabled. Source-enforced owned build-work removal passes; no fresh host absence or independent-machine attestation is claimed.

The complete28-file public carrier is commit `247123187cb1aceae5e61bc89f3c01dbf2986311`, branch `codex/ksm16k-advice-kernel-inputs-v1`. It preserves original native files, Root build-only decision and transport pins. See the [finite result](../../manifests/ksm-advice-kernel-build-result.json).

Boot, VM execution, live sysfs, memory sharing, interruption/unmerge behavior, performance and M2 hardware remain NOT RUN or NOT MEASURED. Earlier scalar results cannot substitute for the separate sharing trial. This diagnostic Image is not a shipped Asahi platform replacement. Both M2 Air sizes remain unqualified; release remains NOT ADMITTED.
