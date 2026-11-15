# Perl 5.42.3 native ARM4K build pair, 2026-11-15

Root accepted the exact **Perl 5.42.3-1.3 native ARM4K build pair only** after
[CI run 43692477455](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/43692477455),
job `perl5423-native-v2` / `132745843566`, completed successfully from
08:00:42 to 08:24:41 UTC. Root's scoped decision was issued at 09:29:02 UTC.
External XS, native installation/removal, native 16K, target ABI, M2,
performance and release acceptance remain unqualified.

## Exact source and build domain

The published Source is `25dc3e65bdb6137c87a9409067fe9b2cf6e9763f`, ref
`codex/native-arm-perl5423-v2-20261115`, with 272 files, tree
`43dfa9d6370abd1424bd5586c5524a6f4b4e1556` and source-map SHA256
`4b1de3aade5116206318570d1d44ee1063342faeab54935748b1b7c179a99e96`.
The recipe SHA256 is
`cf0df8990ac83f48a4c29978c932922108f0e01cb6d052209934da5b01af4068`.
Its retained upstream source snapshot is revision
`bc3dab4d4f66de5ea67dda34e5feb5230a54c603`, 22610875 bytes, SHA256
`16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725`.
This candidate does not reproduce or establish source correspondence with the
historical ALARM Perl 5.42.3-1 archive.

The signed bootstrap supplied 349 packages from 257 signed payloads and 517
input files. Two fresh dependency-checked builds used the
`PERL_ARM_CAP0_NNP_RO_CONTAINER_V1` domain on an observed 4096-byte-page native
ARM host. The fixed command was:

```sh
/usr/bin/makepkg --config /work/makepkg.conf --cleanbuild --nosign --noconfirm --log
```

The selected configuration fixed `MAKEFLAGS='-j2'` and zstd compression
`zstd -c -T2 -19 -`. These output archives were built with `--nosign`;
bootstrap signature verification does not make the new package signed.
Nested namespace invocation remained **NOT_INVOKED / NOT_QUALIFIED**.

## Actual pair result and limitations

Both `perl-5.42.3-1.3-aarch64.pkg.tar.zst` archives are byte-identical:
22071176 bytes, SHA256
`647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22`.
Their compared payloads are identical, with 3262 entries and 54 ELF files each.

| Upstream harness observation | Build 1 | Build 2 |
| --- | ---: | ---: |
| Files | 2920 | 2920 |
| Reported tests | 1351601 | 1351626 |
| Whole-file skips | 157 | 157 |
| Seconds | 386 | 383 |
| Fakeroot preload warnings | 1700 | 1700 |

The differing test counts are retained as observed, not normalized. Both logs
also report `TODO passed: 3-4` and a source-directory warning. The pair result
does not imply every upstream test ran or that these warnings disappeared.

The retained retirement joins cover 37 supervised operations, two retired
volumes, 33 exported files per build and final owned-resource absence. Both
build actors retired naturally. The created bootstrap image was removed and
its absence verified.

## Authenticated evidence and decision

Original artifact `14153417247`, named
`perl5423-native-v2-43692477455-1`, was retained unchanged: 114747714 bytes,
SHA256 `75323ce74aabe9b64d250486c18ce5c58809726a8ba9f76b618d6bc9abf35c77`.
Its faithful 711-file view preserved bytes and modes, including both raw export
TARs. Root separately entered passive Reader3; it returned
`PASS_HOSTED_PERL_PAIR_DATA` and closed naturally with `CLOSE_ONLY`. Reader1's
implicit-CLOEXEC guard refusal and Reader2's absent-optional-file guard refusal
remain closed records; neither was treated as a package failure or replayed.

| Retained receipt | Bytes | SHA256 |
| --- | ---: | --- |
| Reader3 result | 10992 | `b4df9cfe90aa3a23bd8aefc43e006d0e2ca0265b9070e3188a67beaf733169ce` |
| Reader3 execution and release | 1035 | `269d83dd21a668332aab834f32f7c65cbbd55c1f7f9363dd3be2d58614674542` |
| Root scoped component decision | 5804 | `27803c99064198f8688abe2e4d91910eef93df5ad337ebfc7f2d8798afbf41e1` |

Next gates are separately admitted installed/removed and external-XS journeys,
16K and supported-target validation, and release signing/admission. This document
adds no actor execution or acceptance beyond the exact native 4K build pair.
