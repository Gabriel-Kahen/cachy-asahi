# Updater native acquisition failure and retry

[Run 45697080431](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45697080431)
dispatched reviewed source `d5299e83aa3ae504d7a9f951ab6bab00555f0f04`. The
committed-source freeze and exact source/vendor materialization passed. The
controller stopped at native input authentication with exit 1. The validated
guarded acquisition frame recorded **303 PASS, 224 HTTP 404, and zero pending**
out of 527 objects. Signature authentication and compilation were not reached.

All three public evidence frame byte counts and SHA-256 values matched:
`guarded` 25,369 bytes / `e6dbb664cdb216bb3828c57ac21383f67a3e60e3d9781afda99421efd902a166`,
`terminal-public` 1,202 bytes / `299a6f47ecb3b9fd5e34ecf634a28e87da464debe2e91d1d1aa9c941571a14dc`,
and `recovery-terminal-public` 843 bytes / `803ee3cbaf165277beb47478693f0369224e91d4354ebde1702414bd7e240d48`.
Projection, scoped cleanup and recovery passed. The terminal reports private-data
removal and retention within budget. Daemon disposal remains unattested. The
final workflow step returned failure because it verifies the native trial
outcome alongside recovery and export.

## Exact retained-input join

The 527 receipt tuples joined bijectively to the merged updater lock by SHA-256
and byte count. The missing set totals **632,237,043 bytes** and consists of 210
base and 14 extension objects. Keyring and rootfs acquisition passed. Actual
archive and signature bytes authenticated against these tuples locally:

| Source | Exact join to failed objects |
| --- | ---: |
| Private `native349-r1` commit `9d9e1ab7ce694e33238ec1152bef72270d4bf91f`, tree `cc6298d8dbbb5b0dd522de76b7140306d83bfe7a` | 182 of 182 |
| Private `native623-base-r1` commit `3ac0b845b13b9a8f1da4fc9ec90ac627a6f0da0c`, tree `e3f619a2bb8a287cd0aaa7d1975d8d392cb8786e` | 22 of 22 |
| Private `native623-r1` commit `b429266444c82238783044301ceb0f8d08bbf3f6`, tree `a8f1cd41e3aadeee9a25bc3b96e14c823de870aa` | 14 of 22 |
| Retained native574 commit `4659076d3a1d3e5cf87c185a3ff383fbc38e734d`, tree `e21f947bac3afdfbd67e4e65c8234b35ae42b00f` | 4 additional |
| GNU Parallel package and signature from the dated ALAA snapshot | 2 additional |
| **Total, with zero unrecovered** | **224** |

The first three refs cover 218 distinct failures. The four existing native574
blobs are Git 2.56.0-1 and Perl Error 0.17030-3, with their signatures, under
`packages/`. Fetch only the four named blobs at this immutable commit. The two
new files total **369,770 bytes** and were recovered from the
[2026-10-09 ALAA snapshot](https://pkgmirror.sametimetomorrow.net/aarch64/repos/2026/10/09/extra/).
The archive SHA-256 is
`abd4a16e9348cc1bb0f39b7affb92a18c81efae1e791dee30c548b170a7ba4ec`.
The detached signature SHA-256 is
`9f6f122076bee134ca13bf08dfe5a66a76f88a63e5bc1f636e4ab948db9e9f60`.
Isolated `gpgv` verified ALARM signer
`68B3537F39A313B3E574D06777193F152BDBE6A6` for that pair.

## Retry handoff

Reuse the kernel job's read-only SSH deploy-key scope for the three existing
private refs. Authenticate the exact host key, commit, tree and selected blobs
and keep the credential in the bounded intake step. Prefer immutable raw
fetches for the four native574 blobs. Only the Parallel pair needs a new private
carrier if the ALAA snapshot cannot be used directly. Bind any new carrier to
its exact commit and tree before using it.

A reviewed intake step should merge those 224 objects into a flat UID-owned
`$UPDATER_CONTROL/retained-cache` directory at mode 0700 with files at mode 0600.
The coordinator owns provisioning and disposal of that input directory and
any provider credential scratch. The updater accepts data files only, verifies
the supplied subset against the exact 527-object plan, and copies it into the
registered stage's private build cache. The local handoff copied and verified all
224 actual objects, without contacting a provider or starting a build.
The native worker still acquires any remaining input through the pinned original
route and checks all 262 signatures, the exact 354-package inventory, and the
native pair. Stage cleanup retires its own copy.

After integrating a reviewed intake and confirming the cache route, preflight
the published tip using the literal `READY_SHA256`, `STAGE_SHA256`, and
`SOURCE_SHA256` from the reviewed workflow. Run the commands in the
[4.4.2-3 preflight record](updater-442-3-preflight-20261125.md) with those updated
bootstrap literals, then dispatch `native-arm-updater.yml` on that branch with
`source_commit` equal to the exact remote tip. The workflow should be retried
with the verified cache handoff present. No recipe, dependency version,
inventory, or upstream trust pin changed in this repair. Hosted retry,
installed Check, and hardware qualification remain pending.
