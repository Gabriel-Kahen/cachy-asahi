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

## Build-only retry

The updater workflow accepts `retained_inputs=true`. After authenticating the
committed source and before the native stage, a bounded intake step reads the
existing read-only deploy key from `CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY`.
It pins the GitHub host and deploy-key fingerprints and fetches four exact
parentless refs from `Gabriel-Kahen/cachy-asahi-ci-inputs`. Git objects and key
scratch are private to intake. Only the selected archives and signatures reach
the flat UID-owned 0700 cache. An independent, credential-free step retires
the handoff even if the build fails. The native stage rechecks the supplied
subset against the exact 527-object plan and retires its own copy.

The fourth ref is `native-updater-442-r1`, commit
`dd3647c78ece17207f605b9275eddf3314e2d8b1`, tree
`11048ce3fffdbab0037d9c5c3c4a8108763ce462`. It contains exactly six files
and 9,042,806 bytes. This private supplemental branch includes the Git and Perl
Error pairs from the retained native574 carrier and the verified Parallel pair.
Host-side verification used authenticated local copies of all four Git trees.
Hosted SSH access needs the coordinator to publish the fourth ref and grant the
existing read-only key access. No new trust pin is introduced for package
signatures.

Preflight the exact integrated and published tip with the literal
`READY_SHA256`, `STAGE_SHA256`, and `SOURCE_SHA256` from the reviewed
workflow as in the [4.4.2-3 preflight record](updater-442-3-preflight-20261125.md).
After the four immutable refs match their pins, dispatch:

```bash
gh workflow run native-arm-updater.yml --repo Gabriel-Kahen/cachy-asahi \
  --ref "$reviewed_ref" -f "source_commit=$reviewed_commit" -F retained_inputs=true
```

The worker acquires other objects through the pinned original route and checks
all 262 signatures, the exact 354-package inventory, and the native pair.
Installed Check additionally requires a container rule in the Docker broker,
an independent runtime dependency closure, and reserved time before private
archive retirement. Native build, installed Check, and hardware gates remain
pending.
