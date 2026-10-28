# Independent controller review

October 11, 2026. **Interim source review: changes remain in progress; no frozen
handoff or native end-to-end execution has been accepted by this reviewer.**
The reviewer owns this file only for the controller review. No implementation,
shared manifest/status, Git state, host package/account/keyring, Docker daemon,
or workflow was changed. Reproductions used temporary files and mocked commands
with subprocess tripwires. Read the roadmap, integration contract and package
inventory; the four development configuration packages do not satisfy the full
port or physical acceptance requirements.

## Open findings

### C1 — P1: guards accept unintended host mounts (V02)

`scripts/ci/sign_fixture.py:139–145` permits arbitrary mounts below `/dev`,
`/sys` and `/proc`. `scripts/ci/source_suites.py:88–89` permits known mount
destinations without checking their filesystem types/options. Guard-only
reproductions added these synthetic writable ext4 mount records to otherwise
valid probes; every case was accepted:

| Guard | Additional/replaced mount | Outcome |
| --- | --- | --- |
| TEST signer | `/dev/dri`, `/dev/snd`, `/sys/private-home` | ACCEPTED |
| Source suites | `/sys`, `/proc`, `/dev` | ACCEPTED |

The current launch command constructs restricted mounts, so this is a failure
of the required independent refusal contract, not evidence that the workflow
actually exposed a host resource. Validate destination, filesystem, flags and
unexpected devices/sockets before commands. Add negative fixtures for these
accepted cases. During review, lifecycle's previously permissive unrelated-mount
handling was corrected (`scripts/integration/lifecycle.py:134–140`); that earlier
finding does not describe the current lifecycle source.

### C2 — P2: cleanup failure can accompany stage PASS (V02/V08)

`scripts/ci/integration.py:201–207` ignores the return code from `docker rm -f`;
the lifecycle-specific finally block at `:421–422` and signer host finally at
`scripts/ci/sign_fixture.py:366–371` have the same issue. A mocked successful
container execution followed by removal return code 1 made `execute_container`
return normally. The stage therefore has no indication that its disposable
container may remain. Removal timeout can also interrupt final provenance writes.

Record bounded cleanup outcomes, retain the original stage error, and require
successful removal/verified absence before accepting a stage. No Docker removal
was actually attempted in this review.

### C3 — P2: cancellation bypasses container/process cleanup (V02/V08)

The controller and signer use `native.run()` without installing cancellation
handling; default SIGTERM terminates Python without executing their finally
blocks. `installed_handoff.py:117–124` runs lifecycle through `subprocess.run`
without a new process group or cancellation-safe finalization. Timeout handles
the direct child, leaving descendant cleanup to container removal; C2 prevents
that fallback from being verified. Source suites handles timeout process groups
but does not handle ordinary controller cancellation.

This finding is source-audited, not a live signal/container reproduction. Handle
SIGTERM and interruption, terminate tracked process groups, remove named
containers with bounded retries, and finalize sanitized failure evidence even
when cleanup itself fails. Mock interruption/removal failure at each adapter
boundary; do not rely solely on CI runner disposal.

### C4 — P2: handoff certifies the mounted `/tmp`, not the image (V02)

The controller mounts tmpfs at `/tmp` (`integration.py:401`). Handoff cleanup
empties and certifies that view (`installed_handoff.py:183–199`), then the
controller commits the stopped container. Mounted storage is excluded from
[Docker commit](https://docs.docker.com/reference/cli/docker/container/commit/).
Consequently those checks do not inspect or clean the underlying image `/tmp`.
The current bootstrap copies `/tmp/disabled-hooks.txt` and does not remove it
(`native_arm.py:307–312`), providing a concrete source-derived residue example.

This does not establish a private-key leak: newly generated lifecycle key state
is on tmpfs. It establishes that READY's empty-tmp/image-sanitization claim is
unsupported for the committed layer. Sanitize and verify the underlying writable
image view before READY/commit, then independently verify the committed image.
No Docker commit or resulting image was executed/inspected in this review.

### C5 — P2: failed fixture builds omit detailed diagnostics (V08)

`integration.py:324–331` copies builder provenance, validation and `build.log`
only after `native.run()` succeeds. A temporary mocked build wrote all three
files, wrote the driver's `build failed; see build.log`, then raised a nonzero
exit. The raw stage contained only `fixture-1.log` and `fixture-manifest.json`;
the specific compiler failure remained under private `work/fixture-fixture-1`.
Workflow retention exports public stage directories, so the referenced detailed
failure is missing from retained evidence.

Copy already-created, explicitly public builder diagnostics in a finally path,
with regular-file/content/bounds validation. Preserve FAIL when output is absent
or incomplete. Add a fixture reproducing failure after output creation.

## Contracts already present

- Snapshot hashing/modes and recipe/fixture pins precede native mutation;
  unused `scripts/virtual/**` and `scripts/client/**` are excluded.
- Required stage failures block aggregate PASS; source-suite skips are visible
  and cannot satisfy complete acceptance. Public export failure has a separate
  failed controller record; credential-bearing exception strings are sanitized.
- Signatures bind exact archive hashes and TEST identity. Installed handoff
  checks complete base-plus-original inventory and archive-derived owned payloads;
  desktop/onboarding receive the derived immutable image and installed lock.
- Hardware validation, production trust and release selection remain separate.
  Generic native ARM software success cannot establish M2 performance/graphics,
  recovery or full-port acceptance.
- Workflow evidence retention now continues after individual bundle failures;
  the earlier fail-fast retention concern is corrected in the current source.

## Reproduction snapshot and remaining work

These are behavioral probes, not a complete test-suite pass. Host subprocess
execution was forbidden except the outer Python interpreter; mocked calls used
synthetic names and paths. No ARM build/install or runtime performance was measured.

| File | SHA-256 at reproduced checkpoint |
| --- | --- |
| `scripts/ci/integration.py` | `85c8c084441f007473813ee227c7d99917cb2a73e580260a82c5bd9ebf328ba5` |
| `scripts/ci/sign_fixture.py` | `938f9c6d6659e2f042d851add7e6396a1fdf712f31c13313a1ab1925fe562609` |
| `scripts/ci/installed_handoff.py` | `61bb5e13591df21ba343e8cd3132fe8aa9709dac71709265f4d82a02a8dd6967` |
| `scripts/ci/source_suites.py` | `8b5734d1c6ddba6b492876dae0baa80db6b6b8348dce4b32ac3b96fb071e028f` |
| `scripts/integration/lifecycle.py` | `e5ada2160d8c2e45f576d323da48af1c175eabb7110b05948f16fd5f68d8ae68` |
| `scripts/ci/native_arm.py` | `566a537220e4734775cb88467b65d87d827b1b07bb286135070d74f8c3f8a57a` |

Resolve/reproduce C1–C5 against the final source freeze, then inspect actual
native stage receipts, lock/archive bindings, retained failed diagnostics,
cleanup outcomes and derived image state. V09 is not complete at this checkpoint.

## Candidate-freeze recheck

The CI owner's candidate lock is now present: SHA-256
`641be67646a40f396f6aaff7c24dcfa4af2c91d4734c99a30702df6e472d54c8`,
151 source files and 125 generated fixture files. Read the final handoff in
`docs/workstreams/native-arm-ci.md`. Independently compared current source
hashes/modes with that lock; the candidate is **not currently a matching freeze**:
`README.md`, `scripts/ci/integration.py`, `scripts/ci/installed_handoff.py`,
`scripts/ci/test_integration.py`, `scripts/ci/test_installed_handoff.py`,
`scripts/ci/sign_fixture.py` and `scripts/integration/lifecycle.py` have changed
in bytes or modes. Both excluded follow-up trees remain absent. The owner's reported
141-test pass is their local mocked validation, not an independently rerun native
aggregate or proof that subsequent edits passed.

At this later checkpoint, controller SHA-256 is
`466e5d634dd1f2eb02230523d1eed5d3593733d89b01e10765a10082021fe1cd`;
handoff SHA-256 is
`1dd19c7989d515b90bbe1160d3d4289929b86eb39c234b823b0b0ce194744b18`.
The other four hashes above still match. C1, C2 and C5 remain present.

C3 is **partially corrected in source**: handoff now creates a child process
session, handles cancellation and writes failure receipts in a protected finally
path. Controller/signer cancellation and verified container removal remain open.
No current handoff cancellation tests or live signal execution were run here.

C4 has a new handoff guard refusing any mounted `/tmp` view and a check for empty
image `/tmp`. However, the current controller still supplies `/tmp` tmpfs. A
direct pure guard reproduction returned:

```text
handoff must inspect the image /tmp; mounted temporary view refused
```

This correction is not yet integrated: the current launch contract necessarily
fails that guard before handoff work. Remove the incompatible mount using the
reviewed private-state strategy, validate both adapters together and refreeze.
These in-progress edits are not represented as a resolved or accepted native
handoff. Independent source acceptance remains **WITHHELD** pending corrections
and one coherent matching freeze; actual integration/derived-image evidence
remains **NOT RUN by this reviewer**.
