# Native preflight recovery source registration

The local Source ref `codex/native-preflight-registered-source-20261127` selects
`a113f522e6f17ac86daf82193442485e88b69316` and composition
`installer-preflight`. The canonical consumer path in that commit is
`scripts/ci/development/packet.lock.json`. This directory retains a separate
copy of the same packet for the implementation branch.

| Item | SHA-256 |
| --- | --- |
| Registered packet | `6892cec93380a9773ecd8b4905227fa5aefb4b3796f68271025166d7a6d5d7e3` |
| Bootstrap-encoded source rows | `8cc7c63286f41b54d95472b487cd334f6c02f02769d3cd042478b4b1c8916e68` |
| Captured Session issuer | `4d14aa2dd78a793f923f77123833ea5cd06c743002d73f742e2490aedd20518b` |
| Receiver | `fe2becb4fe6c22e50903ab390db5a79aae311b7284fc71bf4b1c4b79e99824c4` |
| Tool profile | `b7fbd65e357e132949432fb00e765a05e3c76ea29a41d1df93413870d9fd1ed8` |
| Receiver runtime | `8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821` |
| Builder input lock | `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650` |
| Builder inventory (341 packages) | `89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f` |

The Source commit derives from `bcf0cee981ee4b7f7b082f636922c859dc7e0abc`.
Its 265-row source map changes only the Session issuer from `c380e278f` and
the bridge and two tests from `aeab1fb35`. It preserves all 159 original
source rows, 125 generated fixture rows, and 12 metadata pins. The historical
`packet-installer-preflight.lock.json` retains SHA-256 `59f4d6ec…`.

The original [trusted launcher](../../../.github/bootstrap/development-launcher.py)
selects the composition and checks the canonical packet digest. The
[bootstrap](../../../.github/bootstrap/development-bootstrap.py) checks the
Root-selected source rows and metadata against the peer selection. The
[packet verifier](../../ci/development/packet.py) checks tracked blobs and
modes at the exact Source commit. The [controller](../../ci/development/controller.py)
and [Session issuer](../../ci/development/repository_handoff.py) validate and
register the exact `native_install_preflight.run` callback. The bridge then
checks the receiver, runtime, profile, and builder pins.

Run the focused source controls with the Source ref present in the same local
repository.

```sh
TMPDIR=/home/gabe/.cache python3 -B scripts/install/native_preflight_registration/test_registration.py
```

The Source commit has passed source registration checks. Hosted use still
requires a real peer Data commit, an external Root plan with CLI and Git pins,
and a workflow at the Source commit wired to the original trusted launcher.
The frozen development workflow and the separately maintained composition
have their own entry contracts. No run grant or Docker, guest, ABI, or
hardware result is established by this registration.

The full controller suite has one inherited early-entry assertion failure.
The same test fails at the frozen parent. All 25 installer-specific controller
controls pass.

## Hosted source-only check

The [workflow](../../../.github/workflows/native-preflight-source-registration.yml)
checks out the canonical Source SHA at depth one, authenticates the packet and
its 265 Git rows, and runs 11 cleanup models and 37 receiver controls on
Python 3.14. The job summary records the Source SHA, packet digest, and each
step outcome.

Publish `a113f522e6f17ac86daf82193442485e88b69316` to
`refs/heads/codex/native-preflight-registered-source-20261127` on
`Gabriel-Kahen/cachy-asahi` before opening the separate route PR. The route
PR should target a branch containing `1db8f7a59`, which already carries the
bridge fix. GitHub Actions must be enabled with read access to the canonical
repository. The path-filtered PR check can run when the workflow is present
in the PR. Manual dispatch also requires the workflow on the default branch.
