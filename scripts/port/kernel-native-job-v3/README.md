# Kernel native job V3

V3 binds a new invocation of the native ARM producer to the current
`scripts/build/build.py` and `scripts/build/compare.py` bytes. It uses
`packet_v2.producer_snapshot` to reconstruct the historical Setup recipe files
and enrollment helper from the checked-in held Setup source and vendored helper.
The private producer view combines those exact recipe inputs with the V3 build
and comparison helpers.

The job requires fresh producer, image, inventory, and input receipts from the
same run before accepting the base for the kernel stage. The
[original packet](../kernel-native-job/packet.lock.json), the
[V2 packet](../kernel-native-job-v2/packet.lock.json), and their receipts remain
historical evidence tied to their own source and tool identities. The producer
uses the existing `build` mode. Archived integration-mode evidence remains tied
to its original source.

## Source-only review

From the repository root at the proposed commit, compare the generated lock with
both the checked-out and committed lock, then run the V3 packet controls.

```bash
set -euo pipefail
packet=scripts/port/kernel-native-job-v3/packet.lock.json
python3 -I -B scripts/port/kernel-native-job/packet_v3.py --root "$PWD" | cmp - "$packet"
git show "HEAD:$packet" | cmp - "$packet"
python3 -I -B -Werror::ResourceWarning -m unittest discover \
  -s scripts/port/kernel-native-job-v3 -p test_current_packet.py
git rev-parse HEAD
sha256sum "$packet"
```

Record the review against the complete commit SHA, dispatch ref, and SHA-256 of
the committed lock. The lock binds source paths, bytes, hashes, and file modes.
These commands verify source and packet behavior only. A native result requires
a separate successful workflow run.

## Manual dispatch

Use [`native-arm-kernel.yml`](../../../.github/workflows/native-arm-kernel.yml)
in the public `Gabriel-Kahen/cachy-asahi` repository. Manual dispatch requires
repository write access and the workflow on the default branch.
[GitHub manual workflow requirements](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)

The reviewed branch or tag must resolve to the reviewed commit and contain the V3 workflow and
`scripts/port/kernel-native-job-v3/packet.lock.json`. Confirm the ref's SHA on
GitHub immediately before dispatch and confirm the resulting run's head SHA
against the review. The workflow authenticates the committed V3 lock and its
source closure against checkout HEAD, `GITHUB_SHA`, and `GITHUB_WORKFLOW_SHA`.
Supply the independently reviewed lock SHA-256 as `packet_sha256`.

The `native-arm-kernel` concurrency group keeps the active run. A new pending
run replaces any earlier pending run in the group.
[GitHub Actions concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)

The runner and native job require:

- The hosted `ubuntu-24.04-arm` Linux ARM64 runner, Python 3.11 or newer, and
  executable Git, GPG, lscpu, zstd, Docker, and Python in `/usr/bin`. The job
  requires an ordinary nonzero UID and GID, with zero effective and permitted
  capabilities.
- Canonical `/usr/bin/docker` and a canonical, root-owned
  `/run/docker.sock`. The local daemon must be ARM64 Linux, rootful, use host
  UID mapping and cgroup v2, and advertise an API range covering 1.48. The
  initial container census must be empty. Existing images must be observed and
  recorded as protected.
- At least 15 GiB total memory, 14 GiB available memory, and 30 GiB initial free
  disk. The kernel stage requires at least 8 GiB free disk when it begins.
  The job has a 360-minute ceiling and a 346-minute native step.
- Access to the pinned input sources. The workflow can stage a private retained
  input subset through either existing transport. The chosen endpoint and
  credentials need separate operational verification.

Leave `retained_inputs` false for ordinary pinned acquisition. For retained
inputs, select exactly one configured transport:

| Inputs | Required Actions secret and source |
| --- | --- |
| `retained_inputs=true`, `retained_transport=https` | `KERNEL_NATIVE_RETAINED_INPUTS_URL` for the exact retained 22-file archive. |
| `retained_inputs=true`, `retained_transport=ssh` | `CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY` for the pinned refs and trees in the private `Gabriel-Kahen/cachy-asahi-ci-inputs` repository. |

Only the private intake step receives the selected secret. When enabled, intake
must succeed before the native job launches the producer and acquisition
children. The native job independently verifies retained bytes and the existing
signature checks still apply.

After the prerequisite and ref checks, dispatch with the selected settings.
For example, for an authorized SSH-retained run:

```sh
reviewed_ref='<reviewed branch or tag>'
reviewed_packet_sha256='<independently reviewed SHA-256>'
gh workflow run native-arm-kernel.yml \
  --repo Gabriel-Kahen/cachy-asahi \
  --ref "$reviewed_ref" \
  -f packet_sha256="$reviewed_packet_sha256" \
  -f retained_inputs=true -f retained_transport=ssh
```

Review the bounded public status against the exact source commit and packet
SHA-256. A successful run provides evidence for this hosted invocation. Physical
M2 installation, boot, recovery, and release qualification require separate
evidence. See the [kernel job guide](../../../docs/workstreams/kernel-native-job.md)
for the existing acquisition, signature, timing, and cleanup contracts.
