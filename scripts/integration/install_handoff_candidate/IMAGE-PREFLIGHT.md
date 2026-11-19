# Host-x86 install-handoff image preflight

Use this read-only companion before obtaining short-lived TEST fixtures for an
install-handoff controller. It checks that the operator-selected rootless Linux
x86_64 daemon can identify the exact image under review. Use the receipt as an
input to the separate controller review. It grants no signing or container
authority.

The rebuild plan reuses the [composition builder](../../port/supported-composition/ci-runtime/README.md).
Supply its retained offline context containing `inputs.lock` and the exact five
input files. The preflight checks whole lengths and digests and joins both
detached signatures to the pinned core database. The Dockerfile uses only that
local repository during its RUN transaction and requires the pinned base
image's package signature policy. The two additional packages produce the same
139-package inventory as the accepted x86 lifecycle. The controller still
checks that inventory at runtime.

From the repository root, provide a selected local Docker context name
`docker_context`, the ordinary selected OCI SHA-256 blobs directory `blobs`,
the retained composition context `build_context`, and a fresh private evidence
directory `evidence`. Capture only Docker metadata. Use the OCI blobs from the
same selected daemon or a separately verified retained OCI copy.

```bash
preflight=scripts/integration/install_handoff_candidate/image_preflight.py
base=sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae
docker --context "$docker_context" context inspect "$docker_context" > "$evidence/context.json"
docker --context "$docker_context" info --format '{{json .}}' > "$evidence/daemon.json"
docker --context "$docker_context" image inspect "$base" > "$evidence/base.json"
metadata=(--blobs "$blobs" --context-inspect "$evidence/context.json" --daemon-info "$evidence/daemon.json")
python3 -I -B "$preflight" rebuild-plan "${metadata[@]}" --context "$build_context" \
  --image-inspect "$evidence/base.json" > "$evidence/rebuild-plan.json"
```

The plan emits the exact builder argv, with the network disabled for RUN and
the pinned base already present. An independently authorized operator may add a
fresh `--tag` and an `--iidfile` before the final context argument to retain the
build identity. A rebuild has a new immutable ID because OCI build metadata may
change. Keep the actual build record and use that ID from the selected daemon
after a successful build. Capture fresh context, daemon and image metadata
again before the controller review.

```bash
docker --context "$docker_context" image inspect "$image_id" > "$evidence/image.json"
python3 -I -B "$preflight" image-check "${metadata[@]}" --image-id "$image_id" \
  --image-inspect "$evidence/image.json" > "$evidence/image-check.json"
```

The image check selects exactly one Linux amd64 OCI execution manifest, rejoins
the selected daemon's image and rootfs digests, and verifies each compressed
layer and its uncompressed digest. It derives the package inventory from the
actual ALPM entries and compares it with the image's package manifest and the
historically accepted whole lock. The scope is the rootless host-x86 TEST
controller. ARM, Apple hardware and release acceptance remain separate.
