# First Login 0.1.0-4 and Setup 0.3.1-2 native build pair

This [manual workflow](../../../.github/workflows/native-arm-first-login-v4-native-pair.yml)
builds both successors twice on one hosted `ubuntu-24.04-arm` machine. It
checks AArch64 and 4,096-byte pages on the runner and in each build container.
Both lanes start from separate fresh containers of the same prepared image.

## Inputs and build

- The workflow checks out integrated recipe commit
  `289e009831f6d00a5401059aeb1199bd834c3ebf` separately from the workflow code.
  The controller checks both Git tree IDs, extracts the exact committed inputs,
  and records their SHA-256 hashes. The commit time is the common
  `SOURCE_DATE_EPOCH`.
- The base is the pinned ARM64 [Menci Arch Linux ARM image](https://github.com/Menci/docker-archlinuxarm/blob/a1f885ca8dee50004d46109260589b2ab4ec3760/.github/workflows/build.yaml).
  The runner verifies the architecture-specific OCI manifest reference and
  the expected image config ID. It fetches the four [Arch Linux ARM mirror](https://ca.us.mirror.archlinuxarm.org/aarch64/extra/)
  inputs in [supplement.sha256](supplement.sha256). The offline preparer verifies
  the hashes, requires Arch Linux ARM package signatures for Fish and Zsh,
  and checks the ordinary tools using `pacman -T`. Both builds verify the
  exact same resulting package inventory.
- Each lane uses normal `makepkg --check` and dependency checks. It builds
  Setup, verifies the archive's helper bytes against the pinned First Login
  fixture, then installs that exact unsigned archive as a build dependency
  inside its disposable container. A separate local-only pacman configuration
  permits that single unsigned input. It verifies the installed version, the
  installed bytes, and the resulting inventory before building First Login.
- Both builds run offline, with one CPU and 768 MiB per container. The
  verifier checks the 36 Setup and 20 First Login test results from each
  lane. It verifies paths, modes, ownership, dependencies, source and mtree
  digests, and the build inventory in the archives. Both Setup archives must
  be byte-identical, and both First Login archives must be byte-identical.

## Local source controls

Run from a checkout containing this workflow. Pass a separate exact checkout
of the pinned recipe commit as `PINNED_CHECKOUT`.

```bash
slice=scripts/ci/first-login-v4-native-pair
bash -n "$slice/hosted.sh"
bash -n "$slice/container.sh"
python3 -I -B "$slice/test_verify.py" -v
bash "$slice/hosted.sh" source "$PINNED_CHECKOUT" "$NEW_OUTPUT_DIRECTORY"
```

The manual dispatch requires the workflow file on the repository's default
branch. The job retains the two archive pairs, exact supplement, package
inventories, source hashes, logs, comparison receipt and cleanup result for
14 days. Build evidence requires a successful job and `pair.json` with
`native_build_pair = PASS`. See [GitHub workflow dispatch](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch).

Hosted native build, signed installation, graphical first login, and M2
validation are **NOT RUN** at source preparation. The unsigned Setup
transaction in a future build lane establishes build dependency satisfaction.
