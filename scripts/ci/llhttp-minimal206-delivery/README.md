# Authenticated minimal206 llhttp delivery

This build-only route starts with the exact 96-file command512 Source at
`1f0a2a18600b5aea4c837974f91e3ba2451f18a9`. It verifies its complete
historical inverse and binds Root's exact r2 authentication adoption
and 207-signature transcript. The hosted and inner admission checks
require that adoption's exact canonical hash. Seven Source leaves change,
including the enclosing maps. The original build entry, controller,
two 512-command caps, package inventory, cleanup and evidence exporter
remain byte-identical.

The local preparation generates a parentless Git commit with the original
author identity and timestamp. It compares the staged Git tree and all 96
checkout body and mode pins. The proposed fixed destination is
`refs/heads/codex/llhttp-minimal206-authenticated-source-20261117-r1`.
The tracked workflow is byte-identical to the Source workflow. It skips
all refs except the designated Source branch and requires the exact
workflow identity, pair job and first run attempt at admission.

## Local preparation and tests

Run from this code checkout with the actual command512 construction and
the two verified r2 Root files.

```sh
parent=/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-minimal-builder-command512-readiness-20261117-r2/constructed-source
auth_dir=/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-minimal206-public-input-authentication-r2
adoption="$auth_dir/Root-authentication.ACTUAL.json"
transcript="$auth_dir/signatures.DATA.json"

/usr/bin/python3 -I -B scripts/ci/llhttp-minimal206-delivery/delivery.py prepare \
  --parent "$parent" --adoption "$adoption" --transcript "$transcript" \
  --output /absolute/fresh/local-publication-repository

/usr/bin/python3 -I -B -Werror::ResourceWarning scripts/ci/llhttp-minimal206-delivery/test_data.py \
  --parent "$parent" --adoption "$adoption" --transcript "$transcript"
```

The actual local Source has commit `7a55473d017e5c95c86088027ecb44df06ad2cf9`,
tree `0ce20196636943c4fb9d30b5d2907dcbcf6f2bf8`, 96 leaves and 1,630,219
Source bytes. Its 20,332-byte map SHA-256 is
`1524a79087d38204ce90935da70e0526610c108d5bd351ca57321b0bf9ba3d8b`.
Its 3,818-byte workflow SHA-256 is
`16f583f6e2add0be80975afa2f4695ee599cd4e9094dfe2114e78e76470afa7f`.

## Canonical dispatch inputs

Root publishes exactly that commit and independently checks the actual
public ref, public Git blobs, tree and complete clone. Register the tracked
workflow body on Main through ordinary review, and obtain a fresh Root
registration and Source ref readback before using the five-input
canonical guard. These are separate from Root's r2 adoption, which only
authenticates the public build inputs.

The publication document contains the output fields from `prepare`
excluding `status` and `publication`, plus
`kind = ROOT_LLHTTP_MINIMAL206_SOURCE_PUBLICATION_V1`, `issuer = Root`,
`public_clone_complete = true` and `public_blob_tree_join = true`.
Its `Root_native_authority` remains null.

The registration document has `kind = ROOT_LLHTTP_MINIMAL206_WORKFLOW_REGISTRATION_V1`,
`issuer = Root`, `repository = Gabriel-Kahen/cachy-asahi`, `state = active`,
a positive integer `workflow_id`, `workflow_path`, and the whole `workflow`
body pin from `prepare`. It has `registered_on_default_branch = true`,
the actual Main `registration_commit`, the actual `public_ref` and
`public_source` from fresh readback, integer UTC seconds in `observed_utc`,
and `Root_native_authority = null`. Read back registration before
the ten-minute freshness window closes.

Root separately issues the admission and runtime documents from the Source
templates. They join the actual Source/ref/map, exact scope and resources,
same nonce and exact authentication adoption under
`builder_input_authentication`. The runtime pins the actual source
owner program as `external_supervision` and policy as
`bootstrap_resource_domain`, and copies the reviewed `host_tools` policy.
Pass the four whole Root document SHA-256 pins to the local guard.

```sh
umask 077
/usr/bin/python3 -I -B scripts/ci/llhttp-minimal206-delivery/delivery.py canonical \
  --parent "$parent" --adoption "$adoption" --transcript "$transcript" \
  --checkout /absolute/independent-public-readback \
  --publication /absolute/Root-publication.ACTUAL.json --publication-sha256 "$publication_sha256" \
  --registration /absolute/Root-registration.ACTUAL.json --registration-sha256 "$registration_sha256" \
  --admission /absolute/Root-admission.ACTUAL.json --admission-sha256 "$admission_sha256" \
  --runtime /absolute/Root-runtime.ACTUAL.json --runtime-sha256 "$runtime_sha256" \
  > /absolute/dispatch-plan.json
```

The guard checks genuine operands offline and emits the workflow ID/path
and its exact ref/five-input JSON body for the Root operator. It does not
send a POST or acquire a lease. Only MODEL admission and registration
records were used to test it.

The hosted audit seeds the original 206 embedded package signatures and
fetches cold public inputs via the pinned HTTPS routes, including around
1.455 GB of rootfs and package bytes. The hosted run still needs reachable
servers that serve the pinned bytes, the existing-host tools and resource
domains, and complete re-verification of all 207 signatures before the two
offline builds. Publication, Main registration, hosted input reachability,
native execution and M2 compatibility are unverified.
