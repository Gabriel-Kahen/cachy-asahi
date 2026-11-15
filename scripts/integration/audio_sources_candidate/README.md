# Audio-source tool private-container candidate

The Root-reviewed [v2 successor contract](HOST-CONTRACT-v2.md) now has an
[actual host TEST-signed result](RESULT-20261114.md): unsigned refusal, signed
install, same-version reinstall, two installed genuine-packet verifications,
removal,139→140→140→139 inventory and owned cleanup pass. Twenty-five focused
controls also pass. `/scratch` remains noexec; the copied root executes only on
the separately declared `/alpm` tmpfs. This is host-x86 evidence with mask0x400cb,
not cap0/native/M2/release qualification. All original refusals remain below.

## Retained predecessor evidence (55aa3ae1)

The original finite host-x86_64 journey was source-implemented and invoked. That
invocation refused the protected-null mount contract **before TEST key
generation, copied-root construction or pacman execution**. Installation,
reinstallation, installed-tool verification and removal remained **NOT_RUN** at that checkpoint.
Sixteen ingress, guard, DATA and cleanup controls pass; they do not replace the
missing real transaction result.

## Exact operands and invocation

`profile.json` is pinned at SHA256
`a7a20c44cabd6ba05dac8096906c0c133310c1d914a099d4fcfb5aab4ed7ebf5`.
It selects only:

- Original opt-in `cachy-asahi-audio-sources 0.1.0-1`,82101 bytes, SHA256
  `9c5332015a0dca27469021fdfe7cda135ba2de62f7a60e1b969be03ab0ad6ec8`,
  from package commit `48099ebe0814990ab0d3d97d50e4e5203256da3f`, with its exact
  17-file installed payload map and original archive checker.
- Genuine five-package/117-crate source delivery index SHA256
  `78ff30f1d9dceaa568a4c2b92df0d2e054eb7166762fba18588fc2ac2a37fc63`.
- The already present immutable amd64 image
  `sha256:30cfe09952ef8d9bfabd64224185c97021b260d47bb83941fec5bae7bdd16145`,
  the [separately documented host test runtime](../../port/supported-composition/ci-runtime/README.md).
  This driver neither builds nor fetches an image or installs dependencies.
- Unchanged `lifecycle.py` SHA256
  `c3223a1bd4002683071f4442e1f5b9caf439c68c4e231da10039cc9cebcdb52b`
  and `repository.py` SHA256
  `fdfd3611ca8d3fab7584594ccaf627f42a9ae31898372925af1bcae173d55cd7`.

From a trusted checkout, as the ordinary user of the existing rootless daemon:

```sh
python3 -I -B scripts/integration/audio_sources_candidate/run.py \
  --archive /private/cachy-asahi-audio-sources-0.1.0-1-any.pkg.tar.zst \
  --packet /private/genuine-portable-source-packet \
  --output /private/new-candidate-records
```

The output parent must already exist. Output must be fresh, canonical and outside
the original packet. Alias/dot-dot operands refuse before creating output or any
actor. Inputs and original packet files are independently hashed before copying;
their bytes/modes remain unchanged. The private records retain the exact code and
input contract pins, bounded command output, real return codes and owned cleanup.
No operator acquisition receipts, cache locations or credentials are committed.
Generated operands/evidence stay private; this command publishes nothing.

## Bounded mechanism and intended installed journey

The actor is a separately labeled **host** candidate. It never calls, overrides,
aliases or rewrites the native ARM guard. The original modules/package/frozen
runtime remain byte-identical. It reuses the unchanged process-group deadline,
pipe-byte-limit and reap implementation; mount/capability/inventory/signature
validators; and copied-root capacity/hook-masking implementation.

The exact image/actual rootless x86 daemon are checked. Docker gets a read-only
overlay root, network-none, the original six-cap repository mask `0x400cb`, NNP,
default seccomp,128 PIDs,2GiB memory and two CPUs. Only copied `/inputs` and
`/runner` are mounted read-only and fresh private `/out` is writable; `/scratch`
and `/test-home` are bounded nodev/nosuid tmpfs. No producer checkout, host system
directory, Docker socket or hardware device is exposed. Actual UID/GID maps,
loopback-only interfaces, seccomp and capabilities are observed and checked.

Root's narrow host-only admission is limited to individual mounts at
`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom` and `/dev/tty`.
Each must be a nonsymlink character node with the expected major/minor, a
tmpfs/devtmpfs mount rooted at its exact canonical device leaf, and nonconflicting
access/security flags. Only these fully validated records are projected out;
every remaining mount faces the unchanged inherited validator. Arbitrary devices,
file substitutes, aliases, nonstandard sources and nested host mounts refuse.
Protected `/proc` null masks are **not** covered by this extension.

After all admission checks pass, the intended sequence is:

1. Copy the immutable image's `/usr`, `/etc` excluding gnupg, and local ALPM DB to
   `/scratch/system`, using the existing bounded-capacity copied-root mechanism.
   The owned adapter supplies an explicit x86_64 local-only signature-required
   pacman configuration. The original container root/default trust stay read-only.
2. Create an ephemeral one-day TEST-only Ed25519 key under `/test-home`; export
   only its public certificate into a separate private verifier home. No host,
   default or production keyring is changed. Verify rejection of the exact
   unsigned archive without an inventory change, then sign the unchanged archive
   with SHA256 and independently verify its full TEST fingerprint.
3. Perform actual `pacman -U --noscriptlet` installation into the copied root,
   check the exact inventory/ownership/17 payload hashes/modes and `-Qkk`/`-Dk`,
   then run that installed launcher against the genuine packet offline.
4. Reinstall the same signed archive, repeat installed checks and real packet
   verification, then perform actual `pacman -R --noscriptlet`. Require the
   original inventory and absence of every package-owned regular file while the
   caller packet/sentinel and original input packet remain byte/mode-identical.
5. Retire the private TEST agents/key homes and the exact labeled container;
   confirm its absence. An unacknowledged Docker create outcome stays UNKNOWN,
   even if one immediate census is empty. Cleanup failures cannot become success.

The private ALPM root must be executable before any copy/key/pacman step: neither
the installed launcher nor copied-root ldconfig may be routed around a `noexec`
restriction. The current Docker scratch mount is observed `noexec`, so this is an
additional unresolved resource prerequisite. This implementation does not change
that mount flag or invoke Python manually to hide the restriction.

## Actual retained result, November 14, 2026

The first real strict-container attempt refused its individual `/dev/zero` mount;
that refusal and its retired container remain recorded. After the explicitly
scoped six-device adapter, actual attempts still refuse:

`standard Docker runtime mount identity/options differ: /proc/timer_list`

Passive metadata records `/proc/interrupts`, `/proc/kcore`, `/proc/keys` and
`/proc/timer_list` as nonsymlink character1:3 nodes, each bound from `/null` on
devtmpfs with `rw,nosuid`. The original inherited mask contract requires its
specific tmpfs representation. No representation is normalized, removed or
accepted for these protected paths. The selected mount source/root bodies are
not exported; bounded public filesystem/flag/node identity categories suffice.

Observed facts include rootless `0→1000` UID/GID mapping, capability mask262347
in effective/permitted/bounding with zero inheritable/ambient, NNP1 and seccomp2
with one active filter. `/scratch` is a nodev/nosuid **noexec** tmpfs. The actual
actor emitted no guest command receipts and no key/copy/pacman step ran. Its
acknowledged container exited1 without OOM, was removed by exact label/name, and
the final label census is empty. Original packet preservation passes.

Resolve the protected-null representation and executable copied-root resource
admission before claiming any installed result. The positive transaction path is
source-reviewed and remains unexercised. Native ARM/16K, M2/audio/speaker safety,
compiler/original-binary correspondence, wmidi/nalgebra terms, legal/source
completeness, security/revocation, production trust and release remain held.

```sh
python3 -I -B -Werror::ResourceWarning \
  scripts/integration/audio_sources_candidate/test_candidate.py \
  --packet /private/genuine-portable-source-packet \
  --engine-observation /private/create-only-engine-contract-observation.json
```

The16 controls cover exact source/profile/payload pins, private-tree relocation
and mutation detection, the public `size` descriptor join, alias/overlap rejection
before actors, character-device identities and remaining mount refusals, unchanged
caps/NNP, noexec refusal, initial admission preventing all mutation, cleanup
failure/collision/uncertain-create cases, and zero-exit ancillary pacman errors.
Synthetic DATA/callback controls are explicitly separate from the actual refused
container invocation; no passing installation result is synthesized.
