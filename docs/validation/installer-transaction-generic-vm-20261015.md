# Signed installer fixture transaction in a generic ARM VM

[Run38817754164](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38817754164), attempt1, completed with the bounded public result `PASS_TRANSACTION_ONLY`. Root retained the logs once. Offline review matched the public owner result, six guest events and outer integration/lifecycle metadata. This is a generic aarch64/4096-page QEMU TCG fixture result; native-container P0 remains separate and its earlier failure is not upgraded.

| Selected unchanged test | Retained closed outcome |
| --- | --- |
| Signed tiny dependency pair | worker0, phase `complete`, commit started/committed, `PASS-disposable-payload-transaction` |
| Invalid signature | worker1, phase `isolated`, no commit, expected refusal assertions pass |
| Missing dependency | worker1, phase `prepare`, no commit, expected refusal assertions pass |

The real TestSuite reports tests3/failures0/errors0/skips0, UID/GID23001, first_failure null, cancelled false and class_cleanups_returned true. The positive creates two fresh TEST-signed inert `caa-install-fixture-*` packages, with A depending on B>=1.0, and exercises the existing GPG verification, signed ALPM load/prepare/commit/reopen and parent export checks. Its unchanged assertions require exact payload bytes, package inventory/ownership, exported installed lock and no committed payload in the parent system root. The negative assertions require refusal without commit or installed-lock authority. Selected Source additionally requires that invalid-signature refusal reached the original GPG `--verify`, rather than an earlier import/keyring failure.

These signature, payload and detailed negative-path statements are guarantees enforced by the exact selected test/worker/guest Source. The public projection exposes their fixed outcomes, not the original private package, authentication or result bodies. This review did not decode package/source/binary frames or rerun GPG/ALPM, and does not independently reverify package signatures.

## Source and execution binding

- Source `b4e7122151daaf37fa8e4ef194db80a54ade4cf1`; workflow `b59f0934b6819c889b1858bf3b82d8d6bb7c3431` from Root's frozen selection.
- Worker SHA256 `757841a9af84cd2fe84c292711c93745f5985738c4186d219c34783891319ba8`; maintained tests `1987ed23821da917215e9e3366545810d565ece08406fafd429a8c3c772eb2cd`; runtime `8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821`.
- Fixed136-file tool profile `b7fbd65e357e132949432fb00e765a05e3c76ea29a41d1df93413870d9fd1ed8`, including libalpm16.0.1 SHA256 `94c013b9026772ffe4f227f508a2cdf0c61323dc1f7b7836fe629b49bfbc3902`.
- Proof SHA256 `ad640124cc1987f3d66db76eb7976595faefb435625361a0bc5607ab263cd3b1`; nonce `aa9a2799833d966897767e7346849df1` matches owner, boot, result and natural child-exit event.
- Guest boot directly reports aarch64, kernel `7.2.10-1-aarch64-ARCH`,4096-byte pages. The Source-bound path uses the selected launcher closure, drops all five parent capability sets and sets NNP1, then verifies the actual state and Root-protected Source/profile/library/tool bytes before signing or CDLL. Cap values and individual tool rehash records are not separately exported in this run's public record.

The reviewed worker retains source memfds, user/mount/PID/network isolation, inner capabilities/NNP/seccomp/mount guards and the real ALPM engine; no fake native grant or direct engine entry was used. This source-bound result does not independently attest VM origin or transfer a grant to another runtime.

## Completion and cleanup

The result is followed by the matching ordinary child natural exit0. Owner/guest records match the preparation, image and Source references; QEMU owned-group retirement is declared PASS with uncertainty false. Natural QEMU exit0 and final UART EOF/duplicate/partial checks are selected-Source PASS preconditions; no separate raw QEMU exit field is exported.

Scoped outer records report absence of the four named virtual containers and private tooling image, private workspace cleanup PASS and removal/absence of the outer lifecycle-installed image. Integration reports PASS and cancelled false. Class cleanup returning does not separately prove individual GPG-agent absence. No daemon-wide absence or parent-layer erasure is claimed.

The upstream handoff remains bound to the166-check package lifecycle and361-check sanitized commit receipt:345 installed packages extended to the366-package guest inventory. It includes fish0.1.0-1, zsh0.1.0-1, Hyprland settings0.1.0-2 and setup0.1.0-3. Production trust and release selection remain NOT RUN/false.

Reported owner duration229.23s, preparation60.585s and VM158.06s are observations, not performance measurements. Declared transaction child900s/unit950s/completion900s remain bounded by the original whole-VM1200s endpoint. Per-method duration is not exported; this three-test result does not establish that a larger fixture set fits those limits.

## Retained evidence and limits

Root's logs ZIP is4,419,412 bytes, SHA256 `d1486118bf1085c14d6281dc412334bbbd64e8f7939c006bd799b08fbbc03d27`. The [retained readout](../../artifacts/development/installer-transaction-virtual-run38817754164/review/readout.json) contains result joins and hashes; its review directory also contains decoded selected public metadata, frame/member indexes and the finite offline join scripts. The five selected compressed public metadata frames match their advertised bytes/hashes and their aggregate/native-log copies. Excluded frame headers match between copies, but their payloads were not decoded or reattested. Workflow success/publication and workflow OID are Root observations; this review made no API or Git query.

This establishes the three selected signed inert fixture outcomes under the generic VM boundary. It does not establish the remaining transaction methods, full installer/recovery matrix, production installation/signing trust, native-container P0, graphical session, ABI compatibility, performance, Asahi integration, M2 hardware or16K-page support.
