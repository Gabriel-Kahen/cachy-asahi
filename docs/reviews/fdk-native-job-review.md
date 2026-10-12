# Independent FDK hosted-wrapper source review

The frozen wrapper is **source/fixture ready for the coordinator's separate hosted workflow integration**. No concrete blocker was found in this bounded review. Workflow source was still being authored and is not accepted by this review. Actual Git publication/prerequisite closure, hosted acquisition/GPG/Docker operation, original native producer, native FDK build pair, installation, provider substitution, codec publication, M2/Asahi/16K hardware and performance are **NOT RUN** here.

Read the current roadmap, package inventory and `docs/workstreams/fdk-native-job.md`. All five port requirements remain mandatory and incomplete; the candidate library and this finite job are intermediate preparation. This review edits only this document, with no source, lock, shared manifest, workflow or Git mutation.

## Frozen bytes and independent tests

The actual packet SHA-256 is `2e190f75594fe5550770aa567b7729637853a99d6c2ce3b137248ed3954cbe32`. Independently validated its complete **128-file, 1,934,570-byte** set against actual checkout bytes and modes. The accepted adapter lock remains `a7048064c0c20abd246a466035313abaf65590f3ed10d0f7927b21a346200ad6`: all 39 adapter pins are unchanged. All 71 original recipe hashes match `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`. Inputs remain `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`; unchanged producer source remains `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`.

| New code under `scripts/port/fdk-native-job/` | SHA-256 |
| --- | --- |
| `job.py` | `3e4b684c2fbeaa2594f9880427b86d60ee7c9d72885616c8c62f66e82c3eda64` |
| `packet.py` | `2c37ba658ded0ff4c08e48d61120f3e977d1217b48d3a9cde5d3d496542ed09e` |
| `producer.py` | `283ae76fd57d698e248c15fb723f820a7979094adcd41bf3d096958e1bec62b2` |
| `base_broker.py` | `64c6fefc67c92e945d90e7b32794f0f798dd5239c17750760b12adbf5c9c877a` |
| `job_runtime.py` | `99077fde24d060a3b73649f0d45803ec2d155ebc41e21d0de54be635c24cf631` |
| `evidence.py` | `dc62d5e99532b5372ac1819208e5cc2f995f278c7ba4ae5c9daeb57fbac59524` |
| `test_job.py` | `cdc2f86fb07b857a4f86bb671ea51133be5626b156a7cbc3f1bf4f46a591c679` |
| `test_packet.py` | `ec7cc9f32daded6180051dc07d57e3205089091bb34c35a2ee9b11c8028e2c46` |
| `test_producer.py` | `fe55ec01b46a29fee731e859dc253795cdf31629d8b95e9cd286011a705163c0` |
| `test_base_broker.py` | `0f7de1db5d0b6e45e8e5eda5b0e6699e97d666705ad1d5d083b8a772c11a58d9` |
| `test_runtime.py` | `1872c5e662bcd8e93c57d09a963d17ead7c6aff26c73065409a0e595908acacc` |
| `test_evidence.py` | `df2e5ddfa73a925cebc9c06fcf391acf26e761e6b8490057bf2469f302c1f42a` |

Independently ran `python -B -m unittest discover -s scripts/port/fdk-native-job -p 'test_*.py'`: **90 PASS, zero skips**, 16.741 seconds. Escalation permitted only the owned temporary Unix-socket/HTTP fixture and local child-process regressions; no real Docker, native build, network, installation, signing-key import or host trust mutation occurred.

Additional bounded checks in `/tmp/fdk-native-job-independent-review.py --broker` all passed:

- Copied the actual complete 128-file source closure into an external temporary directory and exercised its second byte/mode verification with synthetic Git responses. This is actual local copy verification, not proof that the packet is committed.
- Injected secret response/exception strings into raw acquisition records; the finite publisher excluded them and existing private fixture secrets. Cancellation downgraded native acceptance and retained only the allowed structured files.
- Replaced a zero-exit FDK child PASS with a structurally valid receipt reporting `owned_container_absence=False`. The wrapper rejected all public acceptance while preserving original producer result bytes.
- Changed the fake daemon identity after the owned image build; cleanup returned FAIL and did not remove the image.
- Replaced the fake Docker CLI with identical bytes in a new inode; cleanup returned FAIL and did not remove the image.

The latter two use a local fake executable and owned temporary Unix HTTP socket, with no Docker daemon.

## Source and execution binding

The packet derives the full 116-file predecessor closure plus all 12 new source/test files, excludes only its own lock and Python caches, and applies finite path/count/size bounds. It rejects unsafe paths, links, hardlinks, special files, missing/extra entries and unsupported modes. Each copied source byte/mode must match its reviewed map and exact Git blob/mode, followed by a second original/copy comparison. The wrapper also checks HEAD against the hosted commit. These guards require the coordinator to commit the whole packet; this review deliberately makes no assertion about actual Git publication.

The producer executes from the verified external snapshot. Canonical setup source and root license are included for the unchanged synchronization gate. The accepted FDK stage executes from the original checkout to preserve its own source-location and Git requirements. No synthetic Git repository or relaxed adapter source gate is introduced. The unchanged producer helper receives the original input/recipe pins and epoch `1791748800`; the new wrapper adapts only reviewed command boundaries.

The host guard requires Linux ARM, matching positive real/effective UID/GID, zero effective/permitted capabilities, hosted ARM/Linux identity, current commit and the disk reserve. Environments discard inherited Docker contexts/auth/plugins. Every broker operation checks the accepted executable bytes/inode, canonical Unix socket identity and live daemon identity before and after execution. The fixed bounded HTTP daemon query avoids CLI plugin discovery. Image/root user, labels, resources and expected mounts are independently checked.

Legacy image creation adds reviewed nonce/context/Dockerfile labels, force-removal request and finite memory/CPU flags while preserving the original helper and Dockerfile. `DOCKER_BUILDKIT=0` is explicit; unsupported legacy flags must fail rather than switch execution paths. Actual argv is retained separately in the durable reservation. GPG routes only finite original public import/verification forms through a private key home with explicit `--no-autostart`; separate bounded streams preserve original status parsing. Actual hosted GPG behavior remains pending.

## Authority, disposal and publication

Image reservation is persisted before the build attempt. Parent cleanup reloads the image and both producer/FDK container journals; it checks nonce/context/image/daemon/socket/CLI/user binding and disposes only verified owned resources, containers before image. An unresolved attempted build with no recovered image ID remains uncertain FAIL. Recovered IDs are persisted before removal, and both ID/global listings and nonce listings confirm absence. No global pruning or force-removal of unrelated images is used.

The job has finite work/producer/FDK budgets. The larger worker permits the pinned rootfs/context file sizes and has process-group cleanup, parent-death signal, subreaping, address/file/descriptor/CPU limits and bounded combined output. Final cleanup uses a shared 180-second deadline; descendant journal cleanup and cancellation retries are clamped to that deadline. Tests exercise real TERM-resistant local descendants and cancellation during image/container queries and removals. Unlabelled legacy intermediate cache and abrupt host/daemon failure are outside the attested owned-resource scope; complete daemon cleanliness is not claimed.

The wrapper accepts the complete unchanged original producer evidence before invoking FDK on that same live image/bootstrap/inventory. It preserves the exact original result bytes and does not add FDK's BUILDINFO comparison criterion to the four original package acceptance rules. Original package hashes and audited metadata/provenance receipts are rechecked; the unchanged authenticated producer remains responsible for executing the original package parser and comparator. The accepted FDK receiver independently reparses its own artifacts and requires all four FDK comparisons.

Public export follows cleanup and uses only the new `public/` directory. The producer allowlist comprises six finite structured files; FDK publication is status-only. Cache, context, key home, raw logs/exception bodies, archives and both original/codec binaries remain private. Complete source/producer/FDK evidence, no cancellation and confirmed image absence are required for job PASS. Malformed child PASS, stale producer PASS, cancellation during publication or failed late rewrite are downgraded or retired. Failure receipts retain explicit hardware/installation/binary-publication `NOT RUN` scope.

The coordinator must separately review the stable hosted workflow, commit/check the frozen packet, provide compatible host prerequisites and allow the cleanup/publication margin beyond the chosen work deadline. The default 7200-second work budget requires at least the documented 126-minute hosted timeout. Only an actual successfully completed hosted job and inspected authoritative receipts can establish native producer/FDK acceptance.
