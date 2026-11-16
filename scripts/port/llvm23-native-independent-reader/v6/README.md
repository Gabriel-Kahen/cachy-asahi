# Reader6: exact absent-image stdout compatibility

Source and synthetic DATA controls only. No operational Reader6, lease, GET or
actor has run. Source260, package/source inverses, memory/time/resource policy
and all old Readers are unchanged. Root's Reader5 r2 HOLD remains preserved.

The actual successful LLVM260 native run43760769287 retained a final exact
Docker image inspect after successful removal: returncode1, stdout `[]\n`,
and stderr exactly `Error response from daemon: No such image: ` followed by
the same whole image ID. Reader5 required empty stripped stdout and refused.
This is a finite CLI serialization difference, not missing cleanup evidence.

Reader6 derives reversibly from Reader5. Its new scope is
`ROOT_BOUND_LLVM23_INDEPENDENT_READER_V6`; its distinct successful DATA status is
`PASS_INDEPENDENT_LLVM23_ABSENT_IMAGE_STDOUT_SUCCESSOR_DATA_ONLY`.
`derivation.json` records both literal Reader edits. New pins differ from v5
only in the new base descriptor; storage.py and inverse-frame.json are copied
byte-identically. The new base whole-pins the old v5 base, reuses its pinned
passive dependency closure, and replaces exactly one expression in the cloned
v2 retirement function:

```python
read(evidence/row['stdout']).strip() in (b'', b'[]')
```

The whole function has an exact byte inverse. Returncode1, exact stderr/same
image ID, successful image removal before the last exact inspect, all raw
output pins, natural retirement and other owned resource absence guards stay
unchanged. Nonempty arrays, objects, malformed output and `[ ]` refuse. The
cloned replay must resolve to the new predicate both before and after the held
stage-command namespace installation. No old Source/actual tuple is projected
to another identity. Source260→256→253→251→248 and original200 guards remain.

For a separate actual call Root issues a NEW binding from binding.TEMPLATE.json
with new Reader selector and external SHA, pins this complete new code closure,
and supplies fresh resource/runtime/custody/storage grants. All actual selectors
in the committed template are NULL. The existing genuine Original, publication,
provider and native approval remain unchanged inputs. Use the same v5 CLI
arguments, with `v6/reader.py` as entry and a fresh private output. It still
requires Python3.14 stdlib compression.zstd, AS256MiB, internal1800s, full fresh
Original decode and20GiB storage floor. The unchanged Btrfs storage-profile
contract remains available. No memory cap change or automatic role retry occurs.

```sh
python3 -I -B -Werror::ResourceWarning scripts/port/llvm23-native-independent-reader/v6/test_v6.py
```

Eleven actor-fenced controls exercise complete synthetic retirement sequences,
both accepted encodings, wrong bytes/image/code/order, missing/failed removal,
forced/uncertain lifecycle, output pin drift, exact derivation and clone wiring.
They prove no actual Reader/package/native/M2/release acceptance.
