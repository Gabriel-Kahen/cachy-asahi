# Repository runtime source publication custody review

PASS for the exact 21 proposed publication rows: all 16 repository-native-handoff files and five collector/phase changes. This is a finite byte/mode custody review, not a fresh semantic review of every existing module, execution grant, Git publication or native acceptance. No missing or mismatched required row remains.

The runtime directory contains seven production modules, **seven** tests, one README and one production map. The initial description of six tests was a count typo. The production map intentionally covers seven runtime modules; it does not authenticate the tests by itself. The matrix below authenticates every publication file through separate retained source records.

Current `test_launch.py` (`8d897acaa2ecb4b9aa06d62a2467198c6713725d38d3702a6978cdf628f15aff`, 18357 bytes, 0644) matches the original owner hold, phase02 capture/peer, deadline correction/peer and final loader capture. It is absent from the historical 243-row execution graph. This closes publication custody for that file without claiming it was in that graph.

Custody lineage:

- Original implementation checkpoint `2e42f087…`: 15 referenced artifact rows verified; owner provenance/test sources retained.
- Phase02 checkpoint `7e3d4d57…` and peer receipt `873b98ef…`: 12 artifact rows verified, exact nineteen-file capture and subsequent per-file lineage checked.
- Deadline correction checkpoint `7051b51c…` and peer `bd83e7d4…`: 17 artifact rows verified, corrected supervisor and test rows match.
- Final loader checkpoint `1e170f6a…`: all 69 artifact rows, three owned source rows and six unchanged runtime rows verified (78 records); its full 35-file capture also matches retained bytes/sizes/modes. Historical 143 handoff tests and 58 independent loader controls are authenticated through the retained records, **not rerun**.

Entry `1cd5f074…`, test_entry `383e7b1b…` and README `c29fce6e…` come from the final loader hold. The other six production modules match its explicit unchanged-runtime rows. `test_provenance.py` (`01bce133…`) is not in that final 35-file loader capture; its current bytes/mode are instead bound to the original owner checkpoint/source and the phase02/deadline peer copies. Its original 24-test provenance record remains historical.

All current publication files are regular, single-link, 0644; bounded no-follow reads checked stable metadata and inode before/after reading. An isolated owned byte capture was retained without project imports, loaders or foreign PYC. Source hashes below are abbreviated for readability; the sealed proof contains full hashes, sizes, mode and exact witness selectors.

| Publication path | SHA256 prefix | Custody |
| --- | --- | --- |
| `scripts/port/repository-native-handoff/README.md` | `c29fce6ea695faa2` | final loader capture |
| `scripts/port/repository-native-handoff/broker.py` | `c19056f60caa46a5` | final loader capture |
| `scripts/port/repository-native-handoff/capture.py` | `60ae2434ecb6e327` | final loader capture |
| `scripts/port/repository-native-handoff/entry.py` | `1cd5f0749fdd347b` | final loader capture |
| `scripts/port/repository-native-handoff/launch.py` | `0e0b40b748091fdd` | final loader capture |
| `scripts/port/repository-native-handoff/producer.py` | `35ac09f5aef9afb8` | final loader capture |
| `scripts/port/repository-native-handoff/source-map.json` | `c0b52067ec44339a` | loader proposal + root canonical adoption |
| `scripts/port/repository-native-handoff/supervisor.py` | `06701d2f2e78ee33` | final loader capture |
| `scripts/port/repository-native-handoff/test_broker.py` | `52bed5a84e77432f` | final loader capture |
| `scripts/port/repository-native-handoff/test_capture.py` | `f662aed09e648cb7` | final loader capture |
| `scripts/port/repository-native-handoff/test_entry.py` | `383e7b1b4eca9a7a` | final loader capture |
| `scripts/port/repository-native-handoff/test_launch.py` | `8d897acaa2ecb4b9` | final loader capture |
| `scripts/port/repository-native-handoff/test_producer.py` | `4b7a7a16df15fa75` | final loader capture |
| `scripts/port/repository-native-handoff/test_supervisor.py` | `f0b08e021e8d4e9c` | final loader capture |
| `scripts/port/repository-native-handoff/test_transport.py` | `98866257514f5ae0` | final loader capture |
| `scripts/port/repository-native-handoff/transport.py` | `27772ed057e29f79` | final loader capture |
| `scripts/port/repository-client-native/provenance.py` | `42d18ff6cfa68d7d` | frozen collector/phase capture |
| `scripts/port/repository-client-native/source-map.json` | `26eeddc56574c547` | frozen collector/phase capture |
| `scripts/port/repository-client-native/test_provenance.py` | `01bce13357ec283d` | original owner + phase02/deadline peers |
| `scripts/port/repository-client-phase-stage/dependencies.py` | `d21ba92d4993233c` | frozen collector/phase capture |
| `scripts/port/repository-client-phase-stage/source-map.json` | `5718ca6cda60d7f6` | frozen collector/phase capture |

The runtime map is canonical SHA `c0b52067ec44339aae55a3b8f0a213d48ab4eaa2b410d0243c5267c9656f1f1e`: its only change from the historical root map is entry.py. It matches the owner proposed map, peer controls and root loader adoption. The collector map `26eeddc56574c5475df67841c1ac8120900deabe1478f6d1fa7cd290f64f63a9` binds seven actual source files; phase map `5718ca6cda60d7f6c02952cba7e92ff46666e20f8252ce7c1cdf722825ec2e43` binds five. All declared source bytes/modes match, canonical bytes regenerate exactly, and phase dependencies d21ba92d declare the exact collector pin/rows and four unchanged pinned predecessors. Root source-adoption metadata matches these identities. This is metadata registration/source closure, not actor permission.

The four contextual composition rows independently match the previously approved graph peer: repository_handoff `ed8180f0…`, its test `6aaec1d8…`, repository_authority `80264c33…`, and its test `da22bbd9…`. They are recorded separately from the 21-row runtime/collector/phase custody matrix. Peer receipt `23fff93f…` remains a historical 243-source snapshot. Other current primary KSM bytes have moved; this review does not claim that whole snapshot is the current source packet.

Root retains Git/source-map/workflow integration. Actual controllers, native/Docker/GPG/network/installation actors, independent live external authority and the future original-only 160-source/Zsh view have not been admitted or run by this review. Source/publication custody does not reconstruct missing historical raw argv/CID/checkpoints or establish native, hardware, cleanup, build, performance or whole-port acceptance. No source/shared maps/Git/workflow files were edited.

Evidence: `artifacts/reviews/repository-runtime-source-publication-peer-20261012/verified02/proof.json`, SHA `0ca8d2e8d7c681dc271a6805c9403c476e8207abcf094a10b5c2a6bbd2ed51ff`. The reproducible read-only audit and isolated source capture are in the same owned review directory.
