# Updater ELF leaf observation review

BLOCKED against owner hold `7fbdb177d21ed73515e853c5210a942bc4c79415629b5c65ef93fa5efeb0e951`: one narrow observation regression replaces the original refusal when reading an exception tag raises an ordinary reporting error. Acceptance remains refused. This is a source/model finding, not a native8 cause. The held sources were not edited by this reviewer.

In `worker-build.py` line 133, `getattr(error, 'updater_elf_predicate', 'UNKNOWN')` occurs before the guard around `diagnostic.fail()`. A controlled ValueError subclass whose tag property raises RuntimeError causes the actual captured compile-elf handler to raise the getter RuntimeError; the original ELF exception object is lost as the raised failure and no diagnostic.fail call occurs. The exact same original object is tested in the reproducer. A class-level unregistered plain string correctly remains UNKNOWN and rethrows the original. Neither case promotes success or exports an arbitrary tag.

Root selected the bounded repair: issue a leaf only from an exact built-in ValueError, an exact plain instance dict, and an exact str in the fixed enum. Subclass, class/property, unissued or unexpected attributes must fall back UNKNOWN without calling a descriptor. All ten actual refusal sites create exact ValueError instances. This protects source-issued observation and original failure preservation without suppressing control exceptions from arbitrary getters. The author owns the worker-build/test correction; source re-review must use its new held bytes.

Independent verification completed:

- All eleven source/guide rows and 111 evidence records of the owner hold match hashes, sizes and their declared modes. The eleven source/guide rows are 0644. An independent captured source tree has no foreign PYC.
- Fresh four-module suite: **157 PASS, zero failures/errors/skips**, 1.892 seconds, ResourceWarnings treated as errors. Forty-five existing harmless Python fixture children ran; no nonfixture actor event occurred. No escalation or IPC EPERM failure was encountered.
- All 147 prior test-method bodies match their retained baseline AST, including all 24 gate methods and therefore the original nineteen. They were executed in the fresh suite; mocked positive compile flows are not native compilation.
- Source AST comparison independently restores only fixed reporting mechanics, pin/enum changes and the compile-elf wrapper. It matches every original business condition/message/refusal and all other operations. Diagnostic/public field sets, schema, 4096-byte limit, first failure/write-failed behavior and compile/acceptance distinction are unchanged.
- Ten old/held causal refusal pairs execute the actual functions on synthetic data/private files: six ELF header/machine/program-header/LOAD alignment/bounds/absence sites and four regular-read symlink/type-link-size/read-bound/drift sites. Old and held both refuse with the same private message; only held attaches its fixed tag. Tiny valid static bytes retain the same decision. These checks qualify observations, not completeness of the preexisting ELF parser or runtime-loader/16K/hardware behavior.

The changed compile scope alone opts the first read into ELF observation. Unrelated regular reads remain untagged. Unknown/non-string/nonleaf values fall back UNKNOWN in existing tests; the new getter counterexample is the uncovered ordinary extraction fault. Ordinary diagnostic.fail errors and sticky first/write failure controls pass. Cancellation behavior and later copy/receipt/acceptance gates were not changed. No arbitrary text/path/header/binary field is added to publication.

Exact held package files:

| File | SHA256 | Bytes |
| --- | --- | --- |
| `build-gate.py` | `312772f143602ec58d08e5eebac3f64edb8723bccd5836c1f53cf832f7c27861` | 16791 |
| `build-policy.json` | `2d47d7db696a76b26772866510a5739207f97f08d1a2d1dcdc1a41729492d56e` | 1956 |
| `public-evidence.py` | `e707a2c9ac652b5f7e7c49a6b36b9c11b9baae821564677bbca867529fae3330` | 64340 |
| `test-gate.py` | `047037520f11a59fe55667789ecccdaec8c40c442e9e069a99bebf0c4ac44614` | 21848 |
| `test-public-evidence.py` | `4abfca35140aa9de85cccfdd90a6cc4f348f1d5df522f16b71ac717c77300b8a` | 53463 |
| `test-worker-build.py` | `7a128f1c688ea9b4b721640270f62cacfdfebf82a1063c13607c0f2815006981` | 19467 |
| `test-worker.py` | `2d3dfd1b9c3bc42d0edc32188aca57ef13dcc71968bc2103a46801031980ef42` | 54470 |
| `worker-build.py` | `1d75b0abcb0382abe6998ca20b46f845b24665d50c5dbd8de2de81203ab4ee20` | 10576 |
| `worker-diagnostic.py` | `69e4ba40e882cd62fa1aee8cf4bc7ce788eb8230ce19ca83e95682b9254d668a` | 23894 |
| `worker-metadata.py` | `76ecbd345f571366ee9e11df8df96bbc6f9be5500b626920b5eaa203ab155572` | 30702 |

Guide SHA `125db2c62c5d2d028ea16fc1fe7d0627d20537fffba5296a98433d700aeb4971`, 4381 bytes, 0644. Observer `76ecbd345f571366ee9e11df8df96bbc6f9be5500b626920b5eaa203ab155572` matches both the held gate MODULE_PINS and build-policy row. Recipe/.SRCINFO/input/ready/stage/workflow rebind remains root-owned and pending; no current86-ready/native claim is made.

Native8 remains immutable actual FAIL with observed compiler return0 and ELF UNKNOWN. Its private historical leaf cannot be reconstructed from these new tags, and no cause is guessed. Compiler/build/native/Docker/GPG/mount/services/network actors were not run here. No source/shared maps/Git/workflow files were edited. Licensing/publication exclusions and broader installer/native/M2/whole-port gates remain separate.

Proofs: `verified/proof.json` SHA `ba19c9edaf96e8ad17baa614beb41e56cdff99b9c6e874185ae622904d0609f8`; `preservation.json` SHA `a6ebd612a24d9848cbc29a94271ce8693948d577fd164bc412b7315429b1a01b`; `leaf-pairs.json` SHA `0f027328455b40a83d1b15c6b3d1b375b3cac7ad934cf895e935dc006333ab38`. All are under `artifacts/reviews/updater-elf-leaf-observation-root-peer-20261012/`. Historical proof is retained unchanged for the focused correction recheck.
