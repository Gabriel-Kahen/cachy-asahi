# LLVM23 initializer capability spelling Source correction — 2026-11-15

Root identified a second hosted guard mismatch before publishing or entering the unpublished253 LLVM23 Source. Docker28 reports a CHOWN-only initializer's raw `HostConfig.CapAdd` as `['CAP_CHOWN']`; the existing LLVM guard accepts only `['CHOWN']`. The new `successor_v4` constructor changes exactly that comparison to `h['CapAdd']in(['CHOWN'],['CAP_CHOWN'])`. It does not normalize arbitrary names, remove duplicates, or accept additional capabilities.

The original5c6f5f31 constructor, published251 Source and completed private253 export/once proposal are preserved. New256 DATA is rendered and checked in memory; a corrected physical export has **not** been created. No253 actor has run or been published by this work. No GET, lease, Docker/actor execution or Reader occurred.

| DATA packet | Files | Bytes | Map SHA256 | Git tree calculated from DATA |
| --- | ---: | ---: | --- | --- |
| Unpublished253 parent |253|40,862,047|`5c19a2699856e081712d159c551ce496919938bd456f2182c0c905f03cbd2ef0`|`2f90eaaaa532d14574c0ce1f1c93b02310f44d91`|
| Prospective256 correction |256|40,919,517|`22f6f8a9d3eabf4de16c853cf67183b67beca4e702e26c5b492066e94194735c`|`f251f3b7c7e152943ce85bc012f97305934e8fd8`|

The new map is50,338 bytes. `hosted/volume.py` changes from5,818 bytes/SHA256 `5403e74515cf11aacb05fbd719d5e129549aa565b913b84d86d2b1ed608426bd` to5,834 bytes/SHA256 `0804a28d689fc73fd05474196cb8b443562493eef9392cc8786968d6911e504e`. No other existing leaf changes except the regenerated map. The packet adds `previous-v3/hosted-volume.py`, `previous-v3/source-map.json` and `successor-v4.json`. Those retain the complete previous volume and map plus the exact inverse, restoring every253 body/mode without an external253 operand. Regression controls then restore published251 and original248.

Actors, compiled code, runtime derivation, original200, packages/candidate map, policy/budgets, common, hosted entry, producer/reader and both workflows stay byte-identical. The initializer code is an unchanged inert string: actual kernel CapPrm/CapEff/CapBnd must still be1, CapInh/CapAmb0, and NoNewPrivs1. CapDrop ALL, image/container/role identity, root user, interpreter/code/binding, singleton owned volume/nocopy, read-only root/network isolation and all resource limits remain enforced. Outer operation remains `llvm23-source-reference-native-v2`, inner actor `llvm23-source-reference-native-v1`.

The1,861-byte constructor profile SHA256 is `78d4decc97c57dc0e75d7e4ac097b4f32699fd4ae0fb15d1e35e0a45a566ae7d`. It pins the entire constructor, README, constructor controls, volume controls and their retained DATA fixture. Source/ref and all actual selectors remain NULL; the253 parent has no Git identity to invent.

Eleven new constructor controls verify exact256→253→251→248 inversion, unchanged leaves and recomputed-map/body/mode/archive/metadata tampering. Eleven fenced AST volume controls accept both singleton spellings, reproduce the original CAP_CHOWN refusal and reject extra/mixed/duplicate/unknown/non-list capabilities and identity, security, resource, mount, code and natural-completion drift. They never execute INIT_CODE. The CAP_CHOWN spelling comes from Root's actual Docker28 finding; remaining inspect fields are explicitly modeled. No retained initializer-inspect artifact was found in the bounded local intake lookup; daemon capability lists are not mislabeled as initializer evidence.

All22 existing v3 constructor/hosted controls and22 new constructor/volume controls pass on Python3.12.13 and3.14.7. Controls are DATA-only; process/network/FFI/lease boundaries are fenced for the new controls.

A new private unbound once proposal is prepared separately under `work/llvm256-CAP-Source-and-once-20261115-r1/once-proposal-r2`. It binds these new pins, prepends a strict256→253 passive projection to the existing253→251→248 chain, and preserves outerv2, fresh future`-r2` ref, global two×five-status EMPTY/MainCAS/custody/once-POST/discovery/no-retry/ambiguity-HOLD and unchanged policy. Source/ref/public proof/Root authority/runtime remain NULL. Old operators stay untouched.

Root must separately construct/verify the corrected physical Source, replace/rename the private export without retaining permanent duplicate40MB trees, publish/read back its actual Git identity, and then bind a fresh once packet and independent Reader. Actual Git Source proof, physical256 export, operator entry, Root issuance, native, independent Reader, M2, performance and release acceptance are **NOT RUN** here.
