# Rust configured-mount and CID custody successor v12

Source340 run43891073965/job133382107139 completed the restricted-mode host DATA
hash gate, then failed before qualification data/probes or a Rust build. Public
operation287 records the `/work` configured volume as
`VolumeOptions:{DriverConfig:{},NoCopy:true}`. Source340's producer compared that
whole object with `{NoCopy:true}` and refused. The actual volume name/source,
local driver, writable work root and readonly material binds otherwise match.
This establishes the observed empty-object representation only; it does not
establish any later stage0 subpath or native runtime result.

Qualification recorded the create intent but assigned `ids['data']` only after
full mount validation. Its finally block then raised `KeyError('data')` while
trying to identify the unstarted container. The retained controller records that
error. Operation292 explicitly reports volume-in-use by CID
`16aa9ada533b4d6f5938b7b6cedf8571ba2a059d636c7a2c80f6762a0128513e`;
operation301 reports the same stopped CID preventing image deletion. Actual340
retirement is **FAIL_RETIREMENT**, not successful cleanup. No actual cleanup is
performed here, and Source340/run43891073965 remain immutable and consumed.

Only two operational modules change. `producer.inspect_mounts` accepts an absent
DriverConfig or exactly `{}` for the existing default local volume. Nonempty,
null or unknown driver/options data refuse; bind mounts receive no normalization.
Exact boolean NoCopy, configured and actual Source/Target/Name/type/readonly,
cardinality, propagation and both literal stage0 Subpath operands remain checked.
No alternate driver or mount/subpath fallback is introduced.

Both qualification and build producers record the full acknowledged 64-hex CID
immediately after create, before domain or mount validation, and persist it in
their controller receipt. Cleanup independently verifies the original exact
name/image/source/run/job/token/role identity and the captured CID, then removes
that CID. Cleanup does not require the failed mount check to pass. If create was
not acknowledged, an intended name is removed only after its complete owned
identity is independently verified; foreign or replaced identities refuse.
Forced retirement or any cleanup error continues to fail the operation.

The constructor archives both complete old modules and old source map under
`previous-v11/`, adds one unissued marker and verifies the complete340
byte/mode/namespace inverse. All other leaves, including Source entry, workflow
aliases, actor programs, HTTP/carrier/privacy policy, compiler flags, notices,
606-minute/8GiB resources and108 historical holds remain unchanged. New Source
and Root decision fields are NULL. Existing340 operators/Readers cannot stand in
for a matching successor admission or result review.

The private successor is344 files/43,106,281 bytes, all mode0644, tree
`3f470539f51c0bdbc9fdcb52e0657834310c9e63`, source-map66,940 bytes/SHA256
`8a2f52bb029181c3b547a09f07e4839ce0a58dd40d01c20b2cfd396af1401ec4`.
Its exact public commit/ref, new runtime observations and Root acceptance remain
unset. The external constructor profile pin is in `prospective.DATA.json`.

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/rust199-source-reference-native/successor_v12/test_runtime.py
python3 -I -B -Werror::ResourceWarning scripts/ci/rust199-source-reference-native/successor_v12/test_data.py
python3 -I -B scripts/ci/rust199-source-reference-native/successor_v12/prepare.py \
  --parent /absolute/verified-files-only-Source340 \
  --output /absolute/fresh-private-successor \
  --profile-sha256 EXTERNALLY_SELECTED_WHOLE_CONSTRUCTOR_PROFILE_SHA256
```

The runtime controls use an allowlisted projection of actual public inspect
metadata with no Env fields and inert command mocks; actual daemon/image/package
code never runs. They distinguish the old observed rejection and leaked-resource
failure from modeled successor cleanup. Whole-source controls check the exact
inverse, finite module change sets, current map, fresh output, externally selected
profile and unissued template. MODEL/DATA success is not a native build result.

Root alone reviews, publishes, reads back and binds a matching fresh Source,
operator, Reader, resources and admissions before any new trial. No network,
Original GET, Docker/GPG/actor/lease/Root role, private key/home/credential read,
package execution, platform mutation, grant, publication or push occurred here.
Native, M2, performance, legal and release acceptance remain unproven.
