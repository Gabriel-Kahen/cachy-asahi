# Delegated current private route v4

This additive adapter exposes:

```python
run_registered(*, stage, source, profile, inputs, delegation_raw,
               delegation_sha256, context, image, executor, output, open_session)
```

It uses the new delegated context and image observations, never an old Root
poststart observation schema. It opens only the supplied
`open_delegated_session` callback through `open_session`, using keywords
`delegation_raw`, `delegation_sha256`, `context`, `image_report`, `executor`,
`source_root`, `output`, `inputs`. The owner must replay the actual pinned
delegation/context/Source/image/executor checks before creating any role;
the route's declaration joins and hash comparison do not authenticate Root or
GitHub. No operational role or authority occurs on import.

The yielded session supplies actual `facts`, `run(step, argv)`, native-only
`records`, `native`, `native_pin`, `tools`, `profile`, `image` and `build_inputs`.
Facts join operation/stage, actual context binding, delegation pin, nonce,
immutable image, AArch64 and observed4096/16384 page size. `native_pin` is the
exact13703-byte SHA-256 `cde384acd8574ddfcb07f7316ad4d24349f5b958ac6b2cea48a3a6aff480c827`.
The owner verifies those unchanged helper bytes before loading them.

Backend/UI use new `private_build_plan` and a small explicit pair loop.
They never call the frozen `native.build_vectors` or `native.build_pairs` and
create no `Root_admission`, `Root_capacity` or image-qualification aliases.
`build_inputs` has exactly `source_date_epoch`, `capacity`, `builder_inventory`.
Capacity has `build_seconds`, `builder_cpus`, `builder_memory_bytes`,
`builder_pids`; inventory has `path`, `bytes`, `sha256`, `packages` resolved by
the owner from the Source-relative materials. The plan declares build intent
only. Actual commands come from `session.build(kind, label)`, which owns its
Docker actor and returns `built-package-static-pass` DATA.
`session.compare(kind)` appends the actual held `compare.py --require-bytes`
command and returns its raw JSON. No generic build CLI argv is fabricated as
executed. The unchanged container entry performs normal makepkg checks;
`native.check_log` and complete pair comparisons remain required. Separate
administrative custody/trust/cleanup logs remain with the owner.

`validate_build.py` is a static CLI invoked through the actual owner executor.
Its operands are `--source-root`, `--kind`, `--build-directory`,
`--expected-inventory`, `--source-date-epoch`. It verifies the fixed whole
profile, recipe snapshot, reviewed hashes, actual inventory and pinned helper/
entry bytes. One exact reversible import seam supplies pinned `package_checks`
to held `build.py` predicates without ambient helper imports. It applies
`recipe`, `bind_generated`, `package`, `conflicts` and `bind_artifact`, writes
`validation.json`, and returns static result fields for actual provenance.
Any decoder remains a descendant of that supervised validator command. It
builds/signs nothing and issues no Root observation or image qualification.

Lifecycle must run locally as root AArch64 Python, a non-PID1 direct child of
PID1. The session additionally supplies `signed`, `pacman`, `verifier`,
`fingerprint`, `protected_before`, `verify_state()`, `protected_after()`.
The adapter retains only public signed archive/signature/configuration DATA,
then calls the unchanged `native.lifecycle`. It does not sign packages, obtain
keys or manufacture archive inputs. Signing delegation and image construction
belong to separately authorized owner roles.

Reports have kind `DELEGATED_CURRENT_PRIVATE_STAGE_REPORT_V4` and issuer
`DELEGATED_CURRENT_OWNER_V3`. Backend/UI status is
`PROVISIONAL_CURRENT_BACKEND_DATA_ONLY` / `PROVISIONAL_CURRENT_UI_DATA_ONLY`.
Lifecycle returns `PENDING_OUTER_CURRENT_STAGE_RETIREMENT`, with provisional
body status, after local restoration; it cannot assert its own container absent.
The separate outer owner alone finalizes actual CID retirement. All reports
keep `Root_final_acceptance=null` and independent-component/hardware/release
acceptance false, including failed reports. A callback error, bad recipe check,
pair inequality, forced supervision or uncertain cleanup propagates as failure.

Fenced controls use fictional callbacks and temporary DATA only. They import
the unchanged maintained native module solely for its pure check predicates;
no actual build, ALPM, GPG, Docker, network, lease, Reader or actor runs:

```text
python3 -I -B -Werror scripts/ci/first-login-enrollment-native-source/successor_v4/test_route.py
```

The frozen v1/v2 routes, original owner and Source139 are unchanged. Source
tests provide no native, hardware, independent acceptance or release result.
