# Management policy development contract

Status: source audit and software fixture validation only. The installed CLI
remains read-only. `policy.py` and its tests are build/check sources, not installed
management programs. No activation, privileged helper, service or sysfs mutation
is implemented. R4/M6 KSM management remains unfinished.

## Audited upstream behavior

The [pinned Cachy recipe](https://raw.githubusercontent.com/CachyOS/CachyOS-PKGBUILDS/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachyos-ksm-settings/PKGBUILD)
installs `MemoryKSM=yes` drop-ins for eight services and a `ksmd.service` invoking
`ksmctl -e` on start and `-d` on stop. It includes a tmpfiles source requesting
`run=1`, but does **not** install that source. Its package function contains no
enable command. This source audit does not establish activation on any machine.

| Pinned file | SHA256 |
| --- | --- |
| `10-systemd-ksm.conf` | `adab2cae71b5acb9057d87215edb8c9a079e2d16cf5a6484d1b3898503eaac75` |
| `10-enable-ksm-by-default.conf` | `a5a0f259d6d00228864176d6081372730ee77df9621836de4feeb9dc675390a3` |
| `ksmd.service` | `6c995e28ba0c52e3adb9b68c2f5df59378b14cbedb17fec9a09848d840acd656` |

[systemd v256 documentation](https://raw.githubusercontent.com/systemd/systemd/5c79cdec10a547a866764a66e1e14898112a00cd/man/systemd.exec.xml)
describes process merge eligibility and cautions about security domains.
[Its implementation](https://raw.githubusercontent.com/systemd/systemd/5c79cdec10a547a866764a66e1e14898112a00cd/src/core/exec-invoke.c)
uses `PR_SET_MEMORY_MERGE` and ignores unsupported-kernel failures. A systemd
version or KSM directory alone cannot establish that eligibility works.

[Linux v6.12 source](https://raw.githubusercontent.com/torvalds/linux/adc218676eef25575469234709c2d87185ca223a/mm/ksm.c)
is the reference for this validator's scalar bounds and advisor constraints,
not proof of the target Asahi kernel's behavior. `run=0` pauses scanning and
retains merged pages; `run=1` scans eligible memory; `run=2` requests global
unmerge. Unmerge can fail under memory pressure and reset run to zero. A later
scalar restore cannot reconstruct sharing or recover killed applications.
`pages_to_scan` and `sleep_millisecs` are unsigned 32-bit controls in this pin;
scan-time advisor owns `pages_to_scan`. Changing advisor can reset defaults, so
the validator never proposes it. Actual target versions require their own audit.

## Fixture schema and dry run

`python -B policy.py snapshot.json request.json` reads only those two supplied
JSON files (at most 64 KiB each), emits a proposed transition and exits 0 for
schema/invariant validity, 1 for rejection. Final-component symlinks and special
files are refused with nonblocking read-only opens. Duplicate fields, nonfinite values,
unknown fields, boolean integers and unsupported actions fail. It emits no
commands or arbitrary paths. It does not collect capabilities or prove that a
snapshot is truthful, current, complete or from Apple hardware.

Snapshot exact fields:

```json
{
  "schema_version": 1,
  "target": "m2-air-13",
  "kernel_release": "fixture-6.12",
  "page_size": 16384,
  "controls": {"run": 0, "pages_to_scan": 100, "sleep_millisecs": 20},
  "advisor_mode": "none"
}
```

The target strings `m2-air-13` and `m2-air-15` are project labels, not machine
detection. Numbers above are synthetic, not recommended defaults. Controls must
be captured explicitly; unavailable knobs are not invented. `advisor_mode` may
also be `scan-time` or `unavailable`; the latter declares the interface absent,
not merely unknown. A snapshot with `run=2` is refused as an unrestorable baseline.

Request exact fields: `schema_version: 1`, `snapshot_sha256`, `action`, `tuning`
and `acknowledge_unmerge`. The digest is `snapshot_digest(snapshot)` from
`policy.py`, SHA256 of sorted compact JSON. It binds the request to declared
baseline values; it is not a live concurrent-change or freshness check.
Actions map `enable` to run 1, `pause` to 0, `disable` to 2. Disable requires
`acknowledge_unmerge: true`; the other actions require false. Tuning is an object
containing only explicitly requested `pages_to_scan`/`sleep_millisecs` integers
in the reference bounds. Scan-time advisor rejects pages-to-scan tuning.

Proposals list changed knobs followed by run; restoration proposes pause first,
changed baseline knobs, then original run 1 if applicable. These are declarative
sequences, not an executor or verified rollback. Output keeps management false,
execution unimplemented and every acceptance gate NOT RUN. Global run controls
affect all registered memory, so choosing a service does not isolate their scope.

## Required Apple management implementation

For each exact Air size, collect actual kernel/config/page geometry, exposed
controls and supported merge-registration behavior. Review workload eligibility
and security domains. Specify the privilege boundary, baseline service/config
state, explicit global scope, concurrent-change detection, interruption recovery,
control-value restoration and low-memory unmerge failure handling. Then test
activation and recovery on that machine. Measure responsiveness, memory, CPU,
energy and thermals against a documented baseline before choosing a default.
This software validator supplies none of those execution or hardware results.
