# Supported Asahi composition adapter

This DATA-only adapter connects the retained Asahi image/protected tuple and
repository catalogs to current project candidates, using the existing
`scripts/platform/transaction.py::prepare` engine. It does not introduce another
dependency solver or modify any previous proposal, protected list or selection.

```sh
python3 -B scripts/port/supported-composition/compose.py \
  --contract /absolute/composition-inputs.json \
  --contract-sha256 REVIEWED_SHA256 --output /absolute/new-output
python3 -B -Werror::ResourceWarning \
  scripts/port/supported-composition/test_compose.py
```

The preinstalled reviewed libalpm ABI must be `16.0.1`; bsdtar/libarchive and
Python are also required. Nothing is installed or fetched. Exit `2` means the
metadata plan prepared but remains **HOLD** for custody/acceptance. Exit `1`
means failed/incomplete metadata or refused input. Neither exit accepts a target
transaction, build, package installation, compatibility or hardware result.

## Exact contract

References have exactly `path` (absolute), `size` and lowercase `sha256`. Inputs
are bounded regular single-link DATA, non-writable by group/others, with no symlink ancestors;
JSON rejects duplicates/non-finite values. The contract has these exact fields:

```json
{
  "schema_version": 1,
  "kind": "supported-Asahi-composition-inputs-v1",
  "workflow": "project-extension",
  "image_inventory": {"path": "/retained/image-inventory.json", "size": 123, "sha256": "REVIEWED_SHA256"},
  "protected_tuple": {"path": "/retained/tuple-report.json", "size": 123, "sha256": "REVIEWED_SHA256"},
  "catalogs": [
    {"name": "asahi-alarm", "path": "/retained/asahi-alarm.db", "size": 123, "sha256": "REVIEWED_SHA256"},
    {"name": "core", "path": "/retained/core.db", "size": 123, "sha256": "REVIEWED_SHA256"},
    {"name": "extra", "path": "/retained/extra.db", "size": 123, "sha256": "REVIEWED_SHA256"}
  ],
  "candidate_srcinfo": [
    {
      "srcinfo": {"path": "/checkout/package/.SRCINFO", "size": 123, "sha256": "REVIEWED_SHA256"},
      "archive": {"path": "/retained/candidate-1-1-any.pkg.tar.zst", "size": 123, "sha256": "REVIEWED_SHA256"},
      "archive_scope": "host-assembled-unqualified"
    }
  ],
  "roots": [{"name": "candidate", "version": "1-1", "repo": "project"}],
  "providers": [],
  "allowed_base_changes": []
}
```

Values above are schema examples, not supplied artifact identities. Workflow is
`project-extension` or `full-desktop`. The latter additionally requires the full
named Asahi boot/kernel/firmware/Mesa/audio/protection set in final metadata.
A minimal extension cannot count as a complete supported system.

The original image/tuple binding and every protected name/version are checked.
All original protected identities remain protected. Any baseline platform member
from the maintained platform-name set is also preserved. Original protected
versions cannot be relaxed by a caller base-change entry. Missing boot anchors
or full-workflow platform members fail explicitly. `mesa-dummy` and alternative
protected versions stay excluded with named decisions.

Roots have exact `name/version/repo`; repositories are the supplied catalog
names, `project`, or an explicitly selected `observed-Asahi-base`. Provider
entries add `requirement` to that identity. The pinned package must declare a
matching effective provider before and after preparation. Multiple provider
alternatives are not approved defaults: the existing engine's unapproved-choice
result fails. Unknown/filtered roots remain named unsatisfied pins.

An unprotected base version change requires an exact
`{name, before, after, repo}` entry in `allowed_base_changes`, bound to this
baseline. Removals are never approved here. These entries express caller DATA
policy only; they do not establish ABI, source, signature or update acceptance.
Same-version project replacement needs a separately explicit reinstall path and
is held rather than silently satisfied by the old installed package.

## SRCINFO and real archive boundary

Only single-package SRCINFO with one `aarch64` or `any` declaration is supported.
Declared runtime relations, including target-specific aarch64 fields, are parsed
as text. Recipe/source commands are never evaluated. Split-package inheritance
or unsupported architectures refuse rather than being guessed. Source lists,
checksums, licenses and an architecture declaration are not build/source/license
or hardware evidence.

A candidate's optional archive must be real supplied bytes with an exact
reference. `archive_scope` is caller-declared and unaccepted: accepted labels are
`host-assembled-unqualified`, `retained-native-development-unqualified` and
`synthetic-test-only`. No label grants native or production authority.

The maintained release PKGINFO parser is reused with a private bounded,
read-only bsdtar wrapper. Candidate identity, architecture, runtime relations and
license declarations must match SRCINFO exactly before admission. Only then do
its actual filename, size and SHA-256 enter the metadata DB. No archive identity
or checksum is manufactured from SRCINFO. A source-only reference, or a candidate
with `archive: null`, is a named missing-archive HOLD and gets no DB row.
Signature references remain unknown; this tool performs no signature verification.

Retained image/catalog metadata keeps its own distinct provenance. Unsupported,
sparse or malformed catalog entries are named unavailable holds with reasons;
a filtered selected root cannot disappear into a complete result. Catalog
filenames are required before entering libalpm. During development, incomplete
filename metadata produced errno41 and a C crash on a provider route; complete
filenames removed that failure, and normal explicit-provider/refusal behavior
was verified. No existing ctypes binding or frozen platform module was changed.

## Containment, outputs and next stage

Existing libalpm preparation/audit runs in a child with 90-second outer timeout,
60-second CPU limit, 1.5-GiB address-space limit, 32-MiB file limit and
`RLIMIT_CORE=0`. It exposes the same no-commit/no-download API. The adapter copies
only real semantic/archive declarations to the private DB representation; PGPSIG
and unrelated informational fields stay in the full source/provenance inventory.
The projection does not change dependency/conflict/provider semantics.

Each read-only archive command has a 20-second timeout and 1-MiB output check.
Input intake is capped at 20 MiB/reference and 64 MiB aggregate with a 120-second
reader deadline; candidate SRCINFO is capped at 1 MiB. Metadata/result bounds and
finite root/provider/candidate counts also apply. This is metadata-tool
containment, not a package sandbox or a general process controller.

A new mode0700 output directory retains `composition.json`, projected
`preparation-inputs.json`, worker stdout/stderr and all source/input pins.
Private DB/cache/GPG/hook directories are removed. C failure or timeout produces
FAIL with available DATA/diagnostics instead of terminating the parent adapter.
No host package DB, trust, configuration, filesystem image or payload is mutated.

`proposed_final_inventory` uses the existing platform-transition inventory
metadata envelope, including exact selected origin/version annotations. It can
supply a candidate inventory for the existing transition/recovery planner once
real archive/signature indexes and exact coordinated policy are supplied.
Per-package custody, signature authentication, installed payload/file/hook
correspondence, source/license/grant/maintainer review and native-build limits
remain explicit holds. This adapter never creates the missing acceptance facts.
