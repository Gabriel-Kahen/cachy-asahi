# Exact native349 input carrier

This is an unissued Source95 successor, not a private fetch or native result.
`prepare.py` constructs a new 95-file Source below the unchanged strict 96-file
and 2 MiB bounds. Its compact existing marker reconstructs every original
Source95 body and mode, then the complete Source93/85/76/68/62 chain. All held
Source349 bodies remain identical. No package, URL, hash, architecture,
signature requirement, dependency check, owner resource or success predicate
is replaced.

## Carrier contract

`expected-files.json` fixes the missing 182 original package/signature inputs:
544,634,853 bytes, largest 104,330,276 bytes, with 91 original provenance rows.
The carrier has exactly `manifest.json` and those 182 `packages/<filename>`
blobs, mode 100644, in one parentless commit. The canonical manifest schema is
implemented by `manifest()` in `carrier.py`; extra fields and duplicate keys
are refused. Its provenance includes pins for the actual official-signature
verification reports. The original all-501 acquisition and official GPG
authentication still run after seeding.

`binding.TEMPLATE.json` contains Root-selected public access metadata. Commit,
tree, whole manifest and Root publication receipt remain NULL. Root must bind
those exact results and reconstruct the Source before publication. Binding
refuses before secret access while any required field is absent. Public access
metadata came from Root's 600-byte adoption receipt SHA-256
`f9216841148399d436c74dbb1581cfa91866cd5e5f63ba8836cc131ba49e8ca0`.
The chosen Ed25519 host key is also recorded in Root's 1,072-byte public host
catalog SHA-256
`cd7800dc1c4c3115b365b35cee138355e5d3494d74aa227a2416164789addc51`.
No private key file or value was accessed during preparation.

## Lifecycle

The new workflow template preserves the five dispatch inputs and existing
concurrency group. It needs its own Main publication and fresh registration at
`.github/workflows/native-arm-llhttp-pinned-input-source.yml`; the old workflow
does not acquire a new secret. Only the new fetch step receives
`CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY`.

Fetch independently repeats complete Source/five-input admission, qualifies
existing root-owned `git`, `ssh` and `ssh-keygen` executables, then uses a fresh
Git store and one pinned-CID fetch with strict official host checking. It does
not use an agent, inherited Git configuration, SSH configuration, tracing or a
credential helper. All-stored and reachable forbidden-OID guards, raw
parentless-commit/tree checks, and exact 183-blob metadata checks precede body
checkout. Hashing checks the entire public namespace. The temporary key is
mode 0600; its exact inode and credential home are removed before checkout.
No deploy-key environment reaches the controller or payload. SSH/Git stderr
is discarded; retained receipts contain bounded operation/status and stdout
hashes, not arbitrary diagnostic text.

Fetch has a 180-second deadline, fewer than 24 commands, 45-second CPU and
2 GiB address-space child caps, bounded output, no retries, and naturally
reaped children with two empty censuses. Its new four-minute workflow step
leaves cleanup time beyond that internal deadline; the original 35-minute job
and 30-minute controller ceilings remain unchanged. Its finite staging reserve is
`2 * 544634853 + 64 MiB` in addition to the existing 14 GiB disk preflight.
The existing owned controller limits remain unchanged. No APT action occurs.

Controller entry copies only the complete verified public carrier into its
existing quota volume. Payload entry seeds only those exact 182 names after
the existing retained-cache seed and before the unchanged canonical audit;
wrong existing cache bytes are refused, never overwritten. All 501 inputs,
official signatures, native identity, normal makepkg checks, two builds,
content/byte comparison and retirement remain mandatory. Existing strict
public HOLD export and Source read-only protection remain intact.

## Local source checks

Run `python -I -B -Werror::ResourceWarning test_data.py` from this directory.
The finite MODEL fixtures fence subprocesses, sockets, process ownership,
privileged mutation and writes outside their disposable fixture directory.
They cover full namespace/hash/schema/mode controls, credential cleanup on
success and failure, forbidden/unreachable Git objects before checkout,
same-run staging, cache overwrite refusal, complete Source inverse, and
workflow isolation. They create no real key and perform no network or actor
operation. An actual ARM private fetch and native package pair remain unrun.

Construct a fresh output with `prepare.py --parent <closed-Source95>
--output <new-disjoint-directory>`. Root alone supplies publication,
registration and runtime authority. This preparation does not issue them.

## Canonical caller and registration

`prepare_canonical.py` builds a 28-file canonical ONCE DRAFT from the frozen
27-file v6 caller and this exact Source. Its compact complete inverse reuses
unchanged predecessor bodies and stores every replaced body; it reconstructs
all 27 original files and preserves the older inverse unchanged. It stays
below the original 40-file/2 MiB constructor limits. The issuer, config joiner,
operator and five-input primitive remain concrete. All ten-GET/two-sweep
Actions gate, Main CAS, runtime54, custody, one POST, no retry, CLOSE_ONLY,
resource, owner/payload success and retirement guards remain unchanged.
Only Source/program/policy/helper metadata, the consumed predecessor refusal,
operation name and distinct workflow identity change. Source CID/ref and new
workflow ID initially remain NULL. Optional actual publication/registration
receipts must match the exact Source and new workflow; Root native authority
is never synthesized. The archived constructor/test copies explicitly use
this frozen local code family when run from a generated caller directory.

`read_registration.py --config <file> --sha256 <whole SHA>` is a source-only
adapter over the whole-pinned v6 reader. The configuration template refuses
before any metadata command while actual Main/Source/publication/new workflow
ID are unissued. When Root binds those public operands it retains the same
initial/final Main CAS, API/local/public Git body joins, finite 2 GiB/45-second
children and natural retirement. It checks all 23 literal secret names through
the name-only catalog. It neither reads values nor issues authority. The
reader requires the frozen v6 reader path recorded in its source; it is an
explicit local preparation dependency, not a newly implemented executor.

Run `python -I -B -Werror::ResourceWarning test_canonical.py` for the additional
fenced inverse/tamper, unchanged operational-function, unissued mock-POST,
registration-reader and foreign metadata refusal controls. Actual new-workflow
registration and any private fetch remain separate Root operations.
