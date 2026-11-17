# Auxiliary-cache host/guest DATA equivalence

This standalone CI family compares the strict host normalizer and exact guest
GNU awk canonicalizer as byte programs, using the real public baseline and
finite primary-layout adversarial records. It adds ten differential controls,
not another replay of the older host/guest/projector suites. Existing normalizer,
guest implementation, operational guard, manifests and frozen CI bytes are
unchanged.

The Root-authorized baseline12313/SHA
`bf57218ea22ca530decf18bf8ec548c22ec96afb0afc423088a97fbb148149ed` is already
present in original host author4bf08. It was verified against the single
explicitly authorized public observation file and is reused without duplication.
No Raw image, private Root records or after body are copied.
`provenance.DATA.json` distinguishes supplied origin from checks here.

The host6791-byte implementation is whole-pinned before import. The exact frozen
guest author is `52388fe90594ff3981982e209acd2e9fe58e8b52`; only its two pinned
`canonicalize.sh`/`canonicalize.awk` runtime files execute. Neither `project.py`,
Source389 projection, a cache snapshot nor a live guest guard is invoked.
The 190-record baseline must produce exactly11373 bytes/SHA
`101a81b8720aeb3f5994f133226c19f06a3b9073d51cee7d419c2ceb96184f1d` from both
implementations.

The ten groups exercise:

- Genuine baseline canonical-byte identity.
- Full unsigned64 sorting and serialization, including2^53/2^63 boundaries,
  U64max, tuple-prefix ties and digits-only hex0x9999999999999998/9 in descending
  input order, exposing awk numeric-string rounding mistakes.
- NULL versus non-NULL empty names, full binary names and distinct versions.
- Every supported ISA bit, exact architecture flags and unsupported profiles.
- Record/string relocation and the four ABI tail-padding bytes only.
- Visibility of each defined stat/ISA/name change.
- Empty cache, duplicate identity refusal and membership multiplicity.
- Header/count/extent/endian/cap refusals.
- Segment offset/interior/reuse/unreferenced/NUL/name-cap refusals.
- Maximum4096 records near1MiB and a full4096-byte binary name.

Every accepted input requires exact binary stdout equality. Refused inputs must
fail in both implementations and emit no partial guest canonical output. MODEL
records are grammar adversaries, not substitutes for an actual observation or
provider qualification. SONAMEs are byte data and are never opened as paths.

The dedicated PR/Main workflow explicitly installs **GNU gawk**, coreutils and
bash. It does not assume `awk` means GNU awk. Both Python3.12/3.14 run the host
reference and launch the pinned shell implementation on the CI host. The guest
script itself invokes only fixed `/usr/bin/head`, `/usr/bin/od` and
`/usr/bin/gawk` with `LC_ALL=C`; no Python/Perl is needed by that implementation.
This is a host-side implementation comparison, not execution in baseline111 or
a VM. Tool version output remains in CI logs.

Tests require ten passes, zero skips/expected failures and zero denied actor
attempts. Only the exact pinned Bash DATA command is allowed through the Python
audit boundary; its child coreutils/gawk pipeline is fixed by the pinned source.
Other processes, sockets, ctypes, locks, signals and post-fence resource setters
refuse, except SIGKILL to the retained guest DATA process group on timeout.
Each invocation owns a new session, and timeout cleanup reaps that pipeline.
The test process and children inherit512MiB AS/120CPU seconds/4MiB file/
128FD limits; each guest command has a20-second deadline. Inputs and outputs are
bounded. The result separately counts allowed guest DATA processes.

```sh
python -I -B -Werror::ResourceWarning scripts/ci/perl-auxiliary-cache-data/test_equivalence.py
```

Canonical agreement for one baseline, or for MODEL padding/order variants,
establishes no actual baseline/after semantic equality. No actual after body is
selected. Auxiliary comparison remains NOT_ACCEPTED, selection UNSELECTED,
Source65/private inode guard HOLD unchanged, and Root/lifecycle/VM/M2 fields NULL.
Root98's raw auxiliary-byte comparison failure is not converted into an actual
semantic-equality claim. Any future selection still requires genuine after-body
custody, independent provider/stat qualification and the unchanged metadata,
xattr, initialized/private, dependency and retirement predicates.
