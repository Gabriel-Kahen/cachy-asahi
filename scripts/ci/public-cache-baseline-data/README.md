# Public baseline cache DATA caller

This separate family carries only the Root-authorized public r91 baseline cache
body, its provenance, a finite caller and ten direct DATA controls. Existing
sealed families and workflows are unchanged. No Raw image or private Root record
is included; no Source387 constructor, transform or phase API is imported.

The fixture is exactly 17551 bytes, SHA256
`0128a732a8b926232b5065374176194ea4a1f5c1628728037109bbdbb3d53215`.
`provenance.DATA.json` distinguishes Root-supplied origin from checks performed
here. It records no fresh image scan, live restoration or actual VM qualification.

The caller checks regular single-link0644 file identity and whole bytes, then
whole-pins the existing decoder/provider/transition import closure before import.
The strict decoder must produce358 entries and roundtrip to the same bytes. The
existing independently pinned540-node baseline namespace and three db5.3 ELF
SONAME/provider records derive361 entries:17695 bytes, SHA256
`eeb01c0c2d393aa9bf526a673fedfa331173573722827ec2f68849ccf997412c`.
The observed r90 sample is compared only after derivation; it is not a derivation
input. The restored field is a DATA expectation equal to the original baseline
pin, not an executed restoration.

Ten controls cover the genuine fixture/provenance, canonical roundtrip, provider
joins, independent derivation, exact installed/restored pins, baseline
substitution refusals, alias/mode/body integrity, malformed geometry, finite
bounds and changed provider projections. Processes, sockets, ctypes, locks,
signals and post-fence resource changes are denied. Tests run under512MiB AS,
60CPU seconds,4MiB file and128FD limits, requiring ten passes, zero skips/expected
failures and zero actor attempts. The dedicated PR/Main/manual workflow runs
Python3.12/3.14 with read-only contents permission and pinned setup actions.

```sh
python -I -B scripts/ci/public-cache-baseline-data/caller.py
python -I -B -Werror::ResourceWarning scripts/ci/public-cache-baseline-data/test_baseline.py
```

Derivation and decoding confer no Root authority, lifecycle acceptance, native
execution, VM/M2 result or release qualification. All such fields remain NULL.
No synthetic positive phase, MODEL manifest or baseline substitute is used.
