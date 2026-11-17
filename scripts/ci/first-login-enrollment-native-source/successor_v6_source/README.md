# Written-span capture Source successor v6

Source188's material caller reads `MAX_OUTPUT` bytes from a preallocated sealed
stderr memfd after recording the shared open-file offset. That captures the
unused reservation as payload: an empty successful close pins one MiB of zeros,
and a short failure packet becomes noncanonical, unavailable diagnostic DATA.
This explains the capture failure, while the actual native staging cause remains
UNKNOWN. Source188's run, failure evidence, registry and retained inverse remain
immutable. Diagnostic availability does not establish successful staging.

This constructor replaces only the material caller and its hosted whole-pin
consumer. After the existing held child supervisor reports natural retirement
(reaped identity, empty group twice, complete output, no signals, no timeout or
supervisor error), the caller checks the original anonymous fd identity and
fixed capacity seals, seals further writes, and reads exactly the shared written
offset with `pread`. It preserves whole stdout/stderr pins before applying the
expected-zero exit policy. A naturally retired nonzero child remains failed.
Reserved padding is excluded by length, and actual trailing bytes are never
stripped. Missing/incomplete capture remains unavailable; fixed closed-enum phase
and ordinal packets are the only stderr content exposed by public projection.
No command, deadline, storage, output quota, authority or cleanup gate changes.
The stager and owned executor remain byte-identical.

The new schema6 registry and external profile preserve the complete old schema5
Source188 registry as DATA. `inverse_v5()` recovers Source188 exactly;
`inverse_v4()` recovers Source179; `inverse_v3()` recovers Source139. Complete
namespace, body, mode, map aliases and tree identity must match the fixed basis.
The constructor reads only local committed operands. The fresh output is
unissued DATA; no CID, ref, workflow run, grant, Reader or Root acceptance is
invented. Native, hardware and release acceptance remain absent.

```bash
python3 -I -B scripts/ci/first-login-enrollment-native-source/successor_v6_source/prepare.py \
  --repo "$REPO" --basis "$SOURCE188" --revision "$CONSTRUCTOR_COMMIT" \
  --output "$FRESH_OUTPUT"
python3 -I -B -Werror::ResourceWarning \
  scripts/ci/first-login-enrollment-native-source/successor_v6_source/test_capture.py
python3 -I -B \
  scripts/ci/first-login-enrollment-native-source/successor_v6_source/test_data.py
```

Capture controls model child submission/write/retirement through the actual
material session with real preallocation, inherited-offset writes and kernel
seals. They cover empty stderr, fixed packets, malformed/truncated/short/oversized
spans, retained true lengths, late-write refusal, fd replacement, short reads and
uncertain retirement. The modeled actor boundary never dispatches a process,
network request, privilege change or native role. DATA controls use a tiny
explicitly modeled historical basis, retaining all real inverse transforms.
