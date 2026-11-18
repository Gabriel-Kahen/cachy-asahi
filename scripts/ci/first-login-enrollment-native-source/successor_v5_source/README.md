# Diagnostic Source successor v5

This DATA constructor replaces exactly three pinned programs in the fixed
Source179 basis: the hosted launcher, material domain executor and material
stager. It preserves the old v4 registry, provenance, inverse and original
bodies as DATA. The new schema5 registry selects the replacement descriptors;
`inverse_v4()` restores Source179 exactly, and `inverse_v3()` then applies the
unchanged v4 inverse to recover the original Source139.

The basis must pass its complete namespace, byte, mode, map and tree checks.
Replacement bodies must match the three fixed diagnostic pins. They, the v5
constructor and this README come from the supplied full constructor revision.
Unknown replacements, changed pins or modes, provenance collisions, inverse
drift and Source cap violations refuse. Construction supplies no Root grant,
runtime observations, hardware result or publication. All actual selectors
remain NULL, and the actual native failure cause remains UNKNOWN.

Supply an existing verified Source179 directory, a local repository containing
the reviewed commits and a full committed constructor revision:

```bash
python3 -I -B scripts/ci/first-login-enrollment-native-source/successor_v5_source/prepare.py \
  --repo "$REPO" \
  --basis "$SOURCE179" \
  --revision "$CONSTRUCTOR_COMMIT" \
  --output "$FRESH_OUTPUT"
```

The output is a closed, unissued Source DATA directory. The command performs
local construction and writes its profile to standard output; it does not
dispatch workflows, acquire inputs, run native actors or publish results.

Portable controls use tiny, explicitly modeled basis DATA and inert helper
boundaries. They test rebind/provenance/inverse behavior and refusal paths;
they do not establish the historical Source179 or Source139 identities:

```bash
python3 -I -B scripts/ci/first-login-enrollment-native-source/successor_v5_source/test_data.py
```
