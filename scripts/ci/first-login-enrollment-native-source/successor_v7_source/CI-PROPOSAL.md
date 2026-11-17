# Bounded v7 source-controls registration proposal

The existing `native-source-controls.yml` is owned by Root's integration worker.
This family does not edit that shared workflow. The proposed additive step uses
the existing Python3.12/3.14 source matrix and its timeout/resource envelope:

```yaml
- name: Check nested retained-transport diagnostic Source v7 DATA
  run: |
    python -I -B -Werror::ResourceWarning scripts/ci/first-login-enrollment-native-source/successor_v7_source/test_transport.py
    python -I -B -Werror::ResourceWarning scripts/ci/first-login-enrollment-native-source/successor_v7_source/test_data.py
    python -I -B -Werror::ResourceWarning scripts/ci/first-login-enrollment-native-source/successor_v7_source/test_reader.py
```

These are source/DATA tests with modeled process boundaries, finite public
failure fixtures, strict parser refusals and complete inverse transformations.
They grant no native, HTTP, privileged command, Root issuance, key or host-repair
access. Existing v6 capture tests remain required and unchanged. Full physical
205-source inverse/Reader checks require the exact retained196 public DATA basis;
a MODEL basis is explicitly labeled and cannot stand in for that check.

No hosted result, issued Source CID/ref, run, artifact, Reader or Root acceptance
is inferred from this proposal. Root coordinates shared workflow adoption and
any separate native attempt. The actual Source196 failure remains unexplained;
this successor adds bounded visibility for a future separately authorized run.
