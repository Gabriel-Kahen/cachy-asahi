# Executable First Login v3 isolation fixture

This opt-in projection applies to an already reviewed v3 Overlay583 R1 worker. The old fixture put the deliberately hostile `python3` under the target's `noexec` `/run`, where `access(X_OK)` necessarily failed. R2 places the complete isolation home under a nonce-owned directory on the guest scratch ext4 at `/var/tmp`. The helper checks the actual poison execution access and preserves the same poisoned environment, frozen preview/apply roots and original user configuration. The guest retires this directory with the same ownership stack. The independent reader requires its retirement. The original `/run` flags and the existing v2 package rehearsal remain intact.

From a trusted checkout, select the independently reviewed v3 worker tree, R1 handoff and reader. Pass absolute paths and independently reviewed whole digest pins. `OUT` must be a fresh directory separate from the input worker.

```sh
p=scripts/integration/first_login_overlay583/v3_fixture/project.py
python3 -I -B "$p" --source "$V3_SOURCE" --handoff "$V3_HANDOFF" \
  --handoff-sha256 "$V3_HANDOFF_SHA" --reader "$V3_READER" \
  --reader-sha256 "$V3_READER_SHA" --output "$OUT"
python3 -I -B -Werror scripts/integration/first_login_overlay583/v3_fixture/test_fixture.py -v
```

The output contains a fresh `source/` tree, `readback.py` and `projection.json`. The projection pins each source role and the reader for the existing signed-supplement assembler. Use the emitted R2 handoff kind, updated worker and reader pins, and a separately owned guest scope. Recompose the plan and supplement through the held assembler with the newly selected case data. The four changed worker files and corresponding reader are the only source differences. Continue through the existing signing and actor admission gates. A same-package detached signature can be reused only while it covers the independently selected guest window.

The regression runs the exact seed bytes as the current ordinary test user. It fences the `noexec` refusal and then executes the planted interpreter on executable storage, requiring its expected exit 97 and diagnostic. It also checks nonce containment, emitted frozen roots and refusal of altered worker source. Historical v2 callers take their existing path without opting in.
