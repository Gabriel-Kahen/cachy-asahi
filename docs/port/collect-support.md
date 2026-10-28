# Collect a private support case

Run from the current checkout, as the affected ordinary user in their login
session. No sudo, network, upload, repair or configuration changes are requested.
The session probe may open a brief GLES context and query existing local IPC;
normal service/graphics bookkeeping can occur.

```sh
python -B scripts/support/collect_support.py \
  --release-id candidate-label \
  --release-sha256 RELEASE_JSON_SHA256 \
  --source-commit FULL_SOURCE_OBJECT_ID \
  --output-dir ./new-private-support-case
```

Use the exact identity being investigated; it is operator supplied, not
authenticated by collection. Never put a secret or username in the public release
label. Optional `--model-id apple,j413` / `apple,j415`, `--baseline-sha256 SHA256`
and `--execution-context physical|virtual|emulated|unknown` are declarations.
The default context is unknown. Device-tree observations do not prove physical
execution. No Git command or input discovery is performed.

The command collects Doctor2 and session reports sequentially, preserves each
completed report privately, then feeds their exact SHA-256-selected bytes to the
existing support bundle sanitizer. A failed/inactive service, missing package or
unknown observation remains visible; it does not make valid collection fail.
Doctor2 uses the session probe's custody-aware child runner, with Doctor2's fixed
argv/environment, 64 KiB accepted output bound and its existing report parsers.
Each producer has its existing 20-second query budget, 2-second child deadlines
and up to 1 second of child cleanup per query. These are cooperative Linux
bounds, not hard real-time guarantees. No worker accepts arbitrary shell code.

The output must be new and its parent must exist, without symlink ancestors or
parent traversal. The directory is mode 0700, files mode 0600:

- `doctor.private.json`, `session.private.json`: original private observations.
- `collection.json`: status, source receipts, original hashes and archive hash.
- `README.txt`: privacy/review instructions.
- `share/support-bundle.tar`, `share/SHA256SUMS`: sanitized sharing candidate.

**Keep the whole collection directory private.** Only the archive under `share/`
is sanitized. Review the archive's extracted summary and reports before sharing.
The archive contains no original report, command output, note, arbitrary path or
free-text hardware/version field. See `support-bundle.md` for exact projection
and verification limits. Hashes, model labels, timestamps and finite observations
can still correlate a case.

Optionally include an existing health report using
`--reviewed-health ./private/health.json EXACT_SHA256`. Its digest, envelope and
release binding are validated before live collection. It is rechecked before
bundling. Health is never run automatically, and its authentication claim is not
reverified. No retained report/code is discovered or executed.

Exit 0 means a verified archive was created, with no health/acceptance verdict.
Exit 2 means collection/refusal failure; exit 130 means interruption. Once output
exists, the durable receipt records the failed stage and completed originals
remain available. A hard kill/power loss can leave `COLLECTING` or a `.pending`
file; use a new directory for retry and inspect the old case privately. Nothing
is overwritten on rerun. The CLI prints no report contents or private paths.

Verify using the SHA-256 retained in `collection.json`, then extract privately:

```sh
python -B scripts/support/support_bundle.py verify \
  --archive ./new-private-support-case/share/support-bundle.tar \
  --sha256 EXPECTED_ARCHIVE_SHA256 --extract-to ./new-private-review
python -B -Werror::ResourceWarning tests/support/test_collect_support.py
```

Python 3.11+ standard library and the current project collector, support bundle,
Doctor2 and session probe sources are required. Optional installed clients are
the producers' existing pacman/systemd/Hyprland/Mesa/PipeWire tools. Missing
clients/endpoints produce unavailable or unknown checks. The command installs
nothing. MIT, original cachy-asahi contributors; no package recipe or shared
manifest is changed by this addition. Native ARM build, installed lifecycle,
physical M2 behavior, performance, recovery and release acceptance remain separate.
