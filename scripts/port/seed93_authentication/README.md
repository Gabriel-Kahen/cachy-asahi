# Corrected seed93 archive authentication

Run from the repository as the ordinary user:

```bash
/usr/bin/python3 -I -B scripts/port/seed93_authentication/run.py \
  --layout /home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/reviews/maintained-desktop-seed93-root-physical-layout-sqlite02-20261015/frozen \
  --runtime /home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/maintained-desktop-seed93-authentication-run-20261015-sqlite02
```

The runtime must not exist. The launcher becomes GNU `timeout` with a single1800-second work budget and10-second kill allowance. The reviewed supervisor owns the namespace child and records its cleanup outcome. No preparation receipts, operational plans, or additional admissions are needed to launch this development check.

The worker checks the corrected profile `2f326840…`, manifest `bd72c0d2…`, all pinned Source/input bodies, and existing93-row binding. It runs the existing archive/signature hash checks, selected-key GPG validation, and package metadata observation. There is no package installation, scriptlet execution, system configuration change, or M2 hardware test.

Bubblewrap exposes `/usr`, public network configuration/certificates, the selected public Source, this caller, and fresh private runtime directories. It masks `/etc/ssl/private` and does not mount the host home, credential stores, agent sockets, or old cache. The clean child environment has no inherited credentials. The public-only GPG home is created anew. Network access is needed for the93 declared archive/signature pairs.

Progress is retained under `RUNTIME/work/reports/`; failures retain partial outputs. Check `RUNTIME/process-result.json`, `stdout.log`, `stderr.log`, and the process exit status. Success requires exit0, a successful process cleanup result and a final report with verified_count93. A timeout exits nonzero. Never reuse the runtime or silently splice the old89-package run into this result.

The fresh cache is `RUNTIME/tmp/cachy-asahi-seed93-auth-cache`; GPG home is `RUNTIME/tmp/seed93-public-only-home`. Outputs are private and remain available for inspection or deliberate removal. The recorded development Source baseline is commit `2643e1755d402399035976d1f12cd4e8296148bd`.

`caller.py` is the previously reviewed operational caller with only its profile and manifest literals changed. `guardian/supervisor.py` and `guardian/child_entry.py` are unchanged copies of that implementation. `run.py` supplies the ordinary development entry point. Their provenance is `artifacts/reviews/maintained-desktop-seed93-authentication-operational-preparation-20261015/`; the project MIT license applies.

Focused checks (no product Source import, network, package bodies or GPG):

```bash
/usr/bin/python3 -I -B scripts/port/seed93_authentication/test_run.py
```
