# cachy-asahi measurement tools 0.1.0 candidate

An opt-in, stdlib-only Linux package for recording base identity, freezing an
experiment, executing owned workloads, replaying platform captures and comparing
complete baseline/candidate trial blocks. The five runtime modules are unchanged
copies from commit `852d1b7324e4ad840fa94ea7c9fc994b1aa07280` (MIT). Exact Git blobs,
SHA256 and sizes are in `source-provenance.json`. No repository checkout is needed.

Install with the normal reviewed package workflow. This recipe has no hooks,
services, dependency on a desktop, configuration files or changes to defaults.
Only Python >=3.12 is required at runtime. `arch=any` describes Python payloads;
it does not establish ARM execution. `check()` requires bubblewrap for private
PID/proc and empty-sysfs host controls, and fails if that isolation is unavailable.
Use `makepkg --cleanbuild` in an ordinary-user disposable build directory; no
package-manager installation is performed by this source packet.

The executable resolves its private runtime relative to its own installed path
and uses Python `-I -B`. Cwd, PYTHONPATH, user site packages and repository imports
cannot replace its modules. The prefix can move unchanged. Frozen plans pin
absolute resolved source/state/workload paths and hashes: move first, then freeze
a new plan. A moved old plan must be refused; do not rewrite its pins.

## Interfaces

```
cachy-asahi-measurement-tools --version
cachy-asahi-measurement-tools state --execution-context unknown --output base.json
cachy-asahi-measurement-tools benchmark prepare-plan --config experiment.json \
  --baseline base.json --candidate-state candidate.json --output plan.json
cachy-asahi-measurement-tools benchmark run --plan plan.json --slot 0 \
  --state base.json --conditions conditions.json --cwd /private/work \
  --output /private/results/trial-0 --platform-metrics
cachy-asahi-measurement-tools benchmark compare --plan plan.json \
  --runs /private/results/trial-0 /private/results/trial-1 ... --output report.json
cachy-asahi-measurement-tools metrics capture --machine-label operator-ID \
  --duration 1 --interval 0.1 --output /private/results/fresh-capture
cachy-asahi-measurement-tools metrics summarize \
  --capture /private/results/fresh-capture --output /private/results/replayed.json
```

Run every predeclared slot in order using its correct baseline/candidate state.
All output paths must be fresh and their parents must exist. The state command
records kernel/OS/page/model identity, package inventory and repository DB hashes;
it does not attest to functional/recovery gates or measure physical conditions.
Failed package queries remain unknown. Execution context is operator declared.
Physical plans still need the original reviewed exact-machine hardware gates.

`experiment.example.json` and `conditions.example.json` describe a **synthetic
host control**, with placeholder paths and explicitly invented environmental
values. Replace all paths, identifiers, controls and usefulness/regression budgets
before a real experiment. No example value constitutes a measured baseline.
`smoke_workload.py` is a bounded fixed-work literal-argv fixture, not a benchmark
of the distribution. Its sole variant is the explicitly declared environment
value, which chooses an intentional 0.24s/0.12s sleep. This artificial timing
difference verifies plumbing only. Pin every actual workload executable/input;
the harness is not a sandbox.

## Preserved budgets and source meanings

At least five trials per variant; no three equal consecutive slots. The example
uses twelve alternating ABBA/BAAB slots (six each). Comparison requires complete
unique slots, original raw hashes, source/state/environment identity, controlled
conditions and ordered nonoverlapping timing. Missing trials, mismatched baselines,
drift, invalid numerics and incomplete collection refuse comparison.

Installed `run` requires `--platform-metrics` and a frozen
`"platform_metrics":{"interval_seconds":0.1}` declaration. This selects the
existing pinned exclusive-wait owner, not the legacy runner, whose post-poll
numeric `killpg` cleanup remains a reported source concern. Offline legacy
comparisons are supported. The source is held unchanged; there is no repair or
silent default instrumentation. Optional `owned_rss` retains the original source
validation and limits. Without it legacy RSS stays null; a memory guardrail yields
INCOMPLETE unless another rule fails. Combined stdout/stderr is capped at 512 KiB;
stdout.txt contains that stream and stderr.txt is empty. Timeout is at most 3600s,
platform interval 0.1..10s, at most 10000 samples; original finite-sample admission
and bounded retirement rules remain. Syscalls are not hard real-time bounded.

Standalone metrics retain 0.1..3600s duration, 0.1..60s interval, 128 devices/class,
1024 entries/device, 128 sensors, 10000 samples, 512 bytes/attribute, 512 KiB/sample,
128 MiB capture, and min(120, 2.5*interval)s gaps. Missing, denied, unavailable,
unknown and invalid values are distinct from zero. hwmon temperatures stay
unreviewed; energy is source-specific, without attribution to the whole machine.
Counter decreases, charging transitions, invalid endpoints, clock discontinuities
and gaps are not bridged. Partial energy coverage and unobserved boundaries stay
explicit. Power domains need actual target review. Logging overhead is included
where documented by each original collector and has not been calibrated on M2.

`compare` exits 2 for FAIL or INCOMPLETE and still writes the preliminary report;
inspect `preliminary_result`. `optimization_acceptance` remains
`NOT RUN` in every case. A timing rule alone grants no optimization acceptance.

## Host qualification and removal

`python -IB test_package.py --recipe-root .` invokes real installed launchers
from two moved private prefixes, with read-only host mounts, no network, empty
`/sys`, and a private PID namespace mounted at `/proc`. It uses synthetic
conditions, genuine short owned workloads, source/state/hash negatives and offline
reports. The package reads no real session processes or sensors in these tests.
No ALPM install, native ARM/16K, installed Asahi, physical M2, power/thermal,
performance improvement or release qualification is established. A normal
operator `run` or `metrics capture` outside that test isolation reads real sensors.

`payload-map.json` is the exact installed file map relative to `/usr`; files are
package owned, with no .pyc generation. Removal deletes these files only. User
selected plans/captures/results are outside package ownership and remain intact.
Private staging/removal controls are not an ALPM lifecycle claim.
