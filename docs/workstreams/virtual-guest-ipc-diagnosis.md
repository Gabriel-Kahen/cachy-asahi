# Generic guest IPC readiness correction

Status: source-audited correction and focused host tests **PASS**. A corrected
native controller/QEMU guest trial is **NOT RUN**. Generic software rendering,
Apple hardware validation, 16K-page compatibility, and performance remain separate
claims. This correction establishes none of the latter three.

## Retained first failure

Actual development run `38259350917` reached the generic aarch64 guest running
`7.2.10-1-aarch64-ARCH`, 4096-byte pages. Software GBM/EGL verified 4096 pixels
with llvmpipe. The first minimal-session `hyprctl -j configerrors` returned 6,
with `error: null`, empty stderr, and exactly:

```text
Hyprland IPC didn't respond in time

Couldn't read (6)
```

The guest failed after 124.917 seconds; no frames were captured. Four QEMU
capability checks passed. All five owner cleanup records and private workspace
cleanup passed. These results do not establish a usable compositor session.

Evidence decoded under `artifacts/ci/38259350917/development-decoded/`:

| Evidence | Relative file | SHA-256 |
| --- | --- | --- |
| Actual owner result | `development-virtual-virtual-public-result/result/result.json` | `784adcecac5a79544236f5b7e91855f79d445a63494c80fe6d9172968fb39740` |
| All ten actual guest events | `development-virtual-virtual-public-events/events/guest-events.json` | `823e0909fec0644468ff781383b9949b7c12379829c409d7d29f3ac49124caf3` |
| Decoded `minimal.log` event bytes | Event index 8, filename `minimal.log` | `5560a4f9825cf21b139519b172016575a6343f0569672cc29756a96272292057` |

Events are boot, modprobe, udev settle, dmesg, pacman inventory, GBM command, GBM
pass, failed hyprctl command, minimal stdout log, guest failure. The stdout log
reports that further output moves into the private runtime instance's
`hyprland.log`; its tail contains PointerManager/AsyncResourceGatherer creation.
The actual private compositor log was not retained/exported and is unavailable.
The stdout tail cannot establish where later initialization stalled.

## Pinned source audit

The accepted Hyprland version identifies commit
`efb50993780079460b0cbed1363e2166a2de1d9f`. Its
[Compositor.cpp](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/Compositor.cpp)
constructs CHyprCtl during late initialization, before subsequent managers,
cursor setup, XWayland, and event-loop entry. In
[HyprCtl.cpp](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/debug/HyprCtl.cpp),
the socket is bound, listened on, and registered with the Wayland loop.
[EventLoopManager.cpp](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/managers/eventLoop/EventLoopManager.cpp)
eventually enters `wl_display_run`. Socket existence therefore precedes actual
request servicing. The
[hyprctl client](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/hyprctl/src/main.cpp)
sets a five-second receive timeout; its timed-out read yields the observed
message and exit 6. This supports an IPC readiness race as a causal possibility,
not proof of the actual guest's complete initialization or eventual readiness.

[Logger.cpp](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/debug/log/Logger.cpp)
selects the per-instance `hyprland.log` and independently controls stdout.
[AsyncResourceGatherer.hpp](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/render/AsyncResourceGatherer.hpp)
references Hyprgraphics; the truncated stdout message is not evidence that
resource gathering itself caused the failure. Distribution binary patches were
not independently audited in this focused correction.

Downloaded exact source copies are in `/tmp/cachy-guest-ipc-source-801fe4zm/`:

| Source | SHA-256 |
| --- | --- |
| `src/Compositor.cpp` | `74833ecbf0e2b6f8ad84345ac0716a3295a0e347420a188be0ab4f6a684af7c0` |
| `src/debug/HyprCtl.cpp` | `798b7c6c4c1684557842463d46ac99c96629be4179e0e461dca77670247b91fa` |
| `hyprctl/src/main.cpp` | `f6b0d1fcfc6695194c70964250591a35ffe90274309303d8f5fd0ac6f8c1c93f` |
| `src/managers/eventLoop/EventLoopManager.cpp` | `104ff43a4c02fcc88e8711cade68becd3a1fe099e970e4b1306774c85dd76f7c` |
| `src/debug/log/Logger.cpp` | `d04e3a2fe5c73ad8684377856ce8301e493929ed9f391e405fde4975eaf6b868` |
| `src/render/AsyncResourceGatherer.hpp` | `c4f84c78c4a175ec7025cc91e42a93b6e393a1ea7eb8e05ba9004cbff3a52175` |

## Correction and proposed receiver grant

`guest.py` now requires a successful actual `configerrors` response, JSON `[]`,
with an empty stderr and a living compositor. Only the exact observed exit-6
response above permits another startup probe. Other exits, subprocess timeout,
output overflow, invalid JSON, runtime configuration errors, ambiguous/nonsocket
paths, process exit, or logging overflow fail the phase. Every probe retains its
actual result, including the first failure. A successful response additionally
emits the existing successful ordinary command event.

The startup deadline remains 180 seconds, each probe remains bounded by
`min(30, remaining_seconds)`, and attempts are capped at 24. Each inter-probe
sleep is at most 0.5 seconds and the remaining deadline. Results arriving after
the deadline are retained and fail; they do not become successful commands.
Elapsed milliseconds use integer floor: a ready response at 179.9996 seconds
records 179999, while a response at 180.0001 records 180000 and fails the actual
deadline. Rounding a valid earlier response up to the receiver's deadline is
therefore avoided without changing that deadline.
The guest's 600-second user-session bound, outer proof/owner bounds, strict
mapped-client/frame proof, and process reaping remain in place.

The adapter/controller are outside this change's ownership. Integration requires
the coordinator to add `ipc_probe` to `scripts/virtual/controller.py`'s public
event projection allowlist, extend the adapter's `read_events` with the closed
eight-field schema and two log filename additions below, and extend its
successful `event_protocol` with the ordered readiness checks. `run.py` already
retains generic UART events and needs no grant. Without the controller projection
grant probes would be silently omitted from public evidence. This source/test
correction is therefore **not retry-ready** until those consumer grants and source
pins are separately reviewed. Required closed grants before a trial:

* New event `ipc_probe`, fields exactly `event`, `stage`, `attempt`, `elapsed_ms`,
  `returncode`, `error`, `stdout`, `stderr`. Its command is implicitly fixed to
  `/usr/bin/hyprctl -j configerrors`. Stage is `minimal` or `overlay`; attempt is
  an integer 1–24 and elapsed milliseconds an integer 0–600000, excluding
  booleans. The broader elapsed bound retains failed deadline/reaping diagnostics
  under the existing 600-second session bound; it does not extend startup.
* Successful protocols require consecutive per-stage attempts beginning at 1,
  nondecreasing elapsed time strictly below 180000, stage order matching minimal
  then overlay, and exactly one final ready response per stage. No duplicate
  ready event, probe after ready, missing ready, or interleaving/reordered stage
  sequence is accepted. Every preceding probe must be the exact retry response.
  The final response must have integer exit zero, error null, empty stderr and
  stdout parsing to JSON `[]`. The accompanying successful command must retain
  the same actual response. Other results can be retained only in failed
  outcomes and cannot contribute to a successful proof.
* All fields must have their exact types, closed error values null/`timeout`/
  `output overflow`, and bounded string output. Probe stdout/stderr together
  stay within the existing 1 MiB command cap measured as the sum of their UTF-8
  encoded byte lengths. This includes replacement characters introduced by
  `common.bounded` when decoding invalid UTF-8. A result whose decoded strings
  expand past the byte cap fails before publication of an oversized probe event;
  character counts are insufficient. Failed outcome validation must
  preserve diagnostics without admitting a failed probe as an ordinary success.
* Extend only the existing `session_log.filename` enum with
  `minimal-compositor.log` and `overlay-compositor.log`. Fields remain exactly
  `event`, `stage`, `filename`, `sha256`, `base64`; each decoded log remains
  limited to 1 MiB and hash-bound, with existing content checks. The fixed
  private `hyprland.log` is captured after compositor reaping using a bounded,
  regular-file, no-follow read. Missing/capture-failed logs emit a fixed textual
  diagnostic; they do not assert that actual private bytes were retained.

The existing aggregate receiver event-list bound of 4 MiB remains unchanged.
Large aggregate diagnostics fail closed; no event or serial cap is increased.
Private instance trees are never exported. Secondary diagnostic failures preserve
the original phase exception and emit a fixed capture-failure log where possible;
cleanup errors are reported by type where the bounded serial stream accepts the
write. A closed diagnostic channel cannot establish delivery. A phase without
an original failure raises its first cleanup/retention failure.

## Focused causal proof

Host-only tests use a real bound/listening AF_UNIX socket and a real bounded
subprocess, with request servicing deliberately gated until after the first
receive timeout. The historical gate is reproduced exactly as socket discovery
followed immediately by `command(configerrors)`. The same recovery test fails
under that gate and passes under corrected readiness, with actual probe exits
`[6, 0]` and the first failure retained. The fixture compresses the receive
timeout to 0.05 seconds; it does not execute Hyprland or a guest kernel.

Evidence directory: `/tmp/cachy-guest-ipc-proof-16lrl5m8/` (temporary, not durable
CI publication).

| Check | Actual outcome | Evidence SHA-256 |
| --- | --- | --- |
| Historical gate, recovery test (`old.log`) | Exit 1, expected causal red: command failed at hyprctl | `2bf065de5660cc66e229ded935dd5677a11cd11504ed4fb7d0abac20bd47f4ac` |
| Corrected gate, identical test (`new.log`) | Exit 0, causal green | `3a0e1a22b7a54681ff05b001a44477fc018e2ef45e6ade16e3321d01cb2bc966` |
| Initial 32 tests, `python -B -m unittest discover -s scripts/virtual -p test_virtual.py -v` (`focused-tests.log`) | Exit 0, all pass before fractional/UTF-8 audit correction | `2b2a0d0f6330e1364a6c1a415d8c32ae6edec6ab2b38c50da4d751f678eca9e9` |
| Exact red/green harness (`causal.py`) | Captures historical gate and runs the identical recovery test | `2e0451185d941cd503f322f3faa3e64ff9321724fecfae696b1b55714d99fdde` |
| Historical socket gate recheck (`final-race-old.log`) | Exit 1, expected causal red | `b96e72cc7897bb60629ef82bd5c055f25381db19d4efec12b1911e2b76098326` |
| Final corrected socket gate recheck (`final-race-new.log`) | Exit 0, causal green | `ecedcadc69ab939eaebad7a1f2bb3f0c9f91b8086133767b5c174864b252c976` |
| Original held source, new fractional/UTF-8 tests (`fractional-old.log`) | Exit 1, three expected causal failures: rounded early READY, character-count cap, replacement expansion | `0c7afbd85194494a00f84e816383c3283fbd7133621a44a455cfd8e2a6523059` |
| Final source, identical fractional/UTF-8 tests (`fractional-new.log`) | Exit 0, causal green | `0f2b4eb767b73d7bacf34c09aa2baf56e9ce75ffdaf8656fffe7f957cb95f4f9` |
| Fractional/UTF-8 harness (`fractional-causal.py`) | Loads exact initial held source for red and current source for green | `de2f25026dffe12b45e571c4eb83aeb8c6bf65f003f8c24574cf4215bb438f96` |
| Final 34 tests, `python -B -W error::ResourceWarning -m unittest discover -s scripts/virtual -p test_virtual.py -v` (`final-focused-tests.log`) | Exit 0, all pass; no ResourceWarning diagnostics | `dc8817ce0af55d25398706b7725ea01e3d1a377b7a4798e02d3626fa6a4f998a` |

Checks include strict failure classification, output/type bounds, attempt and
absolute deadlines, late replies, missing/ambiguous/non-socket paths, compositor
liveness, actual timed-out subprocess reaping, bounded regular log retention,
fractional deadline boundaries, combined UTF-8 byte caps with actual replacement
decoding expansion, and preservation of the original phase failure when
private-log capture fails. Exact initial held source remains preserved in the
temporary evidence directory's `initial-held-source/` for the causal audit.
Existing guest guards and virtual process/output/QMP tests also pass.

## Secondary diagnostic failure correction

Independent peer review found a remaining failure-retention defect in held guest
SHA-256 `bf39520348dfa8df2f7cf5afccfacc11d92bc7410f75f394d0907c4ada6f228b`.
With an original IPC `ValueError`, a refused private-log symlink, and a closed
fallback event channel, `BrokenPipeError` escaped cleanup and replaced the
original exception. The compositor was reaped, but the first failure identity
was lost. The peer reproducer and result are retained under
`artifacts/reviews/virtual-guest-ipc-root-peer-20261012/` as
`failure-retention-reproducer.py` and `failure-retention-result.json`.
The subsequent unguarded cleanup-summary print could independently replace
the original exception when its channel closed.

The narrow correction guards both diagnostic writes and appends their failures
to the existing ordered cleanup error list. An active phase exception continues
to propagate as the same exception object. Without an active phase exception,
the first actual cleanup/retention error remains the exception raised, even if
the fallback or summary fails afterward. The working-channel fixture still
retains the fixed hash-bound capture-failure message rather than private bytes.
Closed-channel fixtures record attempted writes separately from delivered logs;
they make no delivery claim. Readiness behavior, deadlines, attempt limits,
schemas, byte caps, private-log restrictions, and native execution are unchanged.

Diagnostic evidence directory: `/tmp/cachy-guest-diagnostic-proof-ij66qmbs/`
(temporary, not durable CI publication). `baseline/` preserves the exact held
guest, tests, and diagnosis document. `causal.py` loads that held guest or the
corrected guest against the same copied diagnostic tests; it also records
exception identity and delivered/refused logs without running Hyprland or a
guest kernel.

| Check | Actual outcome | Evidence SHA-256 |
| --- | --- | --- |
| Held baseline, existing 34 tests (`baseline-tests.log`) | Exit 0; baseline coverage did not catch the defect | `dc8817ce0af55d25398706b7725ea01e3d1a377b7a4798e02d3626fa6a4f998a` |
| Held baseline, identical five new tests (`baseline-causal.log`) | Exit 1; six causal assertion failures | `81d942d3b377c43287839eb87141496169f5f2741b730c980b0ded0a45440ef3` |
| Corrected guest, identical five new tests (`corrected-causal.log`) | Exit 0; all pass | `bf959d9b32a79f7e57a7181903e24c9c2fbdd048b873a110805a6870bd75b207` |
| Baseline exception identity (`baseline-identity.json`) | Original phase/first cleanup or retention error replaced in all five recorded cases | `f4b74a8cfa17563d7adfdf4f588390ee5176a110c2cb662537160f43763706e2` |
| Corrected exception identity (`corrected-identity.json`) | Same original phase/first cleanup or retention exception object preserved in all five cases; closed channels claim no delivery | `885ba9ab775899bf452fcef28eb127e9c6a40f405c26f2d8b9a07be792aaf074` |
| Exact replay harness (`causal.py`) | Loads explicit guest source and identical copied tests | `f6ed83b5124e0dbcc96566df266705263d0b3441dc7bef69d419a0236f81b9bb` |
| Final 39 tests (`final-focused-tests.log`) | Exit 0 with `ResourceWarning` treated as error | `17d41a70100b63ff24f13052fabe012166e7b78bcc053c81b7f7aaef447f90ce` |

The full host command remains
`python -B -W error::ResourceWarning -m unittest discover -s scripts/virtual -p test_virtual.py -v`.
The proposed corrected guest SHA-256 is
`3ca0e95ed89cd21edc96b09e1bc98138e0addbd4b99fc9a3ba41f22ea562ddda`;
source-pin rebind remains the coordinator's separate responsibility.

Remaining work: receiver grant and source-pin rebind by the coordinator; a real
bounded corrected native controller/TCG guest trial; review of retained private
startup logs and both actual frames; exact-M2/16K hardware and performance work.
