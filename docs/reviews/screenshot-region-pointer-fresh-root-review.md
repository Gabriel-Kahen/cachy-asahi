# Independent region pointer Source review

**Disposition: BLOCKED for adoption.** The frozen proposal receipt is
`b81e3aff878deec08746979ec5a24178911b230d5035d34556a84d56abdc9df8`.
One concrete failure-path cleanup defect requires a new immutable proposal.
No canonical/worktree Source, Git state, registration, workflow or runtime was
changed by this review. This is an independent Source review with 50 passing
inert controls; actual capability, overlay, input and region capture remain
**NOT RUN**.

## Blocking finding: helper interruption bypasses slurp custody

At proposed `region_trial.py:114–116`, failure cleanup retires the helper via
`run.py`'s `retire`, which calls `p.terminate()` on that helper PID. The unchanged
helper installs its `cancelled` handler for SIGTERM (`cachy-asahi-screenshot:178–186`);
that handler raises `KeyboardInterrupt`. During `region()` this unwinds
`subprocess.run` around the wrapper process. The **exact runtime Python
3.13.5-2+deb13u5** implementation catches that exception and calls
`process.kill()` on its direct wrapper child (`subprocess.py:571–574`).
That is SIGKILL on POSIX; the wrapper cannot forward it or execute its `finally`.

The wrapper's actual `/usr/bin/slurp` child is therefore outside the explicit
retirement path. The wrapper's 20-second timeout and terminate/wait/kill cleanup
(`region-tools/slurp:25,31–35`) also cannot execute after wrapper SIGKILL.
`owned` tracks the helper and background, with no slurp PID/identity record or
child-retirement acknowledgement. A timeout before the press gate, or an
exception while selection is pending, is a concrete trigger. Closing the
virtual pointer first does not terminate slurp's event loop. Later compositor
or container retirement may contain the orphan; it does not establish the
claimed actor cleanup and retirement evidence for the region stage.

The independent reproducer reads the pinned libpython3.13-minimal `.deb` as
archive data, authenticates its runtime-lock size/SHA, and extracts only `run`
and `Popen.__exit__` definitions with a mock Popen object. A simulated
`KeyboardInterrupt` kills the wrapper; the separately modelled slurp remains
alive and no forwarding callback occurs. It also extracts the exact helper
`cancelled` definition to confirm the signal-to-exception join. No process or
signal was actually created or delivered. The pinned `subprocess.py` member is
89486 bytes, SHA256
`21ecc4c8f4fcf641974fc0d9cc28e97b07670ed1cef7e9d96769b31bb8345586`;
the `.deb` hash is `a4aa6a9a8c77f87bfe545e1d14ec42c001d189ace90e3aa75deec882b39dee49`.

A successor needs explicit ownership and finite retirement of the real slurp
producer that remains effective when the unchanged helper kills its direct
child. Preserve the helper and actual producer/trace/geometry semantics; retain
failure evidence and ensure every actor is dead/reaped or report unresolved
custody before any PASS. Merely forwarding wrapper SIGTERM does not repair the
helper-to-wrapper SIGKILL path. Root must independently review that successor
and its full Source closure before adoption or registration.

## Authenticated scope and controls

The proposal's **18 owned and 24 external** absolute-path records authenticate
exact sizes, original modes and SHA256 values. Its nested selection audit's
**112 owned and 26 external** records also authenticate. The current screenshot
worktree HEAD was read as `453699c276ecd7377cf9e1ef682acf9e9554cf61`;
all **two replacement preimages and eight new-file absences** match there.
All 18 rows of the proposed Source closure join proposed bytes or held current
worktree bytes/modes. The Source lock is
`fc52c7753a90cc5107e22b460cfd4fc994ae9a09e8166a9f9e3a4e53a8b56b29`.
The unchanged runtime lock is
`dc19e9dd0d67fd9710fab57c3cddc211be931d61ef730e147dd53f4f148cbc05`,
with 196 packages. These checks make this precise proposal reviewable; they do
not authorize or perform adoption.

The original client, trace parser, wrapper, trial, run integration and Source
lock were read end to end. Held helper/validator/CI/Containerfile/workflow rows
remain authenticated. The pinned core Wayland 1.23.1 formatter uses interface
and object `#` IDs, optional queue text, eight decimal fixed-point digits,
`new id` arguments and an extra send-space; the parser strips that space.
The pinned slurp 1.5.0 sources request the selection overlay, emit configure
acknowledgement and buffer commit, request a pointer after capability delivery,
and emit cursor-shape/core-cursor requests from enter processing. Its integer
positions and `abs(distance)+1` dimensions support the declared inclusive
endpoints. Slurp destroys its overlay and performs a roundtrip before exit,
which is consistent with the success path's helper completion then final trace
read. These are source facts; no actual trace was observed here.

The finite controls cover native wire serialization, malformed/padded/truncated
strings, fragmented reads, oversized/unaligned/unknown event refusal,
capability-bit refusal, mock FD closing and refusal, message-flag refusal,
monotonic deadlines, object/trace bounds, real formatter syntax, configure and
enter callback gates, discarded/missing/wrong-coordinate refusal, serial and
surface mismatch, protocol errors, and press/motion/release recording. Watch
controls cover partial lines, private modes and size bounds, exited-actor
refusal, simulated-clock timeout, and a normal helper-exit race where complete
trace evidence wins over an already-exited poll. Extracted preservation logic
accepts an unchanged prior PNG record and refuses a changed inode. All I/O for
these behavioral controls was mocked or in memory; source authentication only
reads existing files. No fixture tree or actor was created.

The source path displays an asymmetric test input with one unique 73×59 patch
at (31,47), then requires every full-frame capture pixel to match that input.
It validates only a new actual helper-produced crop, with unchanged PNG/pixel
validator bytes and retained actual slurp geometry. This establishes a coherent
proposed origin check and introduces no fake capture or canned geometry
substitution. The producer lifecycle defect above still blocks adoption.
Protocol XML copies retain their pinned grants and notices, including the
supporting `REGION_PROTOCOL_NOTICES`; this is a finite notice/source join,
not distribution-license clearance.

## Retained result

The independent script and result are in
`artifacts/reviews/screenshot-region-pointer-fresh-root-peer-20261014/`.
Its own absolute-path index and receipt bind this report, controls and exact
external inputs. The receipt records **SOURCE_REVIEW_BLOCKED_CLEANUP**, not
runtime acceptance. No Docker, APT, compositor, helper, socket, network/API,
source-package actor, user GUI, dispatch, Git write or worktree write occurred.
ARM builds, accelerated Hyprland, either M2 Air, installation/removal, full
licensing and performance remain unaccepted. No speedup is claimed.
