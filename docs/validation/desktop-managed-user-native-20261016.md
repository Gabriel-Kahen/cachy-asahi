# Managed user-session generic ARM trial

[Actual38867491003](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38867491003)
passes the managed591 session, both readable launcher frames and scoped cleanup.
Source/workflow is `fe6b1d3522244f23caf1295a502010d3172ee87b`; its parent source is
`d090c5baa048e443ff384a44bea1b52bdd5d71f5`.

The fixture starts the packaged Permit User Sessions service rather than
bypassing PAM or replacing account policy. The packaged runtime directory and
`user@23001.service` start successfully. After typed D-Bus name readiness, root
and the unprivileged workload independently confirm UID23001, manager PID266,
the real `unix:path=/run/user/23001/bus` and a successful systemd GetUnit call.
No private replacement bus is used. This does not establish that every user
default-target service passed.

Both original minimal/overlay launcher phases complete. Root independently
views the exact1024×768 frames and replays the managed event gate, public byte/
frame joins, matching base image,14 VM cleanup records and final owned base/probe
absence. Both user units end inactive/dead with PID0 and the runtime tree absent.
The expected591 package composition and configuration verifier pass.

- Minimal PPM: `a2541c1fb4186b5bdbd1185f9d7f4336283a5fc67e5464b73ee6e09d785af7ed`.
- Overlay PPM: `8bf169de00b1c51e7e7e59e9d23052c39cf83f2d3a16884ecc3675ff3ba2995c`.

Artifact12032257018 is731423 bytes, SHA256
`feab413de3d3736760d329285fe15f26bf26907d04fb2b4496680ebd2a355d76`.
Logs are31764 bytes, SHA256
`61b591d8600fa9a3b91e6407779a2c61f521901b94764584617767c2e77741f8`.
Each archive was retrieved once; extraction is restricted to the declared public
allowlist. Private source/runner assertions remain enforced by the selected
caller rather than independently reconstructed from unexported records.

Earlier38864107466 fails before native actors because of a relative manifest
argument. Corrected38865232794 starts the manager, then queries its bus name too
early; managed and outer cleanup pass. The bounded readiness correction retains
the original60-second budget and all UID/PID/API checks;24 managed and9 caller
controls pass. These failures remain failures. The original historical PAM
denial was not journal-confirmed.

This is a generic4KiB VM software result. It does not transfer acceptance to
Waybar/Mako, acceleration, Asahi platform behavior, physical M2 or release gates.
