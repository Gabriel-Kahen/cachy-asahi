# NetworkManager with a real login session

Root ran the revised x86 QEMU TCG experiment with stock systemd, D-Bus,
NetworkManager 1.58.1 and Polkit 128. The ordinary `builder` account completed
serial PAM login and registered the real `pkttyagent` in that logind session.

The genuine own-profile action requested a password. The driver supplied the
private TEST credential once, only after matching the exact action, user,
session and agent. Own-profile creation, editing, disk persistence and cleanup
passed. Foreign-profile and system-profile deletions were denied; the root/admin
prompt received no credential. All original profiles, user data, package
inventory, PAM and policy snapshots were preserved. PAM logout, emulator
retirement and exact container absence passed.

The session was active but had no seat: the measured
`sd_session_get_seat` result was `-61`. The installed policy matched its upstream
template. This is consistent with the recorded stock Polkit local-session gate
selecting `allow_any=auth_self_keep`; no session or rule was changed to force a
challenge.

The private `journey.json` is 25,757 bytes with SHA256
`16eef7743711033874544eeb04cdf297e96c2c1bae541cbe87e6a6c6323e8869`.
Its status is `PASS_X86_REAL_LOGIN_OWN_PROFILE_AND_DENIALS_ONLY`. The 1561-byte
substrate report has SHA256
`df2dd68d6abcd1eb2a42a370dc328990993ce68c4f0c53d49d7113c0dfcbf872`.
See the [experiment and exact invocation](../../scripts/integration/networkmanager_session_vm/README.md).

The earlier attempt remains a separate HOLD: its genuine prompt went unanswered,
and its proof-script copy omission caused a later serial timeout. The corrected
experiment used fresh prepared inputs, credentials, nonce, output and once state.

This is x86 software evidence under the declared rootless, cap-zero host
container contract. The guest is a full reference system. It does not qualify
Wi-Fi hardware, Asahi/M2, ARM/16K, performance or a supported release. Guest
shutdown was not tested; QMP quit followed normal logout.
