# NetworkManager on an owned private SYSTEM bus

This is a separate, explicit x86 daemon/settings test. It does not change the
prior `networkmanager_candidate` 61-command **no-daemon** lifecycle result.
It uses the same four exact `1.58.1-2.1` archives and retained pinned Arch
prerequisite image. Native ARM/16K, Asahi/M2, real connectivity, suspend,
non-root polkit/session authorization and release acceptance remain NOT RUN.
The historical ALARM `1.58.1-2` source correspondence remains UNBOUND.

```sh
python scripts/integration/networkmanager_private_bus/run.py \
  --allow-owned-private-system-bus \
  --archives work/networkmanager-source-candidate-20261114/archives \
  --output work/networkmanager-private-bus-20261114/new-run
```

Use an ordinary host user, Python 3.11+ and Docker. The output directory must not
exist. The launcher reuses the earlier adapter's exact archive intake and base
image pin (`7052baf57a6eec068371ffdb2f9670ef69bd5ce11ee3ba67f705b724dc8a53d5`).
It requires that retained local image; no pull/acquisition/version/dependency
fallback exists. Before/after image-ID and base-layer checks bind the COPY-only
source context plus private image installation to that base. No host package or
configuration is installed or changed.

The four unsigned but hash-pinned candidates are dependency-checked and installed
**only in the image layer**, with a private pacman config, `--noscriptlet`, and
all existing hooks masked. This path explicitly accepts those pinned unsigned
local files; it does not claim new signature/trust validation. The earlier
TEST-signed repository journey is independent. The installer requires its
explicit image-only flag, build marker and overlay root before reading inputs.
A synthetic machine-id belongs only to this disposable image.

The fresh test runtime has:

- Read-only root; no caller mounts, host bus, hardware devices or service manager.
- Network `none`, private PID/UTS/IPC/cgroup namespaces, **all capabilities dropped**,
  no-new-privileges, 2 CPUs, 4 GiB and 256 PIDs.
- Six bounded private `nosuid,nodev,noexec` tmpfs roots for run, NM state/config,
  HOME, temporary files and output. `/sys`, cgroup and `/proc/sys` stay read-only.
- Explicit checks for mount destinations/types/flags, zero capabilities, standard
  Docker character devices/init metadata and an interface inventory containing
  only private loopback before any bus or daemon action.
- A 120-second action budget, bounded per-command/retirement waits and a finite
  150-second host readiness wait. The image build has a separate 180-second cap.

No privilege, host network, CAP_SYS_ADMIN, NET_ADMIN, module/policy access or
host-interface changes are granted as a fallback.

The SYSTEM bus is a new EXTERNAL/root-only server at the owned Unix socket
`/run/dbus/system_bus_socket`, with no service-activation directories. All child
environments are freshly constructed. Deliberately hostile caller SYSTEM,
SESSION, STARTER and G_BUS addresses are checked and discarded; daemon, nmcli
and GIR receive only the exact owned socket. The GIR client's bus ID must equal
the separately queried private server ID. Loader/proxy/HOME/XDG overrides are
not inherited.

The daemon runs foreground with `--debug` for stderr capture, upstream polkit
behavior and keyfile settings. The private runtime config disables DNS and
connectivity probes, hostname management, auto-default profiles and management
of all devices. Built features remain intact. No activation is requested.

The real journey queries running/version/capabilities, creates and modifies an
Ethernet profile bound to the **absent** `cachy-test0`, with autoconnect false and
IPv4/IPv6 disabled, and verifies its saved 0600 keyfile. It stops/restarts the
owned daemon, reads the persisted profile through real GIR/NM.Client, deletes it,
and requires no remaining profile or active connection. User config survives;
private loopback's complete `ip -j address` snapshot and Docker metadata hashes
must remain unchanged. The owned bus socket is removed after retirement.

Existing `virtual/owned_process.py` supervises every finite command and holds
exclusive custody of bus/daemon children. Both daemon instances and the bus
receive normal SIGTERM, exit zero, are reaped and obtain `EMPTY_TWICE` without
supervisor escalation for a successful result. There is no new general process
supervisor. Public tmpfs logs are exported while only the entry process waits
at a bounded acknowledgment boundary; the entry then exits normally. The owned
container/image tag and all private tmpfs state are removed.

**Natural limitations are retained, not passed:** without capabilities, the daemon
attempts a private loopback link operation that receives EPERM, and shutdown IPv6
loopback sysctl writes receive read-only errors. The custom bus has no
ModemManager/hostnamed/other auxiliary services. Successful profile CRUD does not
qualify those platform operations, real networking, DNS, Wi-Fi, WWAN, OVS,
polkit user flows or hardware. Reports preserve every warning/error and mark
platform operations HOLD; no skip, capability or policy bypass hides them.

```sh
python -m unittest discover -s scripts/integration/networkmanager_private_bus -p test_private_bus.py -v
```

Three focused controls cover caller-environment isolation and host-execution
refusals. They do not substitute for the actual opt-in daemon run.
`validation.json` records the actual software result, source/report pins,
retirement evidence and limitations. Earlier diagnostic runs retained a test
expectation error (D-Bus VERSION is upstream `1.58.1`, while CLI `--version`
includes package release), and corrected live tmpfs export; neither required a
candidate recipe change.
