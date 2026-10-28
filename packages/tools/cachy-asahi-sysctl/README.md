# Named sysctl experiments

An original MIT CLI for one explicit, available-key experiment: `vm.swappiness`.
There is no preset, automatic activation, service, boot change or sysctl.conf.
The candidate range is0..100; a saved baseline outside that range is retained
exactly for undo. No value is recommended or performance benefit assumed.
Other keys, Qt/polkit integration and measured ARM/M2 policy remain separate work.

```sh
cachy-asahi-sysctl keys
sudo install -d -m700 /var/lib/cachy-asahi-sysctl-experiments
sudo cachy-asahi-sysctl plan --state /var/lib/cachy-asahi-sysctl-experiments \
  --name my-trial --key vm.swappiness --value 30
sudo cachy-asahi-sysctl inspect --state /var/lib/cachy-asahi-sysctl-experiments --name my-trial
sudo cachy-asahi-sysctl apply --state /var/lib/cachy-asahi-sysctl-experiments --name my-trial
sudo cachy-asahi-sysctl undo --state /var/lib/cachy-asahi-sysctl-experiments --name my-trial
```

30 is an illustrative chosen value, not a tuning recommendation. `keys` only
observes required interfaces. `plan` reads the baseline and creates a new named
experiment without changing the kernel. `inspect` reports saved/current values
and whether they match baseline, experiment or neither. Explicit named apply/undo
are noninteractive actions; they never invoke sudo or prompt for privileges.
Kernel writes require root, with plan/apply/undo run as the same identity.

The existing state directory must be caller-owned mode0700; plan/journal files
are mode0600. Names are1..48 lowercase letters, digits or hyphens starting with
a letter. Plans are immutable, hash-bound to their journals and never overwritten.
Use a fresh name for another experiment. There are no arbitrary paths/keys or
alternate proc roots in the CLI. Root, file identity and a hash of the running
boot ID bind the plan; no raw boot identifier is emitted. A journal from an old
boot refuses reuse even if values or inode numbers happen to match.

Apply rechecks the saved baseline before writing. Undo restores only when the
current value is still baseline or the selected value with a matching journal
intent. An unapplied plan does not own a coincidentally equal foreign target.
Any other value or file/boot/path identity change is preserved and refused.
Repeated completed apply/undo does not write again. JSON results distinguish
actual writes from an already present value. Exit0 means that requested operation
completed; exit1 means refusal/I/O failure, and exit2 is invalid CLI usage.

Each write has a durable APPLY_INTENT or UNDO_INTENT before it, followed by exact
readback and a committed journal state. If interrupted or an I/O/journal step
fails, inspect the named experiment and use explicit undo. An intent with the
selected value can restore the saved baseline; an already restored baseline can
finish undo without writing. Unexpected or malformed values are never forced
back. Partial state is retained for inspection, not deleted or guessed successful.
Undo restores the control value; it cannot reconstruct prior page residency,
swap I/O or application effects.
A crash while creating the initial plan can leave an incomplete private directory;
it has performed no kernel write and is not reused automatically.

Use one state store and stop other writers to this sysctl while experimenting.
The advisory store lock excludes cooperating tool calls, not external writers.
Linux proc/sys has no compare-and-swap here: another writer between checks, or a
foreign write of the same value, cannot always be distinguished. This is guarded
local recovery, not atomic kernel transactions, power-loss certification or a
trusted release policy. There is one bounded64-byte value, one selected key and
16KiB state files, with a cooperative5s check around mutation; blocking kernel or
storage I/O cannot be made a hard real-time guarantee.

Installation owns only this CLI and documentation/licenses. It does not create
the state directory or change kernel state. Removal does not undo an active
experiment or delete operator journals; undo explicitly before removal. A reboot
does not trigger this tool or restore an old journal. Normal kernel/base startup
policy continues to apply.

```sh
python3 -B -Werror::ResourceWarning test_sysctl.py
```

Controls perform real writes, conflict/refusal checks and SIGKILL recovery only
in private temporary sysctl-like trees. The internal model API supplies regular
file replacement semantics (including truncation) for those tests; it cannot be
selected through the CLI. No actual `/proc/sys` mutation, native ARM package
build, target installation, memory-pressure/performance test, M2 validation or
release acceptance is established by these controls.

An isolated native/staged fixture can select the installed command source with
`test_sysctl.py --command-source /usr/bin/cachy-asahi-sysctl`; the test,
source-provenance.json and LICENSE stay together as trusted readonly fixture
inputs. This option belongs to the tests, not the shipped CLI, and all kernel
operations still use their private model tree.
