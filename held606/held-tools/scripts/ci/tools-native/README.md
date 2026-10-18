# Native tools candidates

Manual, unselected candidate lane for exactly three products: mirrors, Zsh
syntax highlighting and Zsh history substring search. This reuses the
accepted owned574 producer and Welcome native build/preservation helpers.
It does not change the selected core inventory or register these packages
in any original574 database. No desktop, kernel or Rust build is added.

Root must finish the source binding after the mirror activation product is
adopted. `product-spec.json` is deliberately marked incomplete. Its payload
maps and mirror check markers must match the final recipes. The activation
vectors currently reflect the proposed `activate CATALOG --candidate ...
--target ... --state ... --repository core` / `restore --target ... --state
... --repository core` CLI. Confirm these against the final source before
setting status `FINAL_SOURCE_REVIEWED`. Until then the empty source pins,
empty CI manifest and workflow hash markers prevent dispatch before secrets.
Missing or unfinished products cannot be skipped.

After adopting the lane and all three final product directories, Root runs:

```sh
python3 -B scripts/ci/tools-native/freeze.py --source "$PWD"
python3 -B -m unittest discover -s scripts/ci/tools-native -p test_native.py
```

The first command freezes local source hashes, exact recipe metadata,
license inputs, installed payload mappings and dependency references, then
fills the manual workflow's two checksum markers. It never builds, installs
or launches a container. A later source change requires Root to refresh the
binding explicitly. The workflow's source SHA must equal its workflow SHA;
no future commit is hardcoded. It uses its own
`native-arm-tools-candidates` concurrency group with cancellation disabled.
It reuses only the existing retained-input secret route and fourteen-file
public seed checkout. No new input package or dependency fetch is added.

The actual native consumer verifies the complete 574 inventory and native
daemon/image architecture. `pacman -T` checks the three tools' runtime,
build and check dependencies already exist; makepkg independently checks
them. Each package gets two distinct, offline, read-only clean build
containers using the unchanged accepted builder entry. Generated metadata,
PKGINFO/BUILDINFO, source hashes and exact installed payload type, mode,
owner and file hashes are bound to the reviewed recipes. All payload and
complete archive bytes must reproduce. The packages are scripts/data and
must contain no ELF. Failed packages remain failures for the whole lane.

One disposable native ARM container then performs five real ALPM
transitions: install, same-version reinstall, remove, reinstall after removal,
and final remove. Inventory must be exactly 577 when installed and exactly 574
when removed. Files and ALPM ownership are checked at each installed phase.
Existing `.zshrc`, `.zshenv`, history, a configuration symlink, mirror
preferences and system mirror/Zsh configuration are preserved, including
content, mode, ownership and recorded timestamps. Generated fixture paths
live outside those protected homes; created candidates and substring
receipts must survive subsequent package transitions unchanged.

Installed behavior is exercised as an ordinary fixture user:

- Mirrors runs its real CLI against an owned loopback HTTPS server inside
  `--network=none`, using an ephemeral private test CA. It checks an exact
  snapshot, a mismatched snapshot, all-failed/no-output, version/help,
  no overwrite and symlink refusal. It activates a candidate only at an
  explicit private fixture target, restores preexisting bytes/mode/owner, verifies repeated activation and
  restoration preserve the recorded target,
  refuses a restore after a third-party edit and refuses a symlink target.
  These are local fixture trust and activation checks; no public mirror,
  host trust store, live pacman configuration or external ranking is used.
- Syntax highlighting uses the existing owned PTY transport to check real
  installed ZLE highlighting, custom keybinding preservation, repeated
  source, noninteractive no-op, preexisting module precedence and natural
  shell exit0.
- Substring search runs the final product's actual fixture driver against
  the installed module and installed highlighting wrapper. All six real
  PTY cases, including coexistence, must pass. Its standalone HOST labels
  remain unchanged. The outer receipt separately records actual aarch64
  execution, page size, source hashes and container/image provenance.

There are eight owned consumer containers: one probe, six clean builds and
one lifecycle. Names are persisted before launch and labeled with the
source/run-bound consumer token. An exclusive consumer lease prevents
cleanup racing active work. The always-run cleanup validates each actual
container name, ID, image and label, removes only that confirmed ID and
verifies absence before invoking the existing producer cleanup. Unknown or
foreign state fails cleanup and preserves the producer. An interrupted run
retains partial diagnostics and cannot earn candidate acceptance.

One closed 192 MiB artifact includes source proof, exact source/license
files, lane harness, both package archives per tool, build metadata and
logs, lifecycle receipts, inventory and ordered cleanup. Per-file bounds
and the aggregate bound are enforced; arbitrary build output, private CA
keys, caches, HOME contents and container layers are excluded. Acceptance
requires all six archive hashes, byte comparisons, native behavior,
preservation and all eight consumers plus producer retired.

Current implementation/source controls are separate from actual native
execution. Native builds, installed lifecycle, external mirror results,
hardware behavior, performance, signatures and release admission remain
`NOT_RUN` until their corresponding evidence exists. An aarch64 CI run
does not establish M2 or 16K execution; the receipt records the actual page size.
