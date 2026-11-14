# Finite Perl candidate ALPM lifecycle

This original route tests the exact unsigned x86 source-built Perl candidate
archives retained from r3 (`5.42.3-1.1`) and command-delivery repack (`1.2`). It
creates private TEST signatures and trust entirely inside a disposable container.
These TEST signatures provide no production repository trust or historical ALARM
source correspondence. Existing r3/repack evidence and package bytes stay intact.

`run.py` requires the exact archive hashes and pinned composition image
`sha256:30cfe09952ef8d9bfabd64224185c97021b260d47bb83941fec5bae7bdd16145`.
It copies inputs into owned container layers with `docker cp`; it accepts no
caller bind mounts, volumes, network, host devices or privileged mode. Each
container has 2 CPU, 4 GiB memory, 256 PIDs, six explicit capabilities and
no-new-privileges. A fixed inert PID1 expires after 300 seconds; the test child
has a 165-second aggregate budget and Docker execution a 180-second outer bound.
Existing `lifecycle.bounded_process` handles bounded pipes and child retirement.
The controller removes only its own two containers and derived image and verifies
their absence; failed cleanup makes the overall result fail.

The pinned base has no Perl. Its only missing candidate prerequisite is exact
Arch `db5.3 5.3.28-7`. Preparation joins its bytes and signature to frozen
November 8, 2026 `core.db`, verifies the official signature with the image's
existing Arch keyring, and installs it offline with full dependency checking.
No other package is changed. All 25 preinstalled ALPM hooks are masked by exact
name, and mutation commands use `--noscriptlet`. No package/dependency operation
ever runs on the host. Existing repository, virtual inventory and glibc ELF
source helpers are copied unchanged and pinned in the private input manifest.

The TEST lifecycle establishes r3/1.1 as its installed predecessor, alongside a
separately signed synthetic ownership fixture. It checks:

- Unknown signer refusals against initialized private keyrings, before install
  and with r3 installed; inventory, selected payload and sentinels stay exact.
- Signature-specific tamper refusal with the same preservation checks.
- Actual `1.1 → 1.2 → remove → reinstall 1.2 → retained rollback 1.1 → remove`.
- Exact installed archive payloads and ALPM ownership of all 29 PATH aliases;
  complete selected file absence after both removals.
- Actual invocation of all 29 tools, core conversions/generators/documentation,
  `prove` child interpreter/XS checks, and 113 provider/five core C-extension checks.
- A bounded 270-symbol Perl/libperl-to-host-glibc name/version join, using the
  existing source-only ELF helpers. This does not qualify target ABI.
- Operator local commands/modules/XS sentinels and profile, plus separately
  package-owned vendor commands/modules/XS sentinels and modified fixture config.
  These bytes, modes, ownership and inodes survive candidate upgrade/rollback;
  bytes/modes/ownership also survive Perl removal. XS sentinel files are
  deliberately inert preservation data, not functional external XS modules.
- Actual `.pacsave` creation/preservation for the TEST fixture's modified backup
  configuration. Perl itself has no backup entries; no Perl `.pacsave` result
  is claimed.

The final runtime inventory matches the prepared 140-package baseline. The
139-package base image is preserved, and the derived prerequisite image is
removed. The retained r3 archive and its newly generated TEST signature are an
actual rollback asset. No original Arch Perl rollback asset is substituted;
that image initially has no Perl. Production/base upgrade support remains HOLD.

Example using already-retained, hash-verified inputs:

```sh
python3 -I -B scripts/integration/perl_candidate/run.py \
  --candidate /absolute/path/to/perl-5.42.3-1.2-x86_64.pkg.tar.zst \
  --old /absolute/path/to/retained-r3/perl-5.42.3-1.1-x86_64.pkg.tar.zst \
  --prerequisites /absolute/path/to/frozen-prerequisites \
  --output /absolute/path/to/fresh-private-output
python3 -I -B -Werror::ResourceWarning scripts/integration/perl_candidate/test_run.py
```

The prerequisite directory contains the exact `db5.3` archive/signature,
`core-20261108.db` and `prerequisite.json`; their pins are in `run.py` and the
validation record. The controller downloads nothing. Public TEST certificate,
archive signatures and bounded command receipts are retained, while all private
keyrings are killed/deleted before successful completion and the containers are
removed. `validation.json` records the actual run and prior failed/refined trials.

This remains an x86_64/4K disposable software component. External XS ABI,
actual supported-base upgrades, native ARM/16K, M2 hardware, production signing,
performance and release admission are separate unfinished gates. `ptardiff`
still refuses without optional Text::Diff; its archive comparison is not tested.
