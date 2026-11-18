# Offline 583-package install trial

This harness targets the development staging assembled against Main
`8427a33c2fa89ed0bfc1b80439a03e64129ababc`. It selects 574 ALARM base packages
and nine overlay packages by their staged bytes. The retained preflight
authenticates those inputs and resolves all 583 repository-qualified packages.

## Inspect the selected staging

```sh
stage=/absolute/staged-overlay583
receipt=/absolute/preflight-evidence/retained583.json
python3 -I -B scripts/install/overlay583_trial/trial.py prepare \
  --staging "$stage" --preflight "$receipt" \
  --preflight-sha256 efbd1147613ab68721a05268c7973282936b5b61de09268c84f473b02566a3c7
```

This emits a read-only handoff with whole-file pins for the repository
operands and public trust exports. The retained receipt records preflight
authentication and leaves transaction authorization and installation false.

## Connect a disposable ARM VM

The r118-based controller is `controller.py`. In the Root-owned offline
tool image, `bind` emits the candidate authority for the selected kernel,
reference disk, staging, worker and nonce. Root issues that selection
separately. The transaction entry is `controller.py run --authority
<selection> --authority-sha256 <sha256>`. It uses a read-only derived boot
disk, a 2 GiB read-only input disk, 16 GiB scratch, and a 64 MiB evidence disk.

Load `trial.py` and the maintained `scripts/virtual/owned_process.py` as Python
modules. Wrap the controller in `trial.OwnedVMAdapter` and use
`trial.run_owned` from the controller's authorized entry point when adapting
another VM owner.

```python
executor = trial.OwnedVMAdapter(
    owned_process,
    authenticate=controller.authenticate_selection,
    launch=controller.launch,
    export=controller.export_evidence,
    absent_twice=controller.require_absent_twice,
)
trial.run_owned(
    executor,
    staging=staging_path,
    preflight=receipt_path,
    preflight_pin=receipt_pin,
    nonce=fresh_nonce,
    selection=selected_vm_authority,
)
```

- `authenticate_selection(selection, *, plan_sha256, worker, nonce)` must
  authenticate the selected VM authority and bind the plan, worker pin, and
  fresh 32-character lowercase hexadecimal nonce before launch.
- `launch(*, staging, worker, worker_pin, plan, kernel_argument, argv)` must
  start a new offline aarch64 VM with Python 3, pacman, GnuPG and gpgconf.
  Mount staging directly at `/trial-inputs` and the pinned worker and plan
  directly under a `/trial-code` mount, both read-only. Mount fresh empty
  guest-only scratch at `/trial-work` on a separate device with at least
  12 GiB available. Pass the kernel argument at VM boot and run the given
  argv as guest root. Return an owned `Popen` child in a new session with
  piped stdout and stderr for the supervisor. Propagate guest failure to
  the launcher's exit status.
- `export_evidence(observation)` returns the absolute, private local
  directory containing the original files from `/trial-work/evidence`
  after natural guest retirement. `require_absent_twice(nonce)` must raise
  unless independent checks confirm the selected VM and its owned resources
  have retired.

The guest rehashes the offline inputs, imports the three selected public
trust exports into its private keyring, and refreshes the two file
repositories with signature enforcement. It compares the resolved package
versions and origins, runs the normal pacman install with hooks and
scriptlets enabled, then compares the installed inventory byte-for-byte to
`target.lock` and checks the local database. The controller reopens the
guest logs and exact lock after retirement.

## Rehearse removal and reinstall

Add `--lifecycle` to `controller.py bind` when creating a new selection.
The Root-issued selection binds that flag and the longer command plan.
Use the normal `run --authority … --authority-sha256 …` entry with a fresh
output path and nonce. The controller first establishes the exact 583-package
inventory and verifies the local database. It continues on that same scratch
target in the offline guest.

1. Pacman previews a plain removal of the nine names in the authenticated
   overlay. The guest compares the preview to their exact name/version rows
   before running the removal.
2. The guest checks the local database and compares the sorted inventory
   byte-for-byte with the pinned `base-repository/installed-inventory.lock`
   for the authenticated 574-package base.
3. The guest verifies the repository, name and version of each proposed
   reinstall. Pacman installs the nine repo-qualified packages using the same
   signed file repositories and a separate empty cache. The guest compares
   the result with `target.lock` and checks the local database again.

The controller reopens the previews, command logs and the three lock
snapshots after natural guest retirement. If a stage fails with a guest
receipt, the report records `HOLD_DISPOSABLE_OVERLAY583_LIFECYCLE`, the
failed stage and any earlier verified locks. The command exits nonzero and
keeps the original evidence disk, serial logs and private scratch disk.
Earlier bootstrap or export failures also leave the raw disks and logs
already created by the controller. Use a fresh selection for another run.
The rehearsal covers package inventory and local database consistency in a
disposable guest. Asahi installation, hardware validation and release
acceptance remain separate.

## Rehearse signature refusal and recovery

Bind a fresh selection with `controller.py bind --signature-recovery`.
This includes the lifecycle and adds one negative control after the
verified 574-package state. The guest copies the selected
`cachy-asahi-fish-autopair` archive to private scratch, confirms that the
copy has the pinned bytes, and gives pacman the archive without its detached
signature. It uses the same private keyring and `LocalFileSigLevel = Required
TrustedOnly`. The controller requires exit 1 and the missing-signature
diagnostic for that exact copy.

The guest fingerprints the files in the local package database immediately
before and after the attempt. It proceeds only if those fingerprints match,
the exact 574-package lock survives, and the database check passes. It then
reinstalls all nine packages from the original signed repositories and
verifies the final 583-package lock and database. The report pins both
database snapshots and records the original refusal and package inventories.
An unexpected outcome stops at HOLD and retains the original evidence.

The passive preparation ran against real staging. The focused fixture suites
exercise the plan, ownership bridge, controller and evidence readers without
launching an actor. Root issuance and the first real transaction remain
pending. This trial measures package installation and pacman inventory in the
scratch target. Root acceptance, installed Asahi, and M2 hardware results are
unset.
