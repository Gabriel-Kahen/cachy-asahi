# Offline 583-package install trial

This harness targets the development staging assembled against Main
`8427a33c2fa89ed0bfc1b80439a03e64129ababc`. It selects 574 ALARM base packages
and nine overlay packages by their staged bytes. The retained preflight
authenticates those inputs and resolves all 583 repository-qualified packages.

## Inspect the selected staging

```sh
stage=/home/gabe/Documents/ChatGPT/cachy-asahi-staging-install-lock-20261117-overlay583
receipt=/home/gabe/Documents/ChatGPT/cachy-asahi-staging-install-lock-20261117-preflight583-results/retained583.json
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

The passive preparation ran against real staging. The focused fixture suites
exercise the plan, ownership bridge, controller and evidence readers without
launching an actor. Root issuance and the first real transaction remain
pending. This trial measures package installation and pacman inventory in the
scratch target. Root acceptance, installed Asahi, and M2 hardware results are
unset.
