# NetworkManager candidate TEST repository journey

This finite integration installs the four actual unsigned x86_64
NetworkManager `1.58.1-2.1` source-candidate archives in a copied ALPM root
inside a fresh disposable container. It is x86 software integration only;
it does not qualify ARM/16K, an Asahi installation, M2, release promotion,
legal acceptance, or the historical ALARM `1.58.1-2` source correspondence.
It neither selects packages nor changes existing candidate recipes.

## Explicit execution

Use an ordinary host user with Python 3.11+ and Docker and the exact retained candidate archives:

```sh
python scripts/integration/networkmanager_candidate/run.py \
  --allow-disposable-x86-TEST-journey \
  --archives work/networkmanager-source-candidate-20261114/archives \
  --output work/networkmanager-candidate-journey-20261114/new-run
```

The output must not already exist. The launcher verifies all four archive
sizes/SHA256s against the source candidate's committed `validation.json` before
copying them into a private image context. It requires the retained prerequisite
image `cachy-asahi-nm-source-final:20261114` at exact ID
`sha256:7052baf57a6eec068371ffdb2f9670ef69bd5ce11ee3ba67f705b724dc8a53d5`.
That image descends from the official pinned Arch base and frozen prerequisite
DBs documented by the candidate. There is no image pull, dependency acquisition,
version substitution or installation fallback in this integration. A missing or
different image is a hold. The local tag is checked before/after the COPY-only
build, and the resulting base layer prefix must match. An initial attempt to
address this local image by a registry-style digest failed resolver lookup;
the working path uses the verified local tag with `--pull=false`.

The fresh runtime uses network `none`, 2 CPUs, 4 GiB, 256 PIDs, no privilege,
no caller mounts, no host bus or hardware devices, no-new-privileges, and only the existing
repository helper's six ALPM capabilities. Standard Docker metadata, ordinary
character-device and read-only docker-init runtime mounts remain and are checked
explicitly. A 450-second guest deadline and 520-second host wait bound execution;
the COPY-only image build has its own 180-second bound. Core dumps are disabled; optimized
Python is refused. No host package or configuration is installed or changed.
The container is removed even after failure; public reports/logs remain in the
requested output directory. Secret TEST key homes are cleaned inside the guest
and never exported. The one-run private image tag is also removed.

## Actual operations and checks

`journey.py` reuses the existing `scripts/integration/repository.py` TEST key,
signature validation, local trust, signed repo-add, command receipts, copied-base,
hook masking, payload-state and inventory helpers. It does not invoke or alter
that helper's ARM actor guard, frozen policy or generic fixture journey. This
adapter explicitly supplies x86 policy in its own private configuration.

All transactions use the genuine package manager, a complete copied base's local
ALPM DB, strict required/trusted package and DB signatures, and a single private
`file://` repository. Every package gets a new disposable TEST signature; TEST
trust is confined to the private verifier home. There is no `--nodeps`, db-only
installation, simulated transaction, source/build execution or shared keyring.

1. Reject the unknown TEST DB signer with exact inventory/observed files intact.
   The unknown-key case reports a failed remote key lookup inside the no-network
   namespace; no key was acquired. It does not establish freshness.
2. Explicitly trust that TEST signer, then reject a byte-tampered real package
   against the unchanged authenticated DB; preserve inventory/observed files.
3. Restore exact pinned bytes and install all four real candidates. Check the
   complete baseline-plus-candidates inventory, `pacman -Dk`, exact ownership of
   every non-directory archive leaf, bytes, mode, UID/GID and symlink target.
4. Run installed `nmcli --version` and installed GIR/libnm pure
   `NM.SettingWired` construction in the copied root. No daemon, `NM.Client`,
   connection, service, live bus or network operation is run.
5. Edit the package backup config, remove all four packages, verify `.pacsave`,
   final leaf absence, base inventory/dependencies and unrelated/user state.
6. Reinstall, verify original payload, explicitly recover the saved config, then
   repeat the same-version install and require the user edit to survive.
7. Remove all four again; require every package-owned leaf and ALPM entry absent,
   user config saved, and unrelated files/base inventory intact.

The input reader rejects `.INSTALL`, ALPM hooks, privileged modes, escaping
links, special files, duplicate paths, wrong identities/architecture and live
state/connection/DNS payloads. Every candidate leaf must initially be absent, preventing overwrite of base files.
Copied base hooks are masked by name with
`/dev/null`; every transaction uses `--noscriptlet`. This deliberately does not
qualify normal system hook/scriptlet behavior. Any package manager internal
ldconfig/cache work is confined to the copied root. Candidate units and the OVS
docs example are verified as inert payload; no service start/enable occurs.
Package directories may remain because they contain user-owned files; all
package-owned files/symlinks must be absent after removal.

## Validation

```sh
python -m unittest discover -s scripts/integration/networkmanager_candidate -p test_journey.py -v
```

These four small DATA controls exercise raw archive refusals and final absence.
They do not substitute for the explicit real journey above. `validation.json`
records the actual 61-command successful journey and the exact public report and
source pins. The private diagnostic directory also retains earlier adapter
failures, including mount inventory and verifier initialization ordering; those
failures were not candidate recipe defects. No candidate source changes were
needed.
