# Fish 0.1.0-2 upgrade and restoration on Overlay583

This is a separate source and passive input lane for the existing offline
Overlay583 actor. The baseline is the verified 583-package stage with
Fish 4.9.3-1, Setup8 0.3.0-1, and the signed Fish config 0.1.0-1 package.
Exactly one inventory row changes to 0.1.0-2. Installation and restoration
are ordinary pacman transactions with Required TrustedOnly and the guest's
existing hooks and scriptlets.

The guest creates a distinct ordinary account and seeds a private Fish config
with an original user edit. Installed Setup8 activates Fish once, appending
its standard source block pointing to the installed template. Three fresh
scripted interactive Fish startups under that same account run identical
caa_mcd code with a conflicting CDPATH directory containing a space. The
original version must create the local directory but enter the conflicting
CDPATH directory. The successor must enter the newly created local directory
with CDPATH unchanged. Restoration must reproduce the original behavior.
The activated private config bytes, owner and mode must agree at every
phase. Setup8 is never reapplied to make a phase pass.

The rollback is the exact 7,220-byte repository archive and its original
119-byte detached signature. The guest explicitly checks the existing
overlay signer and restores that same archive with pacman. Each phase checks
the full inventory and exact ALPM Fish file ownership. The before/restored
local databases must match after normalizing only the one selected package
install date. Every unrelated retained local ALPM file stays byte-identical.
The original addon pacman log must record exactly one upgrade and its inverse
downgrade. Raw signature, pacman and Fish output are retained with the phase
and whole source pack pins.

## Held R127 provenance and future preparation

R127 on Source 346e897f1b3a0fa273fa74d3331363b6f39b6436, run 44239472740,
retained two byte-identical 5,516-byte archives with SHA-256
6dee81130f3ba3e570791cf079d2152893461ec27fa6e2e34a3d614986f9a949.
The exporter omitted the two raw check logs and the terminal held. Both log
bodies were later recovered from the original build transcripts and matched the
pair's whole-log hashes. The R127 archives support offline controls. The stage
requires an independently closed native PASS for installation.

Once Root has independently qualified the intended native pair, retain both
original package files and both raw successful semantic check logs as separate
files. Bind the original independent Root closure and a canonical qualification
of kind ROOT_FISH02_NATIVE_PAIR_FOR_OVERLAY583_UPGRADE_V2. The qualification
has status PASS, issuer Root, actual source and run, architecture aarch64,
package_architecture any, and the whole original closure pin under closure.
Its builds rows are ordered 1 and 2. Each has build, clean true, checks PASS,
the identical whole archive pin under archive and that build's raw check_log
pin. Every pin has bytes and sha256. The original closure must affirm the
same exact Source, run, package archive, native build and byte comparison,
both builds' custody and cleanup, and native_pair PASS. Missing evidence or
a held closure is refused independently of the qualification's status.
The same contract accepts a later independently qualified exact Source and
run without changing the worker. Preserve the original R127 HOLD.

A separately approved disposable TEST certificate and detached signature
must accompany the exact selected archive. Supply the full primary
fingerprint and its created and expires UTC epochs from the public certificate.
The stage accepts public packet types only. Bind requires more than the whole
guest time budget remaining. The guest checks the actual certificate's dates,
fingerprint and TEST identity before verifying the exact detached signature
and enabling trust.

The following are passive commands.

    python3 -I -B scripts/integration/fish_config_overlay583/operands.py baseline \\
      --staging "$staging" --preflight "$preflight"

    python3 -I -B scripts/integration/fish_config_overlay583/operands.py stage \\
      --staging "$staging" --preflight "$preflight" \\
      --archive "$build_1" --matching-archive "$build_2" \\
      --qualified "$root_qualification" --qualified-sha256 "$qualification_sha256" \\
      --native-closure "$independent_native_closure" \\
      --check-log "$build_1_check" --matching-check-log "$build_2_check" \\
      --signature "$test_detached_signature" --public-key "$test_public_certificate" \\
      --signer "$test_fingerprint" --signer-created "$test_created_epoch" \\
      --signer-expires "$test_expires_epoch" --output "$supplement"

    python3 -I -B scripts/integration/fish_config_overlay583/bridge.py \\
      --staging "$staging" --preflight "$preflight" \\
      --supplement "$supplement" --supplement-sha256 "$supplement_sha256" --nonce "$nonce"

## Root-owned controller

Use the existing qualified controller image and mount the supplement read-only.
Select the Fish operation with its own path and whole manifest SHA-256. This
selection is exclusive with the other addon and upgrade operations, lifecycle,
and signature recovery. The passive bind is separate from Root issuance.

    python3 -I -B scripts/install/overlay583_trial/controller.py bind \\
      --staging "$staging" --preflight "$preflight" --kernel "$kernel" \\
      --config "$kernel_config" --baseline "$baseline" --output "$output" --nonce "$nonce" \\
      --fish-upgrade "$supplement" --fish-upgrade-sha256 "$supplement_sha256"

    python3 -I -B scripts/install/overlay583_trial/controller.py run \\
      --authority "$root_issued_selection" --authority-sha256 "$root_issued_selection_sha256"

The guest receives only the selected Fish supplement under the read-only
code media directory /trial-code/fish-upgrade. The normal signed repository
media also contains the original rollback archive. After its verified
baseline install, the guest admits an exact ordered callback ledger and
checks hooks immediately after both pacman transactions. The original
fish-upgrade.json leaf includes the bounded raw addon pacman log, all
original command streams, and typed independent readback. A HOLD retains
its original scratch disk and evidence. The Root launcher uses the existing
qualified child-container and QEMU identity checks and scope retirement
observations. The offline flags and resource envelope are inherited.

The passive join and source tests can run without a guest. The focused suite
uses the exact retained R127 members and original Setup8 and Fish templates
in unprivileged temporary host fixtures. It runs no pacman operation or VM.
This evidence is separate from the future installed ARM16K result.

    CAA_OVERLAY583_STAGING="$staging" CAA_OVERLAY583_PREFLIGHT="$preflight" \
      CAA_FISH_R127_EVIDENCE_DIR="$r127_evidence" \
      python3 -I -B scripts/integration/fish_config_overlay583/test_upgrade.py
    python3 -I -B -m unittest discover -s scripts/install/overlay583_trial -p 'test_fish_upgrade.py'

The focused selection and refusal tests run without local archive artifacts.
The real host startup checks require the retained Overlay583 and R127 inputs.
