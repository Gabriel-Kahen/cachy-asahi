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
The independent terminal is CLOSED_R127_FISH_RAW_CHECK_LOG_EXPORT_HOLD because
the required raw check logs were unavailable. These archives are source test
inputs. The stage refuses the retained HOLD receipt. This lane has no new
signature, guest authority or attempted installation.

Once Root has independently qualified the intended native pair, retain both
original package files separately. Supply a canonical Root qualification
with kind ROOT_FISH02_R127_NATIVE_PAIR_FOR_OVERLAY583_UPGRADE_V1, status PASS,
issuer Root, source and run above, architecture aarch64, package_architecture
any, the independent closing receipt's bytes and sha256 under closure, and
two builds rows. Each row has build 1 or 2 in order, clean true, checks PASS,
and the identical whole archive pin under archive. If the qualification
instead uses a later Source or run, repin those exact two reviewed operands
in operands.py before using the later result. Keep the original R127 HOLD.
A separately approved disposable TEST certificate and detached signature
must accompany the exact selected archive. The stage accepts public packet
types only and the guest verifies the actual certificate and signed archive
before enabling trust.

The following are passive commands.

    python3 -I -B scripts/integration/fish_config_overlay583/operands.py baseline \
      --staging "$staging" --preflight "$preflight"

    python3 -I -B scripts/integration/fish_config_overlay583/operands.py stage \
      --staging "$staging" --preflight "$preflight" \
      --archive "$build_1" --matching-archive "$build_2" \
      --qualified "$root_qualification" --qualified-sha256 "$qualification_sha256" \
      --signature "$test_detached_signature" --public-key "$test_public_certificate" \
      --signer "$test_fingerprint" --output "$supplement"

    python3 -I -B scripts/integration/fish_config_overlay583/bridge.py \
      --staging "$staging" --preflight "$preflight" \
      --supplement "$supplement" --supplement-sha256 "$supplement_sha256" --nonce "$nonce"

## Existing owner integration

The shared controller in this worktree still exposes its existing operation
modes. Connect this worker at the same finite post-install addon seam used
by first-login and the local llhttp successor. Bind separate fish-upgrade
path/digest flags and exclude the existing alternative modes. Bind the exact
source files and whole supplement, construct the plan through bridge.selected_plan,
and mount only its selected files under the read-only /trial-code/fish-upgrade
directory on the existing code media. Keep the signed repository media intact,
including the original rollback archive.

After the existing authenticated normal 583 install and database check,
invoke guest.run with the same deadline-aware command callback used by the
other addon. The callback must require the roles in guest.command_plan in
order, retain both original streams, and run the existing hook-failure check
immediately after fish-upgrade and fish-restore. Use guest.evidence for the
separate bounded fish-upgrade.json leaf on the existing evidence disk. The
guest must retain its raw disks and phase on HOLD. Reopen the source-pinned
worker and original result disk after natural QEMU exit and pass the addon
blob to guest.readback. In the current Root-owned launcher pattern, qualify
the selected child container and QEMU identity and observe both containers
and the selected scope absent twice. Keep the usual offline flags, actor
authority and resource envelope.

The passive join and source tests can run without a guest. The focused suite
uses the exact retained R127 members and original Setup8 and Fish templates
in unprivileged temporary host fixtures. It runs no pacman operation or VM.
This evidence is separate from the future installed ARM16K result.

    python3 -I -B scripts/integration/fish_config_overlay583/test_upgrade.py
