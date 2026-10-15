# repo-add signature compatibility correction

Source correction is implemented and locally validated against published8806fe7. The hosted failure38660953536 remains retained FAIL:82 release tests,40 errors from Ubuntu6.0.2 rejecting --include-sigs. No new hosted result is claimed.

The release stage now reads actual repo-add version/help before its single database command. Closed6.0/6.1/7.0/7.1 contracts preserve6.0 default signature embedding and require the option for known6.1+ even when help omits it. Unknown versions/probe failures refuse; actual command failure never triggers retry. Official [6.0.2 archive](https://sources.archlinux.org/other/pacman/pacman-6.0.2.tar.xz) and [6.1.0 tagged Source](https://gitlab.archlinux.org/pacman/pacman/-/raw/v6.1.0/scripts/repo-add.sh.in?inline=false) are byte-pinned in the capsule. Final acceptance requires database PGPSIG to equal the exact verified detached package signature bytes.

Actual local release29 targeted tests and full release86/client109 pass with no skips. New controls cover both tool branches, malformed/unknown versions, probe/command first errors without retry and four actually re-signed database signature substitutions. Stage.py changes onlytwo release/test hash pins; all count/ID/lifecycle/authority behavior stays held.

Evidence, complete three-file copy map and seal are in `artifacts/reviews/repo-add-signature-capability-correction-20261014/`. Verify with `python -B artifacts/reviews/repo-add-signature-capability-correction-20261014/verify.py`. Fresh independent peer is required before Root commit/publication; Root owns the changed hosted CI run. No Docker/native worker, production trust, installation or hardware acceptance is established.
