# Root ownership for recovery archive inputs

The genuine Source8a run `42492333977`, attempt 1, failed during recovery preparation. Root's selected original `actor-logs/0025.log` is 22,814 bytes, SHA256 `794b76b494660da482b244d99d931064c9b2ea23e7d216386cc8514139b71feb`. All three makepkg stages completed; the traceback reaches the recovery archive-copy loop and its strict ordinary-input predicate. The log does not record the failing iteration or stat values. Its last-command phase `verify-test-signature` precedes recovery preparation; it does not establish signature failure.

The producer runs makepkg as `alarm`, then copies three archive files between image stages. Recovery requires regular, single-link, root UID/GID, nonempty bounded inputs and a stable descriptor/path read. Cross-stage copies previously omitted ownership. Root's primary implementation review found that BuildKit applies `llb.WithUser` only when COPY chown is supplied, and a nil backend chowner preserves source UID/GID. This predicts an archive ownership refusal, rather than measuring the failed file's actual UID/GID. The generic Docker context-copy default does not replace the cross-stage implementation evidence.

The proposed correction adds numeric `--chown=0:0` to exactly the prior archive and two current archive COPY directives. All makepkg stages still run as `alarm`; stage-slot copies and every strict recovery input guard remain unchanged. Package contents and archive byte comparison are unaffected by changing the outer archive file's ownership. The genuine Source8a publication, v11 branch, run, Original ZIP and consumed matching14 role remain historical evidence, not reusable roles.

The updated finite factory profile proposes v12 with 209 leaves and 208 map rows. Its expected map is `4faca949a9caa2f09c4ec0b1bb0d2b5fef2a24d709c3f612a61687d93964448b`, expected Git tree `6e6660003155b24307d7e3cd8780d7f1a27f77bc`. Actual source/run/job/artifact fields remain null. Updating `prepare.py` changes only its whole-profile SHA256 literal to `0e088421affc5c670bb6e7c6944593c29a3430acee678cf83f66cebe893928e1`.

Seven new focused controls pass: exact emitted archive ownership and unchanged remaining recipe; accepted ordinary root-owned fixture; nonroot UID/GID refusal; hardlink/symlink refusal; FIFO/empty/oversized refusal; changed-input refusal; and profile/payload/map/hash consistency. Guard fixtures execute only isolated function definitions against temporary files, with descriptor-owner stats supplied explicitly; they do not claim real root ownership on the development host. Opened descriptors close on acceptance and refusal. The full previous recipe digest, after removing exactly the three new flags, is retained by the renderer control.

Run these controls with:

```sh
python -B -m unittest discover -s scripts/ci/security-maintenance-native-source/recovery-v1/tests -p test_archive_root_ownership.py -v
```

The 15 focused factory DATA controls also pass against the authenticated Source850 directory, with assembler/emitter replaced by a refusal function and the actor-denying audit hook active. These verify the changed profile and independent tree calculation plus input-tampering refusals. Discovery finds 87 HOST controls; the runner and CI literals now expect 62 original + 110 new = 172 total. The full 172-control suite was not replayed locally.

No Docker build, GPG, pacman, Source constructor/publication, native run, archive reopen or Reader execution was performed for this correction. A fresh Root-owned Source publication and native run must establish whether it clears the observed failure; hardware compatibility and native recovery acceptance remain unproven.

Primary implementation basis supplied by Root: [BuildKit COPY conversion](https://raw.githubusercontent.com/moby/buildkit/master/frontend/dockerfile/dockerfile2llb/convert_copy.go), especially `cfg.chown`/`llb.WithUser`; Root also inspected [backend `mapUserToChowner`](https://raw.githubusercontent.com/moby/buildkit/master/solver/llbsolver/file/backend_unix.go) and [fsutil file-copy ownership handling](https://raw.githubusercontent.com/tonistiigi/fsutil/master/copy/copy_linux.go). These upstream links describe implementation and are not pinned native test evidence.
