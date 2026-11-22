# Cachy-Asahi branch archive

This archive records the GitHub branch tips as observed on November 22, 2026.
[github-branch-tips.tsv](github-branch-tips.tsv) maps each original branch name
to its exact commit. The archive's parent history retains those commits and
their trees. Each line starts with the commit SHA, followed by the full branch
ref.

Four additional historical Actions source commits are listed in
[historical-actions-sources.tsv](historical-actions-sources.tsv).

Fetch the archive with `git fetch origin tag archive/branches-2026-11-22`.
Inspect any archived source with `git show <commit>` or restore its original
branch with `git branch <branch> <commit>`. The archive tree contains the index
only. Archived branches include experiments, refused runs, and superseded
install candidates. Consult the original validation record before using one.

## Historical pull requests

- [#7](https://github.com/Gabriel-Kahen/cachy-asahi/pull/7) and [#11](https://github.com/Gabriel-Kahen/cachy-asahi/pull/11) used an earlier maintained
  composition. Later signed Overlay583 and Asahi626 rehearsals are in the
  repository's validation documentation.
- [#8](https://github.com/Gabriel-Kahen/cachy-asahi/pull/8), [#9](https://github.com/Gabriel-Kahen/cachy-asahi/pull/9), [#10](https://github.com/Gabriel-Kahen/cachy-asahi/pull/10),
  [#14](https://github.com/Gabriel-Kahen/cachy-asahi/pull/14), and [#15](https://github.com/Gabriel-Kahen/cachy-asahi/pull/15) covered early ARM tool
  observations, callers, and package pairs. Later integration uses the tool
  recipes and signed ARM trials on main. The original native sources stay
  available in this archive.
- [#12](https://github.com/Gabriel-Kahen/cachy-asahi/pull/12), [#16](https://github.com/Gabriel-Kahen/cachy-asahi/pull/16), and [#23](https://github.com/Gabriel-Kahen/cachy-asahi/pull/23)
  covered experimental signer, compiler, and installer transport. The
  recorded installer container trial failed during the Docker proc mount.
- [#18](https://github.com/Gabriel-Kahen/cachy-asahi/pull/18), [#19](https://github.com/Gabriel-Kahen/cachy-asahi/pull/19), and [#21](https://github.com/Gabriel-Kahen/cachy-asahi/pull/21) were
  diagnostic branches for older FDK, updater, and KSM work. Later validation
  uses the canonical FDK pair, Updater607, and KSM2.
- [#20](https://github.com/Gabriel-Kahen/cachy-asahi/pull/20), [#24](https://github.com/Gabriel-Kahen/cachy-asahi/pull/24), and [#25](https://github.com/Gabriel-Kahen/cachy-asahi/pull/25)
  covered archived JBIG/TIFF trials. [#13](https://github.com/Gabriel-Kahen/cachy-asahi/pull/13) carries the original
  candidate and canonical gzip commits.
- [#26](https://github.com/Gabriel-Kahen/cachy-asahi/pull/26), [#27](https://github.com/Gabriel-Kahen/cachy-asahi/pull/27), and [#28](https://github.com/Gabriel-Kahen/cachy-asahi/pull/28)
  covered historical screenshot trials. The accepted region-cancel source
  and run are recorded under `docs/reviews` on main, with later product-source
  improvements in [#367](https://github.com/Gabriel-Kahen/cachy-asahi/pull/367) and [#496](https://github.com/Gabriel-Kahen/cachy-asahi/pull/496).
