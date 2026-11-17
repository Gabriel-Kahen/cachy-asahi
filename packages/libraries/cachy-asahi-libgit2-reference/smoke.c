/* SPDX-License-Identifier: MIT */
#include <git2.h>
#include <stdio.h>
int main(int argc, char **argv) {
  git_repository *repo = NULL;
  git_oid oid;
  int major, minor, revision, features;
  if (argc != 2 || git_libgit2_init() < 0) return 1;
  git_libgit2_version(&major, &minor, &revision);
  features = git_libgit2_features();
  if (major != 1 || minor != 9 || revision != 7 ||
      (features & (GIT_FEATURE_THREADS | GIT_FEATURE_HTTPS | GIT_FEATURE_SSH)) !=
      (GIT_FEATURE_THREADS | GIT_FEATURE_HTTPS | GIT_FEATURE_SSH)) return 2;
  if (git_repository_init(&repo, argv[1], 1) < 0 || !git_repository_is_bare(repo)) return 3;
  if (git_blob_create_from_buffer(&oid, repo, "hello\n", 6) < 0) return 4;
  git_repository_free(repo);
  repo = NULL;
  if (git_repository_open(&repo, argv[1]) < 0) return 5;
  git_repository_free(repo);
  if (git_oid_fromstr(&oid, "invalid") == 0) return 6;
  if (git_libgit2_shutdown() != 0) return 7;
  puts("libgit2: version/features, repository/blob and invalid-OID controls passed");
  return 0;
}
