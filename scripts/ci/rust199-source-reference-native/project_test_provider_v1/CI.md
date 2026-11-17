# Automatic actor-free integration coverage

`.github/workflows/rust-project-test-v19-data.yml` is the single dedicated
workflow for this interface and Rust v19. Pull requests and pushes to `main`
run Python 3.12 and 3.14 with SHA-pinned checkout/setup actions and read-only
contents permission. It has no package build, Root role, signing, runtime,
secret reference or workflow mutation. `runner.temp` appears only in step env.

The explicit public source operand is commit
`8fb13c028cf043119f8324eb089c51d74e3891ee` in
`Gabriel-Kahen/cachy-asahi`. Setup fetches that exact commit, retains its raw
commit bytes, and creates a file-only Git tar with `tar.umask=0022`.
`ci.py` checks the raw Git commit hash, its absence of parents, the full367
file/byte/tree/map tuple, and the complete file and directory census. It then
atomically extracts fresh ordinary DATA files. Source programs are never
imported or executed, and there is no fallback to a local Root artifact cache.

The runner executes the seven unchanged suites and the CI guards as eight isolated Python
workers under 512 MiB. An audit hook installed before test imports refuses
process creation, sockets, system commands, locks and native library loading.
The only ctypes operations permitted by the outer hook are the existing
filesystem helper's current-process libc lookup and `renameat2` publication.
Workers refuse caught actor attempts, skips, expected failures, failures and
test-count drift. The runner retains complete bounded rawlogs, canonical
worker receipts and aggregate result DATA in a fresh evidence directory.

There are **73 unique controls**, counted once: 38 interface controls and
27 v19 controls. The Source suite includes the genuine367→364→361→355→351→344→340
inverse and each exact re-render, plus eight CI self-controls for
published Source extraction and refusal boundaries. All eight guard tests are
required by the same count/skip/actor checks as the existing65. None of these MODEL
provider/signature controls grants real signature, native, ARM or M2 credit.

Local execution uses an independently retrieved tar/raw-commit pair:

```sh
RUST199_CI_SOURCE_ARCHIVE=/absolute/Source367.tar \
RUST199_CI_SOURCE_COMMIT=/absolute/Source367.commit \
TMPDIR=/absolute/private-temporary-parent \
python -I -B -Werror::ResourceWarning \
  scripts/ci/rust199-source-reference-native/project_test_provider_v1/test_ci.py

python -I -B -Werror::ResourceWarning \
  scripts/ci/rust199-source-reference-native/project_test_provider_v1/ci.py \
  --source-archive /absolute/Source367.tar \
  --source-commit /absolute/Source367.commit \
  --output /absolute/private-parent/fresh-evidence
```

The unchanged interface and v19 require the passive official v18 author
closure from `8128cd73c85d533092d081f0b9131b2ca9893ecd`. This integration merges
that original author history, including its 17 exact unchanged v18 files,
and Main17ce. The original8128,14dd,72482 and0840 commits remain ancestors.
Missing dependencies produce a failed suite, never a skip or a partial green
result; the workflow obtains no dependency from a cache or unpublished ref.

Real accepted provider tuples and the constructor profile remain UNBOUND.
The original interface and v19 author files, including their frozen seals,
are unchanged by these CI-only additions.
