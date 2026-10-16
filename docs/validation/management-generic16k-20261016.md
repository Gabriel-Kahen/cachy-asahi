# Management CLI execution with 16K pages

Root accepts `ROOT_ACCEPTED_GENERIC16K_MANAGEMENT_CLI_PRIVATE_FIXTURES` from
[run 38978464494](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38978464494),
source `694be4031e2cdf30a83c25ffb74cb9c9aa7d4318`.

All 19 original Apps, Cache and Orphans CLI cases pass in the generic AArch64
16,384-byte-page VM. Apps uses its default installed helper prefix and verifies
signed TEST catalog/release plans against collected local database metadata.
Cache exercises selected archive quarantine, real ALPM exclusion and preservation.
Orphans exercises read-only assessment/plan verification and protected-package
refusals. The ordinary process runs as UID/GID23001, with empty groups, NNP and
zero capabilities; payloads, user configuration and private-fixture cleanup pass.
The packages are data-staged in private fixtures, not ALPM-installed in this VM.

The previous actual failed because its realtime remained in 1970. The corrected
startup seeds actual VM realtime from observed runner UTC before privilege drop,
with exact source/job/nonce/payload binding. Guest readback is 325,040ns after the
seed; seed-to-dispatch is 247,905,885 monotonic ns. This is a startup anchor,
not continuous synchronization. Original GPG time, expiry, revocation and signer
checks remain unchanged; earlier failed runs remain failed.

Root replays the original structured guards, all 19 exact argv/stdout/exit joins,
25 mapped original native payload files, kernel/config receipt checks, three
natural actor exits and ordered capture/private/producer/kernel-work cleanup.
All 142 original source pins independently join frozen Git. The VM exits0 after
167.861912 seconds. The capture declares 1,854 files totaling116,995,960 bytes
and135 ELF dependency closures.

Only runtime.json and bounded workflow logs are retained. Full UART, captured
runtime tar/ELFs, kernel Image/full config and fresh TEST fixture bytes are absent;
those raw checks are source-enforced execution records. The retained UART suffix
joins the final nonce PASS. Advisory QMP observation remains UNAVAILABLE, reason
`exact QMP response required`. Cleanup is retained execution evidence, not a new
live probe. No installation, GUI, physical M2, performance or release acceptance
follows. Separate native package installation evidence remains unchanged.
