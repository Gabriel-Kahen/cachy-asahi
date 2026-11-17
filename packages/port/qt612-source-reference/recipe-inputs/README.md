# Pinned recipe inputs

These are unchanged authentic packaging inputs for designing a new project Qt
source-reference provider. They establish neither correspondence with an existing
binary nor a successful build. The coordinator owns the new provider PKGBUILD.

- `alarm/PKGBUILD`: Arch Linux ARM commit
  `b32d838db0daea604a2f8080b9e17cc24d4c8b6f`, `extra/qt6-base/PKGBUILD`.
- `arch/PKGBUILD`: Arch Linux commit
  `070299bbd137a648d9da9d430eefb7ac47a55f1c`, version tag `6.12.0-3`.
- The two `alarm/*.patch` files have the hashes declared in both recipes.
- `qt-cherry-pick-inputs/` retains the three full upstream patches named by both
  recipes. Their necessity and applicability must be decided for the new pinned
  source. They are not automatically part of the new provider.
- `acquisition.DATA.json` records every primary URL, byte count, hash and retained
  local provenance. `../recipe-inputs.DATA.json` records complete static arrays,
  CMake argument tokens, license scope and recommendations. No PKGBUILD was sourced.

Both pinned per-package `REUSE.toml` files explicitly declare the PKGBUILD and
two distribution patches to be 0BSD. Both `LICENSE` files provide the grant.
These grants cover the packaging inputs; Qt source and Qt commit patches retain
their own file-specific licenses. No repository-wide ALARM GPL grant is inferred.
Original maintainer and contributor headers are preserved.

The historical recipes declare `arch=(x86_64)`. That field does not qualify an ARM
build. The ALARM delta removes Arch LTO and its no-direct-external-access flag,
disables the iBase SQL plugin, changes the source remote, and adds a SONAME
provide. A new private provider should have its own package identity and prefix
without advertising itself as the system Qt replacement. Its normal external
libraries must remain supplied by the supported base, preserving Asahi and Mesa.

The retained recipes have 45 ordinary runtime dependencies plus translations in
the packaging function, and 17 make dependencies. Optional SQL, GTK and other
backends must be disabled explicitly before removing their build dependencies.
A reduced source-reference build must report its actual configure feature summary
and limits; this input packet does not assert that a reduced recipe already builds.
