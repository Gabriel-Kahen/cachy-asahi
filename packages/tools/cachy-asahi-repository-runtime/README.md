# cachy-asahi-repository-runtime 0.1.0-1

The small MIT runtime companion for cachy-asahi-apps0.1.0-2. It installs exactly the three unchanged helper sources (86,445 bytes) under `/usr/share/cachy-asahi/repository-runtime/`, preserving their original `scripts/client/` and `scripts/release/` relative layout. They are client.py, release.py and source_delivery.py. The package includes the MIT grant, notice, exact source pins and provenance in ordinary documentation/license locations. No Git checkout, test toolchain, GPG keys or application catalog is installed.

Dependencies are Python3.11+, GPG, libarchive's bsdtar and pacman's vercmp. This pure-source package has `arch=any`; the application planner still restricts its data to aarch64/any. This package does not execute any helper main function or install an automatic service/hook. The planner loads pinned Source bytes as modules and retains all existing signature/provenance/dependency checks. No new trust or apply endpoint is introduced.

The apps CLI defaults to this installed helper tree, relative to its own `/usr/lib/cachy-asahi-apps/apps.py` installation prefix. The same layout works under a private staging root. Its explicit `--repository-source` override remains available for an exact development source snapshot. Both paths must match the same existing helper hashes before helper execution. The apps package pins this runtime dependency to exactly0.1.0-1.

Run `python3 -I -B check_source.py` to check source pins and `--stage /absolute/private-stage` to check the exact8-file package payload and the closed3-file helper subtree. No native package build, real installation lifecycle, production release or M2 hardware acceptance is implied by these source/staging checks.
