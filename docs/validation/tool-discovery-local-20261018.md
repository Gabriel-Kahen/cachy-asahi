# Saved sysctl experiment discovery

The alternative [sysctl0.1.0-2 recipe](../../packages/tools/cachy-asahi-sysctl2/README.md) adds `cachy-asahi-sysctl experiments --state /absolute/private/store`. It lists saved names, baseline/target values and journal phases, while retaining incomplete or invalid entries. It does not read kernel values, create state, grant undo permission or automatically restore anything. Use explicit named `inspect` and `undo`; their existing boot, ownership and conflict checks still apply.

This is an alternative recipe for the same package name and installed command. Select one version; the original0.1.0-1 recipe remains available for its pinned native results. Native credit does not transfer between versions.

Twenty-eight local controls passed on Python3.12 and3.14, including the original19 mutation/conflict/interruption controls and9 read-only discovery controls. All writes use private model files. Actual package staging installed the five expected paths; the staged CLI read a plan created by the originalv1 program with saved bytes and model value unchanged. A saved journal is explicitly reported as `live_state: NOT_READ`.

Native ARM paired builds, signed installation/upgrade/removal, actual kernel restoration, M2 behavior and release selection remain NOT_RUN. This development variant is not selected by the supported-system inventory.
