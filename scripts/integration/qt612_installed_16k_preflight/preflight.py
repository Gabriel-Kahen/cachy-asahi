#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read exact Q3 inputs and emit an unissued installed-Qtbase trial plan."""

import argparse
import ast
from pathlib import Path
import re
from runpy import run_path
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PROJECT = ROOT / "scripts/integration"
RECIPE = ROOT / "packages/port/qt612-gui-server-source-reference"
T = SimpleNamespace(**run_path(str(ROOT / "scripts/install/overlay583_trial/trial.py")))
Q = SimpleNamespace(**run_path(str(PROJECT / "qt612_base_16k_link_preflight/preflight.py")))
M = SimpleNamespace(**run_path(str(PROJECT / "qt612_full_16k_preflight/package_metadata.py")))

Q3_INVENTORY = dict(bytes=6925, sha256="e2a4da7903e6de26b0ee37758ad424439f83196fa6a3b0bdffa501f35a02d0b9")
Q3_SCRATCH = Q.file_record(Q.Q3_SCRATCH)
Q3_TERMINAL = Q.file_record(Q.Q3_TERMINAL)
SCOPE = "cachy-asahi-qtbase16k-installed-trial.scope"
MEDIA = "/qt-install-inputs"
WORK = "/qt-install-work"
CERT = MEDIA + "/qtbase-TEST-public.gpg"
ARCHIVE = MEDIA + f"/{M.PACKAGE}-{M.VERSION}-aarch64.pkg.tar.xz"
PACMAN = ["/usr/bin/pacman", "--config", WORK + "/pacman.conf"]
CONFIG = f"""[options]
Architecture = aarch64
DBPath = /var/lib/pacman/
GPGDir = {WORK}/gnupg/
CacheDir = {WORK}/cache/
LogFile = {WORK}/pacman.log
SigLevel = Required TrustedOnly
LocalFileSigLevel = Required TrustedOnly
"""
SMOKE = "PASS_QT612_GUI_SERVER_OFFSCREEN_AND_LOCAL_DISPLAY_API_ONLY"
RECIPE_INPUTS = {
    "PKGBUILD": (6145, "121f2ec8f25a8c935be16136cd3dc036603679fdaea2f1b95e45a7a2201f852b"),
    ".SRCINFO": M.SRCINFO_INPUT,
    "SmokeCMakeLists.txt": (6902, "91036b0a511b570d7ce738584ff9607ae4e3d1f88fda3b0a926847ff260a79a1"),
    "smoke.cpp": (3105, "cd504607ac0aec8aad372aad0387c60fb405a216addfa29d6ff2f16b93eaeb96"),
    "check_stage.py": (22362, "35f410bf60af41f677f7a36d58cc5079ecf57dfde2b84f29dc1b006a4bf7f0da"),
}


def recipe_inputs():
    return {name: T.read(RECIPE / name, Q.file_record(pin), cap=32 << 10)
            for name, pin in RECIPE_INPUTS.items()}


def recipe_metadata(files):
    projected = M.successor(files["PKGBUILD"], files[".SRCINFO"])
    info = projected[".SRCINFO"].decode("ascii").splitlines()

    def values(field):
        prefix = f"\t{field} = "
        return [line.removeprefix(prefix) for line in info if line.startswith(prefix)]

    provides = values("provides")
    sonames = tuple(sorted(provide for provide in provides if provide.endswith(".so.6")))
    T.need(provides[0] == "qt6-base=" + M.VERSION and len(sonames) == 18 and len(set(sonames)) == 18,
           "Exact release-qualified Qtbase provide plus 18 SONAMEs required")
    fields = {}
    for node in ast.parse(files["check_stage.py"]).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in {"TOOLS", "PLUGINS"}:
                fields[name] = ast.literal_eval(node.value)
    tools = ["/" + tool for tool in fields["TOOLS"]]
    plugins = ["/usr/lib/qt6/plugins/" + plugin for plugin in fields["PLUGINS"]]
    return dict(package=M.PACKAGE, version=M.VERSION, architecture="aarch64", depends=values("depends"),
                provides=provides, conflicts=values("conflicts"), sonames=sonames, tools=tools, plugins=plugins,
                staged_recipe=Q.file_record(M.RECIPE_PINS[Q.OPERANDS["PKGBUILD"]][1]))


def consumer_cmake(raw):
    original = b'if(NOT IS_ABSOLUTE "${QT612_BUILD_TREE}" OR\n   NOT IS_DIRECTORY "${QT612_BUILD_TREE}/lib/cmake/Qt6")\n    message(FATAL_ERROR "An explicit absolute own-built Qt6 tree is required")\nendif()'
    header = b'${QT612_BUILD_TREE}/include/QtWaylandGlobal'
    T.need(raw.count(original) == raw.count(header) == 1, "Exact build-tree smoke inputs required")
    return raw.replace(original, b'set(QT612_BUILD_TREE "/usr")').replace(header, b'${QT612_BUILD_TREE}/include/qt6/QtWaylandGlobal')


def phases(package, base, installed):
    mutation = {
        "install": ["--noconfirm", "-U", "--", ARCHIVE],
        "reinstall": ["--noconfirm", "-U", "--", ARCHIVE],
        "remove": ["--noconfirm", "-R", "--", M.PACKAGE],
        "install-again": ["--noconfirm", "-U", "--", ARCHIVE],
        "final-remove": ["--noconfirm", "-R", "--", M.PACKAGE],
    }
    states = (("baseline", base), ("install", installed), ("reinstall", installed), ("remove", base),
              ("install-again", installed), ("final-remove", base))
    result = []
    for name, inventory in states:
        present = inventory == installed
        row = dict(name=name, mutation=PACMAN + mutation[name] if name in mutation else None,
                   inventory=inventory, state="installed" if present else "restored",
                   inventory_query=PACMAN + ["-Q"], database_check=PACMAN + ["-Dk"])
        if present:
            row.update(payload_check=PACMAN + ["-Qkk", M.PACKAGE],
                       dependency_check=PACMAN + ["-T", *package["depends"], "qt6-base=6.12.0", "qt6-base=" + M.VERSION],
                       version_refusal=PACMAN + ["-T", "qt6-base=6.12.0-3"])
        result.append(row)
    return result


def make_plan(raw, nonce, baseline, files):
    packages = T.canonical_lock(raw, 356)
    T.need(T.pin(raw) == Q3_INVENTORY and re.fullmatch("[0-9a-f]{32}", nonce)
           and all(packages.get(name) == version for name, version in {
               "md4c": "0.5.3-1", "wayland": "1.26.0-1", "libglvnd": "1.7.0-3",
           }.items()), "Exact Q3 installed inventory and fresh nonce required")
    meta = recipe_metadata(files)
    T.need(not ({M.PACKAGE, *meta["conflicts"]} & packages.keys()), "The clean no-Qtbase Q3 fixture is required")
    next_inventory = b"".join(sorted([*raw.splitlines(keepends=True), f"{M.PACKAGE} {M.VERSION}\n".encode()]))
    T.canonical_lock(next_inventory, 357)
    installed = T.pin(next_inventory)
    consumer = WORK + "/consumer"
    injected = {"CMakeLists.txt": T.pin(consumer_cmake(files["SmokeCMakeLists.txt"])), "smoke.cpp": T.pin(files["smoke.cpp"])}
    return dict(kind="QTBASE16K_INSTALLED_TRIAL_DATA_V1", scope=SCOPE, nonce=nonce, authority=None,
                baseline=baseline, package=meta | {"archive": ARCHIVE, "signature": ARCHIVE + ".sig"},
                guest=dict(architecture="aarch64", page_size_bytes=16384, network="none", root="/qtwork/root",
                           fresh_child=dict(backing=MEDIA + "/scratch.raw", format="qcow2", backing_format="raw"),
                           isolated_package_database=True),
                signer=dict(certificate=CERT, scope="current dedicated isolated public TEST key",
                            selected=None, packaging_receipt=None, verification=None,
                            required=["exact archive and adjacent detached signature pins",
                                      "exact current public certificate bytes and full primary and signing fingerprints",
                                      "independent original and tampered and unknown-key signature receipts",
                                      "verified original admission to this disposable ALPM keyring only",
                                      "retirement of the owned signing and guest trust environments"]),
                package_manager=dict(configuration=CONFIG, installed_dependency_preflight=PACMAN + ["-T", *meta["depends"]],
                                     prepare_addition=PACMAN + ["-U", "--print-format", "%n %v", "--", ARCHIVE],
                                     prepare_expected=f"{M.PACKAGE} {M.VERSION}"),
                stages=phases(meta, Q3_INVENTORY, installed),
                negative_trials={role: dict(clone="separate-fresh-Q3-child", command=PACMAN + ["--noconfirm", "-U", "--", ARCHIVE],
                                            otherwise_same_archive=True, expected="signature refusal with exact unchanged local DB")
                                 for role in ("tampered_signature", "unknown_key")},
                postconditions=dict(restored_inventory=Q3_INVENTORY,
                                    exact_stopped_local_database_restoration="overlay583_trial.local_database_snapshot(count=356)",
                                    preserve=["protected configuration bytes, type, ownership and modes",
                                              "ordinary user's configuration bytes, type, ownership and modes",
                                              "protected system provider payloads and loader paths"],
                                    payload_join=["exact package-owned file and symlink leaves",
                                                  "type checks for reported package directories outside shared /usr roots",
                                                  "all 18 real DSO and alias owners and bytes",
                                                  "all 12 plugin and five tool owners and bytes"],
                                    absent_after_remove=["all package-owned nonshared leaves",
                                                         "all 18 SONAMEs unavailable to the normal loader"],
                                    installed_runtime=["RTLD_NOW|RTLD_LOCAL on each SONAME using the regular loader",
                                                       "full transitive load map bound to installed signed owners and exact bytes",
                                                       "offscreen plugin mapping matches the package payload"]),
                consumer=dict(files=injected, ordinary_user=True, marker=SMOKE,
                              environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": WORK + "/home",
                                           "XDG_RUNTIME_DIR": WORK + "/runtime", "QT_QPA_PLATFORM": "offscreen"},
                              configure=["/usr/bin/cmake", "-G", "Ninja", "-S", MEDIA + "/consumer",
                                         "-B", consumer, "-DCMAKE_SKIP_RPATH=ON"],
                              build=["/usr/bin/cmake", "--build", consumer, "--parallel", "1"],
                              run=[consumer + "/qt612-smoke"]),
                signing="NOT_RUN", installation="NOT_RUN", restore="NOT_RUN",
                official_provider_replacement="OUT_OF_SCOPE", physical_M2="NOT_RUN")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit-consumer-cmake", action="store_true")
    for name in ("q3-inventory", "q3-scratch", "q3-terminal"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--nonce")
    args = parser.parse_args()
    try:
        files = recipe_inputs()
        if args.emit_consumer_cmake:
            T.need(not any((args.q3_inventory, args.q3_scratch, args.q3_terminal, args.nonce)),
                   "Select either the plan or deterministic installed consumer source")
            sys.stdout.buffer.write(consumer_cmake(files["SmokeCMakeLists.txt"]))
            return
        T.need(all((args.q3_inventory, args.q3_scratch, args.q3_terminal, args.nonce)),
               "An inventory, scratch, terminal and nonce are required")
        Q.verify_terminal(args.q3_terminal)
        raw = T.read(args.q3_inventory, Q3_INVENTORY, cap=16 << 10)
        pins = {"inventory": Q3_INVENTORY, "terminal": Q3_TERMINAL,
                "scratch": T.read(args.q3_scratch, Q3_SCRATCH, cap=Q3_SCRATCH["bytes"], collect=False)}
        baseline = {key: {"path": str(path), **pins[key]} for key, path in (
            ("inventory", args.q3_inventory), ("scratch", args.q3_scratch), ("terminal", args.q3_terminal))}
        sys.stdout.buffer.write(T.encoded(make_plan(raw, args.nonce, baseline, files)))
    except (OSError, ValueError, TypeError, KeyError) as error:
        sys.exit(f"Qtbase installed-trial preflight refused: {error}")


if __name__ == "__main__":
    main()
