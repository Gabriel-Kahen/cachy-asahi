#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate pathless Qt family custody from fresh, offline runner-local paths."""
import argparse
from contextlib import ExitStack, contextmanager
import importlib.util
import os
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("qt_runner_input_common", HERE / "common.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
M, P, need = C.M, C.P, C.need
spec = importlib.util.spec_from_file_location("qt_runner_md4c", HERE / "md4c_handoff.py")
md4c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(md4c)

KIND = "QT612_PATHLESS_RUNNER_INPUTS_DATA_V1"
ORIGINAL = "source-map.json"
INPUTS = "family-inputs.DATA.json"
SELECTION = "selection.DATA.json"
BASE_GROUPS = {
    "base_materials": "base-materials",
    "supplemental_materials": "supplemental-materials",
    "keyring_materials": "keyrings",
}
BASE_META = {
    "base_lock": "base-input.lock.json",
    "bootstrap_profile": "bootstrap-profile.json",
    "baseline_inventory": "expected349.lock",
}


def pin(row):
    return {field: row[field] for field in ("bytes", "sha256")}


def external_pin(path, sha):
    return dict(bytes=path.lstat().st_size, sha256=sha)


def mapped_archive_paths():
    return {f"archives/{key}/{row['archive']['filename']}": row["archive"]["filename"]
            for key, row in C.load_lock()["components"].items()}


def mapped_git_paths(mapping):
    lock = C.load_lock()
    parent = "scripts/ci/qt612-reference-native-source"
    result = {f"{parent}/{name}": f"{parent}/{name}" for name in lock["parents"]}
    if mapping["desktop_consumer"] is not None:
        consumer = lock["consumer"]
        result.update({f"consumer/{name}": f"{consumer['source_path']}/{name}" for name in consumer["files"]})
    need(result.keys() <= mapping["files"].keys(), "COMPLETE_PUBLIC_GIT_MAP")
    return result


def dependency_projection(rows):
    return {name: dict(name=row["name"], version=row["version"], arch=row["arch"], filename=row["filename"],
                       archive=pin(row["archive"]), signature=pin(row["signature"]))
            for name, row in rows.items()}


def export_inputs(source, source_map_sha256, output):
    source, output = M.ordinary(source), M.ordinary(output)
    need(not output.exists() and not output.is_relative_to(source) and not source.is_relative_to(output),
         "FRESH_DISJOINT_PORTABLE_OUTPUT")
    mapping = C.read_source(source, source_map_sha256)
    need(mapping["input_plan_complete"], "COMPLETE_ORIGINAL_FAMILY_REQUIRED")
    seen = {}
    source_pin = external_pin(source / ORIGINAL, source_map_sha256)
    original = M.stream(source / ORIGINAL, source_pin, seen, collect=True)
    inputs = M.load(source / INPUTS, pin(mapping["files"][INPUTS]), seen)
    dep_lock = P.selected(C.PARENT / "dependency-candidates.lock.json", P.DEPENDENCIES, seen)
    P.validate_base_provider(inputs["base_provider"], dep_lock, seen)
    base = M.decode(P.reference(inputs["base_provider"], seen, collect=True, cap=4 * 1024**2))
    deps = inputs["dependencies"]["packages"]
    for row in deps.values():
        for role in ("archive", "signature"):
            P.reference(row[role], seen)
    public = mapped_git_paths(mapping)
    selection = dict(schema=1, kind=KIND, original_source_map=source_pin,
                     original_family_inputs=pin(mapping["files"][INPUTS]),
                     original_base_provider=pin(inputs["base_provider"]),
                     historical_candidate_map=P.CANDIDATE_MAP, official_dependency_lock=P.DEPENDENCIES,
                     base_metadata={field: pin(base[field]) for field in BASE_META},
                     base_actual_fields=sorted(base["actual"]),
                     base_materials={group: {name: pin(row) for name, row in base[group].items()}
                                     for group in BASE_GROUPS},
                     dependencies=dependency_projection(deps), public_git=public, Root_acceptance=None)
    archived = mapped_archive_paths()
    writer = M.Writer(output)
    try:
        writer.put(ORIGINAL, raw=original)
        for name, row in sorted(mapping["files"].items()):
            if name != INPUTS and name not in archived and name not in public:
                writer.put(f"skeleton/{name}", source=source / name, expected=pin(row),
                           mode=row["mode"], observed=seen, cap=128 * 1024**2)
        selected = writer.put(SELECTION, raw=C.encoded(selection))
        M.unchanged(seen)
        return dict(status="PREPARED_PATHLESS_FAMILY_INPUTS_DATA_ONLY", selection=pin(selected),
                    original_source_map=source_pin, public_git_files=len(public),
                    skeleton_files=len(mapping["files"]) - len(archived) - len(public) - 1,
                    historical_candidate_map=P.CANDIDATE_MAP, Root_acceptance=None)
    finally:
        writer.close()


def mount_path(value):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)


@contextmanager
def owned_workspace(path, device, inode, mount_id):
    root = M.ordinary(path)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        root_info = os.fstat(fd)

        def check():
            fdinfo = Path(f"/proc/self/fdinfo/{fd}").read_text()
            mounts = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()]
            descendants = [row for row in mounts if Path(mount_path(row[4])).is_relative_to(root)]
            need((root_info.st_dev, root_info.st_ino, root_info.st_uid) == (device, inode, os.geteuid())
                 and not root_info.st_mode & 0o022 and M.identity(root.stat())[:3] == M.identity(root_info)[:3]
                 and re.search(rf"^mnt_id:\s*{mount_id}$", fdinfo, re.M)
                 and len(descendants) == 1 and descendants[0][0] == str(mount_id)
                 and mount_path(descendants[0][4]) == str(root)
                 and descendants[0][2] == f"{os.major(device)}:{os.minor(device)}"
                 and descendants[0][descendants[0].index("-") + 1] == "ext4",
                 "EXACT_OWNED_EXT4_MOUNT_REQUIRED")

        check()
        yield root
        check()
    finally:
        os.close(fd)


def local_ref(root, folder, leaf, expected):
    need(isinstance(leaf, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+@~:-]{0,254}", leaf), "FLAT_OPERAND_LEAF_REQUIRED")
    M.descriptor(expected, 2 * 1024**3)
    return dict(path=str(root / folder / leaf), **expected)


def base_reference(selection, operands, writer, dep_lock, seen):
    value = dict(api="BASE349_CACHE_REFERENCES_V3", kind="VERIFIED_BASE349_CACHE_REFERENCES_DATA_V3",
                 complete=True, verified_files=517, missing_materials=[], actual=dict.fromkeys(selection["base_actual_fields"]))
    for role, leaf in BASE_META.items():
        value[role] = local_ref(operands, "metadata", leaf, selection["base_metadata"][role])
    for key, folder in BASE_GROUPS.items():
        value[key] = {leaf: local_ref(operands, folder, leaf, p) for leaf, p in selection["base_materials"][key].items()}
    leaf = "base-provider.DATA.json"
    ref = dict(path=str(writer.root / leaf), **pin(writer.put(leaf, raw=C.encoded(value))))
    base = P.validate_base_provider(ref, dep_lock, seen)
    return ref, base


def dependency_refs(selection, operands, dep_lock, seen):
    rows = selection["dependencies"]
    need(set(rows) == {*dep_lock["additional"], "md4c"}, "EXACT_SEVEN_DEPENDENCY_OPERANDS")
    result = {}
    for name, row in rows.items():
        need(set(row) == {"name", "version", "arch", "filename", "archive", "signature"} and row["name"] == name,
             "EXACT_DEPENDENCY_IDENTITY")
        archive = local_ref(operands, "dependencies", row["filename"], row["archive"])
        signature = local_ref(operands, "dependencies", row["filename"] + ".sig", row["signature"])
        if name == "md4c":
            bound = md4c.build_reference(archive=archive["path"], archive_pin=row["archive"],
                                         signature=signature["path"], signature_pin=row["signature"])
            need(dependency_projection({name: bound})[name] == row, "EXACT_SELECTED_MD4C_METADATA")
        else:
            original = dep_lock["additional"][name]
            need(all(row[key] == original[key] for key in ("version", "arch", "filename", "archive", "signature")),
                 "EXACT_OFFICIAL_DEPENDENCY_PINS")
            bound = dict(row, archive=archive, signature=signature)
        P.reference(archive, seen)
        P.reference(signature, seen, cap=1024**2)
        if name != "md4c":
            need(P.pkginfo(archive["path"]) == original["PKGINFO"], "EXACT_OFFICIAL_DEPENDENCY_PKGINFO")
        result[name] = bound
    return dict(kind="QT612_INCREMENTAL_SIGNED_INPUT_DATA_ONLY", packages=result, missing_roles=[],
                available_packages=7, required_packages=7, complete=True, GPG="NOT_RUN", Root_acceptance=None)


def bind_inputs(portable, selection_sha256, operands, framework, output, workspace):
    portable, operands, framework, output = map(M.ordinary, (portable, operands, framework, output))
    need(all(p.is_relative_to(workspace) and p != workspace for p in (portable, operands, framework, output))
         and not output.exists() and all(not output.is_relative_to(p) and not p.is_relative_to(output)
                                         for p in (portable, operands, framework)), "FRESH_DISJOINT_IN_VOLUME_INPUTS")
    seen = {}
    selection_path = portable / SELECTION
    selected = external_pin(selection_path, selection_sha256)
    selection = M.load(selection_path, selected, seen)
    need(selection["schema"] == 1 and selection["kind"] == KIND and selection["Root_acceptance"] is None
         and selection["historical_candidate_map"] == P.CANDIDATE_MAP
         and selection["official_dependency_lock"] == P.DEPENDENCIES, "PINNED_PATHLESS_SELECTION_REQUIRED")
    raw = M.stream(portable / ORIGINAL, selection["original_source_map"], seen, collect=True)
    mapping = M.decode(raw)
    rows = mapping["files"]
    need(mapping["kind"] == "QT612_COMPLETE_FAMILY_SOURCE_DATA_V1" and mapping["input_plan_complete"] is True
         and mapping["Root_acceptance"] is None and pin(rows[INPUTS]) == selection["original_family_inputs"]
         and len(rows) <= 512 and sum(v["bytes"] for v in rows.values()) <= 256 * 1024**2,
         "EXACT_ORIGINAL_FAMILY_MAP")
    archived = mapped_archive_paths()
    public = mapped_git_paths(mapping)
    need(set(archived) <= set(rows) and public == selection["public_git"], "COMPLETE_QT_UPSTREAM_AND_PUBLIC_GIT_MAP")
    expected_skeleton = {"skeleton/" + name for name in rows.keys() - public.keys() - archived.keys() - {INPUTS}}
    found = set()
    nodes = 0
    for folder, dirs, names in os.walk(portable, followlinks=False):
        for name in dirs + names:
            nodes += 1
            path = Path(folder) / name
            need(nodes <= 1024 and not path.is_symlink(), "BOUNDED_ORDINARY_PORTABLE_NAMESPACE")
            if name in names:
                found.add(path.relative_to(portable).as_posix())
                need(len(found) <= 512, "BOUNDED_PORTABLE_NAMESPACE")
    need(found == expected_skeleton | {ORIGINAL, SELECTION}, "EXACT_PORTABLE_FILE_SET")
    dep_lock = P.selected(C.PARENT / "dependency-candidates.lock.json", P.DEPENDENCIES, seen)
    dependencies = dependency_refs(selection, operands, dep_lock, seen)
    with ExitStack() as opened:
        result = M.Writer(output)
        opened.callback(result.close)
        base_ref, base = base_reference(selection, operands, result, dep_lock, seen)
        inventory = dict(base["inventory"])
        inventory.update({name: item["version"] for name, item in dependencies["packages"].items()})
        expected = "".join(f"{name} {version}\n" for name, version in sorted(inventory.items())).encode()
        need(len(inventory) == 356 and C.pin(expected) == pin(rows["expected356.lock"]), "UNCHANGED_349_PLUS_7")
        root = output / "Source-DATA"
        writer = M.Writer(root)
        opened.callback(writer.close)
        for name, row in sorted(rows.items()):
            need(row["mode"] == 0o644, "EXACT_FAMILY_LEAF_MODE")
            if name == INPUTS:
                continue
            if name in archived:
                path = operands / "qt-upstream" / archived[name]
            elif name in public:
                path = framework / public[name]
            else:
                path = portable / "skeleton" / name
            writer.put(name, source=path, expected=pin(row), observed=seen, cap=128 * 1024**2)
        inputs = dict(base_provider=base_ref, dependencies=dependencies, complete=True, baseline_packages=349,
                      derived_packages=356, GPG="NOT_RUN", Root_acceptance=None)
        rows[INPUTS] = writer.put(INPUTS, raw=C.encoded(inputs))
        new_raw = C.encoded(mapping)
        new_map = pin(writer.put(ORIGINAL, raw=new_raw))
        M.unchanged(seen)
        C.read_source(root, new_map["sha256"])
        receipt = dict(status="BOUND_RUNNER_SOURCE_DATA_ONLY", original_source_map=selection["original_source_map"],
                       original_family_inputs=selection["original_family_inputs"],
                       original_base_provider=selection["original_base_provider"], new_source_map=new_map,
                       selection=selected, base_provider=pin(base_ref), base_roles=517,
                       packages=7, expected_inventory=C.pin(expected), changed_source_leaves=[INPUTS, ORIGINAL],
                       GPG="NOT_RUN", Root_acceptance=None, actor_enabled=False)
        result.put("runner-inputs.DATA.json", raw=C.encoded(receipt))
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    for arg in ("source", "source-map-sha256", "output"):
        export.add_argument("--" + arg, required=True)
    bind = commands.add_parser("bind")
    for arg in ("portable", "selection-sha256", "operands", "framework", "output", "workspace"):
        bind.add_argument("--" + arg, required=True)
    for arg in ("workspace-device", "workspace-inode", "workspace-mount-id"):
        bind.add_argument("--" + arg, type=int, required=True)
    args = parser.parse_args()
    sys.addaudithook(M.fence)
    try:
        if args.command == "export":
            result = export_inputs(args.source, args.source_map_sha256, args.output)
        else:
            with owned_workspace(args.workspace, args.workspace_device, args.workspace_inode, args.workspace_mount_id) as root:
                result = bind_inputs(args.portable, args.selection_sha256, args.operands, args.framework, args.output, root)
        print(C.encoded(result).decode(), end="")
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Qt runner inputs refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
