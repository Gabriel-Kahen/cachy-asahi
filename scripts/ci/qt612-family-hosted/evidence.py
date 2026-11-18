# SPDX-License-Identifier: MIT
"""Passive export and readback of the exact hosted GUI pair evidence."""

from pathlib import Path
import re


GIB = 1024**3
CAP = 2 * GIB
FILE_CAP = 128 * 1024**2
ARCHIVE_CAP = 512 * 1024**2
JSON_CAP = 32 * 1024**2
FAMILY = "scripts/ci/qt612-complete-family-native-source"
COMPONENT = "gui_server"
MANIFEST = "pair-export.json"


def pair_members(C, *, stage, commands, source_map, inventory, selected):
    """Read only finite original files selected by trusted stage and Source pins."""
    M, need = C.M, C.need
    need(set(selected) == {"source_map", "qualification", "owner", "stage_binding_sha256", "dispatch"},
         "Explicit selected hosted pair evidence pins required")
    need(set(selected["dispatch"]) == {"source", "ref", "run", "job", "attempt"}
         and selected["dispatch"]["attempt"] == "1"
         and re.fullmatch(r"[0-9a-f]{64}", selected["stage_binding_sha256"]),
         "Exact separately selected dispatch and stage binding required")
    rows, observed = {}, {}
    total = 0

    def read(name, path, expected=None, *, cap=JSON_CAP, collect=True, sha256=None):
        nonlocal total
        M.member(name)
        need(name not in rows, "Unique raw pair export member required")
        sink = C.F.HashSink()
        before = M.ordinary(path).lstat()
        need(total+before.st_size <= CAP and len(rows) < 2048, "Finite pair evidence export budget")
        raw = M.stream(path, expected, observed, cap=cap, collect=collect, target=sink)
        pin = sink.result()
        need(sha256 is None or pin["sha256"] == sha256, "Exact raw pair operand digest required")
        total += pin["bytes"]
        rows[name] = (M.ordinary(path), pin)
        return M.decode(raw) if collect else None

    mapping = read("source-map.json", source_map, selected["source_map"])
    owner = read("owned-pair.json", stage/"owned-pair.json", selected["owner"])
    pair = read("qualification.json", stage/"qualification.json", selected["qualification"])
    frozen = C.load_lock()["components"][COMPONENT]
    filename = frozen["filename"]
    sha = selected["source_map"]["sha256"]
    need(mapping["kind"] == "QT612_COMPLETE_FAMILY_SOURCE_DATA_V1" and mapping["input_plan_complete"] is True
         and mapping["Root_acceptance"] is None
         and owner["kind"] == "QT612_HOSTED_OWNED_PAIR_WITNESS_V1" and owner["mode"] == "pair-only"
         and owner["dispatch"] == selected["dispatch"]
         and owner["stage_binding_sha256"] == selected["stage_binding_sha256"]
         and owner["qualification"] == selected["qualification"] and owner["component"] == pair["component"] == COMPONENT
         and owner["source_map_sha256"] == pair["source_map_sha256"] == sha and owner["image"] == pair["image"]
         and owner["nonce"] == pair["nonce"] and owner["inventory_pin"] == pair["inventory_pin"]
         and pair["recipe_commit"] == frozen["commit"] and pair["filename"] == filename
         and pair["status"] == "PASS_QT612_FAMILY_COMPONENT_PAIR_CURRENT_BYTES_ONLY"
         and pair["native_acceptance"] is pair["Root_acceptance"] is None
         and pair["M2"] == pair["GPG"] == "NOT_RUN", "Exact already-qualified current hosted pair required")
    need(re.fullmatch(r"sha256:[0-9a-f]{64}", pair["image"] or "") and re.fullmatch(r"[0-9a-f]{32}", pair["nonce"] or ""),
         "Immutable qualified image and pair nonce required")
    inv = {k:mapping["files"]["expected356.lock"][k] for k in ("bytes", "sha256")}
    need(inv == pair["inventory_pin"], "Exact signed356 inventory pin required")
    read("expected356.lock", inventory, inv, collect=False)
    read("comparison.json", stage/"comparison.json", pair["comparison"])

    observed_pair = pair["observations"]
    need(len(observed_pair) == 2 and observed_pair[0]["archive"] == observed_pair[1]["archive"]
         and set(pair["provenance_pins"]) == {"build-1", "build-2"},
         "Same two canonical archive pins required")
    check_log = filename.removesuffix(".pkg.tar.xz")+"-check.log"
    package_base = filename.removesuffix(".pkg.tar.xz")
    for idx, observation in enumerate(observed_pair, 1):
        key = f"build-{idx}"
        provenance = read(f"{key}/provenance.json", stage/key/"provenance.json", pair["provenance_pins"][key])
        artifact = "artifacts/"+filename
        check = "artifacts/"+check_log
        required = {"build.log", "validation.json", "expected-packages.lock", artifact, check,
            *(f"artifacts/{leaf}" for leaf in ("environment.txt", "packages.lock", "config.sha256",
                "generated.SRCINFO", "makepkg.conf", "pacman.conf", "family-stage.json", "family-configuration.json",
                "family-notices.json", "family-dependencies.missing", "family-build-proof.json"))}
        expected = {artifact: observation["archive"], check: observation["check_log"],
            "expected-packages.lock": inv, "artifacts/packages.lock": inv,
            "artifacts/family-build-proof.json": observation["build_proof"]}
        for relative, pin in (("family-stage.json", "stage"), ("family-configuration.json", "configuration"),
                              ("family-notices.json", "notices")):
            # These package-side receipts have their own raw pins. The
            # qualifier pins the canonical parsed content separately.
            raw = M.stream(stage/key/"artifacts"/relative, None, observed, cap=FILE_CAP, collect=True)
            need(C.pin(C.encoded(M.decode(raw))) == observation[pin], "Same canonical qualified stage evidence")
        files = provenance["files"]
        need(provenance["image_id"] == pair["image"] and provenance["artifacts"] == {filename:observation["archive"]["sha256"]}
             and required <= files.keys() and len(files) < 64, "Complete bounded per-build provenance required")
        for relative, checksum in sorted(files.items()):
            M.member(relative)
            allowed_material = re.fullmatch(r"source-material/(?:source-plan\.json|source-catalog\.json|selection\.json"
                r"|receipts/gui_server\.json|notices/[0-9a-f]{64}|srcdest/qtbase-everywhere-src-6\.12\.0\.tar\.xz)", relative)
            extra_log = re.fullmatch("artifacts/"+re.escape(package_base)+r"-(?:prepare|build|package)\.log", relative)
            need(relative in required or allowed_material or extra_log, "Only exact public Qt build operands may be exported")
            read(f"{key}/{relative}", stage/key/relative, expected.get(relative), sha256=checksum,
                 cap=ARCHIVE_CAP if relative == artifact else FILE_CAP, collect=False)
        for leaf in provenance["recipe_inputs"]:
            M.member(leaf)
            descriptor = mapping["files"]["recipes/"+COMPONENT+"/"+leaf]
            pin = {k:descriptor[k] for k in ("bytes", "sha256")}
            need(provenance["recipe_inputs"][leaf] == pin["sha256"], "Exact selected recipe snapshot SHA required")
            read(f"{key}/inputs/{leaf}", stage/key/"inputs"/leaf, pin, cap=FILE_CAP, collect=False)

    entries = owner["commands"]
    absence = owner["absence"]
    need(len(entries) == 4 and set(absence) == {"build-1", "build-2", "qualifier"}
         and all(len(a) == 2 for a in absence.values()), "Exact naturally retired build and qualifier commands required")
    first, second, compare, qualifier = entries
    empty = C.pin(b"")
    need(compare["stdout"] == pair["comparison"] and qualifier["stdout"] == selected["qualification"],
         "Original comparison and separate qualifier stdout receipts required")
    need("--require-bytes" in compare["argv"] and "--memory=2g" in qualifier["argv"]
         and "--memory-swap=2g" in qualifier["argv"] and "--cpus=1" in qualifier["argv"]
         and "--network=none" in qualifier["argv"] and "--read-only" in qualifier["argv"]
         and "cachy-qt612-qualify-"+pair["nonce"] in qualifier["argv"],
         "Strict comparison and isolated bounded qualifier required")
    req_name = "qualifier-input/request.json"
    req_raw = read(req_name, stage/req_name, sha256=qualifier["argv"][-1], cap=65536)
    need(req_raw["kind"] == "QT612_FAMILY_PAIR_QUALIFICATION_REQUEST_V1"
         and req_raw["source_map_sha256"] == sha and req_raw["component"] == COMPONENT
         and {k: req_raw["expected"][k] for k in ("image", "nonce", "inventory_pin", "entry_pin", "source_date_epoch")}
         == {k: pair[k] for k in ("image", "nonce", "inventory_pin", "entry_pin", "source_date_epoch")}
         and compare["argv"][-3:] == [req_raw["first"], req_raw["second"], "--require-bytes"],
         "Exact request, build roots and original qualification context required")
    for key, event in (("first", first), ("second", second)):
        argv = event["argv"]
        need(argv[:3] == ["/usr/bin/python3", "-I", "-B"] and Path(argv[3]).name == "executor.py"
             and Path(argv[4]).name == "build_family.py" and argv[-2:] == ["--output", req_raw[key]]
             and all(argv.count(flag) == 1 and argv[argv.index(flag)+1] == value
                     for flag, value in (("--network", "none"), ("--mode", "native"), ("--image", pair["image"]))),
             "Exact ordinary offline owner-path build receipt required")
    ordered = [first, *absence["build-1"], second, *absence["build-2"],
               compare, qualifier, *absence["qualifier"]]
    indices = [event["index"] for event in ordered]
    need(indices == sorted(set(indices)) and all(type(i) is int and 0 <= i < 512 for i in indices),
         "Original serial command ordering required")
    for key, events in absence.items():
        for event in events:
            expected_name = ("name=^/cachy-qt612-family-"+pair["nonce"]+"-gui_server-"+key[-1]+"$"
                             if key.startswith("build-") else None)
            argv = event["argv"]
            need(event["stdout"] == empty and argv[2:7] == ["container", "ls", "-a", "--no-trunc", "--quiet"]
                 and argv[7:] == (["--filter", expected_name] if expected_name else []),
                 "Exact two observed owned container absences required")
    for event in ordered:
        record = event["retirement"]
        need(type(record["exit"]) is int and record["exit"] == 0 and record["reaped"] is True
             and record["ownership"] == "REAPED" and record["group_census"] == "EMPTY_TWICE"
             and record["output_complete"] is True and record["signals"] == [] and record["timeout"] is False
             and record["error"] is None, "Complete natural command ownership evidence required")
        label = f"{event['index']:03}"
        raw = read(f"commands/{label}.json", commands/(label+".json"))
        need(all(raw[key] == event[key] for key in ("argv", "retirement", "stdout", "stderr")),
             "Same original owned command record required")
        for stream in ("stdout", "stderr"):
            read(f"commands/{label}.{stream}", commands/(label+"."+stream), event[stream],
                 collect=False, cap=16*1024**2)
    M.unchanged(observed)
    return rows, observed


def export_pair(C, *, stage, commands, source, output, selected):
    """Stream the original allowlisted bodies without invoking actor code."""
    M = C.M
    stage, commands, source, output = map(M.ordinary, (stage, commands, source, output))
    C.need(all(not output.is_relative_to(p) and not p.is_relative_to(output) for p in (stage, commands, source)),
           "Disjoint fresh passive evidence output required")
    rows, observed = pair_members(C, stage=stage, commands=commands, source_map=source/"source-map.json",
                                 inventory=source/"expected356.lock", selected=selected)
    writer = M.Writer(output)
    try:
        for name, (path, pin) in sorted(rows.items()):
            writer.put(name, source=path, expected=pin, observed=observed, cap=ARCHIVE_CAP)
        M.unchanged(observed)
        manifest = dict(kind="QT612_HOSTED_PAIR_EXACT_EXPORT_V1", selected=selected,
                        files={name:pin for name, (_, pin) in rows.items()},
                        lifecycle_status="NOT_RUN", native_acceptance=None, Root_acceptance=None)
        return {key:value for key,value in writer.put(MANIFEST, raw=C.encoded(manifest)).items() if key != "mode"}
    finally:
        writer.close()


def verify_export(C, *, root, manifest_pin, selected):
    """Recompute the exact public bundle from its own passive bytes."""
    M = C.M
    root = M.ordinary(root)
    observed = {}
    manifest = M.load(root/MANIFEST, manifest_pin, observed)
    C.need(set(manifest) == {"kind", "selected", "files", "lifecycle_status", "native_acceptance", "Root_acceptance"}
           and manifest["kind"] == "QT612_HOSTED_PAIR_EXACT_EXPORT_V1" and manifest["selected"] == selected
           and manifest["lifecycle_status"] == "NOT_RUN" and manifest["native_acceptance"] is manifest["Root_acceptance"] is None,
           "Exact separately pinned pair-only export manifest required")
    rows, bodies = pair_members(C, stage=root, commands=root/"commands", source_map=root/"source-map.json",
                               inventory=root/"expected356.lock", selected=selected)
    C.need(manifest["files"] == {name:pin for name, (_, pin) in rows.items()}, "Whole exported evidence map required")
    pending, found = [root], set()
    members = set(rows) | {MANIFEST}
    directories = {str(parent) for name in members for parent in Path(name).parents if str(parent) != "."}
    while pending:
        for path in pending.pop().iterdir():
            relative = path.relative_to(root).as_posix()
            C.need(not path.is_symlink() and (relative in members if path.is_file()
                   else relative in directories and path.is_dir()), "Unexpected raw pair export member")
            if path.is_dir():
                pending.append(path)
            else:
                found.add(relative)
    C.need(found == members, "Complete exact public evidence export required")
    M.unchanged({**observed, **bodies})
    return dict(status="PASS_QT612_HOSTED_PAIR_EXACT_READBACK_ONLY", files=len(rows),
                bytes=sum(pin["bytes"] for _,pin in rows.values()), lifecycle_status="NOT_RUN", Root_acceptance=None)
