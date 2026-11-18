# SPDX-License-Identifier: MIT
"""Collect exact backend inputs in private custody and bind completed product adoption."""
import argparse
import os
from pathlib import Path
import re
import sys
import tarfile
from tempfile import TemporaryDirectory
import types

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backend_private_handoff as H

C, T, S, R = H.C, H.T, H.S, H.reader
KINDS = ("enrollment", "first-login")
DIRECT = {
    "inputs": ("private/inputs.json", 4*T.MIB),
    "prerequisite_timing": ("public/timing.json", T.MIB),
    "prerequisite_report": ("public/host-prerequisite.json", T.MIB),
    "prerequisite_initial_context": ("public/context.json", T.MIB),
    "prerequisite_launcher": ("public/launcher-report.json", T.MIB),
    "prerequisite_controller": ("public/controller-observation.json", T.MIB),
    "material_staging": ("public/material-staging.json", 4*T.MIB),
    "material_close": ("material-domain-close.json", T.MIB),
}
STATIC = {
    "base_lock": "bootstrap/scripts/ci/inputs.lock.json",
    "bootstrap_profile": "native/input-profile.json",
    "baseline_inventory": "inputs/stages/baseline349.expected.lock",
}
EMBEDDED = ("material_grant", "material_assembly_request")
PRODUCER_ROLES = frozenset(DIRECT) | STATIC.keys() | set(EMBEDDED)
INDEPENDENT_ROLES = H.SUPPORT - PRODUCER_ROLES
PAIRS = "private-backend-pairs"
SELECTION = "ROOT_SELECTED_PRIVATE_SOURCE207_HANDOFF_V1"
FAMILY = "scripts/ci/first-login-enrollment-native-source/"
PROFILE_MEMBER = FAMILY+"successor_v2/profile.json"
CONTEXT_MEMBER = FAMILY+"payload/native/delegated_context_v4.py"
ASSEMBLER_MEMBER = FAMILY+"payload/native/inputs_current_v3.py"


def data(path, pin, cap=T.MIB):
    expected = C.whole(pin, cap)
    raw = T.read_local(str(path), expected["bytes"])
    C.need(C.pin(raw) == expected, "HOLD_SOURCE207_ADAPTER_BODY_PIN")
    return raw


def load_producer_support(control, source, request, launcher):
    """Read thirteen original bodies, leaving the nine independent documents to Root."""
    staging = request["material_staging"]
    assembly = staging["assembler_request"]
    bodies = {role:T.read_local(str(control/path), cap) for role,(path,cap) in DIRECT.items()}
    C.need(C.pin(bodies["prerequisite_launcher"]) == C.pin(C.encoded(launcher)),
           "HOLD_SOURCE207_ADAPTER_LAUNCHER")
    bodies.update({role:data(source/path, R.BASE_METADATA_PINS[role]) for role,path in STATIC.items()})
    for role, text, pin, cap in (
        ("material_grant", staging["grant_json"], staging["grant_pin"], T.MIB),
        ("material_assembly_request", assembly["json"], assembly["pin"], 8192),
    ):
        bodies[role] = text.encode()
        C.need(C.pin(bodies[role]) == C.whole(pin,cap), "HOLD_SOURCE207_ADAPTER_EMBEDDED_PIN")
    for role,raw in bodies.items():
        if role not in STATIC:
            R.delegated_public_body(raw)
    return bodies


def package_pair(files, manifest, kind, recipe, original):
    """Keep byte identity for the original pair required by the Context4 adoption API."""
    pair_name = kind + "-pair.public.json"
    original_pin = manifest["origins"][pair_name]["pin"]
    C.need(C.pin(original) == C.whole(original_pin,T.MIB), "HOLD_SOURCE207_ORIGINAL_PAIR_PIN")
    R.delegated_public_body(original)
    pair = C.decode(original)
    projected = C.decode(files[pair_name])
    C.need(set(pair) == set(projected)|{"comparison_receipt"}, "HOLD_SOURCE207_PAIR_PROJECTION")
    T.matches(pair, projected, "HOLD_SOURCE207_PAIR_PROJECTION")
    T.matches(pair, {"binding":manifest["binding"], "nonce":manifest["nonce"], "matching_pair":True,
                     "component":{"name":recipe["name"],"version":recipe["version"],"architecture":"any"}},
              "HOLD_SOURCE207_PAIR_PRODUCER")
    T.matches(pair["comparison_receipt"], {"step":"current-"+kind+"-compare", "exit":0, "success":True},
              "HOLD_SOURCE207_PAIR_COMPARE")
    T.final(pair)
    archive = recipe["archive"]
    C.need(Path(archive).name == archive, "HOLD_SOURCE207_PAIR_ARCHIVE_NAME")
    bodies = [files[f"builds/{kind}-{label}/artifacts/{archive}"] for label in ("a","b")]
    C.need(bodies[0] == bodies[1] and [C.pin(raw) for raw in bodies] == pair["archives"],
           "HOLD_SOURCE207_PAIR_ARCHIVE_BODIES")
    return pair, bodies


def producer(selection, *, mode=None):
    """Selected unchanged-mode companion after separately pinned launcher completion."""
    if mode is None:
        return H.snapshot(None)
    C.need(mode == H.MODE, "HOLD_SOURCE207_ADAPTER_MODE")
    T.fields(selection, ("schema","kind","issuer","approved","snapshot","source_root","request_pin"))
    T.matches(selection, {"schema":1, "kind":SELECTION, "issuer":"Root", "approved":True},
              "HOLD_SOURCE207_ADAPTER_SELECTION")
    chosen = selection["snapshot"]
    control, owner, private, source = (Path(value) for value in
        (chosen["control_root"], chosen["owner_root"], chosen["private_root"], selection["source_root"]))
    H.private_directory(private)
    C.need(source.is_absolute() and source.resolve(strict=True) == source and
           all(H.disjoint(source,path) for path in (control, owner, private)), "HOLD_SOURCE207_ADAPTER_SOURCE_ROOT")
    source_lock = data(source/"source.lock.json", S.SOURCE["source_map"])
    C.need(data(source/"source-map.json", S.SOURCE["source_map"]) == source_lock, "HOLD_SOURCE207_ADAPTER_SOURCE_MAP")
    source_leaves = C.decode(source_lock)["files"]
    profile = C.decode(data(source/PROFILE_MEMBER, R.whole(source_leaves[PROFILE_MEMBER])))
    raw_request = data(control/"private/request.json", selection["request_pin"], C.LIMITS["request_bytes"])
    request = C.decode(raw_request)
    delegation_raw = request["delegation_json"].encode()
    delegation = C.decode(delegation_raw)
    binding = H.exact_binding(chosen["binding"])
    T.matches(delegation["binding"], {key:binding[key] for key in ("source","ref","source_lock")},
              "HOLD_SOURCE207_ADAPTER_REQUEST_BINDING")
    T.matches(delegation, {"stage":"backend","nonce":chosen["nonce"]}, "HOLD_SOURCE207_ADAPTER_REQUEST_BINDING")
    C.need(C.pin(delegation_raw)==request["delegation_pin"], "HOLD_SOURCE207_ADAPTER_DELEGATION_PIN")
    launcher = C.decode(data(control/H.LAUNCHER, chosen["expected"]["launcher"]))
    T.matches(launcher, {"request_pin":C.pin(raw_request)}, "HOLD_SOURCE207_ADAPTER_REQUEST_PIN")
    destination=private/"producer-handoff"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    with TemporaryDirectory(prefix=".source207-producer-",dir=private) as temporary:
        pending=Path(temporary)
        held = H.snapshot(chosen | {"private_root":str(pending)},mode=mode)
        snapshot_root=Path(held["path"])
        support = load_producer_support(control,source,request,launcher)
        manifest = C.decode(data(snapshot_root/"retention-manifest.json",held["files"]["retention-manifest.json"]))
        capsule = data(snapshot_root/"backend.capsule.tar.gz",held["files"]["backend.capsule.tar.gz"],R.MAX_COMPRESSED)
        files, _ = R.delegated_capsule_files(capsule, capsule_selector(manifest, capsule))
        C.need(files["delegation.json"] == delegation_raw, "HOLD_SOURCE207_ADAPTER_ACTUAL_DELEGATION")
        pairs={}
        for kind in KINDS:
            original_pin = manifest["origins"][kind+"-pair.public.json"]["pin"]
            original = data(owner/PAIRS/(kind+".json"), original_pin)
            package_pair(files,manifest,kind,profile["packages"][kind],original)
            pairs[kind] = original
        staged=pending/"complete"
        staged.mkdir(mode=0o700)
        snapshot_root.rename(staged/"snapshot")
        write_group(staged/"support",support)
        write_group(staged/"pairs",pairs)
        result=dict(kind="SOURCE207_PRIVATE_PRODUCER_HANDOFF_DATA_V1",binding=binding,nonce=chosen["nonce"],
                    transfer_pin=held["transfer_pin"], support={role:C.pin(raw) for role,raw in support.items()},
                    pairs={kind:C.pin(raw) for kind,raw in pairs.items()}, independent=sorted(INDEPENDENT_ROLES),
                    first_usable_login_ready=False, **C.FINAL)
        write_body(staged/"producer.json", C.encoded(result))
        publish_directory(staged,destination)
    return dict(result, path=str(destination), producer_pin=C.pin(C.encoded(result)))


def capsule_selector(manifest, capsule):
    return {key:manifest[key] for key in ("stage","binding","nonce","delegation_pin","context_pin",
                                          "stage_report_pin","image_report_pin")} | {
        "source":{"retention":R.BASE_RETENTION_PIN}, "capsule_pin":C.pin(capsule),
        "origin_pins": {name:{"original":row["pin"],"projection":manifest["files"][name]}
                        for name,row in manifest["origins"].items()}}


def write_body(path, body):
    with os.fdopen(os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o400),"wb") as stream:
        stream.write(body)


def write_group(directory, bodies):
    directory.mkdir(mode=0o700)
    for role,raw in bodies.items():
        write_body(directory/(role+".json"),raw)


def publish_directory(staged, destination):
    destination.mkdir(mode=0o700)
    try:
        staged.rename(destination)
    except OSError:
        destination.rmdir()
        raise


def consumer(root, producer_pin, *, expected_raw, expected_pin, source_files, independently_retained, now):
    """Bind the thirteen original and nine independent inputs to the unchanged full Reader."""
    H.private_directory(root)
    C.need({path.name for path in root.iterdir()} == {"producer.json","support","pairs","snapshot"},
           "HOLD_SOURCE207_ADAPTER_CLOSED_HANDOFF")
    producer = C.decode(data(root/"producer.json", producer_pin))
    T.matches(producer, {"kind":"SOURCE207_PRIVATE_PRODUCER_HANDOFF_DATA_V1","first_usable_login_ready":False,
                         "independent":sorted(INDEPENDENT_ROLES)}, "HOLD_SOURCE207_ADAPTER_PRODUCER")
    T.final(producer)
    T.fields(producer["support"], PRODUCER_ROLES)
    T.fields(producer["pairs"], KINDS)
    for directory, names in (("support",PRODUCER_ROLES),("pairs",KINDS)):
        held = root/directory
        H.private_directory(held)
        C.need({path.name for path in held.iterdir()} == {role+".json" for role in names},
               "HOLD_SOURCE207_ADAPTER_CLOSED_HANDOFF")
    C.need(type(independently_retained) is dict and set(independently_retained)<=INDEPENDENT_ROLES,
           "HOLD_SOURCE207_ADAPTER_INDEPENDENT_ROSTER")
    missing = sorted(INDEPENDENT_ROLES-set(independently_retained))
    if missing:
        return dict(status="HOLD_SOURCE207_INDEPENDENT_BACKEND_SUPPORT", missing=missing, **C.FINAL)
    refs = {role:dict(path=str(root/"support"/(role+".json")),pin=pin) for role,pin in producer["support"].items()}
    return H.replay(root/"snapshot",producer["transfer_pin"],expected_raw=expected_raw,expected_pin=expected_pin,
                    source_files=source_files,support_refs=refs|independently_retained,now=now)


def selected_module(name, member, source_files, descriptor):
    T.fields(descriptor, ("member","bytes","sha256"))
    raw = source_files[member]
    C.need(descriptor["member"] == member and C.pin(raw) == R.whole(descriptor),
           "HOLD_SOURCE207_ADAPTER_CONSUMER_PROGRAM")
    module = types.ModuleType(name)
    module.__file__ = member
    exec(compile(raw,member,"exec"),module.__dict__)
    return module


def stage_product(root, producer_pin, *, expected_raw, expected_pin, source_files, independently_retained,
                  consumer_raw, consumer_pin, product_root, kind, test, signatures, public_test_key, now):
    """Materialize one assembler-ready product after the exact complete backend replay."""
    C.need(kind in KINDS, "HOLD_SOURCE207_ADAPTER_PRODUCT")
    result = consumer(root,producer_pin,expected_raw=expected_raw,expected_pin=expected_pin,
                      source_files=source_files,independently_retained=independently_retained,now=now)
    if result["status"] != "PASS_DELEGATED_PUBLIC_CURRENT_STAGE_DATA_ONLY":
        return result
    expected = C.decode(expected_raw)
    C.need(C.pin(consumer_raw)==C.whole(consumer_pin), "HOLD_SOURCE207_ADAPTER_CONSUMER_PIN")
    H.private_directory(product_root)
    C.need(H.disjoint(product_root,root), "HOLD_SOURCE207_ADAPTER_PRODUCT_DESTINATION")
    delegation = C.decode(consumer_raw)
    C.need(delegation["stage"] == "lifecycle" or (delegation["stage"],kind)==("ui","first-login"),
              "HOLD_SOURCE207_ADAPTER_CONSUMER_STAGE")
    T.matches(delegation["binding"], {key:expected["binding"][key] for key in ("source","ref","source_lock")},
              "HOLD_SOURCE207_ADAPTER_CONSUMER_SOURCE")
    context_desc=delegation["programs"]["context"]
    C.need(R.whole(context_desc)==R.CURRENT_CONTEXT4_PIN, "HOLD_SOURCE207_ADAPTER_CONTEXT_VERSION")
    context=selected_module("source207_consumer_context",CONTEXT_MEMBER,source_files,context_desc)
    delegation=context.validate_delegation(consumer_raw,consumer_pin["sha256"],now=now)
    assembler=selected_module("source207_consumer_assembler",ASSEMBLER_MEMBER,source_files,
                              delegation["programs"]["inputs_assembler"])
    profile=C.decode(source_files[PROFILE_MEMBER])
    recipe=profile["packages"][kind]
    selection_role = None
    if "pair_selections" in delegation:
        matches = [role for role,row in delegation["pair_selections"].items()
                   if row["component"]["name"]==recipe["name"]]
        C.need(len(matches)==1,"HOLD_SOURCE207_ADAPTER_SELECTED_ROLE")
        selection_role = matches[0]
    selected = context._selection(delegation,selection_role)
    C.need(selected is not None and selected["public_test_key_pin"] == C.pin(public_test_key) == R.SELECTED_TEST_KEY_PIN,
           "HOLD_SOURCE207_ADAPTER_CONSUMER_TEST_KEY")
    capsule = data(root/"snapshot/backend.capsule.tar.gz",expected["capsule_pin"],R.MAX_COMPRESSED)
    files,manifest=R.delegated_capsule_files(capsule,expected)
    original_pair=data(root/"pairs"/(kind+".json"),manifest["origins"][kind+"-pair.public.json"]["pin"])
    _,archives=package_pair(files,manifest,kind,recipe,original_pair)
    C.need(result["backend_reader"]["packages"][kind]["archive"]==C.pin(archives[0]),
           "HOLD_SOURCE207_ADAPTER_REPLAYED_ARCHIVE")
    def input_support(role):
        ref=independently_retained[role]
        return data(Path(ref["path"]),expected["support_pins"][role])
    bodies={"pair":original_pair,"producer_context":files["context.json"],"producer_delegation":files["delegation.json"],
            "completion":input_support("completion"),"root_component":input_support("component_"+kind),"root_test":test}
    C.need(type(signatures) in (list,tuple) and len(signatures)==2 and
           all(type(raw) is bytes and 0<len(raw)<=65536 for raw in signatures) and [C.pin(raw) for raw in signatures]==selected["signatures"],
           "HOLD_SOURCE207_ADAPTER_ACTUAL_TEST_SIGNATURES")
    for group,values in (("archives",archives),("signatures",signatures)):
        bodies.update({group+"-"+str(i):raw for i,raw in enumerate(values)})
    def check(refs):
        assembler.selected_product(kind,refs,profile,delegation,context,
                                   {"public_key":selected["public_test_key_pin"],"fingerprint":selected["test_fingerprint"]})
    refs = retain_product(product_root/kind,recipe["archive"],selection_role,bodies,check)
    return dict(status="SOURCE207_ASSEMBLER_PRODUCT_REFS_STAGED_DATA_ONLY",product=refs,
                first_usable_login_ready=False, **C.FINAL)


def retain_product(target, archive, selection_role, bodies, check):
    """Stage fixed product roles atomically after the original assembler checks them."""
    if target.exists() or target.is_symlink():
        raise FileExistsError(target)
    C.need(Path(archive).name == archive and archive not in ("",".",".."),"HOLD_SOURCE207_PAIR_ARCHIVE_NAME")
    T.fields(bodies, ("pair","producer_context","producer_delegation","completion","root_component","root_test",
                      "archives-0","archives-1","signatures-0","signatures-1"))
    with TemporaryDirectory(prefix=".source207-product-",dir=target.parent) as temporary:
        staged=Path(temporary)/target.name
        staged.mkdir(mode=0o700)
        names={name:name+".json" for name in bodies}
        for i in range(2):
            names[f"archives-{i}"]=f"build-{i}/{archive}"
            names[f"signatures-{i}"]=names[f"archives-{i}"]+".sig"
        for name, body in bodies.items():
            path=staged/names[name]
            path.parent.mkdir(mode=0o700,exist_ok=True)
            write_body(path,body)
        def refs(directory):
            operands={name:dict(path=str(directory/names[name]),**C.pin(raw)) for name,raw in bodies.items()}
            return {**{key:operands[key] for key in bodies if not key.startswith(("archives-","signatures-"))},
                    **{group:[operands[group+"-"+str(i)] for i in range(2)] for group in ("archives","signatures")},
                    "kind":"ROOT_SELECTED_PRODUCT_INPUT_REFS_V4","selection_role":selection_role}
        check(refs(staged))
        publish_directory(staged,target)
    return refs(target)


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=(H.MODE,))
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--selection-sha256")
    args=parser.parse_args()
    sys.addaudithook(H.review.fence)
    try:
        C.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, "HOLD_SOURCE207_ADAPTER_ISOLATION")
        selection=None
        if args.mode is not None:
            C.need(args.selection is not None, "HOLD_SOURCE207_ADAPTER_SELECTION")
            raw=T.read_local(str(args.selection),C.MAX_BYTES)
            C.need(C.pin(raw)["sha256"]==args.selection_sha256, "HOLD_SOURCE207_ADAPTER_SELECTION_PIN")
            selection=C.decode(raw)
        result=producer(selection,mode=args.mode)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, tarfile.TarError) as error:
        reason=str(error) if isinstance(error,ValueError) and re.fullmatch(r"HOLD_[A-Z_0-9]+",str(error)) else None
        print(C.encoded(dict(status="HOLD_SOURCE207_PRIVATE_PRODUCER_INPUT",reason=reason,**C.FINAL)).decode(),end="")
        raise SystemExit(2)
    print(C.encoded(result).decode(),end="")
