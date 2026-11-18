# SPDX-License-Identifier: MIT
"""Project the held Asahi maintenance preflight into finite guest media."""

from itertools import islice
from pathlib import Path
import re

KIND = "ASAHI_MAINTENANCE_DISPOSABLE_TRANSPORT_V1"
PLAN_KIND = "supported-Asahi-maintenance-disposable-guest-preflight-DATA-plan"
SEED = dict(bytes=3680501760,sha256="76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db")
ZIP = dict(bytes=1341634634,sha256="42df228b8bb7a3fc980a94d1eca01bc44a4e29efaf002bf77ffac2fbc08bbbd7")
UUID = "725346d2-f127-47bc-b464-9dd46155e8d6"
ORIGINAL_POLICY = dict(bytes=1531,sha256="0c50cd95593ae1e7d3d1ad4f254528adc36f009e984dcec466f631a822d86549")
SELECTION = dict(bytes=197216,sha256="354dbbccb0982827478d406549d1e53427a4ae887c20640a9fa68a581aa377ac")
PLAN_LIMIT = 512*1024
SIZE = 16*1024**3
IN = Path("/trial-inputs")
TARGET = Path("/trial-scratch")
WORK = Path("/trial-work")
RUNTIME = {
    "base-repository/repo/python-3.14.8-1-aarch64.pkg.tar.xz":
        dict(bytes=13588352,sha256="5e00dbb30ab55fd160d64205e1f3418c8bcf5b295ff07bf9af7ad4ab85bc6984"),
    "base-repository/repo/mpdecimal-4.0.1-3-aarch64.pkg.tar.xz":
        dict(bytes=93808,sha256="388611eba7f9b0dddcc03adb4f28bcb8fd2c42fbd8c930ca6b9b0f9e4ece0f1e"),
}
KEY_IDS = {"alarm","community","cachy-asahi-first-login","cachy-asahi-setup"}
REFS = {
    "baseline.lock":(261,5104,"279fba6cfd35bee27b8ba2d42337bd51be8258ed137e3b814b2a18e1bda4f34d"),
    "forward.lock":(626,12245,"13fe3489158a0bd7d8ca204c350ae852a78680cd2712c8fd8dd9e632b16b09c5"),
    "rollback.lock":(626,12245,"671526351a35f00582e4fab2b0fb66d40832144adb72eb44aa412d6af7ce942c"),
    "forward-preview.lock":(368,7195,"181c578a021115b348b03920bbaa4ca003583bb62bd1fa846367e2d964ee98d0"),
    "rollback-preview.lock":(3,54,"8acb5bd24b577522253d6618ddbb821a0b3c35bd6422366714846f34ecc635be"),
}
REVERSED = {"networkmanager","perl","python"}


def pin(ref):
    return dict(bytes=ref.get("bytes",ref.get("size")),sha256=ref["sha256"])


def relative(T,name):
    T.need(type(name) is str and all(T.NAME.fullmatch(part) and part not in (".","..") for part in name.split("/")),
           "Finite relative guest media paths required")
    return Path(name)


def lock_ref(name):
    _,size,sha=REFS[name]
    return dict(bytes=size,sha256=sha)


def locks(T,root):
    return {name:T.canonical_lock(T.read(root/name,lock_ref(name),cap=64*1024),count)
            for name,(count,_,_) in REFS.items()}


def check_delta(T, rows):
    before,forward,rollback=(rows[name+".lock"] for name in ("baseline","forward","rollback"))
    additions=dict(rows["forward-preview.lock"])
    replacements=dict(rows["rollback-preview.lock"])
    T.need(len(before|additions)==626 and before|additions==forward and forward|replacements==rollback
           and set(before)&set(additions)==set(replacements)==REVERSED
           and all(before[name]==replacements[name]!=forward[name] for name in replacements),
           "Only the inspected 368 forward operands and three inverse replaces are permitted")


def selection_pin(T, manifest):
    # The compiler records the whole input separately because generated DATA contains absolute paths.
    return T.pin(T.encoded({key:value for key,value in manifest.items() if key!="preflight"}))


def project(T, raw, digest, runtime_stage, *, controller_source, actor_image, boot):
    approved=T.decode(raw)
    provenance=T.pin(raw)
    T.need(provenance["sha256"]==digest and T.encoded(approved)==raw and approved["kind"]==PLAN_KIND
           and approved["schema_version"]==1 and approved["installation"]=="NOT RUN"
           and approved["status"]=="HOLD_UNAPPROVED_GUEST" and approved["approval_status"]=="UNAPPROVED"
           and approved["actor_authorized"] is False and approved["transaction_started"] is False
           and T.pin(T.encoded(approved["original_policy"]))==ORIGINAL_POLICY
           and approved["protected_versions_restored_after_rollback"]==201,
           "Exact held proposal data required")
    T.need(approved["controller_source"]==controller_source and approved["controller_actor_image"]==actor_image
           and {name:pin(ref) for name,ref in approved["boot"].items()}==boot,
           "Exact current Overlay583 control source, image and boot inputs required")
    original=approved["original_root"]
    geometry=original["geometry"]
    T.need(pin(original["seed"])==SEED and pin(original["image_zip"])==ZIP
           and geometry==dict(bytes=SEED["bytes"],block_size=4096,free_bytes=514011136,uuid=UUID)
           and approved["guest"]==dict(architecture="aarch64",page_size=16384,network="none",
               use_control_root_as_boot=True,writable_target_is_disposable_clone=True,
               expand_clone_before_forward=True,scratch_bytes=SIZE,forward_archive_installed_bytes=2988144063),
           "Exact original ext4 and selected disposable geometry required")
    sources={}
    rows={}
    for field,suffix in (("expected_locks",".lock"),("expected_previews","-preview.lock")):
        for label,ref in approved[field].items():
            name=label+suffix
            T.need(pin(ref)==lock_ref(name),"Whole inspected inventory or preview pin required")
            rows[name]=T.canonical_lock(T.read(Path(ref["path"]),pin(ref),cap=64*1024),REFS[name][0])
            sources[name]=ref
    check_delta(T,rows)
    T.need(set(sources)==set(REFS),"Exact five inventory and preview files required")
    packages={}
    for phase in ("forward","rollback"):
        index=approved["operand_sources"][phase]
        expected=rows[phase+"-preview.lock"]
        T.need(set(index)==set(expected),"Exact phase package selection required")
        packages[phase]={}
        for name,values in sorted(index.items()):
            archive=values["archive"]
            sig=values["signature"]
            versions={expected[name],expected[name].split(":",1)[-1]}
            leaf=Path(archive["path"]).name
            T.need(any(re.fullmatch(re.escape(name+"-"+version)+r"-(?:aarch64|any)\.pkg\.tar\.(?:xz|zst)",leaf)
                       for version in versions)
                   and Path(sig["path"]).name==leaf+".sig" and pin(archive)["bytes"]>0 and pin(sig)["bytes"]>0,
                   "Exact name, version, architecture and adjacent signature required")
            target=phase+"/"+leaf
            sources[target]=archive
            sources[target+".sig"]=sig
            packages[phase][name]=dict(archive=target,signer=values["primary_fingerprint"],scope=values["signer_role"])
    keys={}
    selected=approved["operand_sources"]["public_keys"]
    T.need(set(selected)==KEY_IDS,"Exact two vendor and two disposable project public keys required")
    for name,row in sorted(selected.items()):
        filename="keys/"+name+".gpg"
        sources[filename]=row["file"]
        keys[name]=dict(file=filename,fingerprint=row["primary_fingerprint"],scope=row["scope"])
    for name,expected in RUNTIME.items():
        sources[name]=dict(expected,path=str(runtime_stage/name))
    value=dict(kind=KIND,approval_status="UNAPPROVED",Root_acceptance=None,
               preflight=provenance,seed=SEED,geometry=geometry,packages=packages,keys=keys,
               files={name:pin(ref) for name,ref in sources.items()})
    check_manifest(T,value)
    return value,sources


def check_manifest(T,value):
    T.need(value["kind"]==KIND and value["approval_status"]=="UNAPPROVED"
           and value["Root_acceptance"] is None and value["seed"]==SEED,
           "No platform approval in rehearsal media")
    origin=value["preflight"]
    T.need(set(origin)=={"bytes","sha256"} and type(origin["bytes"]) is int
           and 0<origin["bytes"]<=PLAN_LIMIT and T.HEX.fullmatch(origin["sha256"]),
           "Whole held proposal provenance required")
    keys=value["keys"]
    T.need(set(keys)==KEY_IDS and all(re.fullmatch("[A-F0-9]{40}",k["fingerprint"]) for k in keys.values())
           and len({k["fingerprint"] for k in keys.values()})==4,
           "Four distinct selected public signers required")
    fingerprint_scopes={k["fingerprint"]:k["scope"] for k in keys.values()}
    T.need({key["scope"] for key in keys.values()}=={"vendor","project-test"}
           and all(row["scope"]==("vendor" if name in ("alarm","community") else "project-test") for name,row in keys.items()),
           "Disjoint approved rehearsal trust scopes required")
    selected=set(REFS)|set(RUNTIME)|{row["file"] for row in keys.values()}
    for phase,count in (("forward",368),("rollback",3)):
        rows=value["packages"][phase]
        T.need(len(rows)==count,"Exact bounded transaction size required")
        for name,row in rows.items():
            leaf=relative(T,row["archive"])
            T.need(leaf.parent==Path(phase) and leaf.name.startswith(name+"-")
                   and fingerprint_scopes.get(row["signer"])==row["scope"],
                   "Wrong scope, signer or package binding")
            selected.update((row["archive"],row["archive"]+".sig"))
    needed=value["files"]
    T.need(set(needed)==selected and len(needed)==753,"Exact ordinary transport manifest required")
    for name,ref in needed.items():
        relative(T,name)
        T.need(type(ref["bytes"]) is int and 0<ref["bytes"]<=512*1024**2 and T.HEX.fullmatch(ref["sha256"]),
               "Finite transport file pin required")
    T.need(sum(ref["bytes"] for ref in needed.values()) < 1024**3,"Selected input budget exceeded")
    T.need(all(needed[name]==ref for name,ref in RUNTIME.items())
           and all(needed[name]==lock_ref(name) for name in REFS),"Exact held runtime and inventory pins required")
    T.need(selection_pin(T,value)==SELECTION,"Exact reviewed Asahi transport selection required")


def rehash(T,root,value,observed=None):
    check_manifest(T,value)
    nodes=list(islice(root.rglob("*"),2048))
    actual={str(path.relative_to(root)) for path in nodes if path.is_file() or path.is_symlink()}
    T.need(len(nodes)<2048 and actual==set(value["files"])|{"manifest.json"} and not any(p.is_symlink() for p in nodes),
           "Exact transport path census required")
    for name,ref in value["files"].items():
        T.read(root/name,ref,cap=512*1024**2,collect=False,observed=observed)
    check_delta(T,locks(T,root))
