# SPDX-License-Identifier: MIT
"""Prepare and verify an exact offline 583-package disposable guest trial."""

import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
from itertools import islice
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
BASE = "base-repository"
KIT = "offline-overlay-kit"
RELEASE = KIT+"/release"
BASE_REPO = "desktop574-test"
OVERLAY_REPO = "setup8-shells-overlay-test"
BASE_INVENTORY = BASE+"/installed-inventory.lock"
REPOS = {OVERLAY_REPO: RELEASE+"/repo", BASE_REPO: BASE+"/repo"}
SUFFIXES = (".db.tar.gz", ".db.tar.gz.sig", ".files.tar.gz", ".files.tar.gz.sig")
GPG_PATHS = (KIT+"/public.gpg", BASE+"/repository-TEST-public.gpg", BASE+"/archlinuxarm.gpg")
HEX = re.compile("[0-9a-f]{64}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+@:-]{0,254}")
MAX_MEMBER = 512*1024**2
MAX_PACKAGE_BYTES = 2*1024**3
IN, WORK = Path("/trial-inputs"), Path("/trial-work")
CONFIG, TARGET, OUTPUT = WORK/"pacman.conf", WORK/"target", WORK/"evidence"
PLAN = Path("/trial-code/plan.json")
PINS = {'bytes': 2568, 'sha256': '0ed0f7ccd177280d6a9132c436e71aac4a669d04f5ba6a1f66f738b78cd9e3ff'}
TIMEOUT = 3600
LIFECYCLE_HOLD_EXIT = 75
UPGRADE_KIND = "OVERLAY583_SETUP7_TO_SETUP8_GUEST_PLAN_V1"
UPGRADE_HOLD = "HOLD_DISPOSABLE_OVERLAY583_SETUP_UPGRADE"
INSTALL_PASS = "PASS_DISPOSABLE_PACMAN_TRANSACTION_ONLY"
LIFECYCLE_PASS = "PASS_DISPOSABLE_OVERLAY583_LIFECYCLE_ONLY"
LIFECYCLE_HOLD = "HOLD_DISPOSABLE_OVERLAY583_LIFECYCLE"
RECOVERY_PASS = "PASS_DISPOSABLE_OVERLAY583_SIGNATURE_RECOVERY_ONLY"
PROBE_PACKAGE = "cachy-asahi-fish-autopair"
PROBE_ROLE = "signature-refusal"
DB_BEFORE = "refusal-db-before.json"
DB_AFTER = "refusal-db-after.json"
HOOK_FAILURE = re.compile(rb"(?im)^error: (?:failed to execute|command failed)")


def need(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False)+"\n").encode()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    def reject(_value):
        raise ValueError("Non-finite JSON constant")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ordinary(path):
    p = Path(path)
    need(p.is_absolute() and p == p.resolve() and not any(k.is_symlink() for k in (p,*p.parents)),
         "Canonical ordinary absolute path required")
    return p


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def read(path, expected=None, *, cap=MAX_MEMBER, collect=True, observed=None, allowed_links=(1,)):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,"rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink in allowed_links and 0 <= before.st_size <= cap,
             "Finite ordinary file with selected link count required: "+path.name)
        if expected is not None:
            need(type(expected) is dict and set(expected) == {"bytes","sha256"}
                 and type(expected["bytes"]) is int and expected["bytes"] == before.st_size
                 and type(expected["sha256"]) is str and HEX.fullmatch(expected["sha256"]),
                 "Expected file length or digest differs: "+path.name)
        if collect:
            raw = stream.read(before.st_size+1)
            digest = pin(raw)
        else:
            raw, hasher, remaining = None, hashlib.sha256(), before.st_size
            while remaining:
                chunk = stream.read(min(remaining,1024**2))
                need(chunk, "Short pinned file read")
                hasher.update(chunk)
                remaining -= len(chunk)
            need(not stream.read(1), "Pinned file grew")
            digest = dict(bytes=before.st_size,sha256=hasher.hexdigest())
        need(digest["bytes"] == before.st_size
             and identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat())
             and (expected is None or digest == expected), "Changed pinned bytes: "+path.name)
        if observed is not None:
            key = str(path)
            need(key not in observed or observed[key] == identity(before), "Reopened file identity changed")
            observed[key] = identity(before)
        return raw if collect else digest


def unchanged(observed):
    need(all(identity(ordinary(path).lstat()) == row for path,row in observed.items()), "Input changed at readback")


def canonical_lock(raw, count):
    lines = raw.decode("ascii").splitlines(keepends=True)
    need(len(lines) == count and lines == sorted(lines), "Exact sorted pacman lock required")
    packages = {}
    for row in lines:
        fields = row.removesuffix("\n").split(" ")
        need(row.endswith("\n") and len(fields)==2 and all(NAME.fullmatch(part) for part in fields)
             and fields[0] not in packages, "Invalid or duplicate pacman lock row")
        packages[fields[0]] = fields[1]
    return packages


def choose(staging, *, selected_lock):
    """Reopen actual staging bytes. No signature or transaction actor runs here."""
    stage = ordinary(staging)
    wanted = decode(read(HERE/"staging-pins.json", selected_lock, cap=128*1024))
    need(wanted["kind"] == "OVERLAY583_LOCAL_STAGING_PINS_V1", "Expected selected staging lock")
    pins = wanted["files"]
    observed = {}
    contents = {name:read(stage/name,row,cap=16*1024**2,observed=observed) for name,row in pins.items()}
    staging_receipt = decode(contents["staging.json"])
    base_receipt_raw = contents[BASE+"/staging.json"]
    base_receipt = decode(base_receipt_raw)
    base_indexes = base_receipt["repository_files"]
    base = decode(contents[BASE+"/desktop574-inputs.lock.json"])
    overlay = decode(contents[RELEASE+"/release.json"])
    spec = decode(contents[RELEASE+"/spec.json"])
    need(spec["repo_name"] == OVERLAY_REPO and spec["target_arch"] == "aarch64" and spec["synthetic"] is True
         and staging_receipt["target_lock_sha256"] == pins["target.lock"]["sha256"]
         and staging_receipt["base_lock_sha256"] == pins[BASE+"/desktop574-inputs.lock.json"]["sha256"]
         and staging_receipt["base_receipt_sha256"] == pin(base_receipt_raw)["sha256"]
         and staging_receipt["overlay_release_sha256"] == pins[RELEASE+"/release.json"]["sha256"]
         and staging_receipt["offline_kit_sha256"] == pins[KIT+"/kit.json"]["sha256"],
         "Staging, base, kit and target pins do not join")
    need((staging_receipt["base_packages"],staging_receipt["overlay_packages"],staging_receipt["target_packages"]) == (574,9,583),
         "Different staging cardinalities")
    signers = (staging_receipt["overlay_signer"], staging_receipt["base_signer"], base["signer_fingerprint"])
    need(len(set(signers)) == 3 and all(re.fullmatch("[0-9A-F]{40}",x) for x in signers)
         and overlay["signer"] == signers[0] and base_receipt["repository_test_signer"] == signers[1]
         and base_receipt["original_signer"] == signers[2], "Exact separate repository and package signers required")
    need(set(base_indexes)=={BASE_REPO+suffix for suffix in SUFFIXES},"Exact signed base index map required")
    target = canonical_lock(contents["target.lock"],583)
    baseline = canonical_lock(contents[BASE_INVENTORY],574)
    packages, file_pins, aliases = {}, {}, {}
    for repo, rows, count in ((BASE_REPO,base["packages"],574),(OVERLAY_REPO,overlay["packages"],9)):
        need(len(rows)==count, "Repository package count differs")
        for row in rows:
            name, version, arch = (row[key] for key in ("name","version","arch"))
            leaf = row["filename"]
            need(NAME.fullmatch(name) and NAME.fullmatch(version) and arch in ("any","aarch64")
                 and name not in packages and leaf == f"{name}-{version}-{arch}.pkg.tar.xz"
                 and target.get(name)==version and (baseline.get(name)==version if repo==BASE_REPO else name not in baseline),
                 "Invalid or overlapping selected package")
            packages[name] = dict(version=version,repo=repo)
            for suffix, field, size_key in (("","sha256","size"),(".sig","signature_sha256","signature_size")):
                relative = REPOS[repo]+"/"+leaf+suffix
                path = stage/relative
                declared = row[field] if repo==BASE_REPO else overlay["files"]["repo/"+leaf+suffix]
                available = row[size_key] if repo==BASE_REPO else path.lstat().st_size
                need(type(available) is int and available>0,"Nonempty selected package input required")
                expected = dict(bytes=available,sha256=declared)
                file_pins[relative] = read(path,expected,cap=1024**2 if suffix else MAX_MEMBER,
                                           collect=False,observed=observed)
        for suffix in SUFFIXES:
            leaf = repo+suffix
            relative = REPOS[repo]+"/"+leaf
            path = stage/relative
            expected = base_indexes[leaf] if repo==BASE_REPO else overlay["files"]["repo/"+leaf]
            file_pins[relative] = read(path,dict(bytes=path.lstat().st_size,sha256=expected),
                                       cap=32*1024**2,collect=False,observed=observed)
        for name,content in ((".db",".db.tar.gz"),(".db.sig",".db.tar.gz.sig"),
                             (".files",".files.tar.gz"),(".files.sig",".files.tar.gz.sig")):
            aliases[REPOS[repo]+"/"+repo+name] = repo+content
    need(len(packages) == 583 and set(packages)==set(target)
         and sum(row["bytes"] for row in file_pins.values()) <= MAX_PACKAGE_BYTES,
         "Selected package set or byte budget differs")
    check_repos(stage,file_pins,aliases)
    unchanged(observed)
    return dict(schema=1,kind="OVERLAY583_TRANSACTION_DATA_V1",main_commit=wanted["main_commit"],
                target=pins["target.lock"],baseline=pins[BASE_INVENTORY],
                packages=packages,files=file_pins,aliases=aliases,
                trust={name:pins[name] for name in GPG_PATHS},signers=list(signers),
                staging_receipt=pins["staging.json"],base_receipt=pins[BASE+"/staging.json"],
                base_lock=pins[BASE+"/desktop574-inputs.lock.json"],kit=pins[KIT+"/kit.json"],
                release=pins[RELEASE+"/release.json"],authenticated_preflight=wanted["authenticated_preflight"],
                release_declares_synthetic_fixture=True,
                preflight=None,executed=False,Root_acceptance=None)


def check_repos(root, files, aliases):
    for repo in REPOS.values():
        expected = {Path(name).name for name in files.keys() | aliases.keys() if name.startswith(repo+"/")}
        actual = {child.name for child in ordinary(root/repo).iterdir()}
        need(actual==expected,"Unexpected or absent repository member")
    for name, target in aliases.items():
        path = root/name
        need(path.is_symlink() and os.readlink(path)==target,"Repository alias differs")


def pacman_plan(packet):
    return "".join(f'{name} {row["version"]} {row["repo"]}\n' for name,row in sorted(packet["packages"].items())).encode("ascii")


def admit(packet, receipt, receipt_pin):
    """Join a Root-selected preflight receipt. External custody is mandatory."""
    need(pin(receipt)==receipt_pin==packet["authenticated_preflight"],"Exact original preflight receipt pin required")
    data = decode(receipt)
    need(data.get("status") == "verified-offline-install-preflight"
         and data.get("base_archives_authenticated") is True and data.get("base_rootfs_authenticated") is True
         and data.get("synthetic") is packet["release_declares_synthetic_fixture"]
         and data.get("pacman_siglevel") == "Required TrustedOnly"
         and data.get("packages_installed") is False and data.get("transaction_authorized") is False,
         "Authenticated preflight of the exact development fixture required")
    fields = {"kit_sha256":packet["kit"]["sha256"],"release_sha256":packet["release"]["sha256"],
              "target_lock_sha256":packet["target"]["sha256"],"base_lock_sha256":packet["base_lock"]["sha256"],
              "base_receipt_sha256":packet["base_receipt"]["sha256"],"base_signer":packet["signers"][1],
              "base_package_signer":packet["signers"][2],"target_package_count":583,
              "base_package_count":574,"overlay_package_count":9,
              "pacman_plan_sha256":pin(pacman_plan(packet))["sha256"]}
    for k,v in fields.items():
        need(data.get(k)==v,"Different preflight "+k)
    need(data.get("signer",{}).get("primary_fingerprint")==packet["signers"][0],
         "Different preflight overlay signer")
    return dict(packet,preflight=receipt_pin)


def lifecycle_operands(packet):
    baseline, overlay, resolution = [], [], []
    for name,row in sorted(packet["packages"].items()):
        version, repo = row["version"], row["repo"]
        need(NAME.fullmatch(name) and NAME.fullmatch(version) and repo in REPOS,
             "Invalid lifecycle package identity")
        if repo == BASE_REPO:
            baseline.append(f"{name} {version}\n")
        else:
            overlay.append(f"{name} {version}\n")
            resolution.append(f"{name} {version} {repo}\n")
    base_lock = "".join(baseline).encode("ascii")
    need(len(baseline)==574 and len(overlay)==9 and pin(base_lock)==packet["baseline"],
         "Exact authenticated baseline and nine overlay operands required")
    return base_lock, "".join(overlay).encode("ascii"), "".join(resolution).encode("ascii")


def probe_operand(packet):
    row = packet["packages"].get(PROBE_PACKAGE)
    need(row is not None and row["repo"]==OVERLAY_REPO,"Selected overlay refusal operand required")
    name = f'{PROBE_PACKAGE}-{row["version"]}-any.pkg.tar.xz'
    relative = REPOS[OVERLAY_REPO]+"/"+name
    need(relative in packet["files"] and relative+".sig" in packet["files"],
         "Original signed archive and detached signature required")
    return relative, WORK/"signature-probe"/name


def guest_plan(packet, nonce, *, lifecycle=False, signature_recovery=False):
    need(packet["preflight"] is not None and re.fullmatch("[0-9a-f]{32}",nonce or ""),
         "Selected preflight and guest nonce required")
    options = ["--config",str(CONFIG),"--root",str(TARGET),"--dbpath",str(TARGET/"var/lib/pacman"),
               "--gpgdir",str(WORK/"trust"),"--cachedir",str(WORK/"cache"),"--logfile",str(OUTPUT/"pacman.log")]
    command = ["/usr/bin/pacman",*options]
    targets = [row["repo"]+"/"+name for name,row in sorted(packet["packages"].items())]
    plan = dict(kind="OVERLAY583_OWNED_GUEST_PLAN_V1",nonce=nonce,packet=packet,
                timeout_seconds=TIMEOUT,Root_acceptance=None,
                operations=[
                    ["refresh",[*command,"--sync","--refresh","--noconfirm"],60],
                    ["resolve",[*command,"--sync","--print","--print-format","%n %v %r","--",*targets],120],
                    ["install",[*command,"--sync","--noconfirm","--",*targets],2700],
                    ["query",[*command,"--query"],60],
                    ["check",[*command,"--database","--check"],60],
                ])
    if lifecycle or signature_recovery:
        lifecycle_operands(packet)
        names = [name for name,row in sorted(packet["packages"].items()) if row["repo"]==OVERLAY_REPO]
        repo_names = [OVERLAY_REPO+"/"+name for name in names]
        options[options.index("--cachedir")+1] = str(WORK/"lifecycle-cache")
        command = ["/usr/bin/pacman",*options]
        plan["lifecycle"] = True
        plan["operations"] += [
            ["remove-plan",[*command,"--remove","--print","--print-format","%n %v","--",*names],60],
            ["remove",[*command,"--remove","--noconfirm","--",*names],180],
            ["query-base",[*command,"--query"],60],
            ["check-base",[*command,"--database","--check"],60],
            ["reinstall-plan",[*command,"--sync","--print","--print-format","%n %v %r","--",*repo_names],60],
            ["reinstall",[*command,"--sync","--noconfirm","--",*repo_names],300],
            ["query-restored",[*command,"--query"],60],
            ["check-restored",[*command,"--database","--check"],60],
        ]
        if signature_recovery:
            _, probe = probe_operand(packet)
            plan["signature_recovery"] = True
            position = next(i for i,row in enumerate(plan["operations"]) if row[0]=="reinstall-plan")
            plan["operations"][position:position] = [
                [PROBE_ROLE,[*command,"--upgrade","--noconfirm","--",str(probe)],120],
                ["query-refused",[*command,"--query"],60],
                ["check-refused",[*command,"--database","--check"],60],
            ]
    return plan


def upgrade_path():
    if HERE == PLAN.parent:
        return HERE/"upgrade.py"
    return HERE.parent/"overlay583_upgrade/upgrade.py"


def upgrade_module(expected=None):
    path = upgrade_path()
    raw = read(path,expected,cap=128*1024)
    spec = importlib.util.spec_from_file_location("overlay583_setup_upgrade",path)
    loaded = importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),"exec"),loaded.__dict__)
    return loaded


def target_bytes(packet):
    raw = "".join(f'{name} {row["version"]}\n' for name,row in sorted(packet["packages"].items())).encode("ascii")
    need(pin(raw)==packet["target"],"Derived target inventory differs")
    return raw


def selected_plan(packet, nonce, *, lifecycle=False, signature_recovery=False, predecessor=None, predecessor_pin=None):
    if predecessor is None:
        need(predecessor_pin is None,"Unexpected predecessor digest")
        return guest_plan(packet,nonce,lifecycle=lifecycle,signature_recovery=signature_recovery)
    need(not lifecycle and not signature_recovery and predecessor_pin is not None,
         "Choose only one Overlay583 operation")
    upgrade = upgrade_module()
    return upgrade.plan(packet,target_bytes(packet),upgrade.check_stage(predecessor,predecessor_pin),nonce)


def mount_mode(path, mode, lines):
    found = [parts for line in lines if len(parts := line.split()) >= 10 and parts[4] == str(path)]
    need(len(found)==1 and mode in found[0][5].split(","), "Expected isolated mount at "+str(path))


def evidence_names(plan):
    if plan.get("kind")==UPGRADE_KIND:
        return upgrade_module(plan["upgrade_worker"]).evidence_names(plan)
    roles = {"import-0", "import-1", "import-2", "ownertrust"} | {row[0] for row in plan["operations"]}
    snapshots = {"installed.lock", "result.json", "pacman.log"}
    if plan.get("lifecycle"):
        snapshots.update(("removed.lock","reinstalled.lock"))
    if plan.get("signature_recovery"):
        snapshots.update(("refused.lock",DB_BEFORE,DB_AFTER))
    return snapshots | {
        f"{role}.{stream}" for role in roles for stream in ("stdout", "stderr")
    }


def sorted_rows(raw):
    return b"".join(sorted(raw.splitlines(keepends=True)))


def role_outputs(plan, target):
    packet = plan["packet"]
    expected = dict(resolve=(pacman_plan(packet),None), query=(target,"installed.lock"))
    if plan.get("lifecycle"):
        baseline, removed, resolution = lifecycle_operands(packet)
        expected.update({
            "remove-plan":(removed,None), "query-base":(baseline,"removed.lock"),
            "reinstall-plan":(resolution,None), "query-restored":(target,"reinstalled.lock"),
        })
        if plan.get("signature_recovery"):
            expected["query-refused"] = baseline,"refused.lock"
    return expected


def target_api_mounts(target, env, stack):
    """Provide the normal chroot API filesystems using guest-only mounts."""
    for name,kind,options in (
        ("proc","proc","ro,nosuid,nodev,noexec"),
        ("sys","sysfs","ro,nosuid,nodev,noexec"),
        ("run","tmpfs","mode=0755,nosuid,nodev,noexec,size=64m"),
        ("dev","tmpfs","mode=0755,nosuid,noexec,size=4m"),
    ):
        path = target/name
        path.mkdir(mode=0o755,exist_ok=True)
        need(path.is_dir() and not path.is_symlink(),"Ordinary guest API mountpoint required: "+name)
        subprocess.run(["/usr/bin/mount","-n","-t",kind,"-o",options,kind,str(path)],
                       env=env,stdin=subprocess.DEVNULL,timeout=15,check=True)
        stack.callback(subprocess.run,["/usr/bin/umount","-n",str(path)],
                       env=env,stdin=subprocess.DEVNULL,timeout=15,check=True)
    for name,major,minor in (("null",1,3),("zero",1,5),("full",1,7),("random",1,8),
                             ("urandom",1,9),("tty",5,0)):
        path = target/"dev"/name
        os.mknod(path,stat.S_IFCHR|0o666,os.makedev(major,minor))
        path.chmod(0o666)
    for name,source in (("fd","/proc/self/fd"),("stdin","fd/0"),("stdout","fd/1"),("stderr","fd/2")):
        (target/"dev"/name).symlink_to(source)


def guest(plan_sha256, worker_sha256):
    """Run only from the externally owned offline disposable ARM guest."""
    need(os.getuid()==os.geteuid()==0 and os.uname().machine=="aarch64", "A native ARM guest root is required")
    mounts = Path("/proc/self/mountinfo").read_text().splitlines()
    for path in (IN, PLAN.parent):
        mount_mode(path,"ro",mounts)
    mount_mode(WORK,"rw",mounts)
    need(WORK.stat().st_dev!=Path("/").stat().st_dev and not list(WORK.iterdir()),
         "Fresh guest-only scratch mount required")
    usage = os.statvfs(WORK)
    need(usage.f_bavail*usage.f_frsize>=12*1024**3,"Disposable guest scratch budget unavailable")
    need({p.name for p in Path("/sys/class/net").iterdir()} <= {"lo"}, "Offline guest required")
    need(read(Path(__file__).absolute(),collect=False,cap=128*1024)["sha256"]==worker_sha256,
         "Guest program differs")
    raw = read(PLAN,cap=1024**2)
    need(pin(raw)["sha256"]==plan_sha256,"Guest plan differs")
    plan = decode(raw)
    packet, nonce = plan["packet"], plan["nonce"]
    lifecycle = plan.get("lifecycle") is True
    recovery = plan.get("signature_recovery") is True
    need(raw==encoded(plan)
         and Path("/proc/cmdline").read_text().split().count("cachy_overlay583_nonce="+nonce)==1,
         "Exact owned guest boot nonce required")
    upgrade = upgrade_module(plan["upgrade_worker"]) if plan.get("kind")==UPGRADE_KIND else None
    if upgrade is None:
        need(plan==guest_plan(packet,nonce,lifecycle=lifecycle,signature_recovery=recovery),"Exact selected guest plan required")
    else:
        predecessor = upgrade.check_stage(IN/upgrade.PREDECESSOR,plan["predecessor"]["receipt"])
        need(plan==upgrade.plan(packet,target_bytes(packet),predecessor,nonce),"Exact selected upgrade plan required")
    start = time.monotonic()
    deadline = start + TIMEOUT - 60
    observed = {}
    check_repos(IN,packet["files"],packet["aliases"])
    need(len(packet["files"])==2*583+8 and len(packet["aliases"])==8
         and set(packet["trust"])==set(GPG_PATHS)
         and sum(item["bytes"] for item in packet["files"].values())<=MAX_PACKAGE_BYTES,
         "Exact bounded guest transaction operands required")
    for name,item in packet["files"].items():
        need(time.monotonic() < deadline,"Guest input rehash timed out")
        read(IN/name,item,collect=False,observed=observed)
    lock = read(IN/"target.lock",packet["target"],cap=256*1024,observed=observed)
    target_rows = canonical_lock(lock,583)
    need(target_rows=={name:row["version"] for name,row in packet["packages"].items()},"Guest target differs")
    if lifecycle:
        baseline = read(IN/BASE_INVENTORY,packet["baseline"],cap=256*1024,observed=observed)
        need(lifecycle_operands(packet)[0]==baseline,"Guest base inventory differs")
    if upgrade is not None:
        return execute_guest(plan,lock,observed,deadline,upgrade=upgrade)
    return execute_guest(plan,lock,observed,deadline)


def execute_guest(plan, lock, observed, deadline, *, upgrade=None):
    packet = plan["packet"]
    lifecycle = plan.get("lifecycle") is True
    if lifecycle:
        (WORK/"lifecycle-cache").mkdir(mode=0o700)
    for p in (OUTPUT,TARGET,WORK/"cache",WORK/"trust",WORK/"home"):
        p.mkdir(mode=0o700)
    config = ("[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\n"
              "LocalFileSigLevel = Required TrustedOnly\n"+
              "".join(f"[{repo}]\nServer = file://{IN/relative}\n" for repo,relative in REPOS.items())).encode("ascii")
    CONFIG.write_bytes(config)
    env = {"PATH":"/usr/bin:/bin","HOME":str(WORK/"home"),"GNUPGHOME":str(WORK/"trust"),"LC_ALL":"C","TZ":"UTC"}
    commands = []
    phase = "trust"

    def run(role, argv, seconds, contents=None):
        nonlocal phase
        phase = role
        remaining = deadline-time.monotonic()
        need(remaining>0,"Guest transaction deadline exhausted")
        with (OUTPUT/(role+".stdout")).open("xb") as stdout, (OUTPUT/(role+".stderr")).open("xb") as stderr:
            result = subprocess.run(argv, env=env, input=contents,
                                    stdin=subprocess.DEVNULL if contents is None else None,
                                    stdout=stdout, stderr=stderr, timeout=min(remaining,seconds), check=False)
        commands.append(dict(role=role,argv=argv,exit=result.returncode))
        need(result.returncode==expected_exit(role), f"Guest command failed: {role} (exit {result.returncode})")

    def transaction():
        nonlocal phase
        gpg = ["/usr/bin/gpg","--batch","--no-options"]
        for index,name in enumerate(GPG_PATHS):
            phase = "import-"+str(index)
            run(phase,[*gpg,"--import"],30,read(IN/name,packet["trust"][name],cap=1024**2,observed=observed))
        signers=packet["signers"]
        need(len(signers)==len(set(signers))==3 and all(re.fullmatch("[0-9A-F]{40}",x) for x in signers),
             "Expected the selected public trust identities")
        run("ownertrust",[*gpg,"--import-ownertrust"],30,"".join(x+":6:\n" for x in signers).encode("ascii"))
        rootdb = TARGET/"var/lib/pacman"
        rootdb.mkdir(parents=True,mode=0o700)
        if upgrade is not None:
            phase = "upgrade-setup"
            upgrade.execute(plan,lock,run,env,config)
        else:
            expected = role_outputs(plan,lock)
            # File-repository refresh may create ALPM's database version marker only.
            for role,argv,seconds in plan["operations"]:
                phase = role
                if role==PROBE_ROLE:
                    run_signature_probe(packet,argv,seconds,run,env,config,observed)
                else:
                    run_operation(role,argv,seconds,expected,run,env,config if lifecycle else None)
        phase = "seal"
        unchanged(observed)
        check_repos(IN,packet["files"],packet["aliases"])

    def retire_trust():
        # Only the newly created guest trust directory is selected.
        subprocess.run(["/usr/bin/gpgconf","--homedir",env["GNUPGHOME"],"--kill","all"],
                       env=env,stdin=subprocess.DEVNULL,timeout=30,check=True)

    errors = (ValueError,OSError,subprocess.SubprocessError)
    hold = None
    try:
        transaction()
    except errors as error:
        if not lifecycle and upgrade is None:
            raise
        hold = phase
        print(f"overlay583 guest {phase}: {error}",file=sys.stderr,flush=True)
    finally:
        try:
            retire_trust()
        except errors as error:
            if not lifecycle and upgrade is None:
                raise
            hold = hold or "trust-retirement"
            print(f"overlay583 guest trust-retirement: {error}",file=sys.stderr,flush=True)
    passed = RECOVERY_PASS if plan.get("signature_recovery") else LIFECYCLE_PASS if lifecycle else INSTALL_PASS
    if upgrade is not None:
        passed = upgrade.PASS
    hold_status = UPGRADE_HOLD if upgrade is not None else LIFECYCLE_HOLD
    result = dict(status=hold_status if hold else passed,
                  nonce=plan["nonce"],plan=pin(encoded(plan)),commands=commands,Root_acceptance=None)
    if hold:
        result["phase"] = hold
    else:
        result["installed_lock"] = packet["target"]
    (OUTPUT/"result.json").write_bytes(encoded(result))
    return LIFECYCLE_HOLD_EXIT if hold else 0


def run_operation(role, argv, seconds, expected, run, env, config):
    if config is not None:
        read(CONFIG,pin(config),cap=4096)
        ordinary(TARGET/"var/lib/pacman")
        if role=="reinstall":
            need(not list(ordinary(WORK/"lifecycle-cache").iterdir()),"Reinstall cache must start empty")
    if role in ("install","remove",PROBE_ROLE,"reinstall"):
        with ExitStack() as mounts:
            target_api_mounts(TARGET,env,mounts)
            run(role,argv,seconds)
        check_hooks(OUTPUT,role)
    else:
        run(role,argv,seconds)
    if role=="refresh":
        local = TARGET/"var/lib/pacman/local"
        need(not local.exists() or {p.name for p in local.iterdir()} <= {"ALPM_DB_VERSION"},
             "Candidate target unexpectedly preinstalled")
    if role in expected:
        wanted, snapshot = expected[role]
        raw = sorted_rows(read(OUTPUT/(role+".stdout"),cap=256*1024))
        need(raw==wanted,"Guest pacman evidence differs: "+role)
        if snapshot:
            (OUTPUT/snapshot).write_bytes(raw)


def check_hooks(output, role, observed=None):
    stderr = read(output/(role+".stderr"),cap=8*1024**2,observed=observed)
    need(not HOOK_FAILURE.search(stderr),"Pacman reported a failed scriptlet or hook: "+role)


def expected_exit(role):
    return 1 if role==PROBE_ROLE else 0


def local_database_snapshot(root):
    root = ordinary(root)
    lock = root.parent/"db.lck"
    need(not lock.exists() and not lock.is_symlink(),"Stopped pacman database required for refusal readback")
    seen = {str(root):identity(root.lstat())}
    entries = sorted(islice(root.iterdir(),576))
    version = root/"ALPM_DB_VERSION"
    need(len(entries)==575 and version in entries,"Expected exact local 574-package database namespace")
    files = {"ALPM_DB_VERSION":read(version,cap=1024,collect=False,observed=seen)}
    remaining = 128*1024**2-files["ALPM_DB_VERSION"]["bytes"]
    for package in entries:
        if package==version:
            continue
        need(NAME.fullmatch(package.name) and ordinary(package).is_dir(),"Invalid local database package directory")
        seen[str(package)] = identity(package.lstat())
        members = list(islice(package.iterdir(),17))
        need(2<=len(members)<=16 and {"desc","files"}<={path.name for path in members},
             "Invalid local database package entries")
        for member in members:
            need(NAME.fullmatch(member.name),"Invalid local database member")
            operand = read(member,cap=min(8*1024**2,remaining),collect=False,observed=seen)
            files[str(member.relative_to(root))] = operand
            remaining -= operand["bytes"]
    unchanged(seen)
    need(not lock.exists() and not lock.is_symlink(),"Unstable local database")
    return encoded(files)


def check_signature_refusal(output, probe, observed=None):
    raw = read(output/(PROBE_ROLE+".stderr"),cap=8*1024**2,observed=observed)
    errors = [line for line in raw.splitlines() if line.startswith(b"error:")]
    expected = f"error: '{probe}': package missing required signature".encode("ascii")
    need(errors==[expected],"Pacman did not refuse the exact local archive for its missing signature")


def run_signature_probe(packet, argv, seconds, run, env, config, observed):
    relative, probe = probe_operand(packet)
    signed = packet["files"][relative]
    probe.parent.mkdir(mode=0o700)
    with probe.open("xb") as scratch:
        scratch.write(read(IN/relative,signed,cap=2*1024**2,observed=observed))
    need(list(probe.parent.iterdir())==[probe],"Unsigned probe must own exactly the copied archive")
    read(probe,signed,cap=2*1024**2,collect=False)
    local = TARGET/"var/lib/pacman/local"
    before = local_database_snapshot(local)
    (OUTPUT/DB_BEFORE).write_bytes(before)
    run_operation(PROBE_ROLE,argv,seconds,{},run,env,config)
    after = local_database_snapshot(local)
    (OUTPUT/DB_AFTER).write_bytes(after)
    check_signature_refusal(OUTPUT,probe)
    need(before==after,"Unsigned probe changed the local package database")


def command_ledger(plan):
    gpg = ["/usr/bin/gpg","--batch","--no-options"]
    return ([("import-"+str(i),[*gpg,"--import"]) for i in range(3)]
            +[("ownertrust",[*gpg,"--import-ownertrust"])]
            +[(role,argv) for role,argv,_ in plan["operations"]])


def read_lifecycle_outputs(output, plan, completed, observed):
    snapshots = set()
    target_rows = "".join(
        f'{name} {row["version"]}\n'
        for name,row in sorted(plan["packet"]["packages"].items())
    ).encode("ascii")
    expected = role_outputs(plan,target_rows)
    need(pin(target_rows)==plan["packet"]["target"],"Derived lifecycle target pin differs")
    for role in completed:
        if role in ("install","remove","reinstall"):
            check_hooks(output,role,observed)
        if role in expected:
            wanted, snapshot = expected[role]
            actual = sorted_rows(read(output/(role+".stdout"),cap=256*1024,observed=observed))
            need(actual==wanted,"Original lifecycle evidence differs: "+role)
            if snapshot:
                read(output/snapshot,pin(wanted),cap=256*1024,observed=observed)
                snapshots.add(role)
    return {stage:dict(package_count=count,lock=pin(expected[query][0])) for stage,count,query,check in (
        ("before_remove",583,"query","check"),("after_remove",574,"query-base","check-base"),
        ("after_refusal",574,"query-refused","check-refused"),
        ("after_reinstall",583,"query-restored","check-restored"),
    ) if query in snapshots and check in completed}


def read_refusal(output, plan, completed, observed):
    if PROBE_ROLE not in completed:
        return None
    probe = next(argv[-1] for role,argv,_ in plan["operations"] if role==PROBE_ROLE)
    check_signature_refusal(output,probe,observed)
    before = read(output/DB_BEFORE,cap=8*1024**2,observed=observed)
    database = decode(before)
    need(type(database) is dict and "ALPM_DB_VERSION" in database
         and len({name.split("/",1)[0] for name in database if "/" in name})==574
         and len(database)>=1149 and before==encoded(database),"Invalid local database evidence")
    need(all(isinstance(row,dict) and set(row)=={"bytes","sha256"} and type(row["bytes"]) is int
             and 0<=row["bytes"]<=8*1024**2 and isinstance(row["sha256"],str) and HEX.fullmatch(row["sha256"])
             for row in database.values()),"Invalid local database file pins")
    unchanged_db = pin(before)
    read(output/DB_AFTER,unchanged_db,cap=8*1024**2,observed=observed)
    packet = plan["packet"]
    relative, _ = probe_operand(packet)
    return dict(package=PROBE_PACKAGE,probe=probe,archive=packet["files"][relative],
                expected_exit=expected_exit(PROBE_ROLE),
                diagnostic="package missing required signature",local_database=unchanged_db)


def read_lifecycle_result(output, plan, result, held, observed):
    expected = command_ledger(plan)
    available = {path.name for path in output.iterdir()}
    allowed = evidence_names(plan)
    need("result.json" in available and available <= allowed and (held or available==allowed),
         "Missing or extra guest evidence")
    recovery = plan.get("signature_recovery") is True
    passed = RECOVERY_PASS if recovery else LIFECYCLE_PASS
    expected_status = LIFECYCLE_HOLD if held else passed
    outcome_field = "phase" if held else "installed_lock"
    need(set(result)=={"status","nonce","plan","commands","Root_acceptance",outcome_field}
         and result["status"]==expected_status and result["nonce"]==plan["nonce"]
         and result["plan"]==pin(encoded(plan)) and result["Root_acceptance"] is None,
         "Unbound guest lifecycle receipt")
    ledger = result["commands"]
    phase = result.get("phase")
    phases = ["trust",*(role for role,_ in expected),"seal","trust-retirement"]
    if held:
        need(phase in phases,"Unrecognized lifecycle hold phase")
        completed_count = min(len(expected),max(0,phases.index(phase)-1))
        attempt_count = completed_count + int(phase in phases[1:-2])
        need(type(ledger) is list and completed_count<=len(ledger)<=attempt_count,
             "Incomplete lifecycle command prefix")
    else:
        need(result["installed_lock"]==plan["packet"]["target"],"Unbound restored inventory")
        completed_count = attempt_count = len(expected)
        need(type(ledger) is list and len(ledger)==completed_count,"Incomplete lifecycle command ledger")
    completed = [role for role,_ in expected[:completed_count]]
    for index,(role,argv) in enumerate(expected[:attempt_count]):
        logs = {role+".stdout",role+".stderr"}
        allowed -= logs
        if index<len(ledger):
            record = ledger[index]
            need(type(record) is dict and set(record)=={"role","argv","exit"}
                 and record["role"]==role and record["argv"]==argv and type(record["exit"]) is int
                 and (index>=completed_count or record["exit"]==expected_exit(role)) and logs<=available,
                 "Guest lifecycle command ledger differs")
    attempted = {role for role,_ in expected[:attempt_count]}
    for role,name in (("query","installed.lock"),("query-base","removed.lock"),
                      ("query-refused","refused.lock"),
                      ("query-restored","reinstalled.lock")):
        if role not in attempted:
            need(name not in available,"Unexpected snapshot after lifecycle hold")
    need(not any(name.endswith((".stdout",".stderr")) for name in available & allowed),
         "Unexpected logs after lifecycle hold")
    need(PROBE_ROLE in attempted or not ({DB_BEFORE,DB_AFTER} & available),
         "Unexpected local database snapshots before the unsigned probe")
    snapshots = read_lifecycle_outputs(output,plan,completed,observed)
    refusal = read_refusal(output,plan,completed,observed) if recovery else None
    files = {name:read(output/name,cap=8*1024**2,collect=False,observed=observed)
             for name in sorted(available)}
    need(sum(row["bytes"] for row in files.values()) <= 32*1024**2, "Guest evidence byte budget exceeded")
    unchanged(observed)
    matched = ("MATCHED_DISPOSABLE_OVERLAY583_SIGNATURE_RECOVERY_EVIDENCE" if recovery
               else "MATCHED_DISPOSABLE_OVERLAY583_LIFECYCLE_EVIDENCE")
    report = dict(status=LIFECYCLE_HOLD if held else matched,
                phase=phase,verified_locks=snapshots,files=files,Root_acceptance=None,
                Asahi_installation=None,M2=None)
    if recovery:
        report["signature_refusal"] = refusal
    return report


def read_result(output, plan, *, held=False):
    """Reopen the owned guest's original evidence and compare the exact lock."""
    output = ordinary(output)
    observed = {}
    need(not any(p.is_symlink() or not p.is_file() for p in output.iterdir()),
         "Ordinary bounded guest evidence required")
    result_raw = read(output/"result.json",cap=1024**2,observed=observed)
    result = decode(result_raw)
    if plan.get("kind")==UPGRADE_KIND:
        files = upgrade_module(plan["upgrade_worker"]).readback(output,plan,target_bytes(plan["packet"]),held=held)
        unchanged(observed)
        return dict(status=UPGRADE_HOLD if held else "MATCHED_DISPOSABLE_OVERLAY583_SETUP_UPGRADE_EVIDENCE",
                    installed_lock=None if held else plan["packet"]["target"],
                    predecessor_lock=plan["before"], files=files, phase=result.get("phase"),
                    package_count=None if held else 583, Root_acceptance=None, Asahi_installation=None, M2=None)
    if plan.get("lifecycle"):
        return read_lifecycle_result(output,plan,result,held,observed)
    need(not held,"Lifecycle opt-in required for hold readback")
    target = plan["packet"]["target"]
    installed = read(output/"installed.lock",target,cap=256*1024,observed=observed)
    canonical_lock(installed,583)
    need(result["status"]==INSTALL_PASS
         and result["nonce"]==plan["nonce"] and result["plan"]==pin(encoded(plan))
         and result["installed_lock"]==target and result["Root_acceptance"] is None,
         "Unbound guest completion receipt")
    need(result["commands"]==[dict(role=role,argv=argv,exit=0) for role,argv in command_ledger(plan)],
         "Guest command ledger differs")
    before=read(output/"resolve.stdout",cap=256*1024,observed=observed)
    after=read(output/"query.stdout",cap=256*1024,observed=observed)
    need(sorted_rows(before)==pacman_plan(plan["packet"]) and sorted_rows(after)==installed,
         "Original pacman plan or installed inventory differs")
    expected_files = evidence_names(plan)
    need({p.name for p in output.iterdir()}==expected_files,"Missing or extra guest evidence")
    files = {name:read(output/name,cap=8*1024**2,collect=False,observed=observed)
             for name in sorted(expected_files)}
    need(sum(row["bytes"] for row in files.values()) <= 32*1024**2, "Guest evidence byte budget exceeded")
    unchanged(observed)
    return dict(status="MATCHED_DISPOSABLE_OVERLAY583_TRANSACTION_EVIDENCE",
                installed_lock=target,package_count=583,files=files,Root_acceptance=None,
                Asahi_installation=None,M2=None)


def run_owned(executor, *, staging, preflight, preflight_pin, nonce, selection, lifecycle=False,
              signature_recovery=False, predecessor=None, predecessor_pin=None):
    """Bridge to a selected VM owner. The owner authenticates all actual authority."""
    need(getattr(executor,"API",None)=="ROOT_OWNED_OVERLAY583_VM_V1","Owned disposable ARM VM executor required")
    staging = ordinary(staging)
    packet = choose(staging,selected_lock=PINS)
    plan = selected_plan(admit(packet,read(preflight,preflight_pin,cap=128*1024),preflight_pin),
                         nonce,lifecycle=lifecycle,signature_recovery=signature_recovery,
                         predecessor=predecessor,predecessor_pin=predecessor_pin)
    worker = ordinary(HERE/"trial.py")
    worker_pin = read(worker,collect=False,cap=128*1024)
    plan_sha = pin(encoded(plan))["sha256"]
    executor.authenticate(selection, plan_sha256=plan_sha, worker=worker_pin, nonce=nonce)
    result = executor.run_guest(staging=staging,worker=worker,worker_pin=worker_pin,plan=encoded(plan),
        kernel_argument="cachy_overlay583_nonce="+nonce,
        argv=["/usr/bin/python3","-I","-B","/trial-code/trial.py","guest",plan_sha,worker_pin["sha256"]],
        timeout=TIMEOUT)
    need(result.get("exit")==0 and all(result.get(key) is True for key in ("natural","reaped","output_complete")),
         "Owned disposable guest did not complete and retire")
    executor.require_absent_twice(nonce)
    need(choose(staging,selected_lock=PINS)==packet,"Repository operands changed during the trial")
    read(worker,worker_pin,cap=128*1024,collect=False)
    if predecessor is not None:
        upgrade = upgrade_module(plan["upgrade_worker"])
        need(upgrade.check_stage(predecessor,predecessor_pin)==plan["predecessor"],
             "Predecessor operands changed during the trial")
    if result.get("held") is True:
        need(plan.get("lifecycle") or plan.get("kind")==UPGRADE_KIND,"Lifecycle opt-in required for hold evidence")
        return read_result(result["evidence"],plan,held=True)
    return read_result(result["evidence"],plan)


class OwnedVMAdapter:
    """Bridge an authorized VM owner's launch and readback to owned_process.

    The selected supervisor is the existing scripts/virtual/owned_process.py
    module. The controller supplies a fresh VM launcher, owned evidence export
    and independent retirement checks for its disposable guest implementation.
    """
    API = "ROOT_OWNED_OVERLAY583_VM_V1"

    def __init__(self, supervisor, *, authenticate, launch, export, absent_twice):
        self.supervisor = supervisor
        self.authenticate = authenticate
        self.launch = launch
        self.export = export
        self.require_absent_twice = absent_twice

    def run_guest(self, *, timeout, **request):
        self.supervisor.prepare()
        child = self.launch(**request)
        observation = self.supervisor.supervise(child, cap=timeout, retirement=30, grace=5,
                                                max_output=1024**2, group=True)
        need(observation.get("passed") is True and observation.get("reaped") is True
             and observation.get("ownership")=="REAPED" and observation.get("group_census")=="EMPTY_TWICE"
             and observation.get("signals")==[] and observation.get("timeout") is False
             and observation.get("exit")==0 and observation.get("output_complete") is True,
             "Owned VM process failed or retirement is incomplete")
        evidence = self.export(observation)
        return dict(exit=observation["exit"],natural=True,reaped=True,
                    output_complete=observation["output_complete"],evidence=evidence)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="mode",required=True)
    inspect=sub.add_parser("prepare")
    inspect.add_argument("--staging",required=True,type=Path)
    inspect.add_argument("--preflight",required=True,type=Path)
    inspect.add_argument("--preflight-sha256",required=True)
    worker=sub.add_parser("guest")
    worker.add_argument("plan_sha256")
    worker.add_argument("worker_sha256")
    args=parser.parse_args()
    if args.mode=="guest":
        return guest(args.plan_sha256,args.worker_sha256)
    def passive(event,_args):
        need(not event.startswith(("subprocess.","socket.","ctypes."))
             and event not in ("os.system","os.exec","os.fork","os.forkpty","os.posix_spawn"),
             "Passive preparation cannot start an actor")
    sys.addaudithook(passive)
    packet=choose(args.staging,selected_lock=PINS)
    raw=read(args.preflight,cap=128*1024)
    need(pin(raw)["sha256"]==args.preflight_sha256,"External preflight pin differs")
    print(encoded(admit(packet,raw,pin(raw))).decode(),end="")


if __name__ == "__main__":
    raise SystemExit(main())
