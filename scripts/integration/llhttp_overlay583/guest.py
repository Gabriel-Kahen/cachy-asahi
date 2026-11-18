# SPDX-License-Identifier: MIT
"""Installed llhttp lifecycle addon for the existing Overlay583 actor."""

from base64 import b64decode, b64encode
from contextlib import ExitStack
import os
from pathlib import Path
import stat
import time

SUPPLEMENT = Path("/trial-code/llhttp")
PROBE = "/run/caa-llhttp-lifecycle.py"
PACKAGE = "cachy-asahi-llhttp-reference"
VERSION = "9.3.1-1"
ARCHIVE = PACKAGE+"-"+VERSION+"-aarch64.pkg.tar.xz"
REAL = "/usr/lib/libllhttp.so.9.3.1"
SONAME = "libllhttp.so.9.3"
PUBLIC = "llhttp-lifecycle-TEST-public.gpg"
PASS = "PASS_ARM16K_OVERLAY583_LLHTTP_LIBRARY_LIFECYCLE"
MAX_EVIDENCE = 2*1024**2
MAX_LOG = 256*1024


def commands(nonce, digest):
    work=Path("/trial-work")
    trust=work/"trust"
    target=work/"target"
    pacman=["/usr/bin/pacman","--config",str(work/"pacman.conf"),"--root",str(target),
            "--dbpath",str(target/"var/lib/pacman"),"--gpgdir",str(trust),"--cachedir",str(work/"cache"),
            "--logfile",str(work/"llhttp-alpm.log")]
    gpg=["/usr/bin/gpg","--batch","--no-options","--homedir",str(trust)]
    package=str(SUPPLEMENT/ARCHIVE)
    probe=["/usr/bin/chroot",str(target),"/usr/bin/python3","-I","-B",PROBE]
    return {
        "llhttp-before":[*pacman,"--query"],
        "llhttp-loader-before":[*probe,"absent",digest,nonce],
        "llhttp-import":[*gpg,"--import"],
        "llhttp-verify":[*gpg,"--status-fd","1","--verify",package+".sig",package],
        "llhttp-trust":[*gpg,"--import-ownertrust"],
        "llhttp-install":[*pacman,"--upgrade","--noconfirm","--",package],
        "llhttp-installed":[*pacman,"--query"],
        "llhttp-installed-db":[*pacman,"--database","--check"],
        "llhttp-owner":[*pacman,"--query","--list","--",PACKAGE],
        "llhttp-loader-installed":[*probe,"present",digest,nonce],
        "llhttp-uninstall":[*pacman,"--remove","--noconfirm","--",PACKAGE],
        "llhttp-removed":[*pacman,"--query"],
        "llhttp-removed-db":[*pacman,"--database","--check"],
        "llhttp-loader-removed":[*probe,"absent",digest,nonce],
    }


ROLES = tuple(commands("",""))


def payload_state(trial, target, payload, installed):
    for name, expected in payload.items():
        path=target/name
        trial.need(path.parent==path.parent.resolve(), "Noncanonical target payload parent")
        if not installed:
            trial.need(not path.exists() and not path.is_symlink(), "Unexpected llhttp payload path: "+name)
        elif "target" in expected:
            row=path.lstat()
            trial.need(stat.S_ISLNK(row.st_mode) and row.st_uid==row.st_gid==0
                       and os.readlink(path)==expected["target"], "Installed library symlink differs: "+name)
        else:
            row=path.lstat()
            trial.need(row.st_uid==row.st_gid==0 and stat.S_IMODE(row.st_mode)==expected["mode"],
                       "Installed payload owner or mode differs: "+name)
            trial.read(path,expected["pin"],cap=512*1024)


def ownership(raw, payload):
    rows=[line.decode("ascii").split(" ",1) for line in raw.splitlines()]
    leaves={str(Path("/"+name)) for name in payload}
    ancestry={str(parent) for leaf in leaves for parent in Path(leaf).parents if parent!=Path("/")}
    seen={}
    for row in rows:
        if len(row)!=2 or row[0]!=PACKAGE or row[1] in seen:
            return False
        seen[row[1]]=True
    return set(seen)=={"/trial-work/target"+name for name in leaves|{path+"/" for path in ancestry}}


def probe_receipt(digest, *, present):
    basic=dict(loaded=present,page_size=16384,soname=SONAME)
    return dict(basic,mapped=REAL,sha256=digest,method="POST",split_request=["HPE_OK"]*3,
                invalid_length=["HPE_INVALID_CONTENT_LENGTH"],incomplete_body=["HPE_OK","HPE_INVALID_EOF_STATE"]) if present else basic


def run(trial, *, supplement_sha256, nonce, env, command):
    need=trial.need
    need(os.getuid()==os.geteuid()==0 and os.uname().machine=="aarch64" and os.sysconf("SC_PAGE_SIZE")==16384
         and Path("/proc/cmdline").read_text().split().count("cachy_overlay583_nonce="+nonce)==1
         and {path.name for path in Path("/sys/class/net").iterdir()}<={"lo"}, "Exact admitted ARM16K guest required")
    mounts=Path("/proc/self/mountinfo").read_text().splitlines()
    for path,mode in ((SUPPLEMENT.parent,"ro"),(trial.IN,"ro"),(trial.WORK,"rw")):
        trial.mount_mode(path,mode,mounts)
    target=trial.ordinary(trial.TARGET)
    need(target.parent==trial.WORK and target.stat().st_dev==trial.WORK.stat().st_dev!=Path("/").stat().st_dev,
         "Owned scratch target required")
    raw=trial.read(SUPPLEMENT/"supplement.json",cap=64*1024)
    need(trial.pin(raw)["sha256"]==supplement_sha256,"Exact selected llhttp supplement required")
    ops=trial.llhttp_module("operands.py",trial.decode(raw)["files"]["operands.py"])
    packet=ops.check_stage(trial,SUPPLEMENT,supplement_sha256,SUPPLEMENT)
    base=trial.read(trial.IN/"target.lock",packet["before"],cap=64*1024)
    return exercise(trial,ops,packet,base,target,nonce,env,command)


def exercise(trial, ops, packet, base, target, nonce, env, command):
    need=trial.need
    config=trial.read(trial.CONFIG,cap=4096).decode("ascii").splitlines()
    need("SigLevel = Required TrustedOnly" in config and "LocalFileSigLevel = Required TrustedOnly" in config
         and env.get("GNUPGHOME")==str(trial.WORK/"trust"), "Selected disposable normal ALPM signature policy required")
    before=trial.canonical_lock(base,583)
    after=trial.sorted_rows(base+f"{PACKAGE} {VERSION}\n".encode())
    need(PACKAGE not in before and trial.pin(after)==packet["after"] and len(trial.canonical_lock(after,584))==584,
         "Only the exact selected package may enter the inventory")
    payload=packet["payload"]
    digest=payload[REAL[1:]]["pin"]["sha256"]
    db=target/"var/lib/pacman/local"
    key=packet["rehearsal"]
    need(ops.valid_key(key,time.time()), "Current TEST key required")
    argv=commands(nonce,digest)

    def call(role, cap=30, contents=None):
        return command(role,argv[role],cap,contents)

    checked={}
    with ExitStack() as stack:
        trial.target_api_mounts(target,env,stack)
        worker=trial.read(SUPPLEMENT/"probe.py",packet["files"]["probe.py"],cap=128*1024)
        (target/PROBE[1:]).write_bytes(worker)
        payload_state(trial,target,payload,False)
        need(trial.sorted_rows(call("llhttp-before"))==base,"Base inventory changed")
        current=trial.pin(trial.local_database_snapshot(db,count=583))
        expect=probe_receipt(digest,present=False)
        checked["before"]=trial.decode(call("llhttp-loader-before"))
        need(checked["before"]==expect,"Preexisting SONAME provider")
        call("llhttp-import",contents=trial.read(SUPPLEMENT/PUBLIC,packet["files"][PUBLIC],cap=128*1024))
        need(ops.signed(call("llhttp-verify"),key),"Exact current selected TEST signature required")
        call("llhttp-trust",contents=(key["fingerprint"]+":6:\n").encode())
        call("llhttp-install",90)
        need(trial.sorted_rows(call("llhttp-installed"))==after,"Installed inventory differs")
        call("llhttp-installed-db")
        need(ownership(call("llhttp-owner"),payload),"Installed ALPM ownership differs")
        payload_state(trial,target,payload,True)
        checked["installed"]=trial.decode(call("llhttp-loader-installed"))
        need(checked["installed"]==probe_receipt(digest,present=True),"Installed shared library semantics differ")
        call("llhttp-uninstall",90)
        need(trial.sorted_rows(call("llhttp-removed"))==base,"Removal inventory differs")
        call("llhttp-removed-db")
        restored=trial.pin(trial.local_database_snapshot(db,count=583))
        need(restored==current,"Baseline ALPM ownership or metadata did not restore")
        payload_state(trial,target,payload,False)
        checked["after_removal"]=trial.decode(call("llhttp-loader-removed"))
        need(checked["after_removal"]==expect,"Removed SONAME is still loadable")
    return dict(status=PASS,locks=dict(before=trial.pin(base),installed=trial.pin(after),after_removal=trial.pin(base)),
                baseline_db=current,restored_db=restored,probes=checked,package_payload=payload,
                pair=packet["qualification"],rehearsal=key,Root_acceptance=None,M2="NOT RUN")


def evidence(trial,directory,ledger,result):
    rows=[]
    for row in ledger:
        selected=dict(row)
        for stream in ("stdout","stderr"):
            selected[stream]=b64encode(trial.read(directory/(row["role"]+"."+stream),cap=MAX_LOG)).decode("ascii")
        rows.append(selected)
    raw=trial.encoded(dict(result=result,commands=rows))
    trial.need(len(raw)<=MAX_EVIDENCE,"Bounded llhttp evidence export")
    return raw


def readback(raw, *, nonce, base, supplement, held, pin, need, policy):
    import json
    value=json.loads(raw)
    ledger=value["commands"]
    payload=supplement["payload"]
    digest=payload[REAL[1:]]["pin"]["sha256"]
    expected=commands(nonce,digest)
    names=[row["role"] for row in ledger]
    need(set(value)=={"result","commands"} and names==list(expected)[:len(names)]
         and (held or names==list(expected)), "Original llhttp command ledger differs")
    outputs={}
    for index,row in enumerate(ledger):
        role=row["role"]
        need(set(row)=={"role","argv","exit","stdout","stderr"} and row["argv"]==expected[role]
             and type(row["exit"]) is int and (row["exit"]==0 or held and index==len(ledger)-1),
             "Unexpected llhttp original command or exit")
        stdout,stderr=(b64decode(row[key],validate=True) for key in ("stdout","stderr"))
        need(len(stdout)<=MAX_LOG and len(stderr)<=MAX_LOG,"Unexpected llhttp output length")
        outputs[role]=stdout
    result=value["result"]
    if result is None:
        need(held,"Missing llhttp completion")
        return None
    need(names==list(expected) and all(row["exit"]==0 for row in ledger),"Incomplete llhttp completion")
    after=b"".join(sorted((base+f"{PACKAGE} {VERSION}\n".encode()).splitlines(keepends=True)))
    locks={"before":base,"installed":after,"after_removal":base}
    query=dict(before="llhttp-before",installed="llhttp-installed",after_removal="llhttp-removed")
    probes=dict(before="llhttp-loader-before",installed="llhttp-loader-installed",after_removal="llhttp-loader-removed")
    for name,wanted in locks.items():
        need(b"".join(sorted(outputs[query[name]].splitlines(keepends=True)))==wanted
             and result["locks"][name]==pin(wanted)
             and json.loads(outputs[probes[name]])==result["probes"][name]==probe_receipt(digest,present=name=="installed"),
             "Original llhttp inventory or shared library evidence differs")
    need(policy.signed(outputs["llhttp-verify"],supplement["rehearsal"])
         and ownership(outputs["llhttp-owner"],payload) and result["status"]==PASS
         and result["baseline_db"]==result["restored_db"] and result["package_payload"]==payload
         and result["pair"]==supplement["qualification"] and result["rehearsal"]==supplement["rehearsal"]
         and result["Root_acceptance"] is None and result["M2"]=="NOT RUN", "Restoration or qualified llhttp result differs")
    return result
