# SPDX-License-Identifier: MIT
"""Offline rehearsal worker for one disposable copy of the selected Asahi root."""

from base64 import b64encode
from contextlib import ExitStack
import hashlib
import importlib.util
from itertools import islice
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
PASS="PASS_DISPOSABLE_ASAHI_626_THREE_VERSION_REVERSE"
HOLD="HOLD_DISPOSABLE_ASAHI_MAINTENANCE"
TIMEOUT=3600
SHOW=("baseline","forward","rollback")
BOOT="ASAHI_MAINTENANCE_EXACT_GUEST_PLAN_V1"
NAMES={"result.json","commands.json","platform.json","signatures.json","pacman.log",
       "baseline.lock","forward.lock","rollback.lock","forward-preview.lock","rollback-preview.lock",
       "apply-forward.stdout","apply-forward.stderr","apply-rollback.stdout","apply-rollback.stderr"}
BAD_SIG={"BADSIG","ERRSIG","REVKEYSIG","EXPKEYSIG","EXPSIG","KEYEXPIRED","SIGEXPIRED","NO_PUBKEY"}


def load(path, ref):
    raw=path.read_bytes()
    if dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())!=ref or len(raw)>128*1024:
        raise ValueError("Exact selected Asahi worker dependency required")
    spec=importlib.util.spec_from_file_location("asahi_worker_"+path.stem,path)
    loaded=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),"exec"),loaded.__dict__)
    return loaded


def signature(T, raw, fingerprint):
    lines=[line.split() for line in raw.decode("utf-8").splitlines() if line.startswith("[GNUPG:] ")]
    tags={row[1] for row in lines}
    valid=[row for row in lines if row[1]=="VALIDSIG"]
    good=[row for row in lines if row[1]=="GOODSIG"]
    T.need(not tags&BAD_SIG and len(valid)==len(good)==1 and len(valid[0])>=12
           and valid[0][-1]==fingerprint and good[0][2]==valid[0][2][-16:],
           "Exact current selected detached signature required")
    return dict(primary=fingerprint,signing=valid[0][2],status=T.pin(raw))


def platform(T, target):
    result={}
    total=0
    for relative in ("boot","etc/fstab","etc/crypttab"):
        first=target/relative
        pending=[first]
        while pending:
            path=pending.pop()
            name=str(path.relative_to(target))
            try:
                row=path.lstat()
            except FileNotFoundError:
                result[name]=None
                continue
            T.need(len(result)<2048,"Bounded boot/platform namespace required")
            common=dict(uid=row.st_uid,gid=row.st_gid,mode=stat.S_IMODE(row.st_mode),links=row.st_nlink)
            if stat.S_ISLNK(row.st_mode):
                result[name]=dict(common,type="link",target=os.readlink(path))
            elif stat.S_ISDIR(row.st_mode):
                result[name]=dict(common,type="directory")
                pending.extend(sorted(islice(path.iterdir(),2048),reverse=True))
                T.need(len(pending)<2048,"Bounded boot/platform directory required")
            else:
                T.need(stat.S_ISREG(row.st_mode) and total+row.st_size<=512*1024**2,
                       "Bounded regular boot/platform file required")
                total+=row.st_size
                result[name]=dict(common,type="file",pin=T.read(path,cap=512*1024**2,collect=False,allowed_links=(row.st_nlink,)))
    return result


def command_plan(O, manifest):
    trust=O.WORK/"trust"
    pacman=["/usr/bin/pacman","--config",str(O.WORK/"pacman.conf"),"--root",str(O.TARGET),
            "--dbpath",str(O.TARGET/"var/lib/pacman"),"--gpgdir",str(trust),
            "--cachedir",str(O.WORK/"cache"),"--logfile",str(O.WORK/"evidence/pacman.log")]
    output={}
    for phase in SHOW:
        output["query-"+phase]=[*pacman,"--query"]
        output["check-"+phase]=[*pacman,"--database","--check"]
    for phase in SHOW[1:]:
        packages=[str(O.IN/entry["archive"]) for _,entry in sorted(manifest["packages"][phase].items())]
        output["preview-"+phase]=[*pacman,"--upgrade","--noconfirm","--print","--print-format","%n %v","--",*packages]
        output["apply-"+phase]=[*pacman,"--upgrade","--noconfirm","--",*packages]
    return output


def log_actions(T, before, forward, rollback, raw, *, completed):
    actions=re.findall(rb"^\[[^\]\r\n]+\] \[ALPM\] (installed|upgraded|downgraded|removed|reinstalled) ([^ \r\n]+) ([^\r\n]+)$",
                       raw,re.M)
    intro=[]
    reverse=[]
    for name,version in forward.items():
        if name not in before:
            intro.append((b"installed",name.encode(),f"({version})".encode()))
        elif before[name]!=version:
            intro.append((b"upgraded",name.encode(),f"({before[name]} -> {version})".encode()))
    for name,version in rollback.items():
        if forward[name]!=version:
            reverse.append((b"downgraded",name.encode(),f"({forward[name]} -> {version})".encode()))
    if completed:
        T.need(sorted(actions[:len(intro)])==sorted(intro) and sorted(actions[len(intro):])==sorted(reverse),
               "Original ALPM log must show only the selected forward and three inverse changes")
    return dict(entries=len(actions),pin=T.pin(raw))


def execute(T, O, selected):
    manifest=selected["media"]
    evidence=O.WORK/"evidence"
    evidence.mkdir(mode=0o700)
    trust=O.WORK/"trust"
    (O.WORK/"cache").mkdir(mode=0o700)
    trust.mkdir(mode=0o700)
    config=O.WORK/"pacman.conf"
    config.write_text("[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n")
    env={"PATH":"/usr/bin:/bin","HOME":str(O.WORK),"GNUPGHOME":str(trust),"LC_ALL":"C","TZ":"UTC"}
    observed={}
    steps=[]
    signatures={}
    inventory={}
    reviews={}
    system={}
    phase="rehash"
    deadline=time.monotonic()+TIMEOUT-90
    final=HOLD
    commands=command_plan(O,manifest)

    def call(role,argv,seconds,stdin=None):
        nonlocal phase
        phase=role
        remaining=deadline-time.monotonic()
        T.need(remaining>0,"Guest transaction deadline exhausted")
        with (O.WORK/(role+".stdout")).open("xb") as stdout, (O.WORK/(role+".stderr")).open("xb") as stderr:
            result=subprocess.run(argv,env=env,input=stdin,stdin=subprocess.DEVNULL if stdin is None else None,
                                  stdout=stdout,stderr=stderr,timeout=min(seconds,remaining),check=False)
        out=T.read(O.WORK/(role+".stdout"),cap=2*1024**2)
        err=T.read(O.WORK/(role+".stderr"),cap=2*1024**2)
        steps.append(dict(role=role,argv=argv,exit=result.returncode,stdout=T.pin(out),stderr=T.pin(err)))
        if role in ("apply-forward","apply-rollback"):
            (evidence/(role+".stdout")).write_bytes(out)
            (evidence/(role+".stderr")).write_bytes(err)
        T.need(result.returncode==0,"Selected guest command failed: "+role)
        if role.startswith("apply-"):
            T.need(not T.HOOK_FAILURE.search(err),"Pacman reported a failed hook/scriptlet")
        return out

    gpg=["/usr/bin/gpg","--batch","--no-options","--no-auto-key-retrieve","--homedir",str(trust)]
    def verify_all():
        for name,row in sorted(manifest["keys"].items()):
            call("import-"+name,[*gpg,"--import"],30,T.read(O.IN/row["file"],manifest["files"][row["file"]],
                                                           cap=64*1024,observed=observed))
        raw=call("list-public",[*gpg,"--with-colons","--fingerprint","--list-keys"],30)
        actual=[]
        previous=None
        for row in raw.decode("utf-8").splitlines():
            cells=row.split(":")
            if cells[0]=="fpr" and previous=="pub":
                actual.append(cells[9])
            if cells[0] in ("pub","sub","fpr"):
                previous=cells[0]
        pins=sorted(row["fingerprint"] for row in manifest["keys"].values())
        T.need(sorted(actual)==pins,"Only exact declared primaries in guest keyring")
        for stage in SHOW[1:]:
            signatures[stage]={}
            for name,row in sorted(manifest["packages"][stage].items()):
                pkg=str(O.IN/row["archive"])
                status=call("verify-"+stage+"-"+name,[*gpg,"--status-fd","1","--verify",pkg+".sig",pkg],20)
                signatures[stage][name]=dict(signature(T,status,row["signer"]),scope=row["scope"],
                                              original=b64encode(status).decode("ascii"))
        call("set-ownertrust",[*gpg,"--import-ownertrust"],30,"".join(fpr+":6:\n" for fpr in pins).encode())

    def query(label, expected):
        data=T.sorted_rows(call("query-"+label,commands["query-"+label],60))
        T.need(data==expected,"Complete installed inventory differs: "+label)
        (evidence/(label+".lock")).write_bytes(data)
        inventory[label]=T.pin(data)
        call("check-"+label,commands["check-"+label],60)
        system[label]=T.pin(T.encoded(platform(T,O.TARGET)))
        T.need(system[label]==system["baseline"],"Asahi boot and mount configuration changed in the copy")

    try:
        O.rehash(T,O.IN,manifest,observed=observed)
        free=os.statvfs(O.TARGET)
        T.need(free.f_bavail*free.f_frsize>=8*1024**3,"Target clone must be expanded before package changes")
        with ExitStack() as mounts:
            T.target_api_mounts(O.TARGET,env,mounts)
            query("baseline",T.read(O.IN/"baseline.lock",O.lock_ref("baseline.lock"),cap=64*1024,observed=observed))
            verify_all()
            for stage in SHOW[1:]:
                preview=stage+"-preview.lock"
                reference=T.read(O.IN/preview,O.lock_ref(preview),cap=64*1024,observed=observed)
                actual=T.sorted_rows(call("preview-"+stage,commands["preview-"+stage],180))
                T.need(actual==reference,"Local package preview differs: "+stage)
                (evidence/preview).write_bytes(actual)
                reviews[stage]=T.pin(actual)
                call("apply-"+stage,commands["apply-"+stage],2400 if stage=="forward" else 420)
                query(stage,T.read(O.IN/(stage+".lock"),O.lock_ref(stage+".lock"),cap=64*1024,observed=observed))
        phase="seal"
        T.unchanged(observed)
        rows=O.locks(T,O.IN)
        log_actions(T,rows["baseline.lock"],rows["forward.lock"],rows["rollback.lock"],
                    T.read(evidence/"pacman.log",cap=2*1024**2),completed=True)
        final=PASS
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        print(f"Asahi maintenance HOLD {phase}: {error}",file=sys.stderr,flush=True)
    finally:
        try:
            subprocess.run(["/usr/bin/gpgconf","--homedir",str(trust),"--kill","all"],env=env,
                           stdin=subprocess.DEVNULL,timeout=30,check=True)
        except (OSError,subprocess.SubprocessError):
            phase,final="trust-retirement",HOLD
    for name,data in (("commands",steps),("platform",system),("signatures",signatures)):
        (evidence/(name+".json")).write_bytes(T.encoded(data))
    (evidence/"result.json").write_bytes(T.encoded(dict(status=final,phase=None if final==PASS else phase,
         nonce=selected["nonce"],plan=T.pin(T.encoded(selected)),approval_status="UNAPPROVED",Root_acceptance=None,
         inventory=inventory,previews=reviews,platform=system,M2="NOT RUN",physical_installation="NOT RUN")))
    return 0 if final==PASS else 75


def boot(plan_sha, worker_sha):
    if (os.getuid()!=os.geteuid() or os.getuid()!=0 or os.uname().machine!="aarch64" or os.sysconf("SC_PAGE_SIZE")!=16384
        or {p.name for p in Path("/sys/class/net").iterdir()}!={"lo"}):
        raise ValueError("Exact offline aarch64 16 KiB control guest required")
    here=Path("/trial-code")
    plan=(here/"plan.json").read_bytes()
    if hashlib.sha256(plan).hexdigest()!=plan_sha or hashlib.sha256(Path(__file__).read_bytes()).hexdigest()!=worker_sha:
        raise ValueError("Asahi guest pack must match the held plan and worker")
    import json
    pre=json.loads(plan)
    T=load(here/"trial.py",pre["code"]["trial.py"])
    O=load(here/"operands.py",pre["code"]["operands.py"])
    selected=T.decode(plan)
    T.need(plan==T.encoded(selected) and selected["kind"]==BOOT
           and T.HEX.fullmatch(worker_sha) and T.HEX.fullmatch(plan_sha)
           and Path("/proc/cmdline").read_text().split().count("cachy_overlay583_nonce="+selected["nonce"])==1,
           "Exact declared nonce and Asahi worker profile required")
    mounts=Path("/proc/self/mountinfo").read_text().splitlines()
    for path,mode in ((here,"ro"),(O.IN,"ro"),(O.TARGET,"rw"),(O.WORK,"rw")):
        T.mount_mode(path,mode,mounts)
    T.need(len({Path("/").stat().st_dev,O.TARGET.stat().st_dev,O.WORK.stat().st_dev})==3,
           "Control boot, disposable Asahi target and tmpfs trust must be separate")
    T.read(O.IN/"manifest.json",selected["manifest"],cap=512*1024)
    return execute(T,O,selected)


if __name__=="__main__":
    raise SystemExit(boot(*sys.argv[1:]))
