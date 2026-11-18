# SPDX-License-Identifier: MIT
"""Upgrade and restore one package inside the admitted installed Overlay583 guest."""

from base64 import b64decode, b64encode
from contextlib import ExitStack
from itertools import islice
from pathlib import Path
import os
import re
import stat
import time
from types import ModuleType

SUPPLEMENT=Path("/trial-code/fish-upgrade")
PLAN_KIND="OVERLAY583_FISH_CONFIG_UPGRADE_GUEST_PLAN_V1"
PASS="PASS_DISPOSABLE_OVERLAY583_FISH_CONFIG_UPGRADE"
MAX_EVIDENCE=2*1024**2
MAX_LOG=256*1024
OVERLAY_SIGNER="C908F19D5618FE95F08864A8E397439FC7A7980D"


def module(T, root, name, pin):
    path=root/name
    raw=T.read(path,pin,cap=128*1024)
    loaded=ModuleType("overlay583_fish_"+path.stem)
    loaded.__file__=str(path)
    exec(compile(raw,str(path),"exec"),loaded.__dict__)
    return loaded


def command_plan(T, O, P):
    trust=T.WORK/"trust"
    pacman=["/usr/bin/pacman","--config",str(T.CONFIG),"--root",str(T.TARGET),
            "--dbpath",str(T.TARGET/"var/lib/pacman"),"--gpgdir",str(trust),
            "--cachedir",str(T.WORK/"cache"),"--logfile",str(T.WORK/"fish-upgrade-pacman.log")]
    gpg=["/usr/bin/gpg","--batch","--no-options","--homedir",str(trust)]
    chroot=["/usr/bin/chroot",str(T.TARGET)]
    query=[*pacman,"--query"]
    check=[*pacman,"--database","--check"]
    ownership=[*query,"--list","--",O.PACKAGE]
    new=str(SUPPLEMENT/O.SUCCESSOR)
    old=str(T.IN/O.REPO/O.PREVIOUS)
    opts=["--upgrade","--noconfirm"]
    identity=["/usr/bin/runuser","-u",P.ACCOUNT,"--","/usr/bin/env","-i",
              "PATH=/usr/bin:/bin","LC_ALL=C.UTF-8","TZ=UTC","HOME="+str(P.HOME),
              "XDG_CONFIG_HOME="+str(P.HOME/".config"),"XDG_STATE_HOME="+str(P.HOME/".local/state")]
    return {
        "fish-before":query,
        "fish-before-owners":ownership,
        "fish-create-user":[*chroot,"/usr/bin/useradd","--no-create-home","--user-group","--uid",str(P.UID),
                            "--home-dir",str(P.HOME),"--shell","/usr/bin/nologin",P.ACCOUNT],
        "fish-user":[*chroot,"/usr/bin/getent","passwd",P.ACCOUNT],
        "fish-activate":[*chroot,*identity,"/usr/bin/cachy-asahi-setup","activate","--components","fish",
                        "--home",str(P.HOME),"--template-root","/usr/share/cachy-asahi","--apply"],
        "fish-start-before":P.command(T.TARGET,"before"),
        "fish-test-metadata":[*gpg,"--with-colons","--fingerprint","--show-keys",str(SUPPLEMENT/O.PUBLIC)],
        "fish-import-test":[*gpg,"--import"],
        "fish-verify-successor":[*gpg,"--status-fd","1","--verify",new+".sig",new],
        "fish-trust-test":[*gpg,"--import-ownertrust"],
        "fish-preview-upgrade":[*pacman,*opts,"--print","--print-format","%n %v","--",new],
        "fish-upgrade":[*pacman,*opts,"--",new],
        "fish-upgraded":query,
        "fish-upgraded-db":check,
        "fish-upgraded-owners":ownership,
        "fish-start-upgraded":P.command(T.TARGET,"upgraded"),
        "fish-verify-predecessor":[*gpg,"--status-fd","1","--verify",old+".sig",old],
        "fish-preview-restore":[*pacman,*opts,"--print","--print-format","%n %v","--",old],
        "fish-restore":[*pacman,*opts,"--",old],
        "fish-restored":query,
        "fish-restored-db":check,
        "fish-restored-owners":ownership,
        "fish-start-restored":P.command(T.TARGET,"restored"),
        "fish-remove-user":[*chroot,"/usr/bin/userdel",P.ACCOUNT],
    }


def test_key(T, raw, signer, now):
    rows=[line.split(":") for line in raw.decode("utf-8").splitlines()]
    pubs=[row for row in rows if row[0]=="pub"]
    ids=[row[9] for row in rows if row[0]=="uid"]
    fprs=[row[9] for row in rows if row[0]=="fpr"]
    T.need(len(pubs)==len(ids)==len(fprs)==1 and fprs==[signer] and "TEST" in ids[0]
           and all(row[0] not in ("sec","ssb","sub") for row in rows),
           "Exactly one public signing-only disposable TEST key required")
    start,end=map(int,pubs[0][5:7])
    T.need(start<=now<end<=start+7*86400,"Current finite TEST key required")
    return dict(fingerprint=signer,created=start,expires=end)


def signature_valid(raw, fingerprint, window=None):
    rows=[line.split() for line in raw.decode("utf-8").splitlines() if line.startswith("[GNUPG:] ")]
    tags={row[1] for row in rows}
    invalid={"EXPKEYSIG","KEYEXPIRED","REVKEYSIG","SIGEXPIRED","EXPSIG","BADSIG","ERRSIG","NO_PUBKEY"}
    goods=[row for row in rows if row[1]=="GOODSIG"]
    valid=[row for row in rows if row[1]=="VALIDSIG"]
    return (not tags&invalid and len(goods)==len(valid)==1 and goods[0][2]==fingerprint[-16:]
            and valid[0][2]==valid[0][-1]==fingerprint
            and (window is None or window["created"]<=int(valid[0][4])<window["expires"]))


def payload(T, O, path, ref):
    owners=[]
    for name,pin in ref.items():
        leaf=T.ordinary(path/name)
        info=leaf.lstat()
        T.need(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o644,"Installed Fish path ownership or mode differs")
        T.read(leaf,pin,cap=64*1024)
        owners.append("/"+name)
    return owners


def ownership(T, O, raw):
    rows={"/"+name for name in O.PAYLOAD}
    rows|={str(parent)+"/" for path in rows for parent in Path(path).parents if parent!=Path("/")}
    expected=[f"{O.PACKAGE} {T.TARGET}{name}".encode() for name in rows]
    T.need(sorted(raw.splitlines())==sorted(expected),"Exact ALPM Fish payload ownership differs")


def db_snapshot(T, O, version):
    """Keep every original local DB file and normalize only Fish's install date."""
    root=T.ordinary(T.TARGET/"var/lib/pacman/local")
    lock=root.parent/"db.lck"
    T.need(not lock.exists() and not lock.is_symlink(),"Stopped guest local database required")
    observed={str(root):T.identity(root.lstat())}
    entries=sorted(islice(root.iterdir(),585))
    T.need(len(entries)==584 and root/"ALPM_DB_VERSION" in entries,"Exact 583-package local DB required")
    result={}
    retained_bytes=0
    for folder in entries:
        if folder.name=="ALPM_DB_VERSION":
            result[folder.name]=T.read(folder,cap=1024,collect=False,observed=observed)
            continue
        T.need(T.NAME.fullmatch(folder.name) and T.ordinary(folder).is_dir(),"Unexpected local package entry")
        observed[str(folder)]=T.identity(folder.lstat())
        files=list(islice(folder.iterdir(),17))
        T.need(2<=len(files)<=16 and {"desc","files"}<={f.name for f in files},"Unexpected local package member set")
        for file in files:
            T.need(T.NAME.fullmatch(file.name),"Invalid local package member")
            key=str(file.relative_to(root))
            cap=min(8*1024**2,128*1024**2-retained_bytes)
            if key==f"{O.PACKAGE}-{version}/desc":
                raw=T.read(file,cap=cap,observed=observed)
                contents,edits=re.subn(rb"(?m)^%INSTALLDATE%\n[0-9]+\n",b"%INSTALLDATE%\nNORMALIZED\n",raw)
                T.need(edits==1,"Fish record must have exactly one normal install date")
                ref=T.pin(contents)
            else:
                ref=T.read(file,cap=cap,collect=False,observed=observed)
            retained_bytes+=ref["bytes"]
            result[key]=ref
    T.unchanged(observed)
    T.need(not lock.exists() and not lock.is_symlink(),"Local database changed during capture")
    fish=f"{O.PACKAGE}-{version}/"
    selected={name.removeprefix(fish):ref for name,ref in result.items() if name.startswith(fish)}
    T.need({"desc","files"}<=set(selected),"Selected Fish ALPM metadata missing")
    rest={name:ref for name,ref in result.items() if not name.startswith(fish)}
    return dict(unchanged_packages=T.pin(T.encoded(rest)),selected_package=T.pin(T.encoded(selected)))


def alpm(T, O, raw):
    rows=re.findall(rb"^\[[^\]\r\n]+\] \[ALPM\] (installed|removed|upgraded|downgraded|reinstalled) ([^ \r\n]+) ([^\r\n]+)$",
                    raw,re.M)
    package=O.PACKAGE.encode()
    old,new=O.OLD.encode(),O.NEW.encode()
    T.need(rows==[(b"upgraded",package,b"("+old+b" -> "+new+b")"),
                  (b"downgraded",package,b"("+new+b" -> "+old+b")")],
           "Exact original ALPM one-version upgrade and rollback required")
    return T.pin(raw)


def user_fixture(T, P, identity):
    row=identity.decode("ascii").removesuffix("\n").split(":")
    T.need(len(row)==7 and row[0]==P.ACCOUNT and int(row[2])==P.UID and int(row[3])>0
           and row[5]==str(P.HOME) and row[6]=="/usr/bin/nologin","Exact ordinary disposable account required")
    group=int(row[3])
    private=T.TARGET/str(P.PRIVATE).lstrip("/")
    private.mkdir(mode=0o700)
    private.chmod(0o755)  # PID 1 sets umask 077.
    home=T.TARGET/str(P.HOME).lstrip("/")
    for path in (home,home/".config",home/".config/fish"):
        path.mkdir(mode=0o700)
        os.chown(path,P.UID,group)
    config=home/P.USER_CONFIG
    config.write_bytes(P.USER_BYTES)
    config.chmod(0o600)
    os.chown(config,P.UID,group)
    return config,group


def run(T, *, supplement_sha256, nonce, env, command):
    T.need(os.getuid()==os.geteuid()==0 and os.uname().machine=="aarch64" and os.sysconf("SC_PAGE_SIZE")==16384
           and re.fullmatch("[a-f0-9]{32}",nonce)
           and Path("/proc/cmdline").read_text().split().count("cachy_overlay583_nonce="+nonce)==1
           and {path.name for path in Path("/sys/class/net").iterdir()}<={"lo"},"Exact held offline ARM16K guest required")
    mounts=Path("/proc/self/mountinfo").read_text().splitlines()
    for path,mode in ((SUPPLEMENT.parent,"ro"),(T.IN,"ro"),(T.WORK,"rw")):
        T.mount_mode(path,mode,mounts)
    target=T.ordinary(T.TARGET)
    T.need(target.parent==T.WORK and target.stat().st_dev==T.WORK.stat().st_dev!=Path("/").stat().st_dev,
           "Exact guest-only installation target required")
    raw=T.read(SUPPLEMENT/"supplement.json",cap=64*1024)
    T.need(T.pin(raw)["sha256"]==supplement_sha256,"Exact held supplement required")
    pins=T.decode(raw)["files"]
    O=module(T,SUPPLEMENT,"operands.py",pins["operands.py"])
    P=module(T,SUPPLEMENT,"probe.py",pins["probe.py"])
    stage=O.check_stage(T,SUPPLEMENT,supplement_sha256,sources=SUPPLEMENT)
    return exercise(T,O,P,stage,env,command)


def exercise(T, O, P, stage, env, command):
    config=T.read(T.CONFIG,cap=4096).decode("ascii").splitlines()
    T.need("SigLevel = Required TrustedOnly" in config and "LocalFileSigLevel = Required TrustedOnly" in config
           and env.get("GNUPGHOME")==str(T.WORK/"trust"),"Existing guest-only signature and trust policy required")
    before,upgraded=O.inventories(T,T.read(T.IN/"target.lock",O.TARGET,cap=64*1024))
    bodies={"before":before,"upgraded":upgraded,"restored":before}
    known=stage["inventories"]["predecessor"]["payload"]
    T.need({name:T.pin(raw) for name,raw in bodies.items()}=={name:stage["inventories"][name] for name in bodies},
           "Exact single-version transition required")
    old=T.IN/O.REPO/O.PREVIOUS
    T.need(O.package(T,T.read(old,O.PIN_OLD,cap=64*1024),O.OLD)==known,"Original rollback archive differs")
    T.read(old.with_name(old.name+".sig"),O.PIN_OLD_SIG,cap=1024,collect=False)
    expected=command_plan(T,O,P)

    def call(role, seconds=30, contents=None):
        return command(role,expected[role],seconds,contents)

    locks={}
    states={}
    probes={}
    user_pins={}

    def observe(phase, version, archive_payload):
        locks[phase]=T.pin(T.sorted_rows(call("fish-"+phase)))
        T.need(locks[phase]==T.pin(bodies[phase]),"Only exact Fish version replacement is allowed")
        if phase!="before":
            call("fish-"+phase+"-db")
        ownership(T,O,call("fish-"+phase+"-owners"))
        payload(T,O,T.TARGET,archive_payload)
        states[phase]=db_snapshot(T,O,version)

    def check_shell(phase):
        probes[phase]=P.receipt(call("fish-start-"+phase),P.HOME/phase,P.UID,expect_local=(phase=="upgraded"))
        info=user_file.lstat()
        T.need(info.st_uid==P.UID and info.st_gid==user_gid and stat.S_IMODE(info.st_mode)==0o600,
               "Original user-owned Fish config mode or owner changed")
        user_pins[phase]=T.read(user_file,active_config,cap=64*1024,collect=False)

    with ExitStack() as stack:
        T.target_api_mounts(T.TARGET,env,stack)
        observe("before",O.OLD,known)
        call("fish-create-user")
        user_file,user_gid=user_fixture(T,P,call("fish-user"))
        call("fish-activate",45)
        cfg=T.read(user_file,cap=64*1024)
        T.need(P.USER_BYTES in cfg and b"/usr/share/cachy-asahi/fish/config.fish" in cfg,
               "Setup8 must keep the original user text and opt into the installed package path")
        active_config=T.pin(cfg)
        check_shell("before")
        signer=stage["rehearsal"]["fingerprint"]
        T.need(signer!=OVERLAY_SIGNER,"Separate scoped Fish upgrade TEST identity required")
        key=test_key(T,call("fish-test-metadata"),signer,time.time())
        T.need(key==stage["rehearsal"],"Selected TEST key dates or signer differ")
        call("fish-import-test",contents=T.read(SUPPLEMENT/O.PUBLIC,stage["files"][O.PUBLIC],cap=4096))
        T.need(signature_valid(call("fish-verify-successor"),signer,key),"Actual current successor TEST signature required")
        call("fish-trust-test",contents=(signer+":6:\n").encode())
        T.need(call("fish-preview-upgrade")==f"{O.PACKAGE} {O.NEW}\n".encode(),"Expected one upgrade and no dependency changes")
        call("fish-upgrade",90)
        observe("upgraded",O.NEW,stage["successor"])
        check_shell("upgraded")
        T.need(signature_valid(call("fish-verify-predecessor"),OVERLAY_SIGNER),"Exact original repository rollback signature required")
        T.need(call("fish-preview-restore")==f"{O.PACKAGE} {O.OLD}\n".encode(),"Expected one signed rollback and no dependency changes")
        call("fish-restore",90)
        observe("restored",O.OLD,known)
        check_shell("restored")
        T.need(states["before"]==states["restored"] and len({state["unchanged_packages"]["sha256"] for state in states.values()})==1,
               "Exact unrelated ALPM metadata and normalized original Fish record must restore")
        call("fish-remove-user")
    installed_log=alpm(T,O,T.read(T.WORK/"fish-upgrade-pacman.log",cap=MAX_LOG))
    return dict(status=PASS,alpm=installed_log,locks=locks,db=states,probes=probes,user_config=user_pins,
                key=key,qualified_pair=stage["qualification"],page_size=16384,hardware="NOT RUN",Root_acceptance=None)


def evidence(T, directory, ledger, result):
    rows=[]
    for row in ledger:
        record=dict(row)
        for stream in ("stdout","stderr"):
            record[stream]=b64encode(T.read(directory/(row["role"]+"."+stream),cap=MAX_LOG)).decode("ascii")
        rows.append(record)
    path=T.WORK/"fish-upgrade-pacman.log"
    source=T.read(path,cap=MAX_LOG) if path.exists() else b""
    raw=T.encoded(dict(result=result,commands=rows,alpm=b64encode(source).decode("ascii")))
    T.need(len(raw)<=MAX_EVIDENCE,"Bounded original Fish evidence required")
    return raw


def readback(T, O, P, raw, *, baseline, stage, held):
    body=T.decode(raw)
    plan=command_plan(T,O,P)
    commands=body["commands"]
    roles=[row["role"] for row in commands]
    alpm_body=b64decode(body["alpm"],validate=True)
    T.need(len(alpm_body)<=MAX_LOG and set(body)=={"commands","result","alpm"}
           and roles==list(plan)[:len(roles)] and (held or roles==list(plan)),
           "Original Fish transaction command order differs")
    output={}
    for i,row in enumerate(commands):
        role=row["role"]
        T.need(set(row)=={"role","argv","exit","stdout","stderr"} and row["argv"]==plan[role]
               and type(row["exit"]) is int and (row["exit"]==0 or held and i==len(commands)-1),
               "Original Fish transaction argument or exit differs")
        stdout,stderr=(b64decode(row[side],validate=True) for side in ("stdout","stderr"))
        T.need(len(stdout)<=MAX_LOG and len(stderr)<=MAX_LOG,"Original Fish output length differs")
        if role in ("fish-upgrade","fish-restore") and row["exit"]==0:
            failed=re.search(rb"(?im)^error: (?:failed to execute|command failed)",stderr)
            T.need(not failed or (held and i==len(commands)-1 and body["result"] is None),
                   "Fish hook/scriptlet failure")
        output[role]=stdout
    result=body["result"]
    if result is None:
        T.need(held,"Expected complete Fish upgrade and rollback")
        return None
    T.need(roles==list(plan) and all(row["exit"]==0 for row in commands)
           and result["alpm"]==alpm(T,O,alpm_body)
           and output["fish-preview-upgrade"]==f"{O.PACKAGE} {O.NEW}\n".encode()
           and output["fish-preview-restore"]==f"{O.PACKAGE} {O.OLD}\n".encode(),
           "Exact original successful Fish transaction previews and actions required")
    before,upgraded=O.inventories(T,baseline)
    for phase,wanted in (("before",before),("upgraded",upgraded),("restored",before)):
        T.need(T.sorted_rows(output["fish-"+phase])==wanted and result["locks"][phase]==T.pin(wanted),
               "Exact Fish inventory differs: "+phase)
        ownership(T,O,output["fish-"+phase+"-owners"])
        T.need(P.receipt(output["fish-start-"+phase],P.HOME/phase,P.UID,expect_local=(phase=="upgraded"))
               ==result["probes"][phase],"Original ordinary-user Fish proof differs")
    T.need(result["status"]==PASS and result["qualified_pair"]==stage["qualification"]
           and result["key"]==stage["rehearsal"]
           and signature_valid(output["fish-verify-successor"],stage["rehearsal"]["fingerprint"],result["key"])
           and signature_valid(output["fish-verify-predecessor"],OVERLAY_SIGNER)
           and result["db"]["before"]==result["db"]["restored"]
           and len({state["unchanged_packages"]["sha256"] for state in result["db"].values()})==1
           and set(result["user_config"])==set(P.PHASES)
           and result["user_config"]["before"]==result["user_config"]["upgraded"]==result["user_config"]["restored"]
           and result["user_config"]["before"]["bytes"]>0
           and O.HEX.fullmatch(result["user_config"]["before"]["sha256"])
           and result["page_size"]==16384 and result["hardware"]=="NOT RUN" and result["Root_acceptance"] is None,
           "Bound signed Fish upgrade/rollback and user config restoration evidence required")
    return result
