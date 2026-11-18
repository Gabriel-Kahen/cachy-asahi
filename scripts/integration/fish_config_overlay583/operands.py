# SPDX-License-Identifier: MIT
"""Pin the signed Fish rollback and prepare a future qualified upgrade DATA tree."""

import argparse
from io import BytesIO
import importlib.util
import lzma
from pathlib import Path
import re
import tarfile

HERE=Path(__file__).resolve().parent
PACKAGE="cachy-asahi-fish-config"
OLD="0.1.0-1"
NEW="0.1.0-2"
PREVIOUS=PACKAGE+"-"+OLD+"-any.pkg.tar.xz"
SUCCESSOR=PACKAGE+"-"+NEW+"-any.pkg.tar.xz"
PUBLIC="fish-upgrade-TEST-public.gpg"
PAIR="qualified-r127.json"
RECEIPT="supplement.json"
REPO="offline-overlay-kit/release/repo"
TARGET=dict(bytes=11450,sha256="12e5f0d74f8530fee9cc2b10ad7887748c2f9d5fdfed259b498f4b3db87167ba")
PREFLIGHT="efbd1147613ab68721a05268c7973282936b5b61de09268c84f473b02566a3c7"
PIN_OLD=dict(bytes=7220,sha256="d714cea85c8ef651d4b688a4a13dd2d6504192fb8f69a1ff4e70ad6237e8089a")
PIN_OLD_SIG=dict(bytes=119,sha256="e54a333f0f2178ef5d829353fa8493957602bf6eab0de5c77abb6f66f25feebe")
SOURCE="346e897f1b3a0fa273fa74d3331363b6f39b6436"
RUN=44239472740
PAIR_KIND="ROOT_FISH02_R127_NATIVE_PAIR_FOR_OVERLAY583_UPGRADE_V1"
KIND="OVERLAY583_FISH_CONFIG_UPGRADE_SUPPLEMENT_V1"
CONFIG="usr/share/cachy-asahi/fish/config.fish"
PAYLOAD={
    CONFIG: {OLD:"223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c",
             NEW:"d26d8826c8a7e096a55d0a4b3eee8e67013d6c9b201971e89ca32e273c0847aa"},
    f"usr/share/licenses/{PACKAGE}/NOTICE": dict.fromkeys((OLD,NEW),"19eb85ed65396056e59782ddf80fb5285ee26cad5ddf77ccb378936a2d5601c9"),
    f"usr/share/licenses/{PACKAGE}/LICENSE": dict.fromkeys((OLD,NEW),"51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7"),
}
CODE=("operands.py","guest.py","probe.py","bridge.py")
HEX=re.compile("[a-f0-9]{64}")
FPR=re.compile("[A-F0-9]{40}")


def inventories(trial, raw):
    trial.need(trial.pin(raw)==TARGET and trial.canonical_lock(raw,583).get(PACKAGE)==OLD,
               "Exact authenticated Overlay583 Fish predecessor required")
    before=f"{PACKAGE} {OLD}\n".encode()
    after=f"{PACKAGE} {NEW}\n".encode()
    trial.need(raw.count(before)==1 and after not in raw,"Exact single Fish config row required")
    changed=raw.replace(before,after)
    trial.canonical_lock(changed,583)
    return raw,changed


def package(trial, raw, version):
    trial.need(version in (OLD,NEW),"Only the held Fish versions are supported")
    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=32*1024**2)
    expanded=decoder.decompress(raw,max_length=1024*1024)
    trial.need(decoder.eof and not decoder.unused_data,"Finite single XZ package required")
    seen=set()
    files={}
    directories={str(parent) for path in PAYLOAD for parent in Path(path).parents if parent!=Path(".")}
    metadata={".PKGINFO",".BUILDINFO",".MTREE"}
    with tarfile.open(fileobj=BytesIO(expanded),mode="r:") as tar:
        for row in tar:
            name=row.name.rstrip("/")
            trial.need(name not in seen and row.uid==row.gid==0 and not row.pax_headers,
                       "Exact ordinary root-owned Fish payload required")
            seen.add(name)
            if name in directories:
                trial.need(row.isdir() and row.mode==0o755,"Unexpected Fish archive directory")
                continue
            trial.need(name in metadata|set(PAYLOAD) and row.isreg() and row.mode==0o644 and 0<row.size<=64*1024,
                       "Unexpected Fish archive operand: "+name)
            body=tar.extractfile(row).read()
            if name==".PKGINFO":
                values=[line.split(" = ",1) for line in body.decode("utf-8").splitlines() if " = " in line]
                expected={"pkgname":[PACKAGE],"pkgver":[version],"arch":["any"],"depend":["coreutils","fish"],"backup":[]}
                for key,want in expected.items():
                    trial.need(sorted(value for field,value in values if field==key)==want,
                               "Unexpected Fish package metadata: "+key)
            if name in PAYLOAD:
                ref=trial.pin(body)
                trial.need(ref["sha256"]==PAYLOAD[name][version],"Fish leaf bytes differ: "+name)
                files[name]=ref
    trial.need(seen==directories|metadata|set(PAYLOAD) and set(files)==set(PAYLOAD),
               "Complete exact Fish payload required")
    return files


def baseline(trial, staging, preflight):
    raw=trial.read(staging/"target.lock",TARGET,cap=64*1024)
    old,updated=inventories(trial,raw)
    pre=trial.read(preflight,cap=64*1024)
    trial.need(trial.pin(pre)["sha256"]==PREFLIGHT and trial.decode(pre)["base_archives_authenticated"] is True,
               "Exact signed Overlay583 preflight required")
    operands=staging/REPO
    old_package=trial.read(operands/PREVIOUS,PIN_OLD,cap=64*1024)
    trial.read(operands/(PREVIOUS+".sig"),PIN_OLD_SIG,cap=1024)
    return dict(before=trial.pin(old),upgraded=trial.pin(updated),restored=trial.pin(old),
                predecessor=dict(archive=PIN_OLD,signature=PIN_OLD_SIG,payload=package(trial,old_package,OLD)))


def qualification(trial, raw, archive_pin):
    value=trial.decode(raw)
    expected={"kind","issuer","status","source","run","closure","architecture","package_architecture","builds"}
    trial.need(set(value)==expected and raw==trial.encoded(value) and value["kind"]==PAIR_KIND
               and value["issuer"]=="Root" and value["status"]=="PASS" and value["source"]==SOURCE and value["run"]==RUN
               and value["architecture"]=="aarch64" and value["package_architecture"]=="any"
               and value["builds"]==[dict(build=i,archive=archive_pin,clean=True,checks="PASS") for i in (1,2)],
               "Two qualified matching R127 native archives and semantic checks required")
    close=value["closure"]
    trial.need(set(close)=={"bytes","sha256"} and type(close["bytes"]) is int and close["bytes"]>0
               and HEX.fullmatch(close["sha256"]),"Independent Root closure pin required")
    return value


def packet_tags(raw):
    """Read finite binary OpenPGP packet tags without invoking a key tool."""
    tags=[]
    at=0
    while at<len(raw) and len(tags)<4:
        tag=raw[at]
        if tag<128 or at+1>=len(raw):
            return None
        at+=1
        if tag&0x40:
            tag &= 0x3f
            first=raw[at]
            at+=1
            if first<192:
                length=first
            elif first<224 and at<len(raw):
                length=((first-192)<<8)+raw[at]+192
                at+=1
            elif first==255 and at+4<=len(raw):
                length=int.from_bytes(raw[at:at+4],"big")
                at+=4
            else:
                return None
        else:
            count={0:1,1:2,2:4}.get(tag&3)
            if count is None or at+count>len(raw):
                return None
            tag=(tag>>2)&0xf
            length=int.from_bytes(raw[at:at+count],"big")
            at+=count
        if not length or at+length>len(raw):
            return None
        at+=length
        tags.append(tag)
    return tags if at==len(raw) else None


def bounded_public_signature(trial, public, signature):
    trial.need(packet_tags(public)==[6,13,2] and packet_tags(signature)==[2],
               "Only a bounded public TEST certificate and detached signature are allowed")


def stage(trial, *, staging, preflight, archive, matching_archive, qualified, qualified_sha256,
          signature, public_key, signer, output):
    before=baseline(trial,staging,preflight)
    raw=trial.read(archive,cap=128*1024)
    archive_pin=trial.pin(raw)
    trial.need(not archive.samefile(matching_archive),"Distinguish the two retained original build files")
    trial.read(matching_archive,archive_pin,cap=128*1024)
    approval=trial.read(qualified,cap=16*1024)
    trial.need(trial.pin(approval)["sha256"]==qualified_sha256,"Exact external R127 qualification required")
    pair=qualification(trial,approval,archive_pin)
    trial.need(FPR.fullmatch(signer),"Exact selected TEST signature identity required")
    signature_bytes=trial.read(signature,cap=4096)
    public_bytes=trial.read(public_key,cap=4096)
    bounded_public_signature(trial,public_bytes,signature_bytes)
    # GnuPG verifies the detached signature and current TEST key through a
    # held command before trust is enabled in the disposable actor.
    materials={SUCCESSOR:raw,SUCCESSOR+".sig":signature_bytes,PUBLIC:public_bytes,PAIR:approval}
    materials.update({name:trial.read(HERE/name,cap=128*1024) for name in CODE})
    result=dict(kind=KIND,files={name:trial.pin(data) for name,data in materials.items()},
                inventories=before,rehearsal=signer,qualification=pair,successor=package(trial,raw,NEW),
                Root_authority=None,installation="NOT RUN")
    output=trial.ordinary(output)
    output.mkdir(mode=0o700)
    for name,body in materials.items():
        (output/name).write_bytes(body)
        (output/name).chmod(0o444)
    receipt=trial.encoded(result)
    (output/RECEIPT).write_bytes(receipt)
    (output/RECEIPT).chmod(0o444)
    return dict(result,receipt=trial.pin(receipt))


def check_stage(trial, root, digest, *, sources):
    raw=trial.read(root/RECEIPT,cap=64*1024)
    packet=trial.decode(raw)
    files=packet["files"]
    trial.need(trial.pin(raw)["sha256"]==digest and raw==trial.encoded(packet) and packet["kind"]==KIND
               and packet["Root_authority"] is None and packet["installation"]=="NOT RUN"
               and FPR.fullmatch(packet["rehearsal"]) and set(files)=={SUCCESSOR,SUCCESSOR+".sig",PUBLIC,PAIR,*CODE}
               and {p.name for p in root.iterdir()}==set(files)|{RECEIPT},
               "Exact read-only Fish upgrade DATA required")
    bodies={name:trial.read(root/name,pin,cap=128*1024) for name,pin in files.items()}
    bounded_public_signature(trial,bodies[PUBLIC],bodies[SUCCESSOR+".sig"])
    trial.need(all(trial.read(sources/name,files[name],cap=128*1024)==bodies[name] for name in CODE)
               and qualification(trial,bodies[PAIR],files[SUCCESSOR])==packet["qualification"]
               and package(trial,bodies[SUCCESSOR],NEW)==packet["successor"],"Exact Fish source or pair archive differs")
    return dict(packet,receipt=trial.pin(raw))


def cli():
    import sys
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_subparsers(dest="mode",required=True)
    baseline_mode=modes.add_parser("baseline")
    stage_mode=modes.add_parser("stage")
    for mode in (baseline_mode,stage_mode):
        for name in ("staging","preflight"):
            mode.add_argument("--"+name,type=Path,required=True)
    for name in ("archive","matching-archive","qualified","signature","public-key","output"):
        stage_mode.add_argument("--"+name,type=Path,required=True)
    for name in ("qualified-sha256","signer"):
        stage_mode.add_argument("--"+name,required=True)
    spec=importlib.util.spec_from_file_location("overlay583_trial",HERE.parents[1]/"install/overlay583_trial/trial.py")
    T=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(T)
    sys.addaudithook(lambda event,_: T.need(not event.startswith(("subprocess.","socket.","ctypes.")),
                                           "No actor is permitted during Fish DATA preparation"))
    args=vars(parser.parse_args())
    mode=args.pop("mode")
    data=baseline(T,args["staging"],args["preflight"]) if mode=="baseline" else stage(T,**args)
    print(T.encoded(data).decode(),end="")


if __name__=="__main__":
    cli()
