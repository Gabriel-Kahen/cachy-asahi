# SPDX-License-Identifier: MIT
"""Read-only selection and public TEST staging for the qualified llhttp pair."""

import argparse
from io import BytesIO
import importlib.util
import lzma
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time

HERE = Path(__file__).resolve().parent
PACKAGE = "cachy-asahi-llhttp-reference"
VERSION = "9.3.1-1"
ARCHIVE = f"{PACKAGE}-{VERSION}-aarch64.pkg.tar.xz"
SIGNATURE = ARCHIVE+".sig"
PUBLIC = "llhttp-lifecycle-TEST-public.gpg"
RECEIPT = "supplement.json"
QUALIFICATION = "native-pair.json"
KIND = "OVERLAY583_LLHTTP_SUPPLEMENT_V1"
PAIR_KIND = "ROOT_LLHTTP_REFERENCE_NATIVE_PAIR_FOR_DISPOSABLE_LIFECYCLE_V1"
REAL = "usr/lib/libllhttp.so.9.3.1"
HEADER = "a812a1aa52c07532d163dad7725c1c135235c43ce2c954ede39b48e99d830d61"
LINKS = {"usr/lib/libllhttp.so":"libllhttp.so.9.3", "usr/lib/libllhttp.so.9.3":"libllhttp.so.9.3.1"}
EXPECTED = {REAL, *LINKS, "usr/include/llhttp.h", "usr/lib/cmake/llhttp/llhttp-config-release.cmake",
            "usr/lib/cmake/llhttp/llhttp-config.cmake", "usr/lib/pkgconfig/libllhttp.pc",
            f"usr/share/licenses/{PACKAGE}/LICENSE-MIT"}
BASE = "12e5f0d74f8530fee9cc2b10ad7887748c2f9d5fdfed259b498f4b3db87167ba"
PRE = "efbd1147613ab68721a05268c7973282936b5b61de09268c84f473b02566a3c7"
CODE = ("guest.py","operands.py","probe.py")


def pair(trial, raw, archive_pin):
    data=trial.decode(raw)
    need=trial.need
    need(set(data)=={"kind","issuer","status","source","run","closure","architecture","builds","structural_page_size"}
         and data["kind"]==PAIR_KIND and data["issuer"]=="Root" and data["status"]=="PASS"
         and data["architecture"]=="aarch64" and data["structural_page_size"]==16384
         and re.fullmatch("[0-9a-f]{40}",data["source"]) and type(data["run"]) is int and data["run"]>0
         and raw==trial.encoded(data), "External Root-qualified exact native pair required")
    closure=data["closure"]
    need(set(closure)=={"bytes","sha256"} and type(closure["bytes"]) is int and closure["bytes"]>0
         and re.fullmatch("[a-f0-9]{64}",closure["sha256"]), "Pair requires the independent terminal closure pin")
    builds=data["builds"]
    need(type(builds) is list and builds==[dict(build=index,checks="PASS",archive=archive_pin,clean=True)
                                          for index in (1,2)],
         "Two independent clean native builds must match the exact whole qualified archive and checks")
    return data


def package(trial, raw):
    need=trial.need
    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=32*1024**2)
    expanded=decoder.decompress(raw,max_length=2*1024**2)
    need(decoder.eof and not decoder.unused_data,"Finite single XZ package required")
    members={}
    directories={str(parent) for leaf in EXPECTED for parent in Path(leaf).parents if parent!=Path(".")}
    payload={}
    with tarfile.open(fileobj=BytesIO(expanded),mode="r:") as tar:
        for member in tar:
            name=member.name.rstrip("/")
            need(name not in members and len(members)<40 and member.uid==member.gid==0
                 and not member.mode&0o7000 and (member.issym() or not member.mode&0o022) and not member.pax_headers,
                 "Exact finite root-owned llhttp package namespace required")
            members[name]=member
            if member.isdir():
                need(name in directories, "Unexpected package directory")
            elif name in LINKS:
                need(member.issym() and member.linkname==LINKS[name],"Compiler library symlink target differs")
                payload[name]=dict(target=member.linkname)
            else:
                need(member.isreg() and name in EXPECTED|{".PKGINFO",".MTREE",".BUILDINFO"}
                     and 0<member.size<=512*1024, "Unexpected package member: "+name)
                body=tar.extractfile(member).read()
                if name==".PKGINFO":
                    pairs = [line.split(" = ",1) for line in body.decode("utf-8").splitlines() if " = " in line]
                    for key,want in (("pkgname",[PACKAGE]),("pkgver",[VERSION]),("arch",["aarch64"]),("depend",["glibc"])):
                        need([value for field,value in pairs if field==key]==want, "Unexpected .PKGINFO "+key)
                if name in EXPECTED:
                    if name=="usr/include/llhttp.h":
                        need(trial.pin(body)["sha256"]==HEADER,"ctypes 9.3.1 ABI header differs")
                    if name==REAL:
                        need(body[:6]==b"\x7fELF\x02\x01" and int.from_bytes(body[18:20],"little")==183,
                             "Exact AArch64 shared library required")
                    payload[name]=dict(mode=member.mode,pin=trial.pin(body))
    need(set(payload)==EXPECTED and set(members)==EXPECTED|directories|{".PKGINFO",".MTREE",".BUILDINFO"},
         "Complete llhttp runtime and development payload required")
    return payload


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


def public_only(trial, files):
    trial.need(packet_tags(files[PUBLIC])==[6,13,2] and packet_tags(files[SIGNATURE])==[2],
               "Only a single Public TEST certificate and detached signature may enter staged data")


def valid_key(record, now):
    return (set(record)=={"fingerprint","created","expires","test_only"} and record["test_only"] is True
            and re.fullmatch("[A-F0-9]{40}",record["fingerprint"])
            and type(record["created"]) is type(record["expires"]) is int
            and record["created"]<=now<record["expires"]<=record["created"]+7*86400)


def signed(raw, key):
    rows=[line.split() for line in raw.decode("ascii").splitlines() if line.startswith("[GNUPG:] ")]
    good=[row for row in rows if row[1]=="GOODSIG"]
    valid=[row for row in rows if row[1]=="VALIDSIG"]
    fpr=key["fingerprint"]
    bad={"EXPKEYSIG","KEYEXPIRED","SIGEXPIRED","EXPSIG","BADSIG","ERRSIG","REVKEYSIG","NO_PUBKEY"}
    return (len(good)==len(valid)==1 and len(good[0])>=3 and len(valid[0])>=12 and good[0][2]==fpr[-16:]
            and valid[0][2]==valid[0][-1]==fpr and not bad & {row[1] for row in rows}
            and key["created"]<=int(valid[0][4])<key["expires"])


def check_stage(trial, root, digest, source):
    root=trial.ordinary(root)
    raw=trial.read(root/RECEIPT,cap=64*1024)
    value=trial.decode(raw)
    permit=trial.pin(raw)
    files=value["files"]
    need=trial.need
    need(permit["sha256"]==digest and raw==trial.encoded(value) and value["kind"]==KIND
         and set(value)=={"kind","files","rehearsal","payload","qualification","before","after","Root_authority","installation"}
         and value["Root_authority"] is None and value["installation"]=="NOT RUN"
         and set(files)=={ARCHIVE,SIGNATURE,PUBLIC,QUALIFICATION,*CODE}
         and {leaf.name for leaf in root.iterdir()}==set(files)|{RECEIPT}
         and valid_key(value["rehearsal"],time.time()) and value["before"]["sha256"]==BASE,
         "Exact rooted, signed, current llhttp supplement required")
    payload={name:trial.read(root/name,want,cap=128*1024) for name,want in files.items()}
    public_only(trial,payload)
    need(all(trial.pin(trial.read(source/name,cap=128*1024))==files[name] for name in CODE),
         "Selected llhttp source and code media differ")
    need(value["qualification"]==pair(trial,payload[QUALIFICATION],files[ARCHIVE])
         and value["payload"]==package(trial,payload[ARCHIVE]),"Qualified archive or payload differs")
    return dict(value,receipt=permit)


def prepare(trial, *, staging, preflight, archive, matching_archive, qualification, qualification_sha256,
            signature, public_key, output):
    lock=trial.read(staging/"target.lock",cap=64*1024)
    pre=trial.read(preflight,cap=64*1024)
    before=trial.pin(lock)
    trial.need(before["sha256"]==BASE and trial.pin(pre)["sha256"]==PRE,"Exact authenticated Overlay583 required")
    trial.need(PACKAGE not in trial.canonical_lock(lock,583),"llhttp already installed")
    after=trial.sorted_rows(lock+f"{PACKAGE} {VERSION}\n".encode())
    trial.canonical_lock(after,584)
    files={name:trial.read(path,cap=128*1024) for name,path in ((ARCHIVE,archive),(SIGNATURE,signature),(PUBLIC,public_key),
                                                             (QUALIFICATION,qualification))}
    trial.need(trial.pin(files[QUALIFICATION])["sha256"]==qualification_sha256,"External qualification bytes differ")
    archive_pin=trial.pin(files[ARCHIVE])
    approved=pair(trial,files[QUALIFICATION],archive_pin)
    trial.need(not archive.samefile(matching_archive),"Distinct retained native build artifacts required")
    trial.read(matching_archive,archive_pin,cap=128*1024,collect=False)
    payload=package(trial,files[ARCHIVE])
    public_only(trial,files)
    output=trial.ordinary(output)
    trial.need(not output.exists(),"Fresh private public DATA output required")
    with tempfile.TemporaryDirectory(prefix="llhttp-verify-public-test-") as temp:
        home=Path(temp)
        for name in (ARCHIVE,SIGNATURE,PUBLIC):
            (home/name).write_bytes(files[name])

        def verify(argv):
            return subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,check=True,timeout=25,
                                  env={"PATH":"/usr/bin:/bin","LC_ALL":"C"}).stdout
        gpg=["/usr/bin/gpg","--batch","--no-options","--homedir",str(home)]
        meta=verify([*gpg,"--with-colons","--fingerprint","--show-keys",str(home/PUBLIC)]).decode("ascii")
        records=[line.split(":") for line in meta.splitlines()]
        pub=[row for row in records if row[0]=="pub"]
        fprs=[row[9] for row in records if row[0]=="fpr"]
        uid=[row[9] for row in records if row[0]=="uid"]
        trial.need(len(pub)==len(fprs)==len(uid)==1 and "TEST" in uid[0] and not any(row[0]=="sub" for row in records),
                   "One plain current TEST-only signing certificate required")
        rehearsal=dict(fingerprint=fprs[0],created=int(pub[0][5]),expires=int(pub[0][6]),test_only=True)
        raw=verify(["/usr/bin/gpgv","--homedir",str(home),"--keyring",str(home/PUBLIC),"--status-fd","1",
                    str(home/SIGNATURE),str(home/ARCHIVE)])
        trial.need(valid_key(rehearsal,time.time()+trial.TIMEOUT) and signed(raw,rehearsal),
                   "Actual current TEST signature and full guest time budget required")
    files.update({name:trial.read(HERE/name,cap=128*1024) for name in CODE})
    value=dict(kind=KIND,files={name:trial.pin(raw) for name,raw in files.items()},rehearsal=rehearsal,
               payload=payload,qualification=approved,before=before,after=trial.pin(after),Root_authority=None,installation="NOT RUN")
    output.mkdir(mode=0o700)
    for name,body in files.items():
        (output/name).write_bytes(body)
    (output/RECEIPT).write_bytes(trial.encoded(value))
    return check_stage(trial,output,trial.pin(trial.encoded(value))["sha256"],HERE)


def cli():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("staging","preflight","archive","matching-archive","qualification","signature","public-key","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--qualification-sha256",required=True)
    spec=importlib.util.spec_from_file_location("overlay583_trial",HERE.parents[1]/"install/overlay583_trial/trial.py")
    trial=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(trial)
    print(trial.encoded(prepare(trial,**vars(parser.parse_args()))).decode(),end="")


if __name__=="__main__":
    cli()
