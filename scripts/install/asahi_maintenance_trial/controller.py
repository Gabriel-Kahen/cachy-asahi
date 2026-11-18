#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-selected disposable Asahi maintenance rehearsal using the existing QEMU owner."""

import argparse
from base64 import b64decode
import importlib.util
import os
from pathlib import Path
import re
import shutil
import sys
import time

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
BASE=HERE.parent/"overlay583_trial"
KIND="ROOT_ASAHI_MAINTENANCE_DISPOSABLE_QEMU_SELECTION_V1"


def module(path):
    spec=importlib.util.spec_from_file_location("asahi_maintenance_"+path.stem,path)
    value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C=module(BASE/"controller.py")
T=C.T
O=module(HERE/"operands.py")
G=module(HERE/"guest.py")
B=module(HERE/"bootstrap.py")


def prepare(preflight, digest, runtime_stage, output):
    """Standalone passive copying of exact selected public operands."""
    raw=T.read(C.absolute(preflight),cap=O.PLAN_LIMIT)
    boot={name:dict(bytes=size,sha256=sha256) for name,(size,sha256) in C.REFERENCES.items()}
    value,sources=O.project(T,raw,digest,C.absolute(runtime_stage),controller_source=C.source_pins(),
                            actor_image=C.ACTOR_IMAGE,boot=boot)
    out=C.absolute(output)
    T.need(all(not out.is_relative_to(Path(ref["path"]).parent) for ref in sources.values()),
           "New independent transport destination required")
    out.mkdir(mode=0o700)
    for name,ref in sources.items():
        C.checked_copy(Path(ref["path"]),out/O.relative(T,name),O.pin(ref))
    receipt=T.encoded(value)
    (out/"manifest.json").write_bytes(receipt)
    (out/"manifest.json").chmod(0o444)
    return dict(status="PREPARED_ASAHI_TRANSPORT_DATA_ONLY",path=str(out),manifest=T.pin(receipt),
                preflight=value["preflight"],authority=None,installation="NOT RUN")


def selection():
    paths={"trial.py":BASE/"trial.py","asahi-guest.py":HERE/"guest.py","operands.py":HERE/"operands.py"}
    return paths,{name:T.read(path,cap=128*1024,collect=False) for name,path in paths.items()}


def source_pins():
    extra={str(path.relative_to(REPO)):T.read(path,cap=128*1024,collect=False)
           for path in (HERE/"controller.py",HERE/"guest.py",HERE/"operands.py",HERE/"bootstrap.py")}
    return C.source_pins()|extra


def init_bytes():
    return B.project(T,T.read(BASE/"guest-init.sh",cap=128*1024),O.UUID,G.NAMES)


def binding(*, staging, seed, kernel, config, baseline, output, nonce, media_digest, issuer=None):
    paths={key:C.absolute(value) for key,value in dict(staging=staging,seed=seed,kernel=kernel,
                                                      config=config,baseline=baseline,output=output).items()}
    T.need(re.fullmatch("[a-f0-9]{32}",nonce) and T.HEX.fullmatch(media_digest),"Exact guest nonce and media pin required")
    for key,path in paths.items():
        if key!="output":
            T.need(path!=paths["output"] and not path.is_relative_to(paths["output"])
                   and not paths["output"].is_relative_to(path), "Output and inputs must be disjoint")
    raw=T.read(paths["staging"]/"manifest.json",cap=512*1024)
    value=T.decode(raw)
    media=T.pin(raw)
    T.need(media["sha256"]==media_digest and T.encoded(value)==raw,"Exact selected held transport manifest required")
    O.rehash(T,paths["staging"],value)
    references={key:C.pinned(paths[key],ref) for key,ref in C.REFERENCES.items()}
    references["seed"]=T.read(paths["seed"],O.SEED,cap=O.SEED["bytes"],collect=False)
    _,files=selection()
    plan=dict(kind=G.BOOT,nonce=nonce,code=files,manifest=media,media=value)
    data=dict(kind=KIND,issuer=issuer,approval_status="UNAPPROVED",nonce=nonce,actor_image=C.ACTOR_IMAGE,
              paths={key:str(path) for key,path in paths.items()},media=media,plan=T.pin(T.encoded(plan)),
              init=T.pin(init_bytes()),references=references,source=source_pins(),tools=C.tool_pins())
    return data,plan


def copy_transport(staging, plan, root):
    media=root/"inputs"
    code=root/"code"
    values=plan["media"]["files"]|{"manifest.json":plan["manifest"]}
    files={}
    for name,ref in values.items():
        C.checked_copy(staging/name,media/name,ref)
        files["inputs/"+name]=ref
    workers,_=selection()
    for leaf,ref in plan["code"].items():
        C.checked_copy(workers[leaf],code/leaf,ref)
        files["code/"+leaf]=ref
    (code/"plan.json").write_bytes(T.encoded(plan))
    files["code/plan.json"]=T.pin(T.encoded(plan))
    aliases={}
    for name,ref in C.runtime_payload(media,root/"runtime").items():
        if isinstance(ref,dict):
            files["runtime/"+name]=ref
        elif isinstance(ref,str):
            aliases["runtime/"+name]=ref
    directories={str(path.relative_to(root)) for path in root.rglob("*") if not path.is_symlink() and path.is_dir()}
    return files,aliases,directories


def export(reader, disk_path, out, *, held):
    with reader.Ext4Reader(disk_path,max_nodes=64,max_file_bytes=8*1024**2) as disk:
        nodes=disk.inventory()["nodes"]
        folders={".","lost+found","evidence"}
        files=set(nodes)-folders
        required={"evidence/"+name for name in ("result.json","commands.json","signatures.json","platform.json")}
        allowed={"evidence/"+name for name in G.NAMES}
        T.need(folders<=set(nodes) and all(nodes[name]["type"]=="directory" for name in folders)
               and required<=files<=allowed and (held or files==allowed)
               and sum(nodes[key]["size"] for key in files)<=32*1024**2,"Exact bounded Asahi evidence namespace required")
        out.mkdir(mode=0o700)
        for name in sorted(files):
            row=nodes[name]
            T.need(row["type"]=="file" and row["uid"]==row["gid"]==0 and row["mode"]==0o600
                   and row["links"]==1,"Original guest evidence identity differs")
            fields,raw=disk.inode(row["inode"])
            body=b"".join(disk.chunks(fields,raw))
            T.need(T.pin(body)==dict(bytes=row["size"],sha256=row["sha256"]),"Asahi result reread differs")
            with (out/Path(name).name).open("xb") as stream:
                stream.write(body)


def review(output, plan, *, held):
    result=T.decode(T.read(output/"result.json",cap=128*1024))
    T.need(result["nonce"]==plan["nonce"] and result["plan"]==T.pin(T.encoded(plan))
           and result["approval_status"]=="UNAPPROVED" and result["Root_acceptance"] is None
           and result["M2"]==result["physical_installation"]=="NOT RUN"
           and result["status"]==(G.HOLD if held else G.PASS),"Original exact Asahi development receipt required")
    raw=T.read(output/"commands.json",cap=2*1024**2)
    commands=T.decode(raw)
    seen={row["role"]:row for row in commands}
    T.need(len(commands)==len(seen),"Duplicate original Asahi command")
    expected=G.command_plan(O,plan["media"])
    actual=[row["role"] for row in commands if row["role"] in expected]
    roles=["query-baseline","check-baseline","preview-forward","apply-forward","query-forward","check-forward",
           "preview-rollback","apply-rollback","query-rollback","check-rollback"]
    T.need(actual==roles[:len(actual)] and (held or actual==roles),"Missing or reordered Asahi transaction commands")
    T.need(all(row["argv"]==expected[role] for role,row in seen.items() if role in expected)
           and (held or all(row["exit"]==0 for row in commands)),"Actual guest command arguments or exits differ")
    mounted={}
    for name,(count,_,_) in O.REFS.items():
        path=output/name
        if path.is_file():
            mounted[name]=T.canonical_lock(T.read(path,O.lock_ref(name),cap=64*1024),count)
    if not held:
        T.need(set(mounted)==set(O.REFS),"Five original locks required after the declared reverse")
        O.check_delta(T,mounted)
        phases=set(G.SHOW)
        trust=T.decode(T.read(output/"signatures.json",cap=512*1024))
        T.need(set(trust)=={"forward","rollback"},"Both original signature phase receipts required")
        for stage,rows in plan["media"]["packages"].items():
            T.need(set(trust[stage])==set(rows),"All original matching detached signature observations required")
            for name,row in rows.items():
                receipt=trust[stage][name]
                original=b64decode(receipt["original"],validate=True)
                observed=G.signature(T,original,row["signer"])
                T.need(receipt==dict(observed,scope=row["scope"],original=receipt["original"])
                       and observed["status"]==seen["verify-"+stage+"-"+name]["stdout"],
                       "Independent original signed archive evidence differs: "+name)
        platform=T.decode(T.read(output/"platform.json",cap=128*1024))
        T.need(platform==result["platform"] and set(platform)==phases
               and platform["baseline"]==platform["forward"]==platform["rollback"],
               "Preserved Asahi platform output required")
        T.need(result["inventory"]=={name:O.lock_ref(name+".lock") for name in phases}
               and result["previews"]=={name:O.lock_ref(name+"-preview.lock") for name in ("forward","rollback")},
               "Exact physical command inventories and previews required")
        for phase in ("forward","rollback"):
            for stream in ("stdout","stderr"):
                file=output/("apply-"+phase+"."+stream)
                body=T.read(file,seen["apply-"+phase][stream],cap=2*1024**2)
                T.need(stream!="stderr" or not T.HOOK_FAILURE.search(body),"Original ALPM hooks did not pass")
        G.log_actions(T,mounted["baseline.lock"],mounted["forward.lock"],mounted["rollback.lock"],
                      T.read(output/"pacman.log",cap=2*1024**2),completed=True)
    result["files"]={path.name:T.read(path,cap=8*1024**2,collect=False) for path in sorted(output.iterdir())}
    return result


class Controller(C.Controller):
    def run_asahi(self, authority_path, authority_digest):
        C.actor_boundary(self.paths|{"authority":authority_path})
        T.need(os.environ.get("CACHY_ASAHI_MAINTENANCE_ACTOR")=="1","Explicit Asahi rehearsal actor entry required")
        actual,plan=binding(**self.paths,nonce=self.authority["nonce"],media_digest=self.authority["media"]["sha256"],
                                issuer="Root")
        T.need(actual==self.authority,"Exact independently issued guest run operands required")
        T.need(not self.out.exists() and shutil.disk_usage(self.out.parent).free>=O.SIZE+C.INPUT_SIZE+2*C.REFERENCES["baseline"][0]+C.RESERVE,
               "Fresh private output and unchanged VM headroom required")
        self.out.mkdir(mode=0o700)
        self.runtime=C.module(C.PERL/"runtime.py")
        self.reader=C.module(C.PERL/"frozen/independent_readback.py")
        out,deadline=self.out,time.monotonic()+C.PHASE_BUDGET
        refs=actual["references"]
        C.checked_copy(self.paths["kernel"],out/"Image",refs["kernel"])
        stock,clone=self.paths["baseline"],out/"reference.raw"
        self.command("clone-control-root","cp",["--sparse=always","--reflink=never",stock,clone],180,deadline)
        C.pinned(clone,C.REFERENCES["baseline"])
        init=out/"init.selected"
        init.write_bytes(init_bytes())
        script=out/"init.debugfs"
        script.write_text("".join(f"mkdir /{name}\n" for name in C.MOUNTPOINTS)
                          +f"write {init} /{C.BOOT}\nset_inode_field /{C.BOOT} mode 0100755\n"
                          +f"set_inode_field /{C.BOOT} uid 0\nset_inode_field /{C.BOOT} gid 0\n")
        self.command("prepare-control","debugfs",["-w","-f",script,clone],90,deadline)
        self.command("check-control","e2fsck",["-fn",clone],120,deadline)
        dump=out/"init.readback"
        self.command("read-control-init","debugfs",["-R",f"dump /{C.BOOT} {dump}",clone],30,deadline)
        T.read(dump,actual["init"],cap=128*1024)
        nonce=actual["nonce"]
        part=C.partition_boot(clone,out/"boot.raw",nonce)
        clone.unlink()

        packed=out/"input-tree"
        manifest=copy_transport(self.paths["staging"],plan,packed)
        inputs=self.filesystem("inputs","OV583_INPUT",C.INPUT_SIZE,nonce,deadline,packed)
        C.verify_input(self.reader,inputs,manifest)
        shutil.rmtree(packed)
        inputs.chmod(0o444)
        result=self.filesystem("result","OV583_RESULT",C.RESULT_SIZE,nonce,deadline)
        scratch=out/"scratch.raw"
        self.command("clone-asahi-target","cp",["--sparse=always","--reflink=never",self.paths["seed"],scratch],
                     300,deadline)
        T.read(scratch,O.SEED,cap=O.SEED["bytes"],collect=False)
        scratch.chmod(0o600)
        with scratch.open("r+b") as stream:
            stream.truncate(O.SIZE)
        before={name:T.read(out/name,cap=C.INPUT_SIZE,collect=False) for name in ("Image","boot.raw","inputs.raw")}
        argv=C.qemu_argv(out,nonce,part,actual["plan"]["sha256"],plan["code"]["asahi-guest.py"]["sha256"])
        self.runtime.command(argv,out,"qemu",seconds=G.TIMEOUT,deadline=time.monotonic()+G.TIMEOUT,
                             watched_tree=(out,24*1024**3,C.RESERVE))
        process=self.runtime.receipt(out/"qemu.json")
        T.need(self.runtime.natural(process) and process["argv"]==argv,"Natural owned QEMU retirement required")
        self.require_absent_twice(nonce)
        serial=T.read(out/"qemu.stdout",cap=1024**2)
        held=not C.serial_pass(serial,nonce,lifecycle=True)
        for name,ref in before.items():
            T.read(out/name,ref,cap=C.INPUT_SIZE,collect=False)
        for name in ("seed","baseline","config","kernel"):
            T.read(self.paths[name],refs[name],cap=refs[name]["bytes"],collect=False)
        T.need(source_pins()==actual["source"] and C.tool_pins()==actual["tools"],
               "Selected reviewed source/tool pins changed")
        T.need(T.pin(T.read(authority_path,cap=128*1024))["sha256"]==authority_digest,"Root authority changed")
        self.command("check-result","e2fsck",["-fn",result],60,time.monotonic()+70)
        evidence=out/"evidence"
        export(self.reader,result,evidence,held=held)
        report=review(evidence,plan,held=held)
        report.update(seed=refs["seed"],qemu=T.read(out/"qemu.json",cap=128*1024,collect=False),
                      serial=T.pin(serial),result_disk=T.read(result,cap=C.RESULT_SIZE,collect=False),
                      authority_sha256=authority_digest)
        with (out/"report.json").open("xb") as stream:
            stream.write(T.encoded(report))
        return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_subparsers(dest="mode",required=True)
    pack=modes.add_parser("prepare-transport")
    for name in ("preflight","digest","runtime-stage","output"):
        pack.add_argument("--"+name,required=True)
    bind=modes.add_parser("bind")
    for name in ("staging","seed","kernel","config","baseline","output","nonce","media-digest"):
        bind.add_argument("--"+name,required=True)
    run=modes.add_parser("run")
    run.add_argument("--authority",required=True)
    run.add_argument("--authority-sha256",required=True)
    args=vars(parser.parse_args())
    mode=args.pop("mode")
    if mode!="run":
        sys.addaudithook(C.passive_fence)
        value=prepare(**args) if mode=="prepare-transport" else binding(**args)[0]
        print(T.encoded(value).decode(),end="")
        return 0
    path=C.absolute(args["authority"])
    raw=T.read(path,cap=128*1024)
    value=T.decode(raw)
    expected=args["authority_sha256"]
    T.need(T.pin(raw)["sha256"]==expected and T.encoded(value)==raw and value["kind"]==KIND
           and value["issuer"]=="Root" and value["approval_status"]=="UNAPPROVED",
           "Exact independently issued Root development-guest authority required")
    report=Controller(value).run_asahi(path,expected)
    print(T.encoded(report).decode(),end="")
    return int(report["status"]!=G.PASS)


if __name__=="__main__":
    raise SystemExit(main())
