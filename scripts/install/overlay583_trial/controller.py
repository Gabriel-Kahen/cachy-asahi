# SPDX-License-Identifier: MIT
"""Root-issued offline QEMU TCG controller for the exact Overlay583 trial."""

import argparse
import base64
from hashlib import sha256
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import tarfile
import time
from uuid import UUID

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PERL = REPO/"scripts/integration/arm16k_perl5423_vm"
BOOT = "overlay583-init"
INPUT_SIZE, WORK_SIZE, RESULT_SIZE = 2<<30, 16<<30, 64<<20
RESERVE = 2<<30
PHASE_BUDGET = 1200
ACTOR_IMAGE = "sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a"
KIND = "ROOT_OVERLAY583_QEMU_TCG_SELECTION_V1"
TOOL_PATHS = tuple("/usr/bin/"+name for name in ("cp","debugfs","e2fsck","mke2fs","qemu-system-aarch64"))
PROVEN_TOOLS = {
    "/usr/bin/cp": (129336,"3a597f7c21f2922e97bc1607f111ee15d2ed71998570d8a152d1e40aedfa2035"),
    "/usr/bin/debugfs": (202328,"9b27184084383c8607eee03b43c80eca4ef912acf4887b40a7cc420e267ad8a8"),
    "/usr/bin/e2fsck": (356568,"a9ea133a844edd695b5172abadc8bbbbb03aaedad80fc24d039bdbf4563a125c"),
    "/usr/bin/qemu-system-aarch64": (34622584,"6f16cea44da813a65a1076886f63687350a0173e188873ba227dcc06f5c16b27"),
}
REFERENCES = {
    "kernel": (9019400,"36066ded2f5721fd9bb257cebb2e4cb32084f45c3717f4d7a45430fe3cdcc494"),
    "config": (71585,"b8bc8c636ae7e58e8e338e7dba87d84a390d0555fa7307fc76217e0d56553d7f"),
    "baseline": (1610612736,"f30fa96283042b12229b455fe33918facb83a0650a8e7849fcaab493dda366cb"),
}
RUNTIME_PACKAGES = (
    "base-repository/repo/python-3.14.8-1-aarch64.pkg.tar.xz",
    "base-repository/repo/mpdecimal-4.0.1-3-aarch64.pkg.tar.xz",
)
MOUNTPOINTS = ("trial-media","trial-inputs","trial-code","trial-scratch","trial-work","trial-export")


def module(path):
    spec = importlib.util.spec_from_file_location("overlay583_"+path.stem,path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


T = module(HERE/"trial.py")


def pinned(path, ref, *, allowed_links=(1,)):
    size,digest = ref
    return T.read(path,dict(bytes=size,sha256=digest),cap=size,collect=False,allowed_links=allowed_links)


def source_pins(*, upgrade=False, first_login=False, llhttp=False):
    paths = [HERE/name for name in ("controller.py","trial.py","guest-init.sh","staging-pins.json")]
    paths += [PERL/name for name in ("runtime.py","contracts.py","helper-origin.json",
                                    "frozen/independent_readback.py","frozen/owned_process.py")]
    if upgrade:
        paths.append(T.upgrade_path())
    if first_login:
        paths.extend(T.first_login_sources().values())
    if llhttp:
        paths.extend(T.llhttp_sources().values())
    return {str(path.relative_to(REPO)):T.read(path,cap=128<<10,collect=False) for path in paths}


def absolute(path):
    path = T.ordinary(path)
    T.need(re.fullmatch(r"/[A-Za-z0-9_./+-]+",str(path)), "Literal local path required")
    return path


def binding(*, staging, preflight, kernel, config, baseline, output, nonce, issuer=None, lifecycle=False,
            signature_recovery=False, predecessor=None, predecessor_sha256=None,
            first_login=None, first_login_sha256=None, llhttp=None, llhttp_sha256=None):
    paths = {key:absolute(value) for key,value in
             dict(staging=staging,preflight=preflight,kernel=kernel,config=config,baseline=baseline,output=output).items()}
    T.need((predecessor is None)==(predecessor_sha256 is None),"Predecessor path and external receipt digest required together")
    T.need((first_login is None)==(first_login_sha256 is None),"First-login path and external receipt digest required together")
    T.need((llhttp is None)==(llhttp_sha256 is None),"llhttp path and external receipt digest required together")
    T.need(not ((first_login is not None or llhttp is not None) and
                (lifecycle or signature_recovery or predecessor is not None))
           and (first_login is None or llhttp is None), "Choose only one Overlay583 operation")
    lib=None
    if llhttp is not None:
        paths["llhttp"]=absolute(llhttp)
        lib=T.llhttp_selection(paths["llhttp"],llhttp_sha256)
        T.need(lib["rehearsal"]["expires"]-time.time()>T.TIMEOUT,"llhttp TEST key must cover the guest budget")
    supplement = None
    if first_login is not None:
        paths["first_login"] = absolute(first_login)
        supplement = T.first_login_selection(paths["first_login"],first_login_sha256)
        T.need(supplement["rehearsal"]["expires"]-time.time()>T.TIMEOUT,
               "First-login TEST key must remain current through the guest budget")
    predecessor_pin = None
    if predecessor is not None:
        T.need(not lifecycle and not signature_recovery,"Choose only one Overlay583 operation")
        paths["predecessor"] = absolute(predecessor)
        upgrade = T.upgrade_module()
        predecessor_pin = upgrade.digest_pin(paths["predecessor"]/upgrade.RECEIPT,predecessor_sha256)
    for key,path in paths.items():
        if key!="output":
            T.need(path!=paths["output"] and not path.is_relative_to(paths["output"])
                   and not paths["output"].is_relative_to(path), "Output and selected inputs must be disjoint")
    for key,ref in REFERENCES.items():
        pinned(paths[key],ref)
    packet = T.choose(paths["staging"],selected_lock=T.PINS)
    receipt = T.read(paths["preflight"],packet["authenticated_preflight"],cap=128<<10)
    plan = T.selected_plan(T.admit(packet,receipt,T.pin(receipt)),nonce,lifecycle=lifecycle,
                           signature_recovery=signature_recovery,predecessor=paths.get("predecessor"),
                           predecessor_pin=predecessor_pin,first_login=supplement,llhttp=lib)
    authority = dict(kind=KIND,issuer=issuer,nonce=nonce,actor_image=ACTOR_IMAGE,
                paths={key:str(path) for key,path in paths.items()},
                preflight=packet["authenticated_preflight"], plan=T.pin(T.encoded(plan)),
                references={key:dict(bytes=value[0],sha256=value[1]) for key,value in REFERENCES.items()},
                tools=tool_pins(), source=source_pins(upgrade=predecessor_pin is not None,first_login=supplement is not None,llhttp=lib is not None))
    if supplement is not None:
        authority["first_login"] = supplement["receipt"]
    if lib is not None:
        authority["llhttp"]=lib["receipt"]
    if predecessor_pin is not None:
        authority["predecessor"] = predecessor_pin
    if lifecycle or signature_recovery:
        authority["lifecycle"] = True
    if signature_recovery:
        authority["signature_recovery"] = True
    return authority


def tool_pins():
    pins = {}
    for name in TOOL_PATHS:
        path = T.ordinary(name)
        info = path.lstat()
        links = (1,4) if path.name in ("e2fsck","mke2fs") else (1,)
        T.need(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o755
               and 0<info.st_size<=64<<20, "Expected root-owned reviewed image tool "+name)
        if name in PROVEN_TOOLS:
            pins[name] = pinned(path,PROVEN_TOOLS[name],allowed_links=links)
        else:
            pins[name] = T.read(path,cap=64<<20,collect=False,allowed_links=links)
    return pins


def checked_copy(source, target, expected):
    source = T.ordinary(source)
    target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    fd = os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    digest = sha256()
    with os.fdopen(fd,"rb") as src, target.open("xb") as dst:
        before = os.fstat(src.fileno())
        size = expected["bytes"]
        T.need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==size,
               "Incorrect copy source identity")
        remaining = size
        while remaining:
            block = src.read(min(remaining,1<<20))
            T.need(block,"Short copy")
            dst.write(block)
            digest.update(block)
            remaining -= len(block)
        T.need(not src.read(1) and digest.hexdigest()==expected["sha256"]
               and T.identity(before)==T.identity(os.fstat(src.fileno()))==T.identity(source.lstat()),
               "Selected bytes changed during copy")
    target.chmod(0o444)


def runtime_payload(inputs, runtime):
    """Stage only the selected Python interpreter, stdlib and mpdecimal library."""
    size = 0
    nodes = {}
    pattern = (r"usr/bin/python3\.14|usr/lib/(?:libpython3\.14\.so\.1\.0|libmpdec\.so\.(?:4|4\.0\.1)"
               r"|python3\.14(?:/[A-Za-z0-9_+.@/-]+)?)")
    for name in RUNTIME_PACKAGES:
        with tarfile.open(inputs/name,"r|xz") as archive:
            for row in archive:
                path = row.name
                if not re.fullmatch(pattern,path):
                    continue
                T.need(all(part not in ("",".","..") for part in path.split("/"))
                       and path not in nodes and len(nodes)<4096,"Invalid or excessive runtime member")
                dst = runtime/path
                for parent in dst.parents:
                    if parent==runtime:
                        break
                    T.need(not parent.is_symlink(),"Runtime ancestor must be an ordinary directory")
                dst.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
                if row.isdir():
                    dst.mkdir(mode=0o755,exist_ok=True)
                    nodes[path] = None
                elif row.issym():
                    T.need(path=="usr/lib/libmpdec.so.4" and row.linkname=="libmpdec.so.4.0.1",
                           "Unexpected runtime alias")
                    dst.symlink_to(row.linkname)
                    nodes[path] = row.linkname
                else:
                    size += row.size
                    T.need(row.isfile() and 0<=row.size<=16<<20 and size<=128<<20,
                           "Ordinary bounded runtime file required")
                    with archive.extractfile(row) as src:
                        raw = src.read(row.size+1)
                    T.need(len(raw)==row.size,"Short runtime file")
                    with dst.open("xb") as stream:
                        stream.write(raw)
                    dst.chmod(0o555 if row.mode&0o111 else 0o444)
                    nodes[path] = T.pin(raw)
    T.need({"usr/bin/python3.14","usr/lib/libpython3.14.so.1.0","usr/lib/python3.14/os.py",
            "usr/lib/libmpdec.so.4","usr/lib/libmpdec.so.4.0.1"} <= nodes.keys(),
           "Incomplete selected Python runtime")
    return nodes


def input_tree(staging, worker, worker_pin, plan, packed, *, predecessor=None, first_login=None, llhttp=None):
    inputs, code = packed/"inputs",packed/"code"
    selected = T.decode(plan)
    packet = selected["packet"]
    files = {}
    operands = packet["files"] | packet["trust"] | {"target.lock":packet["target"]}
    if selected.get("lifecycle"):
        operands[T.BASE_INVENTORY] = packet["baseline"]
    for name,wanted in operands.items():
        checked_copy(staging/name,inputs/name,wanted)
        files["inputs/"+name] = wanted
    if selected.get("kind")==T.UPGRADE_KIND:
        upgrade = T.upgrade_module(selected["upgrade_worker"])
        T.need(predecessor is not None and upgrade.check_stage(predecessor,selected["predecessor"]["receipt"])==selected["predecessor"],
               "Exact independently selected predecessor staging required")
        prefix = "inputs/"+upgrade.PREDECESSOR+"/"
        previous = selected["predecessor"]
        previous_files = dict(previous["files"], **{upgrade.RECEIPT:previous["receipt"]})
        for name,wanted in previous_files.items():
            checked_copy(predecessor/name,packed/(prefix+name),wanted)
            files[prefix+name] = wanted
        checked_copy(T.upgrade_path(),code/"upgrade.py",selected["upgrade_worker"])
        files["code/upgrade.py"] = selected["upgrade_worker"]
    mode=T.ADDON_MODES.get(selected.get("kind"))
    if mode is not None:
        key=mode[0]
        supplement=selected[key]
        path,validator=(llhttp,T.llhttp_selection) if key=="llhttp" else (first_login,T.first_login_selection)
        T.need(path is not None and validator(path,supplement["receipt"]["sha256"])==supplement,
               "Exact issued addon media required")
        prefix=key.replace("_","-")
        for name,wanted in dict(supplement["files"],**{"supplement.json":supplement["receipt"]}).items():
            checked_copy(path/name,code/prefix/name,wanted)
            files["code/"+prefix+"/"+name]=wanted
    aliases = {"inputs/"+name:target for name,target in packet["aliases"].items()}
    for name,target in aliases.items():
        (packed/name).symlink_to(target)
    checked_copy(worker,code/"trial.py",worker_pin)
    (code/"plan.json").write_bytes(plan)
    files.update({"code/trial.py":worker_pin,"code/plan.json":T.pin(plan)})
    for name,ref in runtime_payload(inputs,packed/"runtime").items():
        if isinstance(ref,dict):
            files["runtime/"+name] = ref
        elif isinstance(ref,str):
            aliases["runtime/"+name] = ref
    dirs = {str(p.relative_to(packed)) for p in packed.rglob("*") if not p.is_symlink() and p.is_dir()}
    return files,aliases,dirs


def verify_input(reader, path, manifest):
    files,aliases,dirs = manifest
    with reader.Ext4Reader(path,max_nodes=6000,max_file_bytes=T.MAX_MEMBER) as disk:
        nodes = disk.inventory()["nodes"]
    T.need(set(nodes)==set(files)|set(aliases)|dirs|{".","lost+found"}, "Non-exact input disk namespace")
    for name,wanted in files.items():
        row = nodes[name]
        T.need(row["type"]=="file" and row["links"]==1
               and dict(bytes=row["size"],sha256=row["sha256"])==wanted,"Input disk file differs: "+name)
    for name,target in aliases.items():
        row = nodes[name]
        T.need(row["type"]=="symlink" and row["links"]==1
               and base64.b64decode(row["target_b64"],validate=True)==target.encode(),"Input disk alias differs")
    T.need(all(nodes[name]["type"]=="directory" for name in dirs|{".","lost+found"}),
           "Input disk directory differs")


def partition_boot(source, dest, nonce):
    """Add a one-partition virtual disk envelope around the unmodified ext4 bytes."""
    signature = int(nonce[:8],16) or 1
    start, size = 2048, source.stat().st_size
    T.need(size==REFERENCES["baseline"][0] and size%512==0,"Fixed r118 boot ext4 geometry")
    mbr = bytearray(512)
    struct.pack_into("<I",mbr,440,signature)
    struct.pack_into("<B3xB3xII",mbr,446,0,0x83,start,size//512)
    mbr[510:] = b"\x55\xaa"
    with source.open("rb") as src, dest.open("xb") as dst:
        dst.write(mbr)
        dst.seek(start*512)
        while block := src.read(1<<20):
            if block.count(0)==len(block):
                dst.seek(len(block),os.SEEK_CUR)
            else:
                dst.write(block)
        dst.truncate(start*512+size)
    dest.chmod(0o444)
    return f"{signature:08x}-01"


def qemu_argv(out, nonce, partuuid, plan_sha, worker_sha):
    T.need(re.fullmatch("[0-9a-f]{32}",nonce) and re.fullmatch("[0-9a-f]{8}-01",partuuid)
           and T.HEX.fullmatch(plan_sha) and T.HEX.fullmatch(worker_sha),"Exact guest boot binding")
    append = (f"root=PARTUUID={partuuid} rootfstype=ext4 rootflags=noload ro rootwait "
              f"console=ttyAMA0,115200n8 init=/{BOOT} cachy_overlay583_nonce={nonce} "
              f"cachy_overlay583_plan={plan_sha} cachy_overlay583_worker={worker_sha}")
    argv = [TOOL_PATHS[-1],"-machine","virt","-accel","tcg,thread=multi","-rtc","base=utc,clock=host",
            "-cpu","max","-smp","4","-m","4096","-nodefaults","-no-user-config","-display","none",
            "-monitor","none","-nic","none","-no-reboot","-kernel",str(out/"Image"),"-append",append,
            "-serial","stdio","-name","overlay583-"+nonce,
            "-sandbox","on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]
    for disk,mode in (("boot","on"),("inputs","on"),("scratch","off"),("result","off")):
        argv += ["-drive",f"if=none,id={disk},file={out/disk}.raw,format=raw,readonly={mode}",
                 "-device",f"virtio-blk-device,drive={disk}"]
    return argv


def serial_pass(data, nonce, *, lifecycle=False):
    rows = [line for line in data.splitlines() if line.startswith(b"OVERLAY583 ")]
    if lifecycle and rows==[f"OVERLAY583 {nonce} HOLD lifecycle".encode()]:
        return False
    T.need(rows==[f"OVERLAY583 {nonce} PASS 16384".encode()],"Missing, repeated or failed guest terminal receipt")
    return True


def export_result(reader, disk_path, output, plan, *, held=False):
    expected = {"evidence/"+name for name in T.evidence_names(plan)}
    with reader.Ext4Reader(disk_path,max_nodes=64,max_file_bytes=8<<20) as disk:
        nodes = disk.inventory()["nodes"]
        files = set(nodes)-{".","lost+found","evidence"}
        correct_files = ("evidence/result.json" in files and files<=expected
                         if held and (plan.get("lifecycle") or plan.get("kind") in T.HOLD_KINDS)
                         else not held and files==expected)
        T.need(correct_files and {".","lost+found","evidence"}<=set(nodes)
               and all(nodes[name]["type"]=="directory" for name in (".","lost+found","evidence")),
               "Result disk evidence namespace differs")
        T.need(sum(nodes[name]["size"] for name in files)<=32<<20,"Result disk byte budget exceeded")
        output.mkdir(mode=0o700)
        for name in sorted(files):
            row = nodes[name]
            T.need(row["type"]=="file" and row["uid"]==row["gid"]==0 and row["mode"]==0o600
                   and row["links"]==1,"Result disk file identity differs")
            fields,raw = disk.inode(row["inode"])
            data = b"".join(disk.chunks(fields,raw))
            T.need(T.pin(data)==dict(bytes=row["size"],sha256=row["sha256"]),"Result disk reread changed")
            with (output/Path(name).name).open("xb") as stream:
                stream.write(data)


def require_absence(nonce):
    """Independent own-UID command-line census, in addition to the raw wait owner."""
    token = ("overlay583-"+nonce).encode()
    for _ in range(2):
        deadline = time.monotonic()+3
        with os.scandir("/proc") as entries:
            for count,entry in enumerate(entries,1):
                T.need(count<=131072 and time.monotonic()<deadline,"VM absence census exhausted")
                if not entry.name.isdecimal():
                    continue
                path = Path(entry.path)
                try:
                    if path.stat().st_uid!=os.getuid():
                        continue
                    with (path/"cmdline").open("rb") as stream:
                        args = stream.read(131073)
                except (FileNotFoundError,ProcessLookupError):
                    continue
                T.need(len(args)<=131072 and token not in args.split(b"\0"),"Possible surviving owned VM")
        time.sleep(.02)


def actor_boundary(paths):
    """Check the confinement supplied by the Root-owned outer role."""
    T.need(os.environ.get("CACHY_ASAHI_OVERLAY583_ACTOR")=="1" and Path("/.dockerenv").is_file(),
           "Explicit disposable actor entry required")
    status = dict(line.split(":",1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    T.need(all(int(status[key],16)==0 for key in ("CapEff","CapPrm","CapInh","CapAmb","CapBnd"))
           and status["NoNewPrivs"].strip()=="1" and not Path("/dev/kvm").exists()
           and {p.name for p in Path("/sys/class/net").iterdir()}<={"lo"},
           "Cap-zero NNP offline software actor required")
    mounts = {}
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        mounts[Path(fields[4])] = set(fields[5].split(","))
    for path,mode in [(Path("/"),"ro"),(REPO,"ro"),
                      *((path,"rw" if key=="output" else "ro") for key,path in paths.items())]:
        owner = next(parent for parent in (path,*path.parents) if parent in mounts)
        T.need(mode in mounts[owner],"Actor mount flags differ: "+str(path))


class Controller:
    API = T.OwnedVMAdapter.API

    def __init__(self, authority):
        self.authority = authority
        self.paths = {key:absolute(path) for key,path in authority["paths"].items()}
        self.out = self.paths["output"]
        self.ready = False

    def authenticate(self, selection, *, plan_sha256, worker, nonce):
        actor_boundary(self.paths)
        actual = binding(**self.paths,nonce=nonce,issuer="Root",lifecycle=self.authority.get("lifecycle") is True,
                         signature_recovery=self.authority.get("signature_recovery") is True,
                         predecessor_sha256=self.authority.get("predecessor",{}).get("sha256"),
                         first_login_sha256=self.authority.get("first_login",{}).get("sha256"),
                         llhttp_sha256=self.authority.get("llhttp",{}).get("sha256"))
        T.need(self.authority==selection==actual and actual["plan"]["sha256"]==plan_sha256
               and actual["source"]["scripts/install/overlay583_trial/trial.py"]==worker,
               "Root authority, reviewed operands or trial binding differ")
        T.need(not self.out.exists() and shutil.disk_usage(self.out.parent).free>=WORK_SIZE+INPUT_SIZE+2*REFERENCES["baseline"][0]+RESERVE,
               "Fresh private output and fixed VM disk headroom required")
        self.out.mkdir(mode=0o700)
        self.runtime = module(PERL/"runtime.py")
        self.reader = module(PERL/"frozen/independent_readback.py")
        self.ready = True

    def command(self, label, name, args, seconds, deadline):
        return self.runtime.command(["/usr/bin/"+name,*map(str,args)],self.out,label,
                                    seconds=seconds,deadline=deadline,
                                    watched_tree=(self.out,24<<30,RESERVE))

    def filesystem(self, name, label, size, nonce, deadline, tree=None):
        path = self.out/(name+".raw")
        with path.open("xb") as stream:
            stream.truncate(size)
        disk_uuid = UUID(bytes=sha256((nonce+":"+label).encode()).digest()[:16])
        args = ["-t","ext4","-F","-b","4096","-m","0","-O","^orphan_file",
                "-E","lazy_itable_init=0,lazy_journal_init=0","-U",disk_uuid,"-L",label]
        if tree is not None:
            args += ["-d",tree]
        self.command("make-"+name,"mke2fs",[*args,path],180,deadline)
        self.command("fsck-"+name,"e2fsck",["-fn",path],120,deadline)
        T.need(path.stat().st_size==size,"VM image geometry differs")
        return path

    def run_guest(self, *, staging,worker,worker_pin,plan,kernel_argument,argv,timeout):
        T.need(self.ready and staging==self.paths["staging"] and timeout==T.TIMEOUT,
               "Root-authenticated controller required")
        self.ready = False
        nonce = self.authority["nonce"]
        plan_pin = T.pin(plan)
        T.need(plan_pin==self.authority["plan"] and kernel_argument=="cachy_overlay583_nonce="+nonce
               and argv==["/usr/bin/python3","-I","-B","/trial-code/trial.py","guest",
                         plan_pin["sha256"],worker_pin["sha256"]],"Unexpected worker command")
        out,deadline = self.out,time.monotonic()+PHASE_BUDGET
        checked_copy(self.paths["kernel"],out/"Image",self.authority["references"]["kernel"])
        stock, clone = self.paths["baseline"],out/"reference.raw"
        self.command("clone-reference","cp",["--sparse=always","--reflink=never",stock,clone],180,deadline)
        pinned(clone,REFERENCES["baseline"])
        init,edits = HERE/"guest-init.sh",out/"boot.debugfs"
        edits.write_text("".join(f"mkdir /{name}\n" for name in MOUNTPOINTS)
                         +f"write {init} /{BOOT}\nset_inode_field /{BOOT} mode 0100755\n"
                         +f"set_inode_field /{BOOT} uid 0\nset_inode_field /{BOOT} gid 0\n")
        self.command("prepare-reference","debugfs",["-w","-f",edits,clone],90,deadline)
        self.command("fsck-reference","e2fsck",["-fn",clone],120,deadline)
        dump = out/"init.readback"
        self.command("read-reference-init","debugfs",["-R",f"dump /{BOOT} {dump}",clone],30,deadline)
        T.read(dump,self.authority["source"]["scripts/install/overlay583_trial/guest-init.sh"],cap=128<<10)
        partuuid = partition_boot(clone,out/"boot.raw",nonce)
        clone.unlink()

        packed = out/"input-tree"
        manifest = input_tree(staging,worker,worker_pin,plan,packed,predecessor=self.paths.get("predecessor"),
                              first_login=self.paths.get("first_login"),llhttp=self.paths.get("llhttp"))
        inputs = self.filesystem("inputs","OV583_INPUT",INPUT_SIZE,nonce,deadline,packed)
        verify_input(self.reader,inputs,manifest)
        shutil.rmtree(packed)
        inputs.chmod(0o444)
        self.filesystem("scratch","OV583_WORK",WORK_SIZE,nonce,deadline)
        result = self.filesystem("result","OV583_RESULT",RESULT_SIZE,nonce,deadline)
        before = {name:T.read(out/name,cap=INPUT_SIZE,collect=False) for name in ("Image","boot.raw","inputs.raw")}
        command = qemu_argv(out,nonce,partuuid,plan_pin["sha256"],worker_pin["sha256"])
        self.runtime.command(command,out,"qemu",seconds=timeout,deadline=time.monotonic()+timeout,
                             watched_tree=(out,24<<30,RESERVE))
        observation = self.runtime.receipt(out/"qemu.json")
        T.need(self.runtime.natural(observation) and observation["argv"]==command,"Natural owned QEMU exit required")
        self.require_absent_twice(nonce)
        selected_plan = T.decode(plan)
        held = not serial_pass(T.read(out/"qemu.stdout",cap=1<<20),nonce,
                               lifecycle=selected_plan.get("lifecycle") is True
                               or selected_plan.get("kind") in T.HOLD_KINDS)
        for name,ref in before.items():
            T.read(out/name,ref,cap=INPUT_SIZE,collect=False)
        pinned(stock,REFERENCES["baseline"])
        T.need(source_pins(upgrade="predecessor" in self.authority,first_login="first_login" in self.authority,
                           llhttp="llhttp" in self.authority)==self.authority["source"]
               and tool_pins()==self.authority["tools"],
               "Reviewed source or tool bytes changed during the trial")
        self.command("fsck-result-readback","e2fsck",["-fn",result],60,time.monotonic()+70)
        evidence = out/"evidence"
        export_result(self.reader,result,evidence,selected_plan,held=held)
        return dict(exit=0,natural=True,reaped=True,output_complete=True,evidence=evidence,held=held)

    def require_absent_twice(self, nonce):
        T.need(nonce==self.authority["nonce"],"Unmatched retirement observation")
        require_absence(nonce)


def load_authority(path, digest):
    raw = T.read(absolute(path),cap=128<<10)
    value = T.decode(raw)
    T.need(T.pin(raw)["sha256"]==digest and value.get("kind")==KIND and value.get("issuer")=="Root",
           "Exact externally issued Root authority required")
    return value


def passive_fence(event,_args):
    T.need(not event.startswith(("subprocess.","socket.","ctypes."))
           and event not in ("os.system","os.exec","os.fork","os.forkpty","os.posix_spawn"),
           "Passive binding cannot launch an actor")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode",required=True)
    bind = sub.add_parser("bind")
    for key in ("staging","preflight","kernel","config","baseline","output","nonce"):
        bind.add_argument("--"+key,required=True)
    bind.add_argument("--lifecycle",action="store_true")
    bind.add_argument("--signature-recovery",action="store_true")
    bind.add_argument("--predecessor")
    bind.add_argument("--predecessor-sha256")
    bind.add_argument("--first-login")
    bind.add_argument("--first-login-sha256")
    bind.add_argument("--llhttp")
    bind.add_argument("--llhttp-sha256")
    run = sub.add_parser("run")
    run.add_argument("--authority",required=True)
    run.add_argument("--authority-sha256",required=True)
    args = vars(parser.parse_args())
    if args.pop("mode")=="bind":
        import sys
        sys.addaudithook(passive_fence)
        print(T.encoded(binding(**args)).decode(),end="")
        return
    authority = load_authority(args["authority"],args["authority_sha256"])
    actor = Controller(authority)
    value = T.run_owned(actor,staging=actor.paths["staging"],preflight=actor.paths["preflight"],
                        preflight_pin=authority["preflight"],nonce=authority["nonce"],selection=authority,
                        lifecycle=authority.get("lifecycle") is True,
                        signature_recovery=authority.get("signature_recovery") is True,
                        predecessor=actor.paths.get("predecessor"),predecessor_pin=authority.get("predecessor"),
                        first_login=actor.paths.get("first_login"),first_login_pin=authority.get("first_login"),
                        llhttp=actor.paths.get("llhttp"),llhttp_pin=authority.get("llhttp"))
    T.need(load_authority(args["authority"],args["authority_sha256"])==authority,
           "Root authority changed during the trial")
    value.update(emulation="QEMU_TCG_AARCH64_16K",nonce=authority["nonce"],
                 authority_sha256=args["authority_sha256"],
                 qemu_receipt=T.read(actor.out/"qemu.json",cap=128<<10,collect=False),
                 serial=T.read(actor.out/"qemu.stdout",cap=1<<20,collect=False),
                 result_disk=T.read(actor.out/"result.raw",cap=RESULT_SIZE,collect=False))
    held = value["status"] in (T.LIFECYCLE_HOLD,T.UPGRADE_HOLD,T.FIRST_LOGIN_HOLD,T.LLHTTP_HOLD)
    if not held:
        (actor.out/"scratch.raw").unlink()
    with (actor.out/"report.json").open("xb") as stream:
        stream.write(T.encoded(value))
    print(T.encoded(value).decode(),end="")
    return 1 if held else 0


if __name__=="__main__":
    raise SystemExit(main())
