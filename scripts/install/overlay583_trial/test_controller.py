# SPDX-License-Identifier: MIT
"""Source and inert fixtures for the offline Overlay583 controller."""

import base64
import importlib.util
import io
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def fence(event,_args):
    if event.startswith(("subprocess.","socket.","ctypes.")) or event in (
        "os.system","os.exec","os.fork","os.forkpty","os.posix_spawn",
    ):
        raise AssertionError("Fixture cannot start an actor")


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("overlay583_controller",HERE/"controller.py")
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
NONCE = "abc123ab"*4


def fake_reader(nodes, by_inode=None):
    class Disk:
        def __init__(self,_path,**_bounds):
            pass

        def __enter__(self):
            return self

        def __exit__(self,*_exc):
            pass

        def inventory(self):
            return {"nodes":nodes}

        def inode(self,number):
            return number,by_inode[number]

        def chunks(self,_fields,raw):
            yield raw

    return SimpleNamespace(Ext4Reader=Disk)


class ControllerTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="overlay583-model-")
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name)

    def test_qemu_uses_stable_partuuid_and_only_two_owned_writable_disks(self):
        argv = C.qemu_argv(self.output,NONCE,"abc123ab-01","a"*64,"b"*64)
        for flag,expected in (("-accel","tcg,thread=multi"),("-nic","none"),
                              ("-serial","stdio"),("-name","overlay583-"+NONCE)):
            self.assertEqual(argv[argv.index(flag)+1],expected)
        self.assertIn("root=PARTUUID=abc123ab-01",argv[argv.index("-append")+1])
        self.assertIn("rootflags=noload ro",argv[argv.index("-append")+1])
        self.assertNotIn("-enable-kvm",argv)
        self.assertNotIn("-daemonize",argv)
        drives = [argv[i+1] for i,value in enumerate(argv) if value=="-drive"]
        self.assertEqual([row.rsplit("=",1)[1] for row in drives],["on","on","off","off"])
        self.assertTrue(all(f"file={self.output}" in row and "format=raw" in row for row in drives))

    def test_genuine_mbr_layout_in_inert_small_fixture(self):
        source,dest = self.output/"fs",self.output/"disk"
        source.write_bytes(b"x"*512)
        with patch.dict(C.REFERENCES,baseline=(512,"unused")):
            self.assertEqual(C.partition_boot(source,dest,NONCE),"abc123ab-01")
        raw = dest.read_bytes()
        self.assertEqual(raw[510:512],b"\x55\xaa")
        self.assertEqual(struct.unpack_from("<I",raw,440),(0xABC123AB,))
        self.assertEqual(struct.unpack_from("<B3xB3xII",raw,446),(0,0x83,2048,1))
        self.assertEqual(raw[1<<20:],source.read_bytes())

    def test_terminal_rejects_stale_duplicate_or_hold(self):
        good = f"OVERLAY583 {NONCE} PASS 16384".encode()
        C.serial_pass(b"kernel log\r\n"+good+b"\r\n",NONCE)
        for raw in (good+b"\n"+good,good.replace(b"PASS",b"HOLD"),
                    good.replace(b"16384",b"4096"),good.replace(NONCE.encode(),b"f"*32)):
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                C.serial_pass(raw,NONCE)

    def test_archive_copy_preserves_epoch_names_and_rejects_wrong_pin(self):
        src = self.output/"firmware-1:2-3-any.pkg.tar.xz"
        src.write_bytes(b"model archive")
        out = self.output/"inputs"/src.name
        C.checked_copy(src,out,C.T.pin(b"model archive"))
        self.assertEqual(out.read_bytes(),b"model archive")
        self.assertEqual(out.stat().st_mode&0o777,0o444)
        with self.assertRaises(ValueError):
            C.checked_copy(src,self.output/"wrong",C.T.pin(b"alien archive"))

    def test_runtime_pack_uses_bounded_subset_and_exact_alias(self):
        paths = ("python.tar.xz","mpdecimal.tar.xz")
        items = [
            [("usr/bin/python3.14",b"ELF model"),("usr/lib/python3.14/os.py",b"stdlib model"),
             ("usr/lib/libpython3.14.so.1.0",b"library model"),("etc/unselected",b"exclude")],
            [("usr/lib/libmpdec.so.4.0.1",b"decimal model"),("usr/lib/libmpdec.so.4","libmpdec.so.4.0.1")],
        ]
        for name,members in zip(paths,items):
            with tarfile.open(self.output/name,"w:xz") as arc:
                for filename,contents in members:
                    row = tarfile.TarInfo(filename)
                    if isinstance(contents,str):
                        row.type,row.linkname = tarfile.SYMTYPE,contents
                        arc.addfile(row)
                    else:
                        row.size = len(contents)
                        row.mode = 0o755
                        arc.addfile(row,io.BytesIO(contents))
        with patch.object(C,"RUNTIME_PACKAGES",paths):
            result = C.runtime_payload(self.output,self.output/"runtime")
        self.assertEqual(len(result),5)
        self.assertEqual(os.readlink(self.output/"runtime/usr/lib/libmpdec.so.4"),"libmpdec.so.4.0.1")
        self.assertFalse((self.output/"runtime/etc").exists())

    def test_input_disk_rejects_changed_alias_and_leftover_file(self):
        wanted = C.T.pin(b"model")
        files,aliases,dirs = {"repo/model":wanted},{"repo/model-alias":"model"},{"repo"}
        nodes = {name:{"type":"directory"} for name in (".","lost+found","repo")}
        nodes["repo/model"] = dict(type="file",links=1,size=wanted["bytes"],sha256=wanted["sha256"])
        nodes["repo/model-alias"] = dict(type="symlink",links=1,target_b64=base64.b64encode(b"model"))
        C.verify_input(fake_reader(nodes),None,(files,aliases,dirs))
        nodes["repo/model-alias"]["target_b64"] = base64.b64encode(b"../foreign")
        with self.assertRaisesRegex(ValueError,"alias differs"):
            C.verify_input(fake_reader(nodes),None,(files,aliases,dirs))
        nodes["extra"] = dict(type="file")
        with self.assertRaisesRegex(ValueError,"namespace"):
            C.verify_input(fake_reader(nodes),None,(files,aliases,dirs))

    def test_exact_result_export_and_inode_identity(self):
        plan = {"operations":[]}
        nodes = {name:{"type":"directory"} for name in (".","lost+found","evidence")}
        by_inode = {}
        for inode,basename in enumerate(sorted(C.T.evidence_names(plan)),3):
            body = basename.encode()
            by_inode[inode] = body
            nodes["evidence/"+basename] = dict(inode=inode,type="file",uid=0,gid=0,mode=0o600,
                                              links=1,size=len(body),sha256=C.T.pin(body)["sha256"])
        C.export_result(fake_reader(nodes,by_inode),None,self.output/"export",plan)
        self.assertEqual({p.name for p in (self.output/"export").iterdir()},C.T.evidence_names(plan))
        nodes["evidence/installed.lock"]["links"] = 2
        with self.assertRaisesRegex(ValueError,"file identity"):
            C.export_result(fake_reader(nodes,by_inode),None,self.output/"bad",plan)
        nodes["evidence/unexpected"] = dict(type="file")
        with self.assertRaisesRegex(ValueError,"namespace"):
            C.export_result(fake_reader(nodes,by_inode),None,self.output/"extra",plan)

    def test_binding_needs_explicit_external_digest_and_issuer(self):
        path = self.output/"authority.json"
        for issuer in (None,"Root"):
            raw = C.T.encoded(dict(kind=C.KIND,issuer=issuer))
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                C.load_authority(path,"0"*64)
            if issuer is None:
                with self.assertRaises(ValueError):
                    C.load_authority(path,C.T.pin(raw)["sha256"])
            else:
                self.assertEqual(C.load_authority(path,C.T.pin(raw)["sha256"])["issuer"],"Root")


if __name__=="__main__":
    unittest.main()
