# SPDX-License-Identifier: MIT
"""Fence every Asahi rehearsal command and verify the actual held input projection."""

from copy import deepcopy
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("asahi_trial",HERE/"controller.py")
C=importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
T,O,G=C.T,C.O,C.G
HELD_ENV=("CAA_ASAHI_MAINTENANCE_PREFLIGHT","CAA_ASAHI_MAINTENANCE_PREFLIGHT_SHA256","CAA_OVERLAY583_STAGING")
ORIGINAL=b"070701 original"
GENERATED=b"070701 generated"
WARNING=b"==> WARNING: architecture 'aarch64' not supported, skipping hook"
HOOK=b"\n".join((*G.MKINITCPIO[:2],WARNING,*G.MKINITCPIO[2:]))+b"\n"


def fence(event,_):
    if event.startswith(("subprocess.","socket.","ctypes.","os.exec","os.fork","os.posix_spawn","os.system")):
        raise AssertionError("Actual subprocess, socket and VM forbidden in fixtures")


def setUpModule():
    sys.addaudithook(fence)


class LocalControls(unittest.TestCase):
    def test_generic_pid1_projection_keeps_immutable_control_boot_and_distinct_target(self):
        base=T.read(C.BASE/"guest-init.sh",cap=128*1024)
        body=C.init_bytes().decode()
        self.assertIn(f'blkid -c /dev/null -U {O.UUID}',body)
        self.assertIn('$(blockdev --getsize64 "$scratch") == 17179869184',body)
        self.assertIn('/usr/bin/e2fsck -fn "$scratch"\n/usr/bin/resize2fs "$scratch"',body)
        self.assertIn('tmpfs /trial-work',body)
        self.assertIn('root_mount_is_readonly',body)
        self.assertIn('/trial-code/asahi-guest.py',body)
        self.assertIn('umount -n /trial-export /trial-work /trial-scratch',body)
        self.assertIn('mount -n -t ext4 -o ro,noload,nosuid,nodev "$input"',body)
        self.assertNotIn('/trial-scratch/work',body)
        self.assertNotIn('OV583_WORK',body)
        self.assertIn('limit=8388608',body)
        self.assertIn('generated-initramfs-forward.img) limit=14680064',body)
        self.assertIn('[[ $total -le 33554432 ]]',body)
        with self.assertRaisesRegex(ValueError,"seam changed"):
            limits={name:G.INITRAMFS_LIMIT for name in G.GENERATED.values()}
            C.B.project(T,base.replace(b'-L OV583_WORK',b'-L wrong'),O.UUID,G.NAMES,limits)
    def test_only_hook_generated_candidate_is_retained_and_exact_original_restored(self):
        with tempfile.TemporaryDirectory() as temp, patch.multiple(
            G,INITRAMFS_OWNER=(os.getuid(),os.getgid()),INITRAMFS_PIN=T.pin(ORIGINAL)
        ):
            root=Path(temp)
            path=root/G.INITRAMFS
            path.parent.mkdir()
            path.write_bytes(ORIGINAL)
            path.chmod(0o600)
            original,origin,atime=G.initramfs(T,path,G.INITRAMFS_PIN)
            unrelated=root/"etc"
            unrelated.mkdir()
            unrelated=(unrelated/"fstab")
            unrelated.write_bytes(b"same")
            before=G.platform(T,root)
            rows={}
            path.write_bytes(GENERATED)
            with self.assertRaisesRegex(ValueError,"missing forward mkinitcpio"):
                G.preserve_initramfs(T,path,original,origin,atime,root,rows,"forward",b"other")
            with self.assertRaisesRegex(ValueError,"successful mkinitcpio output"):
                G.preserve_initramfs(T,path,original,origin,atime,root,rows,"forward",G.MKINITCPIO[0])
            G.preserve_initramfs(T,path,original,origin,atime,root,rows,"forward",HOOK)
            self.assertEqual(G.platform(T,root),before)
            self.assertEqual((root/G.GENERATED["forward"]).read_bytes(),GENERATED)
            self.assertEqual(rows["forward"]["restored"],origin)
            self.assertEqual(rows["forward"]["hook"]["warnings"],[WARNING.decode()])
            G.preserve_initramfs(T,path,original,origin,atime,root,rows,"rollback",b"ordinary rollback")
            self.assertIsNone(rows["rollback"]["generated"])
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError,"root-owned Asahi initramfs metadata"):
                G.preserve_initramfs(T,path,original,origin,atime,root,rows,"rollback",HOOK)

    def test_semantics_of_qemu_target_and_device_boundaries(self):
        with tempfile.TemporaryDirectory() as temp:
            argv=C.C.qemu_argv(Path(temp),"a"*32,"caffef00-01","b"*64,"c"*64)
        opts=[argv[index+1] for index,word in enumerate(argv) if word=="-drive"]
        self.assertEqual(len(opts),4)
        self.assertEqual([item.rsplit("=",1)[-1] for item in opts],["on","on","off","off"])
        self.assertTrue(all("/dev/" not in item and "format=raw" in item for item in opts))
        self.assertEqual(argv[argv.index("-nic")+1],"none")
        self.assertIn("rootflags=noload ro",argv[argv.index("-append")+1])

    def test_unissued_data_and_host_run_refuse_before_binding_or_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            receipt=root/"authority.json"
            for issuer,expected in ((None,"independently issued"),("Root","disposable actor entry")):
                paths={role:str(root/role) for role in ("staging","seed","kernel","config","baseline","output")}
                authority=dict(kind=C.KIND,issuer=issuer,approval_status="UNAPPROVED",paths=paths)
                raw=T.encoded(authority)
                receipt.write_bytes(raw)
                argv=["controller.py","run","--authority",str(receipt),"--authority-sha256",T.pin(raw)["sha256"]]
                with (
                    patch.object(sys,"argv",argv),
                    patch.dict(os.environ,{"CACHY_ASAHI_OVERLAY583_ACTOR":"0"}),
                    patch.object(C,"binding") as binding,
                    self.assertRaisesRegex(ValueError,expected),
                ):
                    C.main()
                binding.assert_not_called()

    def test_signature_checks_primary_and_detects_expiry(self):
        primary="A1"*20
        signing="B2"*20
        raw=(f"[GNUPG:] GOODSIG {signing[-16:]} Fixture\n"
             f"[GNUPG:] VALIDSIG {signing} 2026-11-18 1794973000 0 4 0 22 8 00 {primary}\n").encode()
        self.assertEqual(G.signature(T,raw,primary)["signing"],signing)
        with self.assertRaisesRegex(ValueError,"detached signature"):
            G.signature(T,raw,signing)
        with self.assertRaisesRegex(ValueError,"detached signature"):
            G.signature(T,raw.replace(b"GOODSIG",b"EXPKEYSIG"),primary)


    def test_transport_selection_pin_excludes_only_whole_preflight_provenance(self):
        manifest=dict(preflight=dict(bytes=50,sha256="a"*64),files={"archive":{"bytes":10,"sha256":"b"*64}})
        relocated=deepcopy(manifest)
        relocated["preflight"]=dict(bytes=51,sha256="c"*64)
        self.assertNotEqual(T.pin(T.encoded(relocated)),T.pin(T.encoded(manifest)))
        self.assertEqual(O.selection_pin(T,relocated),O.selection_pin(T,manifest))
        relocated["files"]["archive"]["sha256"]="d"*64
        self.assertNotEqual(O.selection_pin(T,relocated),O.selection_pin(T,manifest))


@unittest.skipUnless(any(os.environ.get(name) for name in HELD_ENV),"Supply the explicit retained Asahi DATA and runtime stage")
class HeldData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data,digest,cls.tools=[os.environ[name] for name in HELD_ENV]
        cls.data=Path(cls.data)
        cls.tools=Path(cls.tools)
        cls.raw=T.read(cls.data,cap=O.PLAN_LIMIT)
        cls.projection=dict(controller_source=C.C.source_pins(),actor_image=C.C.ACTOR_IMAGE,
                            boot={name:dict(bytes=size,sha256=sha) for name,(size,sha) in C.C.REFERENCES.items()})
        cls.selected,cls.sources=O.project(T,cls.raw,digest,cls.tools,**cls.projection)
        cls.rows=O.locks(T,cls.data.parent)

    def test_verified_original_passive_inputs_and_fixed_delta(self):
        self.assertEqual(self.selected["preflight"],T.pin(self.raw))
        self.assertEqual(O.selection_pin(T,self.selected),O.SELECTION)
        self.assertEqual(len(self.sources),753)
        self.assertEqual(sum(ref["bytes"] for ref in self.selected["files"].values()),653469760)
        O.check_delta(T,self.rows)
        foreign=dict(self.selected,approval_status="APPROVED")
        with self.assertRaisesRegex(ValueError,"No platform approval"):
            O.check_manifest(T,foreign)
        records={key:dict(value) for key,value in self.rows.items()}
        del records["rollback-preview.lock"]["perl"]
        with self.assertRaisesRegex(ValueError,"three inverse"):
            O.check_delta(T,records)

    def test_relocated_preflight_preserves_reviewed_contents(self):
        preflight=T.decode(self.raw)
        with tempfile.TemporaryDirectory() as temp:
            for key in ("expected_locks","expected_previews"):
                for pin in preflight[key].values():
                    original=Path(pin["path"])
                    copied=Path(temp)/original.name
                    copied.write_bytes(original.read_bytes())
                    pin["path"]=str(copied)
            raw=T.encoded(preflight)
            relocated,_=O.project(T,raw,T.pin(raw)["sha256"],self.tools,**self.projection)
            self.assertNotEqual(self.selected["preflight"],relocated["preflight"])
            self.assertEqual(O.selection_pin(T,self.selected),O.selection_pin(T,relocated))
        with self.assertRaisesRegex(ValueError,"Exact held proposal"):
            O.project(T,self.raw,"f"*64,self.tools,**self.projection)

    def test_refuses_changed_control_source_and_archive(self):
        preflight=T.decode(self.raw)
        name=next(iter(preflight["controller_source"]))
        preflight["controller_source"][name]["sha256"]="a"*64
        raw=T.encoded(preflight)
        with self.assertRaisesRegex(ValueError,"current Overlay583 control source"):
            O.project(T,raw,T.pin(raw)["sha256"],self.tools,**self.projection)
        altered=deepcopy(self.selected)
        name=next(iter(altered["packages"]["forward"].values()))["archive"]
        altered["files"][name]["sha256"]="b"*64
        with self.assertRaisesRegex(ValueError,"Exact reviewed Asahi transport selection"):
            O.check_manifest(T,altered)

    def fixture(self,*,bad_preview=False,other_boot_drift=False):
        with tempfile.TemporaryDirectory(prefix="asahi-maintenance-control-") as temp:
            home=Path(temp)
            work,inputs,target=(home/"work",home/"inputs",home/"target")
            work.mkdir()
            inputs.mkdir()
            (inputs/"keys").mkdir()
            target.mkdir()
            (target/"boot").mkdir()
            (target/"boot/preserved").write_bytes(b"kept")
            initramfs=target/G.INITRAMFS
            initramfs.write_bytes(ORIGINAL)
            initramfs.chmod(0o600)
            for name in O.REFS:
                (inputs/name).write_bytes(T.read(self.data.parent/name,O.lock_ref(name),cap=64*1024))
            for name in self.selected["keys"].values():
                leaf=name["file"]
                source=self.sources[leaf]
                (inputs/leaf).write_bytes(T.read(Path(source["path"]),O.pin(source),cap=64*1024))
            selected=dict(kind=G.BOOT,nonce="7"*32,media=self.selected)
            attempted=[]
            keys=self.selected["keys"]
            roles_by_archive={str(inputs/ref["archive"]):(phase,name,ref) for phase,packages in self.selected["packages"].items()
                              for name,ref in packages.items()}
            def command(argv,**kwargs):
                if argv[0]=="/usr/bin/gpgconf":
                    return SimpleNamespace(returncode=0)
                role=Path(kwargs["stdout"].name).name.removesuffix(".stdout")
                attempted.append(role)
                if role.startswith("query-"):
                    kwargs["stdout"].write((inputs/(role.removeprefix("query-")+".lock")).read_bytes())
                elif role.startswith("preview-"):
                    logical=role.removeprefix("preview-")
                    body=b"wrong 1-0\n" if bad_preview and logical=="forward" else (inputs/(logical+"-preview.lock")).read_bytes()
                    kwargs["stdout"].write(body)
                elif role=="list-public":
                    for value in keys.values():
                        primary=value["fingerprint"]
                        kwargs["stdout"].write(f"pub:-:255:22:{primary[-16:]}:\nfpr:::::::::{primary}:\n".encode())
                elif role.startswith("verify-"):
                    side,name,record=roles_by_archive[argv[-1]]
                    self.assertEqual(role,f"verify-{side}-{name}")
                    primary=record["signer"]
                    kwargs["stdout"].write((f"[GNUPG:] GOODSIG {primary[-16:]} fixture\n"
                        f"[GNUPG:] VALIDSIG {primary} time 1794973000 0 4 0 22 8 00 {primary}\n").encode())
                elif role.startswith("apply-"):
                    name=role.removeprefix("apply-")
                    if name=="forward":
                        initramfs.write_bytes(GENERATED)
                        kwargs["stdout"].write(HOOK)
                        if other_boot_drift:
                            (target/"boot/preserved").write_bytes(b"changed")
                    before=self.rows["baseline.lock" if name=="forward" else "forward.lock"]
                    after=self.rows[name+".lock"]
                    with (work/"evidence/pacman.log").open("ab") as log:
                        for key,version in after.items():
                            if key not in before:
                                log.write(f"[time] [ALPM] installed {key} ({version})\n".encode())
                            elif before[key]!=version:
                                action="upgraded" if name=="forward" else "downgraded"
                                log.write(f"[time] [ALPM] {action} {key} ({before[key]} -> {version})\n".encode())
                return SimpleNamespace(returncode=0)
            with (
                patch.multiple(O,WORK=work,IN=inputs,TARGET=target),
                patch.multiple(G,INITRAMFS_OWNER=(os.getuid(),os.getgid()),INITRAMFS_PIN=T.pin(ORIGINAL)),
                patch.object(O,"rehash"),
                patch.object(T,"target_api_mounts"),
                patch.object(G.os,"statvfs",return_value=SimpleNamespace(f_bavail=3000000,f_frsize=4096)),
                patch.object(G.subprocess,"run",side_effect=command),
            ):
                code=G.execute(T,O,selected)
                report=C.review(work/"evidence",selected,held=bool(code))
                if not code:
                    self.assertEqual(initramfs.read_bytes(),ORIGINAL)
                    generated=work/"evidence"/G.GENERATED["forward"]
                    self.assertEqual(generated.read_bytes(),GENERATED)
                    generated.write_bytes(b"070701 tampered")
                    with self.assertRaisesRegex(ValueError,"Expected file length|Changed pinned"):
                        C.review(work/"evidence",selected,held=False)
                    generated.write_bytes(GENERATED)
                    broken=work/"evidence"/"rollback-preview.lock"
                    broken.write_bytes(b"bad 1-1\n")
                    with self.assertRaisesRegex(ValueError,"Expected file length|Changed pinned"):
                        C.review(work/"evidence",selected,held=False)
            return code,report,attempted

    def test_exact_full_command_sequence_and_evidence_without_actor(self):
        code,report,roles=self.fixture()
        self.assertEqual(code,0)
        self.assertEqual(report["status"],G.PASS)
        self.assertEqual(report["approval_status"],"UNAPPROVED")
        self.assertIsNone(report["Root_acceptance"])
        self.assertEqual(roles.count("apply-forward"),1)
        self.assertEqual(roles.count("apply-rollback"),1)
        self.assertEqual(sum(role.startswith("verify-") for role in roles),371)

    def test_bad_preview_stops_before_any_package_apply(self):
        code,report,roles=self.fixture(bad_preview=True)
        self.assertEqual(code,75)
        self.assertEqual((report["status"],report["phase"]),(G.HOLD,"preview-forward"))
        self.assertNotIn("apply-forward",roles)
        self.assertNotIn("apply-rollback",roles)

    def test_other_boot_drift_holds_after_preserving_generated_evidence(self):
        code,report,roles=self.fixture(other_boot_drift=True)
        self.assertEqual((code,report["status"],report["phase"]),(75,G.HOLD,"check-forward"))
        self.assertEqual(roles.count("apply-forward"),1)
        self.assertNotIn("apply-rollback",roles)
        self.assertEqual(report["files"][G.GENERATED["forward"]],T.pin(GENERATED))


if __name__=="__main__":
    unittest.main(verbosity=2)
