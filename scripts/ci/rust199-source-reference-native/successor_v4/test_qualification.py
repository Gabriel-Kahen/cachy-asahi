# SPDX-License-Identifier: MIT
"""FENCED native-qualification record controls; no actor/candidate/child role."""
import ast
import copy
import io
import tarfile
import tempfile
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('qualification_DATA',HERE/'payload/hosted/qualification.py');Q=importlib.util.module_from_spec(s);s.loader.exec_module(Q)
s=importlib.util.spec_from_file_location('qualification_actor_DATA',HERE/'payload/actor/qualify.py');A=importlib.util.module_from_spec(s);s.loader.exec_module(A)


class Controls(unittest.TestCase):
    def model(self):
        # Only component record shapes; never a Root pregrant or accepted package.
        provider=dict(source={'FENCED':'provider'},dispatch_sha256='a'*64);boot=dict(image='sha256:'+'b'*64,rootfs_tree_sha256='c'*64)
        life=dict(natural_exit=True,forced_cleanup=False,group_absent=True,retirement='REAPED',ownership_lost=False,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,exit=0)
        ro=dict(paths=['/stage0','/work/build/stage0'],readonly=True,namespace_permissions_verified=True,write_attempts_denied=True,alias_write_attempts_denied=True,attempts=[dict(errno=30),dict(errno=30)])
        value=dict(schema=4,status='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY',binding=provider['source'],dispatch_sha256=provider['dispatch_sha256'],provider_phase_sha256=hashlib.sha256(Q.encode(provider)).hexdigest(),image_id=boot['image'],rootfs_tree_sha256=boot['rootfs_tree_sha256'],native_acceptance=False,holds_preserved=True,readonly_stage0=ro,probe_receipts=[dict(argv=argv,returncode=0,lifecycle=copy.deepcopy(life))for argv in Q.PROBES])
        for name in ('stage0_tree_sha256','qualified_llvm_tree_sha256','library_cargo_config_sha256','source_tree_sha256'):value[name]='d'*64
        return value,provider,boot
    def test_exact_nine_frozen_probe_vectors(self):
        self.assertEqual(A.PROBES,Q.PROBES);self.assertEqual(len(Q.PROBES),9);self.assertEqual(Q.PROBES[:2],[['/stage0/bin/rustc','-vV']]*2)
        self.assertEqual(Q.PROBES[3],['/stage0/bin/cargo','--version'])
        text=(HERE/'payload/actor/qualify.py').read_text();self.assertIn('c.probe()',text);self.assertNotIn('c.build(',text);self.assertNotIn('install.sh',text)
    def test_record_joins_and_retirement_refusals(self):
        value,provider,boot=self.model();Q.validate_result(value,provider,boot)
        for mode in ('image','provider','native','probe','forced','readonly'):
            bad=copy.deepcopy(value)
            if mode=='image':bad['image_id']='sha256:'+'e'*64
            elif mode=='provider':bad['dispatch_sha256']='e'*64
            elif mode=='native':bad['native_acceptance']=True
            elif mode=='probe':bad['probe_receipts'][0]['argv']=['/usr/bin/false']
            elif mode=='forced':bad['probe_receipts'][0]['lifecycle']['forced_cleanup']=True
            else:bad['readonly_stage0']['attempts'][1]['errno']=13
            with self.subTest(mode=mode),self.assertRaises(ValueError):Q.validate_result(bad,provider,boot)
    def test_readonly_tests_require_actual_EROFS_for_both_aliases(self):
        with patch.object(A.os,'open',side_effect=OSError(30,'FENCED EROFS')):value=A.readonly_test()
        self.assertEqual(value['paths'],['/stage0','/work/build/stage0']);self.assertEqual([r['errno']for r in value['attempts']],[30,30])
        with patch.object(A.os,'open',side_effect=OSError(13,'FENCED denied')):
            with self.assertRaises(ValueError):A.readonly_test()
    def test_source_and_volume_guards_precede_work_writes(self):
        tree=ast.parse((HERE/'payload/actor/qualify.py').read_text());run=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='run');text=ast.unparse(run)
        self.assertLess(text.index('kernel(phase)'),text.index('WORK.mkdir'))
        self.assertLess(text.index('V.verify_receipt('),text.index('WORK.mkdir'))
        self.assertIn('c.subprocess.check_output = previous',text)
    def test_flat_qualification_export_requires_complete_bounded_tar(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-qualification-tar-')as temporary:
            base=Path(temporary);path=base/'valid.tar'
            with tarfile.open(path,'w')as archive:
                item=tarfile.TarInfo('output/FENCED.json');raw=b'{"FENCED":true}';item.size=len(raw);archive.addfile(item,io.BytesIO(raw))
            data=Q.unpack(path,base/'valid');self.assertEqual((data/'FENCED.json').read_bytes(),raw)
            original=path.read_bytes()
            for index,body in enumerate((original+b'BAD_TRAILING',original[:1024])):
                bad=base/f'bad-{index}.tar';bad.write_bytes(body)
                with self.assertRaises((ValueError,tarfile.TarError)):Q.unpack(bad,base/f'bad-{index}')
            info=tarfile.TarInfo('FENCED');info.type=tarfile.XHDTYPE;info.size=65537;bad=base/'pax.tar';bad.write_bytes(info.tobuf()+bytes(512))
            with self.assertRaises((ValueError,tarfile.TarError)):Q.unpack(bad,base/'pax')
    def test_qualification_host_order_nocopy_and_no_build(self):
        text=(HERE/'payload/hosted/qualification.py').read_text()
        self.assertLess(text.index("intent('container',actors['data']"),text.index("DOCKER+['start','--attach',actors['init']]"))
        self.assertIn("P.mount_specs(volume,inputs,root,materials",text)
        self.assertIn('same captured qualification container',text);self.assertIn('owned_resources_absent',text)
        self.assertNotIn("DOCKER+['build'",text)
    def test_export_leaf_copy_and_hash_stop_at_chunk_cancellation(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-qualification-chunks-')as temporary:
            base=Path(temporary);path=base/'data.tar'
            with tarfile.open(path,'w')as archive:
                item=tarfile.TarInfo('output/large.stdout');raw=b'x'*(3*1024**2);item.size=len(raw);archive.addfile(item,io.BytesIO(raw))
            def cancel_copy():
                leaf=base/'data/large.stdout'
                if leaf.exists() and leaf.stat().st_size>=1024**2:raise ValueError('FENCED copy cancellation')
            with self.assertRaisesRegex(ValueError,'FENCED copy cancellation'):Q.unpack(path,base/'data',cancel_copy)
            self.assertLess((base/'data/large.stdout').stat().st_size,len(raw));calls=[]
            def cancel_hash():
                calls.append(None)
                if len(calls)==2:raise ValueError('FENCED hash cancellation')
            with self.assertRaisesRegex(ValueError,'FENCED hash cancellation'):Q.sha(path,cancel_hash)


if __name__=='__main__':unittest.main()
