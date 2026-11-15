# SPDX-License-Identifier: MIT
"""Focused refusal controls; no Docker or project installation."""
import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('candidate', HERE / 'run.py')
candidate = importlib.util.module_from_spec(spec); spec.loader.exec_module(candidate)
spec = importlib.util.spec_from_file_location('journey', HERE / 'user_journey.py')
journey = importlib.util.module_from_spec(spec); spec.loader.exec_module(journey)


class Controls(unittest.TestCase):
    def actor(self):
        return {'Config': {'User':'1000:1000'}, 'HostConfig': {'NanoCpus':2000000000,
            'Memory':4*1024**3,'MemorySwap':4*1024**3,'PidsLimit':256,'NetworkMode':'none',
            'Init':True,'ReadonlyRootfs':True,'CapDrop':['ALL'],'CapAdd':None,'Privileged':False,
            'Devices':[],'SecurityOpt':['no-new-privileges'],'PidMode':'','IpcMode':'private'}}

    def test_exact_worker_resources(self):
        candidate.resources(self.actor(),True,'1000:1000')

    def test_every_resource_privilege_escape_refused(self):
        for key,value in {'NanoCpus':0,'Memory':0,'MemorySwap':-1,'PidsLimit':0,'NetworkMode':'host',
                'Init':False,'ReadonlyRootfs':False,'CapDrop':[],'CapAdd':['SYS_ADMIN'],'Privileged':True,
                'Devices':['/dev/dri'],'SecurityOpt':['no-new-privileges','seccomp=unconfined'],
                'PidMode':'host','IpcMode':'host'}.items():
            data=self.actor();data['HostConfig'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):candidate.resources(data,True,'1000:1000')

    def test_wrong_actor_identity_refused(self):
        data=self.actor();data['Config']['User']='0:0'
        with self.assertRaises(ValueError):candidate.resources(data,True,'1000:1000')

    def test_input_symlink_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'data';path.write_bytes(b'data');link=path.with_name('link');link.symlink_to(path)
            with self.assertRaises(ValueError):candidate.pin(link)

    def test_unpinned_shared_code_is_not_executed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'data.py';path.write_text('raise AssertionError("unreviewed code executed")')
            with self.assertRaisesRegex(ValueError,'source changed'):candidate.load('unsafe',path,'0'*64)

    def test_cleanup_unknown_errors_not_hidden(self):
        self.assertTrue(candidate.absent(['docker','rm','-f','owned'],'Error response from daemon: No such container: owned\n'))
        for output in ('daemon unavailable','Error response from daemon: No such container: other'):
            self.assertFalse(candidate.absent(['docker','rm','-f','owned'],output))

    def test_invalid_material_refuses_before_docker_or_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            material=Path(temporary)/'wrong';material.write_bytes(b'not pinned')
            output=Path(temporary)/'new-output'
            argv=[sys.executable,'-I',str(HERE/'run.py')]
            for name in ('first-login','setup','fish','zsh'):argv+=['--'+name,str(material)]
            argv+=['--output',str(output)]
            result=subprocess.run(argv,capture_output=True,text=True,timeout=5)
            self.assertNotEqual(result.returncode,0);self.assertIn('archive pin differs',result.stderr)
            self.assertFalse(output.exists())

    def test_direct_nonisolated_entry_refused(self):
        result=subprocess.run([sys.executable,str(HERE/'run.py'),'--help'],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0);self.assertIn('isolated unoptimized',result.stderr)

    def test_empty_former_mount_placeholder_has_no_source_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);inputs=root/'inputs';inputs.mkdir();mountinfo=root/'mountinfo';mountinfo.write_text('')
            self.assertFalse(journey.source_visible(inputs,root/'missing-checkout',mountinfo))
            (inputs/'source.py').write_text('source')
            self.assertTrue(journey.source_visible(inputs,root/'missing-checkout',mountinfo))

    def test_even_empty_active_source_mount_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);inputs=root/'inputs';inputs.mkdir();mountinfo=root/'mountinfo'
            mountinfo.write_text('1 2 3:4 / '+str(inputs)+' ro - tmpfs source ro\n')
            self.assertTrue(journey.source_visible(inputs,root/'missing-checkout',mountinfo))


if __name__=='__main__':unittest.main()
