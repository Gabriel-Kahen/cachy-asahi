#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic lifecycle DATA only; no operational Reader or actor entry."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.'))or event in('resource.setrlimit','fcntl.flock','os.exec','os.fork','os.system','os.posix_spawn'):
        raise RuntimeError('Reader6 DATA controls forbid '+event)
sys.addaudithook(fence)
r=load('Reader6_DATA',HERE/'reader.py');v=r.v
IMAGE='sha256:'+'a'*64
def life(code=0):return dict(natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,retirement='REAPED',ownership_lost=False,forced_cleanup=False,exit=code,cleanup_error=None)
def save(path,value):path.write_bytes(v.canonical(value))


class Controls(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name);(self.root/'bootstrap').mkdir()
        self.producer=dict(actor='MODELED-actor',init='MODELED-init',volume='MODELED-volume',export=dict(lifecycle=life()),export_lifecycle=life())
        prefix=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
        commands=[(['rm','-f','MODELED-actor'],0),(['rm','-f','MODELED-init'],0),(['volume','rm','MODELED-volume'],0),(['container','ls','--all','--format','{{.Names}}'],0),(['volume','ls','--quiet'],0),(['image','rm',IMAGE],0),(['image','inspect',IMAGE],1)]
        self.rows=[]
        for index,(argv,code)in enumerate(commands):
            row=dict(argv=prefix+argv,returncode=code,lifecycle=life(code),stdout=f'bootstrap/{index}.stdout',stderr=f'bootstrap/{index}.stderr')
            self.rows.append(row);self.channel(index,'stdout',b'');self.channel(index,'stderr',b'')
        self.channel(6,'stderr',('Error response from daemon: No such image: '+IMAGE+'\n').encode())
    def channel(self,index,name,raw):
        row=self.rows[index];path=self.root/row[name];path.write_bytes(raw);row[name+'_pin']=v.hashed(path)
    def check(self,reader=v):
        save(self.root/'bootstrap/operations.json',self.rows);return reader.retirement(self.root,self.producer,IMAGE)
    def test_empty_and_only_stripped_empty_array_after_successful_removal(self):
        for raw in(b'',b'\n',b'[]',b'[]\n',b' \t[]\r\n'):
            with self.subTest(raw=raw):self.channel(6,'stdout',raw);self.check()
    def test_nonempty_array_object_garbage_and_internal_array_whitespace_refuse(self):
        for raw in(b'["image"]\n',b'[{}]',b'{}\n',b'garbage',b'null',b'[ ]',b'[]garbage',b'[]\n[]'):
            with self.subTest(raw=raw):
                self.channel(6,'stdout',raw)
                with self.assertRaises(ValueError):self.check()
    def test_wrong_exact_image_id_and_nonabsence_stderr_refuse(self):
        for raw in(('Error response from daemon: No such image: sha256:'+'b'*64+'\n').encode(),b'Permission denied\n',b''):
            self.channel(6,'stderr',raw)
            with self.assertRaises(ValueError):self.check()
    def test_inspect_other_image_or_rc_zero_refuses(self):
        self.rows[6]['argv'][-1]='sha256:'+'b'*64
        with self.assertRaises(ValueError):self.check()
        self.rows[6]['argv'][-1]=IMAGE;self.rows[6].update(returncode=0,lifecycle=life())
        with self.assertRaises(ValueError):self.check()
    def test_image_absence_before_removal_or_missing_failed_removal_refuses(self):
        self.rows[5],self.rows[6]=self.rows[6],self.rows[5]
        with self.assertRaises(ValueError):self.check()
        self.rows[5],self.rows[6]=self.rows[6],self.rows[5];self.rows[5].update(returncode=1,lifecycle=life(1))
        with self.assertRaises(ValueError):self.check()
        self.rows.pop(5)
        with self.assertRaises(ValueError):self.check()
    def test_other_resource_order_and_whole_output_pin_guards_retained(self):
        self.rows[0],self.rows[3]=self.rows[3],self.rows[0]
        with self.assertRaises(ValueError):self.check()
        self.rows[0],self.rows[3]=self.rows[3],self.rows[0]
        (self.root/self.rows[6]['stdout']).write_bytes(b'[]\n')
        with self.assertRaises(ValueError):self.check()
    def test_forced_uncertain_group_or_export_lifecycle_refuses(self):
        for change in(dict(forced_cleanup=True),dict(group_absent=False),dict(ownership_lost=True),dict(retirement='UNKNOWN'),dict(exit=0)):
            before=copy.deepcopy(self.rows[6]['lifecycle']);self.rows[6]['lifecycle'].update(change)
            with self.assertRaises(ValueError):self.check()
            self.rows[6]['lifecycle']=before
        self.producer['export_lifecycle']['forced_cleanup']=True
        with self.assertRaises(ValueError):self.check()
    def test_v5_stays_strict_and_new_cloned_replay_selects_only_v6_predicate(self):
        legacy=load('Held_Reader5_unchanged_DATA',HERE.parent/'v5/reader.py')
        self.channel(6,'stdout',b'[]\n')
        with self.assertRaises(ValueError):self.check(legacy.v)
        self.check();r.B.install(v.load(HERE/'pins.json')['output_namespace'],lambda *a:None)
        self.assertIs(v.replay.__globals__['retirement'],v.retirement);self.assertIsNot(v.retirement,legacy.v.retirement)
        self.assertEqual(r.B.absence_proof['seams'],1);self.assertEqual(r.B.absence_proof['inverse'],'EXACT_FUNCTION_BYTES')
    def test_complete_reader_inverse_and_other_profile_fields_stay_exact(self):
        proof=v.load(HERE/'derivation.json');raw=(HERE/'reader.py').read_bytes()
        for seam in reversed(proof['seams']):
            self.assertEqual(raw.count(seam['after'].encode()),1);raw=raw.replace(seam['after'].encode(),seam['before'].encode())
        self.assertEqual(raw,(HERE.parent/'v5/reader.py').read_bytes());self.assertEqual(hashlib.sha256(raw).hexdigest(),proof['parent_reader_sha256'])
        pins=v.load(HERE/'pins.json');old=v.load(HERE.parent/'v5/pins.json');old['base_sha256']=pins['base_sha256'];self.assertEqual(pins,old)
        for name,digest in proof['copied_byte_identical'].items():self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest)
    def test_binding_scope_is_distinct_all_actual_selectors_remain_null(self):
        binding=v.load(HERE/'binding.TEMPLATE.json');self.assertEqual(binding['scope'],'ROOT_BOUND_LLVM23_INDEPENDENT_READER_V6');self.assertTrue(all(value is None for value in binding['actual'].values()))
        with self.assertRaises(ValueError):r.binding(binding,v.load(HERE/'pins.json'))
        request=v.load(HERE/'request.TEMPLATE.json')
        for key in('binding','actual_reader_selector','source','original','output','Root_issuer','Root_approved','Root_issued_at','Root_runtime54','Root_resources','Root_storage_profile'):self.assertIsNone(request[key])
        self.assertEqual(request['entry']['sha256'],hashlib.sha256((HERE/'reader.py').read_bytes()).hexdigest())
        self.assertEqual(request['memory_cap_bytes'],256*1024**2);self.assertEqual(request['internal_seconds'],1800)
    def test_actor_fence_refuses_operational_entry_primitives(self):
        for event in('subprocess.Popen','socket.__new__','ctypes.dlopen','fcntl.flock','resource.setrlimit'):
            with self.assertRaises(RuntimeError):fence(event,())


if __name__=='__main__':unittest.main(verbosity=2)
