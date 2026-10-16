"""Doctor terminal command/preservation controls with fake installed clients."""
import contextlib
import io
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import doctor_worker as D
from test_gui import ROOT, doctor


class Worker(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.actors=[];self.bad_overwrite=False;self.wait_error=False;self.finish_error=False
        self.raw=(json.dumps(doctor()['doctor'],sort_keys=True,indent=2)+'\n').encode();self.original_stat=Path.stat
        spec=importlib.util.spec_from_file_location('doctor_real_guest',ROOT/'scripts/ci/desktop574_guest.py')
        self.base=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.base)
        self.real_finish=self.base.Logged.finish;self.original_emit=self.base.emit
        self.base.Logged=self.launch;self.base.terminate=lambda p:None;self.omit_event=False

    def launch(self,argv,name,logs,env):
        actor=SimpleNamespace(process=SimpleNamespace(returncode=0),paths=[logs/(name+'.stdout'),logs/(name+'.stderr')],
                              threads=[],errors=[],overflow=False,finished=False)
        actor.process.poll=lambda:actor.process.returncode
        stdout=self.raw;stderr=b''
        if '--output' in argv:
            path=Path(argv[argv.index('--output')+1])
            if path.exists() or path.is_symlink():
                actor.process.returncode=0 if self.bad_overwrite else 2;stdout=b'';stderr=b'output refused\n'
            else:path.write_bytes(self.raw);path.chmod(0o600)
        actor.paths[0].write_bytes(stdout);actor.paths[1].write_bytes(stderr)
        def wait(timeout):
            if self.wait_error:raise TimeoutError('primary Doctor timeout')
            return actor.process.returncode
        def finish():
            actor.finished=True
            if self.finish_error:raise RuntimeError('secondary Doctor drain failure')
            if not self.omit_event:self.real_finish(actor)
        actor.process.wait=wait;actor.finish=finish;self.actors.append(actor);return actor

    def stat(self,path,*args,**kwargs):
        value=self.original_stat(path,*args,**kwargs)
        if path.name=='doctor-report.json':
            fields={name:getattr(value,name) for name in dir(value) if name.startswith('st_')}
            return SimpleNamespace(**(fields|{'st_uid':23001}))
        return value

    def exercise(self):
        with patch.object(Path,'stat',autospec=True,side_effect=self.stat),patch.object(D.os,'isatty',return_value=True),\
             patch.object(D.os,'ttyname',return_value='/dev/pts/7'),\
             contextlib.redirect_stdout(io.StringIO()):
            return D.exercise(self.base,self.root,'minimal','a'*32,101,{})

    def test_original_finish_requires_uninitialized_module_event_port(self):
        self.assertIsNone(self.base.EVENTS)
        actor=self.launch(['/usr/bin/cachy-asahi-doctor','--json'],'doctor-1',self.root,{})
        with self.assertRaisesRegex(ValueError,'event port unavailable'):self.real_finish(actor)

    def test_installed_json_report_and_two_no_overwrite_refusals(self):
        result=self.exercise();self.assertEqual(len(result['commands']),4)
        self.assertEqual([r['returncode'] for r in result['commands']],[0,0,2,2])
        self.assertEqual(result['report_mode'],'0600');self.assertIn('no-overwrite PASS',result['transcript'])
        self.assertTrue(all(a.finished for a in self.actors));self.assertEqual((self.root/'doctor-report.json').read_bytes(),self.raw)
        self.assertIsNone(self.base.EVENTS);self.assertIs(self.base.emit,self.original_emit)
        self.assertEqual([r['name'] for r in result['processes']],['doctor-'+str(n) for n in range(1,5)])
        self.assertEqual([r['returncode'] for r in result['processes']],[0,0,2,2])
        self.assertTrue(all(len(r['logs'])==2 for r in result['processes']))

    def test_missing_local_process_proof_is_fatal_and_restores_emitter(self):
        self.omit_event=True
        with self.assertRaisesRegex(ValueError,'Doctor process exit proof differs'):self.exercise()
        self.assertIs(self.base.emit,self.original_emit);self.assertTrue(self.actors[0].finished)

    def test_unexpected_no_overwrite_success_refuses_proof(self):
        self.bad_overwrite=True
        with self.assertRaisesRegex(ValueError,'command exit differs'):self.exercise()
        self.assertTrue(all(a.finished for a in self.actors))

    def test_primary_timeout_survives_secondary_drain_error(self):
        self.wait_error=True;self.finish_error=True
        with self.assertRaisesRegex(TimeoutError,'primary Doctor timeout'):self.exercise()
        self.assertTrue(self.actors[0].finished)
        self.assertIs(self.base.emit,self.original_emit)


if __name__=='__main__':unittest.main()
