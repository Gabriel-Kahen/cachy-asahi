"""Doctor terminal command/preservation controls with fake installed clients."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import doctor_worker as D
from test_gui import doctor


class Worker(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.actors=[];self.bad_overwrite=False;self.wait_error=False;self.finish_error=False
        self.raw=(json.dumps(doctor()['doctor'],sort_keys=True,indent=2)+'\n').encode();self.original_stat=Path.stat

    def launch(self,argv,name,logs,env):
        actor=SimpleNamespace(process=SimpleNamespace(returncode=0),paths=[logs/(name+'.stdout'),logs/(name+'.stderr')],finished=False)
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
        actor.process.wait=wait;actor.finish=finish;self.actors.append(actor);return actor

    def stat(self,path,*args,**kwargs):
        value=self.original_stat(path,*args,**kwargs)
        if path.name=='doctor-report.json':return SimpleNamespace(st_uid=23001,st_mode=value.st_mode)
        return value

    def exercise(self):
        base=SimpleNamespace(Logged=self.launch,terminate=lambda p:None)
        with patch.object(Path,'stat',autospec=True,side_effect=self.stat),patch.object(D.os,'isatty',return_value=True),\
             patch.object(D.os,'ttyname',return_value='/dev/pts/7'),\
             contextlib.redirect_stdout(io.StringIO()):
            return D.exercise(base,self.root,'minimal','a'*32,101,{})

    def test_installed_json_report_and_two_no_overwrite_refusals(self):
        result=self.exercise();self.assertEqual(len(result['commands']),4)
        self.assertEqual([r['returncode'] for r in result['commands']],[0,0,2,2])
        self.assertEqual(result['report_mode'],'0600');self.assertIn('no-overwrite PASS',result['transcript'])
        self.assertTrue(all(a.finished for a in self.actors));self.assertEqual((self.root/'doctor-report.json').read_bytes(),self.raw)

    def test_unexpected_no_overwrite_success_refuses_proof(self):
        self.bad_overwrite=True
        with self.assertRaisesRegex(ValueError,'command exit differs'):self.exercise()
        self.assertTrue(all(a.finished for a in self.actors))

    def test_primary_timeout_survives_secondary_drain_error(self):
        self.wait_error=True;self.finish_error=True
        with self.assertRaisesRegex(TimeoutError,'primary Doctor timeout'):self.exercise()
        self.assertTrue(self.actors[0].finished)


if __name__=='__main__':unittest.main()
