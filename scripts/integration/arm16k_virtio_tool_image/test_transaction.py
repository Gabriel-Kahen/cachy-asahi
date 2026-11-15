#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real <5s ordinary fixture: no pacman/GPG/Docker/lease/existing service."""
import argparse,importlib.util,json,subprocess,sys,tempfile,time,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--owned-process',type=Path,required=True);a=p.parse_args();C=load('transaction_test_contract',HERE/'contract.py');C.checked(a.owned_process.resolve(),C.lock()['runtime']['owned_process.py']);O=load('transaction_test_owned',a.owned_process.resolve());O.prepare()
 class RealTransaction(unittest.TestCase):
  def fixture(self,transaction_exit=0,shutdown_exit=0):
   with tempfile.TemporaryDirectory(prefix='cachy-virtio-transaction-fixture-')as d:
    root=Path(d);stop=root/'normal-stop';result=root/'result.json'
    # Two forks and setsid model a naturally retiring detached verification child.
    transaction="import os,time;from pathlib import Path\nif os.fork()==0:\n if os.fork()>0:os._exit(0)\n os.setsid()\n while not Path("+repr(str(stop))+").exists():time.sleep(.005)\n os._exit(0)\nos._exit("+str(transaction_exit)+")\n"
    shutdown="from pathlib import Path;import sys;Path("+repr(str(stop))+").write_text('normal shutdown');sys.exit("+str(shutdown_exit)+")"
    code="import importlib.util,json,sys;from pathlib import Path;s=importlib.util.spec_from_file_location('fixture_transaction',"+repr(str(HERE/'transaction.py'))+");m=importlib.util.module_from_spec(s);s.loader.exec_module(m);r=m.execute([sys.executable,'-I','-B','-c',"+repr(transaction)+"],[sys.executable,'-I','-B','-c',"+repr(shutdown)+"],whole=3.3,transaction_seconds=1.5,shutdown_seconds=.5,reap_seconds=.8);Path("+repr(str(result))+").write_text(json.dumps(r));sys.exit(0 if r['status']=='NORMAL_TRANSACTION_AND_PRIVATE_AGENT_REAPED'else 1)"
    child=subprocess.Popen([sys.executable,'-I','-B','-c',code],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);outer=O.supervise(child,cap=4.5,retirement=.5,grace=.1,max_output=65536,log_fd=None);report=json.loads(result.read_bytes());self.assertEqual(outer['signals'],[]);self.assertEqual(outer['ownership'],'REAPED');self.assertEqual(outer['group_census'],'EMPTY_TWICE');self.assertTrue(outer['output_complete']);self.assertTrue(report['subreaper']);self.assertTrue(report['empty_children_twice']);self.assertEqual(report['signals_sent'],[]);self.assertEqual(report['received_signals'],[]);self.assertGreaterEqual(len(report['reaped_children']),1);self.assertTrue(all(r['exit']==0 for r in report['reaped_children']));self.assertEqual(report['transaction_exit'],transaction_exit);self.assertEqual(report['shutdown_exit'],shutdown_exit);self.assertTrue(stop.is_file());return report,outer
  def test_real_detached_child_normal_shutdown_and_natural_reap(self):
   report,outer=self.fixture();self.assertEqual(report['status'],'NORMAL_TRANSACTION_AND_PRIVATE_AGENT_REAPED');self.assertTrue(outer['passed']);self.assertEqual(outer['exit'],0)
  def test_failed_transaction_still_normally_retires_child(self):
   report,outer=self.fixture(transaction_exit=7);self.assertEqual(report['status'],'HOLD');self.assertEqual(outer['exit'],1)
  def test_failed_shutdown_preserves_refusal_despite_natural_reap(self):
   report,outer=self.fixture(shutdown_exit=8);self.assertEqual(report['status'],'HOLD');self.assertEqual(outer['exit'],1)
 return 0 if unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(RealTransaction)).wasSuccessful()else 1
if __name__=='__main__':raise SystemExit(main())
