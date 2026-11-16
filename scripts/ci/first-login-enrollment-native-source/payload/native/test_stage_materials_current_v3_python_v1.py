# SPDX-License-Identifier: MIT
"""Actual held inspector contract, inert tool fixture and modeled children only."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
S=load('FENCED_canonical_stage_successor',HERE/'stage_materials_current_v3_python_v1.py')
BASE=load('FENCED_held_c640_controls',HERE/'test_stage_materials_current_v3.py')
BASE.S=S  # Parameterize the unchanged shared contract controls, no gate override.
EXECUTOR=Path(os.environ.get('CACHY_CURRENT_EXECUTOR_FIXTURE',str(HERE/'owned_executor_current_v3.py'))).resolve()

class SharedControls(BASE.Controls):
 def test_runner_direct_argv_minimal_secret_environment_natural_retirement(self):
  # Same actor boundary as the held controls, now supplying explicit qualified
  # canonical rows. The real inspector is exercised separately below.
  good=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,exit=0)
  E=SimpleNamespace(checked_tool=lambda row:row['path']);tools={'python3':dict(path='/usr/bin/python3.12')}
  O=SimpleNamespace(prepare=lambda:None,supervise=lambda *a,**kw:dict(good));R=S.Runner(O,self.root,time.monotonic()+100,E,tools)
  env={'CACHY_OLD_FOUR_JBIGKIT_01':'INERT_MODEL'};seen=[]
  def spawn(argv,**kw):seen.append(dict(kw['env']));return SimpleNamespace(pid=123)
  with patch.object(S.subprocess,'Popen',side_effect=spawn),patch.object(S.os,'waitid',return_value=object()):
   self.assertEqual(R.run(['/usr/bin/python3.12','MODEL'],15,env=env),b'')
   good['signals']=[15]
   with self.assertRaises(ValueError):R.run(['/usr/bin/python3.12','MODEL'],15)
  self.assertEqual(env,{});self.assertNotIn('CACHY_OLD_FOUR_JBIGKIT_01',seen[1]);self.assertNotIn('INERT_MODEL',json.dumps(R.rows))
  with self.assertRaises(ValueError):R.run(['/tmp/unreviewed-python','MODEL'],15)

class CanonicalControls(unittest.TestCase):
 def setUp(self):
  self.assertEqual(S.pin(EXECUTOR.read_bytes()),dict(bytes=53735,sha256='aee41c0956f3249eef2e9c8974238b214622cb385e2d8f736109d9650ce7120a'))
  self.E=load('actual_qualified_inspector',EXECUTOR)
  self.temp=tempfile.TemporaryDirectory(prefix='FENCED-canonical-tool-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  folder=self.root/'usr/bin';folder.mkdir(parents=True)
  for name in ('python3.12','systemctl'):
   p=folder/name;p.write_bytes(('FENCED INERT '+name).encode());p.chmod(0o755)
  (folder/'python3').symlink_to('python3.12')
  actual=self.E.inspect_tool
  self.inspect=lambda candidate:actual(candidate,root=self.root,trusted_uid=os.getuid())
 def test_normal_alias_is_qualified_canonical_not_path_equality(self):
  with patch.object(self.E,'inspect_tool',side_effect=self.inspect):
   row=self.E.inspect_tool('/usr/bin/python3');path=self.E.checked_tool(row)
   self.assertNotEqual(path,'/usr/bin/python3')
   with self.assertRaises(ValueError):BASE.S.need(path=='/usr/bin/python3','held c640 pathname guard')
   rows=S.qualified_tools(self.E);self.assertEqual(rows['python3']['path'],str(self.root/'usr/bin/python3.12'))
 def test_real_owner_writable_alias_and_unreviewed_name_refuse(self):
  # Real algorithm, deliberately no uid override: user-owned fixtures cannot
  # qualify as operational root-owned tools.
  with self.assertRaises(ValueError):self.E.inspect_tool('/usr/bin/python3',root=self.root)
  with patch.object(self.E,'inspect_tool',side_effect=self.inspect):
   (self.root/'usr/bin/python3.12').chmod(0o777)
   with self.assertRaises(ValueError):S.qualified_tools(self.E)
  with self.assertRaises(ValueError):self.E.inspect_tool('/tmp/unreviewed-python',root=self.root)
 def test_changed_whole_body_rejoins_before_spawn(self):
  with patch.object(self.E,'inspect_tool',side_effect=self.inspect):
   tools=S.qualified_tools(self.E);(self.root/'usr/bin/python3.12').write_bytes(b'CHANGED')
   R=S.Runner(SimpleNamespace(),self.root,time.monotonic()+30,self.E,tools)
   with patch.object(S.subprocess,'Popen',side_effect=AssertionError('no spawn before actual rejoin')):
    with self.assertRaises(ValueError):R.run([tools['python3']['path'],'MODEL'],15)
 def test_held_predecessor_body_and_numeric_policy_stay_exact(self):
  self.assertEqual(S.pin((HERE/'stage_materials_current_v3.py').read_bytes()),dict(bytes=31630,sha256='2e2bf75fb6c59e400cf21aadb719ee687d7b8c12e21ace872637b47f7304fede'))
  held=load('actual_immutable_c640',HERE/'stage_materials_current_v3.py');self.assertEqual(S.PROPOSAL,held.PROPOSAL);self.assertEqual(S.HELPERS,held.HELPERS);self.assertEqual(S.MATERIALS,held.MATERIALS)

if __name__=='__main__':unittest.main()
