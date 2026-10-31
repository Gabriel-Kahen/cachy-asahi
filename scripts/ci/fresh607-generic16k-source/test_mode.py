# SPDX-License-Identifier: MIT
"""Exact emitted source page controls and actual inline retention, no VM/actors."""
import importlib.util,json,os,subprocess,sys,tempfile,textwrap,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fixed_page_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
SOURCE=F.canonical(os.environ['FRESH_PAGE_SOURCE']);PARENT=F.canonical(os.environ['FRESH_PAGE_PARENT'])
F.need({n:F.pin(b)for n,b in F.tree(SOURCE).items()}==json.loads(F.read(HERE/'output-source.json'))['files'],'exact emitted source before executing trusted source-only controls')
def inline(root):
 raw=F.read(root/'implementation/workflow-template.yml').decode();return textwrap.dedent(raw.split("          python3 -I -B - <<'PYPUBLIC'\n",1)[1].split('          PYPUBLIC\n',1)[0])
def export(root,mode):
 with tempfile.TemporaryDirectory()as td:
  t=Path(td);p=t/'owned/cachy-asahi-expanded604-installer-1-1';p.mkdir(parents=True);(p/'result.json').write_bytes(b'{"scope":"INERT_PRIVATE_SOURCE_CONTROL"}')
  fake=types.ModuleType('pathlib');fake.Path=lambda value:t/'owned'if value=='/tmp'else Path(value)
  env=dict(GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1',RUNNER_TEMP=str(t))
  if mode is not None:env['PAGE_MODE']=mode
  with patch.dict(os.environ,env,clear=True),patch.dict(sys.modules,{'pathlib':fake}):exec(compile(inline(root),'<exact-source-inline-export>','exec'),{})
  return{p.name:p.read_bytes()for p in(t/'expanded604-installer-public').iterdir()}
class Controls(unittest.TestCase):
 def test_exact_current_six_source_controls_real_entry(self):
  p=subprocess.run([sys.executable,'-I','-B','-Werror',str(SOURCE/'implementation/test_page_mode.py')],capture_output=True,timeout=60);self.assertEqual(p.returncode,0,p.stderr.decode());self.assertIn(b'Ran 6 tests',p.stderr);self.assertTrue(p.stderr.rstrip().endswith(b'OK'))
 def test_actual_inline4k_bytes_and16k_typed_scope_and_refusal(self):
  old=export(PARENT,None);four=export(SOURCE,'generic4k');sixteen=export(SOURCE,'generic16k');self.assertEqual(old,four)
  left=json.loads(four['retention.json']);right=json.loads(sixteen['retention.json']);self.assertEqual(left.pop('scope'),'generic4K fresh latest607 software installer only; no hardware or native-container P0 credit');self.assertEqual(right.pop('scope'),'generic16K fresh latest607 software installer only; no hardware or native-container P0 credit');self.assertEqual(left,right)
  for mode in(None,'generic16K','generic16k ','','unknown'):
   with self.subTest(mode=mode),self.assertRaises((AssertionError,KeyError)):export(SOURCE,mode)
 def test_source_buildonly_policy_full_inverses_and_all_old_clocks_held(self):
  root=F.tree(SOURCE);before=F.tree(PARENT);p=json.loads(root['implementation/page-parent.json']);self.assertEqual(p['files'],{n:F.pin(b)for n,b in before.items()});s=p['scope_parent'];old={n:s['before_bodies'][n].encode()if n in s['before_bodies']else root[n]for n in s['files']};self.assertEqual({n:F.pin(b)for n,b in old.items()},s['files']);q=s['qualification']['text'].encode();self.assertEqual(F.pin(q),s['qualification']['pin']);self.assertEqual(json.loads(q)['status'],'PASS')
  profile=json.loads(root['implementation/page-mode-profile.json']);self.assertTrue(all(profile[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')));self.assertEqual(profile['kernel']['Image'],dict(bytes=9019400,sha256='cd8053ebdb83302015efbad97ab1cc53fcd5a2353bf3f37ba208f4e6360946ec'));self.assertEqual(profile['kernel']['config'],dict(bytes=68789,sha256='e97d54d4852eceb6cba28c38f78d4a00aacbfdb0c1523cb96366590f7eaa915b'));self.assertEqual(profile['kernel']['source'],'4056e2505ed7081674e949e0460258672cce14ff');self.assertEqual(profile['kernel']['artifact']['id'],12147995917)
  for n in('implementation/common.py','implementation/profile.json','implementation/materialize.py','implementation/adapter.py','implementation/validate.py','implementation/runtime_context.py',*('parent604/'+name for name in('prepare.py','run.py','guest.py','installer.py','numeric_vm.py','profile.py'))):self.assertEqual(root[n],before[n],n)
if __name__=='__main__':unittest.main(verbosity=2)
