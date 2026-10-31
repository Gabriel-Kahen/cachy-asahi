# SPDX-License-Identifier: MIT
"""Finite source/header/fixture adapter controls, no native/signing/ALPM actors."""
import ast,copy,hashlib,importlib.util,json,os,re,stat,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
import contract as C
import install_dependency as D
import lifecycle as L
import stage_source as S
ROOT=Path(os.environ.get('ORPHAN_NATIVE_SOURCE',Path(__file__).resolve().parents[3]))
class Controls(unittest.TestCase):
 def setUp(self):
  self.block=patch.object(subprocess,'Popen',side_effect=AssertionError('all actors forbidden'));self.block.start();self.addCleanup(self.block.stop)
 def test_policy_unbound_before_any_original_owner_or_source_action(self):
  template=C.read(C.HERE/'policy.json')
  with patch.object(C,'read',return_value=template):
   with self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()
   with self.assertRaisesRegex(ValueError,'UNBOUND'):C.source(ROOT)
 def test_only_fixture_install_adds_public_alldeps_preserving_original_flags(self):
  seen=[];actor=NS(handle=123,alpm_trans_init=lambda h,f:seen.append((h,f)) or 0)
  wrapped=D.factory(lambda *a,**k:actor,(1<<7)|(1<<10))
  value=wrapped();self.assertEqual(value.alpm_trans_init(123,(1<<7)|(1<<10)),0)
  self.assertEqual(seen,[(123,(1<<7)|(1<<10)|(1<<8))])
  for handle,flags in ((124,(1<<7)|(1<<10)),(123,0),(123,(1<<7)|(1<<10)|(1<<8))):
   with self.assertRaisesRegex(ValueError,'original install flags'):value.alpm_trans_init(handle,flags)
 def test_fixture_accepts_original_sanitized_child_environment_only(self):
  # Original Calls.call passes a disposable owner token, not the outer actor flag.
  env=dict(C.ENV,HOME='/tmp',CACHY_ASAHI_APPS_TRANSACTION='a'*32)
  with patch.object(D.C,'source'),patch.object(D.os,'getuid',return_value=0),patch.object(D.os,'geteuid',return_value=0),patch.object(D.os,'uname',return_value=NS(machine='aarch64')),patch.object(D.sys,'argv',['fixture']):
   with patch.dict(D.os.environ,env,clear=True):
    with self.assertRaisesRegex(ValueError,'install fixture only'):D.main()
   for bad in ('','a'*31,'g'*32):
    with patch.dict(D.os.environ,dict(env,CACHY_ASAHI_APPS_TRANSACTION=bad,CACHY_APPS574_LIFECYCLE='1'),clear=True):
     with self.assertRaisesRegex(ValueError,'native fixture actor'):D.main()
 def test_native_header_requires_one_exact_supported_public_enum(self):
  self.assertEqual(D.dependency_flag('enum flags { ALPM_TRANS_FLAG_ALLDEPS = (1 << 8), OTHER = 1 };'),256)
  for header in ('', 'ALPM_TRANS_FLAG_ALLDEPS = (1 << 9),', 'ALPM_TRANS_FLAG_ALLDEPS = 256,', 'ALPM_TRANS_FLAG_ALLDEPS = (1 << 8),\nALPM_TRANS_FLAG_ALLDEPS = (1 << 8),', 'x'*(1024**2+1)):
   with self.assertRaises(ValueError):D.dependency_flag(header)
 def test_request_keeps_original_exact_signed_remove_operands(self):
  with tempfile.TemporaryDirectory() as name:
   path=Path(name)/'orphan-plan.json';path.write_bytes(b'{}')
   argv=['python','-I','-B','/source/scripts/apps/transaction.py','apply','--workspace','/work/main','--operation','remove','--applications','apps','--plan','/out/p.json','--plan-sha256','a'*64,'--confirm-disposable-transaction']
   value=L.args_request(argv,path);self.assertEqual(value['applications'],['apps']);self.assertEqual(value['selected'],['cachy-asahi-apps']);self.assertTrue(value['confirm_disposable_transaction']);self.assertEqual(value['plan_sha256'],'a'*64)
   with self.assertRaisesRegex(ValueError,'exact signed Apps'):L.args_request([x if x!='apps' else 'runtime' for x in argv],path)
 def test_original_owner_custody_resource_and_cleanup_functions_unchanged(self):
  root=ROOT/'scripts/ci/apps-full574-native/job.py';raw=root.read_bytes();tree=ast.parse(raw)
  self.assertIn('actor',{n.name for n in tree.body if isinstance(n,ast.FunctionDef)})
  # Our wrapper imports these functions from the pinned original; no replacement bodies.
  wrapper=(ROOT/C.LANE/'job.py').read_text();self.assertIn("H=C.load('original_apps_owner'",wrapper)
  self.assertNotIn('def actor(',wrapper);self.assertNotIn('def cleanup(',wrapper);self.assertNotIn('def retain(',wrapper)
  self.assertIn("3000 if role=='lifecycle' else 900",raw.decode())
 def test_emitted_source_and_selected_source_pins_join(self):
  manifest=C.decode(C.read(C.HERE/'source-manifest.json'))
  for name,row in manifest['files'].items():self.assertEqual(C.checked(ROOT,dict(path=name,**row)),(ROOT/name).read_bytes())
  selected=C.decode(C.read(ROOT/'scripts/orphans/selected-source-pins.json'))
  for name,row in selected['files'].items():self.assertEqual(C.checked(ROOT,dict(path=name,**row)),(ROOT/name).read_bytes())
 def test_result_requires_actual_reason_preservation_and_single_commit_truth(self):
  normal=dict(status='PASS_SELECTED_CATALOG_ORPHAN_REMOVAL_IN_OWNED_COPY',prepared_add={},prepared_remove={'cachy-asahi-apps':'0.1.0-5'},commit_started=True,packages_committed=True,dependency_checks='ORDINARY_LIBALPM',selected=['cachy-asahi-apps'],retained_matching_signed_cache={'cachy-asahi-apps':{}})
  closure=dict(status='PASS-recorded-state-preserved',main_cache='RAW_EQUAL',auxiliary_transition={'kind':'RAW_EQUAL'},security_capabilities='EXACT_SOURCE_MAP_PRESERVED',source_capabilities_sha256='a'*64)
  installed=dict(prepared_add={'cachy-asahi-apps':'0.1.0-5','cachy-asahi-repository-runtime':'0.1.0-1'},plan_sha256='a'*64)
  for row in (normal,installed):row.update(full574_closure=copy.deepcopy(closure),cleanup='OWNED_WORKSPACE_TEMP_AND_ALPM_HANDLE_LOCK_RELEASED')
  pins={n:'a'*64 for n in ('tree_sha256','database_sha256','packages_sha256','inventory_sha256')}
  value=dict(status='PASS_NATIVE574_SELECTED_ORPHAN_CLEANUP',base_count=574,counts=[576,575],selected=['cachy-asahi-apps'],source_preserved=True,user_trust_protected_preserved=True,workspaces_disposed=True,hardware='NOT_RUN',rollback='NOT_CLAIMED',interrupted_copy='NOT_RUN_SEPARATE_ACTOR_REQUIRED',cases=dict(noop={'status':'NOT_APPLIED_NO_SELECTION'},cancel={'status':'CANCELLED_NOT_APPLIED'},foreign_lock={'status':'FAIL'},stale={'status':'FAIL'},normal=normal),case_preservation=dict(noop_cancel_foreign=dict(before=pins.copy(),after=pins.copy()),stale=dict(before=pins.copy(),after=pins.copy()),qualification='FULL_ROOT_DIGEST_EQUALITY_NOT_COMMIT_EVENT_PROOF'),actual_reason_graph={'cachy-asahi-apps':dict(candidate=True,reason='dependency',required_by=[],optional_required_by=[]),'cachy-asahi-repository-runtime':dict(reason='dependency',required_by=['cachy-asahi-apps'])},dependency_reason_readback='ACTUAL_PUBLIC_ALPM_ALLDEPS_AND_ORPHANS2_GRAPH',security_capabilities='EXACT_SOURCE_MAP_PRESERVED',source_capabilities_sha256='a'*64,transactions=[installed,normal],precommit_install_plan=dict(status='EXACT_AUTHENTICATED_APPS_RUNTIME_INSTALL_PLAN',plan_sha256='a'*64,additions=installed['prepared_add'],dependency='cachy-asahi-repository-runtime=0.1.0-1',archives={'cachy-asahi-apps':'b'*64,'cachy-asahi-repository-runtime':'c'*64}),after_reason_graph={**{'fixture-'+str(i):{} for i in range(574)},'cachy-asahi-repository-runtime':dict(reason='dependency',candidate=True,required_by=[],optional_required_by=[])})
  self.assertEqual(C.result(value),value)
  for change in ('reason','preservation','commit','recursive','now-orphan','plan'):
   bad=copy.deepcopy(value)
   if change=='reason':bad['actual_reason_graph']['cachy-asahi-apps']['reason']='explicit'
   elif change=='preservation':bad['case_preservation']['stale']['after']['tree_sha256']='b'*64
   elif change=='commit':bad['cases']['normal']['packages_committed']='UNKNOWN'
   elif change=='recursive':bad['cases']['normal']['prepared_remove']['cachy-asahi-repository-runtime']='0.1.0-1'
   elif change=='now-orphan':bad['after_reason_graph']['cachy-asahi-repository-runtime']['candidate']=False
   else:bad['precommit_install_plan']['plan_sha256']='d'*64
   with self.assertRaises(ValueError):C.result(bad)
 def stage_context(self,source):
  def checked_source(root):
   self.assertEqual(root,source)
   rows=C.decode(C.read(root/(C.LANE+'/source-manifest.json')))['files']
   for n,r in rows.items():C.checked(root,dict(path=n,**r))
  return NS(source=checked_source,LANE=C.LANE,safe=C.safe,need=C.need,read=C.read,decode=C.decode,checked=C.checked,sha=C.sha,encoded=C.encoded)
 def root_owner_observation(self,work):
  # Host tests are unprivileged: only UID/GID observations are simulated, never
  # chown, ALPM, a container or a root/native success claim. Bytes/modes/links real.
  original=Path.lstat
  def observed(path):
   row=original(path)
   if path==work or path.is_relative_to(work):
    values={n:getattr(row,n) for n in dir(row) if n.startswith('st_')};values.update(st_uid=0,st_gid=0);return NS(**values)
   return row
  return patch.object(Path,'lstat',observed)
 def test_exact_original_floor_reproduces_root_reader_foreign_checkout_refusal(self):
  names={'need','identity','read','limits','json_file','pairs','absolute','directory','floor'}
  tree=ast.parse((ROOT/'packages/tools/cachy-asahi-orphans/cachy-asahi-orphans').read_bytes())
  body=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom)) or isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names|{'Refused'}]
  ns=dict(__file__=str(ROOT/'packages/tools/cachy-asahi-orphans/cachy-asahi-orphans'),MAX_JSON=32*1024**2,FLOOR_SHA='0d6dfbf3cd550fe72ddad30058693007f8bb86214de1e83442580677db5005f2')
  exec(compile(ast.Module(body=body,type_ignores=[]),'<original-floor-read>','exec'),ns)
  original_fstat=os.fstat;original_stat=os.stat
  def owner(row,uid):
   fields={n:getattr(row,n) for n in dir(row) if n.startswith('st_')};fields['st_uid']=uid;return NS(**fields)
  for uid,refused in ((1001,True),(0,False)):
   with patch.object(os,'geteuid',return_value=0),patch.object(os,'fstat',side_effect=lambda fd:owner(original_fstat(fd),uid)),patch.object(os,'stat',side_effect=lambda *a,**kw:owner(original_stat(*a,**kw),uid)):
    if refused:
     with self.assertRaisesRegex(ValueError,'ordinary bounded single-link DB/input file required'):ns['floor']()
    else:self.assertIn('pacman',ns['floor']())
 def test_full_actual_frozen_source_stage_exact_bytes_modes_and_closure(self):
  with tempfile.TemporaryDirectory() as name:
   work=Path(name)/'work';work.mkdir(mode=0o700);api=self.stage_context(ROOT)
   with self.root_owner_observation(work):
    stage,receipt=S.copy(api,ROOT,work,'normal')
    self.assertEqual(receipt['file_count'],len(C.decode(C.read(ROOT/C.LANE/'source-manifest.json'))['files'])+1)
    self.assertEqual(receipt['staged'],str(work/'source-normal'));self.assertEqual(S.check(api,ROOT,stage,work),receipt)
    self.assertTrue(all(r['uid']==r['gid']==0 and r['links']==1 and r['mode']==0o644 for r in receipt['files'].values()))
    for n in receipt['files']:self.assertEqual((ROOT/n).read_bytes(),(stage/n).read_bytes())
    self.assertTrue((stage/'manifests/packages.toml').is_file());self.assertTrue((stage/'scripts/orphans/selected.py').is_file())
    selected=C.load('staged_selected_resolution_test',stage/'scripts/orphans/selected.py')
    self.assertEqual(selected.ROOT,stage);self.assertEqual(selected.T.ROOT,stage)
    self.assertEqual(Path(selected.O.__file__),stage/'packages/tools/cachy-asahi-orphans/cachy-asahi-orphans');self.assertIn('pacman',selected.O.floor())
    self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o700 for p in stage.rglob('*') if p.is_dir()))
    self.assertTrue(all(p.stat().st_uid==os.geteuid() for p in stage.rglob('*')))
    (stage/'unexpected').write_text('x')
    with self.assertRaisesRegex(ValueError,'undeclared'):S.check(api,ROOT,stage,work)
 def test_stage_refuses_hash_drift_hardlinks_symlinks_foreign_and_mixed_roles(self):
  with tempfile.TemporaryDirectory() as name:
   source=Path(name)/'source';work=Path(name)/'work';work.mkdir(mode=0o700);source.mkdir();lane=source/C.LANE;lane.mkdir(parents=True)
   file=source/'sample';file.write_bytes(b'original');rows={'sample':dict(bytes=8,sha256=C.sha(b'original'))}
   (lane/'source-manifest.json').write_bytes(C.encoded(dict(files=rows)));api=self.stage_context(source)
   with self.root_owner_observation(work):
    stage,receipt=S.copy(api,source,work,'interruption')
    with self.assertRaisesRegex(ValueError,'fresh'):S.copy(api,source,work,'interruption')
    with self.assertRaisesRegex(ValueError,'actor role'):S.copy(api,source,work,'other')
    with self.assertRaisesRegex(ValueError,'fixed stage sibling'):S.check(api,source,stage,work/'main')
    (stage/'sample').unlink();os.link(file,stage/'sample')
    with self.assertRaises(ValueError):S.check(api,source,stage,work)
    (stage/'sample').unlink();(stage/'sample').symlink_to(file)
    with self.assertRaises(ValueError):S.check(api,source,stage,work)
    (stage/'sample').unlink();(stage/'sample').write_bytes(b'original');(stage/'sample').chmod(0o600)
    with self.assertRaisesRegex(ValueError,'root-owned'):S.check(api,source,stage,work)
    (stage/'sample').chmod(0o644);file.write_bytes(b'drift!!!')
    with self.assertRaisesRegex(ValueError,'hash differs'):S.check(api,source,stage,work)
   with patch.object(S.os,'getuid',return_value=0),patch.object(S.os,'geteuid',return_value=0):
    for root in (Path('/source'),Path('/work/main'),stage,Path('/work/source-normal/child')):
     with self.assertRaisesRegex(ValueError,'explicit fixed'):S.validate(api,root)
   with self.assertRaisesRegex(ValueError,'root-owned'):S.owned(C,work,True)
 def test_native_rules_paths_and_cancel_are_explicit_staged_without_budget_changes(self):
  text=(C.HERE/'lifecycle.py').read_text();cancel=(C.HERE/'cancel.py').read_text();prepare=(C.HERE/'prepare.py').read_text()
  self.assertIn("RULES,stage_receipt=S.stage(C,'interruption' if '--interrupt' in sys.argv else 'normal')",text)
  self.assertEqual(text.count("str(C.HERE/'selected_fixture.py')"),2);self.assertEqual(text.count("'--staged-source',str(RULES)"),3)
  self.assertIn("readonly=str(RULES/'packages/tools/cachy-asahi-orphans/cachy-asahi-orphans')",text)
  self.assertIn("cancel,'--staged-source',str(RULES)",text);self.assertIn("'stage_source.py'",prepare)
  self.assertLess(cancel.index('stage.validate(C,a.staged_source)'),cancel.index("selected=C.load('selected_cancel'"))
  self.assertIn("a.staged_source/'scripts/orphans/selected.py'",cancel)
  self.assertIn('seconds=45',text);self.assertIn("H.backend('prepare-copy'",text);self.assertNotIn('O.floor=',text)
 def fixture_plan(self):
  raw=C.read(C.HERE/'cache-only-plan-39010123449.json');self.assertEqual(C.sha(raw),'76eb8b8e58eaa3ca5242deabb80ecc312af93e868e6779560c8c8881adb702cd')
  value=C.decode(raw);index=dict(packages={name:dict(version=version,files={'a':dict(sha256=sha)}) for name,version,sha in (
   ('cachy-asahi-apps','0.1.0-5','9ec47f6cf506c5d2b6da3ac6f4f42e00ce98b8d1985b1b9eca065c38058c1580'),
   ('cachy-asahi-repository-runtime','0.1.0-1','1c8a9149da02e60a4c14598cdf7007d6dbffcd6150757fcf6711977aa00cf8aa'))})
  return value,index
 def test_actual_retained_cache_only_plan_refuses_before_fixture_commit(self):
  value,index=self.fixture_plan();self.assertEqual(value['plan']['requested_applications'],['cache']);self.assertEqual(value['plan']['dependencies'],[])
  self.assertEqual([p['name'] for p in value['plan']['additions']],['cachy-asahi-cache'])
  checks=C.load('fixture_precommit_tests',C.HERE/'checks.py')
  with self.assertRaisesRegex(ValueError,'Apps dependency install'):checks.install_plan(C,value,index)
  # Even relabeling the old request cannot fabricate its absent Runtime addition.
  value['plan'].update(requested_applications=['apps'],requested_packages=['cachy-asahi-apps'])
  with self.assertRaisesRegex(ValueError,r'Apps\+Runtime additions'):checks.install_plan(C,value,index)
 def test_exact_apps_plan_requires_runtime_dependency_and_original_archive_pins(self):
  value,index=self.fixture_plan();relation='cachy-asahi-repository-runtime=0.1.0-1'
  value['plan'].update(requested_applications=['apps'],requested_packages=['cachy-asahi-apps'],dependencies=[dict(package='cachy-asahi-repository-runtime',required_by='cachy-asahi-apps',dependency=relation)],
    additions=[dict(name=n,version=r['version'],source='signed-release',release_archive_sha256=r['files']['a']['sha256'],depend=[relation] if n=='cachy-asahi-apps' else []) for n,r in index['packages'].items()])
  checks=C.load('fixture_precommit_positive_tests',C.HERE/'checks.py');proof=checks.install_plan(C,value,index)
  self.assertEqual(proof['plan_sha256'],C.sha(C.encoded(value)))
  self.assertEqual(proof['additions'],{'cachy-asahi-apps':'0.1.0-5','cachy-asahi-repository-runtime':'0.1.0-1'})
  for change in ('dependency','archive','extra','removal','version'):
   bad=copy.deepcopy(value)
   if change=='dependency':bad['plan']['additions'][0]['depend']=[]
   elif change=='archive':bad['plan']['additions'][0]['release_archive_sha256']='0'*64
   elif change=='extra':bad['plan']['additions'].append(copy.deepcopy(bad['plan']['additions'][0]))
   elif change=='removal':bad['plan']['removals']=[{}]
   else:bad['plan']['additions'][0]['version']='0.1.0-4'
   with self.subTest(change=change),self.assertRaises(ValueError):checks.install_plan(C,bad,index)
 def test_cache_foreign_lock_and_raw_cache_closure_fields_are_unchanged(self):
  lifecycle=(C.HERE/'lifecycle.py').read_text();checks=(C.HERE/'checks.py').read_text()
  self.assertIn("SOURCE/'packages/tools/cachy-asahi-cache/cachy-asahi-cache'",lifecycle)
  self.assertIn("closure.get('main_cache')=='RAW_EQUAL'",checks)
  self.assertEqual(C.VERSIONS,{'cachy-asahi-repository-runtime':'0.1.0-1','cachy-asahi-apps':'0.1.0-5','cachy-asahi-cache':'0.2.0-1','cachy-asahi-orphans':'0.1.0-1'})
if __name__=='__main__':unittest.main(verbosity=2)
