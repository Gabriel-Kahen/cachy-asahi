# SPDX-License-Identifier: MIT
"""Real private graphs and strict KSM selection/refusal controls; no native fixture."""
import copy,hashlib,json,os,stat,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path[:0]=[str(HERE),str(ROOT/'held-copy/scripts/update'),str(ROOT/'held-copy/scripts/apps')]
import contract as C,guard as G,physical,lifecycle,plan
import full_root as R,disposable_copy,file_capabilities as caps
class Worker(unittest.TestCase):
 def setUp(self):
  for name in('Popen','run'):
   p=patch.object(subprocess,name,side_effect=AssertionError('NO_ACTORS_GIT_API'));p.start();self.addCleanup(p.stop)
 def budget(self):return R.Limits(deadline=time.monotonic()+10,max_nodes=200,max_bytes=1024**2,max_file_bytes=1024**2)
 def test_null_authority_refuses_before_copy_or_actor_io(self):
  with self.assertRaisesRegex(ValueError,'NULL|UNSUPPLIED'):C.authority(C.decode(C.ordinary(HERE/'input-policy.json')),'copy-worker8','a'*32)
 def test_exact_lock_count606_one_substitution_and_removal605(self):
  raw=(HERE/'expected606.lock').read_bytes();base=dict(r.split()for r in raw.decode().splitlines());self.assertEqual(hashlib.sha256(raw).hexdigest(),C.LOCK);self.assertEqual(len(base),606);self.assertEqual(base[G.NAME],'0.1.0-1')
  after=dict(base);after[G.NAME]='0.1.0-2';G.inventory(after,base,'0.1.0-2');after.pop(G.NAME);G.inventory(after,base,None)
  for name in ('cachy-asahi-apps','cachy-asahi-welcome','cachy-asahi-dns','cachy-asahi-sysctl','cachy-asahi-repository-runtime'):
   wrong=dict(base);wrong[name]='FOREIGN'
   with self.assertRaises(ValueError):G.inventory(wrong,base)
 def test_real_copy_hardlinks_cap_map_disposal_and_source_wire_roundtrip(self):
  with tempfile.TemporaryDirectory()as td:
   src=Path(td)/'source';src.mkdir();(src/'dir').mkdir();(src/'dir/a').write_bytes(b'held');os.link(src/'dir/a',src/'dir/b');(src/'alias').symlink_to('dir/a')
   before=R.observe(src,limits=self.budget(),hardlinks='generic-development-internal');wire=C.decode(C.encoded(before));G.same_source(wire,before)
   with disposable_copy.copied_root(src,Path(td)/'owned',limits=self.budget())as(target,report):
    after=R.observe(target,limits=self.budget(),hardlinks='generic-development-internal');self.assertEqual(before['nodes'],after['nodes']);self.assertEqual((target/'dir/a').stat().st_ino,(target/'dir/b').stat().st_ino);self.assertEqual(caps.observe(src,before['nodes'],self.budget()),caps.observe(target,after['nodes'],self.budget()))
   self.assertEqual(report['cleanup'],'PASS-owned-workspace-removed');G.same_source(wire,R.observe(src,limits=self.budget(),hardlinks='generic-development-internal'))
 def test_copy_failure_disposes_only_target(self):
  with tempfile.TemporaryDirectory()as td:
   src=Path(td)/'source';src.mkdir();(src/'data').write_bytes(b'original')
   with self.assertRaisesRegex(RuntimeError,'inert'):
    with disposable_copy.copied_root(src,Path(td)/'owned',limits=self.budget())as(target,report):(target/'data').write_bytes(b'changed');raise RuntimeError('inert')
   self.assertEqual((src/'data').read_bytes(),b'original');self.assertFalse((Path(td)/'owned').exists());self.assertEqual(report['cleanup'],'PASS-owned-workspace-removed')
 def test_nonselected_rawdb_user_trust_content_and_mode_changes_refuse(self):
  selected='usr/bin/cachy-asahi-ksmctl';db='var/lib/pacman/local/cachy-asahi-ksmctl-0.1.0-1'
  for path in ('usr/bin/cachy-asahi-apps','var/lib/pacman/local/pacman-1/desc','home/alarm/user','etc/pacman.d/gnupg/trust'):
   before=dict(complete=True,nodes={selected:dict(type='file',mode=0o755),path:dict(type='file',mode=0o644,sha256='a'*64)},hardlink_groups={},unsupported_counts={})
   for field,value in(('mode',0o600),('sha256','b'*64)):
    after=copy.deepcopy(before);after['nodes'][path][field]=value
    with self.assertRaisesRegex(ValueError,'protected605'):G.target(before,after,old_paths=[selected],new_paths=[selected],old_database=db,new_database='var/lib/pacman/local/cachy-asahi-ksmctl-0.1.0-2')
 def test_real_nonselected_samebyte_inode_replacement_refuses(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'selected').write_bytes(b's');(root/'protected').write_bytes(b'p');before=R.observe(root,limits=self.budget());a=physical.capture(root,before['nodes'],self.budget());(root/'replacement').write_bytes(b'p');os.replace(root/'replacement',root/'protected');after=R.observe(root,limits=self.budget());b=physical.capture(root,after['nodes'],self.budget())
   with self.assertRaisesRegex(ValueError,'inode'):physical.protected(a,b,before['nodes'],after['nodes'],lambda n:n=='selected')
 def test_selected_db_regex_and_user_path_refuse(self):
  for path in ('home/alarm/data','etc/pacman.d/gnupg/key','var/lib/pacman/local/x/desc'):
   with self.assertRaises(ValueError):G.selected_paths([path])
  for db in ('var/lib/pacman/local/cachy-asahi-ksmctl-0.1.0-3','var/lib/pacman/local/cachy-asahi-apps-0.1.0-6'):
   with self.assertRaisesRegex(ValueError,'DB directory'):G.target(dict(nodes={}),dict(nodes={}),old_paths=['usr/bin/cachy-asahi-ksmctl'],new_paths=['usr/bin/cachy-asahi-ksmctl'],old_database=db,new_database=None)
 def test_native_payload7_restoration5_and_no_kernel_or_service_payload(self):
  self.assertEqual(len(C.OLD_FILES),5);self.assertEqual(len(C.KSM_FILES),7);self.assertEqual(C.KSM_FILES-C.OLD_FILES,{'usr/bin/cachy-asahi-ksm-experiment','usr/share/doc/cachy-asahi-ksmctl/experiment-provenance.json'});self.assertFalse(any(n.startswith(('sys/','etc/','usr/lib/systemd/'))for n in C.KSM_FILES))
  self.assertEqual(lifecycle.PHASES,(('baseline1','0.1.0-1'),('upgrade2','0.1.0-2'),('same-version2','0.1.0-2'),('remove2',None),('reinstall2','0.1.0-2'),('restore-original1','0.1.0-1')))
 def test_no_public_carrier_assumption_and_exact_caps_mounts_budgets(self):
  p=C.decode(C.ordinary(HERE/'prerequisite-pins.json'));self.assertIsNone(p['carrier_source']);self.assertEqual(p['status'],'LOCAL_SOURCE_ONLY_NOT_PUBLIC');self.assertEqual((C.COPY_SECONDS,C.WORKER_SECONDS,C.CLEANUP_SECONDS),(600,1800,60));self.assertEqual(C.WORKER_MASK,0x800400db)
  mounts=[dict(source='/owned/'+name,target='/'+name,readonly=name in('runner','seed','bridge-proof'))for name in('runner','seed','bridge-proof','work','out')];C.bindings(mounts);mounts[1]['readonly']=False
  with self.assertRaises(ValueError):C.bindings(mounts)
 def test_complete_db_mapping_optional_reason_and_unknown_fields_refuse(self):
  # Typed inert schema operands only; no signature/ALPM/native success fixture.
  metadata={'pkgname':['cachy-asahi-ksmctl'],'pkgver':['0.1.0-2'],'arch':['any'],'size':['1'],'builddate':['1'],'packager':['INERT_SCHEMA_CONTROL'],'xdata':['pkgtype=pkg']}
  source=dict(INSTALLDATE=['1'],VALIDATION=['pgp']);value=plan.fields(metadata,source);self.assertNotIn('REASON',value);self.assertEqual(value['XDATA'],['pkgtype=pkg'])
  explicit=dict(source,REASON=['0']);self.assertEqual(plan.fields(metadata,explicit)['REASON'],['0'])
  for wrong in (dict(source,REASON=['1']),dict(source,FOREIGN=['unknown']),dict(INSTALLDATE=['1'],VALIDATION=['none']),dict(INSTALLDATE=['1'])):
   with self.assertRaises(ValueError):plan.fields(metadata,wrong)
 def test_restore_uses_original_row_not_native_same_version_substitute(self):
  original=dict(version='0.1.0-1',sha256='a'*64,payload={n:{}for n in C.OLD_FILES});original['source_record']=dict(version=original['version'],sha256=original['sha256'],payload=original['payload'])
  candidate=dict(version='0.1.0-2',sha256='bac3d222b6490412c1c9c7bafd72d8169e8679a1e7b411b5794246aed0b57b5f',payload={n:{}for n in C.KSM_FILES})
  # Refusal requires no successful package or real606 fixture.
  wrong=copy.deepcopy(original);wrong['source_record']['sha256']='b'*64
  with self.assertRaises(ValueError):lifecycle.operands(wrong,candidate,original606_manifest={G.NAME:original['source_record']})

class SignedTransactionLimits(unittest.TestCase):
 def test_actual_pinned_constructor_missing_limits_refuses_before_ALPM(self):
  with patch.object(R.installer.Alpm,'__init__',side_effect=AssertionError('NO_NATIVE_ALPM')):
   with self.assertRaisesRegex(TypeError,'limits'):R.Alpm(Path('/INERT'),Path('/INERT'),Path('/INERT'),'aarch64')
 def test_real_apply_passes_exact_single_bounded_limits_before_native_ALPM(self):
  import alpm_step as S
  class StopBeforeNative(Exception):pass
  captured=[]
  def stop(handle,*args,**kwargs):
   captured.append(handle.limits);raise StopBeforeNative()
  before={f'held-{i}':'1-1'for i in range(605)};before['cachy-asahi-ksmctl']='0.1.0-1';after={k:v for k,v in before.items()if k!='cachy-asahi-ksmctl'}
  with tempfile.TemporaryDirectory()as td:
   info=os.stat(td)
   with patch.object(R.installer.Alpm,'__init__',new=stop),patch.object(S.Path,'stat',return_value=info),patch.object(S.os,'listdir',return_value=[]),patch.object(S.time,'monotonic',return_value=100.):
    with self.assertRaises(StopBeforeNative):S.apply('/work/main/root',before=before,after=after,archive=None,keys='/work/test-verification',log='/out/remove2-alpm.log')
  self.assertEqual(len(captured),1);limits=captured[0];self.assertIsInstance(limits,R.Limits);self.assertEqual(limits.deadline,190.)
  for name,value in C.BOUNDS.items():self.assertEqual(getattr(limits,name),value)
 def test_both_handles_share_one_original90s606_limits_and_guard(self):
  import ast,inspect,alpm_step as S,driver
  tree=ast.parse(inspect.getsource(S.apply));calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='Alpm']
  self.assertEqual(len(calls),2)
  for call in calls:
   self.assertEqual([(v.arg,ast.unparse(v.value))for v in call.keywords],[('limits','limits')])
  limits=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='Limits'];self.assertEqual(len(limits),1)
  self.assertEqual(ast.unparse(limits[0]),'roots.Limits(deadline=time.monotonic() + 90, **C.BOUNDS)')
  raw=inspect.getsource(driver.run);self.assertIn('timeout=min(90,budget.deadline-time.monotonic())',raw);self.assertIn('output_limit=128*1024,grace=1',raw)
  self.assertIn("C.need(result['returncode']==0 and result['termination']is None and result['direct_child_reaped']and result['group_retired'],'signed transaction child failed or group not retired')",raw)

if __name__=='__main__':unittest.main(verbosity=2)
