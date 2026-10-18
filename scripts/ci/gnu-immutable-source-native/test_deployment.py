"""Finite source/inert-transport controls; no accepting VM or fabricated boot."""
import argparse,copy,io,json,os,shutil,subprocess,sys,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import deploy as D,binding,kernel_input as K,runtime_adapter,entry
ROOT=D.ROOT
class Tests(unittest.TestCase):
 def test_actual_current_owner_preparer_and_lifecycle_compose(self):
  v=entry.source(ROOT);self.assertEqual(v['current_provider'],'a8e9_CAA3');self.assertEqual(v['native_owner_seams'],9);self.assertIn('transaction',v['original_lifecycle_bodies_held'])
 def test_default_boot_refuses_before_output_API_or_environment(self):
  with tempfile.TemporaryDirectory()as td,patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):
   out=Path(td)/'out'
   # Exactly invert the explicitly selected boot DATA operands for this one
   # original NULL-default assertion; all source/custody assertions stay live.
   original=D.obj(D.read(ROOT/D.LANE/'input-policy.json'))
   if original['boot_decision']is None:
    with self.assertRaisesRegex(ValueError,'NULL'):binding.build(ROOT,out,{})
   else:
    with self.assertRaisesRegex(ValueError,'genuine first native'):binding.build(ROOT,out,{})
    null=dict(original,boot_decision=None,boot_projection=None)
    def read(path,*args):
     if Path(path)==ROOT/D.LANE/'input-policy.json':return D.encoded(null)
     return before(path,*args)
    before=D.read
    with patch.object(D,'read',side_effect=read):
     with self.assertRaisesRegex(ValueError,'NULL'):binding.boot(ROOT)
   self.assertFalse(out.exists())
 def test_real_Root_kernel20_provenance_and_whole_reader_source(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):
   k,v=K.known();self.assertEqual(len(k['members']),30);self.assertEqual(v['configuration'],dict(active_changes=14,delta=dict(bytes=1582,sha256='8e074cfb3bab7a59e876b2b80d73fbcd7d1832949f60fb4e10e933aaa828087d'),inactive_domain=189))
   with K.reader()as R:self.assertEqual(R.SOURCE,k['source']);self.assertEqual(R.RUN,k['run'])
 def test_selected_boot_exact_identity_and_no_mapping_credit(self):
  p=D.obj(D.read(ROOT/D.LANE/'input-policy.json'))
  if p['boot_decision']is None:
   with self.assertRaises(ValueError):binding.boot(ROOT)
  else:
   raw,projected=binding.boot(ROOT);v=D.obj(projected)
   self.assertEqual([v[n]for n in('verity_mapping','integrity','lifecycle')],['NOT_QUALIFIED']*3)
   import boot_binding
   k,_=K.known();result=D.read(ROOT/D.LANE/'Root-boot-strict.json')
   for data in(raw+b' ',D.encoded(dict(D.obj(raw),source='0'*40))):
    with self.assertRaises(ValueError):boot_binding.projection(data,result,k)
 def test_bootstrap_requires_fresh_writer_witness_not_prior_Root_literal(self):
  I=binding.runtime(ROOT);module=D.load('_immutable_writer_refusal',ROOT/'runtime/immutable/bootstrap_loader.py')
  for v in(None,dict(status='ROOT_VERIFIED_SOURCE_PRODUCERS_RETIRED',source='7d7ccbcb7b5a170999716ed640285806b7cab9bb'),{}):
   with self.assertRaises(ValueError):module.writer_retired(v)
  raw=D.read(ROOT/'runtime/immutable/bootstrap_loader.py');self.assertIn(b'data.replace(old,new)',raw);self.assertIn(b'writer_retired=writer_retired',raw)
 def test_fresh_writer_guard_requires_nonempty_actual_retired_reports(self):
  import pipeline,types
  v=dict(status='PASS_LIFECYCLE_PENDING_ORDERED_PRODUCER_CLEANUP',actors=[],commands=[])
  with patch.object(pipeline,'owner',return_value=types.SimpleNamespace(read=lambda p:v)):
   with self.assertRaisesRegex(ValueError,'writers retired'):pipeline.native_writer_retirement(ROOT,Path('/INERT'))
 def test_one_acquisition_intent_failure_no_retry_or_partial_reuse(self):
  with tempfile.TemporaryDirectory()as td:
   parent=Path(td);parent.chmod(0o700);out=parent/'acquire';calls=[]
   def fail(*a):calls.append(a[0]);raise OSError('INERT_NO_NETWORK')
   with self.assertRaises(OSError):K.acquire(out,fetch=fail,token='INERT')
   self.assertEqual(len(calls),1);self.assertTrue((out/'acquisition-failure.json').is_file());self.assertFalse((out/'artifact.zip').exists())
   with self.assertRaises(ValueError):K.acquire(out,fetch=lambda *a:self.fail('retry'),token='INERT')
 def test_foreign_read_endpoint_refuses_before_subprocess(self):
  with patch.object(subprocess,'run',side_effect=AssertionError('NO_API')):
   for endpoint in('https://foreign.invalid/data','repos/foreign/repo/actions/runs/39156901928','repos/Gabriel-Kahen/cachy-asahi/actions/artifacts/12147995918/zip'):
    with self.assertRaises(ValueError):K.get(endpoint,Path('/tmp/never-created'),1,1,'INERT')
 def test_partial_changed_fresh_API_never_reaches_artifact_download(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'acquire';calls=[]
   def bad(endpoint,path,*args):calls.append(endpoint);path.write_bytes(b'{}')
   with self.assertRaises((ValueError,KeyError)):K.acquire(out,fetch=bad,token='INERT')
   self.assertEqual(len(calls),2);self.assertFalse((out/'artifact.zip').exists())
 def test_missing_or_foreign_artifact_members_rejected_data_only(self):
  with K.reader()as R:
   for name in('Image','../Image','unapproved.py'):
    b=io.BytesIO()
    with zipfile.ZipFile(b,'w')as z:z.writestr(name,b'INERT_NOT_A_KERNEL')
    with self.assertRaises(ValueError):R.archive_files(b.getvalue())
 def test_typed_runtime_derivative_inverse_and_full_roles_held(self):
  p=D.obj(D.read(ROOT/D.LANE/'runtime-derivation.json'));basis=D.obj(D.read(ROOT/D.LANE/'runtime-basis.json',2*1024**2));self.assertEqual(p['basis_files'],667)
  for n,row in p['changed'].items():
   raw=D.read(ROOT/'runtime'/n,4*1024**2);self.assertEqual(D.pin(raw),row['after'])
   if type(row['inverse'])is list:
    for e in reversed(row['inverse']):self.assertEqual(raw.decode().count(e['new']),e['count']);raw=raw.replace(e['new'].encode(),e['old'].encode())
    self.assertEqual(D.pin(raw),row['before'])
  for n,v in basis.items():
   if n not in p['changed']:self.assertEqual(D.pin(D.read(ROOT/'runtime'/n,16*1024**2)),v)
 def test_closed_source_allows_only_topGit_metadata(self):
  with tempfile.TemporaryDirectory()as td:
   def top_metadata(folder,names):return {'.git'}if Path(folder)==ROOT else set()
   self.assertEqual(top_metadata(ROOT/'runtime',['.git']),set())
   root=Path(td)/'source';shutil.copytree(ROOT,root,ignore=top_metadata);(root/'.git').mkdir();(root/'.git/config').write_text('INERT_METADATA');D.source(root)
   (root/'.git/config').unlink();(root/'.git').rmdir();(root/'.git').write_text('gitdir: INERT_NOT_FOLLOWED');D.source(root)
   for extra in(root/'.git-shadow',root/'runtime/.git'):
    extra.write_text('INERT_UNEXPECTED')
    with self.assertRaises(ValueError):D.source(root)
    extra.unlink()
   (root/'extra').write_text('INERT')
   with self.assertRaises(ValueError):D.source(root)
   (root/'extra').unlink();(root/'alias').symlink_to(root/'runtime',target_is_directory=True)
   with self.assertRaises(ValueError):D.source(root)
 def test_exact_archive32_original_lock_profile(self):
  A=D.load('_immutable_archive32_test',ROOT/D.LANE/'archive32.py');v=A.policy(ROOT/D.LANE/'archive32-policy.json',ROOT/D.VM/'scripts/ci/maintained-desktop574-inputs.json');self.assertEqual(len(v['files']),32);self.assertEqual(sum(r['bytes']for r in v['files'].values()),209001064)
 def test_generated_workflow_source_gate_acquisition_and_seed_order(self):
  w=D.read(ROOT/'.github/workflows/native-arm-build.yml').decode();self.assertIn('  actions: read\n',w);self.assertIn('timeout-minutes: 360',w)
  names=('Whole source and maintained phase','Genuine independent boot','Acquire exact existing kernel20','Seed the six existing','Seed exact32 verified','Reuse unchanged owned574','Snapshot original574','Actual new-purpose immutable','Retire all new and native')
  positions=[w.index(n)for n in names];self.assertEqual(positions,sorted(positions));self.assertNotIn('rust6',w.lower());self.assertIn('2300s',w);self.assertIn('timeout-minutes: 220',w)
 def test_unknown_consumer_state_keeps_original_producer(self):
  import pipeline
  with tempfile.TemporaryDirectory()as td:
   out=Path(td);(out/'owner.json').write_text('{"consumer_cleanup":"UNKNOWN"}')
   a=argparse.Namespace(source=ROOT,output=out,proof=None,base=None,owner=None,receipt=None)
   with patch.object(pipeline,'owner',side_effect=AssertionError('NO_PRODUCER_CLEANUP')):
    with self.assertRaisesRegex(ValueError,'unknown new consumer'):pipeline.cleanup(a)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,default=D.ROOT);a,rest=p.parse_known_args();ROOT=a.source.absolute();unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
