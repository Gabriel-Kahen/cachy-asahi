"""Finite source controls plus opt-in real full574 source-held copy/fetch control."""
import hashlib,importlib.util,json,os,shutil,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];sys.path.insert(0,str(HERE));import retained_cache as M
class Controls(unittest.TestCase):
 def test_whole_profile_exact_original574_and_before80(self):
  p=M.profile();raw=M.read(ROOT/'scripts/ci/maintained-desktop574-inputs.json',1024**2);self.assertEqual(M.pin(raw),p['original574_lock']);rows=json.loads(raw)['packages'];pins={}
  for r in rows:pins[r['filename']]=dict(bytes=r['size'],sha256=r['sha256']);pins[r['filename']+'.sig']=dict(bytes=r['signature_size'],sha256=r['signature_sha256'])
  self.assertEqual(pins,p['inputs']);self.assertEqual(len(pins),1148);self.assertEqual(sum(v['bytes']for v in pins.values()),1045287299);self.assertEqual(len(p['before_inputs']),80);self.assertEqual(M.pin(M.read(ROOT/'scripts/ci/maintained_desktop574.py')),p['producer'])
 def test_original2300_wrapper_and_fixed_path_refuse_before_exec(self):
  with patch.object(sys,'argv',['retained_cache.py','wrong']),patch.object(M.os,'execve',side_effect=AssertionError('no exec')):
   with self.assertRaisesRegex(ValueError,'producer argv'):M.main()
  with tempfile.TemporaryDirectory()as td:
   path=Path(td)/'native574-recovered-inputs';path.mkdir()
   with self.assertRaisesRegex(ValueError,'separate fixed external'):M.prove(path,time.monotonic()+30,M.profile(),root=Path(td))
 def test_main_preserves_original_build_args_identity_receipt_and_exec(self):
  with tempfile.TemporaryDirectory()as td:
   workspace=Path(td);root=workspace/'repair-source';ci=root/'scripts/ci';ci.mkdir(parents=True);shutil.copyfile(ROOT/'scripts/ci/maintained_desktop574.py',ci/'maintained_desktop574.py');shutil.copyfile(ROOT/'scripts/ci/maintained-desktop574-inputs.json',ci/'maintained-desktop574-inputs.json');runner=workspace/'runner';runner.mkdir();out=runner/'desktop574';before=Path.cwd();os.chdir(root)
   self.addCleanup(os.chdir,before);args=['build','--inputs','scripts/ci/maintained-desktop574-inputs.json','--output',str(out),'--job-token','a'*16];env=dict(GITHUB_WORKSPACE=str(workspace),RUNNER_TEMP=str(runner),SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',REPAIR_CASE='repair-bytes')
   with patch.object(M,'ROOT',root),patch.object(M,'seed',return_value=dict(status='REPAIR_FULL574_CACHE_JOINED_NOT_AUTHENTICATED'))as seeded,patch.object(sys,'argv',['retained_cache.py',*args]),patch.dict(os.environ,env),patch.object(M.os,'execve',side_effect=SystemExit(0))as execute:
    with self.assertRaises(SystemExit):M.main()
   with patch.object(M,'ROOT',root),patch.object(M,'seed',side_effect=AssertionError('no cache write before source identity')),patch.object(sys,'argv',['retained_cache.py',*args]),patch.dict(os.environ,dict(env,SOURCE_SHA='b'*40)):
    with self.assertRaisesRegex(ValueError,'source/workflow/run/case identity'):M.main()
   call=execute.call_args.args;self.assertEqual(call[0],sys.executable);self.assertEqual(call[1],[sys.executable,'-I','-B',str(ci/'maintained_desktop574.py'),*args]);self.assertEqual(call[2]['SOURCE_SHA'],'a'*40);self.assertEqual(seeded.call_args.args[:2],(out/'context/deps',workspace/'native574-recovered-inputs'));receipt=json.loads((runner/'repair16k-retained-cache.json').read_bytes());self.assertEqual(receipt['identity'],dict(source='a'*40,run=123,attempt=1,case='repair-bytes'))
 @unittest.skipUnless(os.environ.get('REPAIR574_CONTROL_CARRIER'),'explicit real external carrier required')
 def test_real80_to1148_full_Git_shape_maps_and_original_fetch_network_denied(self):
  carrier=Path(os.environ['REPAIR574_CONTROL_CARRIER']).absolute();p=M.profile();p=dict(p,checkout=carrier.name);budget=time.monotonic()+2300
  # Test staging path only differs. Every physical leaf, committed tree/blob
  # join and original seeder still runs; the transport is local and actor-free.
  def git(path,*args,deadline):
   M.tick(deadline)
   if args==('rev-parse','HEAD'):return(p['source']+'\n').encode()
   if args==('ls-tree','-rz','--full-tree',p['source']):
    rows=[]
    for name in p['files']:
     raw=M.read(carrier/name);oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest();rows.append(b'100644 blob '+oid.encode()+b'\t'+name.encode()+b'\0')
    return b''.join(rows)
   self.assertEqual(args[:2],('cat-file','blob'));return M.read(carrier/args[2].split(':',1)[1])
  with tempfile.TemporaryDirectory(prefix='repair574-real-cache-')as td:
   out=Path(td)/'desktop574';cache=out/'context/deps';cache.mkdir(parents=True,mode=0o700);cache.chmod(0o700)
   for name in p['before_inputs']:shutil.copyfile(carrier/'packages'/name,cache/name)
   before={n:M.KEY((cache/n).lstat())for n in p['before_inputs']}
   with patch.object(M,'profile',return_value=p),patch.object(M,'git',side_effect=git),patch.object(M.subprocess,'Popen',side_effect=AssertionError('no Git/API/actors')):receipt=M.seed(cache,carrier,budget)
   self.assertEqual(receipt['seed']['cache']['added'],1068);self.assertEqual(receipt['seed']['cache']['before_files'],p['before_inputs']);self.assertEqual(len(receipt['seed']['cache']['after_files']),1148);self.assertFalse(receipt['actual_authority']);self.assertEqual(before,{n:M.KEY((cache/n).lstat())for n in before})
   spec=importlib.util.spec_from_file_location('_unchanged_repair574_producer',ROOT/'scripts/ci/maintained_desktop574.py');producer=importlib.util.module_from_spec(spec);spec.loader.exec_module(producer);items=producer.plan(json.loads(M.read(ROOT/'scripts/ci/maintained-desktop574-inputs.json',1024**2)),out/'context');selected=[r for r in items if r['target'].parent==cache];self.assertEqual(len(selected),1148)
   def denied(*a,**k):raise AssertionError('network denied for every original1148 package/signature')
   for item in selected:self.assertEqual(producer.fetch(item,opener=denied)['source'],'existing_exact_seed')
   with patch.object(M,'profile',return_value=p),patch.object(M,'prove',return_value={}):
    with self.assertRaisesRegex(ValueError,'preexisting cache'):M.seed(cache,carrier,budget)
if __name__=='__main__':unittest.main(verbosity=2)
