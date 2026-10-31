#!/usr/bin/env python3
"""Real private files and mocked HTTP only, never a native accepting fixture."""
import copy,hashlib,importlib.util,io,json,os,stat,subprocess,sys,tempfile,unittest,urllib.error
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import archive32 as A
class Reply(io.BytesIO):
 status=200
 def __init__(self,data,url,headers=None):super().__init__(data);self.url=url;self.headers={'Content-Length':str(len(data)),**(headers or{})}
 def geturl(self):return self.url
class Clock:
 def __init__(self):self.now=0;self.sleeps=[]
 def monotonic(self):return self.now
 def sleep(self,n):self.sleeps.append(n);self.now+=n
class Controls(unittest.TestCase):
 def tiny(self):
  data={'a.pkg':b'one','a.pkg.sig':b'two'}
  v=dict(files={n:dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),url='https://pkgmirror.sametimetomorrow.net/'+n)for n,b in data.items()},original_inputs=dict(bytes=1,sha256='0'*64));return v,data
 def test_real_policy_matches_whole_frozen574_lock(self):
  root=Path(__file__).resolve().parents[3];v=A.policy(A.HERE/'archive32-policy.json',root/'runtime/borrowed/maintained574-inputs.json');self.assertEqual((len(v['files']),sum(r['bytes']for r in v['files'].values())),(32,209001064))
 def test_private_download_reuse_and_seed_are_exact_no_overwrite(self):
  v,data=self.tiny();clock=Clock();calls=[]
  with tempfile.TemporaryDirectory()as t,patch.object(A,'TOTAL',6),patch.object(A.time,'monotonic',clock.monotonic),patch.object(A.time,'sleep',clock.sleep):
   cache=Path(t)/'cache';deps=Path(t)/'deps';deps.mkdir(mode=0o700)
   def op(req,timeout):calls.append(req.full_url);return Reply(data[req.full_url.rsplit('/',1)[1]],req.full_url)
   r=A.prefetch(cache,v,op);self.assertEqual((r['requests'],len(calls)),(2,2));self.assertEqual(clock.sleeps,[2]);A.prefetch(cache,v,lambda *a,**k:self.fail('cache redownload'));A.seed_exact(cache,deps,v)
   self.assertEqual({p.name:p.read_bytes()for p in deps.iterdir()},data);A.seed_exact(cache,deps,v)
   (deps/'a.pkg').write_bytes(b'BAD')
   with self.assertRaisesRegex(ValueError,'hash'):A.seed_exact(cache,deps,v)
   self.assertEqual((deps/'a.pkg').read_bytes(),b'BAD')
 def test_429_retry_after_paced_and_bounded(self):
  v,data=self.tiny();clock=Clock();calls=[]
  with tempfile.TemporaryDirectory()as t,patch.object(A,'TOTAL',6),patch.object(A.time,'monotonic',clock.monotonic),patch.object(A.time,'sleep',clock.sleep):
   def op(req,timeout):
    calls.append(req.full_url)
    if len(calls)==1:raise urllib.error.HTTPError(req.full_url,429,'limited',{'Retry-After':'3'},None)
    return Reply(data[req.full_url.rsplit('/',1)[1]],req.full_url)
   r=A.prefetch(Path(t)/'cache',v,op);self.assertEqual(r['requests'],3);self.assertEqual(clock.sleeps,[3,2])
   for bad in('31','999999','-1','missing'):
    with self.assertRaises((ValueError,TypeError)):A.retry_delay(bad)
 def test_429_no_header_generic_error_redirect_and_body_pin_refuse(self):
  v,data=self.tiny()
  for kind in('429','404','redirect','over','hash','encoding'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory()as t,patch.object(A,'TOTAL',6):
    cache=Path(t)/'cache'
    def op(req,timeout):
     if kind in('429','404'):raise urllib.error.HTTPError(req.full_url,int(kind),'no',{},None)
     return Reply(b'BAD'if kind=='hash'else b'over'if kind=='over'else data[req.full_url.rsplit('/',1)[1]],req.full_url+'/foreign'if kind=='redirect'else req.full_url,{'Content-Encoding':'gzip'}if kind=='encoding'else{})
    with self.assertRaises(ValueError):A.prefetch(cache,v,op)
    self.assertFalse(any(p.name.startswith('.archive32-')for p in cache.iterdir()))
 def test_owned_cache_alias_hardlink_unknown_mode_and_drift_refuse(self):
  v,data=self.tiny()
  for kind in('alias','hardlink','unknown','mode','drift'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory()as t:
    root=Path(t);cache=root/'cache';cache.mkdir(mode=0o700);p=cache/'a.pkg';p.write_bytes(data['a.pkg'])
    if kind=='alias':p.unlink();p.symlink_to(root/'outside')
    elif kind=='hardlink':os.link(p,root/'alias')
    elif kind=='unknown':(cache/'foreign').write_bytes(b'keep')
    elif kind=='mode':cache.chmod(0o755)
    else:p.write_bytes(b'BAD')
    with self.assertRaises((ValueError,FileNotFoundError)):A.prefetch(cache,v,lambda *a,**k:self.fail('network before refusal'))
    if kind=='unknown':self.assertEqual((cache/'foreign').read_bytes(),b'keep')
 def test_deadline_request_budget_and_owned_partial_cleanup(self):
  v,data=self.tiny();clock=Clock()
  with tempfile.TemporaryDirectory()as t,patch.object(A.time,'monotonic',clock.monotonic),patch.object(A.time,'sleep',clock.sleep):
   class Slow(Reply):
    def read(self,n=-1):clock.now=181;return super().read(n)
   with self.assertRaisesRegex(ValueError,'deadline'):A.prefetch(Path(t)/'cache',v,lambda req,timeout:Slow(b'one',req.full_url))
   self.assertEqual(list((Path(t)/'cache').iterdir()),[])
  with tempfile.TemporaryDirectory()as t,patch.object(A,'MAX_REQUESTS',0):
   with self.assertRaisesRegex(ValueError,'request count'):A.prefetch(Path(t)/'cache',v,lambda *a,**k:self.fail('request'))
 def test_fresh_identity_and_whole_policy_tamper_refuse(self):
  with tempfile.TemporaryDirectory()as t:
   p=Path(t)/'file';p.write_bytes(b'one');row=dict(bytes=3,sha256=hashlib.sha256(b'one').hexdigest());original=A.os.read
   def drift(fd,n):
    b=original(fd,n)
    if b:p.chmod(0o400)
    return b
   with patch.object(A.os,'read',side_effect=drift),self.assertRaisesRegex(ValueError,'identity'):A.digest_file(p,row)
   root=Path(__file__).resolve().parents[3];policy=json.loads((A.HERE/'archive32-policy.json').read_bytes());lock=root/'runtime/borrowed/maintained574-inputs.json'
   for kind in('foreign-host','wrong-pin','unsupported-date','credential'):
    value=copy.deepcopy(policy);name=next(iter(value['files']));r=value['files'][name]
    if kind=='foreign-host':r['url']=r['url'].replace('pkgmirror.sametimetomorrow.net','foreign.invalid')
    elif kind=='wrong-pin':r['sha256']='0'*64
    elif kind=='unsupported-date':r['url']=r['url'].replace('/2026/10/13/','/2026/10/17/')
    else:r['url']=r['url'].replace('https://','https://user:pass@')
    trial=Path(t)/'policy';trial.write_bytes(A.encoded(value))
    with self.assertRaises(ValueError):A.policy(trial,lock)
 def test_cli_cache_operand_and_fixed_custody_retention_interface(self):
  import entry,retain
  root=Path(__file__).resolve().parents[3];argv=['entry.py','run','--source',str(root)]
  for key in('native','kernel','seed','inputs','work'):argv+=['--'+key,'/inert/'+key]
  class Target:
   @staticmethod
   def run(a):
    self.assertEqual(a.archive_cache,Path('/inert/archive'));return {'interface':'ONLY_NO_ACTOR_NO_ACCEPTANCE'}
  with patch.object(entry.O,'prove',return_value={'interface':'NO_ACTUAL_PROOF'}),patch.object(entry.O,'selected',side_effect=lambda v:v),patch.object(entry.O,'load',return_value=Target),patch.object(sys,'argv',argv+['--archive-cache','/inert/archive']):
   self.assertEqual(entry.main(),{'interface':'ONLY_NO_ACTOR_NO_ACCEPTANCE'})
  with patch.object(entry.O,'prove',return_value={'interface':'NO_ACTUAL_PROOF'}),patch.object(entry.O,'selected',side_effect=lambda v:v),patch.object(entry.O,'load',side_effect=AssertionError('missing cache before owner')),patch.object(sys,'argv',argv),self.assertRaisesRegex(ValueError,'explicit owned'):entry.main()
  with tempfile.TemporaryDirectory()as t:
   work=Path(t)/'work';work.mkdir(mode=0o700);(work/'archive32-custody.json').write_bytes(b'{"interface":"DATA_ONLY"}');(work/'unretained-package.pkg').write_bytes(b'NOT_EXPORTED');out=Path(t)/'public';r=retain.run(work,out);self.assertEqual(set(r['files']),{'archive32-custody.json'});self.assertFalse((out/'unretained-package.pkg').exists())
 def test_no_redirect_proxy_or_credential_retry_path(self):
  with self.assertRaisesRegex(ValueError,'redirect'):A.NoRedirect().redirect_request(None,None,None,None,None,None)
  self.assertEqual(A.retry_delay('0'),0)
 def test_actual_workflow_policy_operand_under_foreign_cwd_before_any_network(self):
  import shlex
  root=Path(__file__).resolve().parents[3];text=(root/'.github/workflows/native-arm-ksm2-generic16k.yml').read_text();start=text.index('      - name: Prefetch exact32');block=text[start:text.index('      - name:',start+10)];command=block.split('        run: >-\n',1)[1];command=' '.join(line.strip()for line in command.splitlines()if line.startswith('          '))
  script=r'''import runpy,sys,types,urllib.request
mode=sys.argv[1];sys.argv=[sys.argv[2],*sys.argv[3:]];calls=[]
def blocked(*args,**kwargs):
 calls.append(1);raise RuntimeError('NETWORK_FORBIDDEN_AFTER_VALIDATED_POLICY')
urllib.request.build_opener=lambda *args:types.SimpleNamespace(open=blocked)
try:runpy.run_path(sys.argv[0],run_name='__main__')
except ValueError as error:
 assert mode=='relative'and str(error)=='ordinary archive32 path'and not calls;print('ORIGINAL_RELATIVE_REFUSED_BEFORE_NETWORK')
except RuntimeError as error:
 assert mode=='absolute'and str(error)=='NETWORK_FORBIDDEN_AFTER_VALIDATED_POLICY'and calls==[1];print('ABSOLUTE_POLICY_AND_LOCK_VALIDATED_NETWORK_BLOCKED')
else:raise AssertionError('No real CLI refusal')
'''
  with tempfile.TemporaryDirectory()as t:
   for mode in('relative','absolute'):
    expanded=command.replace('$GITHUB_WORKSPACE',str(root)).replace('$SLICE','scripts/ci/ksm2-generic16k-vm-hosted').replace('$RUNNER_TEMP',t);argv=shlex.split(expanded);self.assertEqual(argv[:3],['python3','-I','-B']);helper=Path(argv[3]);helper=helper if helper.is_absolute()else root/helper;args=argv[4:];position=args.index('--policy')+1
    self.assertTrue(Path(args[position]).is_absolute());self.assertEqual(Path(args[position]),root/'scripts/ci/ksm2-generic16k-vm-hosted/archive32-policy.json')
    if mode=='relative':args[position]='scripts/ci/ksm2-generic16k-vm-hosted/archive32-policy.json'
    row=subprocess.run([sys.executable,'-I','-B','-c',script,mode,str(helper),*args],cwd=t,capture_output=True,timeout=10);self.assertEqual(row.returncode,0,(row.stdout,row.stderr));self.assertEqual(row.stderr,b'');self.assertIn(b'ORIGINAL_RELATIVE_REFUSED_BEFORE_NETWORK'if mode=='relative'else b'ABSOLUTE_POLICY_AND_LOCK_VALIDATED_NETWORK_BLOCKED',row.stdout)
if __name__=='__main__':unittest.main(verbosity=2)
