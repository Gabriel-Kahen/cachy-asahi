# SPDX-License-Identifier: MIT
"""Finite local source/custody checks; no Git, network, or actor execution."""
import hashlib,json,os,re,stat
from pathlib import Path
RECIPE='9f9eae97843531a41b201655100f13984d9ac01e'
PAIR='4ebe9f9afb153b34e8fe200594eaee189626413f'
PAIR_REF='codex/apps9-pair-native-v1'
RUN=39748090833
NAME='cachy-asahi-apps'
VERSION='0.1.0-9'
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def read(p,cap=16*1024**2):
 p=Path(p).absolute();need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary exact input ancestry');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=cap,'ordinary bounded singlelink input');raw=p.read_bytes();t=p.lstat();need(len(raw)==s.st_size and all(getattr(s,k)==getattr(t,k)for k in FIELDS),'stable whole input read');return raw
def decode(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate JSON key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def obj(p):return decode(read(p))
def member(n):need(type(n)is str and n and not n.startswith('/')and all(p not in('','.','..','.git')for p in n.split('/')),'contained ordinary carrier role');return n
def table(root):
 root=Path(root).absolute();out={}
 for b,ds,fs in os.walk(root):
  if Path(b)==root:ds[:]=[n for n in ds if n!='.git'];fs=[n for n in fs if n!='.git']
  for n in ds:need(not(Path(b)/n).is_symlink(),'ordinary source directory')
  for n in fs:out[(Path(b)/n).relative_to(root).as_posix()]=pin(read(Path(b)/n,128*1024**2))
 return out
def closed(root,rows):need(table(root)==rows,'whole exact closed input/source map');return rows

def index_check(index,files,recipe_map,acceptance):
 need(index['status']=='EXACT_ACCEPTED_APPS9_PAIR_INPUT_DATA_ONLY'and index['actual']is None,'Apps9 input DATA only')
 need(index['source']==PAIR and index['ref']==PAIR_REF and index['run']==RUN and index['recipe_source']==RECIPE,'exact Apps9 native pair/recipe source and run')
 need(index['GUI']==index['installed_current606']==index['hardware']=='NOT_RUN','no pair acceptance transfer')
 recipe_prefix=member(index['recipe_prefix']);need(recipe_prefix=='recipe-source','exact public whole41 recipe namespace')
 need({n.removeprefix(recipe_prefix+'/'):w for n,w in files.items()if n.startswith(recipe_prefix+'/')}==recipe_map,'all41 original public recipe leaves')
 archives=index['archives'];need(type(archives)is list and len(archives)==2 and len({r['path']for r in archives})==2,'two distinct original Apps9 build roles')
 pins=[]
 for row in archives:
  path=member(row['path']);w={k:row[k]for k in('bytes','sha256')};need(path.endswith('/cachy-asahi-apps-0.1.0-9-any.pkg.tar.xz')and type(w['bytes'])is int and 0<w['bytes']<=16*1024**2 and re.fullmatch('[a-f0-9]{64}',w['sha256'])and files[path]==w,'exact accepted Apps9 any archive body');pins.append(w)
 need(pins[0]==pins[1],'complete byte-identical Apps9 native pair')
 need(acceptance['source']==PAIR and acceptance['ref']==PAIR_REF and acceptance['run']==RUN and acceptance['status']=='ROOT_ACCEPTED_APPS9_NATIVE_BUILD_PAIRS_AND_FINITE_INSTALLED_LIFECYCLE','genuine matching Root Apps9 finite acceptance required')
 # Root selects the explicit archive-pin field from its original decision. Never
 # infer acceptance from a successful CI result or a historical Apps7 receipt.
 authority=acceptance
 for key in index['acceptance_archive_pointer']:
  need(type(key)in(str,int),'typed Root archive-pin pointer');authority=authority[key]
 need(type(authority)is dict and all(authority[k]==pins[0][k]for k in('bytes','sha256')),'original Root decision authorizes this exact native archive')
 need(files[member(index['acceptance'])]==pin(enc(acceptance)),'canonical original Root decision bytes')
 for role in('LICENSE','NOTICE.md'):
  need(role in files,'public source/license closure required')
 return dict(name=NAME,version=VERSION,archive=Path(archives[0]['path']).name,size=pins[0]['bytes'],sha256=pins[0]['sha256'])

PARENT='51e7797ef639de8fbed96e51b5b12bf5a92c7cb7'

# Source-only completed CLI diagnostic controls; imports never run these fixtures.
if __name__=="__main__":
 # SPDX-License-Identifier: MIT
 """Whole actual run pre-guard flow and bounded retained failure bytes, no actors."""
 import base64,contextlib,importlib.util,io,json,subprocess,sys,tempfile,types,unittest,zipfile
 from pathlib import Path
 from unittest.mock import patch
 D=Path(__file__).resolve().parent
 spec=importlib.util.spec_from_file_location('_proposed_current_products',D/'factory/current_products.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
 class Controls(unittest.TestCase):
  def test_actual_run_preserves_guard_and_full_completed_refusal_data(self):
   with tempfile.TemporaryDirectory(dir=D)as temp:
    home=Path(temp);raw=b'{"status":"REFUSED","error":"injected precise CLI refusal"}\n';process=subprocess.CompletedProcess([],1,raw,b'');capture=io.StringIO();calls=[]
    def actor(argv,**kw):calls.append((argv,kw));return process
    api=types.SimpleNamespace(observe=lambda:{'INERT_SOURCE_IDENTITY':'not_native'})
    with patch.object(P.os,'getuid',return_value=23001),patch.object(P.os,'geteuid',return_value=23001),patch.object(P,'_apps9_runtime',return_value=api),patch.object(P.subprocess,'run',side_effect=actor),contextlib.redirect_stderr(capture),self.assertRaisesRegex(ValueError,'actual bounded installed Apps9 command'):P.run(home,home,{'PATH':'/usr/bin:/bin','HOME':str(home)})
    self.assertEqual(calls[0][0],['/usr/bin/cachy-asahi-apps','inventory','--dbpath','/var/lib/pacman','--output',str(home/'apps9-current606-inventory.json')]);self.assertEqual(calls[0][1]['timeout'],35);line=capture.getvalue();self.assertTrue(line.startswith('CURRENT606_APPS9_COMMAND_FAILURE_DATA '));data=json.loads(line.split(' ',1)[1]);self.assertEqual(data['returncode'],1);self.assertEqual(base64.b64decode(data['stdout']['base64']),raw);self.assertFalse(data['stdout']['truncated']);self.assertEqual(data['stdout']['sha256'],P.digest(raw));self.assertIs(data['acceptance_authority'],False);self.assertEqual(data['stderr']['bytes'],0)
  def test_stderr_and_oversize_keep_complete_hash_and_explicit_truncation(self):
   for stdout,stderr in((b'accepted stdout',b'warning refuses'),(b'x'*65537,b'y'*65537)):
    with self.subTest(),contextlib.redirect_stderr(io.StringIO())as capture:
     data=P._apps9_command_failure(subprocess.CompletedProcess([],0,stdout,stderr),1.25,['/usr/bin/cachy-asahi-apps'],{'HOME':'MUST_NOT_LEAK','UNEXPECTED':'MUST_NOT_LEAK'})
    self.assertNotIn('MUST_NOT_LEAK',capture.getvalue());self.assertTrue(data['unknown_environment_keys_present']);self.assertLessEqual(len(capture.getvalue().encode()),192*1024+64)
    for label,raw in(('stdout',stdout),('stderr',stderr)):
     row=data[label];self.assertEqual(row['sha256'],P.digest(raw));self.assertEqual(row['bytes'],len(raw));self.assertEqual(base64.b64decode(row['base64']),raw[:65536]);self.assertEqual(row['truncated'],len(raw)>65536)
  def test_success_passes_original_gate_without_diagnostic_or_waiver(self):
   class ReachedOriginalAfterIdentity(Exception):pass
   with tempfile.TemporaryDirectory(dir=D)as temp:
    home=Path(temp);count=[]
    def observe():
     count.append(1)
     if len(count)==2:raise ReachedOriginalAfterIdentity()
     return {'INERT_SOURCE_IDENTITY':'not_native'}
    with patch.object(P.os,'getuid',return_value=23001),patch.object(P.os,'geteuid',return_value=23001),patch.object(P,'_apps9_runtime',return_value=types.SimpleNamespace(observe=observe)),patch.object(P.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'{}',b'')),patch.object(P,'_apps9_command_failure',side_effect=AssertionError('success emits no failure DATA')),self.assertRaises(ReachedOriginalAfterIdentity):P.run(home,home,{})
    self.assertEqual(len(count),2)
  def test_full_bounded_diagnostic_survives_unchanged_original_transport(self):
   source=D
   spec=importlib.util.spec_from_file_location('_held_original_transport',source/'transport.py');T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
   self.assertEqual(T.MAX,512*1024**2)
   native=(source/'native.py').read_text();self.assertIn("n in('runtime.json','events.log','guest.log')",native)
   with tempfile.TemporaryDirectory(dir=D)as temp:
    root=Path(temp);public=root/'public';(public/'gui').mkdir(parents=True)
    with contextlib.redirect_stderr(io.StringIO())as capture:P._apps9_command_failure(subprocess.CompletedProcess([],1,b'x'*65536,b'y'*65536),2.0,['/usr/bin/cachy-asahi-apps','inventory'],{'PATH':'/usr/bin:/bin'})
    raw=(capture.getvalue()+'ValueError: actual bounded installed Apps9 command\n').encode();self.assertLess(len(raw),16*1024**2)
    (public/'gui/guest.log').write_bytes(raw);(public/'retention.json').write_bytes(T.enc(dict(status='FAIL_OR_INCOMPLETE',case='minimal-generic4k',files={'gui/guest.log':T.pin(raw)},total_bytes=len(raw))))
    # Source-shaped synthetic DATA only: these arguments do not create actual authority.
    proof=dict(source='09f7758b20c638f302086374931e7e5ceb3ca6fd',run=39735987716,attempt=1,case='minimal-generic4k',job_token='0123456789abcdef')
    result=T.pack(public,root/'transport',proof);self.assertEqual(result['status'],'PACKED_PUBLIC_EVIDENCE_DATA_ONLY');self.assertIs(result['actual_authority'],False)
    with zipfile.ZipFile(root/'transport/evidence.zip')as z:self.assertIsNone(z.testzip());self.assertEqual(z.read('gui/guest.log'),raw);self.assertEqual(set(z.namelist()),{'gui/guest.log','retention.json'})
 if __name__=='__main__':unittest.main()
