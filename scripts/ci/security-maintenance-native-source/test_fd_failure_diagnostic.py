#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused AST-only FD-diagnostic DATA controls; no observer/FD/Source actor."""
import argparse,ast,copy,hashlib,json,os,pathlib,stat,sys,types,unittest
HERE=pathlib.Path(__file__).resolve().parent
NEW='7ab431933359f983bf0c1560930c68cf1e833eba170b5ee4351ef399abc6ae80'
OLD='970793258bca73525db8e40709c845c63a76396f0fbd7b45c9c446571b77e2ef'
OLD_MAP='f30d050072e3d9fe1ff7b61706f5b3093df34cc2df02a98441aee296debac0b6'
NEW_PROFILE='47c61023547433156a79e498e49655fbefe7aee340e2458f8597c0a9cc4a1650'
OLD_PROFILE='4e74176f2804b618c53a6ae1238fc93f132b52c45dcc71f1d359fb8542e98ad1'
PREFIX='SECURITY_OBSERVATION_FD_FAILURE_DATA '
REFUSED='SECURITY_OBSERVATION_FD_DIAGNOSTIC_REFUSED'
REASON='same bounded owned observation FD'
F=None;B=None;RESULT=None;READS=set();DENIED=[];EXTRACTION={}

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path):
 path=path.absolute();assert path==path.resolve()and path in READS
 with path.open('rb')as stream:
  before=os.fstat(stream.fileno());assert stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size<=2*1024**2
  raw=stream.read(before.st_size+1);after=os.fstat(stream.fileno())
 assert len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(path.stat(),k)for k in('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
 return raw

def audit(event,args):
 forbidden=event.startswith(('subprocess.','socket.','ctypes.','pty.','os.exec','os.fork','os.spawn','os.posix_spawn'))or event in('os.system','os.kill','os.killpg','signal.pthread_kill')
 if event=='open'and isinstance(args[0],(str,bytes,os.PathLike)):
  path=pathlib.Path(os.fsdecode(args[0])).absolute();writing=args[2]&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_APPEND|os.O_TRUNC)
  forbidden|=(path!=RESULT if writing else path not in READS)
 if forbidden:DENIED.append(event);raise RuntimeError('FD DATA controls actor/payload access denied: '+event)

def function(module,name):
 found=[n for n in module.body if isinstance(n,ast.FunctionDef)and n.name==name];assert len(found)==1;return found[0]
def message(node):return isinstance(node,ast.Expr)and isinstance(node.value,ast.Call)and any(isinstance(x,ast.Constant)and x.value==REASON for x in node.value.args)
def wrapper(name,body):
 args=['before','info','policy','compiled','owner','map_hash']
 return ast.FunctionDef(name=name,args=ast.arguments(posonlyargs=[],args=[ast.arg(arg=a)for a in args],vararg=None,kwonlyargs=[],kw_defaults=[],kwarg=None,defaults=[]),body=copy.deepcopy(body)+[ast.Return(value=ast.Constant(value=True))],decorator_list=[],returns=None,type_comment=None,type_params=[])

def harness(new_tree,old_tree,common_tree):
 newer=function(new_tree,'observe_real_upgrade');older=function(old_tree,'observe_real_upgrade')
 newtry=next(n for n in newer.body if isinstance(n,ast.Try));oldtry=next(n for n in older.body if isinstance(n,ast.Try))
 index=next(i for i,n in enumerate(newtry.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='predicates'for t in n.targets))
 newblock=newtry.body[index:index+3];assert len(newblock)==3 and isinstance(newblock[1],ast.If)and message(newblock[2])
 oldblock=[n for n in oldtry.body if message(n)];assert len(oldblock)==1
 emitter=function(new_tree,'emit_observation_fd_failure');need=function(common_tree,'need')
 nodes=[copy.deepcopy(need),copy.deepcopy(emitter),wrapper('new_guard',newblock),wrapper('old_guard',oldblock)]
 code=ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[]));namespace={'json':json,'print':lambda *a,**k:None}
 # Only two exact functions and two transparent wrappers around actual predicate AST.
 exec(compile(code,'FD_DIAGNOSTIC_AUTHENTICATED_AST_DATA_ONLY','exec'),namespace)
 EXTRACTION.update(functions=['common.need','emit_observation_fd_failure'],blocks=['actual new predicates/if/need','actual original refusal predicate/need'],whole_Source_imports=0,FD_transport_or_observer_calls=0)
 return namespace,newtry,oldtry,index

class Stats:
 fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size')
 def __init__(self,**changes):
  values=dict(st_dev=55,st_ino=9001,st_mode=stat.S_IFREG|0o600,st_uid=0,st_gid=0,st_nlink=1,st_size=0);values.update(changes)
  object.__setattr__(self,'values',values);object.__setattr__(self,'access',[])
 def __getattribute__(self,name):
  if name in Stats.fields:
   object.__getattribute__(self,'access').append(name);return object.__getattribute__(self,'values')[name]
  if name in('values','access'):return object.__getattribute__(self,name)
  raise AssertionError('metadata object payload/other attribute access forbidden: '+name)

class Sink:
 def __init__(self,error=None,always=False):self.lines=[];self.calls=0;self.error=error;self.always=always
 def __call__(self,value,**kwargs):
  assert kwargs==dict(flush=True);self.calls+=1
  if self.error is not None and(self.always or self.calls==1):raise self.error
  self.lines.append(value)

class FDControls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.new_raw=read(F/'overlay/native/security_native_v1.py');cls.old_raw=read(B/'native/security_native_v1.py');cls.map_raw=read(B/'native/source-map.json');cls.common_raw=read(B/'native/common.py')
  assert pin(cls.new_raw)['sha256']==NEW and pin(cls.old_raw)['sha256']==OLD and pin(cls.map_raw)['sha256']==OLD_MAP
  mapping=json.loads(cls.map_raw);assert pin(cls.common_raw)=={k:mapping['files']['native/common.py'][k]for k in('bytes','sha256')}
  cls.newtree=ast.parse(cls.new_raw);cls.oldtree=ast.parse(cls.old_raw);cls.common_tree=ast.parse(cls.common_raw)
  cls.profile_raw=read(F/'profile.json');assert pin(cls.profile_raw)['sha256']==NEW_PROFILE;cls.profile=json.loads(cls.profile_raw)
  cls.contract_raw=read(B/'native/security-contract-v1.json');cls.contract=json.loads(cls.contract_raw);cls.policy=cls.contract['upgrade']['observation']
  cls.namespace,cls.newtry,cls.oldtry,cls.index=harness(cls.newtree,cls.oldtree,cls.common_tree)
 def setUp(self):
  self.ns=dict(self.namespace)
  # Function globals must be isolated for each fault-injection test.
  self.ns,_,_,_=harness(self.newtree,self.oldtree,self.common_tree);self.sink=Sink();self.ns['print']=self.sink
  self.before=Stats();self.info=Stats(st_size=128);self.compiled=dict(bytes=256,sha256='c'*64)
 def call(self,kind='new_guard',info=None,compiled=None):return self.ns[kind](self.before,info or self.info,self.policy,self.compiled if compiled is None else compiled,4242,'a'*64)
 def refuses_original(self,info=None):
  with self.assertRaises(ValueError)as new:self.call(info=info)
  self.assertEqual(new.exception.args,(REASON,))
  with self.assertRaises(ValueError)as old:self.call('old_guard',info=info)
  self.assertEqual(type(new.exception),type(old.exception));self.assertEqual(new.exception.args,old.exception.args)
  return new.exception
 def shape(self,key,**change):
  info=Stats(st_size=128,**change)if'st_size'not in change else Stats(**change);self.refuses_original(info)
  self.assertEqual(len(self.sink.lines),1);self.assertTrue(self.sink.lines[0].startswith(PREFIX));data=json.loads(self.sink.lines[0][len(PREFIX):])
  self.assertEqual({k for k,v in data['guard_predicates'].items()if not v},{key});self.assertEqual(data['phase'],'AFTER_REQUIRED_INSTALL_BEFORE_OBSERVER_RECORD_DECODE');self.assertEqual(data['owner_pid'],4242)
  self.assertEqual(data['source_map_sha256'],'a'*64);self.assertEqual(data['observer_source'],self.policy['source_pin']);self.assertEqual(data['observer_compiled'],self.compiled)
 def test_device_failure(self):self.shape('same_device',st_dev=56)
 def test_inode_failure(self):self.shape('same_inode',st_ino=9002)
 def test_zero_bytes_failure(self):self.shape('positive_record_bytes',st_size=0)
 def test_over_record_cap_failure(self):self.shape('within_record_cap',st_size=self.policy['record_cap']+1)
 def test_metadata_only_no_payload_or_file_reads(self):
  info=Stats(st_size=0,st_uid=77,st_gid=88,st_nlink=2,st_mode=stat.S_IFREG|0o640);self.refuses_original(info)
  value=json.loads(self.sink.lines[0][len(PREFIX):]);self.assertEqual(set(value['after']),{'dev','inode','mode','uid','gid','nlink','bytes'})
  self.assertEqual(value['after'],dict(dev=55,inode=9001,mode=stat.S_IFREG|0o640,uid=77,gid=88,nlink=2,bytes=0))
  self.assertLessEqual(set(info.access),set(Stats.fields));self.assertEqual(DENIED,[])
  names={n.id for n in ast.walk(function(self.newtree,'emit_observation_fd_failure'))if isinstance(n,ast.Name)}
  self.assertTrue({'os','open','read','fd','payload'}.isdisjoint(names))
 def test_ascii_metadata_escapes_unicode(self):
  self.compiled['tag']='é';self.refuses_original(Stats(st_size=0));raw=self.sink.lines[0][len(PREFIX):];raw.encode('ascii');self.assertIn('\\u00e9',raw)
 def boundary(self,total):
  compiled=dict(self.compiled,padding='');self.ns['emit_observation_fd_failure']('a'*64,4242,self.before,Stats(st_size=0),dict(same_device=True,same_inode=True,positive_record_bytes=False,within_record_cap=True),self.policy,compiled)
  base=len(self.sink.lines.pop()[len(PREFIX):].encode('ascii'));compiled['padding']='x'*(total-base)
  self.sink.lines.clear();self.ns['emit_observation_fd_failure']('a'*64,4242,self.before,Stats(st_size=0),dict(same_device=True,same_inode=True,positive_record_bytes=False,within_record_cap=True),self.policy,compiled)
 def test_exact_4096_ASCII_JSON_payload_allowed(self):
  self.boundary(4096);self.assertEqual(len(self.sink.lines[0][len(PREFIX):].encode('ascii')),4096)
 def test_4097_JSON_payload_refused_primary_preserved(self):
  self.boundary(4097);self.assertEqual(self.sink.lines,[REFUSED]);self.sink.lines.clear();self.compiled['padding']='x'*4097;self.refuses_original(Stats(st_size=0));self.assertEqual(self.sink.lines,[REFUSED])
 def test_nonascii_encoder_result_refuses_primary_preserved(self):
  self.ns['json']=types.SimpleNamespace(dumps=lambda *a,**k:'é');self.refuses_original(Stats(st_size=0));self.assertEqual(self.sink.lines,[REFUSED])
 def test_serialization_BaseExceptions_do_not_replace_refusal(self):
  for kind in(Exception,ValueError,RuntimeError,KeyboardInterrupt,SystemExit,GeneratorExit,BaseException):
   with self.subTest(exception=kind.__name__):
    def fail(*a,**k):raise kind('synthetic serializer fault')
    self.ns['json']=types.SimpleNamespace(dumps=fail);self.sink.lines.clear();error=self.refuses_original(Stats(st_size=0));self.assertEqual(str(error),REASON);self.assertEqual(self.sink.lines,[REFUSED])
 def test_first_and_fallback_output_BaseExceptions_contained(self):
  for kind in(Exception,KeyboardInterrupt,SystemExit,GeneratorExit,BaseException):
   for always in(False,True):
    with self.subTest(exception=kind.__name__,both_outputs=always):
     sink=Sink(kind('synthetic output fault'),always);self.ns['print']=sink;self.refuses_original(Stats(st_size=0));self.assertEqual(sink.calls,2);self.assertEqual(sink.lines,[]if always else[REFUSED])
 def test_unserializable_metadata_refuses_original(self):
  self.compiled['bad']=object();self.refuses_original(Stats(st_size=0));self.assertEqual(self.sink.lines,[REFUSED])
 def test_positive_predicates_emit_no_failure_metadata(self):
  self.ns['print']=Sink(BaseException('positive must never print'),True);self.assertTrue(self.call());self.assertTrue(self.call('old_guard'));self.assertEqual(self.ns['print'].calls,0)
 def test_exact_C_reader_recipes_and_other198_Source_rows_held(self):
  mapping=json.loads(self.map_raw);old=dict(mapping['files']);old['native/source-map.json']=dict(**pin(self.map_raw),mode=0o644);new=self.profile['expected']['files']
  self.assertEqual(len(old),200);self.assertEqual(set(old),set(new));self.assertEqual({n for n in old if old[n]!=new[n]},{'native/security_native_v1.py','native/source-map.json'})
  self.assertEqual(read(F/'overlay/native/security-contract-v1.json'),self.contract_raw)
  self.assertEqual(read(F/'overlay/native/security_reader_v1.py'),read(B/'native/security_reader_v1.py'))
  self.assertEqual(pin(self.contract['upgrade']['observation']['source'].encode()),dict(bytes=6175,sha256='b4f751cceeb5c2df8749025b91a8b2108704736d377b79d84abed6e573e3263c'))
 def test_entire_lifecycle_and_original_FD_transport_AST_held(self):
  new=copy.deepcopy(self.newtree);old=self.oldtree
  new.body=[n for n in new.body if not(isinstance(n,ast.FunctionDef)and n.name=='emit_observation_fd_failure')]
  observe=function(new,'observe_real_upgrade');observe.args.args.pop();newtry=next(n for n in observe.body if isinstance(n,ast.Try));oldtry=next(n for n in function(old,'observe_real_upgrade').body if isinstance(n,ast.Try))
  i=next(i for i,n in enumerate(newtry.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='predicates'for t in n.targets));newtry.body[i:i+3]=[copy.deepcopy(next(n for n in oldtry.body if message(n)))]
  calls=[n for n in ast.walk(new)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='observe_real_upgrade'];self.assertEqual(len(calls),1);calls[0].args.pop()
  self.assertEqual(ast.dump(new,include_attributes=False),ast.dump(old,include_attributes=False))
 def test_factory_pin_only_and_profile_fixed_limits_held(self):
  raw=read(F/'prepare.py');self.assertEqual(raw.count(NEW_PROFILE.encode()),1);self.assertEqual(pin(raw.replace(NEW_PROFILE.encode(),OLD_PROFILE.encode()))['sha256'],'b843f573a9f897754dac5d23f115d90c85c271ddc7c1fb7c6b8df27c9b1db0f1')
  self.assertEqual(self.policy['record_cap'],16384);self.assertEqual(self.profile['actual'],dict(source=None,ref=None,run=None,job=None,artifact=None,runtime=None))
  self.assertEqual(self.profile['payload']['native/security-contract-v1.json'],dict(**pin(self.contract_raw),mode=420))

def main():
 global F,B,RESULT,READS
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--factory-root',type=pathlib.Path,default=HERE);p.add_argument('--baseline-source',type=pathlib.Path,required=True);p.add_argument('--results',type=pathlib.Path,required=True);a=p.parse_args()
 F=a.factory_root.absolute();B=a.baseline_source.absolute();RESULT=a.results.absolute();assert not RESULT.exists()and RESULT.parent.is_dir()and RESULT==RESULT.resolve()
 READS={F/n for n in['overlay/native/security_native_v1.py','profile.json','prepare.py','overlay/native/security-contract-v1.json','overlay/native/security_reader_v1.py']}|{B/n for n in['native/security_native_v1.py','native/common.py','native/source-map.json','native/security-contract-v1.json','native/security_reader_v1.py']}
 READS.add(pathlib.Path(__file__).resolve())
 for module in tuple(sys.modules.values()):
  filename=getattr(module,'__file__',None)
  if filename and pathlib.Path(filename).is_file():READS.add(pathlib.Path(filename).resolve())
 sys.addaudithook(audit)  # Before any supplied Source AST is parsed/evaluated.
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(FDControls);result=unittest.TextTestRunner(verbosity=2).run(suite)
 report=dict(status='PASS_NEW_FD_FAILURE_DIAGNOSTIC_DATA_CONTROLS'if result.wasSuccessful()else'FAIL_NEW_FD_FAILURE_DIAGNOSTIC_DATA_CONTROLS',runtime=sys.version,executable=sys.executable,controls=result.testsRun,failures=len(result.failures),errors=len(result.errors),cases=unittest.defaultTestLoader.getTestCaseNames(FDControls),extraction=EXTRACTION,denied_events=DENIED,Source_actor_imports=0,old37_51_replays=0,factory_emissions=0,observer_FD_payload_reads=0,new_metadata_JSON_ASCII_cap=4096,marker_framing_extra_bytes=len(PREFIX)+1,native_diagnostic='NOT_RUN',actual_FD_cause='UNKNOWN',acceptance=False)
 with RESULT.open('x')as out:json.dump(report,out,indent=2,sort_keys=True);out.write('\n')
 raise SystemExit(0 if result.wasSuccessful()else 1)
if __name__=='__main__':main()
