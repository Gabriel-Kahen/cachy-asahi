# SPDX-License-Identifier: MIT
"""Fenced DATA predicates and modeled complete stage; no operational Reader/actor."""
import argparse,ast,contextlib,copy,ctypes,hashlib,importlib.util,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT_SOURCE=None

def load(n):
 s=importlib.util.spec_from_file_location('xs_v4_test_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
R=load('reader');A=load('adapters');C=load('compiler');d=R.d
MANIFEST=HERE.parents[1]/'hosted_source_v4/compiler-inputs.json'
def binding():return dict(source=R.SOURCE,ref=R.REF,run='1',job='2',approval='3'*64,source_map_sha256=R.MAP,operation=R.OUTER)
def descriptor():return json.loads(MANIFEST.read_bytes())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def modeled_copy():
 m=descriptor();expected=dict(m['payload'])
 for archive in m['archives'].values():
  for n,row in archive['license_payloads'].items():expected['/'+n]=dict(row,aliases=['/'+n])
 observed={n:dict(**{k:row[k]for k in ['bytes','sha256','mode','aliases']},nlink=len(row['aliases']),device=1,inode=i+1)for i,(n,row)in enumerate(expected.items())};driver=m['payload'][m['driver_source']]
 return dict(kind='XS_V4_SINGLE_LINK_COMPILER_COPY_V1',status='COPIED_DATA_ONLY',source=binding()['source'],operation=C.OUTER,manifest=C.PIN,path='/usr/bin/cachy-asahi-xs-gcc',inventory_sha256=C.INVENTORY,count=349,compiler_invocations=0,network='NONE',source_license_freshness_native_acceptance=False,writable_domain='OWNED_CONTAINER_IMAGE_LAYER_ONLY_ROOT_UID0_CAP0',driver=dict(**{k:driver[k]for k in ['bytes','sha256','mode']},nlink=1),original_payloads=observed)

def images():
 b=binding();parent_id='sha256:'+'1'*64;token=hashlib.sha256((b['source']+':'+b['run']+':compiler-v4').encode()).hexdigest()[:24];parent_token=hashlib.sha256((b['source']+':'+b['ref']+':'+b['run']).encode()).hexdigest()[:24]
 base=dict(Id=parent_id,Architecture='arm64',Os='linux',Size=1000,Config=dict(Labels={'cachy-asahi.hosted-perl':parent_token,'cachy-asahi.hosted-perl.source':b['source']},User='alarm',WorkingDir='/tmp',Env=['PATH=/usr/bin:/bin'],Cmd=None,Entrypoint=None,AttachStderr=False,AttachStdout=False,Hostname='',Image=''),RootFS={'Layers':['sha256:'+'a'*64]},RepoTags=['perl-native-base:'+parent_token])
 labels=dict(base['Config']['Labels']);labels.update({'cachy-asahi.xs-compiler':token,'cachy-asahi.xs-compiler.source':b['source'],'cachy-asahi.xs-compiler.parent':parent_id});metadata=dict(AttachStderr=True,AttachStdout=True,Hostname='4'*12,Image=parent_id)
 new=copy.deepcopy(base);new.update(Id='sha256:'+'2'*64,Size=2366000,RepoTags=['perl-xs-compiler:'+token]);new['RootFS']['Layers']+=['sha256:'+'b'*64];new['Config'].update(metadata,Labels=labels,Entrypoint=['/usr/bin/false'],Cmd=['/usr/bin/false'])
 q=dict(kind='XS_V4_DERIVED_COMPILER_IMAGE_QUALIFICATION_V1',status='QUALIFIED_COPY_ONLY_XS_NOT_RUN',binding=b,manifest=C.PIN,parent_image=parent_id,image=new['Id'],tag=new['RepoTags'][0],labels=labels,layer='sha256:'+'b'*64,image_delta_bytes=2365000,derived_default_argv=dict(Entrypoint=['/usr/bin/false'],Cmd=['/usr/bin/false']),sealing_config_metadata=metadata,copy_receipt=modeled_copy(),filesystem_diff=['C /usr','C /usr/bin','A /usr/bin/cachy-asahi-xs-gcc'],compiler_invocations=0,original_inventory=349,sealing_container_id='4'*64,owned_sealing_container_absent=True)
 return base,new,q

def stage_fixture(q_mutate=None,wrong_commit=False,elapsed=None,cleanup_error=False):
 b=binding();base,derived,q=images();cid=q['sealing_container_id'];name='perl-xs-compiler-'+q['labels']['cachy-asahi.xs-compiler'];source=Path('/modeled/source');work=Path('/modeled/work');parent=base['Id'];labels=q['labels']
 config=dict(base['Config']);config.update(q['sealing_config_metadata'],Labels=labels,User='0:0',Entrypoint=['/usr/bin/python3'],Cmd=['-I','-B','/tmp/source/xs/compiler_image.py','--copy-driver',b['source']])
 row=dict(Id=cid,Name='/'+name,Image=parent,Config=config,Mounts=[dict(Type='bind',Source=str(source),Destination='/tmp/source',RW=False)],HostConfig=dict(ReadonlyRootfs=False,NetworkMode='none',CapDrop=['ALL'],CapAdd=[],Privileged=False,Devices=[],Init=False,SecurityOpt=['no-new-privileges'],Memory=536870912,MemorySwap=536870912,NanoCpus=2*10**9,PidsLimit=64,Tmpfs={'/tmp':'rw,noexec,nosuid,nodev,size=8m'}),State=dict(Running=False,Pid=0,ExitCode=0,OOMKilled=False))
 if q_mutate:q_mutate(q,derived)
 raw=encoded(q);prep=dict(compiler_image=dict(manifest=C.PIN,qualification=d.pin(raw),image=q['image']));data={'compiler-image-qualification.json':raw,'bundle/preparation.json':encoded(prep),'compiler-image-cleanup.json':encoded(dict(errors=[],original_error=None,qualified=True))};query=C.DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+name+'$']
 commit=C.DOCKER+['commit','--pause=false','--change','USER alarm','--change','WORKDIR /tmp','--change','ENTRYPOINT ["/usr/bin/false"]','--change','CMD ["/usr/bin/false"]',name,q['tag']]
 if wrong_commit:commit=[arg.replace('ENTRYPOINT ["/usr/bin/false"]','ENTRYPOINT []')for arg in commit]
 operations=[(query,b''),(C.DOCKER+['image','ls','--no-trunc','-q','--filter','reference='+q['tag']],b''),(C.DOCKER+['image','inspect',parent],encoded([base])),(C.create(name,parent,labels,source,work,b),(cid+'\n').encode()),(C.DOCKER+['inspect',name],encoded([row])),(C.DOCKER+['start','--attach',name],(json.dumps(q['copy_receipt'],sort_keys=True)+'\n').encode()),(C.DOCKER+['inspect',name],encoded([row])),(C.DOCKER+['diff',name],('\n'.join(q['filesystem_diff'])+'\n').encode()),(commit,(q['image']+'\n').encode()),(C.DOCKER+['image','inspect',q['image']],encoded([derived])),(query,(name+'\n').encode()),(C.DOCKER+['inspect',name],encoded([row])),(C.DOCKER+['rm',name],b''),(query,b'')]
 class Sequence:
  def __init__(self):self.index=0;self.rows=[dict(lifecycle={'elapsed_seconds':.1})for _ in operations]
  def take(self,argv,**kwargs):
   if self.index>=len(operations)or argv!=operations[self.index][0]:raise ValueError('modeled exact operation mismatch')
   raw=operations[self.index][1];self.index+=1;return raw,b''
 seq=Sequence()
 if elapsed is not None:seq.rows[4]['lifecycle']['elapsed_seconds']=elapsed
 if cleanup_error:data['compiler-image-cleanup.json']=encoded(dict(errors=['MODELED_REFUSAL'],original_error=None,qualified=False))
 result=C.stage(lambda n:data[n],ROOT_SOURCE,b,{'compiler_image':q},parent,work,source,seq,d);return result,seq

class Controls(unittest.TestCase):
 def setUp(self):
  d.start();stack=contextlib.ExitStack();self.addCleanup(stack.close)
  def denied(*a,**k):raise AssertionError('operational role forbidden in DATA controls')
  stack.enter_context(patch.object(R,'validate',denied));stack.enter_context(patch.object(R.B,'original',denied))
  for n in ['subprocess.run','subprocess.Popen','socket.socket','socket.create_connection','fcntl.flock','os.pidfd_open','os.fork','os.system','ctypes.CDLL']:stack.enter_context(patch(n,side_effect=denied,create=True))
 def test_NULL_admission_refuses(self):
  with self.assertRaises(ValueError):R.binding(d.decode((HERE/'binding.TEMPLATE.json').read_bytes()))
 def test_new_v4_binding_rejects_old_sources_or_wrong_literals(self):
  value=dict(schema=1,binding=binding(),artifact=dict(id='4',bytes=1,sha256='5'*64,metadata_sha256='6'*64));self.assertEqual(R.binding(value)[0],value['binding'])
  for key,val in [('source',R.PARENT),('source',R.B.parent.PARENT),('ref',R.B.parent.REF),('operation',R.INNER),('source_map_sha256',R.PARENT_MAP),('approval',None)]:
   bad=copy.deepcopy(value);bad['binding'][key]=val
   with self.subTest(key=key),self.assertRaises(ValueError):R.binding(bad)
 def test_inner_projection_only_changes_outer_literal(self):
  b=binding();self.assertEqual(A.inner_binding(b,{'operation':R.INNER},d),dict(b,operation=R.INNER));self.assertEqual(b['operation'],R.OUTER)
 def test_passive_function_projection_is_exactly_invertible(self):
  for version in(2,3):fn,proof=R.B.source_projection(version);self.assertEqual(proof['seams'],3);self.assertEqual(proof['inverse'],'EXACT_ORIGINAL_FUNCTION_BYTES');self.assertNotEqual(proof['before_sha256'],proof['after_sha256'])
  with self.assertRaises(ValueError):R.B.substitute(b'changed',[(b'original',b'new')])
  with self.assertRaises(ValueError):R.B.substitute(b'original original',[(b'original',b'new')])
 def test_frozen_passive_substitution_refused(self):
  with patch.object(R.B,'raw3',return_value=b'not expected'):
   with self.assertRaises((ValueError,SyntaxError)):R.B.source_projection(3)
 def test_consumer_bundle_projection_and_budget_inverse(self):
  raw=A.B.raw('consumer.py');new=A.consumer_bundle(raw);needle=b",'compiler-image-qualification.json':io.pin(get('compiler-image-qualification.json'))";self.assertEqual(new.count(needle),1);self.assertEqual(new.replace(needle,b''),raw)
  old=ast.parse(A.B.raw('bootstrap.py'));modified=ast.parse(A.extra_budget(A.B.raw('bootstrap.py')))
  for node in ast.walk(modified):
   if isinstance(node,ast.Constant)and type(node.value)is int and node.value==5520:node.value=5340
  self.assertEqual(ast.dump(old),ast.dump(modified))
 def test_exact_copy_alias_helper_notice_and349_controls(self):
  C.copy_receipt(modeled_copy(),descriptor(),binding(),d)
  for key in('driver','alias','notice','count','compiler'):
   bad=modeled_copy()
   if key=='driver':bad['driver']['nlink']=3
   elif key=='alias':bad['original_payloads']['/usr/bin/aarch64-unknown-linux-gnu-gcc']['nlink']=1
   elif key=='notice':bad['original_payloads'].pop('/usr/share/licenses/gcc/RUNTIME.LIBRARY.EXCEPTION')
   elif key=='count':bad['count']=348
   else:bad['compiler_invocations']=1
   with self.subTest(key=key),self.assertRaises(ValueError):C.copy_receipt(bad,descriptor(),binding(),d)
 def test_full_config_exact_refusal_defaults_and_four_captured_fields(self):
  base,new,q=images();C.qualified(base,new,q,d)
  for mode in('Entrypoint','Cmd','User','Env','WorkingDir','unknown','labels','metadata_extra','metadata_value','layer','size'):
   v=copy.deepcopy(new);receipt=copy.deepcopy(q)
   if mode in('Entrypoint','Cmd'):v['Config'][mode]=[]
   elif mode=='User':v['Config'][mode]='root'
   elif mode=='Env':v['Config'][mode]=['PATH=/foreign']
   elif mode=='WorkingDir':v['Config'][mode]='/'
   elif mode=='unknown':v['Config']['UnknownField']=None
   elif mode=='labels':v['Config']['Labels']={}
   elif mode=='metadata_extra':receipt['sealing_config_metadata']['User']='alarm'
   elif mode=='metadata_value':v['Config']['AttachStdout']=False
   elif mode=='layer':v['RootFS']['Layers']=['sha256:'+'f'*64]
   else:v['Size']+=8388608
   with self.subTest(mode=mode),self.assertRaises(ValueError):C.qualified(base,v,receipt,d)
 def test_complete_modeled_stage_raw_command_sequence_and_qualifier(self):
  (q,base,new),seq=stage_fixture();self.assertEqual(seq.index,14);self.assertEqual(q['sealing_config_metadata']['Image'],base['Id']);self.assertEqual(new['Config']['Entrypoint'],['/usr/bin/false'])
 def test_each_captured_value_is_bound_to_actual_stopped_Config(self):
  for key in('AttachStderr','AttachStdout','Hostname','Image'):
   def change(q,v):
    value=False if key.startswith('Attach')else 'e'*12 if key=='Hostname'else 'sha256:'+'e'*64;q['sealing_config_metadata'][key]=value;v['Config'][key]=value
   with self.subTest(key=key),self.assertRaisesRegex(ValueError,'stopped sealing-container'):stage_fixture(change)
 def test_actual_commit_must_request_false_not_empty_defaults(self):
  with self.assertRaisesRegex(ValueError,'operation mismatch'):stage_fixture(wrong_commit=True)
 def test_copy_actor_cap0_limits_identity_and_readonly_Source(self):
  labels={'owner':'MODELED'};b=binding();cid='a'*64;parent='sha256:'+'b'*64
  row={'Id':cid,'Name':'/owned','Image':parent,'Config':{'Labels':labels,'User':'0:0','Entrypoint':['/usr/bin/python3'],'Cmd':['-I','-B','/tmp/source/xs/compiler_image.py','--copy-driver',b['source']]},'Mounts':[{'Type':'bind','Source':'/source','Destination':'/tmp/source','RW':False}],'HostConfig':{'ReadonlyRootfs':False,'NetworkMode':'none','CapDrop':['ALL'],'CapAdd':[],'Privileged':False,'Devices':[],'Init':False,'SecurityOpt':['no-new-privileges'],'Memory':536870912,'MemorySwap':536870912,'NanoCpus':2000000000,'PidsLimit':64,'Tmpfs':{'/tmp':'rw,noexec,nosuid,nodev,size=8m'}}}
  C.confinement(row,'owned',parent,labels,Path('/source'),b,cid,d)
  for key,value in [('NetworkMode','host'),('CapAdd',['SYS_ADMIN']),('MemorySwap',1073741824),('PidsLimit',256),('Init',True),('PidMode','host')]:
   bad=copy.deepcopy(row);bad['HostConfig'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):C.confinement(bad,'owned',parent,labels,Path('/source'),b,cid,d)
  bad=copy.deepcopy(row);bad['Mounts'][0]['RW']=True
  with self.assertRaises(ValueError):C.confinement(bad,'owned',parent,labels,Path('/source'),b,cid,d)
 def test_derived_retirement_requires_exact_image_and_absence(self):
  base,new,q=images();expected=[C.DOCKER+['image','inspect',q['image']],C.DOCKER+['image','rm',q['image']],C.DOCKER+['image','inspect',q['image']]];outer=self
  class Sequence:
   def __init__(self,wrong=False):self.index=0;self.wrong=wrong
   def take(self,argv,**kwargs):
    outer.assertEqual(argv,expected[self.index]);i=self.index;self.index+=1
    if i==0:return encoded([new]),b''
    if i==1:return ('Deleted: '+q['image']+'\n').encode(),b''
    return b'',('Error response from daemon: No such image: '+('foreign'if self.wrong else q['image'])).encode()
  h={'cleanup':{'compiler_image':dict(image=q['image'],removed=True,absence_verified=True)}};seq=Sequence();C.retire(seq,q,h,base,d);self.assertEqual(seq.index,3)
  with self.assertRaises(ValueError):C.retire(Sequence(True),q,h,base,d)
 def test_actual_closed_v3_config_is_not_v4_qualification(self):
  fixture=json.loads((HERE.parents[1]/'hosted_source_v4/closed-v3-config-fixture.json').read_bytes());base,new,q=images();new['Config']=fixture['closed_v3_derived']['Config']
  with self.assertRaises(ValueError):C.qualified(base,new,q,d)
 def test_actual311_to305_to298_to272_Source_DATA(self):
  self.assertEqual(R.source(ROOT_SOURCE,binding())['actual'],R.ACTUAL)
 def test_archived_v3_inverse_bodies_cannot_be_changed_or_missing(self):
  manifest=d.decode(d.read(ROOT_SOURCE,'source-map.json',d.MIB));leaves={n:(d.read(ROOT_SOURCE,n,64*d.MIB),row['mode'])for n,row in manifest['files'].items()};leaves['source-map.json']=(d.read(ROOT_SOURCE,'source-map.json',d.MIB),0o644)
  for mode in('missing','changed'):
   bad=dict(leaves)
   if mode=='missing':bad.pop('previous-v3/compiler_image.py')
   else:bad['previous-v3/compiler_image.py']=(b'MODELED_CHANGED_BODY',0o644)
   with self.subTest(mode=mode),self.assertRaises(ValueError):R.inverse305(bad)
 def test_preparation_and_consumer_always_override_refusal_defaults(self):
  module=R.B.load('bootstrap.py','model_explicit_commands');image='sha256:'+'2'*64
  prep=module.preparation_argv('owned',image,Path('/bundle'),Path('/source'),'a'*64,binding());actor=module.actor_argv('owned','volume',image,Path('/bundle'),'a'*64)
  for argv in(prep,actor):self.assertIn('--entrypoint=/usr/bin/python3',argv);self.assertIn('--user=1001:1001',argv);self.assertNotIn('/usr/bin/false',argv)
  self.assertEqual(prep[-4:],[image,'-I','-B','/source/xs/prepare_inputs.py']);self.assertEqual(actor[-4:],['/inputs/consumer/native_adapter/native.py','actor','--admission-sha256','a'*64])
 def test_stage_budget_and_cleanup_error_never_qualify(self):
  with self.assertRaisesRegex(ValueError,'budgets'):stage_fixture(elapsed=121)
  with self.assertRaisesRegex(ValueError,'retirement'):stage_fixture(cleanup_error=True)
 def test_local_daemon_predicate_does_not_execute_Source_code(self):
  raw=d.read(ROOT_SOURCE,'source-map.json',d.MIB);module=R.B.daemon_classifier(ROOT_SOURCE,d.decode(raw),d);self.assertEqual(module.__file__,str(HERE/'daemon.py'))
  code=(HERE/'adapters.py').read_text();self.assertNotIn('helper=outer.passive_hosted(',code);self.assertIn('helper=B.daemon_classifier(',code)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--v4-source',type=Path,required=True);a=p.parse_args();ROOT_SOURCE=a.v4_source.resolve();result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls));raise SystemExit(not result.wasSuccessful())
