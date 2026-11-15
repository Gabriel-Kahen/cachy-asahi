# SPDX-License-Identifier: MIT
"""Fenced passive modeled controls and optional published-Source DATA join only."""
import contextlib,copy,hashlib,importlib.util,json,sys,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(n):
 spec=importlib.util.spec_from_file_location('xs_v3_test_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
R=load('reader');A=load('adapters');C=load('compiler');d=R.d
ROOT_SOURCE=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-perl-xs-source-r3/source-tree')
MANIFEST=HERE.parents[1]/'hosted_source_v3/compiler-inputs.json'
def binding():return dict(source=R.SOURCE,ref=R.REF,run='1',job='2',approval='3'*64,source_map_sha256=R.MAP,operation=R.OUTER)
def descriptor():return json.loads(MANIFEST.read_bytes())
def modeled_copy():
 m=descriptor();expected=dict(m['payload'])
 for a in m['archives'].values():
  for n,row in a['license_payloads'].items():expected['/'+n]=dict(row,aliases=['/'+n])
 observed={n:dict(**{k:r[k]for k in ['bytes','sha256','mode','aliases']},nlink=len(r['aliases']),device=1,inode=i+1)for i,(n,r)in enumerate(expected.items())};driver=m['payload'][m['driver_source']]
 return dict(kind='XS_V3_SINGLE_LINK_COMPILER_COPY_V1',status='COPIED_DATA_ONLY',source=R.SOURCE,operation=C.OUTER,manifest=C.PIN,path='/usr/bin/cachy-asahi-xs-gcc',inventory_sha256=C.INVENTORY,count=349,compiler_invocations=0,network='NONE',source_license_freshness_native_acceptance=False,writable_domain='OWNED_CONTAINER_IMAGE_LAYER_ONLY_ROOT_UID0_CAP0',driver=dict(**{k:driver[k]for k in ['bytes','sha256','mode']},nlink=1),original_payloads=observed)
class Controls(unittest.TestCase):
 def setUp(self):
  d.start();stack=contextlib.ExitStack();self.addCleanup(stack.close)
  for n in ['subprocess.run','subprocess.Popen','socket.socket','fcntl.flock','os.pidfd_open']:stack.enter_context(patch(n,side_effect=AssertionError('passive Source controls forbid roles/network/lease'),create=n=='os.pidfd_open'))
 def test_NULL_admission_refuses(self):
  with self.assertRaises(ValueError):R.binding(d.decode((HERE/'binding.TEMPLATE.json').read_bytes()))
 def test_exact_v3_binding_rejects_closed_or_wrong_projection(self):
  envelope=dict(schema=1,binding=binding(),artifact=dict(id='4',bytes=1,sha256='5'*64,metadata_sha256='6'*64));self.assertEqual(R.binding(envelope)[0],envelope['binding'])
  for key,val in [('source',R.PARENT),('ref','refs/heads/codex/other'),('operation',R.INNER),('source_map_sha256','0'*64),('approval',None),('run',None)]:
   bad=copy.deepcopy(envelope);bad['binding'][key]=val
   with self.subTest(key=key),self.assertRaises(ValueError):R.binding(bad)
 def test_inner_projection_preserves_outer_binding(self):
  b=binding();self.assertEqual(A.inner_binding(b,{'operation':R.INNER},d),dict(b,operation=R.INNER));self.assertEqual(b['operation'],R.OUTER)
  with self.assertRaises(ValueError):A.inner_binding(b,{'operation':R.OUTER},d)
 def test_frozen_passive_substitution_refused(self):
  with patch.object(A.B,'raw',return_value=b'not the expected passive body'):
   with self.assertRaises((ValueError,SyntaxError)):A.B.load('consumer.py','invalid',A.consumer_bundle)
 def test_consumer_projection_adds_only_one_exact_bundle_leaf(self):
  raw=A.B.raw('consumer.py');new=A.consumer_bundle(raw);needle=b",'compiler-image-qualification.json':io.pin(get('compiler-image-qualification.json'))";self.assertEqual(new.count(needle),1);self.assertEqual(new.replace(needle,b''),raw)
  with self.assertRaises(ValueError):A.consumer_bundle(raw.replace(b"'preparation.json':io.pin(preparation_raw)})",b'changed seam'))
 def test_aggregate_budget_adds_only_separately_reviewed180s(self):
  raw=A.B.raw('bootstrap.py');new=A.extra_budget(raw);import ast
  old=ast.parse(raw);modified=ast.parse(new)
  for node in ast.walk(modified):
   if isinstance(node,ast.Constant)and type(node.value)is int and node.value==5520:node.value=5340
  self.assertEqual(ast.dump(old),ast.dump(modified))
 def test_modeled_copy_requires_exact_driver_aliases_helpers_and_notices(self):
  good=modeled_copy();C.copy_receipt(good,descriptor(),binding(),d)
  for name,change in [('driver',lambda v:v['driver'].update(nlink=3)),('alias',lambda v:v['original_payloads']['/usr/bin/aarch64-unknown-linux-gnu-gcc'].update(nlink=1)),('compiler',lambda v:v.update(compiler_invocations=1)),('inventory',lambda v:v.update(count=348)),('notice',lambda v:v['original_payloads'].pop('/usr/share/licenses/gcc/RUNTIME.LIBRARY.EXCEPTION'))]:
   bad=copy.deepcopy(good);change(bad)
   with self.subTest(name=name),self.assertRaises(ValueError):C.copy_receipt(bad,descriptor(),binding(),d)
 def test_new_image_requires_parent_layer_config_labels_and8MiB_bound(self):
  base=dict(Id='sha256:'+'1'*64,Architecture='arm64',Os='linux',Size=1000,Config=dict(Labels={'parent':'one'},User='alarm',Cmd=None,Entrypoint=None),RootFS={'Layers':['sha256:'+'a'*64]});new=copy.deepcopy(base);new.update(Id='sha256:'+'2'*64,Size=2366000,RepoTags=['owned:one']);new['RootFS']['Layers']+=['sha256:'+'b'*64];new['Config']['Labels']={'parent':'one','derived':'yes'}
  q=dict(parent_image=base['Id'],image=new['Id'],tag='owned:one',labels=new['Config']['Labels'],layer='sha256:'+'b'*64,image_delta_bytes=2365000);C.qualified(base,new,q,d)
  for change in ['same','layers','config','size','tag']:
   bad=copy.deepcopy(new)
   if change=='same':bad['Id']=base['Id']
   elif change=='layers':bad['RootFS']['Layers']=['foreign','new']
   elif change=='config':bad['Config']['User']='root'
   elif change=='size':bad['Size']+=8388608
   else:bad['RepoTags']=['foreign']
   with self.subTest(change=change),self.assertRaises(ValueError):C.qualified(base,bad,q,d)
 def test_create_is_explicit_root_image_domain_cap0_and_readonly_Source(self):
  from pathlib import PurePosixPath
  argv=C.create('owned','sha256:'+'a'*64,{'owner':'modeled'},PurePosixPath('/source'),PurePosixPath('/work'),binding());self.assertIn('--user=0:0',argv);self.assertIn('--cap-drop=ALL',argv);self.assertIn('--network=none',argv);self.assertIn('--pids-limit=64',argv);self.assertIn('type=bind,src=/source,dst=/tmp/source,readonly',argv);self.assertNotIn('--privileged',argv)
 def test_copy_actor_refuses_host_write_caps_wrong_limits_or_identity(self):
  labels={'owner':'MODELED'};b=binding();cid='a'*64;parent='sha256:'+'b'*64
  row={'Id':cid,'Name':'/owned','Image':parent,'Config':{'Labels':labels,'User':'0:0','Entrypoint':['/usr/bin/python3'],'Cmd':['-I','-B','/tmp/source/xs/compiler_image.py','--copy-driver',b['source']]},'Mounts':[{'Type':'bind','Source':'/source','Destination':'/tmp/source','RW':False}],'HostConfig':{'ReadonlyRootfs':False,'NetworkMode':'none','CapDrop':['ALL'],'CapAdd':[],'Privileged':False,'Devices':[],'Init':False,'SecurityOpt':['no-new-privileges'],'Memory':536870912,'MemorySwap':536870912,'NanoCpus':2000000000,'PidsLimit':64,'Tmpfs':{'/tmp':'rw,noexec,nosuid,nodev,size=8m'}}}
  C.confinement(row,'owned',parent,labels,Path('/source'),b,cid,d)
  for key,value in [('NetworkMode','host'),('CapAdd',['SYS_ADMIN']),('MemorySwap',1073741824),('PidsLimit',256),('Init',True),('PidMode','host')]:
   bad=copy.deepcopy(row);bad['HostConfig'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):C.confinement(bad,'owned',parent,labels,Path('/source'),b,cid,d)
  bad=copy.deepcopy(row);bad['Mounts'][0]['RW']=True
  with self.assertRaises(ValueError):C.confinement(bad,'owned',parent,labels,Path('/source'),b,cid,d)
  with self.assertRaises(ValueError):C.confinement(row,'owned',parent,labels,Path('/source'),b,'c'*64,d)
 def test_derived_retirement_requires_removal_and_exact_absence(self):
  b={'Id':'sha256:'+'1'*64,'Architecture':'arm64','Os':'linux','Size':1000,'Config':{'Labels':{},'User':'alarm'},'RootFS':{'Layers':['sha256:'+'a'*64]}};v=copy.deepcopy(b);v.update(Id='sha256:'+'2'*64,Size=2366000,RepoTags=['owned:one']);v['RootFS']['Layers']+=['sha256:'+'b'*64];v['Config']['Labels']={'seal':'owned'}
  q={'parent_image':b['Id'],'image':v['Id'],'tag':'owned:one','labels':v['Config']['Labels'],'layer':'sha256:'+'b'*64,'image_delta_bytes':2365000};expected=[C.DOCKER+['image','inspect',v['Id']],C.DOCKER+['image','rm',v['Id']],C.DOCKER+['image','inspect',v['Id']]]
  class Sequence:
   def __init__(self,wrong=False):self.index=0;self.wrong=wrong
   def take(self,argv,**kw):
    self_outer.assertEqual(argv,expected[self.index]);i=self.index;self.index+=1
    if i==0:return json.dumps([v]).encode(),b''
    if i==1:return ('Deleted: '+v['Id']+'\n').encode(),b''
    return b'',('Error response from daemon: No such image: '+('foreign'if self.wrong else v['Id'])).encode()
  self_outer=self;h={'cleanup':{'compiler_image':{'image':v['Id'],'removed':True,'absence_verified':True}}};seq=Sequence();C.retire(seq,q,h,b,d);self.assertEqual(seq.index,3)
  with self.assertRaises(ValueError):C.retire(Sequence(True),q,h,b,d)
 @unittest.skipUnless(ROOT_SOURCE.is_dir(),'retained Source DATA unavailable; no actual Reader role implied')
 def test_actual305_full_inverse_and_runtime_Source_DATA_only(self):
  self.assertEqual(R.source(ROOT_SOURCE,binding())['actual'],R.ACTUAL)
  mode=R.B.load('v2/adapters.py','modeled_modes');raw=d.read(ROOT_SOURCE,'accepted/runtime-files.json');manifest=d.decode(raw);inputs=dict(archive_sha256=manifest['archive']['sha256'],files=manifest['files']);prep=dict(files=manifest['files'],runtime_manifest=mode.MODE_PIN)
  get=lambda n:json.dumps(inputs if n.endswith('xs-inputs.json')else prep).encode();self.assertEqual(mode.mode_map(get,ROOT_SOURCE,d)['files'],1870)
  inputs['files']=dict(inputs['files']);name=next(iter(inputs['files']));inputs['files'][name]=dict(inputs['files'][name],mode=0o777)
  with self.assertRaises(ValueError):mode.mode_map(get,ROOT_SOURCE,d)

if __name__=='__main__':unittest.main(verbosity=2)
