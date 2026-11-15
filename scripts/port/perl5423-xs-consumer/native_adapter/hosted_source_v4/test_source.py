# SPDX-License-Identifier: MIT
"""Fenced DATA controls. Never run preparation main, image, compiler or XS roles."""
import contextlib,copy,hashlib,importlib.util,json,os,sys,tarfile,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
P=load('xs_v4_constructor_controls',HERE/'prepare.py');C=load('xs_v4_image_controls',HERE/'payload/xs/compiler_image.py');I=load('xs_v4_archive_controls',HERE/'inspect_archives.py')
ACTUAL_PARENT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-perl-xs-source-r3/source-tree')
class Controls(unittest.TestCase):
 def setUp(self):
  stack=contextlib.ExitStack();self.addCleanup(stack.close)
  for name in ['subprocess.run','subprocess.Popen','socket.socket','fcntl.flock','os.pidfd_open']:stack.enter_context(patch(name,side_effect=AssertionError('fenced Source DATA only'),create=name=='os.pidfd_open'))
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def test_profile_and_actual_selectors_are_unissued(self):
  profile=P.atomic.decode((HERE/'profile.json').read_bytes());self.assertEqual(profile['actual'],P.ACTUAL);self.assertEqual(profile['operation'],'perl5423-native-xs-v4');self.assertEqual(profile['delegated_consumer_operation'],'perl5423-native-xs-v1')
  for name,row in profile['payload'].items():self.assertEqual(dict(**C.pin((HERE/'payload'/name).read_bytes()),mode=0o644),row)
 def test_bad_profile_refuses_before_parent(self):
  with self.assertRaises(ValueError):P.render(self.root/'missing','0'*64)
  profile=P.atomic.decode((HERE/'profile.json').read_bytes());profile['actual']['run']='NOT_AN_ACTUAL_RUN';raw=P.encode(profile);(self.root/'profile.json').write_bytes(raw)
  with patch.object(P,'HERE',self.root),patch.object(P,'previous',side_effect=AssertionError('unissued actual must refuse first')):
   with self.assertRaises(ValueError):P.render(self.root/'missing',C.pin(raw)['sha256'])
 def test_incomplete_parent_refuses(self):
  (self.root/'inert').write_bytes(b'not a Source')
  with self.assertRaises(ValueError):P.previous(self.root)
 def test_workflow_retains_lane_and_exports_compiler_receipts(self):
  raw=b'native-arm-perl5423-xs-v3\nperl5423-native-xs-v3\n'+b'a'*64+b'\ngroup: native-arm-build\n  cancel-in-progress: false\n  queue: max\n            ${{ runner.temp }}/perl-hosted/preparation*.json\n            ${{ runner.temp }}/perl-hosted/compiler-image*.json\n'
  got=P.workflow(raw,'a'*64,'b'*64);self.assertIn(b'perl5423-native-xs-v4',got);self.assertIn(b'compiler-image*.json',got);self.assertIn(b'queue: max',got)
  with self.assertRaises(ValueError):P.workflow(raw.replace(b'queue: max',b'queue: wrong'),'a'*64,'b'*64)
 def test_single_link_reader_remains_strict_and_explicit_alias_reader_is_bounded(self):
  path=self.root/'gcc';path.write_bytes(b'opaque fixture');os.link(path,self.root/'gcc-version');os.link(path,self.root/'gcc-canonical')
  with self.assertRaises(ValueError):C.ordinary(path)
  self.assertEqual(C.ordinary(path,100,3)[0],b'opaque fixture')
  with self.assertRaises(ValueError):C.ordinary(path,2,3)
  (self.root/'alias').symlink_to(path)
  with self.assertRaises(ValueError):C.ordinary(self.root/'alias',100,3)
 def test_one_new_copy_preserves_exact_bytes_mode_and_original_links(self):
  body=b'opaque fixture, never executable';source=self.root/'gcc';source.write_bytes(body);source.chmod(0o755);os.link(source,self.root/'gcc-version');os.link(source,self.root/'gcc-canonical');before=C.state(source.stat());target=self.root/'single'
  row=dict(**C.pin(body),mode=0o755);got,st=C.copy_driver(C.ordinary(source,100,3)[0],target,row)
  self.assertEqual((got,st.st_nlink,st.st_mode&0o777),(body,1,0o755));self.assertEqual(C.state(source.stat()),before)
  with self.assertRaises(ValueError):C.copy_driver(body,target,row)
 def test_wrong_copy_bytes_and_mode_refuse_before_write(self):
  target=self.root/'bad';row=dict(**C.pin(b'expected'),mode=0o755)
  with self.assertRaises(ValueError):C.copy_driver(b'foreign',target,row)
  with self.assertRaises(ValueError):C.copy_driver(b'expected',target,dict(row,mode=0o777))
  self.assertFalse(target.exists())
 def test_image_actor_argv_has_explicit_cap0_bounds_and_root_writable_domain(self):
  argv=C.create_argv('owned','sha256:'+'a'*64,{'owner':'modeled'},Path('/held/source'),'b'*40)
  for item in ['--user=0:0','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=512m','--memory-swap=512m','--pids-limit=64','--init=false']:self.assertIn(item,argv)
  self.assertNotIn('--privileged',argv);self.assertNotIn('--read-only',argv);self.assertIn('type=bind,src=/held/source,dst=/tmp/source,readonly',argv);self.assertEqual(argv[-2:],['--copy-driver','b'*40])
 def test_derived_image_is_new_exact_one_layer_and_bounded(self):
  cfg=dict(User='alarm',WorkingDir='/tmp',Entrypoint=None,Cmd=None,Env=['PATH=/usr/bin'],Labels={'parent':'one'},AttachStdout=False,AttachStderr=False,Hostname='',Image='')
  parent=dict(Id='sha256:'+'1'*64,Architecture='arm64',Os='linux',Config=cfg,RootFS={'Layers':['sha256:'+'a'*64]},Size=1000000)
  labels={'parent':'one','seal':'unique'};derived=copy.deepcopy(parent);derived.update(Id='sha256:'+'2'*64,RepoTags=['private:unique'],Size=parent['Size']+2365000);derived['RootFS']['Layers'].append('sha256:'+'b'*64);seal=dict(cfg,AttachStdout=True,AttachStderr=True,Hostname='a'*12,Image=parent['Id']);derived['Config']=C.expected_config(parent,labels,seal)
  self.assertEqual(C.image_qualified(parent,derived,labels,'private:unique',seal)['image_delta_bytes'],2365000)
  for change in ['same','size','layer','env','wrongarch']:
   bad=copy.deepcopy(derived)
   if change=='same':bad['Id']=parent['Id']
   elif change=='size':bad['Size']=parent['Size']+8*1024**2+1
   elif change=='layer':bad['RootFS']['Layers'][0]='foreign'
   elif change=='env':bad['Config']['Env']=['PATH=/foreign']
   else:bad['Architecture']='amd64'
   with self.subTest(change=change),self.assertRaises(ValueError):C.image_qualified(parent,bad,labels,'private:unique',seal)
 def test_frozen_consumer_policy_not_replaced_and_new_driver_stays_usr_bin(self):
  source=(HERE/'payload/xs/prepare_inputs.py').read_text();self.assertIn("cc=tool('/usr/bin/cachy-asahi-xs-gcc')",source);self.assertNotIn('GCC_EXEC_PREFIX',source);self.assertEqual(C.TARGET.parent,Path('/usr/bin'));self.assertEqual(P.NEW_FILES,set())
 def test_exact_archive_descriptor_and_license_notices(self):
  raw=(HERE/'compiler-inputs.json').read_bytes();self.assertEqual(C.pin(raw),C.MANIFEST);m=json.loads(raw);r=m['payload'][m['driver_source']];self.assertEqual((r['bytes'],r['mode'],r['sha256']),(2365000,0o755,'741ced8152a820a28ab88603dd1ceb2343245728ac784839e4b5390f2411890e'));self.assertEqual(len(r['aliases']),3);self.assertEqual(m['archives']['gcc']['license_payloads']['usr/share/licenses/gcc/RUNTIME.LIBRARY.EXCEPTION']['sha256'],'9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74')
 def test_v3_native_cleanup_keeps_parent_and_derived_distinct(self):
  text=(HERE/'payload/xs/entry.py').read_text();self.assertIn('parent_image = image',text);self.assertIn("compiler_seal['image']",text);self.assertIn('compiler_stage.retire(common, command, compiler_seal)',text);self.assertIn('image = parent_image',text);self.assertIn('row[\'Image\'] == expected_image',text)

 def test_exact_actual_v3_config_failure_remains_refused(self):
  fixture=json.loads((HERE/'closed-v3-config-fixture.json').read_bytes());parent=fixture['parent'];old=fixture['closed_v3_derived'];seal=fixture['sealing_config'];labels=old['Config']['Labels'];tag=old['RepoTags'][0]
  with self.assertRaisesRegex(ValueError,'exact full derived Config'):C.image_qualified(parent,old,labels,tag,seal)
  # Modeled v4: only the requested nonempty defaults replace the retained v3
  # executable/argv. All four actual metadata fields remain exact fixtures.
  new=copy.deepcopy(old);new['Config']['Entrypoint']=['/usr/bin/false'];new['Config']['Cmd']=['/usr/bin/false'];result=C.image_qualified(parent,new,labels,tag,seal)
  self.assertEqual(result['derived_default_argv'],{'Entrypoint':['/usr/bin/false'],'Cmd':['/usr/bin/false']});self.assertEqual(result['sealing_config_metadata'],{k:seal[k]for k in C.CAPTURED_CONFIG_FIELDS})
 def test_all_four_captured_fields_are_bound_not_ignored(self):
  fixture=json.loads((HERE/'closed-v3-config-fixture.json').read_bytes());parent=fixture['parent'];old=fixture['closed_v3_derived'];seal=fixture['sealing_config'];labels=old['Config']['Labels'];tag=old['RepoTags'][0];good=copy.deepcopy(old);good['Config']=C.expected_config(parent,labels,seal)
  for key in C.CAPTURED_CONFIG_FIELDS:
   bad=copy.deepcopy(good);bad['Config'][key]=not bad['Config'][key]if isinstance(bad['Config'][key],bool)else'foreign'
   with self.subTest(key=key),self.assertRaises(ValueError):C.image_qualified(parent,bad,labels,tag,seal)
   incomplete=dict(seal);del incomplete[key]
   with self.assertRaises(ValueError):C.expected_config(parent,labels,incomplete)
 def test_other_config_fields_and_extra_keys_stay_exact(self):
  f=json.loads((HERE/'closed-v3-config-fixture.json').read_bytes());parent=f['parent'];old=f['closed_v3_derived'];seal=f['sealing_config'];labels=old['Config']['Labels'];tag=old['RepoTags'][0];good=copy.deepcopy(old);good['Config']=C.expected_config(parent,labels,seal)
  for key,value in [('User','0:0'),('WorkingDir','/'),('Env',['FOREIGN=yes']),('UnknownField','unreviewed'),('Entrypoint',[]),('Cmd',[])]:
   bad=copy.deepcopy(good);bad['Config'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):C.image_qualified(parent,bad,labels,tag,seal)
 @unittest.skipUnless(ACTUAL_PARENT.is_dir(),'retained frozen consumer Source DATA unavailable')
 def test_actual_preparation_and_frozen_XS_argv_override_image_defaults(self):
  # Parse the exact frozen project source as DATA, without importing a producer.
  import ast
  entry=(HERE/'payload/xs/entry.py').read_text();node=next(n for n in ast.parse(entry).body if isinstance(n,ast.FunctionDef)and n.name=='prepare_argv');strings={n.value for n in ast.walk(node)if isinstance(n,ast.Constant)and isinstance(n.value,str)};self.assertIn('--entrypoint=/usr/bin/python3',strings);self.assertIn('/source/xs/prepare_inputs.py',strings);self.assertIn('-I',strings);self.assertIn('-B',strings)
  source=(ACTUAL_PARENT/'consumer/native_adapter/native.py').read_bytes();tree=ast.parse(source);actor=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='create_argv');strings={n.value for n in ast.walk(actor)if isinstance(n,ast.Constant)and isinstance(n.value,str)};self.assertIn('--entrypoint=/usr/bin/python3',strings);self.assertIn('/inputs/consumer/native_adapter/native.py',strings);self.assertIn('actor',strings)
  self.assertIn(b'--entrypoint=/usr/bin/chown',source)
 @unittest.skipUnless(ACTUAL_PARENT.is_dir(),'retained exact305 Source needed; portable controls still run')
 def test_actual_full305_join_v4_render_and_exact_inverse(self):
  sha=C.pin((HERE/'profile.json').read_bytes())['sha256'];files=P.render(ACTUAL_PARENT,sha);before=P.inverse(files);self.assertEqual((len(files),len(before)),(311,305));self.assertEqual(P.atomic.tree(before),P.PARENT_TREE)
  self.assertTrue(all(files[n]==r for n,r in before.items()if n.startswith(('held/','consumer/','accepted/'))));self.assertEqual(json.loads(files['source-map.json'][0])['actual'],P.ACTUAL)
  report=dict(status='PASS_ACTUAL_PARENT_DATA_JOIN_RENDER_INVERSE_ONLY',files=len(files),bytes=sum(len(b)for b,_ in files.values()),map=C.pin(files['source-map.json'][0]),prospective_tree=P.atomic.tree(files),profile=C.pin((HERE/'profile.json').read_bytes()),image='NOT RUN',compiler='NOT RUN',XS='NOT RUN')
  print('ACTUAL_DATA_RESULT '+json.dumps(report,sort_keys=True))

if __name__=='__main__':unittest.main(verbosity=2)
