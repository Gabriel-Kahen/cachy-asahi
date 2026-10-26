# SPDX-License-Identifier: MIT
"""Actual selected module/callsite seams and private owned-file refusal controls."""
import argparse,ast,copy,importlib.util,json,os,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent
parser=argparse.ArgumentParser();parser.add_argument('--core-source',type=Path,required=True);parser.add_argument('--vm-source',type=Path,required=True);parser.add_argument('--fresh607-source',type=Path,required=True);A,rest=parser.parse_known_args();sys.argv=[sys.argv[0],*rest]
CASE=D if(D/'case.py').exists()else D/'source-known';sys.path.insert(0,str(CASE));import case as C,desktop622 as X,formation622 as F,lane622 as L,run622 as R,ownership622 as O
V=json.loads((D/('composition.json'if(D/'composition.json').exists()else'input-profile.json')).read_bytes())
class Controls(unittest.TestCase):
 def test_complete_private_formation_graph_db_capabilities_and_mutations(self):
  base=V['before607'];added=set(base)-set(V['before574']);oldnode=dict(type='file',mode=0o600,uid=os.getuid(),gid=os.getgid(),bytes=1,sha256='a'*64);before=dict(complete=True,unsupported_counts={},nodes={'root/private':oldnode,'usr/lib/libfdk-aac.so':oldnode},hardlink_groups={});nodes={'root/private':dict(oldnode)};ownership={n:[]for n in base};signed={}
  for n in added:
   p='usr/new-'+n;ownership[n]=[p];signed[p]=dict(oldnode);nodes[p]=dict(oldnode)
  after=dict(complete=True,unsupported_counts={},nodes=nodes,hardlink_groups={});payload=dict(nodes=signed,ownership=ownership,hardlinks=[],packages=base);removed=dict(nodes={'usr/lib/libfdk-aac.so':oldnode});initial=[dict(name=n,version=v,files=[])for n,v in V['before574'].items()];final=[dict(name=n,version=v,files=ownership[n])for n,v in base.items()];aux=dict(status='FULL_FD_CHECKPOINT_AND_LIVE_AUXILIARY_LIBRARY_KEYS');args=(V,before,after,{}, {},payload,removed,initial,final,aux);self.assertEqual(F.check(*args)['held'],573)
  for kind in('foreign','held','new','removed','caps','db'):
   values=copy.deepcopy(args)
   if kind=='foreign':values[2]['nodes']['foreign']=dict(oldnode)
   elif kind=='held':values[2]['nodes']['root/private']['mode']=0o644
   elif kind=='new':values[2]['nodes'][next(iter(signed))]['sha256']='b'*64
   elif kind=='removed':values[2]['nodes']['usr/lib/libfdk-aac.so']=dict(oldnode)
   elif kind=='caps':values[4]['root/private']={'forged':True}
   else:values[8][0]['version']='foreign'
   with self.assertRaises(ValueError,msg=kind):F.check(*values)
 def test_actual_current_assembly_globals_and_original_guard_bodies(self):
  import assembly622
  selected=assembly622.module(A.core_source);self.assertEqual(tuple(map(len,selected.C.states())),(607,620,622));self.assertIs(selected.main.__globals__['C'],selected.C);self.assertIs(selected.verify_inputs.__globals__['C'],selected.C);self.assertIn('64',selected.verify_inputs.__code__.co_consts[-1]if isinstance(selected.verify_inputs.__code__.co_consts[-1],str)else'64');self.assertEqual(selected.C.profile()['counts']['installed'],622)
 def test_real_two_library_import_namespace_and_explicit_factory_bindings(self):
  original_adapter=sys.modules.get('adapter');original_case=sys.modules.get('case');bindings=dict(case=C,adapter=__import__('adapter'),desktop622=X,ownership622=O)
  with R.namespace(A.fresh607_source/'implementation'):
   fresh=C.load('_actual_fresh1197_namespace_control',A.fresh607_source/'implementation/run.py');self.assertEqual(Path(fresh.adapter.__file__).resolve(),(A.fresh607_source/'implementation/adapter.py').resolve());self.assertTrue(hasattr(fresh.adapter,'emit'))
   class Selected(fresh.Integration):pass
   callback=lambda raw:R.derive(fresh.derive(raw));selected=X.clone(fresh,Integration=Selected,derive=callback);self.assertIs(selected.main.__globals__['Integration'],Selected);self.assertIs(selected.main.__globals__['derive'],callback)
   with R.namespace(CASE,bindings):
    import adapter,controller
    self.assertEqual(Path(adapter.__file__).resolve(),(CASE/'adapter.py').resolve());self.assertEqual(tuple(map(len,adapter.core(A.core_source).C.states())),(607,620,622));self.assertIs(controller.adapter,adapter)
   self.assertIs(sys.modules['adapter'],fresh.adapter)
  self.assertIs(sys.modules.get('adapter'),original_adapter);self.assertIs(sys.modules.get('case'),original_case)
 def test_actual_generated_media_source_and_whole_clock_owner_inverse(self):
  import media,controller
  text,held=media.derive(A.vm_source/'runtime');emitted=L.media_text(text);self.assertIn("copier.copy_data(Path('/current607-root')",emitted);self.assertIn('actual607 graph bound before full media copy',emitted);self.assertIn('whole actual607 capability map',emitted);compile(emitted,'actual-media622','exec');body=controller.derive_owner(A.core_source);self.assertLess(body.index('PROVISION607(args,report,command,deadline)'),body.index('index=binding(args,report)'));self.assertIn('min(time.monotonic()+14400,args.outer_deadline)',body);self.assertIn('snapshot_source(args.workspace',body)
 def test_actual_generated_fresh_callsite_uses_current_host(self):
  sys.path.insert(0,str(A.fresh607_source/'implementation'));fresh=C.load('_held1197_for622_bridge_control',A.fresh607_source/'implementation/run.py');oldpath=A.fresh607_source/'installer604/scripts/ci/expanded604-apps6-public-pair-installer/ci.py';text=R.derive(fresh.derive(C.read(oldpath,256*1024)));tree=ast.parse(text);calls=[n for n in ast.walk(tree)if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Attribute)and isinstance(n.value.func.value,ast.Name)and n.value.func.value.id=='Y'and n.value.func.attr=='core_host'];self.assertEqual(len(calls),1);seen=[]
  namespace=dict(Y=types.SimpleNamespace(core_host=lambda a:seen.append(a)),SimpleNamespace=types.SimpleNamespace,ready604=Path('/private/ready'),C=types.SimpleNamespace(sha=lambda p:'c'*64),args=types.SimpleNamespace(legacy_source=Path('/private/code')),candidate=Path('/private/candidate'),cache=Path('/private/cache'),vm_output=Path('/tmp/private-vm'))
  exec(compile(ast.Module(body=calls,type_ignores=[]),'actual-derived-Core-host-callsite','exec'),namespace);self.assertEqual(len(seen),1);self.assertEqual(seen[0].ready,Path('/private/ready'));self.assertEqual(seen[0].output,Path('/tmp/private-vm'));self.assertIn('Y.cleanup(producer,producer_output,vm_output)',text);self.assertNotIn('cleanup=producer.cleanup(producer_output)',text)
 def test_owned_handoff_requires_independent_exact_absence_and_raw_identity(self):
  with tempfile.TemporaryDirectory(prefix='core622-handoff-',dir='/tmp')as td:
   root=Path(td);producer=root.with_name(root.name+'-producer');consumer=root.with_name(root.name+'-consumer');producer.mkdir(mode=0o700);consumer.mkdir(mode=0o700)
   try:
    base=producer/'private/desktop574';base.mkdir(parents=True);image='sha256:'+'a'*64;borrowed='sha256:'+'b'*64;raw=(image+'\n').encode();(base/'image-id').write_bytes(raw);report=dict(image=image,ownership=dict(token='c'*16,before_images=[]),owned_cleanup=dict(status='PASS',image=dict(id=image,absence_verified=True),probe=dict(absence_verified=True)));(base/'report.json').write_text(json.dumps(report));(producer/'producer-owner.json').write_text(json.dumps(dict(token='d'*32,core_image=borrowed,images_preexisting=[borrowed])));proof=dict(producer_token='c'*16);cleanup=dict(status='PASS_ALL_VM_THEN_ORIGINAL800_CONSUMER_PRODUCER_RETIREMENT',original_cleanup=0);seen=[]
    def ambiguous(*a):seen.append(a);return dict(code=1,out=b'',err=b'unknown daemon state')
    with self.assertRaises(ValueError):O.handoff(producer,consumer,proof,cleanup,ambiguous,time.monotonic()+5)
    self.assertEqual((base/'image-id').read_bytes(),raw);self.assertEqual(len(seen),1)
    def absent(argv,*a):self.assertEqual(argv,['/usr/bin/docker','image','inspect',image]);return dict(code=1,out=b'[]\n',err=('Error: No such image: '+image).encode())
    value=O.handoff(producer,consumer,proof,cleanup,absent,time.monotonic()+5);self.assertTrue(value['independent_absence']);self.assertFalse((base/'image-id').exists());self.assertEqual((consumer/'image-retirement/original-desktop574-image-id').read_bytes(),raw)
   finally:
    import shutil
    shutil.rmtree(producer);shutil.rmtree(consumer)
 def test_whole_original_cleanup_body_executes_with_real_private_files(self):
  sys.path.insert(0,str(A.fresh607_source/'implementation'));fresh=C.load('_actual1197_runtime_for622_control',A.fresh607_source/'implementation/run.py');legacy=A.fresh607_source/'installer604/scripts/ci/full-composition-installer-vm/producer.py';original=C.load('_actual_whole_original_cleanup_for622',legacy)
  with tempfile.TemporaryDirectory(prefix='core622-original-cleanup-',dir='/tmp')as td:
   root=Path(td);(root/'private').mkdir();(root/'private/ordinary').write_bytes(b'owned private fixture');(root/'public').mkdir();(root/'producer-owner.json').write_text(json.dumps(dict(schema_version=1,token='a'*32,core_image='sha256:'+'b'*64,images_preexisting=[])));context=R.Context(Path('/unexecuted'),A.fresh607_source,{},time.monotonic()+10)
   with patch('subprocess.Popen',side_effect=AssertionError('no actor in genuine private cleanup control')):result=context.cleanup(original,root,root.with_name(root.name+'-vm'))
   self.assertEqual(result['status'],'PASS');self.assertFalse((root/'private').exists());self.assertEqual(json.loads((root/'public/producer-cleanup.json').read_bytes())['status'],'PASS')
 def test_before51_inverse_and_current_product_drift(self):
  import source622
  rows=source622.inverse(CASE);self.assertEqual(len(rows),51);self.assertEqual(C.pin(rows['guest.py']),json.loads((CASE/'composition-parent.json').read_bytes())['before']['guest.py']);self.assertEqual(C.read(CASE/'guest.py'),rows['guest.py']);self.assertEqual(C.read(CASE/'effects.py'),rows['effects.py']);self.assertEqual(C.read(CASE/'validate.py'),rows['validate.py']);self.assertIsNone(json.loads((CASE/'source-manifest.json').read_bytes())['actual'])
 def test_actual_original_producer_desktop_gets_existing_owned_token_before_command(self):
  producer=C.load('_core622_real_base_owner_seam_control',A.fresh607_source/'installer604/scripts/ci/full-composition-installer-vm/producer.py');caller=A.fresh607_source/'installer604/scripts/ci/full-root-upgrade-caller/run.py';seen=[];captured=[]
  class Reached(Exception):pass
  with tempfile.TemporaryDirectory(prefix='core622-owned-base-',dir='/tmp')as td:
   root=Path(td);(root/'private').mkdir();(root/'cache').mkdir();owner=dict(schema_version=1,token='a'*32,preparation_source='/same/preparation');(root/'producer-owner.json').write_text(json.dumps(owner));args=types.SimpleNamespace(code=A.fresh607_source/'installer604',output=root,preparation_source=Path('/same/preparation'))
   def prepare(scoped,args):
    api=scoped.load(caller);captured.append(api);selected=api.desktop;prior_command=api.command
    def command(argv,log,seconds):seen.append((argv,log,seconds));raise Reached()
    api.command=command
    try:
     with self.assertRaises(Reached):api.desktop(A.core_source/'runtime/runtime-vm',root/'private',root/'cache')
    finally:api.command=prior_command
    self.assertIs(api.desktop,selected)
   with patch('subprocess.Popen',side_effect=AssertionError('owned-base control stops before actual build command')):O.prepare_owned(producer,args,prepare,C.pin(C.read(caller,128*1024))['sha256'])
   self.assertEqual(len(seen),1);argv,log,seconds=seen[0];self.assertEqual(argv[-2], '--job-token');self.assertEqual(argv[-1],__import__('hashlib').sha256(('core622-owned574:'+owner['token']).encode()).hexdigest()[:16]);self.assertEqual(seconds,2400);self.assertEqual((root/'private/desktop574').stat().st_mode&0o777,0o700);self.assertNotIn('CURRENT_CORE622_BASE_TOKEN',vars(captured[0]));self.assertNotIn('CURRENT_CORE622_BASE_TOKEN',captured[0].desktop.__code__.co_names)
 def test_real_original_opaque_transport_and_current_failure_export(self):
  import export622,zipfile
  with tempfile.TemporaryDirectory(prefix='core622-transport-',dir='/tmp')as td:
   root=Path(td);(root/'result.json').write_text(json.dumps(dict(status='FAIL',producer='NOT_RUN')));public=root/'public';export622.copy(root,public);self.assertEqual(json.loads((public/'current622-context.json').read_bytes())['acceptance'],False);target=root/'transport';export622.transport(A.core_source,public,target);record=json.loads((target/'transport.json').read_bytes());self.assertEqual(record['status'],'OPAQUE_CORE7_PUBLIC_DATA_ONLY');self.assertEqual(record['acceptance'],False)
   with zipfile.ZipFile(target/'public.zip')as z:self.assertEqual({n:C.pin(z.read(n))for n in z.namelist()},R.public_rows(public))
 def test_actual_original800_cleanup_entry_namespace_and_restore(self):
  import entry
  prior=sys.modules['entry'];original=C.load('_real800_noactors_cleanup_for622',A.core_source/'scripts/ci/core-native-lifecycle/owner.py')
  with tempfile.TemporaryDirectory(prefix='core622-old-cleanup-',dir='/tmp')as td:
   root=Path(td);proof=root/'proof.json';proof.write_text(json.dumps(dict(consumer_token='a'*32,producer_token='b'*16)));args=types.SimpleNamespace(core_source=A.core_source,source=A.core_source,workspace=A.core_source/'runtime/runtime-vm',proof=proof,base=root/'absent-base',output=root/'absent-consumer',receipt=root/'receipt.json')
   with patch('subprocess.Popen',side_effect=AssertionError('no actor for genuine original cleanup NOT_STARTED route')):code=L.old_cleanup(original,args)
   self.assertEqual(code,0);self.assertEqual(json.loads(args.receipt.read_bytes())['status'],'PASS_ORDERED_ALL_CONSUMERS_THEN_PRODUCER');self.assertIs(sys.modules['entry'],prior)
 def test_current_product_and_whole_before_inverse_drift_refuse_before_parent_execution(self):
  import shutil,source622
  for kind in('product','before','foreign'):
   with tempfile.TemporaryDirectory(prefix='core622-drift-')as td:
    root=Path(td)/'source';shutil.copytree(CASE,root)
    if kind=='product':(root/'desktop622.py').write_bytes(C.read(root/'desktop622.py')+b'\n')
    elif kind=='before':
     record=json.loads((root/'composition-parent.json').read_bytes());record['changed']['case.py']+='\n';(root/'composition-parent.json').write_text(json.dumps(record))
    else:(root/'foreign').write_bytes(b'foreign')
    with patch('subprocess.Popen',side_effect=AssertionError('no parent proof after changed current source')):
     with self.assertRaises(ValueError):source622.verify(root)
if __name__=='__main__':unittest.main(verbosity=2)
