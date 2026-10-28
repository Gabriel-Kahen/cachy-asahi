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
 def _core_source_fact_fixture(self):
  p=json.loads((CASE/'profile.json').read_bytes())['source_profiles']['core800']
  # Control DATA only; native inputs() still performs the full actual Git proof.
  return dict(status='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY',source=p['source'],ref=p['ref'],files=len(p['files']),blob_joins=len(p['files']),tree='a'*40)
 def _desktop_args_fixture(self,root):
  old=json.loads((CASE/'composition-parent.json').read_bytes())['actual_desktop_helper'];raw=old['body'].encode();self.assertEqual(C.pin(raw),old['pin']);self.assertEqual(old['source'],'9a2e520dbdfce7e4af417595ff3de9e6a284ef04');desktop=root/'unowned-desktop';scripts=desktop/'scripts/ci';scripts.mkdir(parents=True);(scripts/'maintained_desktop574.py').write_bytes(raw);(scripts/'maintained-desktop574-inputs.json').write_bytes(C.read(A.core_source/O.OWNED_CLOSURE[1],4*1024**2));output=root;(output/'private').mkdir(mode=0o700);(output/'public').mkdir();(root/'cache').mkdir();owner=dict(schema_version=1,token='a'*32,preparation_source='/same/preparation',core_image='sha256:'+'b'*64,images_preexisting=[]);(output/'producer-owner.json').write_bytes(C.encoded(owner));return types.SimpleNamespace(code=A.fresh607_source/'installer604',output=output,desktop=desktop,preparation_source=Path('/same/preparation'),cache=root/'cache'),owner
 def test_actual_original_producer_desktop_gets_existing_owned_token_before_command(self):
  producer=C.load('_core622_real_base_owner_seam_control',A.fresh607_source/'installer604/scripts/ci/full-composition-installer-vm/producer.py');caller=A.fresh607_source/'installer604/scripts/ci/full-root-upgrade-caller/run.py';diag=C.load('_core622_exact_command_factory',A.fresh607_source/'implementation/producer_diagnostic.py');seen=[];captured=[]
  class Reached(Exception):pass
  with tempfile.TemporaryDirectory(prefix='core622-correct-owned-base-',dir='/tmp')as td:
   root=Path(td);args,owner=self._desktop_args_fixture(root)
   def factory(original,raw,callback):
    selected=diag.command(original,raw,callback)
    def command(argv,log,seconds):seen.append((list(map(str,argv)),log,seconds));return selected(argv,log,seconds)
    return command
   def prepare(scoped,args):
    api=scoped.load(caller);captured.append(api);selected=api.desktop
    # The updater callback may wrap its own global command after this loader;
    # the dedicated fixed desktop command must survive that real nesting seam.
    api.command=diag.command(api.command,C.read(caller,128*1024),lambda *a:None)
    with self.assertRaises(Reached):api.desktop(args.desktop,args.output/'private',root/'cache')
    self.assertIs(api.desktop,selected)
   with patch('subprocess.Popen',side_effect=Reached('before any actual build')):O.prepare_owned(producer,args,prepare,C.pin(C.read(caller,128*1024))['sha256'],A.core_source,self._core_source_fact_fixture(),factory,lambda value:None,time.monotonic()+30)
   self.assertEqual(len(seen),1);argv,log,seconds=seen[0];self.assertEqual(argv[3],str(A.core_source/O.OWNED_CLOSURE[0]));self.assertNotEqual(argv[3],str(args.desktop/'scripts/ci/maintained_desktop574.py'));self.assertEqual(argv[-2], '--job-token');self.assertEqual(argv[-1],__import__('hashlib').sha256(('core622-owned574:'+owner['token']).encode()).hexdigest()[:16]);self.assertEqual(seconds,2400);self.assertEqual(log,args.output/'private/desktop574/build.log');self.assertEqual((args.output/'private/desktop574').stat().st_mode&0o777,0o700)
   for name in('CURRENT_CORE622_BASE_TOKEN','CURRENT_CORE622_OWNED_HELPER','CURRENT_CORE622_DESKTOP_COMMAND'):self.assertNotIn(name,vars(captured[0]));self.assertNotIn(name,captured[0].desktop.__code__.co_names)
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
 def test_actual_first_provision_binds_real_command_ledger_before_receipt(self):
  import inspect
  original=__import__('adapter').core(A.core_source);owner=C.load('_real800_provision_receipt_owner',A.core_source/'scripts/ci/core-native-lifecycle/owner.py');scoped=X.clone(owner,runtime=lambda workspace:original.api['runtime']);self.assertIs(scoped.command_api.__code__,owner.command_api.__code__)
  controller_ast=ast.parse((CASE/'controller.py').read_bytes());wrapper=next(n for n in controller_ast.body if isinstance(n,ast.FunctionDef)and n.name=='actor');calls=[n for n in ast.walk(wrapper)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='actor_text'];self.assertEqual(len(calls),1);actor_ast=ast.parse(calls[0].args[0].value);assignments=[n for n in ast.walk(actor_ast)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='run_row'for t in n.targets)and isinstance(n.value,ast.Subscript)];self.assertEqual(len(assignments),1);statement=assignments[0];self.assertEqual(ast.unparse(statement),"run_row = args._owner_report['commands'][-1]");receipt_code=compile(ast.Module(body=[copy.deepcopy(statement)],type_ignores=[]),'<actual-actor-source-receipt-binding>','exec')
  # This is a real harmless owned command and its real group-retirement record;
  # no Docker, image, VM or native lifecycle result is fabricated by the fixture.
  class ReceiptBoundary(Exception):pass
  def actor(args,command,*unused):
   command(['/usr/bin/true'],True,5);env={'args':args};exec(receipt_code,env);raise ReceiptBoundary(env['run_row'])
  fixture=types.SimpleNamespace(prepare_work=lambda *unused:None,actor=actor)
  with tempfile.TemporaryDirectory(prefix='core622-report-binding-',dir='/tmp')as td,patch.dict(sys.modules,{'controller':fixture}):
   root=Path(td);report=dict(commands=[],source_fixture='NO_NATIVE_AUTHORITY');args=types.SimpleNamespace(output=root,_owner_report={'commands':[{'foreign':True}]});command=scoped.command_api(A.core_source/'runtime/runtime-vm',root,report)
   with self.assertRaises(ReceiptBoundary)as found:L.provision(args,report,command,time.monotonic()+30)
   self.assertIs(args._owner_report,report);self.assertIs(found.exception.args[0],report['commands'][-1]);self.assertEqual(len(report['commands']),1);self.assertEqual(report['commands'][0]['exit_code'],0);self.assertIs(report['commands'][0]['group_absence_verified'],True);self.assertEqual(C.decode(C.read(root/'owner.json')),report);self.assertEqual((root/'command-000.stdout').read_bytes(),b'');self.assertEqual((root/'command-000.stderr').read_bytes(),b'')
  # Exact immediate-before source body refuses at the same real receipt seam.
  current=inspect.getsource(L.provision);line=' args._owner_report=report\n';self.assertEqual(current.count(line),1);prior=current.replace(line,'',1);env=dict(vars(L));exec(compile(prior,'<whole-before-first-provision-binding>','exec'),env)
  with tempfile.TemporaryDirectory(prefix='core622-report-before-',dir='/tmp')as td,patch.dict(sys.modules,{'controller':fixture}):
   root=Path(td);report=dict(commands=[],source_fixture='NO_NATIVE_AUTHORITY');args=types.SimpleNamespace(output=root);command=scoped.command_api(A.core_source/'runtime/runtime-vm',root,report)
   with self.assertRaisesRegex(AttributeError,'_owner_report'):env['provision'](args,report,command,time.monotonic()+30)
   self.assertEqual(len(report['commands']),1);self.assertIs(report['commands'][0]['group_absence_verified'],True)

 def test_actual_workflow_helper_rejects_token_selected_owned_parser_accepts(self):
  import argparse,contextlib,io
  old=json.loads((CASE/'composition-parent.json').read_bytes())['actual_desktop_helper'];owned=C.read(A.core_source/O.OWNED_CLOSURE[0]);token='a'*16
  class Parsed(Exception):pass
  def parser_boundary(raw,argv):
   node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='main');index=next(i for i,n in enumerate(node.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='args'for t in n.targets));body=copy.deepcopy(node.body[:index+1]);body.append(ast.Raise(exc=ast.Call(func=ast.Name(id='Parsed',ctx=ast.Load()),args=[ast.Name(id='args',ctx=ast.Load())],keywords=[]),cause=None));fn=ast.FunctionDef(name='boundary',args=ast.arguments(posonlyargs=[],args=[],kwonlyargs=[],kw_defaults=[],defaults=[]),body=body,decorator_list=[]);module=ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[]));env=dict(argparse=argparse,Path=Path,Parsed=Parsed,__doc__='SOURCE_ONLY_ACTUAL_PARSER_BOUNDARY');exec(compile(module,'<actual-helper-parser-prefix>','exec'),env)
   with patch.object(sys,'argv',argv),patch('subprocess.Popen',side_effect=AssertionError('parser only, no actor')):env['boundary']()
  argv=['helper','build','--inputs','/fixed/inputs','--output','/fixed/output','--job-token',token]
  with contextlib.redirect_stderr(io.StringIO())as err,self.assertRaises(SystemExit)as found:parser_boundary(old['body'].encode(),argv)
  self.assertEqual(found.exception.code,2);self.assertIn('unrecognized arguments: --job-token',err.getvalue())
  with self.assertRaises(Parsed)as found:parser_boundary(owned,argv)
  self.assertEqual(found.exception.args[0].job_token,token);self.assertEqual(found.exception.args[0].mode,'build');module=C.load('_actual_owned_helper_parser_control',A.core_source/O.OWNED_CLOSURE[0]);self.assertEqual(module.owner_names(token),('cachy-asahi-574-owned:'+token,'cachy-asahi-574-probe-'+token))
  for bad in(None,'a'*15,'a'*32,'A'*16):
   with self.assertRaises(ValueError):module.owner_names(bad)
 def test_exact_owned_helper_closure_input_and_source_role_refusals(self):
  with tempfile.TemporaryDirectory(prefix='core622-helper-closure-',dir='/tmp')as td:
   args,_=self._desktop_args_fixture(Path(td));fact=self._core_source_fact_fixture();self.assertEqual(O.owned_helper(args,A.core_source,fact),A.core_source/O.OWNED_CLOSURE[0])
   for key,value in(('source','f'*40),('ref','codex/foreign'),('files',0),('blob_joins',0),('status','SOURCE_FIXTURE_NOT_AUTHORITY')):
    bad=dict(fact);bad[key]=value
    with self.subTest(key=key),self.assertRaises(ValueError):O.owned_helper(args,A.core_source,bad)
   path=args.desktop/'scripts/ci/maintained-desktop574-inputs.json';path.write_bytes(path.read_bytes()+b'\n')
   with self.assertRaises(ValueError):O.owned_helper(args,A.core_source,fact)
 def _desktop_failure_fixture(self,exitcode=7,wait_error=None,capture_error=None):
  import base64,subprocess
  producer=C.load('_desktop_failure_real_producer',A.fresh607_source/'installer604/scripts/ci/full-composition-installer-vm/producer.py');caller=A.fresh607_source/'installer604/scripts/ci/full-root-upgrade-caller/run.py';diag=C.load('_desktop_failure_original_command',A.fresh607_source/'implementation/producer_diagnostic.py');real_popen=subprocess.Popen;payload=(b'fixed source fixture output\n'*180)+bytes(range(64));captured=[];apis=[]
  class CommandSuccessBoundary(Exception):pass
  with tempfile.TemporaryDirectory(prefix='core622-log-before-cleanup-',dir='/tmp')as td:
   root=Path(td);args,_=self._desktop_args_fixture(root);context=R.Context(Path('/unexecuted'),A.fresh607_source,{},time.monotonic()+30);original_error=None
   def capture(value):
    self.assertTrue((args.output/'private/desktop574/build.log').is_file());captured.append(value)
    if capture_error is not None:raise capture_error
    context.capture_desktop_build(value)
   def prepare(scoped,args):
    api=scoped.load(caller);apis.append(api);api.command=diag.command(api.command,C.read(caller,128*1024),lambda *a:None);return api.desktop(args.desktop,args.output/'private',root/'cache')
   def factory(original,raw,callback):
    selected=diag.command(original,raw,callback)
    def command(argv,log,seconds):
     value=selected(argv,log,seconds)
     if exitcode==0 and wait_error is None:raise CommandSuccessBoundary('command succeeded, stop before any builder receipt claim')
     return value
    return command
   def start(argv,**kw):
    # Real bounded process/FD/wait/group flow, redirected to inert fixture code;
    # the owned builder intent is inspected, never claimed executed here.
    code='import sys;sys.stdout.buffer.write('+repr(payload)+');sys.stdout.flush();raise SystemExit('+str(exitcode)+')';process=real_popen([sys.executable,'-I','-B','-c',code],**kw)
    if wait_error is not None:
     wait=process.wait;first=True
     def interrupted(*a,**kw):
      nonlocal first
      if first:first=False;raise wait_error
      return wait(*a,**kw)
     process.wait=interrupted
    return process
   try:
    with patch('subprocess.Popen',side_effect=start):O.prepare_owned(producer,args,prepare,C.pin(C.read(caller,128*1024))['sha256'],A.core_source,self._core_source_fact_fixture(),factory,capture,time.monotonic()+30)
   except BaseException as error:original_error=error
   if exitcode!=0 and wait_error is None:self.assertIsInstance(original_error,AssertionError);self.assertEqual(str(original_error),'command failed: build.log')
   if wait_error is not None:self.assertIs(original_error,wait_error)
   for api in apis:
    for name in('CURRENT_CORE622_BASE_TOKEN','CURRENT_CORE622_OWNED_HELPER','CURRENT_CORE622_DESKTOP_COMMAND'):self.assertNotIn(name,vars(api))
   result=dict(status='FAIL',error_type=type(original_error).__name__ if original_error else'NONE',error=str(original_error)if original_error else'NONE')
   context.desktop_failure(result);before=dict(result)
   with patch('subprocess.Popen',side_effect=AssertionError('no actor in original private producer cleanup')):clean=context.cleanup(producer,args.output,root/'absent-vm')
   self.assertEqual(clean['status'],'PASS');self.assertFalse((args.output/'private').exists());self.assertEqual(result,before)
   if exitcode!=0 and wait_error is None and capture_error is None:
    note=result['desktop574_first_build_failure_data'];self.assertEqual(note['command']['returncode'],exitcode);self.assertEqual(note['log']['file_bytes'],len(payload));self.assertEqual(note['log']['file_sha256'],C.hashlib.sha256(payload).hexdigest());self.assertEqual(base64.b64decode(note['log']['tail_base64']),payload[-2048:]);self.assertEqual(note['stage'],'BEFORE_PRIVATE_PRODUCER_CLEANUP')
    outer=root;(outer/'result.json').write_bytes(C.encoded(result));public=root/'public-copy';__import__('export622').copy(outer,public);self.assertEqual(json.loads((public/'fresh607-caller-result.json').read_bytes()),result);self.assertEqual({p.name for p in public.iterdir()},{'fresh607-caller-result.json','current622-context.json','export.json'})
   if exitcode==0 and wait_error is None:self.assertIsInstance(original_error,CommandSuccessBoundary);self.assertEqual(captured,[]);self.assertNotIn('desktop574_first_build_failure_data',result)
   if capture_error is not None:self.assertNotIn('desktop574_first_build_failure_data',result)
   return captured,result
 def test_fixed_failure_log_captured_before_real_private_cleanup_and_export(self):self._desktop_failure_fixture()
 def test_nearest_success_no_note_wait_identity_and_optional_capture_failure(self):
  self._desktop_failure_fixture(exitcode=0);values,_=self._desktop_failure_fixture(wait_error=KeyboardInterrupt('SOURCE_ONLY_CANCELLATION'));self.assertEqual(values[0]['command']['wait_error_type'],'KeyboardInterrupt');self._desktop_failure_fixture(capture_error=SystemExit('optional capture lost'))
 def test_fixed_log_role_bounds_aliases_metadata_and_note_refusals(self):
  import base64,hashlib
  with tempfile.TemporaryDirectory(prefix='core622-log-refusal-',dir='/tmp')as td:
   root=Path(td);args,_=self._desktop_args_fixture(root);helper=O.owned_helper(args,A.core_source,self._core_source_fact_fixture());work=args.output/'private/desktop574';work.mkdir(mode=0o700);log=work/'build.log';log.write_bytes(b'bounded');token='a'*16;argv=[sys.executable,'-I','-B',str(helper),'build','--inputs',str(args.desktop/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(work),'--job-token',token]
   note=O.desktop_note(args,helper,token,argv,log,2400,1,None,time.monotonic()+30);self.assertEqual(note['log']['status'],'CAPTURED_BOUNDED_FULL_HASH_AND_TAIL')
   for badargv,badlog,badtimeout,code in((argv[:-1]+['b'*32],log,2400,1),(argv,root/'foreign.log',2400,1),(argv,log,2401,1),(argv,log,2400,0)):
    with self.assertRaises(ValueError):O.desktop_note(args,helper,token,badargv,badlog,badtimeout,code,None,time.monotonic()+30)
   log.unlink();log.symlink_to(root/'producer-owner.json');self.assertEqual(O.desktop_note(args,helper,token,argv,log,2400,1,None,time.monotonic()+30)['log']['status'],'UNAVAILABLE_UNSAFE_CHANGED_OR_BOUNDED');log.unlink();log.write_bytes(b'x');other=work/'hardlink';os.link(log,other);self.assertEqual(O.desktop_note(args,helper,token,argv,log,2400,1,None,time.monotonic()+30)['log']['status'],'UNAVAILABLE_UNSAFE_CHANGED_OR_BOUNDED');other.unlink();log.write_bytes(b'');log.unlink();self.assertEqual(O.desktop_note(args,helper,token,argv,log,2400,1,None,time.monotonic()+30)['log']['status'],'UNAVAILABLE_NOT_PRESENT')
   with log.open('wb')as stream:stream.truncate(O.DESKTOP_LOG_MAX+1)
   self.assertEqual(O.desktop_note(args,helper,token,argv,log,2400,1,None,time.monotonic()+30)['log']['status'],'UNAVAILABLE_UNSAFE_CHANGED_OR_BOUNDED');log.write_bytes(b'changing');read=os.read;changed=False
   def mutate(fd,size):
    nonlocal changed
    value=read(fd,size)
    if value and not changed:changed=True;log.write_bytes(b'mutated')
    return value
   with patch.object(os,'read',side_effect=mutate):self.assertEqual(O.desktop_note(args,helper,token,argv,log,2400,1,None,time.monotonic()+30)['log']['status'],'UNAVAILABLE_UNSAFE_CHANGED_OR_BOUNDED')
   for change in('extra','success','tail','offset','base64'):
    bad=copy.deepcopy(note)
    if change=='extra':bad['foreign']='no'
    elif change=='success':bad['command']['returncode']=0
    elif change=='tail':bad['log']['tail_bytes']=2049
    elif change=='offset':bad['log']['offset']=1
    else:bad['log']['tail_base64']='!'
    with self.subTest(change=change),self.assertRaises((ValueError,TypeError)):O.validate_desktop_note(bad)
 def test_selected_owner_exception_attaches_note_before_unchanged_cleanup(self):
  import inspect
  raw=C.read(A.fresh607_source/'installer604/scripts/ci/expanded604-apps6-public-pair-installer/ci.py');fresh=C.load('_whole_fresh_for_diagnostic_derive',A.fresh607_source/'implementation/run.py');text=R.derive(fresh.derive(raw));node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='main');handler=next(n for n in ast.walk(node)if isinstance(n,ast.ExceptHandler)and any(isinstance(q,ast.Attribute)and q.attr=='desktop_failure'for q in ast.walk(n)));before=ast.get_source_segment(raw.decode(),next(n for n in ast.walk(ast.parse(raw))if isinstance(n,ast.ExceptHandler)and any(isinstance(q,ast.keyword)and q.arg=='error_type'for q in ast.walk(n))))
  self.assertIn("except BaseException as error:result.update",before);self.assertEqual(len(handler.body),2);self.assertIsInstance(handler.body[1],ast.Try);self.assertEqual(ast.unparse(handler.body[1].handlers[0].type),'BaseException')

 def test_actual_private_compiler6_and_exact_frozen_dependency_globals(self):
  selected=O.cache_facade(A.fresh607_source);base=C.load('_core622_direct_original_compiler6_control',A.fresh607_source/'implementation/compiler6.py')
  self.assertEqual(selected.prepare.__code__.co_code,base.prepare.__code__.co_code);self.assertEqual({k:v for k,v in selected.configuration().items()if k!='dependency_cache'},base.configuration());self.assertIs(selected.prepare_dependency_cache.__globals__['cache_snapshot'],selected.cache_snapshot);self.assertIs(selected.prepare_with_dependencies.__globals__['prepare'],selected.prepare)
  context=json.loads((CASE/'composition-parent.json').read_bytes())['dependency_cache_context'];self.assertEqual(len(context['dependency_cache']['selected']),8);self.assertEqual(len(context['dependency_cache']['carrier_files']),108);self.assertFalse(context['dependency_cache']['acceptance'])
 def test_actual_dependency_prefix_callback_before_private_cleanup(self):
  import subprocess,base64
  producer=C.load('_core622_dependency_actual_producer',A.fresh607_source/'installer604/scripts/ci/full-composition-installer-vm/producer.py');caller=A.fresh607_source/'installer604/scripts/ci/full-root-upgrade-caller/run.py';diag=C.load('_core622_dependency_actual_command_factory',A.fresh607_source/'implementation/producer_diagnostic.py');real_popen=subprocess.Popen;payload=b'SOURCE_ONLY_EXACT_DEPENDENCY_FIXTURE\n'*90;seen=[];updater_callbacks=[];apis=[]
  with tempfile.TemporaryDirectory(prefix='core622-dependency-diagnostic-',dir='/tmp')as td:
   root=Path(td);args,_=self._desktop_args_fixture(root);args.cache=root/'cache';args.updater=root/'updater';args.preparation_source=root/'preparation';owner_path=args.output/'producer-owner.json';owner=json.loads(owner_path.read_bytes());owner['preparation_source']=str(args.preparation_source);owner_path.write_bytes(C.encoded(owner));meta=json.loads((CASE/'composition-parent.json').read_bytes())['dependency_source_data'];folder=args.preparation_source/'scripts/ci/full-development-composition/dependencies';folder.mkdir(parents=True)
   for n,b in meta.items():(folder/n).write_bytes(b.encode())
   context=R.Context(Path('/unexecuted'),A.fresh607_source,{},time.monotonic()+30)
   def prepare(scoped,a):
    api=scoped.load(caller);apis.append(api);api.command=diag.command(api.command,C.read(caller,128*1024),lambda *v:updater_callbacks.append(v));prefix,digest=scoped.preparation_prefix(api,caller);original,prior=producer.preparation_prefix(api,caller);self.assertEqual(digest,prior);self.assertEqual(prefix.__code__.co_code,original.__code__.co_code);self.assertIsNot(prefix.__globals__,vars(api));self.assertIsNot(prefix.__globals__['command'],api.command)
    # Execute the exact dependency statement from the actual immutable caller
    # against the ACTUAL selected prefix globals. No preceding builder is run.
    node=next(n for n in ast.walk(ast.parse(C.read(caller,128*1024)))if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Name)and n.value.func.id=='command'and any(isinstance(q,ast.Constant)and q.value=='dependency.log'for q in ast.walk(n)))
    env=dict(prefix.__globals__,args=a,raw=a.output/'private',py=sys.executable,HERE=a.preparation_source/'scripts/ci/full-development-composition');exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-source-dependency-command>','exec'),env)
   def popen(argv,**kw):
    seen.append(argv);self.assertEqual(argv,[sys.executable,'-B',str(folder/'acquire.py'),'--source-root',str(args.updater),'--cache',str(args.cache),'--keydir',str(args.cache),'--output',str(args.output/'private/dependency-audit')]);return real_popen([sys.executable,'-I','-B','-c','import sys;sys.stdout.buffer.write('+repr(payload)+');raise SystemExit(9)'],**kw)
   with patch('subprocess.Popen',side_effect=popen),self.assertRaisesRegex(AssertionError,'command failed: dependency.log'):O.prepare_owned(producer,args,prepare,diag.CALLER_PIN,A.core_source,self._core_source_fact_fixture(),diag.command,lambda v:None,time.monotonic()+30,context.capture_dependency)
   self.assertEqual(len(updater_callbacks),1);self.assertEqual(len(seen),1);result={'status':'FAIL'};context.desktop_failure(result);note=result['dependency_failure_data'];self.assertEqual(note['command']['returncode'],9);self.assertEqual(note['command']['timeout_seconds'],180);self.assertEqual(note['log']['file_sha256'],C.hashlib.sha256(payload).hexdigest());self.assertEqual(base64.b64decode(note['log']['tail_base64']),payload[-2048:]);self.assertTrue((args.output/'private/dependency.log').exists())
   with patch('subprocess.Popen',side_effect=AssertionError('no actor in original cleanup')):self.assertEqual(context.cleanup(producer,args.output,root/'absent-vm')['status'],'PASS')
   self.assertFalse((args.output/'private').exists());self.assertEqual(result['dependency_failure_data'],note)
   for api in apis:
    for name in('CURRENT_CORE622_BASE_TOKEN','CURRENT_CORE622_OWNED_HELPER','CURRENT_CORE622_DESKTOP_COMMAND'):self.assertNotIn(name,vars(api))
 def test_dependency_fixed_role_source_and_note_refusals(self):
  with tempfile.TemporaryDirectory(prefix='core622-dependency-refusal-',dir='/tmp')as td:
   root=Path(td);args,_=self._desktop_args_fixture(root);args.cache=root/'cache';args.updater=root/'updater';args.preparation_source=root/'preparation';owner_path=args.output/'producer-owner.json';owner=json.loads(owner_path.read_bytes());owner['preparation_source']=str(args.preparation_source);owner_path.write_bytes(C.encoded(owner));folder=args.preparation_source/'scripts/ci/full-development-composition/dependencies';folder.mkdir(parents=True);meta=json.loads((CASE/'composition-parent.json').read_bytes())['dependency_source_data']
   for n,b in meta.items():(folder/n).write_text(b)
   log=args.output/'private/dependency.log';log.write_bytes(b'fixed');argv=[sys.executable,'-B',str(folder/'acquire.py'),'--source-root',str(args.updater),'--cache',str(args.cache),'--keydir',str(args.cache),'--output',str(args.output/'private/dependency-audit')];note=O.dependency_note(args,argv,log,180,1,None,time.monotonic()+30);self.assertEqual(note['command']['role'],'AUTHENTICATE_FIVE_DEDUPLICATE_FOUR')
   for values,path,seconds,code in((argv,log,181,1),(argv,root/'foreign',180,1),(argv[:-1]+['/foreign'],log,180,1),(argv,log,180,0)):
    with self.assertRaises(ValueError):O.dependency_note(args,values,path,seconds,code,None,time.monotonic()+30)
   (folder/'acquire.py').write_text(meta['acquire.py']+'\n')
   with self.assertRaises(ValueError):O.dependency_note(args,argv,log,180,1,None,time.monotonic()+30)
   bad=copy.deepcopy(note);bad['command']['timeout_seconds']=2400
   with self.assertRaises(ValueError):O.validate_dependency_note(bad)


class IsolatedCacheCLI(unittest.TestCase):
 """Fresh production -I subprocesses; actual facade, no mutation sentinel."""
 def argv(self,root,script=None):
  import time
  source=Path(__file__).resolve().parent;fresh=Path(A.fresh607_source)
  return [sys.executable,'-I','-B',str(source/'ownership622.py'if script is None else script),'--prepare-dependency-cache','--compiler6-source',str(fresh),'--carrier',str(root/'carrier'),'--updater',str(root/'updater'),'--desktop-lock',str(root/'desktop.lock'),'--cache',str(root/'cache'),'--incoming31',str(root/'incoming'),'--preparation',str(root/'preparation'),'--deadline',str(time.monotonic()+240)]
 def test_fresh_actual_isolated_cli_reaches_real_facade_original_prepare_before_mutation(self):
  import subprocess
  with tempfile.TemporaryDirectory(prefix='core622-isolated-cache-')as td:
   root=Path(td);source=Path(__file__).resolve().parent
   for n in('carrier','updater','cache','incoming','preparation'):(root/n).mkdir(mode=0o700)
   before={n:(p.lstat().st_ino,p.lstat().st_mode,p.lstat().st_mtime_ns,p.lstat().st_ctime_ns)for n,p in((x.name,x)for x in root.iterdir())};foreign=root/'desktop622.py';foreign.write_text("raise AssertionError('FOREIGN_CWD_MODULE_MUST_NOT_EXECUTE')\n")
   p=subprocess.run(self.argv(root),cwd=root,stdin=subprocess.DEVNULL,capture_output=True,timeout=20,env=dict(PATH='/usr/bin:/bin',LANG='C',PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(root)))
   self.assertEqual(p.returncode,1);text=p.stderr.decode();self.assertNotIn('ModuleNotFoundError',text);self.assertNotIn('FOREIGN_CWD_MODULE',text);self.assertIn('FileNotFoundError',text);self.assertIn(str(root/'updater'/next(iter(json.loads((source/'composition-parent.json').read_bytes())['dependency_cache_context']['updater_files']))),text);self.assertIn('selected.prepare_with_dependencies',text);self.assertIn('compiler6.py',text)
   self.assertEqual(list((root/'cache').iterdir()),[])
   for n,w in before.items():q=root/n;self.assertEqual((q.lstat().st_ino,q.lstat().st_mode,q.lstat().st_mtime_ns,q.lstat().st_ctime_ns),w)
 def test_fresh_actual_cli_refuses_modified_local_helper_before_original_inputs(self):
  import subprocess,shutil
  with tempfile.TemporaryDirectory(prefix='core622-isolated-cache-refuse-')as td:
   root=Path(td);script=root/'ownership622.py';source=Path(__file__).resolve().parent;shutil.copyfile(source/'ownership622.py',script);(root/'desktop622.py').write_bytes((source/'desktop622.py').read_bytes()+b'\n# private wrong helper\n');(root/'cache').mkdir(mode=0o700)
   p=subprocess.run(self.argv(root,script),cwd=root,stdin=subprocess.DEVNULL,capture_output=True,timeout=20,env=dict(PATH='/usr/bin:/bin',LANG='C',PYTHONDONTWRITEBYTECODE='1'));self.assertEqual(p.returncode,1);self.assertIn(b'exact held local desktop622 cache bootstrap',p.stderr);self.assertNotIn(b'FileNotFoundError',p.stderr);self.assertEqual(list((root/'cache').iterdir()),[])

if __name__=='__main__':unittest.main(verbosity=2)
