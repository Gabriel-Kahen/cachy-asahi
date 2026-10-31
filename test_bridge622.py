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
  after=dict(complete=True,unsupported_counts={},nodes=nodes,hardlink_groups={});payload=dict(nodes=signed,ownership=ownership,hardlinks=[],packages=base);removed=dict(nodes={'usr/lib/libfdk-aac.so':oldnode});initial=[dict(name=n,version=v,files=[])for n,v in V['before574'].items()];final=[dict(name=n,version=v,files=ownership[n])for n,v in base.items()];aux=dict(status='FULL_FD_CHECKPOINT_AND_LIVE_AUXILIARY_LIBRARY_KEYS',initialization=dict(status='PASS_ONE_OWNED_ROOT_AUX_INITIALIZATION',preservation=dict(unrelated_nodes_preserved=True,library_closure_preserved=True,cache_parent_and_temps_preserved=True),helper=dict(command=dict(argv=['/usr/bin/python3','-I','-B','/workspace/provision622.py','initialize607'],exit_code=0,group_absence_verified=True)),cache_hashes={name:dict(before='b'*64,after='c'*64)for name in F.CACHE},live_cache_keys=dict(records=1)));nodes.update({name:dict(type='file',uid=0,gid=0,mode=0o600 if name.endswith('aux-cache')else 0o644,bytes=1,sha256='c'*64)for name in F.CACHE});args=(V,before,after,{}, {},payload,removed,initial,final,aux);self.assertEqual(F.check(*args)['held'],573)
  for kind in('foreign','held','new','removed','caps','db','initialization','helper','cache-proof'):
   values=copy.deepcopy(args)
   if kind=='foreign':values[2]['nodes']['foreign']=dict(oldnode)
   elif kind=='held':values[2]['nodes']['root/private']['mode']=0o644
   elif kind=='new':values[2]['nodes'][next(iter(signed))]['sha256']='b'*64
   elif kind=='removed':values[2]['nodes']['usr/lib/libfdk-aac.so']=dict(oldnode)
   elif kind=='caps':values[4]['root/private']={'forged':True}
   elif kind=='db':values[8][0]['version']='foreign'
   elif kind=='initialization':values[9]['initialization']['preservation']['unrelated_nodes_preserved']=False
   elif kind=='helper':values[9]['initialization']['helper']['command']['exit_code']=1
   else:values[9]['initialization']['cache_hashes'][next(iter(F.CACHE))]['after']='0'*64
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
  rows=source622.inverse(CASE);self.assertEqual(len(rows),51);self.assertEqual(C.pin(rows['guest.py']),json.loads((CASE/'composition-parent.json').read_bytes())['before']['guest.py']);self.assertEqual(source622.same66_before(CASE)['guest.py'],rows['guest.py']);self.assertNotEqual(C.read(CASE/'guest.py'),rows['guest.py']);self.assertEqual(C.read(CASE/'effects.py'),rows['effects.py'])
  record=json.loads((CASE/'composition-parent.json').read_bytes())['baseline_capacity_diagnostic'];edits=[["__import__('candidate_capacity').foreground(command,phase,prefix,number,row)", "__import__('candidate_capacity').foreground_diagnostic(command,phase,prefix,number,row,__import__('candidate_capacity').DIAGNOSTIC_NAME)"], ["__import__('candidate_capacity').transaction(transaction,role,row)", "__import__('candidate_capacity').transaction_diagnostic(transaction,role,row,__import__('candidate_capacity').DIAGNOSTIC_NAME)"]]
  self.assertEqual(record['edits']['validate.py'],edits);current=C.read(CASE/'validate.py');restored=current.decode()
  for before,after in reversed(edits):
   self.assertEqual(restored.count(after),1);restored=restored.replace(after,before,1)
  restored=restored.encode();self.assertEqual(C.pin(restored),record['before']['validate.py']);self.assertEqual(restored,source622.same66_before(CASE)['validate.py']);self.assertEqual(restored,rows['validate.py']);expected=restored.decode()
  for before,after in edits:
   self.assertEqual(expected.count(before),1);expected=expected.replace(before,after,1)
  self.assertEqual(current,expected.encode());self.assertNotEqual(current,restored);self.assertIsNone(json.loads((CASE/'source-manifest.json').read_bytes())['actual'])
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
  raw=C.read(A.fresh607_source/'installer604/scripts/ci/expanded604-apps6-public-pair-installer/ci.py')
  with R.namespace(A.fresh607_source/'implementation'):fresh=C.load('_whole_fresh_for_diagnostic_derive',A.fresh607_source/'implementation/run.py');original=fresh.derive(raw)
  text=R.derive(original);node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='main');primaries=[n for n in node.body if isinstance(n,ast.Try)and any(h.name=='error'for h in n.handlers)];self.assertEqual(len(primaries),1);selected=primaries[0];self.assertEqual(len(selected.handlers),1);handler=selected.handlers[0];self.assertEqual(handler.name,'error');before=next(n for n in ast.walk(ast.parse(raw))if isinstance(n,ast.ExceptHandler)and any(isinstance(q,ast.keyword)and q.arg=='error_type'for q in ast.walk(n)));shape=lambda value:ast.dump(value,include_attributes=False)
  self.assertEqual(ast.unparse(handler.type),'BaseException');self.assertEqual(len(handler.body),3);self.assertEqual(shape(handler.body[0]),shape(before.body[0]));capture=ast.parse('try:\n Y.outer_exception(error)\nexcept BaseException:\n pass\n').body[0];desktop=ast.parse('try:\n Y.desktop_failure(result)\nexcept BaseException:\n pass\n').body[0];self.assertEqual(shape(handler.body[1]),shape(capture));self.assertEqual(shape(handler.body[2]),shape(desktop))
  parents=C.decode(C.read(CASE/'composition-parent.json',4*1024**2));inventory=parents['private_context_retirement_inventory_causal'];self.assertEqual((inventory['schema'],inventory['parent_source'],inventory['actual']),(1,'425901e440a4fbe24a5aa00857a9962714599be4',None));prior=C.read(CASE/'run622.py',4*1024**2).decode()
  for old,new in reversed(inventory['edits']['run622.py']):self.assertEqual(prior.count(new),1);prior=prior.replace(new,old,1)
  self.assertEqual(inventory['before']['run622.py'],dict(bytes=21378,sha256='4f49692149c9651b6226a9d04affe3e7dea471b702fa190cf4da31e2912a19ff'));self.assertEqual(C.pin(prior.encode()),inventory['before']['run622.py']);context=parents['context_retirement_observations_causal'];self.assertEqual((context['schema'],context['parent_source'],context['actual']),(1,'23be54e7ee694ed766bfc11fe7bf841a1089b4ba',None));self.assertEqual(len(context['edits']['run622.py']),1)
  for old,new in reversed(context['edits']['run622.py']):self.assertEqual(prior.count(new),1);prior=prior.replace(new,old,1)
  self.assertEqual(context['before']['run622.py'],dict(bytes=20772,sha256='053bc800888d2515d8134e51ccd1d0722bc98b6f25352e514450d36f544df4ba'));self.assertEqual(C.pin(prior.encode()),context['before']['run622.py']);record=parents['outer_diagnostics_causal'];self.assertEqual(record['before']['run622.py'],dict(bytes=20525,sha256='685b2fb348ae07b49973a6a5b47f13a43b1feba86ccf2a1a032be946d2391fac'))
  for old,new in reversed(record['edits']['run622.py']):self.assertEqual(prior.count(new),1);prior=prior.replace(new,old,1)
  self.assertEqual(C.pin(prior.encode()),record['before']['run622.py']);derive=next(n for n in ast.parse(prior).body if isinstance(n,ast.FunctionDef)and n.name=='derive');namespace=dict(C=C,X=X);exec(compile(ast.Module(body=[derive],type_ignores=[]),'<exact pre-capture source derive>','exec'),namespace);previous=next(n for n in ast.parse(namespace['derive'](original)).body if isinstance(n,ast.FunctionDef)and n.name=='main');oldtry=next(n for n in previous.body if isinstance(n,ast.Try)and any(h.name=='error'for h in n.handlers));oldhandler=next(h for h in oldtry.handlers if h.name=='error');self.assertEqual(len(oldhandler.body),2);self.assertEqual(shape(handler.body[0]),shape(oldhandler.body[0]));self.assertEqual(shape(handler.body[2]),shape(oldhandler.body[1]));self.assertEqual(shape(selected.finalbody[0]),shape(oldtry.finalbody[0]));without=copy.deepcopy(node);owned=next(n for n in without.body if isinstance(n,ast.Try)and any(h.name=='error'for h in n.handlers));next(h for h in owned.handlers if h.name=='error').body.pop(1);self.assertEqual(shape(without),shape(previous))

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
   root=Path(td);source=Path(__file__).resolve().parent;closed=root/'closed-source';closed.mkdir(mode=0o700);manifest=json.loads((source/'source-manifest.json').read_bytes());names=set(manifest['files'])|{'source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml'};self.assertEqual(len(names),66)
   for name in sorted(names):
    target=closed/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,target);target.chmod(0o644)
   script=closed/'ownership622.py';(closed/'desktop622.py').write_bytes((closed/'desktop622.py').read_bytes()+b'\n# private wrong helper\n');(root/'cache').mkdir(mode=0o700)
   p=subprocess.run(self.argv(root,script),cwd=root,stdin=subprocess.DEVNULL,capture_output=True,timeout=20,env=dict(PATH='/usr/bin:/bin',LANG='C',PYTHONDONTWRITEBYTECODE='1'));self.assertEqual(p.returncode,1);self.assertIn(b'closed current Source sibling admission refused',p.stderr);self.assertNotIn(b'FileNotFoundError',p.stderr);self.assertNotIn(b'exact held local desktop622 cache bootstrap',p.stderr);self.assertNotIn(b'selected.prepare_with_dependencies',p.stderr);self.assertNotIn(b'compiler6.py',p.stderr);self.assertEqual(list((root/'cache').iterdir()),[]);self.assertFalse((root/'carrier').exists());self.assertFalse((root/'updater').exists())

class ProofOutputControls(unittest.TestCase):
 """Actual actor derivation, argv-derived Docker DATA and real output FDs.

 No Docker/helper executes. Early-call controls mock only bootstrap/process
 boundaries; selected-role mount predicates run without mocks.
 """
 def modules(self):
  import controller,provision622
  self.assertEqual(Path(controller.__file__).resolve(),(CASE/'controller.py').resolve());self.assertEqual(Path(provision622.__file__).resolve(),(CASE/'provision622.py').resolve());return controller,provision622
 class Docker:
  def __init__(self,args,role,change=None):
   self.args=args;self.change=change;self.name='caa-core7-vm-'+args.selected['nonce']+'-'+role;self.exists=False;self.row=None;self.argv=None;self.commands=[]
  def __call__(self,argv,*options):
   self.commands.append(list(argv));self.args._owner_report['commands'].append(dict(argv=list(argv)))
   if argv[:3]==['/usr/bin/docker','image','inspect']:return dict(code=0,err=b'',out=json.dumps([dict(Id=self.args.image,Architecture='arm64',Os='linux',Config=dict(Labels={'org.cachy-asahi.bootstrap574.job':'fixture-token'}))]).encode())
   if argv[:3]==['/usr/bin/docker','container','inspect']:
    if not self.exists:return dict(code=1,out=b'',err=('No such container: '+self.name).encode())
    return dict(code=0,out=json.dumps([self.row]).encode(),err=b'')
   if argv[:2]==['/usr/bin/docker','run']:
    self.exists=True;self.argv=list(argv);mounts=[];host=[]
    for number,value in enumerate(argv):
     if value!='--mount':continue
     items=argv[number+1].split(',');parts=dict(p.split('=',1)for p in items if'='in p);readonly='readonly'in items;propagation=parts.get('bind-propagation','rprivate');mounts.append(dict(Type=parts['type'],Source=parts['src'],Destination=parts['dst'],Mode='',RW=not readonly,Propagation=propagation));entry=dict(Type=parts['type'],Source=parts['src'],Target=parts['dst'])
     if readonly:entry['ReadOnly']=True
     if'bind-propagation'in parts:entry['BindOptions']=dict(Propagation=propagation)
     host.append(entry)
    labels=dict([argv[argv.index('--label')+1].split('=',1)]);image_position=argv.index(self.args.image);caps=['CAP_'+v.split('=',1)[1]for v in argv if v.startswith('--cap-add=')]
    self.row=dict(Id='d'*64,Name='/'+self.name,Image=self.args.image,Mounts=mounts,Config=dict(Labels=labels,Cmd=argv[image_position+1:]),HostConfig=dict(NetworkMode='none'if'--network=none'in argv else'other',ReadonlyRootfs='--read-only'in argv,CapDrop=['ALL']if'--cap-drop=ALL'in argv else[],CapAdd=caps,SecurityOpt=['no-new-privileges']if'--security-opt=no-new-privileges'in argv else[],Mounts=host),State=dict(Running=False,Pid=0,ExitCode=0))
    if self.change:self.change(self.row)
    return dict(code=0,out=b'',err=b'')
   if argv[:3]==['/usr/bin/docker','rm','-f']:
    if argv[-1]!='d'*64:raise AssertionError('wrong synthetic actor removal')
    self.exists=False;return dict(code=0,out=b'',err=b'')
   raise AssertionError('unexpected synthetic Docker command')
 def actor(self,role,change=None):
  controller,_=self.modules();folder=tempfile.TemporaryDirectory(prefix='proof-output-actor-',dir='/tmp');self.addCleanup(folder.cleanup);root=Path(folder.name);base=root/'base';base.mkdir(mode=0o700);image='sha256:'+'a'*64;(base/'report.json').write_text(json.dumps(dict(image=image,ownership=dict(token='fixture-token'))))
  args=types.SimpleNamespace(selected=dict(nonce='c'*32),base=base,image=image,output=root/'output',vm_source=root/'vm-source',kernel_inputs=root/'kernel-inputs',core_source=A.core_source,current607_inputs=root/'current607-inputs',fresh607_source=root/'fresh607-source',current607_code=root/'current607-code',provision_public=root/'current607-public',provision_deadline=time.monotonic()+100,retirement_deadline=time.monotonic()+60,_owner_report=dict(commands=[]));docker=self.Docker(args,role,change);self.last_docker=docker;value=controller.actor(args,docker,root/'work',root/'media',role);return value,docker,args
 def test_actual_five_roles_have_only_the_declared_writable_binds(self):
  five={'CAP_CHOWN','CAP_DAC_OVERRIDE','CAP_FOWNER','CAP_FSETID','CAP_SETFCAP'}
  for role in('provision607','retire607','prepare','scrub','export'):
   with self.subTest(role=role):
    value,docker,args=self.actor(role);row=docker.row;mounts={m['Destination']:m for m in row['Mounts']};host={m['Target']:m for m in row['HostConfig']['Mounts']};writable={'/measurement','/out'}if role in('provision607','retire607')else{'/measurement'}
    self.assertEqual({n for n,m in mounts.items()if m['RW']},writable);self.assertEqual({n for n,m in host.items()if not m.get('ReadOnly',False)},writable);self.assertTrue(all(m['Propagation']=='rprivate'for m in mounts.values()));self.assertEqual(mounts['/out']['Source'],str(args.provision_public)if role in('provision607','retire607')else str(args.output.parent/'work/guest-out'))
    self.assertTrue(row['HostConfig']['ReadonlyRootfs']);self.assertEqual(set(row['HostConfig']['CapAdd']),five|({'CAP_SYS_CHROOT'}if role=='provision607'else set()));self.assertIn('--read-only',docker.argv);self.assertIn('--network=none',docker.argv);self.assertEqual(value['role'],role);self.assertTrue(value['actor_absent']);self.assertFalse(docker.exists);self.assertEqual(sum(cmd[:3]==['/usr/bin/docker','rm','-f']for cmd in docker.commands),1);self.assertEqual(docker.commands[-1][:3],['/usr/bin/docker','container','inspect'])
 def corrupt(self,row,case):
  top=row['Mounts'];host=row['HostConfig']['Mounts'];out=next(m for m in top if m['Destination']=='/out');hout=next(m for m in host if m['Target']=='/out')
  if case=='readonly-out':out['RW']=False;hout['ReadOnly']=True
  elif case in('writable-input','writable-workspace','writable-source'):
   destination={'writable-input':'/inputs','writable-workspace':'/workspace','writable-source':'/source'}[case];next(m for m in top if m['Destination']==destination)['RW']=True;next(m for m in host if m['Target']==destination)['ReadOnly']=False
  elif case=='wrong-source':out['Source']+='/foreign';hout['Source']+='/foreign'
  elif case=='duplicate':top.append(copy.deepcopy(out));host.append(copy.deepcopy(hout))
  elif case=='missing':top.remove(out);host.remove(hout)
  elif case=='extra':top.append(dict(Type='bind',Source='/foreign',Destination='/foreign',Mode='',RW=False,Propagation='rprivate'));host.append(dict(Type='bind',Source='/foreign',Target='/foreign',ReadOnly=True))
  elif case=='propagation':out['Propagation']='rshared';hout['BindOptions']=dict(Propagation='rshared')
  elif case=='host-readonly':hout['ReadOnly']=True
  elif case=='host-source':hout['Source']+='/foreign'
  elif case=='host-missing':host.remove(hout)
  elif case=='host-duplicate':host.append(copy.deepcopy(hout))
  elif case=='host-extra':host.append(dict(Type='bind',Source='/foreign',Target='/foreign',ReadOnly=True))
  elif case=='root-writable':row['HostConfig']['ReadonlyRootfs']=False
  else:raise AssertionError('unknown readback mutation')
 def test_selected_actor_refuses_wrong_mounts_after_owned_cleanup(self):
  cases=('readonly-out','writable-input','writable-workspace','writable-source','wrong-source','duplicate','missing','extra','propagation','host-readonly','host-source','host-missing','host-duplicate','host-extra')
  for role in('provision607','retire607'):
   for case in cases:
    with self.subTest(role=role,case=case):
     with self.assertRaises(ValueError):self.actor(role,lambda row:self.corrupt(row,case))
     self.assertFalse(self.last_docker.exists);self.assertEqual(sum(cmd[:3]==['/usr/bin/docker','rm','-f']for cmd in self.last_docker.commands),1);self.assertEqual(self.last_docker.commands[-1][:3],['/usr/bin/docker','container','inspect'])
 def test_original_readonly_root_guard_remains_held(self):
  for role in('provision607','retire607','prepare','scrub','export'):
   with self.subTest(role=role),self.assertRaises(ValueError):self.actor(role,lambda row:self.corrupt(row,'root-writable'))
 def test_other_actor_roles_bypass_only_the_new_proof_mount_checker(self):
  with patch.object(L,'proof_mounts',side_effect=AssertionError('new checker must stay scoped'))as guard:
   for role in('prepare','scrub','export'):self.actor(role)
  guard.assert_not_called()
 def output_path(self,output):return lambda value:output if str(value)=='/out'else Path(value)
 def test_real_output_fd_accepts_exact_private_ordinary_writable_directory(self):
  _,P=self.modules()
  with tempfile.TemporaryDirectory(prefix='proof-output-fd-',dir='/tmp')as folder:
   output=Path(folder);before=output.stat();fds=len(os.listdir('/proc/self/fd'))
   with patch.object(P,'Path',side_effect=self.output_path(output)):P.proof_output(os.getuid(),os.getgid())
   after=output.stat();self.assertEqual((before.st_dev,before.st_ino,before.st_mode),(after.st_dev,after.st_ino,after.st_mode));self.assertEqual(list(output.iterdir()),[]);self.assertEqual(len(os.listdir('/proc/self/fd')),fds)
 def test_real_output_guard_refuses_readonly_filesystem_mode_and_owner(self):
  _,P=self.modules()
  with tempfile.TemporaryDirectory(prefix='proof-output-bad-fd-',dir='/tmp')as folder:
   output=Path(folder);mapping=self.output_path(output);fds=len(os.listdir('/proc/self/fd'))
   with patch.object(P,'Path',side_effect=mapping),patch.object(P.os,'fstatvfs',return_value=types.SimpleNamespace(f_flag=os.ST_RDONLY)),self.assertRaises(ValueError):P.proof_output(os.getuid(),os.getgid())
   with patch.object(P,'Path',side_effect=mapping),self.assertRaises(ValueError):P.proof_output(os.getuid()+1,os.getgid())
   with patch.object(P,'Path',side_effect=mapping),self.assertRaises(ValueError):P.proof_output(os.getuid(),os.getgid()+1)
   output.chmod(0o755)
   with patch.object(P,'Path',side_effect=mapping),self.assertRaises(ValueError):P.proof_output(os.getuid(),os.getgid())
   output.chmod(0o700);self.assertEqual(len(os.listdir('/proc/self/fd')),fds);self.assertEqual(list(output.iterdir()),[])
 def test_real_output_guard_refuses_alias_file_and_fd_identity_drift(self):
  _,P=self.modules()
  with tempfile.TemporaryDirectory(prefix='proof-output-alias-fd-',dir='/tmp')as folder:
   root=Path(folder);directory=root/'directory';directory.mkdir(mode=0o700);alias=root/'alias';alias.symlink_to(directory,target_is_directory=True);regular=root/'file';regular.write_bytes(b'inert');fds=len(os.listdir('/proc/self/fd'))
   for output in(alias,regular):
    with self.subTest(output=output),patch.object(P,'Path',side_effect=self.output_path(output)),self.assertRaises((ValueError,OSError)):P.proof_output(os.getuid(),os.getgid())
   original=P.os.fstat;calls=[]
   def drift(fd):
    info=original(fd);calls.append(fd)
    if len(calls)==1:return info
    values={name:getattr(info,name)for name in dir(info)if name.startswith('st_')};values['st_ino']+=1;return types.SimpleNamespace(**values)
   with patch.object(P,'Path',side_effect=self.output_path(directory)),patch.object(P.os,'fstat',side_effect=drift),self.assertRaises(ValueError):P.proof_output(os.getuid(),os.getgid())
   self.assertGreaterEqual(len(calls),2);self.assertEqual(len(os.listdir('/proc/self/fd')),fds);self.assertEqual(list(directory.iterdir()),[])
 def test_actual_prepare_and_retire_output_guard_precedes_mutating_calls(self):
  _,P=self.modules();tree=ast.parse(C.read(CASE/'provision622.py'));functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)};mutating={'write_bytes','mkdir','chown','rmdir','_empty','initialize_auxiliary','provision'}
  for name in('prepare','retire'):
   node=functions[name];guard=next(n for n in ast.walk(node)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='proof_output');calls=[n for n in ast.walk(node)if isinstance(n,ast.Call)and((isinstance(n.func,ast.Attribute)and n.func.attr in mutating)or(isinstance(n.func,ast.Name)and n.func.id in mutating))];self.assertTrue(calls);self.assertTrue(all(guard.lineno<n.lineno for n in calls),name)
 def test_actual_early_guard_stops_prepare_and_retire_without_mutation(self):
  _,P=self.modules()
  class Reached(RuntimeError):pass
  for role in('prepare','retire'):
   with self.subTest(role=role),tempfile.TemporaryDirectory(prefix='proof-output-before-mutation-',dir='/tmp')as folder:
    measurement=Path(folder);root=measurement/'current607'
    if role=='retire':root.mkdir(mode=0o700)
    selected=dict(nonce='c'*32);parent=measurement.stat();lease=dict(nonce=selected['nonce'],root=[root.stat().st_dev,root.stat().st_ino]if root.exists()else[1,2],parent=[parent.st_dev,parent.st_ino]);data={'/workspace/selection.json':selected,'/workspace/media-selection.json':dict(uid=os.getuid(),gid=os.getgid()),'/measurement/current607-lease.json':lease,str(measurement/'current607-lease.json'):lease};before=sorted(p.name for p in measurement.iterdir());reason=Reached('actual proof_output call before any mutation')
    def read(name,*args):
     if str(name)not in data:raise AssertionError('unexpected bootstrap read before output guard: '+str(name))
     return json.dumps(data[str(name)]).encode()
    mapping=lambda value:measurement if str(value)=='/measurement'else Path(value)
    with patch.object(P,'ROOT',root),patch.object(P,'Path',side_effect=mapping),patch.object(P,'owned',return_value=selected),patch.object(P,'profile',return_value={}),patch.object(P.C,'read',side_effect=read),patch.object(P,'proof_output',side_effect=reason)as guard,patch.object(P.os,'chown',side_effect=AssertionError('mutation before output guard')),patch.object(P.os,'rmdir',side_effect=AssertionError('mutation before output guard')),patch.object(Path,'write_bytes',side_effect=AssertionError('mutation before output guard')),patch.dict(P.os.environ,{'CAA_CORE622_PHASE_END':str(time.monotonic()+100)}),self.assertRaises(Reached)as found:getattr(P,role)()
    self.assertIs(found.exception,reason);guard.assert_called_once_with(os.getuid(),os.getgid());self.assertEqual(sorted(p.name for p in measurement.iterdir()),before)


class MediaContractInflateControls(unittest.TestCase):
 """Real held prepare/read/gzip/copy/capability bodies on tiny owned files.

 The 48GiB reserve, finite measurement inode capacity and container read-only
 mount flag are modeled explicitly; actual capacity checks remain in the path.
 APIs point at actual held FD algorithms with small fixture limits. Execution
 stops at the first external cp command; no image, namespace or actor is made.
 """
 OLD_MODULE="def module(root):\n text,_=derive(root);text=__import__('lane622').media_text(text);m=types.ModuleType('_core_real_systemd_media');m.__file__=str(Path(root)/'media_adapter.py');m.__dict__['BOOT']=boot\n sys.path.insert(0,str(Path(root)));C.load('contract',Path(root)/'contract.py');C.load('cap_scope',Path(root)/DONOR.replace('disk.py','cap_scope.py'));exec(compile(text,'whole-held574-core-systemd-media','exec'),m.__dict__);return m\n"
 class ExternalBoundary(RuntimeError):pass
 def modules(self):
  import media,provision622
  self.assertEqual(Path(media.__file__).resolve(),(CASE/'media.py').resolve());return media,provision622
 def original_module(self):
  M,_=self.modules();self.assertEqual(C.pin(self.OLD_MODULE.encode())['sha256'],'add823c53e7a5c8a990ec790a3eadf98b1f71b158589c202aea5895c9ea709f0');namespace=dict(vars(M));exec(compile(self.OLD_MODULE,'exact-f46-module-DATA','exec'),namespace);missing=object();saved={n:sys.modules.get(n,missing)for n in('contract','cap_scope')};paths=sys.path[:]
  try:return namespace['module'](A.vm_source/'runtime')
  finally:
   sys.path[:]=paths
   for name,value in saved.items():
    if value is missing:sys.modules.pop(name,None)
    else:sys.modules[name]=value
 def construct_restored(self,call):
  missing=object();saved={n:sys.modules.get(n,missing)for n in('contract','cap_scope')};sentinels={n:types.ModuleType('_fixture_prior_'+n)for n in saved};paths=sys.path[:];sys.modules.update(sentinels)
  try:
   try:return call()
   finally:
    self.assertEqual(sys.path,paths)
    for name,value in sentinels.items():self.assertIs(sys.modules.get(name),value)
  finally:
   sys.path[:]=paths
   for name,value in saved.items():
    if value is missing:sys.modules.pop(name,None)
    else:sys.modules[name]=value
 def tools(self):
  update=A.vm_source/'runtime/media-source/scripts/update'
  with R.namespace(update):
   import full_root,measure_copy
   roots,copier=full_root,measure_copy
  name='_core622_media_tiny_scope';scope=C.load(name,A.vm_source/'runtime/media-source/scripts/ci/full-root-upgrade-caller/persistent_scope.py');sys.modules.pop(name,None);return scope,roots,copier
 def run_prepare(self,module,kind=None,readonly=True):
  import contextlib,gzip
  M,P=self.modules();folder=tempfile.TemporaryDirectory(prefix='media-contract-tiny-',dir='/var/tmp');self.addCleanup(folder.cleanup);root=Path(folder.name);paths={name:root/name.lstrip('/')for name in('/measurement','/current607-root','/current607-proof','/workspace','/source','/inputs')}
  for path in paths.values():path.mkdir(mode=0o700)
  source=paths['/current607-root'];(source/'usr/lib').mkdir(parents=True);(source/'usr/lib/libfixture.so').write_bytes(b'INERT_TINY_LIBRARY_DATA_NEVER_EXECUTED');helper='media-source/scripts/apps/file_capabilities.py';target=paths['/source']/helper;target.parent.mkdir(parents=True);target.write_bytes(C.read(A.vm_source/'runtime'/helper,256*1024));(paths['/inputs']/'input.txt').write_bytes(b'inert input')
  scope,roots,copier=self.tools();limits=roots.Limits(deadline=time.monotonic()+30,max_nodes=1000,max_bytes=8*1024**2,max_file_bytes=1024**2,max_package_files=1000);graph=roots.observe(source,limits=limits,hardlinks='generic-development-internal',absolute_paths=True);nonce='c'*32;identity=[source.stat().st_dev,source.stat().st_ino];proof=dict(nonce=nonce,status='PASS_COMPLETE607_SIGNED_PROVISIONING_GRAPH_DB_CAPS_AND_PRESERVATION',root_identity=identity);data=dict(nodes=copy.deepcopy(graph['nodes']));mapping={}
  if kind=='nonce':proof['nonce']='d'*32
  elif kind=='identity':proof['root_identity']=[identity[0],identity[1]+1]
  elif kind=='nodes':data['nodes']['usr/lib/libfixture.so']['sha256']='f'*64
  elif kind=='caps':mapping={'foreign':'00'}
  compressed=gzip.compress(C.encoded(data),mtime=0)
  if kind=='gzip-truncated':compressed=compressed[:-1]
  elif kind=='gzip-trailing':compressed+=b'x'
  elif kind=='gzip-concatenated':compressed+=compressed
  (paths['/current607-proof']/'current607-formation.json').write_bytes(C.encoded(proof));(paths['/current607-proof']/'current607-root.json.gz').write_bytes(compressed);(paths['/current607-proof']/'current607-capabilities.json').write_bytes(C.encoded(mapping));config=root/'upgrade-config.json';config.write_bytes(C.encoded(dict(scale=dict(limits=dict(root_nodes=1000,root_bytes=8*1024**2,file_bytes=1024**2,package_files=1000)))));paths['/upgrade-config.json']=config
  # Project the host table to actual source/output descriptor mount IDs,
  # matching the isolated container boundary without unrelated host aliases.
  identifiers=set()
  for path in(source,paths['/measurement']):
   fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
   try:identifiers.add(roots._mount_id(fd,limits))
   finally:os.close(fd)
  mount_table=''.join(line+'\n'for line in scope._mount_table().splitlines()if int(line.split(' ',1)[0])in identifiers);self.assertEqual(len(mount_table.splitlines()),len(identifiers))
  def mapped(value):
   value=Path(value)
   for name,target in sorted(paths.items(),key=lambda item:len(item[0]),reverse=True):
    origin=Path(name)
    if value==origin or value.is_relative_to(origin):return target/value.relative_to(origin)
   return value
  real_vfs=os.fstatvfs;calls=[];captures=[];base=module.cap_scope.C;before_path=base.Path;real_derive=module.cap_scope.derive
  real_space=os.statvfs
  def space(path):
   value=real_space(path)
   if Path(path).is_relative_to(paths['/measurement']):
    fields={name:getattr(value,name)for name in dir(value)if name.startswith('f_')};fields['f_favail']=0 if kind=='capacity-unknown'else 16384;return types.SimpleNamespace(**fields)
   return value
  def vfs(fd):
   value=real_vfs(fd);info=os.fstat(fd)
   if readonly and[info.st_dev,info.st_ino]==identity:
    fields={name:getattr(value,name)for name in dir(value)if name.startswith('f_')};fields['f_flag']|=os.ST_RDONLY;return types.SimpleNamespace(**fields)
   return value
  def command(argv,seconds=600):calls.append((list(map(str,argv)),seconds));raise self.ExternalBoundary('before external cp/mkfs, no actor executed')
  s=dict(nonce=nonce,uid=os.getuid(),gid=os.getgid(),bindings=('/inputs',),runner_files={},source_files={})
  with contextlib.ExitStack()as stack:
   stack.enter_context(patch.object(module,'Path',side_effect=mapped));stack.enter_context(patch.object(base,'Path',side_effect=mapped));stack.enter_context(patch.object(module,'apis',return_value=(scope,roots,copier,None)));stack.enter_context(patch.object(module.shutil,'disk_usage',return_value=types.SimpleNamespace(total=64*1024**3,used=0,free=64*1024**3)));stack.enter_context(patch.object(module,'command',side_effect=command));stack.enter_context(patch.object(os,'fstatvfs',side_effect=vfs));stack.enter_context(patch.object(os,'statvfs',side_effect=space));stack.enter_context(patch('subprocess.Popen',side_effect=AssertionError('no external actor in media controls')))
   stack.enter_context(patch.object(scope,'_mount_table',return_value=mount_table))
   manifests=stack.enter_context(patch.object(scope,'source_manifest',wraps=scope.source_manifest));copies=stack.enter_context(patch.object(copier,'copy_data',wraps=copier.copy_data));clock=stack.enter_context(patch.object(module,'limits',wraps=module.limits));guard=stack.enter_context(patch.object(P,'readonly',wraps=P.readonly))
   def derive(raw,omitted):
    actual=real_derive(raw,omitted);observe=stack.enter_context(patch.object(actual,'observe',wraps=actual.observe));restore=stack.enter_context(patch.object(actual,'restore',wraps=actual.restore));captures.append((actual,observe,restore));return actual
   stack.enter_context(patch.object(module.cap_scope,'derive',side_effect=derive))
   try:module.prepare(s)
   finally:self.last=dict(root=root,source=source,measurement=paths['/measurement'],calls=calls,manifests=manifests.call_count,copies=copies.call_count,clock=clock.call_args_list,readonly=guard.call_count,capabilities=[(observe.call_count,restore.call_count)for _,observe,restore in captures],original_contract=base,original_path=before_path)
 def test_old_f46_reproduces_missing_inflate_then_actual_fixed_prepare_reaches_cp(self):
  M,_=self.modules();old=self.original_module();self.assertFalse(hasattr(old.C,'inflate'));self.assertIs(old.cap_scope.C,old.C)
  with self.assertRaisesRegex(AttributeError,"has no attribute 'inflate'"):self.run_prepare(old)
  self.assertEqual(self.last['calls'],[]);self.assertEqual(self.last['copies'],0);self.assertEqual(self.last['readonly'],0)
  current=self.construct_restored(lambda:M.module(A.vm_source/'runtime'));self.assertEqual(current.prepare.__code__,old.prepare.__code__)
  with self.assertRaises(self.ExternalBoundary):self.run_prepare(current)
  self.assertEqual(len(self.last['calls']),1);argv,seconds=self.last['calls'][0];self.assertEqual(argv[:4],['/usr/bin/cp','-a','--reflink=never','--']);self.assertEqual(seconds,900);self.assertEqual(self.last['copies'],1);self.assertEqual(self.last['manifests'],2);self.assertEqual(self.last['readonly'],1);self.assertEqual(self.last['capabilities'],[(3,1)]);self.assertEqual(self.last['clock'][0].args[1],900);self.assertFalse(any(self.last['measurement'].glob('*.raw')));self.assertIs(current.cap_scope.C.Path,self.last['original_path'])
 def test_private_inflater_is_exact_case_helper_and_original_globals_stay_original(self):
  M,_=self.modules();module=self.construct_restored(lambda:M.module(A.vm_source/'runtime'));base=module.cap_scope.C;self.assertIs(module.C.inflate,C.inflate);self.assertIsNot(module.C,base);self.assertFalse(hasattr(base,'inflate'));self.assertIs(module.C.read,base.read);self.assertIs(module.C.decode,base.decode);self.assertIs(base.read.__globals__,vars(base));self.assertEqual(Path(base.__file__),A.vm_source/'runtime/contract.py');self.assertEqual(base.HERE,A.vm_source/'runtime');self.assertIs(module.prepare.__globals__['C'],module.C)
 def test_real_bounded_gzip_accepts_complete_bytes_and_refuses_every_bad_framing(self):
  import gzip
  M,_=self.modules();module=M.module(A.vm_source/'runtime');payload=b'{"nodes":{"bounded":true}}';raw=gzip.compress(payload,mtime=0);self.assertIs(module.C.inflate,C.inflate);self.assertEqual(module.C.inflate(raw,len(payload)),payload)
  for value in(raw[:-1],raw+b'trailing',raw+raw,bytearray(raw),b''):
   with self.subTest(kind=type(value).__name__,length=len(value)),self.assertRaises(ValueError):module.C.inflate(value)
  with self.assertRaises(ValueError):module.C.inflate(raw,len(payload)-1)
 def test_actual_prepare_refuses_bad_gzip_before_copy_or_external_command(self):
  M,_=self.modules()
  for kind in('gzip-truncated','gzip-trailing','gzip-concatenated'):
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.run_prepare(M.module(A.vm_source/'runtime'),kind)
   self.assertEqual(self.last['copies'],0);self.assertEqual(self.last['calls'],[])
 def test_original_proof_identity_nodes_caps_and_real_readonly_fd_guard_stay_required(self):
  M,_=self.modules()
  for kind in('nonce','identity','nodes','caps','readonly'):
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.run_prepare(M.module(A.vm_source/'runtime'),kind,readonly=kind!='readonly')
   self.assertEqual(self.last['copies'],0);self.assertEqual(self.last['calls'],[]);self.assertEqual(self.last['readonly'],1)
 def test_original_capacity_guard_refuses_unknown_measurement_inode_count(self):
  M,_=self.modules()
  with self.assertRaisesRegex(ValueError,'insufficient or unknown filesystem free inode count'):self.run_prepare(M.module(A.vm_source/'runtime'),'capacity-unknown')
  self.assertEqual(self.last['copies'],1);self.assertEqual(self.last['calls'],[]);self.assertFalse((self.last['measurement']/'stage/boot').exists())
 def minimal_vm(self):
  M,_=self.modules();folder=tempfile.TemporaryDirectory(prefix='media-contract-pinned-input-',dir='/var/tmp');self.addCleanup(folder.cleanup);root=Path(folder.name)
  for name in('contract.py',M.DONOR,M.DONOR.replace('disk.py','cap_scope.py')):
   target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(C.read(A.vm_source/'runtime'/name,256*1024))
  return root
 def test_each_exact_contract_donor_or_capability_drift_refuses_before_exec(self):
  M,_=self.modules()
  for name in('contract.py',M.DONOR,M.DONOR.replace('disk.py','cap_scope.py')):
   with self.subTest(name=name):
    root=self.minimal_vm();target=root/name;target.write_bytes(target.read_bytes()+b'\n# private hostile fixture drift\n')
    with patch('builtins.exec',side_effect=AssertionError('drift must refuse before dependency execution')),self.assertRaisesRegex(ValueError,'exact pinned original media contract/donor/capability body'):self.construct_restored(lambda:M.module(root))
 def test_late_donor_drift_after_actual_derivation_refuses_before_exec(self):
  M,_=self.modules();root=self.minimal_vm();original=M.derive
  def drift(path):
   result=original(path);target=Path(path)/M.DONOR;target.write_bytes(target.read_bytes()+b'\n# late private fixture drift\n');return result
  with patch.object(M,'derive',side_effect=drift),patch('builtins.exec',side_effect=AssertionError('late drift must refuse before dependency execution')),self.assertRaisesRegex(ValueError,'same whole media donor after derivation'):self.construct_restored(lambda:M.module(root))
 def test_aliases_and_sys_path_restore_after_partial_donor_execution_failure(self):
  import builtins
  M,_=self.modules();original=builtins.exec;seen=[]
  class Reached(RuntimeError):pass
  reason=Reached('actual held donor exec boundary')
  def stop(code,namespace=None,local=None,**kwargs):
   name=namespace.get('__name__')if isinstance(namespace,dict)else None;seen.append(name)
   if name=='_core_real_systemd_media':raise reason
   return original(code,namespace,local,**kwargs)
  with patch('builtins.exec',side_effect=stop),self.assertRaises(Reached)as found:self.construct_restored(lambda:M.module(A.vm_source/'runtime'))
  self.assertIs(found.exception,reason);self.assertIn('_core622_original_media_contract',seen);self.assertIn('_core622_original_media_cap_scope',seen);self.assertIn('_core_real_systemd_media',seen)
 def test_held_prepare_code_outer_authority_and_all_clocks_remain_exact(self):
  M,_=self.modules();text,held=M.derive(A.vm_source/'runtime');derived=L.media_text(text);module=M.module(A.vm_source/'runtime');expected=next(value for value in compile(derived,module.prepare.__code__.co_filename,'exec').co_consts if isinstance(value,types.CodeType)and value.co_name=='prepare');self.assertEqual(module.prepare.__code__,expected)
  outer_text=C.read(CASE/'media.py').decode();node=next(n for n in ast.parse(outer_text).body if isinstance(n,ast.FunctionDef)and n.name=='prepare');outer=ast.get_source_segment(outer_text,node)+'\n';self.assertEqual(C.pin(outer.encode())['sha256'],'8afe16445ff26c512427b61d180dc41c1af4268e5034c4a4eececa8a2d709d88');self.assertIn('mask=0x8000001b',outer);self.assertNotIn('SYS_CHROOT',outer)
  self.assertEqual(C.BUDGET,dict(owner=14400,producer=2300,assembly=1070,media=1900,vm_shared=7200,boot=3600,transaction=90,cleanup=60));self.assertEqual(module.C.SHARED_SECONDS,3000);self.assertEqual(module.C.PRODUCT_SECONDS,5);self.assertEqual(module.C.CAP,16*1024**2)


class CleanupLifetimeControls(unittest.TestCase):
 """Actual cleanup/actor/work guards; only external transport and old Core bootstrap/cleanup are modeled. Tiny private root effects are synthetic, never native acceptance."""
 RULES=[("   C.need(shutil.rmtree.avoids_symlink_attacks and time.monotonic()<end,'bounded descriptor-safe VM retirement');shutil.rmtree(work);result['vm']='PASS_OWNED_MEDIA_AND_PREPARATION_RETIRED'\n", "   if(a.output/'owner.json').exists():\n    report=C.decode(C.read(a.output/'owner.json',16*1024**2));__import__('lane622').retire(a,report,O.command_api(a.workspace,a.output,report),end)\n   C.need(shutil.rmtree.avoids_symlink_attacks and time.monotonic()<end,'bounded descriptor-safe VM retirement');shutil.rmtree(work);result['vm']='PASS_OWNED_MEDIA_AND_PREPARATION_RETIRED'\n"), ("\n  if(a.output/'owner.json').exists():\n   report=C.decode(C.read(a.output/'owner.json',16*1024**2));__import__('lane622').retire(a,report,O.command_api(a.workspace,a.output,report),end)\n", "\n  elif(a.output/'owner.json').exists():\n   report=C.decode(C.read(a.output/'owner.json',16*1024**2));__import__('lane622').retire(a,report,O.command_api(a.workspace,a.output,report),end)\n")]
 OLD_CLEANUP_PIN={'bytes': 4061, 'sha256': 'f1bd3d426af5168269bbfab29a18bbcb76045849099324598827f5d75498ebe1'}
 class Docker(ProofOutputControls.Docker):
  def __init__(self,args,fixture):super().__init__(args,'retire607');self.fixture=fixture
  def __call__(self,argv,*options):
   if argv[:2]==['/usr/bin/docker','run']:
    self.fixture.attempts+=1;self.fixture.seconds.append(options[1]);missing=[]
    for i,v in enumerate(argv):
     if v=='--mount':
      fields=dict(p.split('=',1)for p in argv[i+1].split(',')if'='in p)
      if not Path(fields['src']).exists():missing.append(fields['src'])
    if missing or self.fixture.fail_run:
     self.commands.append(list(argv));self.args._owner_report['commands'].append(dict(argv=list(argv)));message='bind source path does not exist: '+(missing[0]if missing else'SYNTHETIC_REFUSAL');self.fixture.errors.append(message);return dict(code=125,out=b'',err=message.encode())
    root=self.args.output/'data/current607';lease=C.decode(C.read(root.parent/'current607-lease.json'));st=root.lstat();parent=root.parent.stat();C.need(root.is_relative_to(self.fixture.folder)and not root.is_symlink()and lease['nonce']==self.args.selected['nonce']and lease['root']==[st.st_dev,st.st_ino]and lease['parent']==[parent.st_dev,parent.st_ino],'only fixture-owned exact root effect may be modeled');__import__('shutil').rmtree(root);self.fixture.effects+=1
   result=super().__call__(argv,*options);(self.args.output/'owner.json').write_bytes(C.encoded(self.args._owner_report));return result
 def fixture(self,with_vm=True,original_result=0,fail_run=False):
  import evidence,lane622,adapter
  self.assertEqual(Path(evidence.__file__).resolve(),(CASE/'evidence.py').resolve());t=tempfile.TemporaryDirectory(prefix='cleanup-lifetime-',dir='/tmp');self.addCleanup(t.cleanup);root=Path(t.name);self.folder=root;output=root/'output';output.mkdir(mode=0o700);work=output/'vm-work';media=output/'media';data=output/'data'
  for path in(work,media,data,output/'inputs',output/'current607-public',output/'boots',root/'base',root/'current607-inputs',root/'fresh607-source',root/'current607-code',root/'kernel-inputs',root/'core-workspace'):path.mkdir(mode=0o700)
  for name in('runner','signing','guest-out'):(work/name).mkdir(mode=0o700)
  (work/'runner/inert.txt').write_bytes(b'ONLY_OWNED_FIXTURE_DATA');(work/'upgrade-config.json').write_bytes(b'{}\n');support=root/'vm-source/runtime/media-source';(support/'scripts/ci/full-root-upgrade-caller').mkdir(parents=True);(support/'scripts/ci/full-root-upgrade-caller/persistent_scope.py').write_bytes(b'INERT_SOURCE_NOT_EXECUTED');(root/'base/context/deps').mkdir(parents=True)
  target=data/'current607';target.mkdir(mode=0o700);(target/'owned.txt').write_bytes(b'bounded synthetic owned root');st=target.stat();parent=data.stat();nonce='c'*32;(data/'current607-lease.json').write_bytes(C.encoded(dict(nonce=nonce,root=[st.st_dev,st.st_ino],parent=[parent.st_dev,parent.st_ino])));image='sha256:'+'a'*64;(root/'base/report.json').write_bytes(C.encoded(dict(image=image,ownership=dict(token='fixture-token'))));(output/'owner.json').write_bytes(C.encoded(dict(status='FAIL',error='one actual final observer frame',commands=[])))
  (output/'vm-work-map.json').write_bytes(C.encoded(adapter.source_rows(work)));(output/'vm-media-lease.json').write_bytes(C.encoded(dict(metadata={})));(output/'boots/boot-1.json').write_bytes(C.encoded(dict(group_absence_verified=True)))
  if with_vm:(output/'vm-owner.json').write_bytes(C.encoded(dict(nonce=nonce,work=[work.stat().st_dev,work.stat().st_ino],media=[media.stat().st_dev,media.stat().st_ino])))
  a=types.SimpleNamespace(output=output,case_source=CASE,core_source=A.core_source,workspace=root/'core-workspace',selected=dict(nonce=nonce),base=root/'base',image=image,vm_source=root/'vm-source',kernel_inputs=root/'kernel-inputs',current607_inputs=root/'current607-inputs',fresh607_source=root/'fresh607-source',current607_code=root/'current607-code',receipt=root/'ordered-cleanup.json');self.args=a;self.attempts=0;self.effects=0;self.original_calls=0;self.seconds=[];self.errors=[];self.dockers=[];self.original_result=original_result;self.fail_run=fail_run;self.with_vm=with_vm;return evidence,lane622,a
 def before(self,evidence):
  text=C.read(CASE/'evidence.py').decode()
  for old,new in reversed(self.RULES):self.assertEqual(text.count(new),1);text=text.replace(new,old,1)
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='cleanup');self.assertEqual(C.pin((ast.get_source_segment(text,node)+'\n').encode()),self.OLD_CLEANUP_PIN);module=types.ModuleType('_exact_ad09_cleanup_before');module.__dict__.update(vars(evidence));paths=sys.path[:]
  try:exec(compile(text,str(CASE/'evidence.py'),'exec'),vars(module));return module
  finally:sys.path[:]=paths
 def run_cleanup(self,evidence,lane,a):
  def command_api(workspace,output,report):
   self.assertEqual((workspace,output),(a.workspace,a.output));a._owner_report=report;docker=self.Docker(a,self);self.dockers.append(docker);return docker
  owner=types.SimpleNamespace(command_api=command_api);real_load=C.load
  def load(name,path):
   if Path(path)==a.core_source/'scripts/ci/core-native-lifecycle/owner.py':return owner
   return real_load(name,path)
  def original_cleanup(original,args):
   self.original_calls+=1;self.assertIs(original,owner);self.assertIs(args,a);self.assertFalse((a.output/'data/current607').exists())
   if self.with_vm:self.assertFalse((a.output/'vm-work').exists());self.assertFalse((a.output/'media').exists())
   return self.original_result
  with patch.object(evidence.adapter,'core',return_value=object()),patch.object(C,'load',side_effect=load),patch.object(lane,'old_cleanup',side_effect=original_cleanup),patch('subprocess.Popen',side_effect=AssertionError('no actor in cleanup control')):return evidence.cleanup(a)
 def receipt(self):return C.decode(C.read(self.args.receipt))
 def test_exact_old_cleanup_inverse_and_unchanged_sixty_second_budget(self):
  E,L,a=self.fixture();self.before(E);text=C.read(CASE/'evidence.py').decode();body=ast.get_source_segment(text,next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='cleanup'));self.assertEqual(body.count('end=time.monotonic()+60'),1);self.assertLess(body.index('original bounded preparation source work'),body.index("__import__('lane622').retire"));self.assertLess(body.index("__import__('lane622').retire"),body.index('bounded descriptor-safe VM retirement'));self.assertIn("elif(a.output/'owner.json').exists()",body)
 def test_old_failure_reproduces_missing_bind_then_consequential_none_type(self):
  E,L,a=self.fixture();old=self.before(E);self.assertEqual(self.run_cleanup(old,L,a),1);value=self.receipt();self.assertEqual(value['status'],'FAIL');self.assertEqual(value['vm'],'PASS_OWNED_MEDIA_AND_PREPARATION_RETIRED');self.assertEqual(value['error_type'],'TypeError');self.assertIn('NoneType',value['error']);self.assertEqual(self.attempts,1);self.assertTrue(any('vm-work/upgrade-config.json'in error for error in self.errors));self.assertFalse((a.output/'vm-work').exists());self.assertTrue((a.output/'data/current607').exists());self.assertEqual(self.original_calls,0)
 def test_fixed_cleanup_uses_live_inputs_once_then_retires_only_owned_work(self):
  E,L,a=self.fixture();lease=C.pin(C.read(a.output/'data/current607-lease.json'));self.assertEqual(self.run_cleanup(E,L,a),0);self.assertEqual(self.receipt()['status'],'PASS_ALL_VM_THEN_ORIGINAL800_CONSUMER_PRODUCER_RETIREMENT');self.assertEqual((self.attempts,self.effects,self.original_calls),(1,1,1));self.assertEqual(self.errors,[]);self.assertTrue(all(0<seconds<=60 for seconds in self.seconds))
  for name in('data/current607','media','vm-work'):self.assertFalse((a.output/name).exists())
  owner=C.decode(C.read(a.output/'owner.json'));self.assertEqual(owner['status'],'FAIL');self.assertEqual(owner['error'],'one actual final observer frame');self.assertTrue(all(not d.exists for d in self.dockers));self.assertEqual(C.pin(C.read(a.output/'data/current607-lease.json')),lease)
 def test_pre_vm_fallback_dispatches_once_and_preserves_unleased_work_media(self):
  E,L,a=self.fixture(with_vm=False,original_result=1);work=C.pin(C.read(a.output/'vm-work/upgrade-config.json'));self.assertEqual(self.run_cleanup(E,L,a),1);self.assertEqual((self.attempts,self.effects,self.original_calls),(1,1,1));self.assertEqual(C.pin(C.read(a.output/'vm-work/upgrade-config.json')),work);self.assertTrue((a.output/'media').exists());self.assertEqual(self.receipt()['status'],'FAIL')
 def test_active_qemu_group_refuses_before_any_retirement_or_deletion(self):
  E,L,a=self.fixture();(a.output/'boots/boot-1.json').write_bytes(C.encoded(dict(group_absence_verified=False)));self.assertEqual(self.run_cleanup(E,L,a),1);self.assertEqual(self.attempts,0);self.assertEqual(self.original_calls,0)
  for name in('media','vm-work','data/current607'):self.assertTrue((a.output/name).exists())
 def test_changed_work_map_refuses_before_actor_uses_its_sources(self):
  E,L,a=self.fixture();(a.output/'vm-work/upgrade-config.json').write_bytes(b'CHANGED');self.assertEqual(self.run_cleanup(E,L,a),1);self.assertEqual(self.attempts,0);self.assertEqual(self.original_calls,0);self.assertTrue((a.output/'vm-work').exists());self.assertTrue((a.output/'data/current607').exists());self.assertIn('whole exact unchanged preparation work files',self.receipt()['error'])
 def test_wrong_vm_lease_preserves_borrowed_directories(self):
  E,L,a=self.fixture();path=a.output/'vm-owner.json';lease=C.decode(C.read(path));lease['work'][1]+=1;path.write_bytes(C.encoded(lease));self.assertEqual(self.run_cleanup(E,L,a),1);self.assertEqual(self.attempts,0)
  for name in('media','vm-work','data/current607'):self.assertTrue((a.output/name).exists())
 def test_failed_retire_command_cannot_turn_cleanup_into_pass(self):
  E,L,a=self.fixture(fail_run=True);self.assertEqual(self.run_cleanup(E,L,a),1);self.assertEqual(self.receipt()['status'],'FAIL');self.assertEqual(self.original_calls,0);self.assertTrue((a.output/'data/current607').exists());self.assertTrue((a.output/'vm-work').exists());self.assertEqual(self.effects,0)
 def test_original_cleanup_nonzero_remains_a_failure(self):
  E,L,a=self.fixture(original_result=3);self.assertEqual(self.run_cleanup(E,L,a),1);self.assertEqual(self.receipt()['status'],'FAIL');self.assertEqual(self.receipt()['original_cleanup'],3);self.assertEqual(self.original_calls,1)

class ObserverFailureControls(unittest.TestCase):
 """Portable negative DATA only; no real run, VM, systemd or frame synthesis."""
 FAILED_UART=(b'ValueError: command-time-limit\n'
  b'caa-core-worker.service: Main process exited, code=exited, status=1/FAILURE\n'
  b'caa-core-worker.service: Failed with result exit-code.\n'
  b'caa-core-observer.service: Job caa-core-observer.service/start failed with result dependency.\n'
  b'Powering off: unit caa-core-worker.service failed\n')
 def selector(self):
  profile=C.decode(C.read(CASE/'profile.json',4*1024**2))
  return dict(schema=1,scope=profile['purpose'],actual=dict(source='b'*40,ref='codex/source-only-negative-fixture',run=1,attempt=1),nonce='a'*32,kernel=profile['kernel'],source_profiles={name:profile['source_profiles'][name]for name in('core800','ksm637','core7_carrier')},budgets=C.BUDGET)
 def guest(self):return C.load('_source_only_observer_failure_guest',CASE/'guest.py')
 def test_failed_worker_uart_without_frame_remains_refused(self):
  self.assertFalse(any(line.startswith(C.PREFIX)or line.startswith(C.RETIRED)for line in self.FAILED_UART.splitlines()))
  with self.assertRaisesRegex(ValueError,'one actual final observer frame'):C.protocol(self.FAILED_UART,self.selector(),1,{})
 def test_natural_qemu_foreground_exit_does_not_replace_observer_frame(self):
  row=dict(argv=['/source-only-inert-qemu-boundary'],exit_code=0,group_absence_verified=True,output_limit=1024**2,seconds=843.0,time_limit=3600,stdout_bytes=len(self.FAILED_UART),stdout_sha256=C.pin(self.FAILED_UART)['sha256'],stderr_bytes=0,stderr_sha256=C.pin(b'')['sha256'])
  C.command(row,3600)
  with self.assertRaisesRegex(ValueError,'one actual final observer frame'):C.protocol(self.FAILED_UART,self.selector(),1,{})
 def blocked_observer(self,custody):
  import io
  G=self.guest();buffer=io.BytesIO();stream=types.SimpleNamespace(buffer=buffer,flush=lambda:None);queries=[]
  def forbidden(*args,**kwargs):queries.append(args);raise AssertionError('failed custody must precede any observer command')
  api=dict(runtime=types.SimpleNamespace(run_command=forbidden));core=types.SimpleNamespace(api=api)
  with tempfile.TemporaryDirectory(prefix='observer-failure-source-')as td:
   root=Path(td);(root/'phase1-custody.json').write_bytes(C.encoded(custody))
   with patch.object(G,'OUT',root),patch.object(G,'END',None),patch.object(G,'sources',return_value=core),patch.object(G.sys,'stdout',stream),self.assertRaisesRegex(ValueError,'whole actual stage and independent key retirement'):G.observer(self.selector(),1,{})
   self.assertEqual(queries,[]);self.assertEqual(buffer.getvalue(),b'');self.assertEqual(sorted(p.name for p in root.iterdir()),['phase1-custody.json'])
 def test_actual_observer_rejects_failed_custody_before_queries_or_frame(self):
  for retired in(False,True):
   with self.subTest(public_home_retired=retired):self.blocked_observer(dict(status='FAIL',public_home_retired=retired,error_type='ValueError',error='command-time-limit'))
 def test_actual_observer_requires_independent_public_key_retirement(self):
  # This negative dictionary is not a frame or a claim of actual stage success.
  self.blocked_observer(dict(status='PASS_FULL_GRAPH_SIGNATURE_ACCOUNT_CACHE_AND_USER_PRESERVATION',public_home_retired=False))
 def test_finish_refuses_failed_service_exit_before_any_receipt_read(self):
  G=self.guest();selector=self.selector()
  for result,code,status in(('exit-code','exited','1'),('timeout','killed','15'),('success','exited','1')):
   with self.subTest(result=result,code=code,status=status),patch.dict(os.environ,dict(SERVICE_RESULT=result,EXIT_CODE=code,EXIT_STATUS=status)),patch.object(G.C,'read',side_effect=AssertionError('failed exit must refuse before observer receipt read')),self.assertRaisesRegex(ValueError,'genuine natural observer exec-service exit'):G.finish(selector,1)
 def test_exact_worker_probe_observer_dependency_and_poweroff_policy(self):
  import configparser
  def unit(name):
   value=configparser.ConfigParser(interpolation=None,strict=True);value.read_string(C.read(CASE/'units'/name,16384).decode());return value
  worker=unit('caa-core-worker.service');probe=unit('caa-core-probe.service');observer=unit('caa-core-observer.service');target=unit('caa-core.target')
  self.assertEqual(worker['Unit']['FailureAction'],'poweroff');self.assertEqual(worker['Service']['Type'],'oneshot');self.assertEqual(worker['Service']['TimeoutStartSec'],'3300')
  self.assertEqual(probe['Unit']['Requires'],'caa-core-worker.service');self.assertEqual(probe['Unit']['After'],'caa-core-worker.service');self.assertEqual(observer['Unit']['Requires'],'caa-core-probe.service');self.assertEqual(set(observer['Unit']['After'].split()),{'caa-core-probe.service','caa-core.target'})
  self.assertEqual(observer['Unit']['SuccessAction'],'poweroff');self.assertEqual(observer['Service']['Type'],'exec');self.assertEqual(observer['Service']['ExecStopPost'],'/usr/bin/python3 -I -B /workspace/guest.py finish');self.assertEqual(observer['Service']['TimeoutStartSec'],'180');self.assertEqual(observer['Service']['TimeoutStopSec'],'60')
  self.assertEqual(target['Unit']['Requires'],'caa-core-probe.service');self.assertEqual(target['Unit']['After'],'caa-core-probe.service');self.assertEqual(target['Unit']['Wants'],'caa-core-observer.service')
 def test_original_frame_pid1_hook_guards_and_budgets_are_held(self):
  expected={'guest.py':{'observer':'ea8ad7193bbf223e3ae492a843a1bf4bf7823f4e953caf640dcac248a64fde6c','finish':'12c76f7f7a52a15a26fc2e785cbf63bacb4c5f20c58f87106735d74e81ec69c4'},'case.py':{'protocol':'1c5c58ae035f2efa6065361a003a15687fe9142af54f83feb5953c28ab38e729','command':'4691bd0f860e7be7514d9c56e56aab0f0b5889f6586330acdc57f2aff811d5ac'}}
  for leaf,functions in expected.items():
   raw=C.read(CASE/leaf).decode();tree=ast.parse(raw)
   for name,want in functions.items():
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name);self.assertEqual(C.pin(ast.get_source_segment(raw,node).encode())['sha256'],want)
  self.assertEqual(C.BUDGET,dict(owner=14400,producer=2300,assembly=1070,media=1900,vm_shared=7200,boot=3600,transaction=90,cleanup=60))
  import host
  raw=C.read(CASE/'host.py').decode();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='two_boots');calls=[n for n in ast.walk(node)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name)and n.func.value.id=='C'];command=next(n for n in calls if n.func.attr=='command');protocol=next(n for n in calls if n.func.attr=='protocol');self.assertLess(command.lineno,protocol.lineno);self.assertFalse(any(isinstance(n,ast.ExceptHandler)for n in ast.walk(node)))

class TransactionDiagnosticControls(unittest.TestCase):
 """Finite inert file fixtures; no package manager, guest or observer execution."""
 def exercise(self,mode='failure',change=None,mutate_guest=None):
  G=C.load('_transaction_diagnostic_guest',CASE/'guest.py')
  # Standalone runner supplies the proposed source; production uses integrated guest.
  transform=globals().get('TRANSACTION_DIAGNOSTIC_TRANSFORM')
  if transform:transform(G)
  with tempfile.TemporaryDirectory(prefix='transaction-diagnostic-source-')as td:
   root=Path(td);run=root/'run';run.mkdir();out=root/'out';out.mkdir()
   def path(value):
    text=str(value)
    return root/text.lstrip('/')if text=='/run'or text.startswith('/run/')else Path(value)
   expected=dict(nonce='a'*32,label='baseline-original-reinstall',targets=['systemd'])
   report=dict(phase=1,commands=[]);error=ValueError('command-time-limit')
   log=b"[ALPM] running '20-systemd-sysusers.hook'\n[ALPM] running '21-systemd-tmpfiles.hook'\n[ALPM] running '30-update-mime-database.hook'\n"
   stdout=b'==> Initcpio image generation successful\n'
   class InertCommands:
    def __init__(self):self.report=report
    def call(self,argv,seconds):
     row=dict(argv=argv,exit_code=-15 if mode=='failure'else 0,group_absence_verified=mode!='failure',time_limit=seconds,seconds=90.0454 if mode=='failure'else 1,output_limit=1024**2,stdout_bytes=len(stdout),stdout_sha256=C.pin(stdout)['sha256'],stderr_bytes=0,stderr_sha256=C.pin(b'')['sha256'])
     report['commands'].append(row);(out/'phase1-command-000.stdout').write_bytes(stdout);(out/'phase1-command-000.stderr').write_bytes(b'');(run/'core-pacman.log').write_bytes(log)
     if mode!='failure'and mode!='missing-witness':(run/'core-hook-witness.json').write_bytes(C.encoded(expected))
     if change:change(run,out,report)
     if mode=='failure':raise error
   capacity=types.SimpleNamespace(requested=lambda names,label,seconds:seconds,DIAGNOSTIC_NAME='TCG_BASELINE_TRANSACTION_180_DIAGNOSTIC',requested_diagnostic=lambda names,label,seconds,profile:180,diagnostic_profile=lambda profile:dict(baseline_seconds=180))
   mime=types.SimpleNamespace(hook_log=lambda raw,label:C.need(raw.count(b"running '30-update-mime-database.hook'")==1,'exact original MIME hook'))
   from contextlib import nullcontext
   unlink=patch.object(Path,'unlink',side_effect=OSError('inert witness retirement failure'))if mode=='unlink-failure'else nullcontext()
   original_read=C.read
   with unlink,patch.object(G.C,'read',side_effect=lambda value,cap=2*1024**2:original_read(path(value),cap)),patch.object(G,'Path',side_effect=path),patch.object(G,'OUT',out),patch.dict(sys.modules,{'candidate_capacity':capacity,'mime_cache':mime}):
    if mutate_guest:mutate_guest(G)
    result=None;caught=None
    try:result=G.transact(InertCommands(),{'systemd-original':dict(transaction=dict(name='systemd',version='262-1',archive='/inert/systemd.pkg.tar.xz'))},['systemd-original'],'a'*32,'baseline-original-reinstall')
    except BaseException as value:caught=value
   files={p.name:p.read_bytes()for p in out.iterdir()if p.is_file()and not p.is_symlink()}
   return dict(report=report,error=error,caught=caught,result=result,files=files,witness_exists=(run/'core-hook-witness.json').exists(),log=log)
 def diagnostic(self,value):
  name='phase1-baseline-original-reinstall-transaction-diagnostic.json';self.assertIn(name,value['files'],'failed or completed transaction must retain standalone progress DATA');return C.decode(value['files'][name])
 def test_failed_transaction_retains_log_expected_streams_and_exact_command_boundary(self):
  v=self.exercise();self.assertIs(v['caught'],v['error']);d=self.diagnostic(v)
  self.assertEqual(d['status'],'TRANSACTION_PROGRESS_DATA_ONLY');self.assertEqual(d['stage'],'command');self.assertFalse(d['call_returned']);self.assertFalse(d['pre_return_validation_completed']);self.assertEqual(d['requested_seconds'],180);self.assertIs(d['command_group_absence_verified'],False)
  self.assertEqual(set(d),{'schema','status','phase','label','command_index','requested_seconds','stage','call_returned','command_group_absence_verified','pre_return_validation_completed','witness_retirement','log_scope','artifacts','capture_errors'})
  self.assertEqual(set(d['artifacts']),{'pacman-log','expected','witness','stdout','stderr','command'});self.assertEqual(d['artifacts']['witness'],dict(status='MISSING'))
  for role in('pacman-log','expected','stdout','stderr','command'):
   row=d['artifacts'][role];raw=v['files'][row['file']];self.assertEqual({k:row[k]for k in('bytes','sha256')},C.pin(raw))
  self.assertEqual(v['files'][d['artifacts']['pacman-log']['file']],v['log']);self.assertEqual(C.decode(v['files'][d['artifacts']['command']['file']]),v['report']['commands'][0]);self.assertEqual(d['capture_errors'],[]);self.assertEqual(set(v['report']),{'phase','commands'})
  v=self.exercise(change=lambda run,out,report:(run/'core-hook-witness.json').write_bytes((run/'core-hook-expected.json').read_bytes()));self.assertIs(v['caught'],v['error']);self.assertTrue(v['witness_exists']);self.assertEqual(self.diagnostic(v)['artifacts']['witness']['status'],'RETAINED')
 def test_success_keeps_original_return_log_and_witness_retirement(self):
  v=self.exercise('success');self.assertIsNone(v['caught']);self.assertFalse(v['witness_exists']);d=self.diagnostic(v)
  self.assertTrue(d['call_returned']);self.assertTrue(d['pre_return_validation_completed']);self.assertEqual(d['stage'],'validated-before-witness-retirement');self.assertEqual(d['artifacts']['witness']['status'],'RETAINED')
  self.assertIs(d['command_group_absence_verified'],True)
  self.assertEqual(set(v['result']),{'command','witness','pacman_log','normal_flags','after'});self.assertIs(v['result']['command'],v['report']['commands'][0]);self.assertEqual(v['result']['witness'],dict(nonce='a'*32,label='baseline-original-reinstall',targets=['systemd']));self.assertEqual(v['result']['normal_flags'],'NO_NOHOOKS_NO_NOSCRIPTLET_NO_PRELOAD');self.assertEqual(v['result']['after'],{'systemd':'262-1'});self.assertEqual(v['files'][v['result']['pacman_log']['file']],v['log']);self.assertEqual(v['result']['pacman_log']['sha256'],C.pin(v['log'])['sha256'])
 def test_command_completion_does_not_replace_missing_or_wrong_automatic_witness(self):
  for mode,change in(('missing-witness',None),('success',lambda run,out,report:(run/'core-hook-witness.json').write_bytes(C.encoded(dict(nonce='b'*32,label='baseline-original-reinstall',targets=['systemd']))))):
   with self.subTest(mode=mode):
    v=self.exercise(mode,change);self.assertIsNotNone(v['caught']);d=self.diagnostic(v);self.assertTrue(d['call_returned']);self.assertFalse(d['pre_return_validation_completed']);self.assertEqual(d['stage'],'witness');self.assertIsNone(v['result'])
 def test_scriptlet_and_hook_refusals_retain_failure_evidence(self):
  cases=(('stderr',lambda run,out,report:(out/'phase1-command-000.stderr').write_bytes(b'error: hook failed\n')),
   ('upstream-hooks',lambda run,out,report:(run/'core-pacman.log').write_bytes(b'no upstream hooks\n')),
   ('mime-hook',lambda run,out,report:(run/'core-pacman.log').write_bytes(b"running '20-systemd-sysusers.hook'\nrunning '21-systemd-tmpfiles.hook'\n")))
  for stage,change in cases:
   with self.subTest(stage=stage):
    v=self.exercise('success',change);self.assertIsInstance(v['caught'],ValueError);self.assertIsNone(v['result']);self.assertEqual(self.diagnostic(v)['stage'],stage);self.assertFalse(self.diagnostic(v)['pre_return_validation_completed']);self.assertTrue(v['witness_exists'])
 def test_diagnostic_capture_fault_cannot_replace_original_failure_or_success(self):
  def broken(G):G._transaction_diagnostic=lambda *args:(_ for _ in()).throw(RuntimeError('do not export arbitrary exception'))
  for mode in('failure','success'):
   with self.subTest(mode=mode):
    v=self.exercise(mode,mutate_guest=broken);self.assertEqual(C.decode(v['files']['phase1-baseline-original-reinstall-transaction-capture-error.json']),dict(schema=1,status='TRANSACTION_PROGRESS_CAPTURE_ERROR_DATA_ONLY',error='CAPTURE_ERROR'));self.assertEqual(set(v['report']),{'phase','commands'})
    if mode=='failure':self.assertIs(v['caught'],v['error'])
    else:self.assertIsNone(v['caught']);self.assertIsNotNone(v['result']);self.assertFalse(v['witness_exists'])
  v=self.exercise(change=lambda run,out,report:report['commands'][0].update(extra='x'*65537));self.assertIs(v['caught'],v['error']);self.assertEqual(self.diagnostic(v)['artifacts']['command']['status'],'CAPTURE_ERROR')
  def drift(G):
   read=G.C.read.side_effect
   def unstable(path,cap=2*1024**2):
    if str(path).endswith('/core-pacman.log'):raise ValueError('whole stable descriptor/path read')
    return read(path,cap)
   G.C.read.side_effect=unstable
  v=self.exercise(mutate_guest=drift);self.assertIs(v['caught'],v['error']);self.assertEqual(self.diagnostic(v)['artifacts']['pacman-log']['status'],'REFUSED_INPUT');self.assertEqual(self.diagnostic(v)['capture_errors'],['pacman-log:INPUT_REFUSED'])
 def test_diagnostic_caps_unsafe_inputs_and_existing_outputs_are_refused(self):
  cases=(('REFUSED_INPUT',lambda run,out,report:(run/'core-pacman.log').write_bytes(b'x'*(1024**2+1))),
   ('REFUSED_INPUT',lambda run,out,report:((run/'core-pacman.log').unlink(),(run/'core-pacman.log').symlink_to(run/'core-hook-expected.json'))),
   ('WRITE_ERROR',lambda run,out,report:(out/'phase1-baseline-original-reinstall-transaction-pacman-log.log').write_bytes(b'held')))
  for status,change in cases:
   with self.subTest(status=status):
    v=self.exercise(change=change);self.assertIs(v['caught'],v['error']);d=self.diagnostic(v);self.assertEqual(d['artifacts']['pacman-log']['status'],status);self.assertTrue(d['capture_errors']);self.assertFalse(d['pre_return_validation_completed'])
    if status=='WRITE_ERROR':self.assertEqual(v['files']['phase1-baseline-original-reinstall-transaction-pacman-log.log'],b'held')
 def test_context_labels_paths_indices_and_budgets_are_closed_before_io(self):
  G=C.load('_transaction_diagnostic_closed_guest',CASE/'guest.py');transform=globals().get('TRANSACTION_DIAGNOSTIC_TRANSFORM')
  if transform:transform(G)
  for label,number,seconds,stage,returned in(('../escape',0,90,'command',False),('baseline-original-reinstall',128,90,'command',False),('baseline-original-reinstall',0,90,'command',False),('accepted-core7-install',0,90,'command',False),('baseline-original-reinstall',0,90,'invented',False),('baseline-original-reinstall',0,90,'command',1)):
   with self.subTest(label=label,number=number,seconds=seconds,stage=stage),patch.object(G.C,'read',side_effect=AssertionError('invalid context must not read')):
    report=dict(phase=1,commands=[]);self.assertFalse(G._transaction_diagnostic(types.SimpleNamespace(report=report),label,number,seconds,stage,returned));self.assertNotIn('transaction_diagnostics',report)
  self.assertEqual(C.BUDGET['transaction'],90);self.assertEqual(C.BUDGET['boot'],3600)
 def test_log_export_collision_is_still_failure_and_does_not_claim_acceptance(self):
  v=self.exercise('success',lambda run,out,report:(out/'phase1-baseline-original-reinstall-pacman.log').write_bytes(b'held'));self.assertIsInstance(v['caught'],ValueError);self.assertEqual(self.diagnostic(v)['stage'],'log-export');self.assertFalse(self.diagnostic(v)['pre_return_validation_completed']);self.assertTrue(v['witness_exists']);self.assertEqual(v['files']['phase1-baseline-original-reinstall-pacman.log'],b'held')

  v=self.exercise('unlink-failure');self.assertIsInstance(v['caught'],OSError);self.assertIsNone(v['result']);self.assertTrue(v['witness_exists']);self.assertEqual(self.diagnostic(v)['stage'],'validated-before-witness-retirement');self.assertTrue(self.diagnostic(v)['pre_return_validation_completed']);self.assertEqual(self.diagnostic(v)['witness_retirement'],'NOT_ATTEMPTED_AT_SNAPSHOT')
 def test_output_namespace_and_aggregate_caps_do_not_expand_paths_or_evidence(self):
  G=C.load('_transaction_diagnostic_output_guest',CASE/'guest.py');transform=globals().get('TRANSACTION_DIAGNOSTIC_TRANSFORM')
  if transform:transform(G)
  with tempfile.TemporaryDirectory(prefix='transaction-diagnostic-caps-')as td:
   root=Path(td);out=root/'out';out.mkdir()
   with patch.object(G,'OUT',out):
    for label,role,raw in(('../escape','diagnostic',b'{}'),('baseline-original-reinstall','../escape',b'{}'),('baseline-original-reinstall','expected',b'x'*65537),('baseline-original-reinstall','diagnostic',b'x'*16385)):
     with self.subTest(label=label,role=role),self.assertRaises(ValueError):G._transaction_diagnostic_write(label,role,raw)
    self.assertEqual(list(out.iterdir()),[])
    opened=[];original_open=os.open
    def tracking_open(*args,**kwargs):
     fd=original_open(*args,**kwargs);opened.append(fd);return fd
    with patch.object(G.os,'open',side_effect=tracking_open),patch.object(G.os,'write',side_effect=OSError('inert output fault')),self.assertRaises(OSError):G._transaction_diagnostic_write('baseline-original-reinstall','expected',b'{}')
    self.assertEqual(len(opened),1)
    with self.assertRaises(OSError):os.fstat(opened[0])
    self.assertEqual((out/'phase1-baseline-original-reinstall-transaction-expected.log').read_bytes(),b'')
    held=out/'phase1-baseline-original-reinstall-transaction-held.log'
    with held.open('wb')as stream:stream.truncate(7*1024**2)
    with self.assertRaisesRegex(ValueError,'diagnostic aggregate'):G._transaction_diagnostic_write('baseline-original-reinstall','diagnostic',b'{}')
    held.unlink();held=out/'held-graph'
    with held.open('wb')as stream:stream.truncate(512*1024**2)
    with self.assertRaisesRegex(ValueError,'original guest evidence cap'):G._transaction_diagnostic_write('baseline-original-reinstall','diagnostic',b'{}')
    held.unlink()
    for index in range(223):(out/('empty-%04d'%index)).write_bytes(b'')
    with self.assertRaisesRegex(ValueError,'finite222 guest evidence entry cap'):G._transaction_diagnostic_write('baseline-original-reinstall','diagnostic',b'{}')
   linked=root/'linked';linked.symlink_to(out,target_is_directory=True)
   with patch.object(G,'OUT',linked),self.assertRaisesRegex(ValueError,'ordinary fixed diagnostic output ancestors'):G._transaction_diagnostic_write('baseline-original-reinstall','diagnostic',b'{}')


class TransactionDiagnosticTransportControls(unittest.TestCase):
 """Actual export/parser bodies; debugfs commands are inert temporary-file DATA."""
 OLD_WRITER="def _transaction_diagnostic_write(label,role,raw):\n labels=('baseline-original-reinstall','accepted-core7-install')\n caps={'pacman-log':1024**2,'expected':65536,'witness':65536,'stdout':1024**2,'stderr':1024**2,'command':65536,'diagnostic':16384,'capture-error':1024}\n C.need(type(label)is str and label in labels and type(role)is str and role in caps and type(raw)is bytes and len(raw)<=caps[role],'closed bounded transaction diagnostic output')\n C.need(not any(p.is_symlink()for p in(OUT,*OUT.parents)),'ordinary fixed diagnostic output ancestors')\n total=diagnostic=0\n for index,path in enumerate(OUT.iterdir()):\n  C.need(index<1024,'finite1024 guest evidence entry cap for optional diagnostic')\n  st=path.lstat()\n  if stat.S_ISREG(st.st_mode):\n   total+=st.st_size\n   if any(path.name.startswith('phase1-'+name+'-transaction-')for name in labels):diagnostic+=st.st_size\n C.need(total+len(raw)<=512*1024**2 and diagnostic+len(raw)<=7*1024**2,'original guest evidence cap and smaller7MiB diagnostic aggregate')\n name='phase1-'+label+'-transaction-'+role+('.json'if role in('diagnostic','capture-error')else'.raw')\n fd=os.open(OUT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)\n try:\n  written=0\n  while written<len(raw):\n   count=os.write(fd,raw[written:]);C.need(count>0,'whole diagnostic file write');written+=count\n finally:os.close(fd)\n return dict(status='RETAINED',file=name,**C.pin(raw))"
 def parser(self,M):
  raw=C.read(A.vm_source/'runtime'/M.DONOR,256*1024);profile=C.decode(C.read(CASE/'profile.json',4*1024**2));self.assertEqual(C.pin(raw),profile['source_profiles']['ksm637']['files']['runtime/'+M.DONOR]);tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='image_directory');namespace=dict(C=C);exec(compile(ast.Module(body=[node],type_ignores=[]),'pinned-original-image-directory','exec'),namespace);return namespace['image_directory']
 def exported(self,originals,modeled_directory=False,metadata=None):
  import gzip
  M=C.load('_transaction_transport_media',CASE/'media.py');parser=self.parser(M)
  with tempfile.TemporaryDirectory(prefix='transaction-export-source-')as td:
   root=Path(td);image=root/'data.raw';image.write_bytes(b'INERT_DEBUGFS_BOUNDARY_NEVER_EXECUTED');target=root/'guest-export';calls=[]
   fixed={'baseline-nodes.json':b'{}\n','capabilities.json':b'{}\n','overlay.json':b'{}\n'}
   entries={'.':dict(mode=0o40700,uid=0,gid=0,size=None),'..':dict(mode=0o40700,uid=0,gid=0,size=None)}
   entries.update({name:dict(mode=0o100600,uid=0,gid=0,size=len(raw))for name,raw in originals.items()})
   if metadata:entries.update(metadata)
   listing=b''.join(('/%d/%06o/%d/%d/%s/%s/\n'%(index+2,row['mode'],row['uid'],row['gid'],name,''if row['size']is None else row['size'])).encode()for index,(name,row)in enumerate(entries.items()))
   def command(argv,seconds):
    self.assertEqual(argv[:2],['/usr/bin/debugfs','-R']);self.assertEqual(argv[3],image);calls.append((argv,seconds))
    if argv[2]=='ls -p /out':self.assertEqual(seconds,60);return listing
    self.assertEqual(seconds,120);verb,source,dest=argv[2].split(' ',2);self.assertEqual(verb,'dump');dest=Path(dest)
    if source.startswith('/workspace/'):
     self.assertIn(Path(source).name,fixed);self.assertEqual(dest,root/'fixed-source-map.tmp');raw=fixed[Path(source).name]
    else:self.assertEqual(source,'/out/'+Path(source).name);self.assertEqual(dest,target/Path(source).name);raw=originals[Path(source).name]
    dest.write_bytes(raw);return b''
   actor=types.SimpleNamespace(image_directory=(lambda raw:entries)if modeled_directory else parser,command=command,C=types.SimpleNamespace(row=lambda p:C.pin(C.read(p))))
   pins=None;caught=None
   try:pins=M.export_files(actor,image,target,dict(nonce='a'*32),os.getuid(),os.getgid())
   except BaseException as value:caught=value
   copied={p.name:p.read_bytes()for p in target.iterdir()}if target.exists()else{}
   expected=dict(originals,**{'media-source-nodes.json.gz':gzip.compress(fixed['baseline-nodes.json'],mtime=0),'media-source-capabilities.json':fixed['capabilities.json'],'media-overlay.json':fixed['overlay.json']})
   return dict(pins=pins,caught=caught,copied=copied,expected=expected,calls=calls,target_exists=target.exists())
 def test_frozen_raw_writer_reproduces_actual_export_refusal_before_dump(self):
  def original(G):exec(compile(self.OLD_WRITER,'frozen-initial-diagnostic-writer','exec'),G.__dict__)
  value=TransactionDiagnosticControls().exercise(mutate_guest=original);self.assertIs(value['caught'],value['error']);self.assertTrue(any(name.endswith('.raw')for name in value['files']))
  exported=self.exported(value['files']);self.assertIsInstance(exported['caught'],ValueError);self.assertIn('finite literal public guest export filenames',str(exported['caught']));self.assertFalse(exported['target_exists']);self.assertEqual(len(exported['calls']),1)
 def test_actual_export_transports_failure_and_success_diagnostic_pins(self):
  for mode in('failure','success'):
   with self.subTest(mode=mode):
    value=TransactionDiagnosticControls().exercise(mode);diagnostic=TransactionDiagnosticControls().diagnostic(value)
    exported=self.exported(value['files']);self.assertIsNone(exported['caught'],'generated diagnostic files must cross the unchanged actual export boundary');self.assertFalse(any(name.endswith('.raw')for name in value['files']));self.assertEqual(exported['copied'],exported['expected']);self.assertEqual(exported['pins'],{name:C.pin(raw)for name,raw in exported['expected'].items()})
    for row in diagnostic['artifacts'].values():
     if row['status']=='RETAINED':self.assertTrue(row['file'].endswith('.log'));self.assertEqual(exported['pins'][row['file']],{k:row[k]for k in('bytes','sha256')})
    self.assertEqual(set(value['report']),{'phase','commands'});self.assertEqual(diagnostic['status'],'TRANSACTION_PROGRESS_DATA_ONLY')
 def test_diagnostic_ceiling_reserves32_pinned_parser_slots_and_never_creates_over_budget(self):
  G=C.load('_transaction_transport_ceiling_guest',CASE/'guest.py');transform=globals().get('TRANSACTION_DIAGNOSTIC_TRANSFORM')
  if transform:transform(G)
  with tempfile.TemporaryDirectory(prefix='transaction-count-source-')as td:
   out=Path(td)
   for index in range(221):(out/('phase1-held-%03d.log'%index)).write_bytes(b'')
   with patch.object(G,'OUT',out):
    row=G._transaction_diagnostic_write('baseline-original-reinstall','expected',b'{}');self.assertTrue(row['file'].endswith('.log'));self.assertEqual(len(list(out.iterdir())),222);held={p.name:p.read_bytes()for p in out.iterdir()}
    for role in('witness','diagnostic','capture-error'):
     with self.subTest(role=role),self.assertRaisesRegex(ValueError,'finite222 guest evidence entry cap'):G._transaction_diagnostic_write('baseline-original-reinstall',role,b'{}')
    self.assertEqual({p.name:p.read_bytes()for p in out.iterdir()},held)
   for index in range(32):(out/('phase1-reserved-%03d.json'%index)).write_bytes(b'{}')
   final={p.name:p.read_bytes()for p in out.iterdir()};self.assertEqual(len(final),254);exported=self.exported(final);self.assertIsNone(exported['caught']);self.assertEqual(set(exported['pins'])-{'media-source-nodes.json.gz','media-source-capabilities.json','media-overlay.json'},set(final))
 def test_actual_parser_export_count_and_node_caps_stay_strict(self):
  ordinary={('phase1-cap-%03d.log'%index):b''for index in range(255)}
  parser_refusal=self.exported(ordinary);self.assertIsInstance(parser_refusal['caught'],ValueError);self.assertIn('bounded image entry name/size',str(parser_refusal['caught']));self.assertFalse(parser_refusal['target_exists'])
  ordinary={('phase1-cap-%03d.log'%index):b''for index in range(512)}
  accepted=self.exported(ordinary,modeled_directory=True);self.assertIsNone(accepted['caught']);self.assertEqual(len(accepted['pins']),515)
  ordinary['phase1-cap-512.log']=b'';refused=self.exported(ordinary,modeled_directory=True);self.assertIsInstance(refused['caught'],ValueError);self.assertIn('finite literal public guest export filenames',str(refused['caught']));self.assertFalse(refused['target_exists'])
  refused=self.exported({'phase1-cap.log':b''},metadata={'phase1-cap.log':dict(mode=0o100600,uid=0,gid=0,size=64*1024**2+1)});self.assertIsInstance(refused['caught'],ValueError);self.assertIn('bounded ordinary guest evidence nodes',str(refused['caught']));self.assertEqual(len(refused['calls']),1)



class CurrentRootExportControls(unittest.TestCase):
 """Focused original-byte DATA controls. No ALPM/GPG/VM/API process is started."""
 def setUp(self):
  import provision622
  import hashlib
  self.P=provision622;record=C.decode(C.read(CASE/'composition-parent.json',4*1024**2))['current_root_export'];self.record=copy.deepcopy(record['control_manifest']);self.refs=record['reference_archives'];profile=C.decode(C.read(CASE/'profile.json',4*1024**2));source='f'*40;run=1;nonce=hashlib.sha256(('current607-core622:'+source+':'+str(run)).encode()).hexdigest()[:32];selected=dict(schema=1,scope=X.SCOPE,actual=dict(source=source,ref='codex/current-root-export-data-control',run=run,attempt=1),nonce=nonce,kernel=profile['kernel'],source_profiles={n:profile['source_profiles'][n]for n in('core800','ksm637','core7_carrier')},budgets=C.BUDGET);self.proof=dict(selection=selected,source_sha=source,run_id=str(run),attempt=1,consumer_token=nonce,producer_token='a'*16)
 def inputs(self,root):
  import base64
  ready=root/'ready604';(ready/'packages').mkdir(parents=True);(ready/'keys').mkdir();record=copy.deepcopy(self.record);verification=[]
  for row in record['packages']:
   raw=('fixture detached signature '+row['name']).encode();(ready/row['signature']).write_bytes(raw);row.update(signature_size=len(raw),signature_sha256=C.pin(raw)['sha256']);status=('[GNUPG:] VALIDSIG '+row['signer']+' 2026-10-27 1790000000 0 4 0 22 8 00 '+row['signer']+'\n').encode();argv=['gpg','--batch','--no-options','--homedir','/tmp/owned-producer/private/latest607-verifier','--no-auto-key-retrieve','--auto-key-locate','clear','--status-fd=1','--verify',str(ready/row['signature']),str(ready/row['archive'])];verification.append(dict(argv=argv,returncode=0,stdout_base64=base64.b64encode(status).decode(),stderr_base64='',time_limit=30))
  for row in record['keyrings']:
   raw=('fixture public key '+row['path']).encode();(ready/row['path']).write_bytes(raw);row.update(size=len(raw),sha256=C.pin(raw)['sha256'])
  (ready/'manifest.json').write_bytes(C.encoded(record));return ready,record,verification
 def db(self,root):
  db=C.load('_current_root_export_original_db_control',A.core_source/'runtime/runtime-vm/scripts/ci/full-root-upgrade/root_upgrade.py');nodes={};folder=root/'var/lib/pacman/local';folder.mkdir(parents=True);(folder/'ALPM_DB_VERSION').write_bytes(b'9\n')
  for name,version in V['before607'].items():
   package=folder/(name+'-'+version);package.mkdir();(package/'desc').write_text('%NAME%\n'+name+'\n\n%VERSION%\n'+version+'\n\n%ARCH%\naarch64\n\n');(package/'files').write_bytes(b'')
  # Observe actual fixture bytes using the held DB parser; never relabel these
  # generated controls as original run DATA.
  for p in folder.rglob('*'):
   st=p.stat();node=dict(type='directory'if p.is_dir()else'file',mode=__import__('stat').S_IMODE(st.st_mode),uid=st.st_uid,gid=st.st_gid)
   if p.is_file():node.update(C.pin(p.read_bytes()))
   nodes[p.relative_to(root).as_posix()]=node
  rows=db.database(root,max_packages=622,max_files=100000,max_nodes=500000,observed=nodes);graph=dict(nodes=nodes);lease=dict(root=[root.stat().st_dev,root.stat().st_ino],nonce=self.proof['selection']['nonce'],phase_deadline=time.monotonic()+30);return db,rows,graph,lease
 def test_all607_input_roles_and_reference_export_partition(self):
  with tempfile.TemporaryDirectory(prefix='current607-data-',dir='/tmp')as td:
   ready,record,verification=self.inputs(Path(td));value=self.P.input_evidence(ready,record,self.proof,verification,self.refs);self.assertEqual(len(value['packages']),607);self.assertEqual(value['manifest'],C.pin((ready/'manifest.json').read_bytes()));kinds=[r['archive']['kind']for r in value['packages'].values()];self.assertEqual(kinds.count('EXACT_UPSTREAM_REFERENCE'),337);self.assertEqual(kinds.count('EXPORTED_CURRENT_UPSTREAM'),241);self.assertEqual(kinds.count('EXPORTED_CURRENT_TEST'),29);self.assertEqual(sum(r['archive']['pin']['bytes']for r in value['packages'].values()if r['archive']['kind']!='EXACT_UPSTREAM_REFERENCE'),647070676)
 def test_re_pinned_bad_signature_status_or_nonce_or_reference_is_refused(self):
  import base64
  with tempfile.TemporaryDirectory(prefix='current607-semantic-',dir='/tmp')as td:
   ready,record,verification=self.inputs(Path(td))
   for kind in('signer','expired','returncode','duplicate','argv','nonce','source','reference','signature','missing'):
    vv,pp,rr=copy.deepcopy(verification),copy.deepcopy(self.proof),copy.deepcopy(self.refs)
    if kind=='signer':vv[0]['stdout_base64']=base64.b64encode(base64.b64decode(vv[0]['stdout_base64']).replace(record['packages'][0]['signer'].encode(),b'F'*40)).decode()
    elif kind=='expired':vv[0]['stdout_base64']=base64.b64encode(base64.b64decode(vv[0]['stdout_base64'])+b'[GNUPG:] KEYEXPIRED 1\n').decode()
    elif kind=='returncode':vv[0]['returncode']=1
    elif kind=='duplicate':vv[1]=copy.deepcopy(vv[0])
    elif kind=='argv':vv[0]['argv'][8]='--status-fd=2'
    elif kind=='nonce':pp['selection']['nonce']='0'*32
    elif kind=='source':pp['source_sha']='0'*40
    elif kind=='reference':rr[next(iter(rr))]['sha256']='0'*64
    elif kind=='signature':vv[0]['argv'][-2]+='.other'
    else:vv.pop()
    with self.subTest(kind=kind),self.assertRaises((ValueError,KeyError)):self.P.input_evidence(ready,record,pp,vv,rr)
 def test_actual_input_copy_failure_keeps_partial_index_and_original_failure_bytes(self):
  with tempfile.TemporaryDirectory(prefix='current607-copy-failure-',dir='/tmp')as td:
   root=Path(td);ready,record,verification=self.inputs(root);context=root/'context';context.mkdir();(context/'source-proof.json').write_bytes(C.encoded(self.proof));(context/'fresh607-manifest.json').write_bytes(C.encoded(record))
   with self.assertRaises(FileNotFoundError):self.P.retain_input_evidence(context,ready,record,dict(self.proof,export_phase_end=time.monotonic()+30),verification)
   capture=C.decode((context/'current607-inputs/capture.json').read_bytes());self.assertEqual(capture['status'],'INCOMPLETE_CURRENT607_ORIGINAL_INPUTS_DATA_ONLY');self.assertEqual(capture['error_type'],'FileNotFoundError');self.assertEqual(capture['files'],{});target=root/'public';self.P.retain_input_failure(context,target);out=C.decode((target/'export.json').read_bytes());self.assertEqual(out['status'],'FAIL_OR_INCOMPLETE');self.assertEqual((target/'current607-inputs/capture.json').read_bytes(),(context/'current607-inputs/capture.json').read_bytes())
 def test_full_raw_database_replays_original_parser_and_exact_rows(self):
  import base64
  with tempfile.TemporaryDirectory(prefix='current607-rawdb-',dir='/tmp')as td:
   root=Path(td);db,rows,graph,lease=self.db(root)
   with patch.object(self.P,'ROOT',root):value=self.P.database_evidence(dict(db=db),root,graph,rows,self.proof['selection'],lease,{})
   self.assertEqual(value['status'],'CURRENT607_ORIGINAL_ALPM_DATABASE_DATA_ONLY');self.assertEqual(len(value['records']),1215);self.assertEqual(value['parsed_database'],C.pin(C.encoded(rows)))
   for name,row in value['records'].items():self.assertEqual(base64.b64decode(row['data_base64'],validate=True),(root/name).read_bytes());self.assertEqual(row['node'],graph['nodes'][name]);self.assertEqual(row['pin'],C.pin((root/name).read_bytes()));self.assertEqual(len(row['identity']),9)
 def test_raw_database_changes_cannot_be_normalized_into_old_rows(self):
  with tempfile.TemporaryDirectory(prefix='current607-db-refusal-',dir='/tmp')as td:
   root=Path(td);db,rows,graph,lease=self.db(root);first=next(n for n in graph['nodes']if n.endswith('/desc'));(root/first).write_bytes((root/first).read_bytes()+b'%DEPENDS%\nnew-dependency\n\n');node=graph['nodes'][first];node.update(C.pin((root/first).read_bytes()));progress={}
   with patch.object(self.P,'ROOT',root),self.assertRaisesRegex(ValueError,'whole original raw607 parser replay'):self.P.database_evidence(dict(db=db),root,graph,rows,self.proof['selection'],lease,progress)
   self.assertEqual(progress['status'],'INCOMPLETE_CURRENT607_ORIGINAL_ALPM_DATABASE_DATA_ONLY');self.assertEqual(len(progress['records']),1215)
 def test_raw_database_capture_finally_retains_prefix_on_graph_mismatch(self):
  realpath=Path
  with tempfile.TemporaryDirectory(prefix='current607-db-partial-',dir='/tmp')as td:
   root=Path(td)/'root';root.mkdir();out=Path(td)/'out';out.mkdir();db,rows,graph,lease=self.db(root);name=sorted(n for n,r in graph['nodes'].items()if r['type']=='file')[1];graph['nodes'][name]['sha256']='0'*64
   with patch.object(self.P,'ROOT',root),patch.object(self.P,'Path',side_effect=lambda v:out if str(v)=='/out'else realpath(v)),self.assertRaisesRegex(ValueError,'database record differs'):self.P.retain_database_evidence(dict(db=db),root,graph,rows,self.proof['selection'],lease,os.getuid(),os.getgid())
   value=C.decode(C.inflate((out/'current607-database-raw.json.gz').read_bytes()));self.assertEqual(value['status'],'INCOMPLETE_CURRENT607_ORIGINAL_ALPM_DATABASE_DATA_ONLY');self.assertEqual(value['error_type'],'ValueError');self.assertEqual(len(value['records']),1)
 def query(self,root,absent):
  import hashlib
  producer=root/'owned-producer';base=producer/'private/desktop574';base.mkdir(parents=True);consumer=root/'consumer';consumer.mkdir();image='sha256:'+'c'*64;(base/'image-id').write_text(image);owner=dict(token='d'*32,core_image='sha256:'+'e'*64,images_preexisting=[]);(producer/'producer-owner.json').write_bytes(C.encoded(owner));report=dict(image=image,ownership=dict(token=self.proof['producer_token'],before_images=[]),owned_cleanup=dict(status='PASS',image=dict(id=image,absence_verified=True),probe=dict(absence_verified=True)));(base/'report.json').write_bytes(C.encoded(report));state=dict(commands=[]);proof=dict(self.proof,producer_path=str(producer));end=time.monotonic()+20
  def command(argv,required,seconds):
   out=b'[]\n';err=('Error: No such image: '+image+'\n').encode()if absent else b'uncertain daemon response\n';row=dict(argv=argv,exit_code=1,group_absence_verified=True,time_limit=seconds,seconds=.01,output_limit=1024**2,stdout_bytes=len(out),stdout_sha256=hashlib.sha256(out).hexdigest(),stderr_bytes=len(err),stderr_sha256=hashlib.sha256(err).hexdigest());state['commands'].append(row)
   for suffix,raw in(('stdout',out),('stderr',err)):(consumer/('command-000.'+suffix)).write_bytes(raw)
   return dict(code=1,out=out,err=err)
  wrapped=O.handoff_capture(command,state,consumer,proof,end);return producer,consumer,proof,wrapped,end
 def test_handoff_query_raw_success_and_failure_retained_before_predicate(self):
  for absent in(True,False):
   with tempfile.TemporaryDirectory(prefix='current607-query-',dir='/tmp')as td:
    # Original handoff requires immediate /tmp siblings, so the DATA fixture
    # uses the original capture and literal predicate without moving a marker.
    root=Path(td);producer,consumer,proof,wrapped,end=self.query(root,absent);image=(producer/'private/desktop574/image-id').read_text();result=wrapped(['/usr/bin/docker','image','inspect',image],False,10);value=C.decode((consumer/'handoff-query/command.json').read_bytes());self.assertEqual(value['selection'],self.proof['selection']);self.assertEqual(value['image'],image);self.assertEqual(value['command']['exit_code'],1);self.assertEqual(value['artifacts']['stderr'],C.pin(result['err']));self.assertEqual((consumer/'handoff-query/stderr').read_bytes(),result['err']);public=root/'public';public.mkdir();(public/'export.json').write_bytes(C.encoded(dict(schema=1,status='PASS_CLOSED_CORE7_AUTOMATIC_HOOKS_AND_ACTUAL_PID1_GENERIC16K',files={},bytes=0,errors=[])));O.retain_handoff_query(consumer,public,absent);export=C.decode((public/'export.json').read_bytes());self.assertEqual(export['status']=='FAIL_OR_INCOMPLETE',not absent);self.assertEqual(set(export['files']),{'handoff-query/command.json','handoff-query/stdout','handoff-query/stderr'})
 def test_new_source_inverse_restores_all66_and_all_previous_guards(self):
  import source622
  before=source622.inverse(CASE);self.assertEqual(len(before),51);self.assertEqual(len(source622.same66_before(CASE)),66);parent=C.decode(C.read(CASE/'composition-parent.json',4*1024**2))['current_root_export'];self.assertEqual(len(parent['before']),66);self.assertEqual(len(parent['reference_archives']),337);self.assertEqual(set(parent['edits']),{'provision622.py','ownership622.py','run622.py','evidence.py','test_bridge622.py'});self.assertEqual(C.BUDGET,dict(owner=14400,producer=2300,assembly=1070,media=1900,vm_shared=7200,boot=3600,transaction=90,cleanup=60));self.assertIsNone(parent['actual']);self.assertFalse(parent['normal90_acceptance']);self.assertFalse(parent['acceptance'])
 def test_exact_original_verifier_body_captures_raw_bytes_without_extra_calls(self):
  import subprocess,base64
  with tempfile.TemporaryDirectory(prefix='current607-verifier-',dir='/tmp')as td:
   producer=Path(td)/'producer';(producer/'private').mkdir(parents=True);signer=self.record['preparation']['signer_roles']['upstream_ALARM'];status=('[GNUPG:] VALIDSIG '+signer+' 2026-10-27 1790000000 0 4 0 22 8 00 '+signer+'\n').encode();seen=[];original=C.load('_current607_original_verifier_body',A.fresh607_source/'installer604/scripts/ci/full-composition-installer-vm/producer.py')
   def run(argv,**kw):seen.append((list(map(str,argv)),kw));return subprocess.CompletedProcess(argv,0,status if '--verify'in argv else b'',b'original raw stderr\n')
   verifier=X.clone(original,subprocess=types.SimpleNamespace(run=run));materialize=types.ModuleType('_current607_fixture_materialize')
   def prepare(*args,verifier_api):
    item=verifier_api.PublicVerifier(producer/'private/latest607-verifier',[])
    try:item(producer/'archive.pkg.tar.xz',producer/'archive.pkg.tar.xz.sig',signer)
    finally:item.close()
    return 'ORIGINAL_PREPARE_RETURN'
   materialize.prepare=prepare;namespace=dict(materialize=materialize,types=types,verifier=verifier);exec("def bind(self,original,producer):\n return types.SimpleNamespace(prepare=lambda:materialize.prepare(verifier_api=verifier))\n",namespace);context=types.SimpleNamespace(verification=[],verification_error=None);bound=O.verifier_capture(namespace['bind'],types.SimpleNamespace(materialize=materialize),context,object(),object(),producer);self.assertEqual(bound.prepare(),'ORIGINAL_PREPARE_RETURN');self.assertEqual(len(seen),3);self.assertEqual(len(context.verification),1);row=context.verification[0];self.assertEqual(base64.b64decode(row['stdout_base64']),status);self.assertEqual(base64.b64decode(row['stderr_base64']),b'original raw stderr\n');self.assertEqual(seen[1][1],dict(check=False,capture_output=True,text=False,timeout=30));self.assertEqual(row['argv'],seen[1][0]);self.assertIsNone(context.verification_error)
 def test_original_verifier_refusal_keeps_attempted_raw_status(self):
  import subprocess,base64
  with tempfile.TemporaryDirectory(prefix='current607-verifier-refusal-',dir='/tmp')as td:
   producer=Path(td)/'producer';(producer/'private').mkdir(parents=True);original=C.load('_current607_original_failed_verifier_body',A.fresh607_source/'installer604/scripts/ci/full-composition-installer-vm/producer.py');seen=[]
   def run(argv,**kw):seen.append(argv);return subprocess.CompletedProcess(argv,2 if '--verify'in argv else 0,b'[GNUPG:] BADSIG retained\n',b'actual original failure bytes\n')
   verifier=X.clone(original,subprocess=types.SimpleNamespace(run=run));materialize=types.ModuleType('_current607_failed_fixture_materialize')
   def prepare(*args,verifier_api):
    item=verifier_api.PublicVerifier(producer/'private/latest607-verifier',[])
    try:item(producer/'archive.pkg.tar.xz',producer/'archive.pkg.tar.xz.sig','A'*40)
    finally:item.close()
   materialize.prepare=prepare;namespace=dict(materialize=materialize,types=types,verifier=verifier);exec("def bind(self,original,producer):\n return types.SimpleNamespace(prepare=lambda:materialize.prepare(verifier_api=verifier))\n",namespace);context=types.SimpleNamespace(verification=[],verification_error=None);bound=O.verifier_capture(namespace['bind'],types.SimpleNamespace(materialize=materialize),context,object(),object(),producer)
   with self.assertRaises(subprocess.CalledProcessError):bound.prepare()
   self.assertEqual(len(seen),3);self.assertEqual(context.verification[0]['returncode'],2);self.assertEqual(base64.b64decode(context.verification[0]['stderr_base64']),b'actual original failure bytes\n');self.assertEqual(context.verification_error['error_type'],'CalledProcessError');self.assertFalse(context.verification_error['acceptance'])
 def test_real_context_handoff_failure_exports_attempted_query_before_raising(self):
  import hashlib
  with tempfile.TemporaryDirectory(prefix='current607-query-producer-',dir='/tmp')as producer_td,tempfile.TemporaryDirectory(prefix='current607-query-consumer-',dir='/tmp')as consumer_td:
   producer,consumer=Path(producer_td),Path(consumer_td);base=producer/'private/desktop574';base.mkdir(parents=True);image='sha256:'+'c'*64;(base/'image-id').write_text(image);owner=dict(token='d'*32,core_image='sha256:'+'e'*64,images_preexisting=[]);(producer/'producer-owner.json').write_bytes(C.encoded(owner));base_report=dict(image=image,ownership=dict(token=self.proof['producer_token'],before_images=[]),owned_cleanup=dict(status='PASS',image=dict(id=image,absence_verified=True),probe=dict(absence_verified=True)));(base/'report.json').write_bytes(C.encoded(base_report));(consumer/'owner.json').write_bytes(C.encoded(dict(commands=[])));receipt=consumer/'cleanup.json';receipt.write_bytes(C.encoded(dict(status='PASS_ALL_VM_THEN_ORIGINAL800_CONSUMER_PRODUCER_RETIREMENT',original_cleanup=0)));public=producer/'core622-public';public.mkdir();(public/'export.json').write_bytes(C.encoded(dict(schema=1,status='PASS_CLOSED_CORE7_AUTOMATIC_HOOKS_AND_ACTUAL_PID1_GENERIC16K',files={},bytes=0,errors=[])))
   def command_api(workspace,output,report):
    def command(argv,required,seconds):
     out=b'[]\n';err=b'unknown daemon response\n';row=dict(argv=argv,exit_code=1,group_absence_verified=True,time_limit=seconds,seconds=.01,output_limit=1024**2,stdout_bytes=len(out),stdout_sha256=hashlib.sha256(out).hexdigest(),stderr_bytes=len(err),stderr_sha256=hashlib.sha256(err).hexdigest());number=len(report['commands']);report['commands'].append(row)
     for suffix,raw in(('stdout',out),('stderr',err)):(output/('command-%03d.%s'%(number,suffix))).write_bytes(raw)
     return dict(code=1,out=out,err=err)
    return command
   context=R.Context(Path('/unexecuted'),A.fresh607_source,self.proof,time.monotonic()+30);context.producer=producer;context.current=types.SimpleNamespace(output=consumer,core_source=A.core_source,workspace=Path('/unexecuted'),receipt=receipt);context.cleanup_end=time.monotonic()+20;context.retired=lambda p:True;context.proof_with_producer=lambda:self.proof
   with patch.object(R.adapter,'core',return_value=object()),patch.object(C,'load',return_value=types.SimpleNamespace(command_api=command_api)),self.assertRaisesRegex(ValueError,'unambiguous independently observed'):context.handoff(producer,consumer)
   self.assertTrue((base/'image-id').exists());self.assertFalse((consumer/'image-retirement').exists());self.assertEqual((public/'handoff-query/stderr').read_bytes(),b'unknown daemon response\n');export=C.decode((public/'export.json').read_bytes());self.assertEqual(export['status'],'FAIL_OR_INCOMPLETE');self.assertTrue(export['errors']);self.assertEqual(set(export['files']),{'handoff-query/command.json','handoff-query/stdout','handoff-query/stderr'})
 def early_host(self,root,producer,output):
  import hashlib
  ready,record,verification=self.inputs(root);base=producer/'private/desktop574';base.mkdir(parents=True);image='sha256:'+'c'*64;base_report=dict(image=image,ownership=dict(token=self.proof['producer_token'],before_images=[]));(base/'report.json').write_bytes(C.encoded(base_report));(base/'image-id').write_text(image);(producer/'public').mkdir();(producer/'public/producer.json').write_bytes(C.encoded(dict(fixture='ORIGINAL_PUBLIC_DATA_ONLY')));(producer/'producer-owner.json').write_bytes(C.encoded(dict(token='d'*32,core_image='sha256:'+'e'*64,images_preexisting=[])));record.update(status='READY_SIGNED_EXPANDED607');record['preparation'].update(base_receipt=base_report,package_signatures='verified-each-exact-signer');(ready/'manifest.json').write_bytes(C.encoded(record));context=R.Context(root/'workspace',A.fresh607_source,self.proof,time.monotonic()+30);context.producer=producer;context.tooling_seed=dict(status='EXACT35_TOOLING_INPUT_CACHE_PREPARED_NOT_AUTHENTICATION');context.verification=verification;args=types.SimpleNamespace(output=output,ready=ready);return context,args
 def cleanup_fixture(self):
  import subprocess
  original=types.ModuleType('_current607_exact_cleanup_context_fixture');original.subprocess=subprocess;exec("def cleanup(producer):\n return dict(status='PASS',fixture_original_producer_cleanup=True)\n",vars(original));return original
 def test_actual_early_host_input_failure_retires_context_without_core_actor(self):
  with tempfile.TemporaryDirectory(prefix='current607-precore-',dir='/tmp')as td,tempfile.TemporaryDirectory(prefix='current607-precore-producer-',dir='/tmp')as producer_td:
   root,producer=Path(td),Path(producer_td);output=Path(tempfile.mkdtemp(prefix='current607-never-core-',dir='/tmp'));output.rmdir();context,args=self.early_host(root,producer,output);parent=output.with_name(output.name+'-context');real_core=R.adapter.core
   try:
    with self.assertRaises(FileNotFoundError)as first:context._host(args)
    self.assertIsNone(context.current);self.assertFalse(output.exists());self.assertTrue(parent.is_dir());claim=copy.deepcopy(context.context_lease);self.assertEqual(claim['Core_actor'],'NOT_STARTED');self.assertEqual(C.decode((parent/'context-owner.json').read_bytes()),claim);result=dict(status='FAIL',error_type=type(first.exception).__name__,error=str(first.exception));context.desktop_failure(result)
    with patch.object(R.adapter,'core',side_effect=lambda _:real_core(A.core_source)):cleanup=context.cleanup(self.cleanup_fixture(),producer,output)
    self.assertEqual(cleanup['status'],'PASS');self.assertTrue(cleanup['fixture_original_producer_cleanup']);self.assertFalse(parent.exists());self.assertFalse(output.exists());self.assertIsNone(context.current);self.assertIsNone(context.context_lease);serialized=C.decode(C.encoded(result));data=serialized['current607_input_context_failure_data'];self.assertEqual(data['primary_error_type'],'FileNotFoundError');self.assertEqual(data['retirement'],'PASS_OWNED_PRE_CORE_CONTEXT_REMOVED_AFTER_ORIGINAL_PRODUCER_CLEANUP');self.assertEqual(data['context'],claim);self.assertFalse(data['acceptance']);public=producer/'core622-public';export=C.decode((public/'export.json').read_bytes());self.assertEqual(export['status'],'FAIL_OR_INCOMPLETE');self.assertEqual(export['current607_input_context_failure_data'],data);self.assertIn('current607-inputs/context-owner.json',export['files'])
   finally:
    if parent.exists():__import__('shutil').rmtree(parent)
 def test_copy_failure_preserves_primary_and_serializes_identified_context(self):
  with tempfile.TemporaryDirectory(prefix='current607-copy-secondary-',dir='/tmp')as td,tempfile.TemporaryDirectory(prefix='current607-copy-secondary-producer-',dir='/tmp')as producer_td:
   root,producer=Path(td),Path(producer_td);output=Path(tempfile.mkdtemp(prefix='current607-never-core-secondary-',dir='/tmp'));output.rmdir();context,args=self.early_host(root,producer,output);parent=output.with_name(output.name+'-context');real_read=C.read
   def read(path,*a,**kw):
    if Path(path)==parent/'source-proof.json':raise PermissionError('fixed inert retained-copy refusal')
    return real_read(path,*a,**kw)
   try:
    with patch.object(C,'read',side_effect=read),self.assertRaises(FileNotFoundError)as first:context._host(args)
    self.assertEqual(context.context_failure['primary_error_type'],'FileNotFoundError');self.assertEqual(context.context_failure['retention_error_type'],'PermissionError');self.assertIsNone(context.current);self.assertTrue(parent.is_dir());self.assertFalse(output.exists());result=dict(status='FAIL',error_type=type(first.exception).__name__,error=str(first.exception));context.desktop_failure(result);plain=C.decode(C.encoded(result));state=plain['current607_input_context_failure_data'];self.assertEqual(state['context']['path'],str(parent));self.assertEqual(state['context']['Core_actor'],'NOT_STARTED');self.assertEqual(state['primary_error_type'],'FileNotFoundError');self.assertEqual(state['retention_error_type'],'PermissionError');self.assertEqual(C.decode((parent/'context-owner.json').read_bytes()),context.context_lease);export=C.decode((producer/'core622-public/export.json').read_bytes());self.assertEqual(export['status'],'FAIL_OR_INCOMPLETE');self.assertEqual(export['current607_input_context_failure_data'],state);self.assertTrue(export['errors'])
    with patch.object(C,'read',side_effect=read),patch.object(R.adapter,'core',side_effect=AssertionError('must preserve identified context before destruction on copy refusal')):cleanup=context.cleanup(self.cleanup_fixture(),producer,output)
    self.assertEqual(cleanup['status'],'FAIL_PRE_CORE_CONTEXT_PRESERVED_IDENTIFIED');self.assertTrue(parent.is_dir());self.assertIsNotNone(context.context_lease);after=C.decode(C.encoded(result))['current607_input_context_failure_data'];self.assertEqual(after['primary_error_type'],'FileNotFoundError');self.assertEqual(after['retention_error_type'],'PermissionError');self.assertEqual(after['retirement'],'FAIL_PRESERVED_IDENTIFIED_PRE_CORE_CONTEXT');self.assertEqual(after['retirement_error_type'],'PermissionError');self.assertEqual(C.decode((producer/'core622-public/export.json').read_bytes())['current607_input_context_failure_data'],after);self.assertFalse(after['acceptance'])
   finally:
    if parent.exists():__import__('shutil').rmtree(parent)

if __name__=='__main__':unittest.main(verbosity=2)
