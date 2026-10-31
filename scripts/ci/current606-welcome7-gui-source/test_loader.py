"""Exact549 emission and actual source edit in whole user(); native facts mocked."""
import argparse,ast,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;parser=argparse.ArgumentParser();parser.add_argument('--predecessor-root',type=Path,required=True);parser.add_argument('--expected-root',type=Path,required=True);args,rest=parser.parse_known_args();P,E=args.predecessor_root.absolute(),args.expected_root.absolute()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
F=load('_loader_factory',HERE/'prepare.py')
class OwnedPath(type(Path())):
 def stat(self,*a,**kw):
  s=super().stat(*a,**kw);return types.SimpleNamespace(st_uid=23001,st_gid=23001,st_mode=s.st_mode)
 lstat=stat
class Controls(unittest.TestCase):
 def test_exact549_and_full_original548_admission(self):
  with tempfile.TemporaryDirectory()as temp:
   out=Path(temp)/'source';v=F.prepare_loader(P,out);self.assertEqual(F.files(out),F.files(E));self.assertEqual(v['files'],549);self.assertIsNone(v['actual_run']);self.assertEqual(v['acceptance'],'NOT_GRANTED');proof=load('_whole_549_admission',out/'admission.py').prove(out);self.assertEqual(proof['files'],549);self.assertEqual(proof['original348'],348);self.assertEqual(proof['native_GUI'],'NOT_RUN')
  profile=F.loader_profile();self.assertEqual(set(profile['changed']),{'factory/factory.py','admission.py','source-manifest.json'});self.assertEqual(len(profile['predecessor']['files']),548);self.assertEqual(len(profile['output']['files']),549)
 def emitted_user(self,root):
  # Real original guest transform, then execute exactly the source-owned GUI
  # factory edit AST. Asset/package staging is outside this source-only control.
  native=root/'original';managed=load('_held_managed_guest_prepare',native/'scripts/ci/desktop-user-session/prepare.py');raw=managed.transform_guest((native/'scripts/ci/desktop574_guest.py').read_text());text=(root/'factory/factory.py').read_text();tree=ast.parse(text);fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='transform');calls=[n for n in fn.body if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Name)and n.value.func.id=='edit'and isinstance(n.value.args[0],ast.Constant)and n.value.args[0].value=='base_guest.py'and any(isinstance(a,ast.Constant)and a.value=="    emit('gbm_pass', probe=probe)"for a in ast.walk(n))];self.assertEqual(len(calls),1);module=load('_held_actual_guest_factory',root/'factory/factory.py')
  def edit(name,fn):
   nonlocal raw
   self.assertEqual(name,'base_guest.py');raw=fn(raw);ast.parse(raw)
  exec(compile(ast.Module(body=calls,type_ignores=[]),'<exact-source-owned-guest-edit>','exec'),dict(edit=edit,once=module.once));return next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='user')
 def run_user(self,node,work,fail=False):
  home=OwnedPath(work/'home');home.mkdir(mode=0o700);runtime=OwnedPath(work/'runtime');runtime.mkdir(mode=0o700);share=work/'share';share.mkdir();(share/'current_products.py').write_text("raise RuntimeError('owned product import refusal')\n"if fail else"def run(share,home,env):\n return {'source_owned_loader_control':True,'share':str(share),'home':str(home),'bus':env['DBUS_SESSION_BUS_ADDRESS']}\n");event=OwnedPath(work/'event');event.touch(mode=0o600);card=OwnedPath(work/'card');card.touch(mode=0o600);events=[];phases=[]
  def need(ok,why):
   if not ok:raise ValueError(why)
  def command(argv,env,logs,name,timeout):self.assertEqual(name,'gbm');self.assertEqual(timeout,30);return '{"status":"PASS"}'
  ns=dict(guard=lambda root:self.assertIs(root,False),event_port=lambda:event,HOME=home,RUNTIME=runtime,ENV={},SEAT='/owned-seat',os=os,json=json,need=need,managed_session=types.SimpleNamespace(validate_user=lambda *a:None),managed_base=None,drm_card=lambda:card,command=command,emit=lambda event,**data:events.append(dict(event=event,**data)),SHARE=share,render_access=lambda card:None,phase=lambda stage,*a:phases.append(stage),Path=Path);exec(compile(ast.Module(body=[node],type_ignores=[]),'<whole-source-emitted-user>','exec'),ns)
  with patch.dict(os.environ,{'DBUS_SESSION_BUS_ADDRESS':'unix:path=/owned-bus'}):ns['user']()
  self.assertEqual([e['event']for e in events],['gbm_pass','current606_products','session_pass']);self.assertTrue(events[1]['receipt']['source_owned_loader_control']);self.assertEqual(events[1]['receipt']['share'],str(share));self.assertEqual(events[1]['receipt']['home'],str(home));self.assertEqual(events[1]['receipt']['bus'],'unix:path=/owned-bus');self.assertEqual(phases,['minimal','overlay'])
 def test_old_actual_user_namespace_refuses_new_real_python_loader_reaches_plugin(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);work=root/'old';work.mkdir()
   with self.assertRaisesRegex(NameError,"name 'load' is not defined"):self.run_user(self.emitted_user(P),work)
   for n in('minimal','overlay'):
    work=root/n;work.mkdir();self.run_user(self.emitted_user(E),work)
   work=root/'import-refusal';work.mkdir()
   with self.assertRaisesRegex(RuntimeError,'owned product import refusal'):self.run_user(self.emitted_user(E),work,True)
 def test_real_isolated_cli_and_conflicting_modes(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);out=root/'source';argv=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--loader','--predecessor-root',str(P),'--output',str(out)];r=subprocess.run(argv,capture_output=True,timeout=30,cwd='/tmp');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['files'],549);self.assertEqual(F.files(out),F.files(E))
   for mode in('--welcome8','--transport','--buildkit'):
    bad=root/mode[2:];r=subprocess.run(argv[:-1]+[str(bad),mode],capture_output=True,timeout=30);self.assertEqual(r.returncode,2);self.assertFalse(bad.exists())
 def test_source_and_readable_template_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);source=root/'wrong';source.mkdir();out=root/'out'
   with self.assertRaisesRegex(ValueError,'whole genuine548'):F.prepare_loader(source,out)
   self.assertFalse(out.exists());factory=root/'factory';shutil.copytree(HERE,factory);template=factory/'templates/loader/factory/factory.py';template.write_bytes(template.read_bytes()+b'\n# drift\n');r=subprocess.run([sys.executable,'-I','-B',str(factory/'prepare.py'),'--loader','--predecessor-root',str(P),'--output',str(out)],capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertIn(b'whole readable loader template',r.stderr);self.assertFalse(out.exists())
 def test_all_four_historical_emitter_function_bodies_are_byte_held(self):
  text=(HERE/'prepare.py').read_text();functions={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for name,want in {'prepare':'692658e23db894163ad617417b1dd288c90f896e792ead457e9b3213e70d2ce6','prepare_welcome8':'ad97ab861c65b05c3d53490cd171ffa1e62b75c32de8ece2c32f8c9f385b7174','prepare_transport':'930d03db1c1ace488387a77ed3d85f8dbb93b73155abbeb7e36b9bc076c60e35'}.items():self.assertEqual(F.pin(functions[name].encode())['sha256'],want)
  self.assertEqual(F.buildkit_profile()['output']['source'],'865cc33c8f114c15cef75b3472fbb8d1f4e8da06')
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
