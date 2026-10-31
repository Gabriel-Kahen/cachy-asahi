"""Portable filesystem/proof and emitted-command controls; no Docker/native execution."""
import argparse,ast,base64,contextlib,hashlib,importlib.util,io,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;S=P=None
s=importlib.util.spec_from_file_location('_maintained_buildkit_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
B=load('scope',HERE/'templates/buildkit/factory/build_scope.py')
BASE='sha256:'+'1'*64;REF='cachy-asahi-desktop574-base:'+'2'*32
class Scope(unittest.TestCase):
 def context(self,root,role):
  c=root/role;c.mkdir();_,installer,lock,count=B.ROLES[role]
  shutil.copyfile(S/'factory'/installer,c/installer);shutil.copyfile(HERE/'templates/buildkit/factory/build_scope.py',c/'build_scope.py');p=c/lock;p.parent.mkdir(parents=True,exist_ok=True)
  p.write_text(''.join('package%d 1\n'%i for i in range(count)))
  return c
 @contextlib.contextmanager
 def native_shape(self,c,secret,role,mount=True):
  # Synthetic system facts only. All namespace/hash/inode reads remain real files.
  read_text=Path.read_text;lstat=Path.lstat
  def text(p,*a,**kw):
   if str(p)=='/proc/self/mountinfo':return '9 1 0:7 / '+str(secret)+' '+('ro'if mount else'rw')+' - tmpfs tmpfs rw\n'
   return read_text(p,*a,**kw)
  def ls(p,*a,**kw):
   s=lstat(p,*a,**kw)
   if p==secret:return types.SimpleNamespace(**{n:getattr(s,n)for n in dir(s)if n.startswith('st_')}|{'st_uid':0,'st_gid':0})
   return s
  iterdir=Path.iterdir;exists=Path.exists
  with patch.object(B,'SECRET',secret),patch.dict(B.ROLES,{role:(str(c),*B.ROLES[role][1:])}),patch.object(B.os,'geteuid',return_value=0),patch.object(B.os,'uname',return_value=types.SimpleNamespace(machine='aarch64')),patch.object(Path,'read_text',text),patch.object(Path,'exists',lambda p:False if str(p)=='/run/systemd/system'else exists(p)),patch.object(Path,'lstat',ls),patch.object(Path,'iterdir',lambda p:iter([Path('/lo')])if str(p)=='/sys/class/net'else iterdir(p)),contextlib.redirect_stdout(io.StringIO()):yield
 def test_both_real_context_proofs_and_secret_mount_shape(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for role in B.ROLES:
    c=self.context(root,role);proof=root/(role+'.json');args,meta=B.prepare(c,role,BASE,REF,proof);proof.chmod(0o400)
    self.assertEqual(args[:2],['--secret','id=caa-gui-build,src='+str(proof)]);self.assertIn('required=true,mode=0400',(c/'Dockerfile').read_text())
    with self.native_shape(c,proof,role):r=B.check(B.pin(proof.read_bytes())['sha256'],role)
    self.assertEqual(r,dict(status='PASS_SOURCE_OWNED_NATIVE_OFFLINE_BUILDKIT_BOUNDARY',**meta))
 def test_missing_readonly_mount_and_wrong_digest_refused(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);c=self.context(root,'runtime606');proof=root/'proof.json';B.prepare(c,'runtime606',BASE,REF,proof);proof.chmod(0o400);sha=B.pin(proof.read_bytes())['sha256']
   with self.native_shape(c,proof,'runtime606',False),self.assertRaisesRegex(ValueError,'boundary'):B.check(sha,'runtime606')
   with self.native_shape(c,proof,'runtime606'),self.assertRaisesRegex(ValueError,'proof bytes'):B.check('0'*64,'runtime606')
 def test_real_context_hash_extra_hardlink_symlink_refusals(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);c=self.context(root,'runtime606');proof=root/'proof.json';B.prepare(c,'runtime606',BASE,REF,proof);proof.chmod(0o400);sha=B.pin(proof.read_bytes())['sha256'];installer=c/'install606.py';old=installer.read_bytes()
   installer.write_bytes(old+b'\n')
   with self.native_shape(c,proof,'runtime606'),self.assertRaisesRegex(ValueError,'whole source-owned'):B.check(sha,'runtime606')
   installer.write_bytes(old);(c/'extra').write_bytes(b'foreign')
   with self.native_shape(c,proof,'runtime606'),self.assertRaises(ValueError):B.check(sha,'runtime606')
   (c/'extra').unlink();os.link(installer,c/'alias')
   with self.native_shape(c,proof,'runtime606'),self.assertRaises(ValueError):B.check(sha,'runtime606')
   (c/'alias').unlink();(c/'alias').symlink_to(installer)
   with self.native_shape(c,proof,'runtime606'),self.assertRaises(ValueError):B.check(sha,'runtime606')
 def test_prepare_rejects_bad_lock_and_existing_proof(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);c=self.context(root,'controller590');proof=root/'proof.json';B.prepare(c,'controller590',BASE,REF,proof)
   with self.assertRaises(ValueError):B.prepare(c,'controller590',BASE,REF,proof)
   other=self.context(root,'runtime606');(other/'bundle/expected-installed.lock').write_text('one 1\n')
   with self.assertRaisesRegex(ValueError,'inventory'):B.prepare(other,'runtime606',BASE,REF,root/'bad.json')
 def test_exact_two_emitted_build_commands_and_readonly_proofs(self):
  C=load('context_scope_control',S/'factory/context606.py')
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);runner=root/'runner';runner.mkdir();out=root/'out';out.mkdir();install=runner/'install-context606';install.mkdir();tool=runner/'qemu-context';tool.mkdir()
   shutil.copyfile(S/'factory/expected606.lock',runner/'expected606.lock');(install/'bundle').mkdir();shutil.copyfile(S/'factory/expected606.lock',install/'bundle/expected-installed.lock')
   for name in('build_scope.py','install606.py'):shutil.copyfile(S/'factory'/name,install/name)
   for name in('build_scope.py','install_tooling.py'):shutil.copyfile(S/'factory'/name,tool/name)
   base=json.loads((S/'original/scripts/ci/maintained-desktop574-inputs.json').read_bytes());versions={r['name']:r['version']for r in base['packages']}
   for row in json.loads((S/'original/scripts/virtual/tooling.lock.json').read_bytes())['packages']:versions[row['name']]=row['version']
   self.assertEqual(len(versions),590);(tool/'expected590.lock').write_text(''.join(n+' '+v+'\n'for n,v in sorted(versions.items())))
   (runner/'desktop.pkg').write_bytes(b'SYNTHETIC_ONLY_NOT_PACKAGE')
   receipt=dict(files={p.relative_to(install).as_posix():C.pin(p.read_bytes())for p in install.rglob('*')if p.is_file()},expected=C.pin((runner/'expected606.lock').read_bytes()),desktop='desktop.pkg',desktop_pin=C.pin((runner/'desktop.pkg').read_bytes()))
   (runner/'context606.json').write_bytes(C.enc(receipt));calls=[];images=[];report={}
   def execute(argv,label,seconds):
    self.assertEqual(argv[:4],['docker','build','--network=none','--pull=false']);self.assertEqual(seconds,300);calls.append((argv,label));iid=Path(argv[argv.index('--iidfile')+1]);iid.write_text('sha256:'+('3'if len(calls)==1 else'4')*64)
   got=C.build(runner,BASE,out,execute,None,lambda *args:None,images,report)
   self.assertEqual(got[0],'sha256:'+'3'*64);self.assertEqual(got[3],'sha256:'+'4'*64);self.assertEqual(len(calls),2)
   for role,ctx,index in(('runtime606',out/'context',0),('controller590',out/'qemu-context',1)):
    proof=out/(role+'-build-proof.json');raw=proof.read_bytes();argv=calls[index][0];self.assertIn('id=caa-gui-build,src='+str(proof),argv);self.assertIn('CAA_GUI_BUILD_PROOF_SHA='+B.pin(raw)['sha256'],argv)
    self.assertEqual(json.loads(raw)['files'],{p.relative_to(ctx).as_posix():B.pin(p.read_bytes())for p in ctx.rglob('*')if p.is_file()});self.assertEqual(report['image_build_proofs'][role]['proof'],B.pin(raw));self.assertEqual(json.loads(raw)['base_image'],BASE)
 def test_whole_parent_source_inverse_and_clocks(self):
  v=F.buildkit_profile();before=v['predecessor']['files'];after=v['output']['files'];self.assertEqual(len(before),546);self.assertEqual(len(after),548);self.assertEqual(len(v['changed']),8);self.assertEqual(len(v['added']),2)
  self.assertEqual(set(v['changed']),{'factory/install606.py','factory/install_tooling.py','factory/context606.py','factory/factory.py','factory/qemu_context.py','native.py','admission.py','source-manifest.json'})
  for n,r in before.items():
   if n in v['changed']:self.assertEqual(F.pin((P/n).read_bytes()),v['changed'][n]['before'])
   else:self.assertEqual((S/n).read_bytes(),(P/n).read_bytes())
  old=(P/'factory/install606.py').read_text();new=(S/'factory/install606.py').read_text();self.assertEqual(new[new.index("    code=Path('/tmp/managed604')",new.index("    code=Path('/tmp/managed604')")+1):new.index("if __name__")],old[old.index("    code=Path('/tmp/managed604')"):old.index("if __name__")])
  self.assertEqual((S/'factory/run.py').read_bytes(),(P/'factory/run.py').read_bytes());self.assertIn("'runtime-image',300",(S/'factory/context606.py').read_text());self.assertIn("'qemu-image',300",(S/'factory/context606.py').read_text())
class Factory(unittest.TestCase):
 def test_exact548_repeat_full_original_admission_and_old_function_bodies(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);out=root/'again';fact=F.prepare_buildkit(P,out);self.assertEqual(F.files(out),F.files(S));self.assertEqual(F.files(S),F.files(EXPECTED));self.assertEqual(fact['files'],548);self.assertIsNone(fact['actual_run']);self.assertEqual(fact['acceptance'],'NOT_GRANTED')
   admission=load('_exact548_whole_original_admission',out/'admission.py');proof=admission.prove(out);self.assertEqual((proof['files'],proof['original348'],proof['published_factory53']),(548,348,53))
  text=(HERE/'prepare.py').read_text();functions={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for name,wanted in {'prepare':'692658e23db894163ad617417b1dd288c90f896e792ead457e9b3213e70d2ce6','prepare_welcome8':'ad97ab861c65b05c3d53490cd171ffa1e62b75c32de8ece2c32f8c9f385b7174','prepare_transport':'930d03db1c1ace488387a77ed3d85f8dbb93b73155abbeb7e36b9bc076c60e35'}.items():self.assertEqual(F.pin(functions[name].encode())['sha256'],wanted)
 def test_real_predecessor_changed_missing_extra_refusals_before_output(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);leaf=next(iter(F.buildkit_profile()['predecessor']['files']))
   for kind in('changed','missing','extra'):
    source=root/kind;shutil.copytree(P,source);output=root/(kind+'-output')
    if kind=='changed':(source/leaf).write_bytes(b'drift')
    elif kind=='missing':(source/leaf).unlink()
    else:(source/'extra').write_bytes(b'foreign')
    with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'complete genuine546'):F.prepare_buildkit(source,output)
    self.assertFalse(output.exists())
 def test_profile_template_drift_before_output(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);original=F.ordinary;target=HERE/F.buildkit_profile()['templates']['factory/build_scope.py']['path']
   def drift(path,*a):return b'drift'if path==target else original(path,*a)
   with unittest.mock.patch.object(F,'ordinary',side_effect=drift),self.assertRaisesRegex(ValueError,'readable BuildKit template'):F.prepare_buildkit(P,root/'out')
   self.assertFalse((root/'out').exists())
   with unittest.mock.patch.object(F,'ordinary',side_effect=lambda path,*a:b'{}'if path==HERE/'buildkit.json'else original(path,*a)),self.assertRaisesRegex(ValueError,'frozen BuildKit source authority'):F.prepare_buildkit(P,root/'bad-profile')
   self.assertFalse((root/'bad-profile').exists())
 def test_real_isolated_CLI_and_mutual_exclusive_modes(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);out=root/'cli';done=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--buildkit','--predecessor-root',str(P),'--output',str(out)],capture_output=True,text=True,timeout=30);self.assertEqual(done.returncode,0,done.stderr);value=json.loads(done.stdout);self.assertEqual(value['files'],548);self.assertEqual(value['default'],'UNCHANGED540');self.assertEqual(F.files(out),F.files(EXPECTED))
   for option in('--welcome8','--transport'):
    bad=root/option[2:];done=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--buildkit',option,'--predecessor-root',str(P),'--output',str(bad)],capture_output=True,text=True,timeout=30);self.assertEqual(done.returncode,2);self.assertFalse(bad.exists())

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--predecessor-root',type=Path,required=True);parser.add_argument('--expected-root',type=Path,required=True);args,rest=parser.parse_known_args();P=args.predecessor_root.absolute();EXPECTED=args.expected_root.absolute()
 with tempfile.TemporaryDirectory()as temp:
  S=Path(temp)/'source';F.prepare_buildkit(P,S);unittest.main(argv=[__file__,*rest])

