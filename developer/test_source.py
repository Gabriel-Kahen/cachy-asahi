#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small source/adapter controls; no installed commands, compiler or native actors."""
import ast,copy,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import guard as G
# Import our integration before it installs the whole parent namespace.
import integration as I
sys.path.insert(0,str(HERE))
import fixture as F,receipt as R

def synthetic_work(root):
 """Explicit synthetic format fixture only: not real PTY/editor/compiler output."""
 evidence=root/'evidence';evidence.mkdir();source=(HERE/'held/hello.c').read_bytes();edited=source+b'// Disposable software onboarding edit\n';binary=bytearray(64);binary[:6]=b'\x7fELF\x02\x01';binary[18:20]=(183).to_bytes(2,'little');binary=bytes(binary)
 for name,raw in{'evidence/edited-hello.c':edited,'fresh/workspace/examples/development/hello.c':edited,'evidence/hello':binary,'fresh/workspace/build/onboarding/hello':binary}.items():p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
 outputs=dict(terminal=b'CACHY_ASAHI_TERMINAL_OK\n',**{'fish-startup':b'sentinel-onboarding CACHY_ASAHI_FISH_OK\n','zsh-startup':b'CACHY_ASAHI_ZSH_OK\n','fish-after-remove':b'CACHY_ASAHI_FISH_REMOVED\n','zsh-after-remove':b'CACHY_ASAHI_ZSH_REMOVED\n','hello':b'Hello from cachy-asahi\n'});commands=[]
 for i,step in enumerate(R.STEPS):
  stem='journey-%02d-%s'%(i,step);row=dict(step=step,success=True,error=None,returncode=0,terminal='PTY, scripted command'if step in('terminal','fish-startup','zsh-startup','fish-after-remove','zsh-after-remove')else'captured process',stdout_file=stem+'.stdout',stderr_file=stem+'.stderr',expected_output=outputs[step].decode().strip()if step in('terminal','zsh-startup','fish-after-remove','zsh-after-remove')else'CACHY_ASAHI_FISH_OK'if step=='fish-startup'else None)
  if step=='zsh-after-remove':row['prompt_response']=dict(prompt='--- Type one of the keys in parentheses ---',response='0\n',observed_and_sent=False)
  commands.append(row);(evidence/(stem+'.stdout')).write_bytes(outputs.get(step,b''));(evidence/(stem+'.stderr')).write_bytes(b'')
 (evidence/'journey-commands.json').write_bytes(F.enc(commands));configs={'.config/fish/config.fish':b'# original private Fish configuration\n# >>> cachy-asahi setup fish v1 >>>\n# user-owned edited block, never overwritten\n','.zshrc':b'# original private Zsh configuration\n# >>> cachy-asahi setup zsh v1 >>>\n# user-owned edited block, never overwritten\n','user-owned.conf':b'original unrelated user configuration\n'};before={}
 for name,raw in configs.items():p=root/'existing'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);before[name]=dict(identity=F.key(p.lstat()),sha256=hashlib.sha256(raw).hexdigest())
 rows=[]
 for step,rc in zip(R.CONFLICTS,(2,2,0)):
  raw=F.enc(dict(operation='remove'if step=='remove-preserve-existing'else'activate',mode='preview'if step=='preview-existing'else'applied'));(evidence/(step+'.stdout')).write_bytes(raw);(evidence/(step+'.stderr')).write_bytes(b'');rows.append(dict(step=step,returncode=rc,stdout_sha256=hashlib.sha256(raw).hexdigest(),stderr_sha256=hashlib.sha256(b'').hexdigest()))
 value=dict(journey=dict(steps=13,terminal_scope='software PTY and interactive shell startup, not graphical terminal integration',editor_scope='scripted noninteractive Vim, not GUI/editor usability',original_source_sha256=hashlib.sha256(source).hexdigest(),edited_source_sha256=hashlib.sha256(edited).hexdigest(),binary_sha256=hashlib.sha256(binary).hexdigest()),existing=dict(commands=rows,original_files=sorted(configs),config_identity_preserved=True,before=before,after=copy.deepcopy(before)),commands=commands,security=dict(CapEff=0,CapPrm=0,CapInh=0,CapAmb=0,CapBnd=0xdb,NoNewPrivs=1),uid=1000,gid=1000,nonce='a'*32);(evidence/'ordinary-result.json').write_bytes(F.enc(value));return value

class Controls(unittest.TestCase):
 def test_whole_published676_and_source_only_isolated_entry(self):
  fact=G.verify();self.assertEqual(fact['parent_files'],676);self.assertEqual((fact['graphs'],fact['transactions'],fact['real_suites']),(29,14,4));self.assertIsNone(fact['actual']);self.assertEqual(fact['bounds']['component'],7200)
  for name in('run.py','prepare.py','ordinary_entry.py'):
   row=subprocess.run([sys.executable,'-I','-B',str(HERE/name),'--help'],capture_output=True,timeout=10);self.assertEqual(row.returncode,0,row.stderr)
  row=subprocess.run([sys.executable,'-I','-B',str(HERE/'run.py'),'--source-preflight'],capture_output=True,timeout=30);self.assertEqual(row.returncode,0,row.stderr);self.assertIsNone(json.loads(row.stdout)['actual'])
 def test_actual_runner_full_original_owner_inverse_and_clocks(self):
  anchor=G.anchor();P,A,X,C=anchor.source_context(G.ROOT);old=A.owner(P.ROOT);derived=I.owner_program(old)
  for a,b in reversed(I.I.OWNER_EDITS):self.assertEqual(derived.count(b),1);derived=derived.replace(b,a,1)
  self.assertEqual(derived,old);self.assertEqual(I.I.P.BOUNDS,dict(component=7200,consumer=9000,owner=13800,transaction=90,real_fixture=240,apps_fixture=150,case=30,cleanup=60,job_minutes=300))
  with tempfile.TemporaryDirectory()as temp:
   runner,_=X.emit_runner(P.ROOT,Path(temp)/'runner');ledger=I.stage_runner(G,P,runner);self.assertEqual(ledger['onboarding_bound'],420);self.assertEqual(ledger['expected_graphs'],29);self.assertEqual(G.files(runner/'setup240'),G.files(G.ROOT/'setup240'));new=(runner/'real606/component.py').read_text();original=(G.ROOT/'coexist/component.py').read_bytes();self.assertEqual(new,I.component_program(original));self.assertIn("if phase=='install-setup6':",new);self.assertIn("for parent,before in onboarding_retained.items()",new);self.assertEqual((runner/'developer/held/onboarding.py').read_bytes(),(HERE/'held/onboarding.py').read_bytes())
 def test_whole_reviewed_journey_thirteen_steps_and_actual_program_bodies(self):
  raw=(HERE/'held/onboarding.py').read_bytes();mf=json.loads((HERE/'mechanism-profile.json').read_bytes());self.assertEqual(G.pin(raw),mf['held']['held/onboarding.py']);tree=ast.parse(raw);journey=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='journey');steps=[n.args[0].value for n in sorted(ast.walk(journey),key=lambda n:getattr(n,'lineno',0))if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name)and n.func.value.id=='log'and n.func.attr=='run'];self.assertEqual(steps,list(R.STEPS));self.assertIn('pty.openpty()',raw.decode());self.assertIn('os.killpg(process.pid, signal.SIGKILL)',raw.decode());self.assertIn('"-Wall", "-Wextra", "-Werror", "-O2"',raw.decode());self.assertIn('call append(line',raw.decode())
 def test_stale_atime_refresh_is_ignored_identity_and_content_drift_are_refused(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);path=root/'actual';path.write_bytes(b'ordinary');st=path.stat();os.utime(path,ns=(1,st.st_mtime_ns));before=F.registry(root);self.assertEqual(F.registry(root),before);raw=F.archive(root,before);self.assertTrue(raw);path.write_bytes(b'changed')
   with self.assertRaises(ValueError):F.archive(root,before)
   path.unlink();path.symlink_to('/etc/passwd')
   with self.assertRaises(ValueError):F.registry(root)
 def test_whole_fixture_body_inert_child_and_complete_archive_replay_refusals(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);out=root/'out';out.mkdir();work=root/'owned';realPath=Path;account=types.SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid());seen=[]
   def paths(value):return work if str(value)=='/tmp/onboarding-full606'else realPath(value)
   def child(argv,**kw):
    self.assertEqual(argv[:4],['/usr/bin/python3','-I','-B','/runner/developer/ordinary_entry.py']);self.assertEqual(kw['timeout'],420);self.assertEqual(kw['output_limit'],128*1024);self.assertEqual(kw['signal_uid'],os.getuid());value=synthetic_work(work);return dict(returncode=0,termination=None,direct_child_reaped=True,group_retired=True,stdout=F.enc(value),stderr=b'')
   with patch.object(F,'Path',side_effect=paths),patch.dict(os.environ,{'CACHY_ASAHI_EXPANDED604':'b'*32}),patch.object(F.os,'chown'):
    result,parent,records=F.run(dict(C=None,OUT=out),dict(home='/tmp/expanded604-example/trust'),types.SimpleNamespace(run=child),account,'a'*32,float('inf'),lambda uid:seen.append(uid))
   self.assertEqual(seen,[os.getuid(),os.getuid()]);R.validate(result,'a'*32);raw=(out/'onboarding-evidence.zip').read_bytes();self.assertEqual(R.replay(raw,result,(HERE/'held/hello.c').read_bytes())['actual_acceptance'],'NOT_GRANTED');self.assertEqual(F.registry(parent),records)
   for change in(lambda r:r.update(package_count=605),lambda r:r['commands'].pop(),lambda r:r['security'].update(CapEff=1),lambda r:r.update(group_retired=False),lambda r:r.update(hardware='PASS'),lambda r:r['existing'].update(config_identity_preserved=False)):
    bad=copy.deepcopy(result);change(bad)
    with self.assertRaises(ValueError):R.validate(bad,'a'*32)
   with self.assertRaises(ValueError):R.replay(raw+b'drift',result,(HERE/'held/hello.c').read_bytes())
 def test_whole_exact_setup6_existing_conflict_plan_private_files_no_actor(self):
  helper=G.module('_whole_setup6_conflict_fixture_body',G.ROOT/'setup240/setup6-source/scripts/setup/setup.py')
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);home=root/'home';home.mkdir(mode=0o700);templates=root/'templates';templates.mkdir(mode=0o700)
   for shell,leaf in(('fish','config.fish'),('zsh','config.zsh')):
    target=templates/shell;target.mkdir(mode=0o700);(target/leaf).write_text('# source fixture only\n')
   (home/'.config/fish').mkdir(parents=True,mode=0o700);(home/'.config/fish/config.fish').write_text('# >>> cachy-asahi setup fish v1 >>>\n# user-owned edited block\n');(home/'.zshrc').write_text('# >>> cachy-asahi setup zsh v1 >>>\n# user-owned edited block\n');names=('.config/fish/config.fish','.zshrc');before={n:(G.pin((home/n).read_bytes()),F.key((home/n).lstat()))for n in names};actor=helper.Setup(home,templates)
   try:
    for operation,apply in(('activate',False),('activate',True),('remove',True)):
     reply=actor.run(operation,('fish','zsh'),apply);self.assertEqual(reply['preserved_conflicts'],operation=='activate');self.assertEqual({n:(G.pin((home/n).read_bytes()),F.key((home/n).lstat()))for n in names},before)
   finally:actor.close()
 def test_actual_installed_config_operand_routes_with_inert_command_boundary(self):
  m=G.module('_ordinary_existing_config_source_control',HERE/'ordinary_entry.py')
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);out=root/'out';out.mkdir();calls=[]
   def child(argv,**kw):
    calls.append((argv,kw));expected=0 if argv[1]=='remove'else 2;reply=dict(operation=argv[1],mode='applied'if'--apply'in argv else'preview');return types.SimpleNamespace(returncode=expected,stdout=F.enc(reply),stderr=b'')
   with patch.object(m.subprocess,'run',side_effect=child):value=m.existing(root/'existing',out)
   self.assertTrue(value['config_identity_preserved']);self.assertEqual(len(calls),3)
   for argv,kw in calls:self.assertEqual(argv[0],'/usr/bin/cachy-asahi-setup');self.assertEqual(kw['timeout'],20);self.assertEqual(kw['env']['HOME'],str(root/'existing'))
 def test_actual_emitted_checkout_entire_prepare_loads_coexist_asset_before_producer(self):
  class ReachedHeldPlan(Exception):pass
  # Exercise actual Integration.prepare(), including genuine plan mkdir/nonce
  # projection and actual Apps plan import. Only producer/actor APIs are inert.
  with tempfile.TemporaryDirectory(prefix='onboarding-checkout-control-')as temp:
   checkout=Path(temp)/'expanded604-code';emitted=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--output',str(checkout)],capture_output=True,timeout=30);self.assertEqual(emitted.returncode,0,emitted.stderr);self.assertEqual(len(G.files(checkout)),698)
   code='''import contextlib,json,sys,types
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'developer'))
import guard as G,integration as I
class ReachedHeldPlan(Exception):pass
out=root.parent/'owned-output';out.mkdir(mode=0o700)
tools=out/'tools606';runner=out/'runner'
expected={'original-payload.json','original587-manifest.json','target604-manifest.json','initial14-payload.json','predecessor-payload.json','plan.json','expected587.lock','expected604.lock','selection.json'}
def original_prepare(*args):
 plan=out/'plan';plan.mkdir(mode=0o700)
 for name in expected:(plan/name).write_bytes(b'{}\\n');(plan/name).chmod(0o600)
 tools.mkdir();runner.mkdir();return tools,runner
def doctor(**kw):
 path=kw['output'];path.mkdir();(path/'lifecycle-plan.json').write_bytes(b'{}\\n');return path
class Legacy:
 def make(self,**kw):
  assert kw['ready604']==out/'ready604'and kw['output']==tools/'apps7'
  module=sys.modules['_whole_accepted_apps350_archive_plan']
  assert Path(module.__file__)==root/'coexist/held/apps_plan.py'
  assert callable(module.make)and callable(module.fields)
  raise ReachedHeldPlan('EXACT_HELD_APPS_PLAN_REACHED_BEFORE_PRODUCER')
C=types.SimpleNamespace(encoded=G.enc,read=lambda p:json.loads(p.read_bytes()))
worker_contract=types.SimpleNamespace(need=G.need,encoded=G.enc)
api=types.SimpleNamespace(legacy=lambda:Legacy())
@contextlib.contextmanager
def aliases(values):
 before={k:sys.modules.get(k)for k in values};sys.modules.update(values)
 try:yield
 finally:
  for k,v in before.items():
   if v is None:sys.modules.pop(k,None)
   else:sys.modules[k]=v
anchor=types.SimpleNamespace(builds=types.SimpleNamespace(doctor=doctor,apis=lambda:(worker_contract,None,api),aliases=aliases))
context=(I.P,None,types.SimpleNamespace(prepare=original_prepare),C)
# Reproduce the complete old integration path without changing old source.
old=I.I.Integration(G,anchor,context,Path('/pinned-apps'),Path('/pinned-setup'))
old.prepare_nonce(out)
try:old.prepare(root,Path('/owned-producer'),out,object(),object(),C)
except FileNotFoundError as error:
 assert str(root/'developer/held/apps_plan.py')in str(error)
else:raise AssertionError('old actual loader refusal not reproduced')
assert (out/'plan/bridge-selection.json').read_bytes()==(out/'setup6-selection.json').read_bytes()
# Fresh ordinary output, preserving original exclusive plan mkdir semantics.
out=root.parent/'corrected-output';out.mkdir(mode=0o700);tools=out/'tools606';runner=out/'runner'
new=I.Integration(G,anchor,context,Path('/pinned-apps'),Path('/pinned-setup'))
assert new.G.HERE==root/'coexist'and new.G.ROOT==root and new.G.verify is G.verify and new.G.module is G.module
new.prepare_nonce(out)
try:new.prepare(root,Path('/owned-producer'),out,object(),object(),C)
except ReachedHeldPlan:pass
else:raise AssertionError('corrected real loader boundary not reached')
assert (out/'plan/bridge-selection.json').read_bytes()==(out/'setup6-selection.json').read_bytes()
print('PASS_OLD_ACTUAL_MISSING_PATH_NEW_HELD_PLAN_IMPORT_ENTIRE_PREPARE_BOUNDARY_NO_ACTORS')
'''
   row=subprocess.run([sys.executable,'-I','-B','-c',code,str(checkout)],capture_output=True,timeout=30)
   self.assertEqual(row.returncode,0,row.stdout+row.stderr);self.assertIn(b'PASS_OLD_ACTUAL_MISSING_PATH_NEW_HELD_PLAN_IMPORT',row.stdout)


class ExportClosureControls(unittest.TestCase):
 def test_actual_inherited_export_names_keep_every_distinct_file_once(self):
  anchor=G.anchor();P,A,X,C=anchor.source_context(G.ROOT)
  with tempfile.TemporaryDirectory()as temporary:
   out=Path(temporary)
   for name,raw in{'tools606/apps7/source.json':b'whole Apps7 input\n','tools606/other.json':b'whole other input\n','container/onboarding-result.json':b'whole journey result\n'}.items():
    p=out/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
   current=I.Integration.__new__(I.Integration);current.X=X
   # Execute the full original bridge, coexistence and developer methods.
   inherited=I.I.Integration.export_names(current,out)
   self.assertEqual(inherited.count('tools606/apps7/source.json'),2)
   old=list(inherited)
   old.extend(p.relative_to(out).as_posix()for p in sorted((out/'container').iterdir())if p.is_file()and p.name.startswith('onboarding-'))
   names=current.export_names(out)
   self.assertEqual(names,list(dict.fromkeys(old)));self.assertEqual(set(names),set(old))
   self.assertEqual(names.count('tools606/apps7/source.json'),1)
   # Exercise the complete original source-derived exporter, with only the
   # independent validation hook inert; file checks/copies/counters stay real.
   text=I.owner_program(A.owner(P.ROOT));tree=ast.parse(text)
   node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='export')
   body=ast.get_source_segment(text,node)
   def save(p,value):p.write_bytes(C.encoded(value))
   env=dict(HERE=P.ROOT/'held604'/P.OLD,C=C,stat=__import__('stat'),shutil=shutil,PUBLIC_CAP=64*1024**2,CARRIERS=set(),save=save)
   for selected,consistent in((old,False),(names,True)):
    public=out/'public'
    if public.exists():shutil.rmtree(public)
    report={};env['X']=types.SimpleNamespace(prepare_export=lambda *args:None,export_names=lambda *args:selected)
    exec(compile(body,'<whole-source-owned-export>', 'exec'),env)
    env['export'](out,report,types.SimpleNamespace(),dict(retention=[]))
    self.assertEqual(report['retention']['files'],len(report['public_files']))
    self.assertEqual(report['retention']['bytes']==sum(r['bytes']for r in report['public_files'].values()),consistent)
    self.assertEqual(set(report['public_files']),{n for n in names if(out/n).is_file()})
   self.assertEqual({n:(out/'public'/n).read_bytes()for n in report['public_files']},{n:(out/n).read_bytes()for n in names if(out/n).is_file()})

import base64
# Exact selected payload descriptors from the authentic failed native plan.
# All graph/DB objects below are explicit synthetic data, never native proof.
_RAWDB_PRODUCTS = {'apps': {'new': {'payload': {'usr/bin/cachy-asahi-apps': {'gid': 0, 'link': '', 'mode': 493, 'mtime': 1791748800, 'sha256': '4e9c078c2e05cc00cb6479d5fff23b92cbcabd8d6b3ff970f6181e6467921630', 'size': 310, 'type': '0', 'uid': 0}, 'usr/lib/cachy-asahi-apps/apps.py': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': 'c12f8548d5fd3007a61fb366ca279dd061917cc5320ba81ce5e2ab0d02c7d9a6', 'size': 22601, 'type': '0', 'uid': 0}, 'usr/lib/cachy-asahi-apps/helper-pins.json': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': '33a5e11e6d12df984e07c437c68ee581527cc4c95f3327bc44cbc09e0e29948a', 'size': 493, 'type': '0', 'uid': 0}, 'usr/lib/cachy-asahi-apps/inventory.py': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': '68f9b0bc6bd5c494ebfc10bdc1e243c014d7fa8e56b1386491b75cdb9ee2e3df', 'size': 13206, 'type': '0', 'uid': 0}, 'usr/share/doc/cachy-asahi-apps/README.md': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': 'c00485326caa9a82f911549b6c2232e8109da1b6a8194a4480bdf757cfc3a518', 'size': 12583, 'type': '0', 'uid': 0}, 'usr/share/doc/cachy-asahi-apps/source-provenance.json': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': 'd2431ddf8cc545b168d01e47c9ac35bb8b88728d35b42ed77a8059d68c49c34e', 'size': 3934, 'type': '0', 'uid': 0}, 'usr/share/licenses/cachy-asahi-apps/LICENSE': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'size': 1081, 'type': '0', 'uid': 0}, 'usr/share/licenses/cachy-asahi-apps/NOTICE': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': '425c36c2e9ad688b398d8fbcb2fd8f972420a1db5e0d4b19e9d24021346d4239', 'size': 1079, 'type': '0', 'uid': 0}}, 'pkginfo': {'arch': ['any'], 'builddate': ['1791748800'], 'depend': ['python>=3.11', 'gnupg', 'libarchive', 'pacman', 'cachy-asahi-repository-runtime=0.1.0-1'], 'license': ['MIT'], 'packager': ['Unknown Packager'], 'pkgbase': ['cachy-asahi-apps'], 'pkgdesc': ['Offline signed ARM development application catalog and explicit readonly package plans'], 'pkgname': ['cachy-asahi-apps'], 'pkgver': ['0.1.0-7'], 'size': ['55287'], 'url': ['https://github.com/Gabriel-Kahen/cachy-asahi'], 'xdata': ['pkgtype=pkg']}, 'version': '0.1.0-7'}, 'original': {'payload': {'usr/bin/cachy-asahi-apps': {'gid': 0, 'link': '', 'mode': 493, 'mtime': 1791748800, 'sha256': '4e9c078c2e05cc00cb6479d5fff23b92cbcabd8d6b3ff970f6181e6467921630', 'size': 310, 'type': '0', 'uid': 0}, 'usr/lib/cachy-asahi-apps/apps.py': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': 'c12f8548d5fd3007a61fb366ca279dd061917cc5320ba81ce5e2ab0d02c7d9a6', 'size': 22601, 'type': '0', 'uid': 0}, 'usr/lib/cachy-asahi-apps/helper-pins.json': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': '33a5e11e6d12df984e07c437c68ee581527cc4c95f3327bc44cbc09e0e29948a', 'size': 493, 'type': '0', 'uid': 0}, 'usr/lib/cachy-asahi-apps/inventory.py': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': '986c8baea2921cf3f58f98c2e76a1adad9013fbe4b1f47743d12397e9e6c2516', 'size': 13160, 'type': '0', 'uid': 0}, 'usr/share/doc/cachy-asahi-apps/README.md': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': 'c4ec55dc26bd427c37df59c647bb47719c6a88d91bd7c32b8c9ccc5a08ba6d5d', 'size': 11707, 'type': '0', 'uid': 0}, 'usr/share/doc/cachy-asahi-apps/source-provenance.json': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': 'e942a7ce47dc601de8639f320401e79561d74e0923080f660125825ef860328b', 'size': 3814, 'type': '0', 'uid': 0}, 'usr/share/licenses/cachy-asahi-apps/LICENSE': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'size': 1081, 'type': '0', 'uid': 0}, 'usr/share/licenses/cachy-asahi-apps/NOTICE': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': '425c36c2e9ad688b398d8fbcb2fd8f972420a1db5e0d4b19e9d24021346d4239', 'size': 1079, 'type': '0', 'uid': 0}}, 'pkginfo': {'arch': ['any'], 'builddate': ['1791748800'], 'depend': ['python>=3.11', 'gnupg', 'libarchive', 'pacman', 'cachy-asahi-repository-runtime=0.1.0-1'], 'license': ['MIT'], 'packager': ['Unknown Packager'], 'pkgbase': ['cachy-asahi-apps'], 'pkgdesc': ['Offline signed ARM development application catalog and explicit readonly package plans'], 'pkgname': ['cachy-asahi-apps'], 'pkgver': ['0.1.0-6'], 'size': ['54245'], 'url': ['https://github.com/Gabriel-Kahen/cachy-asahi'], 'xdata': ['pkgtype=pkg']}, 'version': '0.1.0-6'}}, 'setup': {'new': {'payload': {'usr/bin/cachy-asahi-repository': {'gid': 0, 'link': '', 'mode': 493, 'mtime': 1791748800, 'sha256': '38db2d45955b569a4c74c3f31d6b6c79611126238e1bbe1e5cf819f81d0fb54f', 'size': 19778, 'type': '0', 'uid': 0}, 'usr/bin/cachy-asahi-setup': {'gid': 0, 'link': '', 'mode': 493, 'mtime': 1791748800, 'sha256': '29d68d371071487ffd9b5453c2c056105e73f6b2971c98873731193eab6534b0', 'size': 37032, 'type': '0', 'uid': 0}, 'usr/share/doc/cachy-asahi-setup/README.md': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': 'ac3033357bf2443c65ec5e257b9504086c5b412f256de00aff12d07c93292e35', 'size': 13124, 'type': '0', 'uid': 0}, 'usr/share/doc/cachy-asahi-setup/repository-enrollment.md': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': 'a14a53311e7c995b468ddcec1e4996611d7cfe9bb08eb255e0cb6bfee6dcc7e1', 'size': 7786, 'type': '0', 'uid': 0}, 'usr/share/licenses/cachy-asahi-setup/LICENSE': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'size': 1081, 'type': '0', 'uid': 0}, 'usr/share/licenses/cachy-asahi-setup/NOTICE': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': 'a885656c42b81e413549976eb56fa1aad59018af1cad8954f00f45cbd1c2d018', 'size': 970, 'type': '0', 'uid': 0}}, 'pkginfo': {'arch': ['any'], 'builddate': ['1791748800'], 'depend': ['python>=3.11', 'gnupg', 'pacman'], 'license': ['MIT'], 'optdepend': ['cachy-asahi-hyprland-settings: optional desktop template', 'cachy-asahi-fish-config: optional Fish template', 'cachy-asahi-zsh-config: optional Zsh template', 'cachy-asahi-fish-bang-bang: explicit optional Fish history expansion', 'cachy-asahi-fish-autopair: explicit optional Fish pairing', 'cachy-asahi-fish-done: explicit optional Fish completion notifications', 'cachy-asahi-zsh-autosuggestions: explicit optional Zsh history suggestions', 'cachy-asahi-zsh-syntax-highlighting: explicit optional Zsh highlighting', 'cachy-asahi-zsh-history-substring-search: explicit optional Zsh substring search'], 'packager': ['Unknown Packager'], 'pkgbase': ['cachy-asahi-setup'], 'pkgdesc': ['Explicit cachy-asahi user setup and repository enrollment'], 'pkgname': ['cachy-asahi-setup'], 'pkgver': ['0.1.0-6'], 'size': ['79771'], 'url': ['https://github.com/Gabriel-Kahen/cachy-asahi'], 'xdata': ['pkgtype=pkg']}, 'version': '0.1.0-6'}, 'original': {'payload': {'usr/bin/cachy-asahi-repository': {'gid': 0, 'link': '', 'mode': 493, 'mtime': 1791748800, 'sha256': '38db2d45955b569a4c74c3f31d6b6c79611126238e1bbe1e5cf819f81d0fb54f', 'size': 19778, 'type': '0', 'uid': 0}, 'usr/bin/cachy-asahi-setup': {'gid': 0, 'link': '', 'mode': 493, 'mtime': 1791748800, 'sha256': 'ea505b6437a416c49e494e9ee0a16a9b160e95fed232ef920ad29aa510e28afd', 'size': 36348, 'type': '0', 'uid': 0}, 'usr/share/doc/cachy-asahi-setup/README.md': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': 'b5ab05066ad4b3cede6a300079f1a67a883dcc9f4b3f3a5d109280c9cba60221', 'size': 12485, 'type': '0', 'uid': 0}, 'usr/share/doc/cachy-asahi-setup/repository-enrollment.md': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': 'a14a53311e7c995b468ddcec1e4996611d7cfe9bb08eb255e0cb6bfee6dcc7e1', 'size': 7786, 'type': '0', 'uid': 0}, 'usr/share/licenses/cachy-asahi-setup/LICENSE': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'size': 1081, 'type': '0', 'uid': 0}, 'usr/share/licenses/cachy-asahi-setup/NOTICE': {'gid': 0, 'link': '', 'mode': 420, 'mtime': 1791748800, 'sha256': 'a885656c42b81e413549976eb56fa1aad59018af1cad8954f00f45cbd1c2d018', 'size': 970, 'type': '0', 'uid': 0}}, 'pkginfo': {'arch': ['any'], 'builddate': ['1791748800'], 'depend': ['python>=3.11', 'gnupg', 'pacman'], 'license': ['MIT'], 'optdepend': ['cachy-asahi-hyprland-settings: optional desktop template', 'cachy-asahi-fish-config: optional Fish template', 'cachy-asahi-zsh-config: optional Zsh template', 'cachy-asahi-fish-bang-bang: explicit optional Fish history expansion', 'cachy-asahi-fish-autopair: explicit optional Fish pairing', 'cachy-asahi-fish-done: explicit optional Fish completion notifications', 'cachy-asahi-zsh-autosuggestions: explicit optional Zsh history suggestions', 'cachy-asahi-zsh-syntax-highlighting: explicit optional Zsh highlighting', 'cachy-asahi-zsh-history-substring-search: explicit optional Zsh substring search'], 'packager': ['Unknown Packager'], 'pkgbase': ['cachy-asahi-setup'], 'pkgdesc': ['Explicit cachy-asahi user setup and repository enrollment'], 'pkgname': ['cachy-asahi-setup'], 'pkgver': ['0.1.0-5'], 'size': ['78448'], 'url': ['https://github.com/Gabriel-Kahen/cachy-asahi'], 'xdata': ['pkgtype=pkg']}, 'version': '0.1.0-5'}}}

def _rawdb_function(raw, namespace):
 import textwrap
 tree=ast.parse(raw.decode());exercise=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='exercise');node=next(n for n in exercise.body if isinstance(n,ast.FunctionDef)and n.name=='installed_one');body=textwrap.dedent(ast.get_source_segment(raw.decode(),node));scope=dict(namespace);exec(compile(body,'<whole-source-installed_one>','exec'),scope);return scope['installed_one']

def _rawdb_case(role,kind):
 import stat
 p=G.module('_rawdb_exact_plan',G.ROOT/'coexist/latest_plan.py');r=G.module('_rawdb_exact_restoration',G.ROOT/'coexist/latest_restoration.py',{'latest_plan':p});want=dict(line.split()for line in(G.ROOT/'copyworker/scripts/ci/current606-doctor2-copy/expected606.lock').read_text().splitlines());want[p.product(role)[1]]=_RAWDB_PRODUCTS[role][kind]['version'];products=copy.deepcopy(_RAWDB_PRODUCTS);ordinary={};nodes={};packages=[]
 def identity(mode):return [1,2,mode,0,0,1,0,1,1]
 for name,version in sorted(want.items()):
  selected=next((rr for rr,nn,_,_ in p.PRODUCTS if nn==name),None)
  if selected:
   chosen=products[selected]['original'if version==p.product(selected)[2]else'new'];meta=chosen['pkginfo'];files=list(chosen['payload']);depend=meta.get('depend',[]);provides=meta.get('provides',[]);conflict=meta.get('conflict',[]);arch=meta['arch'][0]
   for relative,entry in chosen['payload'].items():nodes[relative]=dict(kind='file',identity=identity(stat.S_IFREG|entry['mode']),sha256=entry['sha256'],capability=None)
   record='var/lib/pacman/local/'+name+'-'+version;nodes[record]=dict(kind='directory',identity=identity(stat.S_IFDIR|0o755),capability=None,children=['desc','files','mtree'])
   for leaf in('desc','files','mtree'):nodes[record+'/'+leaf]=dict(kind='file',identity=identity(stat.S_IFREG|0o644),capability=None)
   # The raw DB adapter is inert; all whole installed_one assertions run unchanged.
   fields=dict(NAME=[name],VERSION=[version],INSTALLDATE=['100'],UNCHANGED=['preserved']);chosen['database_fields']=fields;ordinary['/'+record+'/desc']=json.dumps(fields,sort_keys=True).encode();mtree=('synthetic owned mtree '+name).encode();ordinary['/'+record+'/mtree']=mtree;chosen['mtree']=dict(bytes=len(mtree),sha256=hashlib.sha256(mtree).hexdigest())
  else:
   files=['usr/share/owned-fixture/'+name];nodes[files[0]]=dict(kind='file',identity=identity(stat.S_IFREG|0o644),sha256='0'*64,capability=None);depend=provides=conflict=[];arch='aarch64'
  packages.append(dict(name=name,version=version,arch=arch,files=files,depend=depend,provides=provides,conflict=conflict))
 graph=dict(nodes=nodes,packages=packages);reads=[]
 def read(path):reads.append(str(path));return ordinary[str(path)]
 n=types.SimpleNamespace(ordinary=read,pin=lambda raw:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()));driver=types.SimpleNamespace(fields=json.loads);space=dict(P=p,R=r,N=n,stat=stat,Path=Path,products=products,scopes={rr:types.SimpleNamespace(SELECTED_FILES=set(),SELECTED_DIRS=set())for rr,_,_,_ in p.PRODUCTS},context=dict(driver=driver));return graph,want,space,ordinary,reads

class SelectedRawDBPackageBindingControls(unittest.TestCase):
 def test_whole_original_failure_and_new_full606_apps_setup_old_new(self):
  old=base64.b64decode(json.loads((HERE/'parent676.json').read_bytes())['changed_before']['coexist/component.py'],validate=True);new=(G.ROOT/'coexist/component.py').read_bytes()
  for role in('apps','setup'):
   for kind in('original','new'):
    with self.subTest(role=role,kind=kind):
     graph,want,space,raw,reads=_rawdb_case(role,kind);before=copy.deepcopy(graph);name=space['P'].product(role)[1];version=want[name];last=list(space['products'][role][kind]['payload'])[-1];self.assertEqual(len(graph['packages']),606)
     with self.assertRaises(KeyError)as caught:_rawdb_function(old,space)(graph,want,role)
     self.assertEqual(caught.exception.args[0],'var/lib/pacman/local/'+last+'-'+version);self.assertEqual(reads,[])
     _rawdb_function(new,space)(graph,want,role);self.assertEqual(reads,['/var/lib/pacman/local/'+name+'-'+version+'/mtree','/var/lib/pacman/local/'+name+'-'+version+'/desc']);self.assertEqual(graph,before)
 def test_full_payload_db_metadata_fields_and_hash_refusals_remain(self):
  new=(G.ROOT/'coexist/component.py').read_bytes()
  for corrupt in('payload-hash','payload-mode','DB-missing','DB-owner','mtree-hash','desc-fields','install-date'):
   with self.subTest(corrupt=corrupt):
    graph,want,space,raw,_=_rawdb_case('apps','original');product=space['products']['apps']['original'];record='/var/lib/pacman/local/cachy-asahi-apps-0.1.0-6';first=next(iter(product['payload']))
    if corrupt=='payload-hash':graph['nodes'][first]['sha256']='f'*64
    elif corrupt=='payload-mode':graph['nodes'][first]['identity'][2]^=0o100
    elif corrupt=='DB-missing':del graph['nodes'][record[1:]+'/files']
    elif corrupt=='DB-owner':graph['nodes'][record[1:]]['identity'][3]=1000
    elif corrupt=='mtree-hash':raw[record+'/mtree']+=b'drift'
    elif corrupt=='desc-fields':raw[record+'/desc']=json.dumps(dict(product['database_fields'],UNCHANGED=['drift'])).encode()
    else:raw[record+'/desc']=json.dumps(dict(product['database_fields'],INSTALLDATE=['101'])).encode()
    with self.assertRaises((ValueError,KeyError)):_rawdb_function(new,space)(graph,want,'apps')
 def test_actual_transaction_install_date_window_still_required(self):
  graph,want,space,raw,_=_rawdb_case('setup','new');name=space['P'].product('setup')[1];key='/var/lib/pacman/local/'+name+'-'+want[name]+'/desc';fields=json.loads(raw[key]);fields['INSTALLDATE']=['105'];raw[key]=json.dumps(fields).encode();fn=_rawdb_function((G.ROOT/'coexist/component.py').read_bytes(),space);fn(graph,want,'setup',dict(start_seconds=100,end_seconds=110))
  with self.assertRaisesRegex(ValueError,'actual transaction'):fn(graph,want,'setup',dict(start_seconds=106,end_seconds=110))
 def test_entire_component_inverse_changes_only_payload_variable_binding(self):
  old=base64.b64decode(json.loads((HERE/'parent676.json').read_bytes())['changed_before']['coexist/component.py'],validate=True);new=(G.ROOT/'coexist/component.py').read_bytes();a=b"  for name,expected in product['payload'].items():\n   node=graph['nodes'][name];";b=b"  for relative,expected in product['payload'].items():\n   node=graph['nodes'][relative];";self.assertEqual(old.count(a),1);self.assertEqual(new.replace(b,a,1),old)

if __name__=='__main__':unittest.main(verbosity=2)
