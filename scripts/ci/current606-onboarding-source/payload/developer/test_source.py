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
if __name__=='__main__':unittest.main(verbosity=2)
