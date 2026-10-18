# SPDX-License-Identifier: MIT
"""Finite source/real private-tree controls; no positive native606 fixture."""
import ast,base64,contextlib,copy,hashlib,io,json,os,shutil,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];sys.path.insert(0,str(HERE))
import contract as O,selection as S,owner as Y,runtime as T
LANE=ROOT/'worker/scripts/ci/current606-latest-tools-copy';sys.path[:0]=[str(LANE),str(ROOT/'worker/held-copy/scripts/update'),str(ROOT/'worker/held-copy/scripts/apps')]
C=O.load('_test_joint_contract',LANE/'contract.py');modules={'contract':C}
for name in('roles','guard','physical','lifecycle','rooted_cli','driver','worker'):
 modules[name]=O.load('_test_joint_'+name,LANE/(name+'.py'),modules)
G=modules['guard'];R=modules['worker'].roots;physical=modules['physical']
import disposable_copy,file_capabilities as caps

class Controls(unittest.TestCase):
 def budget(self):return R.Limits(deadline=time.monotonic()+10,max_nodes=100,max_bytes=1024**2,max_file_bytes=1024**2)
 def test_default_two_future_decisions_NULL_before_actor_or_output(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(subprocess,'run',side_effect=AssertionError('actor')):
   p=O.read(HERE/'input-policy.json');self.assertEqual(p['joint_decisions'],{'apps606':None,'welcome606':None})
   with self.assertRaisesRegex(ValueError,'future accepted'):Y.authorize(p)
   with self.assertRaises(ValueError):C.authority(p,'copy-worker8','a'*32)
 def test_all336_and428_historical_bytes_and_closed_source(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   fact=O.verify();self.assertEqual((fact['historical_apps'],fact['historical_welcome']),(336,428));self.assertIsNone(fact['actual_run'])
 def test_source_composed_owner_derivation_and_unchanged_9_to12_topology(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):cls,old=Y.integration_class()
  self.assertTrue(callable(cls.prepare));self.assertTrue(callable(cls.complete));self.assertIn('joint_context',cls.prepare.__code__.co_names)
  self.assertEqual(T.SECONDS,dict(finalize=600,worker=1800,dispose=120));self.assertIn('len(self.owned.rows) == 9',(HERE/'runtime.py').read_text())
  raw=(ROOT/'historical/welcome/scripts/ci/current606-welcome5-closed-owner/runtime.py').read_text();derived=raw.replace('current606-welcome5-copy','current606-latest-tools-copy').replace('CAA_CURRENT606_WELCOME5_COPY','CAA_CURRENT606_LATEST_TOOLS_COPY');self.assertEqual(derived,(HERE/'runtime.py').read_text())
 def test_whole_worker_copy_physical_supervision_and_original_selected_primitives(self):
  a=ROOT/'historical/apps/copyworker/scripts/ci/current606-apps7-copy'
  for n in('worker.py','physical.py','supervised.py'):self.assertEqual((LANE/n).read_bytes(),(a/n).read_bytes())
  for role,source,namespace in [('apps','apps','current606-apps7-copy'),('welcome','welcome','current606-welcome5-copy')]:
   old=ROOT/'historical'/source/'copyworker';new=ROOT/'worker'/('held-'+role+'-worker');self.assertEqual(O.files(old),O.files(new));self.assertEqual((new/'scripts/ci'/namespace/'alpm_step.py').read_bytes(),(old/'scripts/ci'/namespace/'alpm_step.py').read_bytes())
 def test_real_private_copy_full_nodes_hardlinks_caps_and_disposal(self):
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp);source=p/'seed';source.mkdir();(source/'data').write_bytes(b'held private file');os.link(source/'data',source/'link');(source/'alias').symlink_to('data');before=R.observe(source,limits=self.budget(),hardlinks='generic-development-internal');initial=caps.observe(source,before['nodes'],self.budget())
   with disposable_copy.copied_root(source,p/'owned',limits=self.budget())as(target,report):
    after=R.observe(target,limits=self.budget(),hardlinks='generic-development-internal');self.assertEqual(before['nodes'],after['nodes']);self.assertEqual((target/'data').stat().st_ino,(target/'link').stat().st_ino);self.assertEqual(caps.restore(target,after['nodes'],initial,self.budget()),initial)
   self.assertEqual(report['cleanup'],'PASS-owned-workspace-removed');self.assertFalse((p/'owned').exists());G.same_source(before,R.observe(source,limits=self.budget(),hardlinks='generic-development-internal'))
 def test_real_failure_disposes_only_owned_private_copy(self):
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp);source=p/'seed';source.mkdir();(source/'file').write_bytes(b'held')
   with self.assertRaises(RuntimeError):
    with disposable_copy.copied_root(source,p/'owned',limits=self.budget())as(target,report):(target/'file').write_bytes(b'changed');raise RuntimeError('inert fixture')
   self.assertEqual((source/'file').read_bytes(),b'held');self.assertFalse((p/'owned').exists());self.assertEqual(report['cleanup'],'PASS-owned-workspace-removed')
 def test_joint_inventory_uses_real606_lock_never607_or_both_absent(self):
  raw=(ROOT/'historical/apps/held606/scripts/ci/current606-native/expected606.lock').read_bytes();base=dict(line.split()for line in raw.decode().splitlines());self.assertEqual(len(base),606);self.assertEqual(base['cachy-asahi-repository-runtime'],'0.1.0-1')
  latest=dict(base,**{'cachy-asahi-apps':'0.1.0-7','cachy-asahi-welcome':'0.1.0-5'});G.inventory(latest,base,{'apps':'0.1.0-7','welcome':'0.1.0-5'})
  for n in('cachy-asahi-repository-runtime','cachy-asahi-dns','cachy-asahi-sysctl'):
   with self.assertRaises(ValueError):G.inventory(dict(latest,**{n:'foreign'}),base,{'apps':'0.1.0-7','welcome':'0.1.0-5'})
  with self.assertRaises(ValueError):G.inventory({},base,{'apps':None,'welcome':None})
 def test_union_selector_protects_other604_rawDB_users_trust_and_unknowns(self):
  node=dict(type='file',mode=0o644,uid=0,gid=0,bytes=1,sha256='0'*64);paths=set(C.APPS_FILES)|set(C.WELCOME_FILES)|set(C.APPS_DIRS)|set(C.WELCOME_DIRS)
  protected=['usr/share/cachy-asahi/repository-runtime/a','var/lib/pacman/local/cachy-asahi-repository-runtime-0.1.0-1/desc','home/alarm/.config/user','etc/pacman.d/gnupg/trustdb.gpg','unowned','var/lib/pacman/local/cachy-asahi-dns-0.1.0-2/desc']
  before=dict(complete=True,nodes={n:node for n in[*protected,*C.APPS_FILES,*C.WELCOME_FILES]},unsupported_counts={},hardlink_groups={});after=copy.deepcopy(before);after['nodes']['usr/bin/cachy-asahi-apps']=dict(node,sha256='1'*64);after['nodes']['usr/bin/cachy-asahi-welcome']=dict(node,sha256='2'*64);G.target(before,after,paths)
  for n in protected:
   wrong=copy.deepcopy(after);wrong['nodes'][n]=dict(node,sha256='f'*64)
   with self.subTest(path=n),self.assertRaises(ValueError):G.target(before,wrong,paths)
  wrong=copy.deepcopy(after);wrong['hardlink_groups']={'cross':dict(members=['usr/bin/cachy-asahi-apps','unowned'])}
  with self.assertRaises(ValueError):G.target(before,wrong,paths)
 def test_same_bytes_protected_inode_replacement_is_refused(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);(root/'held').write_bytes(b'unchanged');a=R.observe(root,limits=self.budget(),hardlinks='generic-development-internal');ia=physical.capture(root,a['nodes'],self.budget());(root/'replace').write_bytes(b'unchanged');os.replace(root/'replace',root/'held');b=R.observe(root,limits=self.budget(),hardlinks='generic-development-internal');ib=physical.capture(root,b['nodes'],self.budget());self.assertEqual(a['nodes'],b['nodes'])
   with self.assertRaises(ValueError):physical.protected(ia,ib,a['nodes'],b['nodes'],lambda _:False)
 def test_real_xattr_and_source_mutation_refuse(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);(root/'f').write_bytes(b'held');a=R.observe(root,limits=self.budget(),hardlinks='generic-development-internal');os.setxattr(root/'f','user.unrecognized',b'refuse')
   with self.assertRaises(ValueError):caps.observe(root,a['nodes'],self.budget())
   os.removexattr(root/'f','user.unrecognized');(root/'f').write_bytes(b'edit')
   with self.assertRaises(ValueError):G.same_source(a,R.observe(root,limits=self.budget(),hardlinks='generic-development-internal'))
 def test_exact_caps_mounts_and_deadlines_held(self):
  self.assertEqual((C.WORKER_MASK,C.BRIDGE_MASK),(0x800400db,0x8000001b));self.assertEqual((C.WORKER_SECONDS,C.COPY_SECONDS,C.CLEANUP_SECONDS),(1800,600,60))
  paths={n:Path('/owned/'+n)for n in('runner','seed','proof','work','out')};argv=T.argv('worker','sha256:'+'1'*64,'a'*32,paths);_,old=Y.integration_class();C.bindings(old.parse_mounts(argv));self.assertNotIn('--privileged',argv);self.assertIn('--network=none',argv)
  v=dict(CapEff=C.WORKER_MASK,CapPrm=C.WORKER_MASK,CapBnd=C.WORKER_MASK,CapInh=0,CapAmb=0,NoNewPrivs=1,uid=0,gid=0);C.capability_profile(v)
  with self.assertRaises(ValueError):C.capability_profile(dict(v,CapEff=0xdb))
 def test_finite_phase_contract_and_real_transient605_frontend_source(self):
  phases=modules['lifecycle'].PHASES;self.assertEqual(len(phases),11);versions=dict(G.BASE);counts=[]
  for _,role,v in phases:
   if role is not None:versions[role]=v
   self.assertLessEqual(sum(v is None for v in versions.values()),1);counts.append(606-sum(v is None for v in versions.values()))
  self.assertEqual(counts,[606,606,606,606,606,605,606,605,606,606,606]);self.assertEqual(versions,G.BASE)
  text=(LANE/'transient_cli.py').read_text();self.assertIn("'/usr/bin/cachy-asahi-apps','inventory'",text);self.assertIn('NOT_RUN_ORIGINAL15_REQUIRES606_DOMAIN',text);self.assertIn("'cachy-asahi-welcome'not in inventory",text)
 def test_all_programs_compile_and_no_actual_binding_claim(self):
  for p in ROOT.rglob('*.py'):compile(p.read_bytes(),str(p),'exec')
  self.assertIsNone(S.EXPECTED_JOINT);self.assertTrue(all(O.read(HERE/'input-policy.json')[k]is None for k in('actual_source','actual_ref','actual_run')))
 def test_real_Apps7_source_CLI605_private_ALPM_metadata_no_host_mutation(self):
  # Actual portable application CLI over an explicitly inert private metadata
  # corpus, not installed payload, native execution or a positive606 fixture.
  app=O.load('_joint_actual_source_apps',ROOT/'worker/held-apps-worker/held-apps/fixture-apps/apps.py');runtime=ROOT/'historical/apps/held606/held604/packages/tools/cachy-asahi-repository-runtime'
  base=dict(line.split()for line in(ROOT/'historical/apps/held606/scripts/ci/current606-native/expected606.lock').read_text().splitlines());base.pop('cachy-asahi-welcome');base['cachy-asahi-apps']='0.1.0-7';self.assertEqual(len(base),605)
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);helpers=root/'runtime'
   for src,dst in [('client.py','scripts/client/client.py'),('release.py','scripts/release/release.py'),('source_delivery.py','scripts/release/source_delivery.py')]:p=helpers/dst;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(runtime/src,p)
   db=root/'db';local=db/'local';local.mkdir(parents=True);(local/'ALPM_DB_VERSION').write_bytes(b'9\n')
   for name,version in base.items():
    directory=local/(name+'-'+version);directory.mkdir();(directory/'desc').write_text('%NAME%\n'+name+'\n\n%VERSION%\n'+version+'\n\n%ARCH%\naarch64\n\n');(directory/'files').write_bytes(b'')
   before=O.files(db);stream=io.StringIO()
   with patch.object(sys,'argv',['apps','--repository-source',str(helpers),'inventory','--dbpath',str(db),'--output',str(root/'snapshot.json')]),contextlib.redirect_stdout(stream):code=app.main()
   self.assertEqual(code,0,stream.getvalue());receipt=json.loads(stream.getvalue());self.assertEqual(receipt['applied'],'NOT_APPLIED');snapshot=json.loads((root/'snapshot.json').read_bytes());self.assertEqual({p['name']:p['version']for p in snapshot['packages']},base);self.assertEqual(O.files(db),before);self.assertFalse((db/'db.lck').exists())
 def test_prior_real606_authority_is_not_either_future_composition(self):
  prior=O.read(ROOT/'historical/apps/scripts/ci/current606-apps7-closed-owner/input-policy.json')['current606'];raw=base64.b64decode(prior['decision_base64']);d=json.loads(raw);row=dict(prior,status=d['status'],run_field='run_id'if'run_id'in d else'run')
  with patch.object(S,'EXPECTED_JOINT',{'apps606':row,'welcome606':row}),self.assertRaisesRegex(ValueError,'genuine exact single-composition'):S._joint({'joint_decisions':{'apps606':row,'welcome606':row}})
 def test_emitted_source_default_reemission_is_exact_and_actor_free(self):
  E=O.load('_joint_source_emitter',HERE/'prepare.py',{'contract':O})
  with tempfile.TemporaryDirectory()as tmp,patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(subprocess,'run',side_effect=AssertionError('actor')):
   output=Path(tmp)/'source';rows=E.emit(apps=ROOT/'historical/apps',welcome=ROOT/'historical/welcome',worker=ROOT/'worker',bridge=ROOT/'bridge',output=output)
   self.assertEqual(rows,O.files(ROOT));self.assertEqual((output/'.github/workflows/native-arm-build.yml').read_bytes(),(output/'.github/workflows/native-arm-current606-latest-tools-owned-copy.yml').read_bytes())

class Step605Controls(unittest.TestCase):
 def budget(self):return R.Limits(deadline=time.monotonic()+10,max_nodes=200,max_bytes=1024**2,max_file_bytes=1024**2)
 def fixture(self,root):
  # Inert file corpus and abstract version-map unit inputs, never installed606.
  for n in('usr/bin/cachy-asahi-apps','usr/bin/cachy-asahi-welcome','var/lib/pacman/local/cachy-asahi-apps-0.1.0-6/desc','var/lib/pacman/local/cachy-asahi-welcome-0.1.0-4/desc','home/alarm/.config/held','etc/pacman.d/gnupg/held'):
   p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(('INERT_PRIVATE_NOT_NATIVE '+n+'\n').encode())
  inventory={f'inert-unit-{i}':'1'for i in range(604)}|{G.NAMES[k]:v for k,v in G.BASE.items()}
  return inventory
 def observe(self,root,inventory):
  observation=R.observe(root,limits=self.budget(),hardlinks='generic-development-internal')
  return dict(observation=observation,physical=physical.capture(root,observation['nodes'],self.budget()),capabilities=caps.observe(root,observation['nodes'],self.budget()),inventory=dict(inventory))
 def test_real_active_payload_and_DB_change_keeps_inactive605_then_receipt(self):
  for active in G.BASE:
   with self.subTest(active=active),tempfile.TemporaryDirectory()as tmp:
    root=Path(tmp);inventory=self.fixture(root);before=self.observe(root,inventory)
    (root/'usr/bin'/G.NAMES[active]).write_bytes(b'INERT_ACTIVE_CHANGED')
    (root/'var/lib/pacman/local'/(G.NAMES[active]+'-'+G.BASE[active])/'desc').write_bytes(b'INERT_ACTIVE_DB_CHANGED')
    after=self.observe(root,inventory);receipt=modules['lifecycle'].step_preserved(before,after,active,{k:modules['roles'].load(k)for k in G.BASE})
    self.assertEqual(receipt,dict(status='PASS_PREVIOUS_TO_CURRENT_OTHER605',active=active,protected_packages=605,inventory='EXACT_OTHER605',nodes_raw_db='EXACT_ALL_NONSELECTED',physical='FULL_INODE_HARDLINK_WITH_SELECTED_PARENT_AND_LOCK_WITNESSES',capabilities='EXACT_ALL_NONSELECTED',scope='SOURCE_ENFORCED_PRIVATE_MAPS_NOT_EXPORTED'))
 def test_real_inactive_same_byte_inode_rawDB_mode_hardlink_and_protected_changes_refuse(self):
  for active in G.BASE:
   inactive=next(k for k in G.BASE if k!=active)
   for mode in('same-byte-inode','rawDB','metadata','cross-hardlink','user','trust'):
    with self.subTest(active=active,mode=mode),tempfile.TemporaryDirectory()as tmp:
     root=Path(tmp);inventory=self.fixture(root);before=self.observe(root,inventory);p=root/'usr/bin'/G.NAMES[inactive]
     if mode=='same-byte-inode':replacement=p.with_name('replacement');replacement.write_bytes(p.read_bytes());os.replace(replacement,p)
     elif mode=='rawDB':(root/'var/lib/pacman/local'/(G.NAMES[inactive]+'-'+G.BASE[inactive])/'desc').write_bytes(b'UNCHANGED_VERSION_BUT_RAW_DB_DRIFT')
     elif mode=='metadata':p.chmod(0o600)
     elif mode=='cross-hardlink':p.unlink();os.link(root/'usr/bin'/G.NAMES[active],p)
     else:(root/('home/alarm/.config/held'if mode=='user'else'etc/pacman.d/gnupg/held')).write_bytes(b'PROTECTED_DRIFT')
     after=self.observe(root,inventory)
     with self.assertRaises(ValueError):modules['lifecycle'].step_preserved(before,after,active,{k:modules['roles'].load(k)for k in G.BASE})
 def test_real_previous_current_maps_reject_inactive_cap_version_or_missing605(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);inventory=self.fixture(root);before=self.observe(root,inventory);after=self.observe(root,inventory);api={k:modules['roles'].load(k)for k in G.BASE}
   for mode in('capability','version','missing','unknown-active'):
    wrong=copy.deepcopy(after)
    if mode=='capability':wrong['capabilities']['usr/bin/cachy-asahi-welcome']='NOT_A_NATIVE_CAPABILITY_FIXTURE'
    if mode=='version':wrong['inventory'][G.NAMES['welcome']]='foreign'
    if mode=='missing':wrong['inventory'].pop('inert-unit-0')
    with self.subTest(mode=mode),self.assertRaises(ValueError):modules['lifecycle'].step_preserved(before,wrong,'unknown'if mode=='unknown-active'else'apps',api)
 def test_actual_exercise_requires_step_guard_after_retirement_before_fixtures(self):
  # Execute the actual lifecycle loop with inert observe/transaction callbacks;
  # stop at the new guard's real refusal. No successful ALPM/native outcome.
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);inventory=self.fixture(root);before=self.observe(root,inventory);after=copy.deepcopy(before);after['inventory'][G.NAMES['welcome']]='inactive-drift';calls=[];count=[0]
   def observe(versions):
    count[0]+=1;return before if count[0]<=3 else after
   def transact(*args):calls.append('retired');return dict(returncode=0,direct_child_reaped=True,group_retired=True)
   products={k:{v:{'payload':{}}for v in G.VERSIONS[k]if v is not None}for k in G.BASE}
   def readback(*args,**kw):calls.append('initial604');return {}
   def fixtures(*args):calls.append('fixtures');return {k:dict(zero_capabilities=True,NNP=1,homes={h:(dict(CLI=2,inventory_count=606,installed_controls=0)if k=='apps'else dict(CLI=5,report=8))for h in('fresh','existing')})for k in G.BASE}
   # Existing original readback is separately covered by held controls. This
   # isolates new control-flow ordering; actual step_preserved remains real.
   with patch.object(modules['lifecycle'],'operands',return_value=products),patch.object(modules['lifecycle'],'readback',side_effect=readback),self.assertRaisesRegex(ValueError,'inactive605'):
    modules['lifecycle'].exercise(expected=inventory,plans={},apis={k:modules['roles'].load(k)for k in G.BASE},observe=observe,transact=transact,fixtures=fixtures,source_unchanged=lambda:True)
   self.assertEqual(calls.count('retired'),1);self.assertEqual(calls.count('fixtures'),1);self.assertLess(calls.index('retired'),len(calls)-1)

class FailureRetention(unittest.TestCase):
    """Private inert children and real file guards, never a passing native606 fixture."""
    def record(self, root, *, role='worker', nonce='a'*32, terminal=None, error=None, code=7):
        from types import SimpleNamespace
        return T.failed_role_record(root, role, nonce, [sys.executable, '-I', '-B', '-c', 'INERT_CONTROL'],
                                    SimpleNamespace(process=SimpleNamespace(returncode=code,pid=12345)), terminal, error, 10)

    def tree(self, root, raw=b'original failure\n'):
        (root/'bridge-output').mkdir(mode=0o700)
        (root/'worker.log').write_bytes(raw)

    def test_failure_data_full_capture_hash_tail_and_no_authority(self):
        import base64, hashlib, json
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);raw=b'FIRST\n'+bytes(range(256))*400;self.tree(root,raw)
            value=self.record(root);capture=value['capture']
            self.assertEqual(capture['sha256'],hashlib.sha256(raw).hexdigest())
            self.assertEqual(base64.b64decode(capture['tail_base64'],validate=True),raw[-8192:])
            self.assertEqual((capture['bytes'],capture['tail_bytes'],capture['omitted_bytes'],capture['truncated']),
                             (len(raw),8192,len(raw)-8192,True))
            path=root/'bridge-output/failed-worker.json';encoded=path.read_bytes()
            self.assertLessEqual(len(encoded),32768);self.assertEqual(json.loads(encoded),value)
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertEqual(value['acceptance'],'NOT_GRANTED')
            with self.assertRaises(FileExistsError):self.record(root)
            self.assertEqual(path.read_bytes(),encoded)

    def test_failure_data_alias_hardlink_and_wrong_nonce_refused(self):
        for kind in ('symlink','hardlink','fifo','oversize','bad-nonce','unknown-role','receipt-alias'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.tree(root)
                kw={}
                if kind=='symlink':(root/'worker.log').rename(root/'private');(root/'worker.log').symlink_to('private')
                elif kind=='hardlink':os.link(root/'worker.log',root/'alias')
                elif kind=='fifo':(root/'worker.log').unlink();os.mkfifo(root/'worker.log')
                elif kind=='oversize':
                    with (root/'worker.log').open('r+b') as f:f.truncate(16*1024**2+1)
                elif kind=='bad-nonce':kw['nonce']='x'*32
                elif kind=='unknown-role':kw['role']='private/path'
                else:(root/'bridge-output').rename(root/'private-output');(root/'bridge-output').symlink_to('private-output')
                with self.assertRaises((ValueError,OSError)):self.record(root,**kw)
                self.assertFalse((root/'bridge-output/failed-worker.json').exists())

    def test_failure_data_detects_actual_log_mutation(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.tree(root,b'x'*90000);original=os.read;changed=[]
            def read(fd,count):
                raw=original(fd,count)
                if raw and not changed:
                    changed.append(True)
                    with (root/'worker.log').open('ab') as stream:stream.write(b'changed')
                return raw
            with patch.object(os,'read',side_effect=read),self.assertRaisesRegex(ValueError,'drift'):
                self.record(root)
            self.assertFalse((root/'bridge-output/failed-worker.json').exists())

    def common(self):
        import importlib.util
        name='_failed_role_held_common'
        spec=importlib.util.spec_from_file_location(name,HERE.parents[2]/'historical/welcome/held606/held604/scripts/virtual/common.py')
        value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value

    def execute(self,root,script,*,timeout=False):
        from unittest.mock import patch
        common=self.common();seen=[]
        class Owned:
            image='sha256:'+'1'*64
            rows=[dict(status='PASS_ABSENCE_VERIFIED')]
            def launch(self,command):
                seen.append(command)
                return [sys.executable,'-I','-B','-c',script]
            def cleanup(self):pass
        self.tree(root,b'')
        (root/'worker.log').unlink()  # Original logger must itself create the capture.
        owner=T.AfterCapture(owned=Owned(),common=common,env=dict(os.environ),image=Owned.image,
                             nonce='a'*32,output=root,owner_deadline=time.monotonic()+20)
        owner.phase='finalized';paths={n:root/n for n in('runner','seed','proof','work','out')}
        error=None
        with patch.dict(T.SECONDS,worker=.08 if timeout else 10):
            try:owner.run('worker',paths)
            except BaseException as caught:error=caught
        self.assertEqual(len(seen),1);self.assertIn('--network=none',seen[0]);return owner,error

    def test_real_inert_failed_child_result_and_existing_refusal_retained(self):
        import base64,json
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);owner,error=self.execute(root,'import sys;print("OUT",flush=True);print("ERR",file=sys.stderr,flush=True);sys.exit(7)')
            self.assertIsInstance(error,ValueError);self.assertEqual(str(error),'phase failed; receipt cannot authorize continuation')
            self.assertEqual(owner.phase,'retired');self.assertEqual(owner.events[-1]['exit'],'FAILED')
            value=json.loads((root/'bridge-output/failed-worker.json').read_bytes())
            self.assertEqual(value['outcome']['returncode'],7);self.assertEqual(value['outcome']['waitid'],dict(code=os.CLD_EXITED,status=7))
            self.assertEqual(base64.b64decode(value['capture']['tail_base64']),b'OUT\nERR\n')
            self.assertTrue(T.group_absent(owner.events[-1]['pid']))

    def test_real_inert_timeout_original_error_and_retirement_retained(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);owner,error=self.execute(root,'import time;print("before-timeout",flush=True);time.sleep(10)',timeout=True)
            self.assertIsNotNone(error);self.assertIn('child terminal deadline',str(error))
            value=json.loads((root/'bridge-output/failed-worker.json').read_bytes())
            self.assertIsNone(value['outcome']['waitid']);self.assertEqual(value['outcome']['returncode'],-9)
            self.assertEqual(value['outcome']['error_type'],type(error).__name__);self.assertEqual(owner.phase,'retired')
            self.assertTrue(T.group_absent(owner.events[-1]['pid']))

    def test_success_does_not_export_failure_or_change_event_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);owner,error=self.execute(root,'print("inert success only")')
            self.assertIsNone(error);self.assertEqual(owner.phase,'worker-retired')
            self.assertEqual(set(owner.events[-1]),{'phase','argv','pid','exit','direct_child_reaped','group_absent','containers_absent'})
            self.assertEqual(owner.events[-1]['exit'],0);self.assertEqual(list((root/'bridge-output').iterdir()),[])

    def test_unavailable_diagnostic_never_replaces_original_failure(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(T,'failed_role_record',side_effect=OSError('inert diagnostic unavailable')):
                owner,error=self.execute(root,'raise SystemExit(7)')
            self.assertEqual(str(error),'phase failed; receipt cannot authorize continuation')
            self.assertEqual(owner.events[-1]['exit'],'FAILED');self.assertEqual(list((root/'bridge-output').iterdir()),[])

    def test_small_empty_and_bridge_role_failures_have_exact_counts(self):
        import hashlib,json
        for role,raw in (('finalize',b''),('dispose',b'original disposer failure')):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.tree(root);(root/'worker.log').rename(root/(role+'.log'));(root/(role+'.log')).write_bytes(raw)
                value=self.record(root,role=role);capture=value['capture']
                self.assertEqual(capture['bytes'],len(raw));self.assertEqual(capture['tail_bytes'],len(raw))
                self.assertEqual(capture['omitted_bytes'],0);self.assertIs(capture['truncated'],False)
                self.assertEqual(capture['sha256'],hashlib.sha256(raw).hexdigest())
                self.assertEqual(value['outcome']['pid'],12345)
                self.assertEqual(json.loads((root/('bridge-output/failed-'+role+'.json')).read_bytes()),value)


class JointWireCodec(unittest.TestCase):
 def budget(self):return R.Limits(deadline=time.monotonic()+10,max_nodes=200,max_bytes=1024**2,max_file_bytes=1024**2)
 def observe(self,p):return R.observe(p,limits=self.budget(),hardlinks='generic-development-internal',absolute_paths=True)
 def serialized(self,value):
  bridge=O.load('_joint_exact_bridge_wire',ROOT/'bridge/scripts/ci/current606-welcome5-source-bridge/bridge.py')
  return bridge.decode(bridge.encoded(value))
 def tree(self,p):
  (p/'nested').mkdir();(p/'a').write_bytes(b'unchanged source');os.link(p/'a',p/'b');(p/'nested/c').write_bytes(b'another source');os.link(p/'nested/c',p/'nested/d');(p/'relative').symlink_to('a')
 def test_exact_finalizer_JSON_to_full_same_source_real_hardlinks(self):
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp);self.tree(p);before=self.observe(p);loaded=self.serialized(before);after=self.observe(p)
   self.assertEqual(loaded['nodes'],after['nodes']);self.assertEqual(loaded['footprint'],before['footprint']);self.assertEqual(len(loaded['hardlink_groups']),2)
   self.assertIs(type(loaded['hardlink_groups']['a']['members']),list);self.assertIs(type(after['hardlink_groups']['a']['members']),tuple);self.assertTrue(G.same_source(loaded,after))
   self.assertEqual(loaded['hardlink_groups']['a']['members'],['a','b']);self.assertEqual(set(G.observation(loaded)),set(loaded))
 def test_typed_codec_keeps_member_and_every_other_field_refusals(self):
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp);self.tree(p);live=self.observe(p);wire=self.serialized(live)
   for members in (['b','a'],['a','a'],['a'],['a',False],['a','foreign'],'a'):
    wrong=copy.deepcopy(wire);wrong['hardlink_groups']['a']['members']=members
    with self.assertRaises(ValueError):G.same_source(wrong,live)
   for field in ('uid','gid','mode','bytes','sha256'):
    wrong=copy.deepcopy(wire);wrong['nodes']['a'][field]=('0'*64 if field=='sha256'else wrong['nodes']['a'][field]+1)
    with self.assertRaises(ValueError):G.same_source(wrong,live)
   for nlink in (True,1,3,'2'):
    wrong=copy.deepcopy(wire);wrong['hardlink_groups']['a']['nlink']=nlink
    with self.assertRaises(ValueError):G.same_source(wrong,live)
   (p/'a').write_bytes(b'real content mutation')
   with self.assertRaises(ValueError):G.same_source(wire,self.observe(p))
 def test_wire_join_does_not_waive_inactive605_payload_DB_inode_or_caps(self):
  helper=Step605Controls();apis={k:modules['roles'].load(k)for k in G.BASE}
  for active in G.BASE:
   inactive=next(k for k in G.BASE if k!=active)
   for drift in ('payload','DB','inode','mode','hardlink','capability','version'):
    with self.subTest(active=active,drift=drift),tempfile.TemporaryDirectory()as tmp:
     p=Path(tmp);inventory=helper.fixture(p);held=p/'held-hardlink';held.write_bytes(b'protected source');os.link(held,p/'held-alias');before=helper.observe(p,inventory)
     self.assertTrue(G.same_source(self.serialized(before['observation']),before['observation']))
     path=p/'usr/bin'/G.NAMES[inactive]
     if drift=='payload':path.write_bytes(b'inactive payload change')
     elif drift=='DB':(p/'var/lib/pacman/local'/(G.NAMES[inactive]+'-'+G.BASE[inactive])/'desc').write_bytes(b'inactive raw DB change')
     elif drift=='inode':replacement=path.with_name('replacement');replacement.write_bytes(path.read_bytes());os.replace(replacement,path)
     elif drift=='mode':path.chmod(0o600)
     elif drift=='hardlink':path.unlink();os.link(p/'usr/bin'/G.NAMES[active],path)
     after=helper.observe(p,inventory)
     if drift=='capability':after['capabilities']['usr/bin/'+G.NAMES[inactive]]='INERT_CHANGED_CAPABILITY'
     elif drift=='version':after['inventory'][G.NAMES[inactive]]='foreign'
     with self.assertRaises(ValueError):modules['lifecycle'].step_preserved(before,after,active,apis)


class JointInventoryParent(unittest.TestCase):
 def test_actual_transient_operand_database_parent_and_held40(self):
  tree=ast.parse((LANE/'transient_cli.py').read_bytes());calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='call'and isinstance(n.args[0],ast.List)and any(isinstance(v,ast.Constant)and v.value=='--dbpath'for v in n.args[0].elts)];self.assertEqual(len(calls),1);values=calls[0].args[0].elts;i=next(i for i,v in enumerate(values)if isinstance(v,ast.Constant)and v.value=='--dbpath');self.assertEqual(ast.literal_eval(values[i+1]),'/var/lib/pacman');self.assertEqual(ast.literal_eval(calls[0].args[1]),40)
 def test_real_frontend_old_child_refuses_parent_reads_without_DB_mutation(self):
  app=ROOT/'historical/apps/copyworker/held-apps/fixture-apps';runtime=ROOT/'historical/apps/held606/held604/packages/tools/cachy-asahi-repository-runtime'
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);db=root/'db';package=db/'local/cachy-asahi-apps-0.1.0-7';package.mkdir(parents=True);(db/'local/ALPM_DB_VERSION').write_bytes(b'9\n');(package/'desc').write_bytes(b'%NAME%\ncachy-asahi-apps\n\n%VERSION%\n0.1.0-7\n\n%ARCH%\nany\n\n');(package/'files').write_bytes(b'');repo=root/'repository'
   for n,wanted in O.read(app/'helper-pins.json')['files'].items():
    raw=(runtime/Path(n).name).read_bytes();self.assertEqual(O.pin(raw),wanted);p=repo/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
   command=[sys.executable,'-I','-B',str(app/'apps.py'),'--repository-source',str(repo),'inventory','--dbpath'];output=root/'inventory.json';before={str(p.relative_to(db)):(p.read_bytes(),p.stat().st_ino,p.stat().st_mode,p.stat().st_mtime_ns)for p in db.rglob('*')if p.is_file()}
   wrong=subprocess.run(command+[str(db/'local'),'--output',str(output)],capture_output=True,timeout=15);self.assertNotEqual(wrong.returncode,0);self.assertIn(b'local',wrong.stdout+wrong.stderr);self.assertFalse(output.exists())
   good=subprocess.run(command+[str(db),'--output',str(output)],capture_output=True,timeout=15);self.assertEqual(good.returncode,0,good.stderr.decode());receipt=json.loads(good.stdout);value=json.loads(output.read_bytes());self.assertEqual(receipt['applied'],'NOT_APPLIED');self.assertEqual(receipt['package_count'],1);self.assertFalse(value['observation']['payload_verified']);self.assertFalse(value['observation']['hardware_verified']);self.assertEqual(value['observation']['consistency'],'TWO_MATCHING_READS_NO_LOCK_NO_DETECTED_DRIFT');self.assertEqual(output.stat().st_mode&0o777,0o600);self.assertEqual(before,{str(p.relative_to(db)):(p.read_bytes(),p.stat().st_ino,p.stat().st_mode,p.stat().st_mtime_ns)for p in db.rglob('*')if p.is_file()})
   output.unlink();(db/'db.lck').write_bytes(b'held');refused=subprocess.run(command+[str(db),'--output',str(output)],capture_output=True,timeout=15);self.assertNotEqual(refused.returncode,0);self.assertIn(b'db.lck',refused.stdout+refused.stderr);self.assertFalse(output.exists())
 def test_new_source_is_not_qualification_and_transient_signals_exact_declared_uid(self):
  self.assertEqual(S.EXPECTED_SOURCES,{'apps606':'b6808d7a81e148ef04eef604590428b4d4d88c9c','welcome606':'af46d8dd3d24245b2402c9d0397ac88a4f29ae11'});self.assertIsNone(S.EXPECTED_JOINT);self.assertEqual(O.read(HERE/'input-policy.json')['joint_decisions'],{'apps606':None,'welcome606':None})
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):
   with self.assertRaisesRegex(ValueError,'future accepted'):Y.authorize(O.read(HERE/'input-policy.json'))
  tree=ast.parse((LANE/'rooted_cli.py').read_bytes());run=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='run');calls=[n for n in ast.walk(run)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name)and n.func.value.id=='supervised'and n.func.attr=='run'];self.assertEqual(len(calls),1);kw=next(k for k in calls[0].keywords if k.arg=='signal_uid');self.assertEqual(ast.unparse(kw.value),"spec['uid']");self.assertIn("value['group_retired']is True",ast.get_source_segment((LANE/'rooted_cli.py').read_text(),run))

if __name__=='__main__':unittest.main(verbosity=2)
