# SPDX-License-Identifier: MIT
"""Companion source controls and real inert cancellation; no native/ALPM evidence."""
import ast,copy,hashlib,importlib.util,json,os,shutil,signal,stat,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
SOURCE=Path(os.environ['APPS16_INTERRUPTION_SOURCE']).absolute()
sys.path.insert(0,str(HERE))

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module

X=load('common',HERE/'common.py')
L=load('_operation_lifecycle_control',HERE/'lifecycle.py')

def profile_sha():return X.pin((HERE/'profile.json').read_bytes())['sha256']
def function(raw,name):return next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name==name)
def need(ok,why):
    if not ok:raise ValueError(why)

def plan():
    row=dict(name=X.APPS,version=X.VERSION,metadata_sha256='b'*64)
    return dict(status='PLANNED',applied='NOT_APPLIED',installer_authority=False,synthetic=True,
        plan=dict(operation='reinstall',requested_packages=[X.APPS],requested_applications=['apps'],
                  repair_policy='EXPLICIT_SELECTED_SAME_VERSION_AND_METADATA_ONLY_NO_DEPENDENCY_EXPANSION',
                  reinstalls=[dict(before=row,after=dict(row,release_archive_sha256=X.ARCHIVE))],
                  before_inventory_sha256='a'*64,after_inventory_sha256='a'*64,
                  **{k:[]for k in('additions','upgrades','removals','dependencies','conflicts','unchanged_selected')}))


class Controls(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='apps16-interruption-unit-')
        self.addCleanup(temp.cleanup);self.work=Path(temp.name)

    def test_closed245_source_and_separate_capsule_no_actual_identity(self):
        with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):
            p=X.verify(SOURCE,profile_sha())
        self.assertEqual(len(p['source_files']),245)
        self.assertEqual(p['source'],X.SOURCE);self.assertEqual(p['operation'],X.OPERATION)
        self.assertIsNone(p['actual']);self.assertIsNone(p['Root_acceptance'])
        self.assertEqual(X.tree(SOURCE),p['source_files'])
        self.assertEqual(X.tree(HERE),dict(p['operation_files'],**{'profile.json':X.pin((HERE/'profile.json').read_bytes())}))
        for value in(None,True,1,'foreign','0'*64):
            with self.subTest(profile=value),self.assertRaises(ValueError):X.verify(SOURCE,value)
        for name in('common.py','lifecycle.py','job.py','profile.json'):
            capsule=self.work/name;shutil.copytree(HERE,capsule);(capsule/name).write_bytes(b'foreign\n')
            with self.subTest(member=name),patch.object(X,'HERE',capsule),self.assertRaises(ValueError):
                X.verify(SOURCE,profile_sha())

    def test_source_drift_alias_namespace_and_hardlink_refuse_before_actors(self):
        leaf=X.LANE+'/base_lifecycle.py'
        for kind in('bytes','missing','extra','empty','symlink','hardlink'):
            source=self.work/kind;shutil.copytree(SOURCE,source);path=source/leaf
            if kind=='bytes':path.write_bytes(path.read_bytes()+b'\n')
            elif kind=='missing':path.unlink()
            elif kind=='extra':(source/'foreign').write_bytes(b'x')
            elif kind=='empty':(source/'foreign').mkdir()
            elif kind=='symlink':path.unlink();path.symlink_to(SOURCE/leaf)
            else:path.unlink();os.link(source/(X.LANE+'/lifecycle.py'),path)
            with self.subTest(kind=kind),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')),self.assertRaises(ValueError):
                X.verify(source,profile_sha())
        alias=self.work/'alias';alias.symlink_to(SOURCE,target_is_directory=True)
        for source in(alias,'relative',str(SOURCE)+'/../source','//tmp/foreign'):
            with self.subTest(source=str(source)),self.assertRaises(ValueError):X.verify(source,profile_sha())

    def test_capsule_known_null_complete_emission_modes_and_prewrite_refusals(self):
        prepare=load('_companion_capsule_preparer',HERE/'prepare.py')
        expected={'source/'+n:w for n,w in X.tree(SOURCE).items()}
        expected.update({'operation/'+n:w for n,w in X.tree(HERE).items()})
        for context in('known','null'):
            target=self.work/context
            with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):
                receipt=prepare.emit(SOURCE,target,profile_sha(),context)
            self.assertEqual(X.tree(target),expected);self.assertEqual(receipt['files'],expected)
            self.assertEqual(receipt['source']is None,context=='null')
            self.assertIsNone(receipt['actual']);self.assertIsNone(receipt['Root_acceptance'])
            self.assertEqual(receipt['native'],'NOT_RUN')
            self.assertTrue(all(stat.S_IMODE((target/n).stat().st_mode)==0o644 for n in expected))
        for target in(SOURCE/'forbidden',HERE/'forbidden',self.work/'known','relative',str(self.work)+'/a/../out'):
            with self.subTest(target=str(target)),self.assertRaises(ValueError):prepare.emit(SOURCE,target,profile_sha(),'known')
        target=self.work/'late';original_verify=X.verify;seen=[]
        def changed(*a):
            result=original_verify(*a)
            if not seen:seen.append(True);return result
            return dict(result,operation='foreign')
        with patch.object(X,'verify',side_effect=changed),self.assertRaisesRegex(ValueError,'late'):
            prepare.emit(SOURCE,target,profile_sha(),'known')
        self.assertFalse(target.exists())

    def test_companion_owner_keeps_original_cleanup_and_requires_operation_before_process(self):
        job=load('_companion_owner_control',HERE/'job.py')
        with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')), \
             patch.object(subprocess,'run',side_effect=AssertionError('NO_PROCESS')):
            original,H,bodies=job.configure(SOURCE,profile_sha())
        self.assertEqual(set(bodies),{'actor','run','retain'})
        text=(SOURCE/'scripts/ci/apps-full574-native/job.py').read_text()
        codes={c.co_name:c for c in compile(text,str(Path(H.__file__)),'exec').co_consts if isinstance(c,types.CodeType)}
        self.assertEqual(H.cleanup.__code__,codes['cleanup'])
        self.assertEqual(H.C.STATUS,X.STATUS);self.assertEqual(original.STATUS,'PASS_APPS16_GENERIC16K_SIGNED_REPAIR_CASE_AND_ORDERED_TEARDOWN')
        self.assertIn("mounts.append((OPERATION_ROOT,'/operation',True))",bodies['actor'])
        self.assertIn("'/operation/lifecycle.py'if role=='lifecycle'",bodies['actor'])
        self.assertIn('operation_retained(C,life',bodies['retain'])
        self.assertNotIn("actor(args.source,args.output,report,command,api,'interruption'",bodies['run'])
        for argv in([],['proof','--operation','foreign'],['proof','--operation',X.OPERATION]):
            with self.subTest(argv=argv),patch.object(job,'configure',side_effect=AssertionError('configuration before required selection')),patch('sys.stderr',new=__import__('io').StringIO()),self.assertRaises(SystemExit):
                job.main(argv)
        with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')),self.assertRaises(ValueError):
            job.main(['proof','--operation',X.OPERATION,'--operation-profile-sha256','0'*64,'--source',str(SOURCE),'--proof',str(self.work/'proof.json')])
        self.assertFalse((self.work/'proof.json').exists())

    def test_actual_apps16_selection_and_unknown_interruption_contract(self):
        selected=plan();self.assertEqual(X.selected_plan(selected),selected['plan'])
        variants=[]
        for key,value in(('operation','install'),('requested_packages',['fixture']),('additions',[{}]),
                          ('dependencies',[{}]),('after_inventory_sha256','c'*64)):
            bad=copy.deepcopy(selected);bad['plan'][key]=value;variants.append(bad)
        for side,key,value in(('before','version','1-1'),('after','name','fixture'),('after','release_archive_sha256','0'*64)):
            bad=copy.deepcopy(selected);bad['plan']['reinstalls'][0][side][key]=value;variants.append(bad)
        bad=copy.deepcopy(selected);bad['installer_authority']=True;variants.append(bad)
        for bad in variants:
            with self.subTest(plan=bad['plan']),self.assertRaises(ValueError):X.selected_plan(bad)
        before=dict(tree_sha256='d'*64)
        interrupted=dict(status='FAIL_INTERRUPTED_OWNED_COPY_RETAINED',commit_started='UNKNOWN',packages_committed='UNKNOWN',
                         rollback='NOT_CLAIMED',worker_group_absent=True,direct_child_reaped=True,time_limit=600,reap_limit=5,seconds=1,
                         pending=dict(status='ATTEMPT_STARTED_COMMIT_OUTCOME_NOT_RECORDED',plan_sha256='a'*64,before=before),
                         outputs=dict(stdout=dict(bytes=0),stderr=dict(bytes=0)))
        self.assertIs(X.interruption(interrupted,'a'*64,before),interrupted)
        for field,value in(('commit_started',True),('packages_committed',True),('rollback','PASS'),
                            ('worker_group_absent',False),('direct_child_reaped',False),('seconds',606)):
            with self.subTest(field=field),self.assertRaises(ValueError):X.interruption(dict(interrupted,**{field:value}),'a'*64,before)
        with self.assertRaises(ValueError):X.interruption(interrupted,'0'*64,before)
        with self.assertRaises(ValueError):X.interruption(interrupted,'a'*64,dict(tree_sha256='0'*64))

    def test_protected_filter_retains_shared_dirs_user_config_trust_and_other_db(self):
        directory=dict(type='directory',mode=0o755);file=dict(type='file',mode=0o644,sha256='a'*64)
        package='var/lib/pacman/local/'+X.APPS+'-'+X.VERSION
        nodes={n:dict(file)for n in('home/user/note','etc/pacman.conf','etc/pacman.d/trust',
                'usr/share/unselected','var/lib/pacman/local/other-1/desc',package+'/desc','usr/share/apps16/selected','var/lib/pacman/db.lck')}
        nodes['usr/share/apps16']=directory
        payload={'usr/share/apps16':directory,'usr/share/apps16/selected':file}
        protected=L.protected(nodes,payload,X.VERSION)
        self.assertEqual(set(nodes)-set(protected),{package+'/desc','usr/share/apps16/selected','var/lib/pacman/db.lck'})
        self.assertEqual(protected['usr/share/apps16'],directory)
        changed=copy.deepcopy(nodes);changed['usr/share/apps16/selected']['sha256']='b'*64;changed[package+'/desc']['sha256']='b'*64
        self.assertEqual(L.protected(changed,payload,X.VERSION),protected)
        for name in protected:
            bad=copy.deepcopy(nodes);bad[name]=dict(bad[name],mode=0o600)
            self.assertNotEqual(L.protected(bad,payload,X.VERSION),protected,name)
        source=(HERE/'lifecycle.py').read_text()
        self.assertIn('interrupted=H.interrupted(calls,workspace,owner,attempts)',source)
        self.assertNotIn("backend('dispose-copy'",source)
        self.assertNotIn('T.dispose(',source)
        self.assertNotIn('db.lck\').unlink',source)

    def model_driver(self,wrong_archive=False):
        """Drive new orchestration; peers are inert models, files are real temps."""
        area=self.work/('wrong-archive'if wrong_archive else'driver');area.mkdir()
        work=area/'work';work.mkdir();out=area/'out';out.mkdir();seed=area/'seed';seed.mkdir()
        for name,data in(('home/user/config',b'held user config'),('etc/pacman.conf',b'held config'),
                          ('etc/pacman.d/trust',b'held trust'),('var/lib/pacman/local/base-1/desc',b'held DB')):
            path=seed/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        workspace=work/'main';root=workspace/'root';target='usr/share/doc/cachy-asahi-apps/README.md'
        events=[];pins={k:hashlib.sha256(k.encode()).hexdigest()for k in('tree_sha256','database_sha256','packages_sha256','inventory_sha256')}
        versions={'cachy-asahi-repository-runtime':'0.1.0-1',X.APPS:X.VERSION,'cachy-asahi-cache':'0.2.0-1','cachy-asahi-orphans':'0.1.0-2'}
        digest=lambda v:hashlib.sha256(X.encoded(v)).hexdigest()
        caps_sha=digest({});selection=plan();selected_sha=None
        if wrong_archive:selection['plan']['reinstalls'][0]['after']['release_archive_sha256']='0'*64
        checks=load('_real_checks_inert_driver_'+str(wrong_archive),SOURCE/X.LANE/'checks.py')
        def nodes(path):
            return {p.relative_to(path).as_posix():dict(type='directory',mode=0o755)if p.is_dir()else dict(type='file',mode=0o644,bytes=p.stat().st_size,sha256=X.pin(p.read_bytes())['sha256'])for p in sorted(path.rglob('*'))}
        source_nodes=nodes(seed)
        C=types.SimpleNamespace(need=need,HERE=SOURCE/X.LANE,VERSIONS=versions,sha=lambda b:X.pin(b)['sha256'],
              read=lambda p,cap=16*1024**2:p.read_bytes(),decode=X.decode,save=lambda p,v:p.write_bytes(X.encoded(v)),
              ref=lambda d,p:dict(path=p.relative_to(d).as_posix(),**X.pin(p.read_bytes())),load=lambda *a:checks)
        def measure(path,budget):
            events.append('measure-seed'if path==Path('/seed')else'measure-work')
            return dict(nodes=nodes(seed if path==Path('/seed')else path))
        def capabilities(path,observation,budget,*expected):
            events.append('check-source-caps'if path==Path('/seed')else'check-copy-caps')
            if expected:self.assertEqual(expected,({},))
            return {}
        adapter=types.SimpleNamespace(measure=measure,digest=digest,capability_map=capabilities,
                                      current_payloads=lambda:{X.APPS:{target:dict(type='file')}})
        T=types.SimpleNamespace(limits=lambda:object()) # No commit/dispose/ALPM endpoints.
        owner='inert-copy-owner';attempts=['INERT_REINSTALL_NOT_A_COMMAND']
        def backend(action,path,*ownership):
            self.assertEqual((action,path),('prepare-copy',workspace));return ['INERT_PREPARE_NOT_A_COMMAND']
        def planned(calls,path,label,operation,names):
            nonlocal selected_sha
            self.assertEqual(path,workspace);events.append('plan-'+operation)
            self.assertEqual(names,['apps','cache','orphans']if operation=='install'else['apps'])
            value=dict(model='INERT_INSTALL_PLAN')if operation=='install'else copy.deepcopy(selection)
            path=out/(label+'-plan.json');C.save(path,value)
            if operation=='reinstall':selected_sha=C.sha(C.read(path))
            return path,value
        def damage(path,name,missing):
            self.assertEqual((path,name,missing),(workspace,target,False));events.append('damage')
            leaf=root/name;leaf.write_bytes(leaf.read_bytes()+b' inert damage')
        def inspected(t,calls,path,ownership,file,value,label):
            self.assertEqual((path,ownership),(workspace,owner));events.append('inspect')
            inspection=dict(status='INSPECTED_AUTHENTICATED_OWNED_FULL574_REINSTALL',scope='READONLY_AUTHENTICATED_OWNED_FULL574_REINSTALL_PREPARATION',operation='reinstall',selected=[X.APPS],
                plan_sha256=selected_sha,archives={X.APPS:X.ARCHIVE},commit_started=False,packages_committed=False,transaction='NOT_RUN',repair_authority=False,installer_authority=False,
                root_preserved=True,cleanup='OWNED_TEMP_REMOVED_WORKSPACE_FLOCK_RELEASED',source_preservation='LEASED_READONLY_SOURCE_REVALIDATED',before=pins,damage={target:dict(type='file')},
                worker=dict(seconds=600,output_limit=512*1024,returncode=0,termination=None,direct_child_reaped=True,group_kill_sent=True,retirement='ORIGINAL_SUPERVISOR_SIGNALS_GROUP_BEFORE_LEADER_REAP'),
                auxiliary_preservation=dict(status='PASS-recorded-state-preserved',main_cache='RAW_EQUAL',auxiliary_transition={'kind':'RAW_EQUAL'}),source_tree_sha256=digest(source_nodes),capabilities_sha256=caps_sha)
            C.save(out/(label+'-inspection.json'),inspection);return inspection
        def interrupted(calls,path,ownership,argv):
            self.assertEqual((path,ownership,argv),(workspace,owner,attempts));events.append('interrupted-interface')
            pending=dict(status='ATTEMPT_STARTED_COMMIT_OUTCOME_NOT_RECORDED',plan_sha256=selected_sha,before=pins)
            C.save(workspace/'apps-pending.json',pending);(root/'var/lib/pacman/db.lck').write_bytes(b'')
            outputs={}
            for side in('stdout','stderr'):
                path=out/('interrupted-'+side);path.write_bytes(b'INERT_DRIVER_NOT_AUTH_OR_ALPM\n');outputs[side]=C.ref(out,path)
            value=dict(status='FAIL_INTERRUPTED_OWNED_COPY_RETAINED',commit_started='UNKNOWN',packages_committed='UNKNOWN',rollback='NOT_CLAIMED',worker_group_absent=True,direct_child_reaped=True,
                       time_limit=600,reap_limit=5,seconds=1,pending=pending,outputs=outputs)
            C.save(out/'interruption.json',value);return value
        interrupt=__import__('unittest.mock',fromlist=['Mock']).Mock(wraps=interrupted)
        H=types.SimpleNamespace(backend=backend,retain_copy=lambda p,o:events.append('retain-copy'),apply_args=lambda *a:['INERT_INSTALL_NOT_A_COMMAND'],
              count=lambda p:{'inert-package-'+str(i):'1'for i in range(578)},interrupted=interrupt,common=lambda *a:[],credentials=lambda:[])
        R=types.SimpleNamespace(H=H,TARGET=target,planned=planned,damage=damage,inspected=inspected,argv=lambda *a:attempts)
        def call(argv,expected=0):
            if argv[0]=='INERT_PREPARE_NOT_A_COMMAND':
                self.assertEqual(expected,0);events.append('prepare');workspace.mkdir(mode=0o700);shutil.copytree(seed,root)
                return dict(status='OWNED_COPY_PREPARED',source_preserved=True,ownership_sha256=owner)
            if argv==['INERT_INSTALL_NOT_A_COMMAND']:
                events.append('install578-model');leaf=root/target;leaf.parent.mkdir(parents=True);leaf.write_bytes(b'INERT_APPS16_PAYLOAD_MODEL')
                return dict(status='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION',dependency_checks='ORDINARY_LIBALPM',cleanup='OWNED_WORKSPACE_TEMP_AND_ALPM_HANDLE_LOCK_RELEASED',rollback='NOT_ATTEMPTED_DISPOSABLE_COPY_ONLY',
                  commit_started=True,packages_committed=True,prepared_add=versions,prepared_remove={},full574_closure=dict(status='PASS-recorded-state-preserved',main_cache='RAW_EQUAL',auxiliary_transition={'kind':'RAW_EQUAL'},
                  auxiliary_inode_liveness='NOT_ESTABLISHED_SOURCE_SNAPSHOT_KEYS',security_capabilities='EXACT_SOURCE_MAP_PRESERVED',source_capabilities_sha256=caps_sha))
            self.assertEqual(expected,1);self.assertIn('interrupted-interface',events)
            self.assertTrue((root/'var/lib/pacman/db.lck').exists())
            if 'inspect-reinstall'in argv:
                events.append('negative-inspection');return dict(status='FAIL',transaction='NOT_RUN')
            self.assertEqual(argv,attempts);events.append('negative-retry');return dict(status='FAIL',commit_started=False,packages_committed=False)
        with patch.object(L,'WORK',work),patch.object(L,'OUT',out),patch.object(L,'SOURCE',SOURCE):
            if wrong_archive:
                with self.assertRaisesRegex(ValueError,'exact actual Apps16 archive/version'):L.execute(C,R,T,adapter,types.SimpleNamespace(call=call))
                interrupt.assert_not_called();self.assertNotIn('damage',events);return
            result=L.execute(C,R,T,adapter,types.SimpleNamespace(call=call))
        interrupt.assert_called_once();self.assertEqual(result['status'],X.LIFECYCLE)
        self.assertFalse(result['workspaces_disposed']);self.assertTrue(result['workspaces_retained_for_outer_disposal'])
        self.assertEqual(result['commit_started'],result['packages_committed']);self.assertEqual(result['packages_committed'],'UNKNOWN')
        self.assertEqual(result['rollback'],'NOT_CLAIMED');self.assertFalse(result['repair_success'])
        self.assertEqual(json.loads((out/'lifecycle.json').read_bytes()),result)
        self.assertEqual(result['interruption']['pending']['plan_sha256'],selected_sha)
        self.assertEqual(result['interruption']['pending']['before'],pins)
        for a,b in(('install578-model','plan-reinstall'),('plan-reinstall','damage'),('damage','inspect'),('inspect','interrupted-interface'),('interrupted-interface','negative-inspection'),('negative-inspection','negative-retry'),('negative-retry','check-copy-caps')):
            self.assertLess(events.index(a),events.index(b))
        self.assertEqual(nodes(seed),source_nodes);self.assertEqual((root/'home/user/config').read_bytes(),b'held user config')
        self.assertTrue((workspace/'apps-pending.json').is_file());self.assertTrue((root/'var/lib/pacman/db.lck').exists())
        print(json.dumps(dict(test=self._testMethodName,scope='WHOLE_NEW_DRIVER_INERT_MODELS_NOT_AUTH_OR_ALPM',events=events,workspace_retained_for_outer_disposal=True,native='NOT_RUN',hardware='NOT_RUN'),sort_keys=True))

    def test_full_new_driver_inert_protocol_order_and_wrong_archive_stops_before_interrupt(self):
        self.model_driver();self.model_driver(wrong_archive=True)

    def test_original_scrub_requires_modeled_actor_absence_then_real_whole_tree_disposal(self):
        work=self.work/'work';authority=self.work/'authority';out=self.work/'out';inputs=self.work/'inputs'
        for path in(work,authority,out,inputs):path.mkdir(mode=0o700)
        (self.work/'net/lo').mkdir(parents=True);(self.work/'dockerenv').write_bytes(b'inert admission model')
        for path,data in((work/'main/apps-pending.json',b'inert uncertain pending'),
                          (work/'main/root/var/lib/pacman/db.lck',b''),(authority/'keys/private',b'inert signing key bytes')):
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        held=self.work/'original-config';held.write_bytes(b'untouched source config')
        T=load('_original_scrub_real_disposer',SOURCE/'scripts/apps/transaction.py')
        identity={name:T.inode(path)for name,path in(('work',work),('authority',authority))}
        receipt=dict(status='ALL_EARLIER_CONSUMERS_ABSENCE_VERIFIED',token='79'*16,
                     actors=[dict(status='RESERVED',role='inert-consumer')],**identity)
        raw_receipt=inputs/'scrub.json';raw_receipt.write_bytes(X.encoded(receipt));loads=[];modeled=[]
        def path(value):
            value=os.fspath(value)
            roots={'/work':work,'/authority':authority,'/out':out,'/inputs':inputs,'/source':SOURCE,
                   '/.dockerenv':self.work/'dockerenv','/sys/class/net':self.work/'net'}
            for name,target in roots.items():
                if value==name or value.startswith(name+'/'):return target/value[len(name):].lstrip('/')
            raise AssertionError('unmapped original scrub path: '+value)
        def checked(ok,why):
            if why=='exact bound owned private mount':
                for name,root in(('work',work),('authority',authority)):
                    self.assertEqual(T.inode(root),identity[name]);self.assertEqual(stat.S_IMODE(root.stat().st_mode),0o700)
                modeled.append('EXPLICIT_BOUND_TEMP_ROOT_MOUNT_ADMISSION_MODEL');return
            need(ok,why)
        def module(name,file):
            self.assertEqual((name,file),('original_disposer',SOURCE/'scripts/apps/transaction.py'))
            loads.append(name);return T
        C=types.SimpleNamespace(need=checked,source=lambda root:self.assertEqual(root,SOURCE),
               read=lambda p:X.read(p),decode=X.decode,load=module,save=lambda p,v:p.write_bytes(X.encoded(v)))
        modeled_os=types.SimpleNamespace(getuid=lambda:0,geteuid=lambda:0,uname=lambda:types.SimpleNamespace(machine='aarch64'),
              environ=dict(CACHY_APPS574_LIFECYCLE='1',OWNER_TOKEN='79'*16,OUTPUT_UID=str(os.getuid()),OUTPUT_GID=str(os.getgid())),
              fchown=os.fchown,close=os.close,chown=lambda p,uid,gid:os.chown(path(p),uid,gid))
        node=function((SOURCE/'scripts/ci/apps-full574-native/scrub.py').read_bytes(),'main')
        scope=dict(C=C,Path=path,os=modeled_os,time=time)
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<EXACT_ORIGINAL_SCRUB_TEMP_MODELED_ADMISSION>','exec'),scope)
        before={str(p):p.read_bytes()for root in(work,authority)for p in root.rglob('*')if p.is_file()}
        with self.assertRaisesRegex(ValueError,'earlier actor absence receipt required'):scope['main']()
        self.assertFalse(loads);self.assertFalse(modeled);self.assertFalse((out/'disposal.json').exists())
        self.assertEqual({str(p):p.read_bytes()for root in(work,authority)for p in root.rglob('*')if p.is_file()},before)
        receipt['actors'][0]['status']='PASS_ABSENCE_VERIFIED';raw_receipt.write_bytes(X.encoded(receipt))
        with patch.object(T.F,'_open_root',wraps=T.F._open_root)as opened, \
             patch.object(T.LIFETIME,'_empty',wraps=T.LIFETIME._empty)as emptied, \
             patch.object(T.F,'Alpm',side_effect=AssertionError('ALPM forbidden')), \
             patch.object(T,'commit',side_effect=AssertionError('commit forbidden')):
            scope['main']()
        self.assertEqual(opened.call_count,2);self.assertGreaterEqual(emptied.call_count,2)
        self.assertEqual(list(work.iterdir()),[]);self.assertEqual(list(authority.iterdir()),[])
        self.assertEqual(T.inode(work),identity['work']);self.assertEqual(T.inode(authority),identity['authority'])
        self.assertEqual(held.read_bytes(),b'untouched source config')
        result=json.loads((out/'disposal.json').read_bytes())
        self.assertEqual(result['status'],'PASS_WHOLE_OWNED_COPIES_AND_AUTHORITY_DISPOSED_AFTER_ACTOR_ABSENCE')
        self.assertEqual(result['rollback'],'NOT_CLAIMED')
        self.assertEqual(result['lock_handling'],'NO_STALE_LOCK_RELEASE_OR_RAW_LOCK_DELETION_API_WHOLE_PRIVATE_TREE_DISPOSAL_ONLY')
        self.assertEqual(loads,['original_disposer']);self.assertEqual(len(modeled),2)
        print(json.dumps(dict(test=self._testMethodName,scope='ORIGINAL_SCRUB_REAL_TEMP_DELETION_MODELED_NATIVE_MOUNTS_ACTOR_ABSENCE',
              early_absence_refusal_preserved_tree=True,real_descriptor_open=True,real_recursive_whole_tree_empty=True,
              source_config_held=True,rollback='NOT_CLAIMED',native_cleanup='NOT_RUN',hardware='NOT_RUN'),sort_keys=True))

    def inert_interruption(self,early=False):
        workspace=self.work/'workspace';workspace.mkdir(mode=0o700)
        root=workspace/'root';(root/'var/lib/pacman').mkdir(parents=True)
        (root/'home/user').mkdir(parents=True);note=root/'home/user/config';note.write_bytes(b'held inert user config\n')
        output=self.work/'out';output.mkdir();script=self.work/'inert.py'
        before=dict(tree_sha256='b'*64,database_sha256='c'*64,packages_sha256='d'*64,inventory_sha256='e'*64)
        pending=dict(status='ATTEMPT_STARTED_COMMIT_OUTCOME_NOT_RECORDED',plan_sha256='a'*64,before=before)
        code="import os,time\nfrom pathlib import Path\n"
        if early:code+='raise SystemExit(0)\n'
        else:
            code+='p=Path('+repr(str(workspace/'apps-pending.json'))+")\n"
            code+='with p.open("xb") as f:\n f.write('+repr(X.encoded(pending))+');f.flush();os.fsync(f.fileno())\n'
            code+='fd=os.open('+repr(str(root/'var/lib/pacman/db.lck'))+',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)\n'
            code+='print("INERT_FIXTURE_NOT_AUTHENTICATED_NOT_ALPM",flush=True)\nwhile True:time.sleep(0.1)\n'
        script.write_text(code)
        source=(SOURCE/X.LANE/'base_lifecycle.py').read_bytes();node=function(source,'interrupted')
        processes=[];modeled=[];started=time.monotonic();original_popen=subprocess.Popen
        def popen(*a,**kw):
            process=original_popen(*a,**kw);processes.append(process);return process
        def checked(ok,why):
            need(time.monotonic()-started<5,'inert control outer5s deadline')
            if why=='uncertain real transaction lock':
                lock=(root/'var/lib/pacman/db.lck').lstat()
                need(stat.S_ISREG(lock.st_mode)and lock.st_nlink==1 and lock.st_uid==os.getuid()and lock.st_size==0,
                     'exact currentuid inert lock admission model')
                modeled.append('CURRENT_UID_INERT_LOCK_NOT_ROOT_OR_ALPM_PROOF');return
            need(ok,why)
        C=types.SimpleNamespace(need=checked,ENV=dict(PATH='/usr/bin:/bin',LANG='C'),decode=X.decode,
              read=lambda p,cap=2*1024**2:X.read(p),save=lambda p,v:p.write_bytes(X.encoded(v)),
              ref=lambda out,path:dict(path=path.relative_to(out).as_posix(),**X.pin(path.read_bytes())))
        scope=dict(C=C,OUT=output,WORK=self.work,os=os,signal=signal,stat=stat,time=time,
                   subprocess=types.SimpleNamespace(Popen=popen,DEVNULL=subprocess.DEVNULL))
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<EXACT_ORIGINAL_INTERRUPTED_INERT_FIXTURE>','exec'),scope)
        with patch.dict(os.environ,{'OWNER_TOKEN':'79'*16}):
            if early:
                with self.assertRaisesRegex(ValueError,'attempt ended before interruption point'):
                    scope['interrupted'](None,workspace,'inert-owner',[sys.executable,'-I','-B',str(script)])
                value=None
            else:value=scope['interrupted'](None,workspace,'inert-owner',[sys.executable,'-I','-B',str(script)])
        self.assertEqual(len(processes),1);process=processes[0]
        with self.assertRaises(ProcessLookupError):os.killpg(process.pid,0)
        with self.assertRaises(ChildProcessError):os.waitpid(process.pid,os.WNOHANG)
        self.assertEqual(note.read_bytes(),b'held inert user config\n')
        if early:
            self.assertEqual(process.returncode,0);self.assertFalse((output/'interruption.json').exists())
            self.assertFalse((workspace/'apps-pending.json').exists());self.assertFalse(modeled)
        else:
            self.assertEqual(process.returncode,-signal.SIGKILL);self.assertTrue(modeled)
            X.interruption(value,'a'*64,before)
            self.assertEqual(json.loads((output/'interruption.json').read_bytes()),value)
            self.assertEqual((workspace/'apps-pending.json').read_bytes(),X.encoded(pending))
            self.assertTrue((root/'var/lib/pacman/db.lck').is_file());self.assertTrue(workspace.is_dir())
            self.assertEqual(value['disposal'],'ONLY_OUTER_OWNER_AFTER_CONSUMER_ABSENCE')
            self.assertEqual(value['raw_lock'],'NOT_READ_OR_DELETED')
            for side,row in value['outputs'].items():self.assertEqual(row,dict(path='interrupted-'+side,**X.pin((output/('interrupted-'+side)).read_bytes())))
        print(json.dumps(dict(scope='REAL_INERT_SIGNALS_REAP_ONLY_SYNTHETIC_PENDING_LOCK_NOT_AUTH_OR_ALPM',
              test=self._testMethodName,real_private_child=True,direct_child_reaped=True,group_absent=True,
              config_held=True,workspace_retained=True,outcome='EARLY_EXIT_REFUSED'if early else'UNKNOWN_NOT_ROLLBACK',
              native='NOT_RUN',hardware='NOT_RUN'),sort_keys=True))

    def test_exact_original_interrupted_real_inert_signals_reap_retained_uncertainty(self):
        self.inert_interruption()

    def test_exact_original_interrupted_real_inert_early_exit_refuses(self):
        self.inert_interruption(early=True)


if __name__=='__main__':unittest.main(verbosity=2)
