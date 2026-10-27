#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real readonly metadata/empty ALPM lock; model removals, never real ALPM removal."""
import contextlib,importlib.util,io,json,os,shutil,signal,stat,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('remove_candidate',HERE/'remove.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R);O=R.O

class Model(R.Transaction):
    instances=[];hook=None;prepare_hook=None;fail=None;expanded=False
    def __init__(self,root,db):super().__init__(root,db);self.root=root;self.calls=[];self.selected={};type(self).instances.append(self)
    def begin(self):
        if type(self).hook:type(self).hook(self)
        super().begin();self.calls.append('begin')
    def files(self,n,v):return ['usr/','usr/share/','usr/share/orphans3-fixture/',f'usr/share/orphans3-fixture/{n}']
    def declarative(self,n,v):
        if self.fail=='declarative':raise O.Refused('scriptlet/backup unsupported')
    def remove(self,n,v):self.calls.append(('remove',n,v));self.selected[n]=v
    def prepare(self):
        self.calls.append('prepare')
        if type(self).prepare_hook:type(self).prepare_hook(self)
        if self.fail=='prepare':raise O.Refused('model prepare error')
        return {},dict(self.selected,**({'unexpected':'1-1'} if self.expanded else {}))
    def commit(self):
        self.calls.append('commit')
        if self.fail=='commit':raise O.Refused('model commit error')
        if self.fail=='interrupt':raise InterruptedError('model interrupted commit')
        for n,v in self.selected.items():
            # Temporary fixture edits: no libalpm package mutation API is called.
            shutil.rmtree(self.db/'local'/(n+'-'+v));(self.root/'usr/share/orphans3-fixture'/n).unlink()
    def cleanup(self,r):
        self.calls.append('cleanup');super().cleanup(r)
        if self.fail=='cleanup':r['cleanup_errors'].append('model cleanup failure')

class Removal(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name);self.root=self.base/'root';self.root.mkdir(mode=0o700)
        self.db=self.root/'var/lib/pacman';(self.db/'local').mkdir(parents=True);(self.db/'local/ALPM_DB_VERSION').write_text('9\n');self.out=self.base/'out';self.out.mkdir(mode=0o700)
        (self.root/'usr/share/orphans3-fixture').mkdir(parents=True);self.count=0;Model.instances=[];Model.hook=None;Model.prepare_hook=None;Model.fail=None;Model.expanded=False
    def package(self,n,reason=1,depends=(),optional=()):
        d=self.db/'local'/(n+'-1-1');d.mkdir();f={'NAME':[n],'VERSION':['1-1'],'REASON':[str(reason)],'DEPENDS':list(depends),'OPTDEPENDS':list(optional)}
        (d/'desc').write_text(''.join('%'+k+'%\n'+'\n'.join(v)+'\n\n' for k,v in f.items() if v));(d/'files').write_text('%FILES%\nusr/\nusr/share/\nusr/share/orphans3-fixture/\nusr/share/orphans3-fixture/'+n+'\n\n');(self.root/'usr/share/orphans3-fixture'/n).write_text('payload '+n);return d
    def planned(self,names=('test-leaf',),protect=()):
        self.count+=1;a=self.out/('assessment'+str(self.count));report,_=O.inspect(self.root,self.db,list(protect));O.publish(a,report,self.db);p=self.out/('plan'+str(self.count));O.plan(a,list(names),p)
        return SimpleNamespace(plan=p,plan_sha256=O.digest(p.read_bytes()),select=list(names),result=self.out/('result'+str(self.count)),timeout_seconds=2)
    def run_model(self,a):
        receipts=[];r=R.execute(a,lambda value:receipts.append(json.loads(json.dumps(value))),factory=Model);self.assertEqual(receipts[-1],r);return r
    def test_model_success_exact_selection_cleanup_and_unselected_preservation(self):
        self.package('test-leaf');d=self.package('test-other',0);a=self.planned();before=(d/'desc').read_bytes();payload=(self.root/'usr/share/orphans3-fixture/test-other').read_bytes();r=self.run_model(a)
        self.assertEqual(r['status'],'APPLIED',r);self.assertTrue(r['transaction_released']);self.assertTrue(r['handle_released']);self.assertEqual(r['lock_state'],'ABSENT');self.assertEqual(Model.instances[-1].calls,['begin',('remove','test-leaf','1-1'),'prepare','commit','cleanup']);self.assertEqual((d/'desc').read_bytes(),before);self.assertEqual((self.root/'usr/share/orphans3-fixture/test-other').read_bytes(),payload)
    def test_empty_duplicate_unknown_wildcard_and_arguments_refuse_before_adapter(self):
        self.package('test-leaf');a=self.planned()
        for names in ([],['test-leaf']*2,['unknown'],['*'],['--nodeps']):
            a.select=names;self.assertEqual(self.run_model(a)['status'],'REFUSED');self.assertEqual(Model.instances,[])
    def test_stale_database_and_bad_plan_hash_refuse_before_adapter(self):
        d=self.package('test-leaf');a=self.planned();a.plan_sha256='0'*64;self.assertEqual(self.run_model(a)['status'],'REFUSED');a.plan_sha256=O.digest(a.plan.read_bytes());(d/'files').write_text('drift');self.assertEqual(self.run_model(a)['status'],'REFUSED');self.assertEqual(Model.instances,[])
    def test_reason_drift_between_preflight_and_lock_refuses(self):
        d=self.package('test-leaf');a=self.planned()
        def mutate(api):(d/'desc').write_text((d/'desc').read_text().replace('%REASON%\n1','%REASON%\n0'))
        Model.hook=mutate;r=self.run_model(a);self.assertEqual(r['status'],'REFUSED',r);self.assertNotIn('commit',Model.instances[-1].calls);self.assertEqual(r['lock_state'],'ABSENT')
    def test_hard_and_optional_dependency_drift_refuse(self):
        self.package('test-leaf');d=self.package('test-consumer',0)
        for field in ('DEPENDS','OPTDEPENDS'):
            (d/'desc').write_text('%NAME%\ntest-consumer\n\n%VERSION%\n1-1\n\n%REASON%\n0\n\n');a=self.planned()
            def mutate(api):(d/'desc').write_text((d/'desc').read_text()+'%'+field+'%\ntest-leaf\n\n')
            Model.hook=mutate;r=self.run_model(a);self.assertEqual(r['status'],'REFUSED');self.assertNotIn('commit',Model.instances[-1].calls)
    def test_floor_drift_after_preflight_refuses(self):
        self.package('test-leaf');a=self.planned();original=O.floor
        def change(api):O.floor=lambda:original()|{'test-leaf'}
        Model.hook=change
        try:r=self.run_model(a)
        finally:O.floor=original
        self.assertEqual(r['status'],'REFUSED');self.assertNotIn('commit',Model.instances[-1].calls)
    def test_existing_lock_never_removed(self):
        self.package('test-leaf');a=self.planned();p=self.db/'db.lck';p.write_text('foreign\n');before=O.identity(p.stat());r=self.run_model(a);self.assertEqual(r['status'],'REFUSED');self.assertEqual(before,O.identity(p.stat()));self.assertEqual(Model.instances,[])
    def test_expanded_prepare_error_and_scriptlet_refusal_release_lock(self):
        self.package('test-leaf')
        for failure in ('expanded','prepare','declarative'):
            a=self.planned();Model.expanded=failure=='expanded';Model.fail=failure;r=self.run_model(a);self.assertEqual(r['status'],'REFUSED',r);self.assertFalse(r['commit_started']);self.assertTrue(r['transaction_released']);self.assertEqual(r['lock_state'],'ABSENT')
    def test_commit_error_and_interruption_report_unknown_no_retry(self):
        self.package('test-leaf')
        for failure in ('commit','interrupt'):
            a=self.planned();Model.fail=failure;r=self.run_model(a);self.assertEqual(r['status'],'FAILED');self.assertEqual(r['packages_committed'],'UNKNOWN');self.assertTrue(r['commit_started']);self.assertEqual(Model.instances[-1].calls.count('commit'),1);self.assertIn('DO_NOT_RETRY',r['recovery'])
    def test_same_bytes_plan_and_assessment_replacement_refused(self):
        self.package('test-leaf')
        for which in ('plan','assessment'):
            a=self.planned()
            def replace(api):
                p=a.plan if which=='plan' else Path(json.loads(a.plan.read_bytes())['assessment']);q=p.with_suffix('.new');q.write_bytes(p.read_bytes());q.chmod(0o600);q.replace(p)
            Model.prepare_hook=replace;r=self.run_model(a);self.assertEqual(r['status'],'REFUSED');self.assertIn('replaced',r['reason']);self.assertNotIn('commit',Model.instances[-1].calls)
    def test_replaced_lock_retained_without_handle_release(self):
        self.package('test-leaf');a=self.planned();p=self.db/'db.lck'
        def replace(api):q=self.out/'foreign';q.write_text('foreign\n');q.replace(p)
        Model.prepare_hook=replace;r=self.run_model(a);self.assertEqual(r['status'],'FAILED');self.assertEqual(p.read_text(),'foreign\n');self.assertTrue(r['handle_abandoned']);self.assertFalse(r['transaction_released']);self.assertFalse(r['handle_released'])
        # Dispose test-only EMPTY holder after preserving foreign lock evidence.
        api=Model.instances[-1];p.rename(self.out/'retained-foreign');api.lib.alpm_trans_release(api.handle);api.started=False;api.lib.alpm_release(api.handle);api.handle=None
    def test_symlink_hardlink_helper_and_protected_ownership_refuse(self):
        self.package('test-leaf');p=self.root/'usr/share/orphans3-fixture/test-leaf'
        for kind in ('symlink','hardlink','helper','protected'):
            if p.is_symlink() or p.stat().st_nlink!=1:p.unlink();p.write_text('payload')
            q=self.out/'alias'
            if q.exists():q.unlink()
            h=self.root/'usr/bin/ldconfig'
            if h.is_symlink():h.unlink()
            if kind=='symlink':p.unlink();p.symlink_to('/etc/passwd')
            if kind=='hardlink':os.link(p,q)
            if kind=='helper':h.parent.mkdir(exist_ok=True);h.symlink_to('/nonexistent')
            a=self.planned()
            with patch.object(Model,'files',lambda api,n,v:['usr/share/systemd/fake.service']) if kind=='protected' else patch.object(Model,'files',Model.files):r=self.run_model(a)
            self.assertEqual(r['status'],'REFUSED',r);self.assertNotIn('commit',Model.instances[-1].calls)
    def test_cleanup_failure_after_commit_never_reports_success(self):
        self.package('test-leaf');a=self.planned();Model.fail='cleanup';r=self.run_model(a);self.assertEqual(r['status'],'FAILED');self.assertTrue(r['packages_committed']);self.assertTrue(r['cleanup_errors'])
    def test_receipt_noreplace_and_replacement_not_overwritten(self):
        p=self.out/'receipt';r=R.Receipt(p)
        try:
            r.save(R.initial_result());self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
            with self.assertRaises(FileExistsError):R.Receipt(p)
            p.unlink();p.write_text('foreign');p.chmod(0o600)
            with self.assertRaises(O.Refused):r.save(R.initial_result())
            self.assertEqual(p.read_text(),'foreign')
        finally:r.close()
    def test_supervisor_timeout_reaps_term_resistant_worker(self):
        a=SimpleNamespace(timeout_seconds=0.05);receipt=R.Receipt(self.out/'supervisor')
        def blocked(args,save):
            signal.signal(signal.SIGTERM,signal.SIG_IGN);save(dict(R.initial_result(),phase='commit',commit_started=True,packages_committed='UNKNOWN'))
            while True:time.sleep(1)
        try:
            start=time.monotonic();r=R.supervise(a,receipt,work=blocked);self.assertLess(time.monotonic()-start,4);self.assertTrue(r['worker']['reaped']);self.assertEqual(r['worker']['termination'],'TIMEOUT');self.assertEqual(r['worker']['exitcode'],-signal.SIGKILL);self.assertEqual(r['packages_committed'],'UNKNOWN');self.assertEqual(r['status'],'FAILED')
        finally:receipt.close()
    def test_wrapper_preserves_readonly_result(self):
        self.package('test-leaf');r=subprocess.run([sys.executable,'-B',str(HERE/'orphans3'),'assess','--root',str(self.root),'--dbpath',str(self.db)],capture_output=True,text=True,timeout=15);self.assertEqual(r.returncode,0,r.stderr);expected,_=O.inspect(self.root,self.db,[]);self.assertEqual(json.loads(r.stdout),expected)
    def test_supervisor_parent_wait_fault_still_kills_and_reaps(self):
        a=SimpleNamespace(timeout_seconds=2);receipt=R.Receipt(self.out/'wait-fault');original=os.waitpid;calls=[]
        def faulty(pid,flags):
            calls.append(pid)
            if len(calls)==1:raise OSError('injected parent wait fault')
            return original(pid,flags)
        def blocked(args,save):
            while True:time.sleep(1)
        try:
            with patch.object(os,'waitpid',faulty):r=R.supervise(a,receipt,work=blocked)
            self.assertTrue(r['worker']['reaped']);self.assertEqual(r['worker']['termination'],'SUPERVISOR_ERROR');self.assertNotEqual(r['status'],'APPLIED')
        finally:receipt.close()
    def test_receipt_parent_symlink_replacement_refuses(self):
        p=self.out/'parent-receipt';receipt=R.Receipt(p);moved=self.base/'moved'
        try:
            self.out.rename(moved);self.out.symlink_to(moved,target_is_directory=True)
            with self.assertRaises(OSError):receipt.save(R.initial_result())
        finally:receipt.close();self.out.unlink();moved.rename(self.out)
    def test_live_root_refuses_before_transaction(self):
        self.package('test-leaf');a=self.planned();saved,record,assessment=R.read_plan(a.plan,a.plan_sha256,a.select);assessment['root']='/'
        with patch.object(R,'read_plan',return_value=(saved,record,assessment)):r=self.run_model(a)
        self.assertEqual(r['status'],'REFUSED');self.assertIn('offline',r['reason']);self.assertEqual(Model.instances,[])
    def test_real_readonly_adapter_ownership_and_declarative_metadata(self):
        self.package('test-leaf');api=R.Transaction(self.root,self.db);r=R.initial_result()
        try:
            self.assertIn('usr/share/orphans3-fixture/test-leaf',api.files('test-leaf','1-1'));api.declarative('test-leaf','1-1')
        finally:api.cleanup(r)
        self.assertTrue(r['handle_released']);self.assertFalse((self.db/'db.lck').exists())
    def test_parent_receipt_error_after_commit_preserves_true_commit(self):
        self.package('test-leaf');a=self.planned();output=io.StringIO()
        def failed(args,receipt):
            receipt.save(dict(R.initial_result(),commit_started=True,packages_committed=True));raise OSError('postcommit parent output error')
        with patch.object(R,'supervise',failed),contextlib.redirect_stdout(output):
            code=R.main([str(a.plan),'--plan-sha256',a.plan_sha256,'--select','test-leaf','--result',str(a.result)])
        r=json.loads(output.getvalue());self.assertEqual(code,1);self.assertEqual(r['status'],'FAILED');self.assertTrue(r['packages_committed']);self.assertTrue(r['commit_started'])
    def test_audio_payload_owned_by_nonfloor_leaf_refuses(self):
        self.package('test-leaf')
        for path in ('usr/share/alsa/evil','usr/share/pipewire/evil','usr/share/wireplumber/evil','usr/bin/speakersafetyd','usr/bin/asahi-audio'):
            a=self.planned()
            with patch.object(Model,'files',lambda api,n,v:[path]):r=self.run_model(a)
            self.assertEqual(r['status'],'REFUSED');self.assertNotIn('commit',Model.instances[-1].calls)
    def test_unselected_owned_empty_shared_directory_refuses_before_commit(self):
        self.package('test-leaf');self.package('test-other',0);a=self.planned()
        original=Model.files
        def files(api,n,v):return original(api,n,v) if n=='test-leaf' else ['usr/','usr/share/','usr/share/orphans3-fixture/']
        with patch.object(Model,'files',files):r=self.run_model(a)
        self.assertEqual(r['status'],'REFUSED');self.assertIn('empty directory',r['reason']);self.assertNotIn('commit',Model.instances[-1].calls)

class ABI(unittest.TestCase):
    def test_actual_adapter_remove_prepare_commit_calls_fixed_abi(self):
        calls=[]
        class Library:
            def alpm_get_localdb(self,h):calls.append(('local',h));return 12
            def alpm_db_get_pkg(self,d,n):calls.append(('lookup',d,n));return 13
            def alpm_pkg_get_version(self,p):return b'2-1'
            def alpm_remove_pkg(self,h,p):calls.append(('remove',h,p));return 0
            def alpm_trans_prepare(self,h,d):calls.append(('prepare',h));return 0
            def alpm_trans_get_add(self,h):return 'add'
            def alpm_trans_get_remove(self,h):return 'remove'
            def alpm_trans_commit(self,h,d):calls.append(('commit',h));return 0
        api=R.Transaction.__new__(R.Transaction);api.lib=Library();api.handle=11;api.packages=lambda head:{} if head=='add' else {'leaf':'2-1'}
        api.remove('leaf','2-1');self.assertEqual(api.prepare(),({}, {'leaf':'2-1'}));api.commit();self.assertEqual(calls,[('local',11),('lookup',12,b'leaf'),('remove',11,13),('prepare',11),('commit',11)]);self.assertEqual(R.FLAGS,(1<<7)|(1<<10))
        with self.assertRaisesRegex(O.Refused,'identity changed'):api.remove('leaf','wrong')
    def test_actual_begin_fixed_flags_release_failure_abandons_handle(self):
        calls=[]
        class Library:
            def alpm_trans_init(self,h,flags):calls.append(('init',flags));return 0
            def alpm_trans_release(self,h):calls.append(('release',h));return -1
            def alpm_release(self,h):calls.append(('handle',h));return 0
            def alpm_errno(self,h):return 1
            def alpm_strerror(self,e):return b'model release failure'
        api=R.Transaction.__new__(R.Transaction);api.lib=Library();api.handle=11;api.started=False;api.db=Path('/unused');api.lock=None
        class Lock:
            def check(self):calls.append('lock-check')
        with patch.object(R,'OwnedLock',return_value=Lock()):api.begin()
        r=R.initial_result();api.cleanup(r);self.assertEqual(calls,[('init',R.FLAGS),'lock-check',('release',11)]);self.assertTrue(r['handle_abandoned']);self.assertFalse(r['handle_released']);self.assertTrue(r['cleanup_errors'])

if __name__=='__main__':unittest.main()
