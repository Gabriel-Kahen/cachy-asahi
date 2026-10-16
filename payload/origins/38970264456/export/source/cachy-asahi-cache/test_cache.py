#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real tempfile CLI and bounded failure controls; no host cache or package actors."""
import hashlib,importlib.machinery,importlib.util,json,os,signal,stat,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
TOOL=HERE/'cachy-asahi-cache'
loader=importlib.machinery.SourceFileLoader('cache_candidate',str(TOOL));spec=importlib.util.spec_from_loader(loader.name,loader);C=importlib.util.module_from_spec(spec);loader.exec_module(C)
A='sample-1-1-aarch64.pkg.tar.zst';P='rollback-2-1-aarch64.pkg.tar.xz'


class Cache(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.cache=self.root/'var/cache/pacman/pkg';self.db=self.root/'var/lib/pacman';self.out=self.root/'out'
        for p in (self.cache,self.db,self.out):p.mkdir(mode=0o700,parents=True)
        (self.db/'local').mkdir(mode=0o700);(self.db/'local/ALPM_DB_VERSION').write_text('9\n')
        for name,raw in ((A,b'archive data'),(A+'.sig',b'candidate sig'),(P,b'protected archive'),(P+'.sig',b'protected sig'),('unrelated.txt',b'preserve unrelated')):(self.cache/name).write_bytes(raw)
        (self.db/'sentinel').write_text('preserve database')
        row=lambda name:dict(bytes=(self.cache/name).stat().st_size,sha256=hashlib.sha256((self.cache/name).read_bytes()).hexdigest())
        self.policy=self.root/'protect.json';self.policy.write_text(json.dumps(dict(schema_version=1,cache=str(self.cache),protected={P:dict(**row(P),signature=row(P+'.sig'))})));self.policy.chmod(0o600);self.number=0

    def preservation(self):
        return {str(p.relative_to(self.root)):(p.read_bytes(),stat.S_IMODE(p.stat().st_mode),p.stat().st_ino) for d in (self.cache,self.db) for p in d.rglob('*') if p.is_file() and not p.is_symlink() and p.name!='db.lck'}

    def cli(self,*args,code=0):
        result=subprocess.run([sys.executable,'-B',str(TOOL),*map(str,args)],text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,code,result.stdout+result.stderr)
        return json.loads(result.stdout)

    def plan(self,*extra,select=A,code=0,output=None):
        self.number+=1;output=output or self.out/('plan'+str(self.number)+'.json')
        args=['plan','--root',self.root,'--cache',self.cache,'--dbpath',self.db,'--protect',self.policy,'--output',output]
        if select is not None:args+=['--select',select]
        result=self.cli(*args,*extra,code=code);return output,result

    def test_real_cli_confirmed_apply_removes_only_selected_objects(self):
        before=self.preservation();listed=self.cli('list','--cache',self.cache,'--dbpath',self.db,'--protect',self.policy)
        self.assertEqual(listed['status'],'READ_ONLY_CACHE_INVENTORY');self.assertIn('unrelated.txt',listed['cache']['ignored_names'])
        path,result=self.plan();self.assertEqual(result['status'],'NOT_APPLIED');self.assertTrue(result['apply_supported'])
        plan=json.loads(path.read_bytes());self.assertEqual(set(plan['selected_objects']),{A,A+'.sig'})
        self.assertEqual(set(plan['protection']['objects']),{P,P+'.sig'});self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
        self.assertEqual(self.cli('verify',path)['verification'],'PASS_CURRENT_EXACT_SNAPSHOT')
        applied=self.cli('apply',path,'--confirm','REMOVE_SELECTED_CACHE_ARCHIVES','--plan-sha256',result['plan_sha256'],'--quarantine',self.out/'quarantine')
        self.assertEqual(applied['status'],'APPLIED');self.assertIsNone(applied['reclaimed_bytes'])
        self.assertEqual({n:r for n,r in before.items() if Path(n).name not in (A,A+'.sig')},self.preservation())
        self.assertFalse((self.db/'db.lck').exists())

    def test_noop_plan_has_zero_planned_bytes(self):
        path,result=self.plan(select=None);self.assertEqual(result['planned_bytes'],0);self.cli('verify',path)

    def test_protected_archive_and_its_signature_cannot_be_selected(self):
        before=self.preservation();path,_=self.plan(select=P,code=1);self.assertFalse(path.exists());self.assertEqual(before,self.preservation())
        self.plan(select=P+'.sig',code=1)

    def test_protected_hash_missing_archive_and_undeclared_signature_refused(self):
        original=self.policy.read_bytes()
        for kind in ('hash','missing','signature'):
            policy=json.loads(original)
            if kind=='hash':policy['protected'][P]['sha256']='a'*64
            elif kind=='signature':policy['protected'][P]['signature']=None
            else:policy['protected']['absent-1-1-any.pkg.tar.xz']=policy['protected'].pop(P)
            self.policy.write_text(json.dumps(policy));path,_=self.plan(code=1);self.assertFalse(path.exists())
        self.policy.write_bytes(original)

    def test_names_cannot_escape_or_select_globs_or_partial_downloads(self):
        for name in ('../'+A,'/tmp/'+A,'*.pkg.tar.zst',A+'.part',A+'.sig'):
            with self.subTest(name=name):self.plan(select=name,code=1)

    def test_symlink_hardlink_fifo_and_symlink_parent_refused(self):
        extra=self.cache/'unsafe-1-1-any.pkg.tar.xz'
        extra.symlink_to(self.cache/A);self.plan(code=1);extra.unlink()
        os.link(self.cache/A,extra);self.plan(code=1);extra.unlink()
        os.mkfifo(extra);self.plan(code=1);extra.unlink()
        alias=self.root/'alias';alias.symlink_to(self.cache,target_is_directory=True)
        self.cli('list','--cache',alias,'--dbpath',self.db,code=1)

    def test_content_signature_inode_and_mode_drift_reject_stale_plan(self):
        for kind in ('bytes','signature','inode','mode'):
            path,_=self.plan();target=self.cache/(A+'.sig' if kind=='signature' else A);raw=target.read_bytes();mode=stat.S_IMODE(target.stat().st_mode)
            if kind in ('bytes','signature'):target.write_bytes(b'x'*len(raw))
            elif kind=='inode':target.unlink();target.write_bytes(raw)
            else:target.chmod(0o600 if mode!=0o600 else 0o644)
            with self.subTest(kind=kind):self.cli('verify',path,code=1)
            target.write_bytes(raw);target.chmod(mode)

    def test_protected_payload_and_policy_drift_refused(self):
        path,_=self.plan();target=self.cache/P;raw=target.read_bytes();target.write_bytes(raw+b'changed');self.cli('verify',path,code=1);target.write_bytes(raw)
        path,_=self.plan();raw=self.policy.read_bytes();self.policy.unlink();self.policy.write_bytes(raw);self.policy.chmod(0o600);self.cli('verify',path,code=1)

    def test_active_or_unsafe_db_lock_blocks_plan_and_verification(self):
        path,_=self.plan();lock=self.db/'db.lck'
        for kind in ('file','symlink','directory'):
            if kind=='file':lock.write_text('active or stale is not proved')
            elif kind=='symlink':lock.symlink_to(self.db/'sentinel')
            else:lock.mkdir()
            with self.subTest(kind=kind):
                self.plan(code=1);self.cli('verify',path,code=1)
                self.assertEqual(self.cli('list','--cache',self.cache,'--dbpath',self.db)['transaction']['state'],'ACTIVE_OR_UNCERTAIN_DB_LOCK_PRESENT')
            if kind=='directory':lock.rmdir()
            else:lock.unlink()

    def test_absent_lock_never_claims_transaction_exclusion(self):
        _,value=self.plan();self.assertTrue(value['apply_supported'])
        state=C.transaction(self.db);self.assertFalse(state['exclusion_proved']);self.assertIn('UNPROVED',state['state'])

    def test_unsafe_or_existing_outputs_preserve_existing_files(self):
        for path in (self.cache/'plan.json',self.db/'plan.json',self.policy):
            with self.subTest(path=path):self.plan(output=path,code=1)
        existing=self.out/'exists.json';existing.write_bytes(b'preserve existing');self.plan(output=existing,code=1);self.assertEqual(existing.read_bytes(),b'preserve existing')
        alias=self.root/'output-alias';alias.symlink_to(self.out,target_is_directory=True);self.plan(output=alias/'plan.json',code=1)
        self.out.chmod(0o777);self.plan(code=1);self.out.chmod(0o700)

    def test_missing_duplicate_or_insecure_json_policy_refused(self):
        original=self.policy.read_bytes();self.policy.chmod(0o644);self.plan(code=1);self.policy.chmod(0o600)
        self.policy.write_text('{"schema_version":1,"schema_version":1}');self.plan(code=1)
        self.policy.write_bytes(original);self.policy.unlink();self.plan(code=1)

    def test_changed_metadata_during_scan_is_detected(self):
        original=C.snapshot;changed=False
        def drift(fd,name,*args,**kwargs):
            nonlocal changed
            result=original(fd,name,*args,**kwargs)
            if name==A and not changed:changed=True;(self.cache/A).chmod(0o600)
            return result
        with patch.object(C,'snapshot',side_effect=drift),self.assertRaisesRegex(C.Refused,'metadata drift'):C.inventory(self.cache)

    def test_fixed_entry_and_byte_budgets_refuse(self):
        with patch.object(C,'MAX_ENTRIES',1),self.assertRaises(C.Refused):C.inventory(self.cache)
        with patch.object(C,'MAX_TOTAL',1),self.assertRaises(C.Refused):C.inventory(self.cache)

    def test_sigkill_before_publication_leaves_cache_policy_and_database_intact(self):
        before=self.preservation();policy=self.policy.read_bytes();output=self.out/'interrupted.json';ready=self.root/'ready'
        script='''import importlib.machinery,importlib.util,sys,signal
from pathlib import Path
loader=importlib.machinery.SourceFileLoader('cache_child',sys.argv[1]);spec=importlib.util.spec_from_loader(loader.name,loader);m=importlib.util.module_from_spec(spec);loader.exec_module(m)
original=m.publish
def checkpoint(_):
    Path(sys.argv[6]).write_text('durable temporary staged')
    signal.pause()
def interrupted(path,raw,forbidden):return original(path,raw,forbidden,checkpoint)
m.publish=interrupted
raise SystemExit(m.main(['plan','--root',sys.argv[8],'--cache',sys.argv[2],'--dbpath',sys.argv[3],'--protect',sys.argv[4],'--output',sys.argv[5],'--select',sys.argv[7]]))
'''
        child=subprocess.Popen([sys.executable,'-B','-c',script,str(TOOL),str(self.cache),str(self.db),str(self.policy),str(output),str(ready),A,str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        try:
            until=time.monotonic()+5
            while not ready.exists() and child.poll() is None and time.monotonic()<until:time.sleep(.01)
            self.assertTrue(ready.exists(),'child did not reach fault-injection checkpoint')
            os.killpg(child.pid,signal.SIGKILL);child.communicate(timeout=3)
            with self.assertRaises(ProcessLookupError):os.killpg(child.pid,0)
            self.assertFalse(output.exists());self.assertEqual(before,self.preservation());self.assertEqual(policy,self.policy.read_bytes())
            self.assertEqual(len(list(self.out.glob('.caa-cache-*.tmp'))),1)
            path,_=self.plan(output=output);self.cli('verify',path)
        finally:
            if child.poll() is None:os.killpg(child.pid,signal.SIGKILL);child.communicate(timeout=3)


    def apply_direct(self,path,receipt,checkpoint=None,name='quarantine'):
        return C.apply(path,receipt['plan_sha256'],self.out/name,checkpoint)

    def test_real_alpm_holder_refuses_second_process_without_clearing_its_lock(self):
        path,receipt=self.plan();held=C.AlpmLock(self.root,self.db);held.acquire()
        try:
            identity=C.metadata((self.db/'db.lck').lstat());before=self.preservation()
            value=self.cli('apply',path,'--confirm','REMOVE_SELECTED_CACHE_ARCHIVES','--plan-sha256',receipt['plan_sha256'],'--quarantine',self.out/'q',code=1)
            self.assertIn('real ALPM transaction refused',value['reason']);self.assertEqual(identity,C.metadata((self.db/'db.lck').lstat()))
            self.assertEqual(before,self.preservation());self.assertFalse((self.out/'q').exists())
        finally:held.release()
        self.assertFalse((self.db/'db.lck').exists())

    def test_noop_apply_takes_real_lock_and_preserves_all_database_and_cache_files(self):
        path,receipt=self.plan(select=None);before=self.preservation();value=self.apply_direct(path,receipt)
        self.assertEqual(value['status'],'APPLIED');self.assertEqual(value['removed_logical_bytes'],0)
        self.assertEqual(value['removed_objects'],[]);self.assertIsNone(value['reclaimed_bytes']);self.assertEqual(before,self.preservation())
        self.assertFalse((self.db/'db.lck').exists())

    def test_confirmation_hash_and_fresh_quarantine_are_required(self):
        path,receipt=self.plan();before=self.preservation()
        value=C.apply(path,'a'*64,self.out/'wrong');self.assertNotEqual(value['status'],'APPLIED');self.assertFalse((self.out/'wrong').exists())
        q=self.out/'exists';q.mkdir();(q/'foreign').write_bytes(b'keep')
        value=C.apply(path,receipt['plan_sha256'],q);self.assertNotEqual(value['status'],'APPLIED');self.assertEqual((q/'foreign').read_bytes(),b'keep')
        self.assertEqual(before,self.preservation());self.assertFalse((self.db/'db.lck').exists())

    def test_unrelated_root_or_unsafe_quarantine_cannot_claim_exclusion(self):
        path,receipt=self.plan();before=self.preservation()
        for q in (self.cache/'q',self.db/'q'):
            value=C.apply(path,receipt['plan_sha256'],q)
            self.assertNotEqual(value['status'],'APPLIED');self.assertFalse(q.exists())
        alias=self.root/'alias';alias.symlink_to(self.out,target_is_directory=True)
        value=C.apply(path,receipt['plan_sha256'],alias/'q');self.assertNotEqual(value['status'],'APPLIED')
        plan=json.loads(path.read_bytes());plan['root']=C.root_identity(self.out);path.write_text(json.dumps(plan));digest=hashlib.sha256(path.read_bytes()).hexdigest()
        value=C.apply(path,digest,self.out/'wrong-root');self.assertIn('conventional',value['reason'])
        self.assertFalse((self.db/'db.lck').exists());self.assertEqual(before,self.preservation())

    def test_plan_and_all_inputs_are_revalidated_under_real_lock(self):
        path,receipt=self.plan();before=self.preservation()
        def drift(phase):
            if phase=='locked':
                self.assertTrue((self.db/'db.lck').exists());(self.cache/A).write_bytes(b'changed by external test writer')
        value=self.apply_direct(path,receipt,drift)
        self.assertNotEqual(value['status'],'APPLIED');self.assertFalse((self.db/'db.lck').exists())
        self.assertEqual((self.cache/P).read_bytes(),before[str((self.cache/P).relative_to(self.root))][0])
        self.assertEqual(json.loads((self.out/'quarantine/journal.json').read_bytes())['moved'],{})

    def test_cache_replacement_between_stat_and_move_is_retained_never_purged(self):
        path,receipt=self.plan();changed=False;saved=self.root/'original-archive'
        def drift(phase):
            nonlocal changed
            if phase=='before_move' and not changed:
                changed=True;(self.cache/A).rename(saved);(self.cache/A).write_bytes(b'foreign replacement')
        value=self.apply_direct(path,receipt,drift);self.assertNotEqual(value['status'],'APPLIED')
        self.assertIn('moved object differs',value['reason']);self.assertEqual((self.out/'quarantine'/A).read_bytes(),b'foreign replacement')
        self.assertEqual(saved.read_bytes(),b'archive data');self.assertEqual((self.cache/(A+'.sig')).read_bytes(),b'candidate sig')
        self.assertIsNone(value['removed_logical_bytes']);self.assertIsNone(value['reclaimed_bytes'])
        journal=json.loads((self.out/'quarantine/journal.json').read_bytes());self.assertEqual(journal['intent'],dict(action='MOVE',name=A))

    def test_no_replace_move_preserves_foreign_quarantine_destination(self):
        path,receipt=self.plan();inserted=False
        def collide(phase):
            nonlocal inserted
            if phase=='before_move' and not inserted:
                inserted=True;(self.out/'quarantine'/A).write_bytes(b'foreign destination')
        value=self.apply_direct(path,receipt,collide)
        self.assertNotEqual(value['status'],'APPLIED');self.assertEqual((self.cache/A).read_bytes(),b'archive data')
        self.assertEqual((self.out/'quarantine'/A).read_bytes(),b'foreign destination')

    def test_protected_change_before_purge_retains_every_selected_object(self):
        path,receipt=self.plan()
        def drift(phase):
            if phase=='verified_all':(self.cache/P).write_bytes(b'external protected change')
        value=self.apply_direct(path,receipt,drift);self.assertNotEqual(value['status'],'APPLIED')
        self.assertEqual((self.out/'quarantine'/A).read_bytes(),b'archive data');self.assertEqual((self.out/'quarantine'/(A+'.sig')).read_bytes(),b'candidate sig')
        self.assertEqual((self.cache/(P+'.sig')).read_bytes(),b'protected sig');self.assertIsNone(value['reclaimed_bytes'])

    def test_quarantine_payload_or_journal_drift_cannot_be_purged_or_overwritten(self):
        for kind in ('payload','journal','unknown'):
            path,receipt=self.plan();q=self.out/kind
            def drift(phase):
                if phase=='verified_all':
                    target=q/(A if kind=='payload' else 'journal.json' if kind=='journal' else 'foreign')
                    target.write_bytes(b'foreign bytes')
            value=self.apply_direct(path,receipt,drift,name=kind)
            self.assertNotEqual(value['status'],'APPLIED');self.assertIsNone(value['reclaimed_bytes'])
            if kind=='journal':self.assertEqual((q/'journal.json').read_bytes(),b'foreign bytes')
            else:self.assertTrue((q/A).exists())
            # Restore test-owned candidate fixtures for the next isolated apply.
            for name,raw in ((A,b'archive data'),(A+'.sig',b'candidate sig')):(self.cache/name).write_bytes(raw)

    def test_unknown_replaced_lock_is_never_raw_removed_or_api_released(self):
        path,receipt=self.plan();foreign=None
        def replace(phase):
            nonlocal foreign
            if phase=='locked':
                lock=self.db/'db.lck';lock.rename(self.root/'interrupted-own-lock');lock.touch(mode=0o000)
                foreign=C.metadata(lock.lstat())
        value=self.apply_direct(path,receipt,replace)
        self.assertEqual(value['lock'],'RETAINED_UNCERTAIN_SEPARATE_RECOVERY_REQUIRED')
        self.assertEqual(C.metadata((self.db/'db.lck').lstat()),foreign);self.assertTrue((self.root/'interrupted-own-lock').exists())
        self.assertTrue((self.cache/A).exists());self.assertEqual(json.loads((self.out/'quarantine/journal.json').read_bytes())['moved'],{})
        # Fixture teardown removes this isolated root; it is not product recovery.

    def test_failed_api_release_reports_uncertainty_and_no_reclaimed_or_rollback_claim(self):
        path,receipt=self.plan();owned=[];original=C.AlpmLock.release
        def fail(handle):
            owned.append(handle);handle.release_attempted=True;raise OSError('injected API release failure')
        with patch.object(C.AlpmLock,'release',fail):value=self.apply_direct(path,receipt)
        self.assertNotEqual(value['status'],'APPLIED');self.assertIsNone(value['removed_logical_bytes']);self.assertIsNone(value['reclaimed_bytes'])
        self.assertEqual(len(owned),1);self.assertTrue((self.db/'db.lck').exists())
        original(owned[0])  # Same live original API handle, test teardown only.

    def test_sigkill_during_move_and_purge_retains_real_lock_and_durable_intent(self):
        for phase in ('moved','purged'):
            path,receipt=self.plan();q=self.out/phase;ready=self.root/('ready-'+phase);before=self.preservation()
            script='''import importlib.machinery,importlib.util,sys,signal,json
from pathlib import Path
loader=importlib.machinery.SourceFileLoader('apply_child',sys.argv[1]);spec=importlib.util.spec_from_loader(loader.name,loader);m=importlib.util.module_from_spec(spec);loader.exec_module(m)
def pause(phase):
    if phase==sys.argv[5]:
        Path(sys.argv[6]).write_text('real lock and durable intent reached')
        signal.pause()
result=m.apply(Path(sys.argv[2]),sys.argv[3],Path(sys.argv[4]),pause)
print(json.dumps(result),flush=True)
'''
            child=subprocess.Popen([sys.executable,'-B','-c',script,str(TOOL),str(path),receipt['plan_sha256'],str(q),phase,str(ready)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:
                until=time.monotonic()+5
                while not ready.exists() and child.poll() is None and time.monotonic()<until:time.sleep(.01)
                self.assertTrue(ready.exists(),'child failed before real interruption checkpoint')
                lock_id=C.metadata((self.db/'db.lck').lstat());os.killpg(child.pid,signal.SIGKILL);child.communicate(timeout=3)
                with self.assertRaises(ProcessLookupError):os.killpg(child.pid,0)
                self.assertEqual(lock_id,C.metadata((self.db/'db.lck').lstat()))
                journal=json.loads((q/'journal.json').read_bytes());self.assertEqual(journal['intent']['action'],'MOVE' if phase=='moved' else 'PURGE')
                self.assertEqual((self.cache/P).read_bytes(),before[str((self.cache/P).relative_to(self.root))][0])
                retry=self.apply_direct(path,receipt,name='retry-'+phase);self.assertNotEqual(retry['status'],'APPLIED')
                self.assertEqual(lock_id,C.metadata((self.db/'db.lck').lstat()))
            finally:
                if child.poll() is None:os.killpg(child.pid,signal.SIGKILL);child.communicate(timeout=3)
            # A new entire temporary target for the next SIGKILL scenario. Never
            # remove a stale lock as an application recovery operation.
            if phase=='moved':
                self.tmp.cleanup();self.setUp()



if __name__=='__main__':unittest.main()
