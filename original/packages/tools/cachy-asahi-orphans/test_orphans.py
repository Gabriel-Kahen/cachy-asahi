#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real libalpm readonly temporary-database controls; no package operations."""
import ast,ctypes,hashlib,importlib.machinery,importlib.util,json,os,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

HERE=Path(__file__).resolve().parent;TOOL=HERE/'cachy-asahi-orphans'
loader=importlib.machinery.SourceFileLoader('orphan_candidate',str(TOOL));spec=importlib.util.spec_from_loader(loader.name,loader);M=importlib.util.module_from_spec(spec);loader.exec_module(M)


class Orphans(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.db=self.root/'var/lib/pacman';self.out=self.root/'out'
        (self.db/'local').mkdir(mode=0o700,parents=True);self.out.mkdir(mode=0o700);(self.db/'local/ALPM_DB_VERSION').write_text('9\n');self.count=0
    def package(self,name,reason=1,version='1-1',depends=(),optional=(),provides=()):
        directory=self.db/'local'/(name+'-'+version);directory.mkdir()
        fields={'NAME':[name],'VERSION':[version],'REASON':[str(reason)],'DEPENDS':list(depends),'OPTDEPENDS':list(optional),'PROVIDES':list(provides)}
        (directory/'desc').write_text(''.join('%'+key+'%\n'+'\n'.join(values)+'\n\n' for key,values in fields.items() if values));(directory/'files').write_bytes(b'');return directory
    def state(self):
        return {str(p.relative_to(self.db)):(p.read_bytes(),M.identity(p.stat())) for p in self.db.rglob('*') if p.is_file() and p.name!='db.lck'}
    def cli(self,*args,code=0):
        result=subprocess.run([sys.executable,'-B',str(TOOL),*map(str,args)],text=True,capture_output=True,timeout=15);self.assertEqual(result.returncode,code,result.stdout+result.stderr);return json.loads(result.stdout)
    def assessment(self,protect=()):
        self.count+=1;path=self.out/('assessment'+str(self.count)+'.json');args=['assess','--root',self.root,'--dbpath',self.db,'--output',path]
        for name in protect:args+=['--protect',name]
        self.cli(*args);return path,json.loads(path.read_bytes())
    def plan(self,assessment,names=(),code=0):
        self.count+=1;path=self.out/('plan'+str(self.count)+'.json');args=['plan',assessment,'--output',path]
        for name in names:args+=['--select',name]
        result=self.cli(*args,code=code);return path,result
    def holder(self):
        # Transaction API appears only in this test counterpart. The product
        # exposes no transaction or package-mutating functions.
        api=M.Installed(self.root,self.db)
        for name in ('alpm_trans_init','alpm_trans_release'):
            f=getattr(api.lib,name);f.argtypes=[ctypes.c_void_p,ctypes.c_int] if name.endswith('init') else [ctypes.c_void_p];f.restype=ctypes.c_int
        self.assertEqual(api.lib.alpm_trans_init(api.handle,0),0);return api
    def release(self,api):self.assertEqual(api.lib.alpm_trans_release(api.handle),0);api.close()

    def test_real_cli_explicit_dependency_noop_selected_plan_and_verify_preserve_db(self):
        self.package('sample-leaf');self.package('sample-manual',0);before=self.state()
        path,report=self.assessment();self.assertEqual(report['candidates'],['sample-leaf']);self.assertEqual(report['packages']['sample-manual']['reason'],'explicit')
        self.assertEqual(report['packages']['sample-leaf']['reason'],'dependency');self.assertFalse(report['apply_supported'])
        plan,result=self.plan(path,['sample-leaf']);self.assertEqual(result['status'],'NOT_APPLIED');self.cli('verify',plan)
        empty,_=self.plan(path);self.assertEqual(json.loads(empty.read_bytes())['selected'],{});self.cli('verify',empty)
        self.assertEqual(before,self.state());self.assertFalse((self.db/'db.lck').exists())
        self.assertEqual(stat.S_IMODE(plan.stat().st_mode),0o600)

    def test_versioned_provides_and_actual_requiredby_are_resolved_by_libalpm(self):
        self.package('sample-provider',version='3-1',provides=['sample-virtual=2'])
        self.package('sample-oldprovider',provides=['sample-virtual=1'])
        self.package('sample-consumer',0,depends=['sample-virtual>=2'])
        path,r=self.assessment();self.assertEqual(r['packages']['sample-provider']['required_by'],['sample-consumer'])
        self.assertEqual(r['packages']['sample-oldprovider']['required_by'],[]);self.assertTrue(r['packages']['sample-oldprovider']['candidate'])
        self.assertEqual(r['packages']['sample-consumer']['satisfiers']['depends']['sample-virtual>=2'],'sample-provider')
        self.plan(path,['sample-provider'],code=1);self.plan(path,['sample-oldprovider'])

    def test_optional_requiredby_description_and_absent_optional_are_conservative(self):
        self.package('sample-helper',version='2-1');self.package('sample-app',0,optional=['sample-helper>=2: feature description','sample-absent: optional not installed'])
        path,r=self.assessment();helper=r['packages']['sample-helper'];self.assertEqual(helper['required_by'],[]);self.assertEqual(helper['optional_required_by'],['sample-app']);self.assertFalse(helper['candidate'])
        self.assertEqual(r['broken_dependencies'],[]);self.plan(path,['sample-helper'],code=1)

    def test_dependency_cycles_are_not_automatically_collected(self):
        self.package('cycle-a',depends=['cycle-b']);self.package('cycle-b',depends=['cycle-a'])
        path,r=self.assessment();self.assertEqual(r['candidates'],[]);self.assertEqual(r['packages']['cycle-a']['required_by'],['cycle-b'])
        self.plan(path,['cycle-a','cycle-b'],code=1)

    def test_simultaneous_provider_selection_checks_remaining_dependency_graph(self):
        self.package('provider-one',provides=['virtual-interface=2']);self.package('provider-two',provides=['virtual-interface=2']);self.package('consumer',0,depends=['virtual-interface>=2'])
        _,single=M.inspect(self.root,self.db,[],['provider-one']);self.assertEqual(single,[])
        _,both=M.inspect(self.root,self.db,[],['provider-one','provider-two']);self.assertEqual(both,[dict(package='consumer',dependency='virtual-interface>=2',kind='depends')])
        path,_=self.assessment();self.plan(path,['provider-one','provider-two'],code=1)

    def test_simultaneous_loss_of_satisfied_optional_dependency_is_checked(self):
        self.package('optional-one',provides=['optional-virtual=3']);self.package('optional-two',provides=['optional-virtual=3']);self.package('optional-consumer',0,optional=['optional-virtual>=2: retained feature'])
        _,lost=M.inspect(self.root,self.db,[],['optional-one','optional-two']);self.assertEqual(len(lost),1);self.assertEqual(lost[0]['kind'],'optdepends')

    def test_satisfier_memo_is_bounded_to_each_assessment_and_caches_absence(self):
        self.package('memo-provider',provides=['memo-virtual=2'])
        for name in ('memo-first','memo-second'):
            self.package(name,0,depends=['memo-virtual>=2'],optional=['memo-absent: unavailable '+name])
        original=M.Installed.satisfier;calls=[]
        def record(api,head,text):calls.append((head,text));return original(api,head,text)
        with patch.object(M.Installed,'satisfier',record):
            first,lost=M.inspect(self.root,self.db,[]);self.assertEqual(lost,[])
            self.assertEqual(len(calls),3);self.assertEqual(sum(text=='memo-absent' for _,text in calls),1)
            again,lost=M.inspect(self.root,self.db,[]);self.assertEqual(first,again);self.assertEqual(len(calls),6)
        self.assertEqual(first['packages']['memo-first']['satisfiers']['optdepends'],{'memo-absent: unavailable memo-first':None})
        for cap,expected in ((0,6),(1,4)):
            calls.clear()
            with patch.object(M,'MAX_SATISFIERS',cap),patch.object(M.Installed,'satisfier',record):
                bounded,lost=M.inspect(self.root,self.db,[])
            self.assertEqual(bounded,first);self.assertEqual(lost,[]);self.assertEqual(len(calls),expected)

    def test_memo_keeps_full_and_selected_remaining_provider_lists_separate(self):
        self.package('memo-provider',provides=['memo-virtual=2'])
        for name in ('memo-first','memo-second'):self.package(name,0,depends=['memo-virtual>=2'])
        report,lost=M.inspect(self.root,self.db,[],['memo-provider'])
        self.assertEqual([row['package'] for row in lost],['memo-first','memo-second'])
        for name in ('memo-first','memo-second'):
            self.assertEqual(report['packages'][name]['satisfiers']['depends']['memo-virtual>=2'],'memo-provider')
        path,_=self.assessment();self.plan(path,['memo-provider'],code=1)

    def test_existing_base_platform_floor_and_explicit_user_protection(self):
        for name in ('glibc','linux-asahi','asahi-audio','speakersafetyd','custom-important'):self.package(name)
        path,r=self.assessment(['custom-important']);self.assertEqual(r['candidates'],[])
        for name,row in r['packages'].items():self.assertTrue(row['protected']);self.plan(path,[name],code=1)
        self.cli('assess','--root',self.root,'--dbpath',self.db,'--protect','missing-protection-name',code=1)

    def test_unknown_explicit_needed_duplicate_and_path_names_are_not_selected(self):
        self.package('sample-explicit',0);self.package('sample-dependency');self.package('sample-user',0,depends=['sample-dependency'])
        path,_=self.assessment()
        for names in (['missing-name'],['sample-explicit'],['sample-dependency'],['sample-user'],['../escape'],['sample-dependency','sample-dependency']):
            with self.subTest(names=names):self.plan(path,names,code=1)

    def test_broken_installed_dependencies_refuse_any_removal_plan(self):
        self.package('sample-leaf');self.package('sample-broken',0,depends=['missing-interface>=9'])
        path,r=self.assessment();self.assertEqual(len(r['broken_dependencies']),1);self.plan(path,['sample-leaf'],code=1)

    def test_full_db_and_facts_drift_make_assessment_and_plan_stale(self):
        directory=self.package('sample-leaf');path,_=self.assessment();plan,_=self.plan(path,['sample-leaf'])
        sync=self.db/'sync';sync.mkdir();(sync/'local-fixture.db').write_bytes(b'changed opaque sync bytes')
        self.cli('verify',plan,code=1);self.plan(path,['sample-leaf'],code=1)
        path,_=self.assessment();(directory/'desc').write_text((directory/'desc').read_text().replace('%REASON%\n1','%REASON%\n0'));self.plan(path,['sample-leaf'],code=1)

    def test_forged_assessment_dependency_facts_and_plan_versions_refused(self):
        self.package('sample-leaf');path,r=self.assessment();r['packages']['sample-leaf']['version']='999-1';path.write_text(json.dumps(r));self.plan(path,['sample-leaf'],code=1)
        path,_=self.assessment();plan,_=self.plan(path,['sample-leaf']);r=json.loads(plan.read_bytes());r['selected']['sample-leaf']['version']='bad';plan.write_text(json.dumps(r));self.cli('verify',plan,code=1)

    def test_real_concurrent_alpm_holder_is_refused_without_unlock_or_db_writes(self):
        self.package('sample-leaf');before=self.state();api=self.holder()
        try:
            lock=M.identity((self.db/'db.lck').lstat());self.cli('assess','--root',self.root,'--dbpath',self.db,code=1)
            self.assertEqual(lock,M.identity((self.db/'db.lck').lstat()));self.assertEqual(before,self.state())
        finally:self.release(api)

    def test_real_lock_started_during_query_remains_after_readonly_handle_release(self):
        self.package('sample-leaf');held=[]
        def enter():held.append(self.holder())
        try:
            with self.assertRaisesRegex(M.Refused,'existing ALPM lock'):M.inspect(self.root,self.db,[],checkpoint=enter)
            self.assertTrue((self.db/'db.lck').exists())
        finally:
            for api in held:self.release(api)

    def test_mid_read_database_drift_refused(self):
        directory=self.package('sample-leaf')
        def drift():(directory/'files').write_bytes(b'external test writer changed DB')
        with self.assertRaisesRegex(M.Refused,'database drift'):M.inspect(self.root,self.db,[],checkpoint=drift)

    def test_unsafe_db_nodes_and_incomplete_metadata_refused(self):
        directory=self.package('sample-leaf');original=(directory/'files').read_bytes();(directory/'files').unlink();(directory/'files').symlink_to(directory/'desc')
        self.cli('assess','--root',self.root,'--dbpath',self.db,code=1);(directory/'files').unlink();os.link(directory/'desc',directory/'files');self.cli('assess','--root',self.root,'--dbpath',self.db,code=1)
        (directory/'files').unlink();(directory/'files').write_bytes(original);(directory/'desc').write_text('%NAME%\nsample-leaf\n%VERSION%\n1-1\n%REASON%\nunknown\n');self.cli('assess','--root',self.root,'--dbpath',self.db,code=1)
        (directory/'desc').write_text('%NAME%\nsample-leaf\n%VERSION%\n1-1\n%REASON%\n1\n');(self.db/'local/unexpected-record').write_bytes(b'not an ALPM package directory')
        result=self.cli('assess','--root',self.root,'--dbpath',self.db,code=1);self.assertIn('unknown local metadata',result['reason'])

    def test_unsafe_outputs_and_json_inputs_do_not_mutate_database(self):
        self.package('sample-leaf');before=self.state();self.cli('assess','--root',self.root,'--dbpath',self.db,'--output',self.db/'out.json',code=1)
        existing=self.out/'exists';existing.write_text('keep');self.cli('assess','--root',self.root,'--dbpath',self.db,'--output',existing,code=1);self.assertEqual(existing.read_text(),'keep')
        path,_=self.assessment();path.chmod(0o644);self.plan(path,['sample-leaf'],code=1);self.assertEqual(before,self.state())

    def test_snapshot_limits_and_nonconventional_db_are_refused(self):
        self.package('sample-leaf')
        with patch.object(M,'MAX_NODES',2),self.assertRaises(M.Refused):M.database_snapshot(self.db)
        self.cli('assess','--root',self.out,'--dbpath',self.db,code=1)

    def test_runtime_public_abi_contains_no_transaction_or_package_mutation_calls(self):
        tree=ast.parse(TOOL.read_bytes());strings={n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)}
        for name in ('alpm_trans_init','alpm_trans_prepare','alpm_trans_commit','alpm_trans_release','alpm_remove_pkg','alpm_add_pkg','alpm_db_update'):
            self.assertNotIn(name,strings)
        self.assertNotIn('subprocess',TOOL.read_text())
        self.assertEqual(M.digest((HERE/'protection-floor.json').read_bytes()),M.FLOOR_SHA)
        floor=M.floor();self.assertTrue({'glibc','pacman','linux-asahi','asahi-audio','speakersafetyd'}<=floor)


if __name__=='__main__':unittest.main()
