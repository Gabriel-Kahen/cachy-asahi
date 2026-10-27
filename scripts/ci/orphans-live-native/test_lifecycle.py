#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure map/archive/guard controls only; never execute native package actors."""
import ast,copy,hashlib,importlib.util,json,os,stat,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('orphans3_lifecycle',HERE/'lifecycle.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)

def fixture_result():
    """Synthetic contract input only. No archive, ALPM or native actor execution."""
    commands=[];events=[];phases=[]
    def command(argv,code=0,stdout='',stderr=''):
        index=len(commands)+1;commands.append(dict(index=index,argv=list(map(str,argv)),expected_exit=code,exitcode=code,stdout=stdout,stderr=stderr));return index
    def phase(name):
        installed=name in ('install','repeat','reinstall')
        argv=['/usr/bin/pacman','--config','/tmp/orphans-pacman.conf','--noconfirm']+(['--noscriptlet','-U','/inputs/'+M.PRODUCT+'-'+M.VERSION+'-any.pkg.tar.zst'] if installed else ['-R',M.PRODUCT])
        mutation=command(argv);query=command(['/usr/bin/pacman','-Q',M.PRODUCT],0 if installed else 1,M.PRODUCT+' '+M.VERSION+'\n' if installed else '')
        phases.append(dict(phase=name,command_index=mutation,identity_command=query,installed=installed,version=M.VERSION))
    policy=dict(schema_version=1,profile='private-fixture',root=str(M.WORK/'root'),dbpath=str(M.WORK/'root/var/lib/pacman'),supported_base={M.PREFIX+n:'1-1' for n in ('explicit','hard-user','optional-user')},platform={M.PREFIX+'protected':'1-1'},transaction_flags=M.FLAGS,hooks='refuse-matching',scriptlets='refuse',configuration='refuse-selected',ldconfig=dict(mode='forbid'))
    policy_sha=hashlib.sha256(M.encoded(policy)).hexdigest();phase('install');phase('repeat')
    for case in M.EVENT_CASES:
        root,db=('/','/var/lib/pacman') if case=='target-mismatch' else (str(M.WORK/'root'),str(M.WORK/'root/var/lib/pacman'))
        argv=[M.CLI,'live','remove','/out/reports/input/plan.json','--target-root',root,'--target-dbpath',db,'--policy',str(M.OUT/'reports/live-policy.json'),'--policy-sha256','0'*64 if case=='policy-hash' else policy_sha,'--plan-sha256','0'*64]
        leaf='leaf-b' if case in ('different-selection','helper-alias','unsafe-payload','matching-hook') else 'leaf-a'
        for _ in range(2 if case=='duplicate-selection' else 1):argv+=['--select',M.PREFIX+leaf]
        if case!='missing-authorization':argv+=['--authorize-live-removal']
        argv+=['--result',str(M.OUT/'reports'/case/'result.json'),'--timeout-seconds','60']
        result=None;durable=None;code=2 if case=='missing-authorization' else 0 if case=='positive' else 1
        if case!='missing-authorization':result=dict(scope='EXPLICIT_LIVE_ORPHAN_TARGET_V1',status='REFUSED',commit_started=False,packages_committed=False)
        if case=='positive':
            result.update(status='APPLIED',commit_started=True,packages_committed=True,transaction_flags=M.FLAGS,root=str(M.WORK/'root'),dbpath=str(M.WORK/'root/var/lib/pacman'),selected={M.PREFIX+'leaf-a':'1-1'},target=dict(profile='private-fixture'),effects=dict(ldconfig=dict(mode='forbid')),prepared_add={},prepared_remove={M.PREFIX+'leaf-a':'1-1'},transaction_released=True,handle_released=True,lock_state='ABSENT',cleanup_errors=[],worker=dict(reaped=True,exitcode=0,ownership='REAPED',session_registered=True,descendant_exit='UNKNOWN_NOT_DIRECTLY_REAPED'))
            durable='reports/positive/result.json'
        index=command(argv,code,json.dumps(result,sort_keys=True)+'\n' if result is not None else '',stderr='required: --authorize-live-removal\n' if result is None else '')
        events.append(dict(case=case,command_index=index,result=result,durable_result=durable,refusal_stage='ARGPARSE' if result is None else 'PRODUCT'))
    for name in ('remove','reinstall','final-remove'):phase(name)
    names={'positive-before','positive-after','final-target'}|{case+'-'+side for case in M.UNCHANGED_CASES for side in ('before','after')}
    before={name:'1-1' for name in M.FIXTURES};after={name:v for name,v in before.items() if name!=M.PREFIX+'leaf-a'}
    return dict(status=M.STATUS,version=M.VERSION,scope=M.SCOPE,real_backend=True,architecture='aarch64',page_size=4096,hardware='NOT_RUN',release='NOT_ADMITTED',before=before,after=after,before_count=8,after_count=7,base574_preserved=True,configuration_preserved=True,final_lock='ABSENT',commands=commands,events=events,package_lifecycle=phases,installed_backend=dict(path='/usr/lib/cachy-asahi-orphans3/live.py',sha256='0'*64,class_name='LiveTransaction',module='orphans03_installed_actual_backend'),policy_contract=dict(path='reports/live-policy.json',sha256=policy_sha,value=policy),cleanup=dict(outer_candidate='REMOVED',foreign_lock='RELEASED_BY_OWN_HANDLE',TEST_agents='STOPPED',outer_container='PARENT_MUST_VERIFY_ABSENCE_AFTER_ACTOR_EXIT'),maps={name:dict(path='maps/'+name+'.json',sha256='0'*64,nodes=1) for name in names},base_before=dict(path='base-before.json',sha256='0'*64,nodes=1),base_after=dict(path='base-after.json',sha256='0'*64,nodes=1),base_preservation_sha256='0'*64,configuration_before=dict(kind='file',mode=0o640,sha256='0'*64),selected_ownership=dict(package=M.PREFIX+'leaf-a',version='1-1',paths=['usr/share/orphans3-fixture/'+M.PREFIX+'leaf-a.txt','usr/share/licenses/'+M.PREFIX+'leaf-a/LICENSE']),foreign_lock_release=dict(transaction_released=True,handle_released=True,cleanup_errors=[]),ownership_query_cleanup=dict(handle_released=True))


class Lifecycle(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def control(self):
        rows={}
        for name in {M.PRODUCT}|M.FIXTURES:
            version=M.VERSION if name==M.PRODUCT else '1-1';p=self.root/(name+'-'+version+'-any.pkg.tar.zst');p.write_bytes(('inert test bytes '+name).encode());p.with_name(p.name+'.sig').write_bytes(b'inert signature fixture');rows[name]={'archive':p.name,'sha256':M.sha(p)}
        return {'signer':'A'*40,'candidate':rows.pop(M.PRODUCT),'fixtures':rows}
    def test_complete_nine_archive_schema_and_hash_join(self):
        value=self.control();self.assertEqual(set(M.archives(value,self.root)),{M.PRODUCT}|M.FIXTURES)
    def test_archive_hash_extra_version_and_fixture_membership_refuse(self):
        value=self.control();value['candidate']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'archive bytes'):M.archives(value,self.root)
        value=self.control();value['candidate']['archive']='cachy-asahi-orphans-0.1.0-2-any.pkg.tar.zst'
        with self.assertRaisesRegex(ValueError,'basename'):M.archives(value,self.root)
        value=self.control();value['fixtures'].pop(M.PREFIX+'leaf-a')
        with self.assertRaisesRegex(ValueError,'eight'):M.archives(value,self.root)
        value=self.control();(self.root/'arbitrary-1-1-any.pkg.tar.zst').write_bytes(b'never run')
        with self.assertRaisesRegex(ValueError,'additional'):M.archives(value,self.root)
    def test_archive_and_signature_aliases_refuse(self):
        value=self.control();p=self.root/value['candidate']['archive'];p.rename(self.root/'outside');p.symlink_to('outside')
        with self.assertRaisesRegex(ValueError,'archive bytes'):M.archives(value,self.root)
        p.unlink();(self.root/'outside').rename(p);s=p.with_name(p.name+'.sig');os.link(s,self.root/'signature-alias')
        with self.assertRaisesRegex(ValueError,'signature'):M.archives(value,self.root)
    def test_target_map_ignores_atime_but_binds_bytes_identity_links(self):
        d=self.root/'tree';d.mkdir();f=d/'held';f.write_text('inert');before=M.snapshot(d);f.read_bytes();self.assertTrue(M.preservation(before,M.snapshot(d)))
        f.write_text('changed')
        with self.assertRaisesRegex(ValueError,'unselected'):M.preservation(before,M.snapshot(d))
    def test_only_explicit_removal_projection_accepts_absence(self):
        d=self.root/'tree';d.mkdir();(d/'held').write_text('held');(d/'removed').write_text('remove');before=M.snapshot(d);(d/'removed').unlink();after=M.snapshot(d)
        self.assertTrue(M.preservation(before,after,['removed']))
        with self.assertRaisesRegex(ValueError,'undeclared'):M.preservation(before,after)
        (d/'new').write_text('new')
        with self.assertRaisesRegex(ValueError,'appeared'):M.preservation(before,M.snapshot(d),['removed'])
    def test_directory_inode_owner_and_mode_remain_bound(self):
        d=self.root/'tree';d.mkdir();(d/'held').write_text('held');before=M.snapshot(d);d.chmod(0o700)
        with self.assertRaisesRegex(ValueError,'directory'):M.preservation(before,M.snapshot(d))
    def test_mode000_lock_is_recorded_without_read_or_permission_change(self):
        d=self.root/'tree';d.mkdir();p=d/'db.lck';p.write_text('other pid\n');p.chmod(0);rows=M.snapshot(d);self.assertEqual(rows['db.lck']['mode'],0);self.assertNotIn('sha256',rows['db.lck']);self.assertEqual(stat.S_IMODE(p.stat().st_mode),0)
    def test_guard_refuses_before_any_native_actor_on_host(self):
        with patch.object(M.os,'getuid',return_value=1000),patch.object(M.subprocess,'run',side_effect=AssertionError('must not invoke')):
            with self.assertRaisesRegex(ValueError,'dedicated'):M.guard()
    def test_actor_source_uses_installed_actual_backend_and_real_cli(self):
        source=(HERE/'lifecycle.py').read_text();self.assertIn("Path('/usr/lib/cachy-asahi-orphans3/live.py')",source);self.assertIn('self.holder.begin()',source);self.assertNotIn('ModelTransaction',source);self.assertNotIn('factory=',source)
        trial=next(n for n in ast.parse(source).body if isinstance(n,ast.ClassDef) and n.name=='Trial')
        methods={n.name:n for n in trial.body if isinstance(n,ast.FunctionDef)};run=methods['run']
        pm=next(n.value for n in run.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='pm' for t in n.targets))
        self.assertIsInstance(pm,ast.List);self.assertNotIn('--noscriptlet',[n.value for n in pm.elts if isinstance(n,ast.Constant)])
        operations={};outer_operations=set()
        for call in ast.walk(run):
            if not(isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name) and call.func.value.id=='self' and call.func.attr=='command'):continue
            if not(call.args and isinstance(call.args[0],ast.BinOp) and isinstance(call.args[0].op,ast.Add) and isinstance(call.args[0].left,ast.Name)):continue
            base=call.args[0].left.id
            if base not in ('pm','outer'):continue
            operands=call.args[0].right;self.assertIsInstance(operands,ast.List)
            flags=[n.value for n in operands.elts if isinstance(n,ast.Constant)]
            if base=='pm':
                operation=flags[1] if flags and flags[0]=='--noscriptlet' else flags[0]
                self.assertNotIn(operation,operations);operations[operation]=flags
            else:outer_operations.add(flags[0])
        self.assertEqual(operations,{'-U':['--noscriptlet','-U','--asdeps'],'-D':['-D','--asexplicit']})
        query=next(n for n in ast.walk(methods['inventory']) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='command')
        self.assertEqual(ast.dump(query.args[0]),ast.dump(ast.parse("pacman+['-Q']",mode='eval').body))
        inventories=[n for n in ast.walk(run) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='inventory' and n.args and isinstance(n.args[0],ast.Name) and n.args[0].id=='pm']
        self.assertEqual(len(inventories),2);self.assertEqual(outer_operations,set())
        outer=next(n.value for n in methods['signed_pacman'].body if isinstance(n,ast.Return));self.assertIsInstance(outer,ast.List)
        self.assertEqual([n.value for n in outer.elts if isinstance(n,ast.Constant)][-1:],['--noconfirm']);self.assertNotIn('--noscriptlet',[n.value for n in outer.elts if isinstance(n,ast.Constant)])

    def test_complete_synthetic_03_gate_fixture_passes_without_actors(self):
        value=fixture_result();self.assertIs(M.validate_lifecycle(value),value);self.assertEqual(len(value['events']),13);self.assertEqual(len(value['maps']),35)
    def test_old_version_scope_or_non_native_result_cannot_pass(self):
        for key,wrong in [('version','0.2.0-1'),('scope','PRIVATE_OFFLINE_SYNTHETIC_TARGET_ONLY'),('architecture','x86_64'),('real_backend',False),('hardware','PASS'),('release','ADMITTED')]:
            value=fixture_result();value[key]=wrong
            with self.subTest(key=key),self.assertRaises(ValueError):M.validate_lifecycle(value)
    def sync_event(self,value,index):
        event=value['events'][index];value['commands'][event['command_index']-1]['stdout']=json.dumps(event['result'],sort_keys=True)+'\n'
    def test_parse_refusal_has_no_fabricated_product_result(self):
        for mutate in (lambda v:v['events'][0].update(result={'status':'REFUSED'}),lambda v:v['events'][0].update(durable_result='reports/missing-authorization/result.json'),lambda v:v['commands'][v['events'][0]['command_index']-1].update(stdout='{}')):
            value=fixture_result();mutate(value)
            with self.assertRaises(ValueError):M.validate_lifecycle(value)
    def test_negative_unknown_or_commit_claims_fail(self):
        for key,wrong in [('status','FAILED'),('commit_started','UNKNOWN'),('packages_committed',True)]:
            value=fixture_result();value['events'][1]['result'][key]=wrong;self.sync_event(value,1)
            with self.subTest(key=key),self.assertRaises(ValueError):M.validate_lifecycle(value)
    def test_exact_positive_transaction_and_owned_session_are_required(self):
        for key,wrong in [('prepared_add',{'unexpected':'1-1'}),('prepared_remove',{}),('transaction_flags',0),('transaction_released',False),('handle_released',False),('cleanup_errors',['uncertain'])]:
            value=fixture_result();value['events'][8]['result'][key]=wrong;self.sync_event(value,8)
            with self.subTest(key=key),self.assertRaises(ValueError):M.validate_lifecycle(value)
        for key,wrong in [('reaped',False),('exitcode',None),('ownership','UNKNOWN'),('session_registered',False),('descendant_exit','PASS_ALL_EXITED')]:
            value=fixture_result();value['events'][8]['result']['worker'][key]=wrong;self.sync_event(value,8)
            with self.subTest(key=key),self.assertRaises(ValueError):M.validate_lifecycle(value)
    def test_positive_root_fallback_or_helper_permission_cannot_pass(self):
        value=fixture_result();value['events'][8]['result']['root']='/';self.sync_event(value,8)
        with self.assertRaises(ValueError):M.validate_lifecycle(value)
        value=fixture_result();value['events'][8]['result']['effects']['ldconfig']['mode']='reviewed';self.sync_event(value,8)
        with self.assertRaises(ValueError):M.validate_lifecycle(value)
    def test_actual_stdout_command_links_and_explicit_arguments_are_required(self):
        value=fixture_result();value['commands'][value['events'][1]['command_index']-1]['stdout']='{}'
        with self.assertRaisesRegex(ValueError,'stdout'):M.validate_lifecycle(value)
        value=fixture_result();value['events'][1]['command_index']=1
        with self.assertRaises(ValueError):M.validate_lifecycle(value)
        for flag in ('--target-root','--policy-sha256','--plan-sha256','--authorize-live-removal'):
            value=fixture_result();value['commands'][value['events'][8]['command_index']-1]['argv'].remove(flag)
            with self.subTest(flag=flag),self.assertRaises(ValueError):M.validate_lifecycle(value)
    def test_missing_or_reordered_cases_and_maps_fail(self):
        value=fixture_result();value['events'].reverse()
        with self.assertRaises(ValueError):M.validate_lifecycle(value)
        value=fixture_result();value['maps'].pop('matching-hook-after')
        with self.assertRaises(ValueError):M.validate_lifecycle(value)
        value=fixture_result();value['maps']['extra']={'path':'maps/extra.json','sha256':'0'*64,'nodes':1}
        with self.assertRaises(ValueError):M.validate_lifecycle(value)
    def test_full_package_lifecycle_and_operation_specific_flags_required(self):
        value=fixture_result();value['package_lifecycle'].pop()
        with self.assertRaises(ValueError):M.validate_lifecycle(value)
        value=fixture_result();phase=value['package_lifecycle'][2];value['commands'][phase['command_index']-1]['argv'].append('--noscriptlet')
        with self.assertRaisesRegex(ValueError,'operation-specific'):M.validate_lifecycle(value)
        value=fixture_result();phase=value['package_lifecycle'][3];value['commands'][phase['identity_command']-1]['stdout']=M.PRODUCT+' 0.1.0-2\n'
        with self.assertRaises(ValueError):M.validate_lifecycle(value)
    def test_preservation_cleanup_and_installed_backend_bindings_required(self):
        for key,wrong in [('configuration_preserved',False),('base574_preserved',False),('final_lock','PRESENT')]:
            value=fixture_result();value[key]=wrong
            with self.subTest(key=key),self.assertRaises(ValueError):M.validate_lifecycle(value)
        value=fixture_result();value['installed_backend']['path']='/usr/lib/cachy-asahi-orphans3/remove.py'
        with self.assertRaises(ValueError):M.validate_lifecycle(value)
        value=fixture_result();value['cleanup']['outer_candidate']='INSTALLED'
        with self.assertRaises(ValueError):M.validate_lifecycle(value)
        value=fixture_result();value['foreign_lock_release']['handle_released']=False
        with self.assertRaises(ValueError):M.validate_lifecycle(value)
    def test_positive_projection_is_fixed_and_never_removes_shared_parents(self):
        leaf=M.PREFIX+'leaf-a';before={'usr':{},'usr/share':{},'usr/share/orphans3-fixture/'+leaf+'.txt':{},'usr/share/licenses/'+leaf:{},'usr/share/licenses/'+leaf+'/LICENSE':{},'var/lib/pacman/local/'+leaf+'-1-1':{},'var/lib/pacman/local/'+leaf+'-1-1/desc':{},'etc/operator-owned.conf':{},'usr/share/orphans3-fixture/'+M.PREFIX+'leaf-b.txt':{}}
        actual=M.positive_removed(before);self.assertEqual(len(actual),5);self.assertNotIn('usr/share',actual);self.assertNotIn('etc/operator-owned.conf',actual)
    def test_portable_ast_checks_live_cli_and_outer_package_phase_flags(self):
        tree=ast.parse((HERE/'lifecycle.py').read_bytes());trial=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Trial');methods={n.name:n for n in trial.body if isinstance(n,ast.FunctionDef)}
        remove=methods['remove'];argv=next(n.value for n in remove.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='argv' for t in n.targets));self.assertEqual([n.value for n in argv.elts if isinstance(n,ast.Constant)][:2],['live','remove'])
        operations=next(n.value for n in methods['package_phase'].body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='operation' for t in n.targets));self.assertIsInstance(operations,ast.IfExp)
        self.assertEqual([n.value for n in operations.body.elts if isinstance(n,ast.Constant)],['--noscriptlet','-U']);self.assertEqual([n.value for n in operations.orelse.elts if isinstance(n,ast.Constant)],['-R'])
        calls=[n for n in ast.walk(methods['run']) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='package_phase'];self.assertEqual([n.args[2].value for n in calls],list(M.PACKAGE_PHASES))

if __name__=='__main__':unittest.main()
