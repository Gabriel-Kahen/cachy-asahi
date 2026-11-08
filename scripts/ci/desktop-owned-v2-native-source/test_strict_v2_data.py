#!/usr/bin/env python3
"""New synthetic strict-v2 DATA controls. No runtime or original reader imports."""
import ast
import copy
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import re
import sys
import unittest

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
NATIVE=HERE/'payload/native' if (HERE/'payload/native/desktop_reader_v1.py').is_file() else HERE/'candidate/native'
READER=NATIVE/'desktop_reader_v1.py'
RUNTIME_SHA='9388d270d06e28fee50160b7c04dd69593e383647d791f8aaff69380032165d5'
MAP='a'*64
FROZEN_HELPER_AST_SHA={'OWNED_V2_READER_RUNTIME': 'bfa08cbbb8d89836b2f0e706e8cda8278bd0c1390a785d60fe4d06bfb60d2ede', 'OWNED_V2_READER_STATE_KEYS': '3e4ec053cd903e99845a70e71ace8525927ec68390e8b68a00733fee4bba2f7a', 'OWNED_V2_READER_MEMBER_KEYS': '613e3f3127aba376c65472e5555bbf513673a11f1c341a5571395d0016694f8d', 'OWNED_V2_READER_ADOPTION_KEYS': 'f0d5862330b6c9e1c0b03a5e2e5e2c65ab66e72a1c779b692b7700c0ba81e985', 'owned_v2_need': '6ecca1779137bd6c86790b5731e76e14c64e477f4960e0068828c9f7f18ef8c1', 'owned_v2_pid': '5e22d263c63d3655d3251df93e25c972e1755bd50e4dfd3c00b57df00ef6025b', 'owned_v2_ticks': 'dc6b89927e5fb992d37b8016421c877a5704bfac3c304f20e8667f9b33740e8d', 'owned_v2_hash': 'ed7dffe65511dda81b68cfb68692563eb2cbf896b6ca65f5e033f701afd9540a', 'owned_v2_member': 'b109e850222084be688eb8b3faf1ce6f96b6ce58a2bce251055573a90c1e5cfb', 'owned_v2_retirement': '57e2dfde814231a965a2a6abf4ec610edf9531e9e9c8e5cec4ace7b4c53fe809', 'owned_v2_validate_command': '42d4d89a0cf575eeb04358d4e6416a51c34d546f2498417ec0f1c90c3d006968', 'owned_v2_validate_selection': 'ec64f6aa47aee7c4030a14be7d6f1891f40a728b1ffa3a640cd707a304242b48'}
FROZEN_LEGACY_SOURCE_SHA={'desktop_commands': '2ba8a3cb3d126634d3c703b3a62e96203046442ac268d27583635e2562e8878d', 'exact_agent_absence': '78685eb76d256d5cbdbd1730b5ac4663ad5396e0043690ffe6f54434af303eff'}
FROZEN_LEGACY_AST_SHA={'retained_public_projection': '0230e8682b917e936dc1e346b5d83e0768eceff6e9133f3330fd1bc23f73dddd', 'retained_desktop_alpm': '9dece811302ffc3d93846e63e55a48c2e68793b2dfac85e7e4ca8d889c246f28', 'validate_final_return': 'd8bff91e58a41296ac9da9e7e78fcfe4a192b00d132846a12686c7f630003f8f'}

PURE=False
CAPABILITY_ATTEMPTS=[]


def stable_ast_digest(node):
    node=copy.deepcopy(node)
    for item in ast.walk(node):
        for name,value in list(ast.iter_fields(item)):
            if type(value) is list and not value:delattr(item,name)
    return hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest()


def audit(event,args):
    actors=event.startswith(('subprocess.','socket.','ctypes.','signal.','fcntl.')) or event in {
        'os.system','os.fork','os.forkpty','os.exec','os.posix_spawn','os.kill','os.killpg','os.wait','os.waitpid'}
    if actors or (PURE and (event=='open' or event.startswith('os.'))):
        CAPABILITY_ATTEMPTS.append(event)
        raise AssertionError('new strict-v2 DATA controls forbid capability:'+event)
sys.addaudithook(audit)


def invoke(fn,*args,**kwargs):
    global PURE
    PURE=True
    try:return fn(*args,**kwargs)
    finally:PURE=False


def leaf():
    return dict(pid=320,state='Z',group=320,session=320,start_ticks=400,ppid=310,parent_relation='WAIT_OWNER_PID')


def retirement(adopted=False):
    result=dict(phase='PRE_REAP',reserved_leader=dict(pid=320,start_ticks=400),wait_owner_pid=310,
                wait_owner_subreaper='NOT_OBSERVED',member_count=1,members=[leaf()],truncated=False)
    if adopted:
        result['adopted_child']=dict(schema=1,status='QUALIFIED_ONE_ADOPTED_CHILD_REAPED',
            candidate=dict(pid=330,state='Z',group=320,session=320,start_ticks=401,ppid=310,parent_relation='WAIT_OWNER_PID'),
            initial_member_count=2,initial_scan_complete=True,
            waitid=dict(observed=True,pid=330,code='CLD_EXITED',status=0),
            identity_reverified=True,leader_reserved_before_reap=True,
            raw_reap=dict(attempted=True,pid=330,exit=0,status_matches=True),ownership='REAPED',
            target_queries_closed=True,before_leader_reap=True,final_scan_complete=True,
            final_census='RESERVED_LEADER_ONLY',refusal='NONE')
    return result


def command(adopted=False,expected=0):
    exitcode=2 if expected=='nonzero' else expected
    state=dict(exit=exitcode,reaped=True,ownership='REAPED',timeout=False,signals=[],output_complete=True,
               group_census='RESERVED_LEADER_ONLY',group_retirement=retirement(adopted),error=None,
               seconds=.125,passed=exitcode==0)
    return dict(step='synthetic-command',argv=['/usr/bin/true'],cwd='/tmp/desktop-tools-test-SYNTHETIC',
                expected=expected,success=True,log='000-synthetic-command.log',
                log_pin=dict(bytes=0,sha256=hashlib.sha256(b'').hexdigest()),supervision=state,
                channels='stdout+stderr combined in pipe order')


def at(value,path):
    for key in path:value=value[key]
    return value


def changed(value,path,replacement):
    result=copy.deepcopy(value);parent=at(result,path[:-1]);parent[path[-1]]=replacement;return result


def need(ok,message):
    if not ok:raise ValueError(message)


def data_pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def pure_namespace(path,extra_functions=()):
    """Compile only new pure functions/constants, never the original reader module."""
    tree=ast.parse(path.read_bytes(),filename=str(path));nodes=[]
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            name=node.targets[0].id
            if name.startswith('OWNED_V2_READER_') or name in ('PRODUCERS','AGENT_ABSENT'):nodes.append(copy.deepcopy(node))
        elif isinstance(node,ast.FunctionDef) and (node.name.startswith('owned_v2_') or node.name in extra_functions):
            nodes.append(copy.deepcopy(node))
    namespace=dict(need=need,pin=data_pin,re=re,Path=PurePosixPath,
                   C=SimpleNamespace(need=need,pin=data_pin),json=json,hashlib=hashlib)
    module=ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[]))
    exec(compile(module,'<new-strict-v2-pure-data-only>','exec'),namespace)
    return namespace


class RuntimeCommandDATA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.function=staticmethod(pure_namespace(READER)['owned_v2_validate_command'])
    def valid(self,row=None,budget=180):return invoke(self.function,command() if row is None else row,budget=budget)
    def refused(self,row,budget=180):
        with self.assertRaises((ValueError,TypeError)):self.valid(row,budget)
    def mutations(self,base,path,values):
        for value in values:
            with self.subTest(path=path,value=value):self.refused(changed(base,path,value))
    def test_positive_natural_reserved_leader_only(self):self.valid()
    def test_positive_exact_qualified_adopted_zero_child(self):self.valid(command(True))
    def test_positive_expected_nonzero_is_not_fabricated_exit_zero(self):self.valid(command(expected='nonzero'))
    def test_positive_expected_specific_nonzero_retains_runtime_passed_false(self):self.valid(command(expected=2))
    def test_child_and_leader_may_share_start_tick_but_not_pid(self):
        row=command(True);row['supervision']['group_retirement']['adopted_child']['candidate']['start_ticks']=400;self.valid(row)
    def test_known_wait_owner_pid_one_is_not_external_pid_one_inference(self):
        for adopted in (False,True):
            row=command(adopted);group=row['supervision']['group_retirement'];group['wait_owner_pid']=1
            group['members'][0]['ppid']=1
            if adopted:group['adopted_child']['candidate']['ppid']=1
            self.valid(row)
        row=command(True);row['supervision']['group_retirement']['adopted_child']['candidate']['ppid']=1
        self.refused(row)
    def test_zero_start_ticks_are_known_values_when_all_identities_join(self):
        row=command(True);group=row['supervision']['group_retirement'];group['reserved_leader']['start_ticks']=0
        group['members'][0]['start_ticks']=0;group['adopted_child']['candidate']['start_ticks']=0;self.valid(row)
    def test_known_terminal_x_leader_matches_runtime_schema(self):
        row=command();row['supervision']['group_retirement']['members'][0]['state']='X';self.valid(row)
    def test_validation_preserves_original_data_and_never_fills_unknowns(self):
        row=command(True);before=copy.deepcopy(row);result=self.valid(row)
        self.assertIs(result,row);self.assertEqual(row,before)
    def test_smaller_actual_remaining_budget_does_not_raise_the_cap(self):
        self.valid(command(),19);self.valid(command(),.5)
        self.refused(changed(command(),['supervision','seconds'],.5),.5)
    def test_typed_expected_exit_refuses_bool_or_unknown(self):
        self.mutations(command(),['expected'],[True,False,None,0.0,'0','UNKNOWN',[],{}])
    def test_typed_actual_exit_and_expected_match_required(self):
        self.mutations(command(),['supervision','exit'],[True,False,None,0.0,'0',1,-9,256])
    def test_expected_nonzero_requires_positive_exit_and_passed_false(self):
        self.mutations(command(expected='nonzero'),['supervision','exit'],[0,-9,None,True])
        self.refused(changed(command(expected='nonzero'),['supervision','passed'],True))
    def test_success_and_all_retirement_flags_are_exact_booleans(self):
        for path in [['success'],['supervision','reaped'],['supervision','output_complete']]:
            self.mutations(command(),path,[False,0,1,None,'true'])
        self.mutations(command(),['supervision','passed'],[False,0,1,None,'true'])
        self.mutations(command(),['supervision','timeout'],[True,0,1,None,'false'])
    def test_unknown_reaped_or_legacy_census_is_never_positive(self):
        self.mutations(command(),['supervision','ownership'],['UNKNOWN','OWNED','WNOWAIT_RESERVED',None])
        self.mutations(command(),['supervision','group_census'],['UNKNOWN','EMPTY_TWICE','RESERVED_MEMBERS_REMAIN',None])
    def test_signals_errors_and_launch_failure_refuse(self):
        self.mutations(command(),['supervision','signals'],[['SIGTERM'],None,(),False])
        self.mutations(command(),['supervision','error'],['ECHILD','UNKNOWN',False,{}])
        row=command();row['launch_error']='not a successful launch';self.refused(row)
    def test_finite_seconds_must_fit_existing_command_budget(self):
        self.mutations(command(),['supervision','seconds'],[True,False,None,'0',-1,float('nan'),float('inf'),180,181])
        self.valid(command(),20)
        self.refused(changed(command(),['supervision','seconds'],20),20)
    def test_budget_refuses_new_limits_or_mistyped_values(self):
        for budget in (None,True,False,0,-1,181,600,float('nan'),float('inf')):
            with self.subTest(budget=budget):self.refused(command(),budget)
    def test_reserved_leader_identity_is_typed_and_fully_joined(self):
        for key in ('pid','start_ticks'):
            self.mutations(command(),['supervision','group_retirement','reserved_leader',key],[True,False,0,-1,None,'320'])
        self.refused(changed(command(),['supervision','group_retirement','reserved_leader','pid'],321))
        self.refused(changed(command(),['supervision','group_retirement','reserved_leader','start_ticks'],401))
    def test_group_snapshot_phase_and_no_invented_subreaper(self):
        self.mutations(command(),['supervision','group_retirement','phase'],['POST_REAP','UNKNOWN',None])
        self.mutations(command(),['supervision','group_retirement','wait_owner_subreaper'],[True,False,'OBSERVED','UNKNOWN',None])
    def test_group_scan_must_be_complete_exactly_one_terminal_leader(self):
        self.mutations(command(),['supervision','group_retirement','member_count'],[True,0,2,None,1.0])
        self.mutations(command(),['supervision','group_retirement','truncated'],[True,0,1,None])
        self.mutations(command(),['supervision','group_retirement','members'],[[],[leaf(),leaf()],None,{}])
        self.mutations(command(),['supervision','group_retirement','members',0,'state'],['R','S','T','UNKNOWN',None])
    def test_member_pid_start_group_session_parent_full_join(self):
        for key,bad in [('pid',321),('start_ticks',401),('group',321),('session',321),('ppid',1),('parent_relation','PID1')]:
            self.refused(changed(command(),['supervision','group_retirement','members',0,key],bad))
        self.mutations(command(),['supervision','group_retirement','wait_owner_pid'],[True,1,0,-1,None,320])
    def test_no_extra_or_missing_group_or_supervision_fields(self):
        for path in (['supervision'],['supervision','group_retirement'],['supervision','group_retirement','members',0]):
            row=command();at(row,path)['unexpected']='not source schema';self.refused(row)
        for key in ('group_retirement','group_census','exit','passed','seconds'):
            row=command();del row['supervision'][key];self.refused(row)
    def test_log_pin_stays_bounded_by_one_mib(self):
        for value in (-1,True,1048577,None,'0'):
            self.refused(changed(command(),['log_pin','bytes'],value))
        self.mutations(command(),['log_pin','sha256'],['f'*63,'g'*64,None,0])
    def test_argv_and_log_namespace_are_explicit_data(self):
        self.mutations(command(),['argv'],[[],['true'],['/usr/bin/true',1],['/usr/bin/true']+['x']*128])
        self.mutations(command(),['step'],['../escape','x/y','',None])
        self.mutations(command(),['log'],['../../escape','x.log',None])
    def test_adopted_child_requires_exact_qualified_status_schema(self):
        self.mutations(command(True),['supervision','group_retirement','adopted_child','schema'],[True,False,0,2,None])
        self.mutations(command(True),['supervision','group_retirement','adopted_child','status'],['REFUSED_ONE_ADOPTED_CHILD','UNKNOWN',None])
        self.mutations(command(True),['supervision','group_retirement','adopted_child','refusal'],['EXTRA_ECHILD','DEADLINE','EXTRA_NONZERO',None])
    def test_adopted_child_requires_all_reservation_reap_and_close_flags(self):
        for field in ('initial_scan_complete','identity_reverified','leader_reserved_before_reap','target_queries_closed','before_leader_reap','final_scan_complete'):
            self.mutations(command(True),['supervision','group_retirement','adopted_child',field],[False,0,1,None])
        self.mutations(command(True),['supervision','group_retirement','adopted_child','initial_member_count'],[True,1,3,None,2.0])
        self.mutations(command(True),['supervision','group_retirement','adopted_child','ownership'],['UNKNOWN','WNOWAIT_RESERVED','NOT_ACQUIRED',None])
        self.mutations(command(True),['supervision','group_retirement','adopted_child','final_census'],['UNKNOWN','NOT_REACHED','RESERVED_MEMBERS_REMAIN',None])
    def test_adopted_candidate_is_original_distinct_own_zombie(self):
        for field,values in [('pid',[320,310,1,True,None]),('ppid',[1,320,True,None]),('state',['R','X','UNKNOWN',None]),('group',[321,True,None]),('session',[321,True,None]),('start_ticks',[-1,True,None]),('parent_relation',['PID1','RESERVED_LEADER_PID','OTHER',None])]:
            self.mutations(command(True),['supervision','group_retirement','adopted_child','candidate',field],values)
    def test_adopted_wnowait_requires_exact_pid_code_zero_status(self):
        for field,values in [('observed',[False,0,1,None]),('pid',[320,1,True,None]),('code',['CLD_KILLED','CLD_DUMPED','NOT_OBSERVED',None]),('status',[1,-9,True,None,0.0])]:
            self.mutations(command(True),['supervision','group_retirement','adopted_child','waitid',field],values)
    def test_adopted_consuming_wait_requires_actual_exact_matching_zero_reap(self):
        for field,values in [('attempted',[False,0,1,None]),('pid',[320,1,True,None]),('exit',[1,-9,True,None,0.0]),('status_matches',[False,0,1,None])]:
            self.mutations(command(True),['supervision','group_retirement','adopted_child','raw_reap',field],values)
    def test_adopted_rows_cannot_gain_unexported_or_missing_authority(self):
        for path in (['supervision','group_retirement','adopted_child'],['supervision','group_retirement','adopted_child','candidate'],['supervision','group_retirement','adopted_child','waitid'],['supervision','group_retirement','adopted_child','raw_reap']):
            row=command(True);at(row,path)['invented_authority']=True;self.refused(row)
        row=command(True);del row['supervision']['group_retirement']['adopted_child']['raw_reap'];self.refused(row)
    def test_no_actor_capability_was_attempted(self):self.assertEqual(CAPABILITY_ATTEMPTS,[])


class RuntimeSelectionDATA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.function=staticmethod(pure_namespace(READER)['owned_v2_validate_selection'])
    def report(self):
        return dict(operation='desktop-alpm-v1',source_map_sha256=MAP,
            process_layout=dict(schema=1,contract='bash-pid1-direct-python-child-v1',python_pid=310,python_ppid=1,status='OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD'),
            runtime_selection=dict(schema=1,status='SELECTED_EXACT_BUNDLE',selection='desktop-owned-retirement-v2',
                explicit_opt_in=True,source_map_sha256=MAP,
                source=dict(path='native/desktop_owned_process_v2.py',bytes=38256,sha256=RUNTIME_SHA),
                operation_commands='RetirementCommands',cleanup_commands='RetirementCommands',
                legacy_census_wrapper_installed=False,supervision_rows='UNCHANGED_BUNDLE_OUTPUT'))
    def valid(self,value=None,map_hash=MAP):return invoke(self.function,self.report() if value is None else value,map_hash)
    def refuse(self,value,map_hash=MAP):
        with self.assertRaises((ValueError,TypeError)):self.valid(value,map_hash)
    def test_positive_exact_runtime_and_map_selection_without_mutation(self):
        row=self.report();before=copy.deepcopy(row);self.assertIs(self.valid(row),row['runtime_selection']);self.assertEqual(row,before)
    def test_map_binding_must_be_full_and_same_in_both_locations(self):
        for value in (None,'a'*63,'g'*64,False):self.refuse(self.report(),value)
        self.refuse(changed(self.report(),['source_map_sha256'],'b'*64))
        self.refuse(changed(self.report(),['runtime_selection','source_map_sha256'],'b'*64))
    def test_runtime_bytes_hash_path_and_operation_match_exact_source(self):
        for key,value in [('path','native/owned_process.py'),('bytes',38255),('bytes',38256.0),('sha256','b'*64)]:
            self.refuse(changed(self.report(),['runtime_selection','source',key],value))
        self.refuse(changed(self.report(),['operation'],'source184'))
    def test_typed_explicit_optin_cannot_be_inferred_or_equal_integer(self):
        for key,values in [('schema',[True,1.0,0,None]),('explicit_opt_in',[False,1,0,None]),('legacy_census_wrapper_installed',[True,0,1,None])]:
            for value in values:self.refuse(changed(self.report(),['runtime_selection',key],value))
    def test_pending_selection_or_legacy_class_never_qualifies(self):
        for key,value in [('status','SELECTING_EXACT_BUNDLE'),('selection','legacy834'),('operation_commands','Commands'),('cleanup_commands','Commands'),('supervision_rows','NORMALIZED')]:
            self.refuse(changed(self.report(),['runtime_selection',key],value))
    def test_missing_or_extra_selection_keys_are_not_versioned_schema(self):
        for key in self.report()['runtime_selection']:
            row=self.report();del row['runtime_selection'][key];self.refuse(row)
        row=self.report();row['runtime_selection']['accept_UNKNOWN']=True;self.refuse(row)
        row=self.report();row['runtime_selection']['source']['mode']=0o755;self.refuse(row)
    def test_helper_is_pure_new_data_without_imports_or_process_primitives(self):
        original=ast.parse(READER.read_bytes())
        nodes=[n for n in original.body if isinstance(n,ast.FunctionDef)and n.name.startswith('owned_v2_')]
        tree=ast.Module(body=nodes,type_ignores=[])
        self.assertFalse([n for n in ast.walk(tree) if isinstance(n,(ast.Import,ast.ImportFrom))])
        forbidden={'eval','exec','compile','open','__import__','getattr','setattr'}
        calls={n.func.id for n in ast.walk(tree) if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)}
        self.assertFalse(calls&forbidden)
        self.assertEqual(CAPABILITY_ATTEMPTS,[])


class IntegrationDATA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reader_path=READER
        cls.projector_path=NATIVE/'desktop_projection_v1.py'
        cls.reader=pure_namespace(cls.reader_path,('desktop_commands_v2','exact_agent_absence_v2'))
        cls.projector=pure_namespace(cls.projector_path)
    def expected(self):return dict(source='c'*40,ref='refs/heads/codex/SYNTHETIC-v2',run='456',map_sha256=MAP)
    def binding(self):
        value={k:v for k,v in self.expected().items() if k!='map_sha256'}
        value.update(attempt=1,token=hashlib.sha256((value['source']+':'+value['ref']+':'+value['run']).encode()).hexdigest()[:24]);return value
    def mapping(self):
        files={name:dict(bytes=10,sha256=digest,mode=0o644) for name,digest in self.reader['PRODUCERS'].items()}
        files['native/desktop_owned_process_v2.py']=dict(bytes=38256,sha256=RUNTIME_SHA,mode=0o755)
        files['native/desktop_reader_v1.py']=dict(**data_pin(self.reader_path.read_bytes()),mode=0o644)
        for i in range(199-len(files)):files['SYNTHETIC/data-%03d'%i]=dict(bytes=1,sha256='b'*64,mode=0o644)
        return dict(schema=1,actual=dict(source=None,ref=None,run=None),desktop_operation='desktop-alpm-v1',
                    desktop_owned_v2_reader=copy.deepcopy(self.reader['OWNED_V2_READER_CONTRACT']),files=files)
    def projection(self):
        return dict(binding=self.binding(),source_map_sha256=MAP,source_producers=copy.deepcopy(self.reader['PRODUCERS']),
                    omitted_private_scopes=['journey/desktop-alpm-v1/home'],omitted_private_trees_walked=False,
                    original_output_unchanged=True,owned_retirement_reader=copy.deepcopy(self.reader['OWNED_V2_READER_LAYOUT']))
    def source(self,mapping=None,expected=None,map_hash=MAP):
        return invoke(self.reader['owned_v2_source_contract'],self.mapping() if mapping is None else mapping,self.expected() if expected is None else expected,map_hash)
    def refuse_source(self,mapping=None,expected=None,map_hash=MAP):
        with self.assertRaises((ValueError,TypeError)):self.source(mapping,expected,map_hash)
    def projected(self,value=None):return invoke(self.reader['owned_v2_projection_contract'],self.projection() if value is None else value,self.binding(),MAP)
    def refuse_projection(self,value):
        with self.assertRaises((ValueError,TypeError)):self.projected(value)
    def commands(self,operations=1):
        rows=[];steps=['operation-%d'%i for i in range(operations)]+['retire-signing','no-autostart-signing','retire-trust','no-autostart-trust']
        for index,step in enumerate(steps):
            row=command();row['step']=step;row['log']='%03d-%s.log'%(index,step);rows.append(row)
        return rows
    def budgets(self,rows):return invoke(self.reader['owned_v2_command_budgets'],rows,wait_owner_pid=310)
    def refuse_budgets(self,rows):
        with self.assertRaises((ValueError,TypeError)):self.budgets(rows)
    def view(self,rows):
        prefix='journey/desktop-alpm-v1/';raws={};files={}
        for row in rows:
            raw=('SYNTHETIC '+row['step']+' output\n').encode();row['log_pin']=data_pin(raw)
            name=prefix+row['log'];raws[name]=raw;files[name]=dict(kind='file',mode=0o600,**data_pin(raw))
        return SimpleNamespace(load=lambda name:rows if name==prefix+'commands.json' else None,read=lambda name:raws[name]),files,raws,prefix
    def test_positive_explicit_source200_map199_contract_is_unmodified(self):
        mapping=self.mapping();before=copy.deepcopy(mapping);self.assertIs(self.source(mapping),mapping['desktop_owned_v2_reader']);self.assertEqual(mapping,before)
    def test_current_source_map_profile_and_changed_reader_bodies_join_without_execution(self):
        raw=(NATIVE/'source-map.json').read_bytes();mapping=json.loads(raw);map_hash=hashlib.sha256(raw).hexdigest()
        profile=json.loads((HERE/'profile.json').read_bytes());expected=self.expected();expected['map_sha256']=map_hash
        self.assertEqual(invoke(self.reader['owned_v2_source_contract'],mapping,expected,map_hash),self.reader['OWNED_V2_READER_CONTRACT'])
        self.assertEqual(len(profile['after200']),200);self.assertEqual(len(mapping['files']),199)
        self.assertEqual(mapping['files'],{name:{key:row[key]for key in ('bytes','sha256','mode')}for name,row in profile['after200'].items()if name!='native/source-map.json'})
        self.assertEqual(profile['output']['map_sha256'],map_hash)
        self.assertTrue(all(type(row['mode'])is int and row['mode']in(0o644,0o755)for row in profile['after200'].values()))
        self.assertTrue(all(value is None for value in profile['actual'].values()))
        for name in ('desktop_reader_v1.py','desktop_projection_v1.py','desktop_owned_process_v2.py','desktop_alpm_v1.py'):
            row=mapping['files']['native/'+name];body=(NATIVE/name).read_bytes()
            self.assertEqual(data_pin(body),{key:row[key]for key in ('bytes','sha256')})
    def test_null_wrong_or_noncanonical_actual_binding_refuses_before_io(self):
        for key,values in [('source',[None,'d'*39,True]),('ref',[None,'refs/heads/main','refs/heads/codex/../bad','refs/heads/codex/bad//ref','refs/heads/codex/end/']),('run',[None,456,'0','01']),('map_sha256',[None,'b'*64])]:
            for value in values:self.refuse_source(expected=changed(self.expected(),[key],value))
    def test_source_version_operation_actuals_count_and_typed_payload_contract(self):
        for path,value in [(['schema'],True),(['schema'],2),(['desktop_operation'],'source184'),(['actual','run'],'456'),(['desktop_owned_v2_reader','selection'],'legacy834'),(['desktop_owned_v2_reader','payload_files'],6.0),(['desktop_owned_v2_reader','payload_files'],7)]:
            self.refuse_source(changed(self.mapping(),path,value))
        row=self.mapping();row['files'].pop(next(iter(row['files'])));self.refuse_source(row)
        row=self.mapping();row['files']['extra']=dict(bytes=0,sha256='b'*64,mode=0o644);self.refuse_source(row)
    def test_runtime_source_mode_and_whole_body_fields_are_typed_and_exact(self):
        for key,values in [('mode',[0o644,493.0,True]),('bytes',[38255,38256.0,True]),('sha256',['b'*64])]:
            for value in values:self.refuse_source(changed(self.mapping(),['files','native/desktop_owned_process_v2.py',key],value))
    def test_payload_producer_and_reader_source_pins_are_exact(self):
        for name in list(self.reader['PRODUCERS'])+['native/desktop_reader_v1.py']:
            for key,value in [('bytes',True),('bytes',16777217),('mode',420.0),('mode',0o755),('sha256','g'*64)]:
                self.refuse_source(changed(self.mapping(),['files',name,key],value))
    def test_positive_versioned_public_layout_joins_source_map_and_private_omission(self):
        value=self.projection();before=copy.deepcopy(value);self.assertIs(self.projected(value),value['owned_retirement_reader']);self.assertEqual(value,before)
    def test_projection_cannot_walk_retain_or_relabel_private_home(self):
        for path,value in [(['omitted_private_scopes'],[]),(['omitted_private_scopes'],['journey/desktop-alpm-v1/command-home']),(['omitted_private_trees_walked'],True),(['original_output_unchanged'],False),(['owned_retirement_reader','private_trees_walked'],True),(['owned_retirement_reader','omitted_private_scopes'],[])]:
            self.refuse_projection(changed(self.projection(),path,value))
    def test_projection_rejects_typed_layout_payload_runtime_and_producer_tampering(self):
        for path,value in [(['source_map_sha256'],'b'*64),(['binding','run'],'457'),(['owned_retirement_reader','schema'],True),(['owned_retirement_reader','payload_files'],6.0),(['owned_retirement_reader','payload_files'],7),(['owned_retirement_reader','projected_mode'],384.0),(['owned_retirement_reader','runtime','bytes'],38256.0),(['owned_retirement_reader','runtime','sha256'],'b'*64)]:
            self.refuse_projection(changed(self.projection(),path,value))
        row=self.projection();row['source_producers'][next(iter(row['source_producers']))]='b'*64;self.refuse_projection(row)
    def test_projector_tags_exact_selected_report_and_preserves_legacy_absence(self):
        report=RuntimeSelectionDATA.report(self);report['schema_version']=1;report['status']='PASS_DESKTOP_TOOLS_NATIVE_ALPM_COMPONENT'
        actual=invoke(self.projector['owned_v2_projection_tag'],report,MAP)
        self.assertEqual(actual,self.reader['OWNED_V2_READER_LAYOUT']);self.assertIsNot(actual,self.projector['OWNED_V2_READER_LAYOUT'])
        self.assertIsNone(invoke(self.projector['owned_v2_projection_tag'],dict(status='FAIL'),MAP))
    def test_partial_runtime_selection_can_tag_only_source_failure_data(self):
        report=RuntimeSelectionDATA.report(self);report['schema_version']=1;report['runtime_selection']['status']='SELECTING_EXACT_BUNDLE';report['status']='FAIL'
        self.assertEqual(invoke(self.projector['owned_v2_projection_tag'],report,MAP),self.reader['OWNED_V2_READER_LAYOUT'])
        for status in ('PASS_DESKTOP_TOOLS_NATIVE_ALPM_COMPONENT','UNKNOWN',None):
            with self.assertRaises((ValueError,TypeError)):
                invoke(self.projector['owned_v2_projection_tag'],changed(report,['status'],status),MAP)
    def test_positive_partitioned_operation_and_cleanup_budgets_preserve_rows(self):
        rows=self.commands(3);before=copy.deepcopy(rows);self.assertIs(self.budgets(rows),rows);self.assertEqual(rows,before)
        for row in rows[:3]:row['supervision']['seconds']=149
        for row in rows[-4:]:row['supervision']['seconds']=19.9
        self.budgets(rows)
    def test_exact_cleanup_order_and_budget_cannot_be_hidden_or_expanded(self):
        rows=self.commands();rows[-4],rows[-3]=rows[-3],rows[-4];self.refuse_budgets(rows)
        rows=self.commands();rows[-4]['supervision']['seconds']=20;self.refuse_budgets(rows)
        rows=self.commands();rows[0]['step']='cleanup-inventory';rows[0]['log']='000-cleanup-inventory.log';self.refuse_budgets(rows)
        self.refuse_budgets(self.commands(157))
    def test_operation_total_and_ordered_log_identity_stay_bounded(self):
        rows=self.commands(3)
        for row in rows[:3]:row['supervision']['seconds']=150
        self.refuse_budgets(rows)
        rows=self.commands();rows[0]['log']='001-operation-0.log';self.refuse_budgets(rows)
        self.refuse_budgets(self.commands()[-4:])
    def test_new_command_route_joins_complete_raw_log_and_standalone_command_data(self):
        rows=self.commands();view,files,raws,prefix=self.view(rows)
        selected=invoke(self.reader['desktop_commands_v2'],view,files,prefix,rows,wait_owner_pid=310);self.assertEqual(selected('operation-0'),(0,rows[0]))
        bad=copy.deepcopy(files);bad[prefix+rows[0]['log']]['sha256']='b'*64
        with self.assertRaises((ValueError,TypeError)):invoke(self.reader['desktop_commands_v2'],view,bad,prefix,rows,wait_owner_pid=310)
        badview=SimpleNamespace(load=lambda name:[],read=view.read)
        with self.assertRaises((ValueError,TypeError)):invoke(self.reader['desktop_commands_v2'],badview,files,prefix,rows,wait_owner_pid=310)
        rawname=prefix+rows[0]['log'];raws[rawname]+=b'changed'
        with self.assertRaises((ValueError,TypeError)):invoke(self.reader['desktop_commands_v2'],view,files,prefix,rows,wait_owner_pid=310)
    def process_layout(self):
        return dict(schema=1,contract='bash-pid1-direct-python-child-v1',python_pid=310,python_ppid=1,status='OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD')
    def test_positive_process_layout_is_typed_non_pid_one_python_direct_child_data(self):
        layout=self.process_layout();report=dict(process_layout=layout);before=copy.deepcopy(report)
        self.assertIs(invoke(self.reader['owned_v2_process_layout'],report),layout);self.assertEqual(report,before)
    def test_process_layout_refuses_pid_one_wrong_parent_unknown_and_mistyped_fields(self):
        for key,values in [('schema',[True,1.0,0,None]),('contract',['unknown','bash-pid1-direct-python-child-v0',None]),('python_pid',[True,False,0,1,-1,310.0,None]),('python_ppid',[True,1.0,0,2,None]),('status',['UNKNOWN','PID1','OBSERVED',None])]:
            for value in values:
                with self.subTest(key=key,value=value),self.assertRaises((ValueError,TypeError)):
                    invoke(self.reader['owned_v2_process_layout'],dict(process_layout=changed(self.process_layout(),[key],value)))
    def test_process_layout_cannot_omit_fields_add_inference_or_gain_authority(self):
        for key in self.process_layout():
            value=self.process_layout();del value[key]
            with self.assertRaises((ValueError,TypeError)):invoke(self.reader['owned_v2_process_layout'],dict(process_layout=value))
        value=self.process_layout();value['inferred_from_pid']=True
        with self.assertRaises((ValueError,TypeError)):invoke(self.reader['owned_v2_process_layout'],dict(process_layout=value))
        for value in (None,{},[],True):
            with self.assertRaises((ValueError,TypeError)):invoke(self.reader['owned_v2_process_layout'],dict(process_layout=value))
    def test_positive_budget_route_requires_every_command_wait_owner_join_layout_pid(self):
        rows=self.commands();layout=invoke(self.reader['owned_v2_process_layout'],dict(process_layout=self.process_layout()))
        self.assertIs(invoke(self.reader['owned_v2_command_budgets'],rows,wait_owner_pid=layout['python_pid']),rows)
        for index in range(len(rows)):
            bad=copy.deepcopy(rows);group=bad[index]['supervision']['group_retirement'];group['wait_owner_pid']=311;group['members'][0]['ppid']=311
            with self.subTest(index=index),self.assertRaises((ValueError,TypeError)):
                invoke(self.reader['owned_v2_command_budgets'],bad,wait_owner_pid=layout['python_pid'])
        bad=copy.deepcopy(rows);group=bad[0]['supervision']['group_retirement'];group['wait_owner_pid']=1;group['members'][0]['ppid']=1
        with self.assertRaises((ValueError,TypeError)):invoke(self.reader['owned_v2_command_budgets'],bad,wait_owner_pid=layout['python_pid'])
    def test_versioned_source_and_public_layout_bind_the_exact_process_layout_contract(self):
        name='bash-pid1-direct-python-child-v1'
        self.assertEqual(self.reader['OWNED_V2_READER_CONTRACT']['process_layout'],name)
        self.assertEqual(self.reader['OWNED_V2_READER_LAYOUT']['process_layout'],name)
        self.refuse_source(changed(self.mapping(),['desktop_owned_v2_reader','process_layout'],'old-pid1-python'))
        self.refuse_projection(changed(self.projection(),['owned_retirement_reader','process_layout'],'old-pid1-python'))
    def dockerfile(self,map_hash=MAP):
        script=('test "$$" -eq 1 || exit 125; /usr/bin/python3 -I -B '
            '/opt/native-desktop-tools-alpm-v1/source/native/desktop_alpm_v1.py '
            '--inside-image --retain-failure-image --owned-retirement-v2 --map-sha256 '+map_hash+
            ' & desktop_owner=$!; desktop_status=0; wait "$desktop_owner" || desktop_status=$?; exit "$desktop_status"')
        return ('FROM SYNTHETIC\nCOPY desktop-alpm-v1/source/ /opt/native-desktop-tools-alpm-v1/source/\nRUN '+json.dumps(['/usr/bin/bash','--noprofile','--norc','-p','-c',script])+'\nUSER alarm\nWORKDIR /tmp\n').encode()
    def test_reader_accepts_only_exact_bash_pid_one_python_child_wait_launcher(self):
        raw=self.dockerfile();before=bytes(raw)
        self.assertEqual(invoke(self.reader['owned_v2_build_launcher'],raw,MAP),dict(contract='bash-pid1-direct-python-child-v1',source_map_sha256=MAP));self.assertEqual(raw,before)
        row=RuntimeSelectionDATA.report(self);row['schema_version']=1;row['status']='PASS_DESKTOP_TOOLS_NATIVE_ALPM_COMPONENT'
        self.assertEqual(invoke(self.projector['owned_v2_projection_tag'],row,MAP)['process_layout'],'bash-pid1-direct-python-child-v1')
    def test_pid_one_python_foreground_no_wait_wrong_shell_or_success_masking_refuse(self):
        raw=self.dockerfile()
        replacements=[('/usr/bin/bash','/usr/bin/sh'),('--noprofile','--login'),('test "$$" -eq 1 || exit 125; ',''),(' & desktop_owner=$!','; desktop_owner=$!'),('wait "$desktop_owner"','true'),('desktop_status=$?','desktop_status=0'),('exit "$desktop_status"','exit 0'),('--owned-retirement-v2',''),('USER alarm','USER root')]
        for before,after in replacements:
            before=json.dumps(before)[1:-1].encode();after=json.dumps(after)[1:-1].encode()
            self.assertIn(before,raw)
            with self.subTest(tamper=before),self.assertRaises((ValueError,TypeError)):
                invoke(self.reader['owned_v2_build_launcher'],raw.replace(before,after),MAP)
    def test_build_launcher_map_cap_duplicate_run_and_suffix_are_exact(self):
        raw=self.dockerfile()
        for bad in (raw.decode(),b'',raw+b'extra',raw.replace(b'\nUSER alarm\nWORKDIR /tmp\n',b'\n'),raw+b'x'*(16*1024**2+1)):
            with self.assertRaises((ValueError,TypeError)):invoke(self.reader['owned_v2_build_launcher'],bad,MAP)
        run=next(line for line in raw.splitlines()if line.startswith(b'RUN '))
        with self.assertRaises((ValueError,TypeError)):invoke(self.reader['owned_v2_build_launcher'],run+b'\n'+raw,MAP)
        for map_hash in (None,True,'a'*63,'g'*64,'b'*64):
            with self.assertRaises((ValueError,TypeError)):invoke(self.reader['owned_v2_build_launcher'],raw,map_hash)
    def test_build_layout_joins_actual_complete_retained_dockerfile_before_parsing(self):
        name='bootstrap-proof/overlay-Dockerfile';raw=self.dockerfile();files={name:dict(kind='file',mode=0o600,**data_pin(raw))}
        view=SimpleNamespace(read=lambda path:raw)
        self.assertEqual(invoke(self.reader['owned_v2_build_layout'],view,files,MAP),dict(contract='bash-pid1-direct-python-child-v1',source_map_sha256=MAP))
        for bad in ({},changed(files,[name,'kind'],'dir'),changed(files,[name,'sha256'],'b'*64)):
            with self.assertRaises((ValueError,TypeError)):invoke(self.reader['owned_v2_build_layout'],view,bad,MAP)
        with self.assertRaises((ValueError,TypeError)):invoke(self.reader['owned_v2_build_layout'],SimpleNamespace(read=lambda path:raw+b'changed'),files,MAP)
    def test_positive_component_owner_join_is_derived_from_the_observed_report_layout(self):
        tree=ast.parse(self.reader_path.read_bytes());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='retained_desktop_alpm')
        branch=next(n for n in fn.body if isinstance(n,ast.If)and ast.unparse(n.test)=='retirement_selection == OWNED_V2_READER_SELECTION')
        assignments=[n for n in branch.body if isinstance(n,ast.Assign)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Name)]
        layout=next(n for n in assignments if n.value.func.id=='owned_v2_process_layout')
        commands=next(n for n in assignments if n.value.func.id=='desktop_commands_v2')
        self.assertLess(layout.lineno,commands.lineno)
        self.assertEqual(ast.unparse(layout.value),'owned_v2_process_layout(report)')
        owner=next(k.value for k in commands.value.keywords if k.arg=='wait_owner_pid')
        self.assertEqual(ast.unparse(owner),ast.unparse(layout.targets[0])+"['python_pid']")
        validate=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate')
        build_branches=[n for n in validate.body if isinstance(n,ast.If)and ast.unparse(n.test)=='retirement_selection == OWNED_V2_READER_SELECTION' and any(isinstance(call,ast.Call)and isinstance(call.func,ast.Name)and call.func.id=='owned_v2_build_layout'for call in ast.walk(n))]
        self.assertEqual(len(build_branches),1);self.assertFalse(build_branches[0].orelse)
        build=next(n for n in ast.walk(build_branches[0])if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='owned_v2_build_layout')
        component=next(n for n in ast.walk(validate)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='retained_desktop_alpm')
        self.assertLess(build.lineno,component.lineno)
        failure=next(n for n in validate.body if isinstance(n,ast.If)and 'not consumer_diagnostic' in ast.unparse(n.test))
        self.assertLess(failure.lineno,build.lineno)
    def test_no_agent_absence_requires_actual_complete_zero_exit_and_exact_protocol(self):
        row=command();row['step']='no-autostart-signing';row['log']='000-no-autostart-signing.log'
        raw=b'gpg-connect-agent: no gpg-agent running in this session\n';row['log_pin']=data_pin(raw)
        self.assertIsNone(invoke(self.reader['exact_agent_absence_v2'],row,raw))
        for bad in (raw+b'extra',b'',raw.decode()):
            with self.assertRaises((ValueError,TypeError)):invoke(self.reader['exact_agent_absence_v2'],row,bad)
        with self.assertRaises((ValueError,TypeError)):invoke(self.reader['exact_agent_absence_v2'],changed(row,['supervision','seconds'],20),raw)
    def test_legacy_command_and_no_agent_functions_are_byte_identical(self):
        text=self.reader_path.read_text();tree=ast.parse(text)
        for name,expected in FROZEN_LEGACY_SOURCE_SHA.items():
            node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name)
            self.assertEqual(hashlib.sha256(ast.get_source_segment(text,node).encode()).hexdigest(),expected,name)
    def test_embedded_validator_ast_is_exact_new_helper_not_a_weakened_fork(self):
        tree=ast.parse(self.reader_path.read_bytes());actual={}
        for node in tree.body:
            if isinstance(node,ast.FunctionDef)and node.name.startswith('owned_v2_'):actual[node.name]=stable_ast_digest(node)
            elif isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
                actual[node.targets[0].id]=stable_ast_digest(node)
        for name,expected in FROZEN_HELPER_AST_SHA.items():self.assertEqual(actual[name],expected,name)
    def test_default_projection_keeps_all_legacy_caps_privacy_and_archive_guards(self):
        tree=ast.parse(self.reader_path.read_bytes());node=copy.deepcopy(next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='retained_public_projection'))
        defaults=dict(zip([x.arg for x in node.args.kwonlyargs],node.args.kw_defaults));self.assertEqual(ast.literal_eval(defaults['retirement_selection']),'legacy834')
        branches=[n for n in node.body if isinstance(n,ast.If)and ast.unparse(n.test)=='retirement_selection == OWNED_V2_READER_SELECTION'];self.assertEqual(len(branches),1)
        branch=branches[0];self.assertFalse(branch.orelse);self.assertEqual(ast.unparse(branch.body[0]),'owned_v2_projection_contract(value, binding, map_sha256)')
        node.body.remove(branch);node.args.kwonlyargs=[];node.args.kw_defaults=[]
        self.assertEqual(stable_ast_digest(node),FROZEN_LEGACY_AST_SHA['retained_public_projection'])
    def test_default_component_preserves_all_original_business_signature_and_restoration_guards(self):
        tree=ast.parse(self.reader_path.read_bytes());node=copy.deepcopy(next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='retained_desktop_alpm'))
        defaults=dict(zip([x.arg for x in node.args.kwonlyargs],node.args.kw_defaults));self.assertEqual(ast.literal_eval(defaults['retirement_selection']),'legacy834')
        class DefaultBranch(ast.NodeTransformer):
            replacements=0
            def visit_If(self,branch):
                if ast.unparse(branch.test)=='retirement_selection == OWNED_V2_READER_SELECTION':
                    self.replacements+=1
                    return branch.orelse
                return self.generic_visit(branch)
        transform=DefaultBranch();node=transform.visit(node);self.assertEqual(transform.replacements,2)
        node.args.kwonlyargs=[];node.args.kw_defaults=[]
        self.assertEqual(stable_ast_digest(node),FROZEN_LEGACY_AST_SHA['retained_desktop_alpm'])
    def test_default_result_schema_is_exact_original_without_extra_version_credit(self):
        tree=ast.parse(self.reader_path.read_bytes());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate')
        result=[n for n in node.body if isinstance(n,ast.Return)][-1]
        self.assertEqual(stable_ast_digest(result),FROZEN_LEGACY_AST_SHA['validate_final_return'])
    def test_explicit_v2_source_verification_precedes_capsule_open_and_default_is_legacy(self):
        tree=ast.parse(self.reader_path.read_bytes());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate')
        defaults=dict(zip([x.arg for x in fn.args.kwonlyargs],fn.args.kw_defaults));self.assertEqual(ast.literal_eval(defaults['retirement_selection']),'legacy834')
        branch=next(n for n in fn.body if isinstance(n,ast.If)and 'retirement_selection' in ast.unparse(n.test))
        calls=[n for n in ast.walk(branch)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)]
        self.assertTrue({'verify_source','owned_v2_source_contract'}<={n.func.id for n in calls})
        capsule=next(n for n in ast.walk(fn)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='open_capsule')
        self.assertTrue(all(n.lineno<capsule.lineno for n in calls if n.func.id in ('verify_source','owned_v2_source_contract')))
        standalone=next(n for n in tree.body if isinstance(n,ast.If)and '__name__' in ast.unparse(n.test))
        text=ast.unparse(standalone);self.assertIn('--retirement-selection',text);self.assertIn("default='legacy834'",text)


if __name__=='__main__':unittest.main(verbosity=2)
