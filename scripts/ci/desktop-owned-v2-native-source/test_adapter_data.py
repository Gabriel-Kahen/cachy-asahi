#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable adapter DATA/AST controls; no bundle, constructor or native execution.

Root control metadata covers one adopted zero-exit child on native ARM4K only.
It does not qualify the Desktop lifecycle, other branches or target hardware.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import stat
from types import SimpleNamespace
import unittest

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
PAYLOAD=HERE/'payload'
NATIVE=PAYLOAD/'native'
BUNDLE_PIN=dict(bytes=38256,sha256='9388d270d06e28fee50160b7c04dd69593e383647d791f8aaff69380032165d5')
CORE834='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
MAP='a'*64
PURE=False
CAPABILITY_ATTEMPTS=[]


def audit(event,args):
    forbidden=event.startswith(('subprocess.','socket.','ctypes.','fcntl.','signal.')) or event in {
        'os.system','os.fork','os.forkpty','os.exec','os.posix_spawn','os.kill','os.killpg','os.wait','os.waitpid'}
    if forbidden or (PURE and (event=='open' or event.startswith('os.'))):
        CAPABILITY_ATTEMPTS.append(event);raise AssertionError('protocol DATA controls forbid capability:'+event)
sys.addaudithook(audit)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def ast_digest(node):
    """Match Python 3.14 dump omission of empty fields on both supported versions."""
    node=copy.deepcopy(node)
    for item in ast.walk(node):
        for name,value in list(ast.iter_fields(item)):
            if type(value) is list and not value:delattr(item,name)
    return hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest()


def need(ok,why):
    if not ok:raise ValueError(why)


def parse(name):return ast.parse((NATIVE/name).read_bytes(),filename=name)


def function(tree,name):
    rows=[node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name==name]
    need(len(rows)==1,'sole expected function '+name);return rows[0]


def dotted(node):
    if isinstance(node,ast.Name):return node.id
    if isinstance(node,ast.Attribute):return dotted(node.value)+'.'+node.attr
    return '<expression>'


def calls(node,name=None):
    rows=[item for item in ast.walk(node)if isinstance(item,ast.Call)]
    return rows if name is None else [item for item in rows if dotted(item.func)==name]


def constant(node):return ast.literal_eval(node)


def keywords(node):return {item.arg:item.value for item in node.keywords}


def isolated(node,namespace):
    """Define ONE inspected pure function, never an ALPM/runtime module/bundle."""
    module=ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)],type_ignores=[]))
    exec(compile(module,'<isolated-optin-protocol-function>','exec'),namespace)
    return namespace[node.name]


def invoke(fn,*args,**kwargs):
    global PURE
    PURE=True
    try:return fn(*args,**kwargs)
    finally:PURE=False


HELD_HELPERS={
 'build_pair':'5742348bb13cf997dbb7589e92faf5ba01ef22ec7afa9067095964d87b5b78b2',
 'build_update':'b3bd3df2e7f0fe1642ff37f2886f1c5ad725569848065b813dda91bb6b80c7a1',
 'exact_agent_absence':'5fe4f677862f5fc7017e9a54d6fec90220509f844bc5c309e3e85b89d60d0f48',
 'export':'1b3b781bff0b9d4dffc01d0c097bf38d79b472fbb1304fe88dc3a98e0712d606',
 'observe_group_census':'a383c7ff25e90336bd5fd018d03c500aefe2e9716f0641eda5a7f52741bdd0e5',
 'prepare':'a335034709c26d5186d6a92f028688ee4e639cc805f4df50ddeb581150384c31',
 'primary_failure':'28368847dd598b35d03f83d20cff017f5fa4eeb53cf628ee6c9de7eee4bd5325',
 'protected_state':'5bb9303719a63f9a58632d385a627fbc8044fcdbf7d9ab56709f3ab660a63fff',
 'record_group_census':'ae927ff4b6cc931412ba65122fb12b91d887a5338ef77c5ca036a01c07dcb5ef',
 'retain_exception':'fb3b48b1d2aa1ec48b356d8fc99d9baeebae9b0078a3e8546e13303f9afecaa9',
 'retain_group_census':'5b3e495b26d635e2b08bbf97764f8a798dfa12cf68dbc6c67b9ded32bade2dc9',
 'retire_homes':'5cdcae10290e28a9b45b4b99c6eee56d931d189158574aab61d7e3d849728b42',
 'save_result':'656d9ad9fb827e68efef1ca1f0be00f631bf0c4f3d533505a1b3c0a6b81e98a4',
 'strict_signature':'dcffb7dcb3c9f136acd783179096a061d250a1f23a8a6bceed950de00e41bde5',
 'test_config':'2e27c286c053c80981f1cac7f548d3480ed33efed7dd8e4856a96c799693dddb'}


class BundleASTControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw=(NATIVE/'desktop_owned_process_v2.py').read_bytes();cls.tree=ast.parse(cls.raw)
        cls.caller=next(node for node in cls.tree.body if isinstance(node,ast.ClassDef)and node.name=='RetirementCommands')
        cls.caller_run=function(cls.caller,'run');cls.supervisor=function(cls.tree,'supervise')
    def test_whole_exact_bundle_is_data_only_and_not_repackaged(self):
        self.assertEqual(pin(self.raw),BUNDLE_PIN)
        self.assertEqual(ast_digest(self.caller_run),
                         '5daf49f88d71a5383608dff0b36a2081ef76aee77130a85e76dadf747fae1989')
    def test_one_popen_actual_object_and_pipe_ownership_transfer(self):
        launch,=calls(self.caller_run,'subprocess.Popen');supervise,=calls(self.caller_run,'self.core.supervise')
        assignment=next(node for node in ast.walk(self.caller_run)if isinstance(node,ast.Assign)and node.value is launch)
        self.assertIsInstance(assignment.targets[0],ast.Name)
        self.assertEqual(dotted(assignment.targets[0]),dotted(supervise.args[0]));self.assertEqual(dotted(supervise.args[0]),'child')
        flags=keywords(launch)
        self.assertEqual(dotted(flags['stdout']),'subprocess.PIPE');self.assertEqual(dotted(flags['stderr']),'subprocess.STDOUT')
        self.assertEqual(dotted(flags['stdin']),'subprocess.DEVNULL');self.assertIs(constant(flags['start_new_session']),True)
        self.assertEqual(dotted(flags['env']),'self.env')
    def test_prepare_precedes_launch_and_supervise_has_held_caps(self):
        prepare,=calls(self.caller_run,'self.core.prepare');launch,=calls(self.caller_run,'subprocess.Popen');supervise,=calls(self.caller_run,'self.core.supervise')
        self.assertLess(prepare.lineno,launch.lineno);self.assertLess(launch.lineno,supervise.lineno)
        caps=keywords(supervise);self.assertEqual(dotted(caps['cap']),'remaining');self.assertEqual(constant(caps['retirement']),1)
        self.assertEqual(constant(caps['grace']),.2);self.assertEqual(dotted(caps['max_output']),'self.max_output')
        self.assertNotIn('streams',caps)
        defaults=dict(zip([arg.arg for arg in self.supervisor.args.kwonlyargs],self.supervisor.args.kw_defaults))
        self.assertIsNone(constant(defaults['streams']))
        attributes={dotted(node)for node in ast.walk(self.supervisor)if isinstance(node,ast.Attribute)}
        self.assertIn('popen.stdout',attributes);self.assertIn('popen.stderr',attributes)
    def test_caller_never_queries_or_controls_transferred_numeric_child(self):
        attributes={dotted(node)for node in ast.walk(self.caller_run)if isinstance(node,ast.Attribute)}
        for name in ('child.pid','child.returncode','child.poll','child.wait','child.communicate','child.terminate','child.kill','child.send_signal'):
            self.assertNotIn(name,attributes)
        forbidden={'os.waitid','os.waitpid','os.kill','os.killpg','os.getpgid','os.getsid','os.getpid','os.getppid'}
        self.assertFalse({dotted(node.func)for node in calls(self.caller_run)}&forbidden)
        self.assertFalse(calls(self.caller_run,'self.core._stat'));self.assertFalse(calls(self.caller_run,'self.core._members'))
    def test_record_keeps_actual_supervision_object_without_legacy_absence_claims(self):
        updates=[node for node in calls(self.caller_run,'row.update')if 'supervision'in keywords(node)]
        self.assertEqual(len(updates),1);self.assertEqual(dotted(keywords(updates[0])['supervision']),'result')
        pops=calls(self.caller_run,'result.pop');self.assertEqual([constant(node.args[0])for node in pops],['output'])
        writes=[node for node in ast.walk(self.caller_run)if isinstance(node,ast.Subscript)and isinstance(node.ctx,ast.Store)and dotted(node.value)=='result']
        self.assertEqual(writes,[])
        literals={node.value for node in ast.walk(self.caller_run)if isinstance(node,ast.Constant)and type(node.value)is str}
        self.assertIn('RESERVED_LEADER_ONLY',literals);self.assertNotIn('EMPTY_TWICE',literals);self.assertNotIn('group_absent',literals)
    def test_actual_pre_reap_and_adopted_child_schema_stays_in_bundle(self):
        result=[node for node in calls(self.supervisor,'dict')if 'group_retirement'in keywords(node)]
        self.assertEqual(len(result),1);fields=keywords(result[0])
        self.assertEqual(dotted(fields['group_retirement']),'group_retirement');self.assertEqual(dotted(fields['group_census']),'census')
        literals={node.value for node in ast.walk(self.supervisor)if isinstance(node,ast.Constant)and type(node.value)is str}
        for name in ('PRE_REAP','NOT_OBSERVED','WAIT_OWNER_PID','RESERVED_LEADER_PID','WNOWAIT_RESERVED','REAPED',
                     'NOT_ACQUIRED','RESERVED_LEADER_ONLY','RESERVED_MEMBERS_REMAIN','QUALIFIED_ONE_ADOPTED_CHILD_REAPED'):
            self.assertIn(name,literals)
        self.assertNotIn('EMPTY_TWICE',literals)


class PureSelectionControls(unittest.TestCase):
    def setUp(self):self.tree=parse('desktop_alpm_v1.py');self.base='FROM SYNTHETIC\nUSER alarm\nWORKDIR /tmp\n'
    def dockerfile(self):return isolated(function(self.tree,'dockerfile'),dict(need=need,re=re,json=json))
    def loader(self,raw=None,read_error=False):
        events=[];sentinel=object();raw=(NATIVE/'desktop_owned_process_v2.py').read_bytes()if raw is None else raw
        def ordinary(path,cap):
            events.append(('ordinary',str(path),cap))
            if read_error:raise ValueError('SYNTHETIC ordinary source refused')
            return raw
        def checked_compile(body,filename,mode):
            events.append(('compile-data-only',pin(body),filename,mode));return 'SYNTHETIC_NOT_EXECUTABLE'
        def checked_exec(token,namespace):
            self.assertEqual(token,'SYNTHETIC_NOT_EXECUTABLE');events.append(('exec-stub-only',))
            namespace['RetirementCommands']=sentinel
        ns=dict(need=need,T=SimpleNamespace(ordinary=ordinary,data_pin=pin),Path=PurePosixPath,
                OWNED_V2_PATH='native/desktop_owned_process_v2.py',OWNED_V2_PIN=BUNDLE_PIN,
                compile=checked_compile,exec=checked_exec,SimpleNamespace=SimpleNamespace)
        return isolated(function(self.tree,'load_owned_retirement_v2'),ns),events,sentinel
    def chooser(self):
        inside=function(self.tree,'inside')
        gate=inside.body[0];self.assertEqual(dotted(gate.value.func),'need')
        branch=next(node for node in inside.body if isinstance(node,ast.Try))
        selection=next(node for node in branch.body if isinstance(node,ast.If)and isinstance(node.test,ast.Name)and node.test.id=='owned_retirement_v2')
        arguments=ast.parse('def choose(owned_retirement_v2,source,policy,report,map_hash):\n pass').body[0].args
        node=ast.FunctionDef(name='choose',args=arguments,body=[copy.deepcopy(gate),copy.deepcopy(selection),ast.Return(value=ast.Name(id='W',ctx=ast.Load()))],decorator_list=[])
        events=[];legacy=SimpleNamespace(Commands='SYNTHETIC_LEGACY_CLASS');new=SimpleNamespace(Commands='SYNTHETIC_V2_CLASS')
        def original(source,policy):events.append(('legacy',source,policy));return legacy
        def selected(source):events.append(('v2',source));return new
        ns=dict(need=need,T=SimpleNamespace(load_workflow=original),load_owned_retirement_v2=selected,
                OWNED_V2_PATH='native/desktop_owned_process_v2.py',OWNED_V2_PIN=BUNDLE_PIN)
        return isolated(ast.fix_missing_locations(node),ns),events,legacy,new
    def test_default_dockerfile_is_exact_legacy_with_no_optin_flag(self):
        fn=self.dockerfile();a=invoke(fn,self.base,MAP);b=invoke(fn,self.base,MAP,owned_retirement_v2=False)
        self.assertEqual(a,b);self.assertNotIn('--owned-retirement-v2',a)
        expected=self.base[:-len('USER alarm\nWORKDIR /tmp\n')]+('COPY desktop-alpm-v1/source/ /opt/native-desktop-tools-alpm-v1/source/\n'
                 'RUN /usr/bin/python3 -I -B /opt/native-desktop-tools-alpm-v1/source/native/desktop_alpm_v1.py --inside-image --retain-failure-image --map-sha256 '+MAP+'\nUSER alarm\nWORKDIR /tmp\n')
        self.assertEqual(a,expected)
    def test_explicit_dockerfile_uses_versioned_pid1_json_layout(self):
        fn=self.dockerfile();selected=invoke(fn,self.base,MAP,owned_retirement_v2=True)
        self.assertTrue(selected.startswith(self.base[:-len('USER alarm\nWORKDIR /tmp\n')]))
        runs=[line[4:] for line in selected.splitlines() if line.startswith('RUN ')]
        self.assertEqual(len(runs),1);argv=json.loads(runs[0])
        self.assertEqual(argv[:5],['/usr/bin/bash','--noprofile','--norc','-p','-c'])
        self.assertEqual(len(argv),6)
        self.assertEqual(argv[5], 'test "$$" -eq 1 || exit 125; /usr/bin/python3 -I -B /opt/native-desktop-tools-alpm-v1/source/native/desktop_alpm_v1.py --inside-image --retain-failure-image --owned-retirement-v2 --map-sha256 '+MAP+' & desktop_owner=$!; desktop_status=0; wait "$desktop_owner" || desktop_status=$?; exit "$desktop_status"')
        self.assertEqual(json.loads((HERE/'profile.json').read_bytes())['reader_contract']['process_layout'],
                         'bash-pid1-direct-python-child-v1')
        self.assertTrue(selected.endswith('USER alarm\nWORKDIR /tmp\n'))
    def test_nonboolean_and_bad_map_or_suffix_refuse_as_pure_data(self):
        fn=self.dockerfile()
        for flag in (None,0,1,'true',[]):
            with self.subTest(flag=flag),self.assertRaises(ValueError):invoke(fn,self.base,MAP,owned_retirement_v2=flag)
        for value in ('A'*64,'a'*63,'g'*64,''):
            with self.subTest(map=value),self.assertRaises(ValueError):invoke(fn,self.base,value)
        for base in ('FROM SYNTHETIC\n',self.base+'extra',self.base+self.base):
            with self.subTest(base=base),self.assertRaises(ValueError):invoke(fn,base,MAP)
    def test_loader_exact_pin_precedes_compile_and_stub_exec_without_bundle_execution(self):
        fn,events,sentinel=self.loader();value=invoke(fn,'/SYNTHETIC/SOURCE')
        self.assertIs(value.Commands,sentinel);self.assertEqual([row[0]for row in events],['ordinary','compile-data-only','exec-stub-only'])
        self.assertEqual(events[0],('ordinary','/SYNTHETIC/SOURCE/native/desktop_owned_process_v2.py',38256))
        self.assertEqual(events[1][1],BUNDLE_PIN)
    def test_tampered_or_missing_bundle_refuses_before_any_exec(self):
        for raw,error in ((b'CHANGED',False),(b'',False),(b'X'*38257,False),(None,True)):
            fn,events,_=self.loader(raw,read_error=error)
            with self.subTest(length=None if raw is None else len(raw)),self.assertRaises(ValueError):invoke(fn,'/SYNTHETIC/SOURCE')
            self.assertEqual([row[0]for row in events],['ordinary'])
    def test_default_selects_only_original_workflow_class(self):
        fn,events,legacy,new=self.chooser();report={};value=invoke(fn,False,'SOURCE',{'unchanged':'POLICY'},report,MAP)
        self.assertIs(value,legacy);self.assertEqual(events,[('legacy','SOURCE',{'unchanged':'POLICY'})]);self.assertEqual(report,{})
    def test_optin_selects_bundle_for_both_paths_with_unmodified_row_schema_marker(self):
        fn,events,legacy,new=self.chooser();report={};value=invoke(fn,True,'SOURCE',{},report,MAP)
        self.assertIs(value,new);self.assertEqual(events,[('v2','SOURCE')]);row=report['runtime_selection']
        self.assertEqual(row['status'],'SELECTED_EXACT_BUNDLE');self.assertEqual(row['source'],dict(path='native/desktop_owned_process_v2.py',**BUNDLE_PIN))
        self.assertEqual(row['operation_commands'],row['cleanup_commands']);self.assertEqual(row['operation_commands'],'RetirementCommands')
        self.assertEqual(row['supervision_rows'],'UNCHANGED_BUNDLE_OUTPUT');self.assertIs(row['legacy_census_wrapper_installed'],False)
    def test_selection_rejects_truthy_nonbool_before_loading(self):
        for flag in (1,0,None,'true'):
            fn,events,_,_=self.chooser()
            with self.subTest(flag=flag),self.assertRaises(ValueError):invoke(fn,flag,'SOURCE',{}, {},MAP)
            self.assertEqual(events,[])


class RoutingAndDefaultASTControls(unittest.TestCase):
    def setUp(self):self.alpm=parse('desktop_alpm_v1.py');self.owner=parse('owner.py')
    def test_primary_and_cleanup_share_selected_class_and_original_budgets(self):
        inside=function(self.alpm,'inside');constructors=calls(inside,'W.Commands')
        self.assertEqual(len(constructors),2)
        actual=sorted((constant(keywords(node)['timeout']),constant(keywords(node)['total']),ast.unparse(keywords(node)['max_output']))for node in constructors)
        self.assertEqual(actual,[(20,90,'1024 ** 2'),(180,450,'1024 ** 2')])
        wrappers=[node for node in ast.walk(inside)if isinstance(node,ast.IfExp)and calls(node.orelse,'observe_group_census')]
        self.assertEqual(len(wrappers),2)
        for node in wrappers:self.assertEqual(dotted(node.test),'owned_retirement_v2');self.assertIsNone(constant(node.body))
    def test_held_legacy_helpers_and_check_provenance_are_unchanged(self):
        for name,digest in HELD_HELPERS.items():
            node=function(self.alpm,name);actual=ast_digest(node)
            self.assertEqual(actual,digest,name)
        assignments={target.id:node.value for node in self.alpm.body if isinstance(node,ast.Assign)for target in node.targets if isinstance(target,ast.Name)}
        self.assertEqual(constant(assignments['CENSUS_CORE_SHA256']),CORE834)
        self.assertFalse((NATIVE/'desktop-contract-v1.json').exists());self.assertFalse((PAYLOAD/'scripts/virtual/owned_process.py').exists())
    def test_owner_and_inner_flags_are_explicit_store_true_default_false(self):
        for tree,flag in ((self.owner,'--desktop-owned-retirement-v2'),(self.alpm,'--owned-retirement-v2')):
            rows=[node for node in calls(tree,'parser.add_argument')if node.args and isinstance(node.args[0],ast.Constant)and node.args[0].value==flag]
            self.assertEqual(len(rows),1);fields=keywords(rows[0]);self.assertEqual(constant(fields['action']),'store_true');self.assertIs(constant(fields['default']),False)
    def test_owner_gate_restricts_optin_to_existing_desktop_operation(self):
        run=function(self.owner,'run')
        guard=next(node for node in run.body if isinstance(node,ast.Expr)and calls(node,'need')and 'owned_retirement_v2'in ast.unparse(node))
        arguments=ast.parse('def gate(owned_retirement_v2,operation):\n pass').body[0].args
        node=ast.FunctionDef(name='gate',args=arguments,body=[copy.deepcopy(guard)],decorator_list=[])
        fn=isolated(ast.fix_missing_locations(node),dict(need=need))
        for flag,op in ((False,'source184'),(False,'desktop-alpm-v1'),(True,'desktop-alpm-v1')):invoke(fn,flag,op)
        for flag,op in ((True,'source184'),(1,'desktop-alpm-v1'),(None,'desktop-alpm-v1')):
            with self.subTest(flag=flag,operation=op),self.assertRaises(ValueError):invoke(fn,flag,op)
        self.assertLess(guard.lineno,calls(run,'provision.prior_proof')[0].lineno)
    def test_owner_passes_keyword_only_in_explicit_branch_default_call_is_held(self):
        run=function(self.owner,'run');selected=calls(run,'release_dockerfile')
        self.assertEqual(len(selected),2);with_flag=[node for node in selected if 'owned_retirement_v2'in keywords(node)]
        self.assertEqual(len(with_flag),1);self.assertIs(constant(keywords(with_flag[0])['owned_retirement_v2']),True)
        other=next(node for node in selected if node is not with_flag[0]);self.assertEqual(other.keywords,[])
        branches=[node for node in ast.walk(run)if isinstance(node,ast.If)and isinstance(node.test,ast.Name)and node.test.id=='owned_retirement_v2']
        self.assertTrue(any(with_flag[0]in calls(node)and other in [call for statement in node.orelse for call in calls(statement)]for node in branches))
    def test_invocation_default_and_legacy_route_held_new_route_is_explicit(self):
        value=json.loads((NATIVE/'invocation.json').read_bytes());operations=value['operations']
        self.assertEqual(operations['default'],'source184');self.assertNotIn('--desktop-owned-retirement-v2',value['argv'])
        self.assertEqual(value['actual'],dict(source=None,ref=None,run=None))
        self.assertEqual(operations['desktop-alpm-v1']['argv_extra'],['--operation','desktop-alpm-v1'])
        self.assertEqual(operations['desktop-alpm-v1']['matching_reader'],'native/desktop_reader_v1.py')
        selected=operations['desktop-alpm-owned-v2'];self.assertEqual(selected['argv_extra'],['--operation','desktop-alpm-v1','--desktop-owned-retirement-v2'])
        self.assertEqual(selected['matching_reader'],'native/desktop_reader_v1.py')
        self.assertEqual(selected['reader_selection'],'desktop-owned-retirement-v2-reader-v1')
        self.assertEqual(selected['reader_argv_extra'],['--retirement-selection','desktop-owned-retirement-v2-reader-v1'])
        self.assertIn('ROOT_ACTUAL_SOURCE_REF_RUN_MAP_AND_AUTHENTICATED_ARTIFACT_BINDING_REQUIRED',selected['prerequisite'])
        self.assertEqual(selected['actual'],dict(source=None,ref=None,run=None))
    def test_workflow_aliases_preserve_false_default_and_guarded_owner_route(self):
        first=(PAYLOAD/'.github/workflows/native-arm-build.yml').read_text();second=(PAYLOAD/'.github/workflows/native-arm-developer-workflows.yml').read_text()
        self.assertEqual(first,second)
        block=re.search(r'^      owned_retirement_v2:\n(.*?)(?=^[^ ]|^      [A-Za-z_]+:)',first,re.M|re.S)
        self.assertIsNotNone(block);self.assertIn('type: boolean',block[1]);self.assertIn('default: false',block[1])
        self.assertIn('options: [source184, desktop-alpm-v1]',first)
        self.assertIn('NATIVE_OWNED_RETIREMENT_V2: ${{ inputs.owned_retirement_v2 }}',first)
        case=re.search(r'case "\$NATIVE_OWNED_RETIREMENT_V2" in(.*?)esac',first,re.S);self.assertIsNotNone(case)
        self.assertIn('true) [[ "$NATIVE_OPERATION" == desktop-alpm-v1 ]]; owned_retirement_args+=(--desktop-owned-retirement-v2)',case[1])
        self.assertIn('false|"") ;;',case[1]);self.assertRegex(case[1],r'\*\) exit [12] ;;')
        self.assertIn('owned_retirement_args=()',first);self.assertIn('"${owned_retirement_args[@]}"',first)
    def test_new_data_controls_did_not_use_host_capabilities(self):self.assertEqual(CAPABILITY_ATTEMPTS,[])


class FactoryProfileControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.factory=HERE
        cls.profile_raw=(cls.factory/'profile.json').read_bytes()
        cls.profile=json.loads(cls.profile_raw)
        cls.tree=ast.parse((cls.factory/'select_owned_v2.py').read_bytes())
        cls.constants={target.id:node.value for node in cls.tree.body if isinstance(node,ast.Assign)
                       for target in node.targets if isinstance(target,ast.Name)}
    def selector(self):
        return isolated(function(self.tree,'select'),dict(need=need,SELECTION='desktop-owned-retirement-v2',
                        PARENT='72bc639de295704b94901c03ac8acf7667ff6f9c',RUNTIME=dict(**BUNDLE_PIN,mode=0o755)))
    def test_whole_profile_pin_precedes_selection_in_cli(self):
        self.assertEqual(pin(self.profile_raw)['sha256'],constant(self.constants['PROFILE_SHA256']))
        main=function(self.tree,'main');guard=next(node for node in main.body if isinstance(node,ast.Expr)and calls(node,'need'))
        selected,=calls(main,'select');self.assertLess(guard.lineno,selected.lineno)
        self.assertIn('hashlib.sha256(raw).hexdigest() == PROFILE_SHA256',ast.unparse(guard))
        self.assertIn('len(raw) <= 1024 ** 2',ast.unparse(guard))
        self.assertEqual([ast.unparse(node.args[0])for node in calls(main,'stream.read')],['1024 ** 2 + 1'])
        flag=next(node for node in calls(main,'parser.add_argument')if constant(node.args[0])=='--selection')
        self.assertIs(constant(keywords(flag)['required']),True)
    def test_explicit_selector_is_preparation_only_and_does_not_mutate_profile(self):
        before=copy.deepcopy(self.profile);value=invoke(self.selector(),self.profile,selection='desktop-owned-retirement-v2')
        self.assertEqual(self.profile,before)
        self.assertEqual(value['workflow_inputs'],dict(operation='desktop-alpm-v1',owned_retirement_v2=True))
        self.assertEqual(value['invocation_operation'],'desktop-alpm-owned-v2')
        for key in ('constructor_invoked','emitted','executed','dispatchable'):self.assertIs(value[key],False)
        self.assertEqual((value['migration'],value['native'],value['release']),('HOLD','NOT_RUN','NOT_ADMITTED'))
        self.assertEqual(value['source_delta'],self.profile['delta'])
        self.assertTrue({dotted(node.func)for node in calls(function(self.tree,'select'))} <= {'need','dict','type','all','len','value.get','runtime.get'})
    def test_selector_has_no_default_and_refuses_wrong_parent_or_runtime(self):
        fn=self.selector()
        with self.assertRaises(TypeError):invoke(fn,self.profile)
        for selection in (None,'','desktop-alpm-v1',False):
            with self.subTest(selection=selection),self.assertRaises(ValueError):invoke(fn,self.profile,selection=selection)
        for key,value in (('parent_source','0'*40),('runtime_source','0'*40),('kind','other'),
                          ('runtime',dict(**BUNDLE_PIN,mode=0o644)),('runtime',dict(bytes=True,sha256=BUNDLE_PIN['sha256'],mode=493))):
            bad=copy.deepcopy(self.profile);bad[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):invoke(fn,bad,selection='desktop-owned-retirement-v2')
    def test_selector_refuses_changed_caps_null_actuals_and_admission(self):
        changes=[(key,value)for key in ('source_files','source_map_rows','common_mapped_cap','factory_full_file_cap')for value in (True,200.0,201)]
        changes += [('actual',dict(self.profile['actual'],run='123')),('actual',dict(self.profile['actual'],extra=None)),
                    ('admission',dict(self.profile['admission'],matching_reader='QUALIFIED')),('delta',[])]
        for key,value in changes:
            bad=copy.deepcopy(self.profile);bad[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):invoke(self.selector(),bad,selection='desktop-owned-retirement-v2')
    def test_finite_delta_and_all_183_unlisted_leaves_are_closed(self):
        d=self.profile;delta={row['path']:row for row in d['delta']};self.assertEqual(len(delta),17)
        self.assertEqual(set(delta),{'.github/workflows/native-arm-build.yml','.github/workflows/native-arm-developer-workflows.yml',
                        'native/desktop_alpm_v1.py','native/desktop_owned_process_v2.py','native/invocation.json','native/owner.py',
                        'native/desktop_projection_v1.py','native/desktop_reader_v1.py','native/source-map.json',
                        'bootstrap/scripts/ci/setup6-retained-helpers/carrier-profile.json',
                        'bootstrap/scripts/ci/setup6-retained-helpers/legacy-prefill-profile.json',
                        'bootstrap/scripts/ci/setup6-retained-helpers/legacy_prefill.py',
                        'bootstrap/scripts/ci/zlib-pgo-native-hosted/owner.py','native/provision.py',
                        'native/reader.py','native/transport_proof.py','native/transport_retention.py'})
        self.assertEqual(len(d['after']),200);self.assertEqual(len(d['all_unlisted_held']),183)
        self.assertEqual(set(d['after'])-set(delta),set(d['all_unlisted_held']))
        self.assertEqual([row['path']for row in d['delta']if row['before']is None],['native/desktop_owned_process_v2.py'])
        for name,row in d['all_unlisted_held'].items():
            self.assertEqual(row,{key:d['after'][name][key]for key in ('bytes','sha256','mode')},name)
        self.assertIn('native/desktop-contract-v1.json',d['all_unlisted_held'])
        self.assertEqual(len(d['after'])-1,199)  # The sole added runtime leaf reconstructs the actual199 parent.
        for name in ('native/desktop_reader_v1.py','native/desktop_projection_v1.py'):
            self.assertIn(name,delta);self.assertNotIn(name,d['all_unlisted_held'])
    def test_before199_after200_aliases_and_held_legacy_core_metadata_join(self):
        value=self.profile;delta={row['path']:row for row in value['delta']}
        self.assertEqual(len(value['before199']),199)
        self.assertEqual(value['after200'],value['after'])
        self.assertEqual(set(value['after'])-set(value['before199']),{'native/desktop_owned_process_v2.py'})
        for name,before in value['before199'].items():
            if name in delta:self.assertEqual(before,delta[name]['before'],name)
            else:self.assertEqual(before,value['after'][name],name)
        self.assertEqual(value['before199']['scripts/virtual/owned_process.py']['sha256'],CORE834)
        self.assertEqual(value['after']['scripts/virtual/owned_process.py'],value['before199']['scripts/virtual/owned_process.py'])
        self.assertEqual(value['after']['scripts/workflows/developer_workflow.py']['sha256'],
                         '531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba')
    def test_parent_raw_commit_and_native_control_whole_data_pins_join_profile(self):
        value=self.profile;parent=value['parent'];row=parent['raw_commit']
        raw=(HERE/row['path']).read_bytes()
        self.assertEqual(pin(raw),{key:row[key]for key in ('bytes','sha256')})
        self.assertEqual(hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),parent['commit'])
        self.assertEqual(parent['commit'],value['parent_source'])
        self.assertEqual([line[5:].decode()for line in raw.split(b'\n\n',1)[0].splitlines()if line.startswith(b'tree ')],[parent['tree']])
        self.assertEqual(parent['tree'],value['parent_tree'])
        row=value['native_control'];self.assertEqual(row['path'],'native-control.json')
        self.assertEqual(pin((HERE/row['path']).read_bytes()),{key:row[key]for key in ('bytes','sha256')})
    def test_delta_candidate_bodies_modes_and_git_blob_data_pins_join_profile(self):
        for row in self.profile['delta']:
            raw=(HERE/row['candidate_body']).read_bytes();after=row['after']
            self.assertEqual(pin(raw),{key:after[key]for key in ('bytes','sha256')},row['path'])
            self.assertEqual(after['mode'],0o755 if row['path']=='native/desktop_owned_process_v2.py' else 0o644)
            self.assertEqual(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),after['blob'])
            self.assertEqual(after,self.profile['after'][row['path']])
            self.assertEqual(stat.S_IMODE((HERE/row['candidate_body']).stat().st_mode),after['mode'])
        self.assertEqual(self.profile['runtime'],dict(**BUNDLE_PIN,mode=0o755))
    def test_reader_keeps_legacy_retirement_and_business_helpers_exact(self):
        delta={row['path']:row for row in self.profile['delta']}
        self.assertEqual(delta['native/desktop_alpm_v1.py']['before']['sha256'],
                         '94b0c96301a4a7985b758d6a36d50f597478a1a010cb794602d7a73d80da8dd3')
        self.assertEqual(delta['native/desktop_alpm_v1.py']['after']['sha256'],
                         'bc5c84ae2abc21883507785b108101d5b0da964dde384c04e0c090478aeed8ca')
        expected={'retained_failure_data': '8e56b78048bb17c4e2771036218e6c6b871213c4fc0d48841e92560bbb267adf', 'retained_image_lifecycle': '7bf1d9c59a5336a2cba5b08fcd6bccfa587b7609fcfa6a650c01518a2a98af9f', 'retained_consumer_diagnostic': '81b09982b4b05c69a4e71f9ef02099c877cb8a6a4f941dfb591ada4ad885b0af', 'desktop_archive_custody': 'd5b56ce7cc14308c483d8862225a96e70810bd6cf3d332ee6c0087706e741ca4', 'retained_group_census_diagnostics': 'e2e523ea96b04f881735864c6cedb349ec2f58a8d2b84b434d20f5617ca95873', 'retained_191_provision_projection': '9bd488f5b68ce46385eae38a6eddb214823d6b8643dffbafad88992ab9fb5ca9', 'build_summary_document': '5f5b8e5e1a193817e817818fab7e406ccba9e6a9dfb9c0a016861f7f2e778831', 'bound_build_summary': '14d1f1e53c728f18aa38552ee05eebd4f3689fa66fe3e3a194c63063101618e6', 'retained_build_summary': '19e901234e656afd2bd9c11b391636bb17442c3474e78434bae044f2ba77fab1', 'retained_safe_diagnostic': '46fa7bc7e4bc8f51c287d2843061418ae7c8591e72938f136536afa326210440', 'desktop_contract': '0aa0d987c13e14f6fec523107533efaabdfa8a4343af2f1456cf3af308184464', 'strict_test_signature': 'b63949027318991c91a89c8adf049132df0a926c5787ed73d0e3b6bd4412ad40', 'desktop_commands': '5f93cec7cae5c4a69f5031b5926d6695e28e9f3f02f74639db147e73120965f5', 'desktop_metadata': '6a08462cb0bf03b3d90eaa11ed759f6b163c4fa54377cd4727c75f77b13df0e0', 'desktop_update_source': 'bf6c4c9dded24f82e80cb12625714c9f5697a195b61bf09951868651d421517a', 'desktop_build_pair': '97b357b059eaafb93e0957b043f11dc2386dacc41f8f830f2fa2e3dda2a3073e', 'desktop_update_build': 'bcb3ef7e39e6e2aeb8c28267557a8b24266ea48cabeb4f07b6dead6c60985dee', 'desktop_restoration': '25bc2d92d55ce2e406b880af323eb0ca0bd463cc7cf263b059c0978be24524a5', 'exact_agent_absence': 'a34b174b3a34c86911c38e14edcd80f01ff589846c32e698636a728963ff69a1', 'desktop_business': 'e87281fc4a19cc19f2905bff6d39fdb5eacbf0fa3d2c0162d9403bff322721ca', 'retained_transport_diagnostic': 'd72b1e2d23591acb0534fdee3043ccb9bb13ee88258c96fd2a7161b0b71eccf6', 'retained_transport_proof': '3e58e891f95c8b329483bef92b16c2cfd6e6993e33e78e61a66c4cb860c1b929'}
        tree=parse('desktop_reader_v1.py')
        for name,sha in expected.items():
            with self.subTest(legacy_function=name):self.assertEqual(ast_digest(function(tree,name)),sha)
        for name in ('desktop_reader_v1.py','desktop_projection_v1.py'):
            raw=(NATIVE/name).read_bytes()
            self.assertEqual(raw.count(b'bc5c84ae2abc21883507785b108101d5b0da964dde384c04e0c090478aeed8ca'),1)
            self.assertNotIn(b'94b0c96301a4a7985b758d6a36d50f597478a1a010cb794602d7a73d80da8dd3',raw)
    def test_proposed_map_is_full199_rows_for_full200_source_and_actuals_stay_null(self):
        delta={row['path']:row for row in self.profile['delta']}
        raw=(HERE/delta['native/source-map.json']['candidate_body']).read_bytes();mapping=json.loads(raw)
        self.assertEqual(pin(raw),{k:delta['native/source-map.json']['after'][k]for k in ('bytes','sha256')})
        self.assertEqual(mapping['actual'],dict(source=None,ref=None,run=None))
        self.assertEqual(len(mapping['files']),199)
        self.assertEqual(mapping['files'],{name:{k:row[k]for k in ('bytes','sha256','mode')}for name,row in self.profile['after'].items()if name!='native/source-map.json'})
    def test_unchanged_caps_finite_control_and_reader_actual_binding_pending_are_explicit(self):
        d=self.profile
        self.assertEqual((d['MAX_FILE'],d['MAX_TOTAL']),(64*1024**2,96*1024**2))
        self.assertIs(d['constructor_invoked'],False);self.assertIs(d['Source_generated'],False)
        self.assertEqual(d['actual'],dict(source=None,ref=None,run=None,job=None,artifact=None))
        self.assertEqual(d['admission'],dict(native_control='ROOT_ACCEPTED_FINITE_NATIVE_ARM4K_ADOPTED_ZERO_EXIT_CHILD_PROCESS_CONTROL',matching_reader='IMPLEMENTED_V2_DATA_PROTOCOL_ROOT_ACTUAL_BINDING_PENDING',
                         producer_pins='EXACT_SOURCE_PRODUCER_PINS_ONLY',publication='ROOT_ONLY_NOT_AUTHORIZED_HERE'))


class RootFiniteNativeControlMetadata(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.control=json.loads((HERE/'native-control.json').read_bytes())
    def test_exact_root_control_branch_and_same_runtime_body_mode_only(self):
        value=self.control
        self.assertIs(type(value['schema']),int);self.assertEqual(value['schema'],1)
        self.assertEqual(value['issuer'],'Root')
        self.assertEqual(value['status'],'ROOT_ACCEPTED_FINITE_NATIVE_ARM4K_ADOPTED_ZERO_EXIT_CHILD_PROCESS_CONTROL')
        self.assertEqual(value['scope'],'EXACT_NATIVE_RUNTIME_ONE_GENUINE_ADOPTED_ZERO_CHILD_BRANCH_ONLY')
        self.assertEqual(value['runtime_source'],'3ab5da1b4a11495075a9660ad09625a4ff5f0f64')
        self.assertEqual(value['runtime'],dict(**BUNDLE_PIN,mode=0o755,blob='e336152d4b0185ec704661243f0c8968ed37be44'))
        self.assertEqual(value['actual'],dict(run=41214790615,job=124576960645,attempt=1,workflow_id=402771575,
                         workflow_source='9e7c58f51548b7d901ac90084883f41b9dba4e90',architecture='aarch64',page_size=4096,python='3.14.9'))
        for key in ('run','job','attempt','workflow_id','page_size'):self.assertIs(type(value['actual'][key]),int)
    def test_zero_child_reservation_reap_and_authority_closure_are_metadata(self):
        value=self.control
        self.assertEqual(value['actual_actor_ids'],dict(wait_owner=2612,reserved_leader=2613,adopted_child=2614))
        self.assertEqual(value['WNOWAIT'],dict(observed=True,pid=2614,code='CLD_EXITED',status=0))
        self.assertEqual(value['raw_reap'],dict(attempted=True,pid=2614,exit=0,status_matches=True))
        self.assertIs(value['WNOWAIT']['observed'],True);self.assertIs(value['raw_reap']['attempted'],True)
        self.assertIs(value['raw_reap']['status_matches'],True);self.assertIs(value['authority_closed'],True)
        self.assertEqual(value['fresh_final_census'],'RESERVED_LEADER_ONLY')
        self.assertEqual(value['raw_wait_status_integer'],'NOT_EXPORTED_BY_RUNTIME_API')
        self.assertEqual(value['actual_Desktop_zombie1844_ownership'],'UNKNOWN_UNCHANGED')
        self.assertEqual(value['ZIP_GETs'],1);self.assertEqual(value['passive_decoder_calls'],1)
        self.assertEqual(value['original_zip'],dict(bytes=20632,sha256='1574ddde109838adcf9dffc9d9213c95abf9c624dcb8e560b7117ae8ce7af311'))
        self.assertRegex(value['root_acceptance_sha256'],r'^[0-9a-f]{64}$')
        self.assertEqual(set(value['role_pins']),{'control/intent.json','control/result.json','control/runtime-result.json','manifest.json','source-provenance.json'})
        for row in value['role_pins'].values():
            self.assertEqual(set(row),{'bytes','sha256'});self.assertIs(type(row['bytes']),int)
            self.assertGreater(row['bytes'],0);self.assertRegex(row['sha256'],r'^[0-9a-f]{64}$')
    def test_other_branches_default_component_targets_and_release_are_not_qualified(self):
        limits=self.control['scope_limits']
        expected={'all_runtime_branches_native_qualified','component_ALPM_acceptance','default_legacy834_migration',
                  'Developer_migration','M2','Asahi_installed','native16K','performance','production_trust','release'}
        self.assertEqual(set(limits),expected)
        for key in expected:self.assertIs(limits[key],False,key)


class PhysicalCarrierDATAControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bridge_raw=(HERE/'physical-carrier-bridge.json').read_bytes()
        cls.bridge=json.loads(cls.bridge_raw)
        cls.raw=(HERE/'carrier-current-commit.raw').read_bytes()
        cls.carrier=(PAYLOAD/'bootstrap/scripts/ci/setup6-retained-helpers/carrier-profile.json').read_bytes()
        cls.factory=ast.parse((HERE/'prepare.py').read_bytes())
        cls.profile=json.loads((HERE/'profile.json').read_bytes())
    def validator(self):
        def oid(kind,raw):return hashlib.sha1(kind+b' '+str(len(raw)).encode()+b'\0'+raw).digest()
        return isolated(function(self.factory,'carrier_identity'),dict(need=need,pin=pin,oid=oid,document=json.loads))
    def test_current_raw_commit_full_tree_profile_and_bridge_are_bound_as_data(self):
        before=copy.deepcopy(self.bridge)
        self.assertIs(invoke(self.validator(),self.bridge,self.raw,self.carrier),self.bridge)
        self.assertEqual(self.bridge,before)
        self.assertEqual(pin(self.raw),dict(bytes=287,sha256='52311786d11bd25af74a108efe9399b253a6bdad6e36c5b36f03ab70b6756e36'))
        self.assertEqual(hashlib.sha1(b'commit '+str(len(self.raw)).encode()+b'\0'+self.raw).hexdigest(),
                         '4659076d3a1d3e5cf87c185a3ff383fbc38e734d')
        self.assertEqual(self.bridge['tree'],'e21f947bac3afdfbd67e4e65c8234b35ae42b00f')
        selected=self.profile['physical_carrier_bridge']
        self.assertEqual(selected['path'],'physical-carrier-bridge.json')
        self.assertEqual(pin(self.bridge_raw),{k:selected[k]for k in ('bytes','sha256')})
        factory_profile=function(self.factory,'profile')
        self.assertEqual(len(calls(factory_profile,'physical_carrier')),1)
        self.assertLess(calls(factory_profile,'physical_carrier')[0].lineno,factory_profile.body[-1].lineno)
    def test_historical_raw_header_cannot_be_used_as_current_commit(self):
        old=self.raw.replace(b'93809974+Gabriel-Kahen@users.noreply.github.com',b'gabe@users.noreply.github.com')
        self.assertEqual(pin(old),dict(bytes=251,sha256='0e3c9f82541401886b12c5dbf2fa925655dcdcd6ae966a05723a41c4dedbef86'))
        self.assertEqual(hashlib.sha1(b'commit '+str(len(old)).encode()+b'\0'+old).hexdigest(),
                         self.bridge['historical']['commit'])
        for raw in (old,self.raw+b'\n',self.raw.replace(b'e21f947b',b'00000000')):
            with self.subTest(raw_pin=pin(raw)),self.assertRaises(ValueError):
                invoke(self.validator(),self.bridge,raw,self.carrier)
        self.assertEqual(self.bridge['historical_raw_header'],'HISTORICAL_ONLY_NOT_CURRENT_OPERAND')
        self.assertNotEqual(self.bridge['historical']['commit'],self.bridge['current']['commit'])
    def test_changed_tree_current_source_profile_body_or_historical_metadata_refuses(self):
        changes=[('schema',True),('tree','0'*40),('code_tree','REBUILT'),('historical_raw_header','CURRENT')]
        for key,value in changes:
            bad=copy.deepcopy(self.bridge);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                invoke(self.validator(),bad,self.raw,self.carrier)
        for section,key,value in [('current','commit',self.bridge['historical']['commit']),
                                  ('historical','commit','0'*40),('current_carrier_profile','sha256','0'*64)]:
            bad=copy.deepcopy(self.bridge);bad[section][key]=value
            with self.subTest(section=section,key=key),self.assertRaises(ValueError):
                invoke(self.validator(),bad,self.raw,self.carrier)
        for carrier in (self.carrier+b'\n',self.carrier.replace(b'4659076d3a1d3e5cf87c185a3ff383fbc38e734d',
                                                               b'ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad')):
            with self.subTest(carrier_pin=pin(carrier)),self.assertRaises(ValueError):
                invoke(self.validator(),self.bridge,self.raw,carrier)
    def test_carrier_literal_inverses_and_versioned_reader_transport_seam_are_exact(self):
        names={'bootstrap/scripts/ci/setup6-retained-helpers/carrier-profile.json',
               'bootstrap/scripts/ci/setup6-retained-helpers/legacy-prefill-profile.json',
               'bootstrap/scripts/ci/setup6-retained-helpers/legacy_prefill.py',
               'bootstrap/scripts/ci/zlib-pgo-native-hosted/owner.py','native/provision.py',
               'native/transport_proof.py','native/transport_retention.py','native/desktop_reader_v1.py','native/reader.py'}
        substitutions=[(b'4659076d3a1d3e5cf87c185a3ff383fbc38e734d',b'ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'),
                       (b'47ea6a3f358922ad1d643bc2cbd517fe0335f5dbe1313a87af3d24396d5a39ea',b'4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'),
                       (b'91f15e75afff88b7379eaba720f725a0efe6f642648f8dbf002bff058d11ba7c',b'9cc82d4e0947415ecad9d40094a4c0a2709d01be54513e78af8c739fd76fb696')]
        for name in sorted(names):
            raw=(PAYLOAD/name).read_bytes();restored=raw
            for current,old in substitutions:restored=restored.replace(current,old)
            before=self.profile['before199'][name]
            if name=='native/desktop_reader_v1.py':
                # This leaf now also implements the versioned reader. Bind its
                # carrier-only function instead of pretending the whole reader
                # can still be restored using literal substitutions alone.
                tree=ast.parse(restored)
                seam=ast.get_source_segment(restored.decode(),function(tree,'retained_transport_proof')).encode()
                self.assertEqual(pin(seam),{'bytes': 1434, 'sha256': 'e82e9ea58ef41cad81c5cd9ef0134e918d8db6c8dc19860827cab1a6d51ff85d'},name)
                current_seam=ast.get_source_segment(raw.decode(),function(ast.parse(raw),'retained_transport_proof')).encode()
                for current,old in substitutions[:2]:self.assertEqual(current_seam.count(current),1,name)
            else:
                self.assertEqual(pin(restored),{k:before[k]for k in ('bytes','sha256')},name)
            self.assertNotEqual(raw,restored,name)
            self.assertEqual(self.profile['after200'][name]['mode'],before['mode'])
        self.assertEqual(CAPABILITY_ATTEMPTS,[])


if __name__=='__main__':unittest.main(verbosity=2)
