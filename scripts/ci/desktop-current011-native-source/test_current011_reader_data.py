#!/usr/bin/env python3
"""Prospective helper DATA/AST tests; never invoke a reader or Source entry."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
PAYLOAD = HERE / ('payload' if (HERE/'payload/native/desktop_reader_v1.py').is_file() else 'candidate')
READER = PAYLOAD / 'native/desktop_reader_v1.py'
PROJECTOR = PAYLOAD / 'native/desktop_projection_v1.py'
PURE = False
ATTEMPTS = []


def audit(event, args):
    actors = event.startswith(('subprocess.', 'socket.', 'ctypes.', 'signal.', 'fcntl.')) or event in {
        'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn', 'os.kill', 'os.killpg', 'os.wait', 'os.waitpid'}
    if actors or PURE and (event == 'open' or event.startswith('os.')):
        ATTEMPTS.append(event)
        raise AssertionError('prospective reader DATA forbids capability: ' + event)
sys.addaudithook(audit)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def stable_ast_digest(node):
    node = copy.deepcopy(node)
    for item in ast.walk(node):
        for name,value in list(ast.iter_fields(item)):
            if type(value) is list and not value: delattr(item,name)
    return hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest()


def invoke(function, *args, **kwargs):
    global PURE
    PURE = True
    try:
        return function(*args, **kwargs)
    finally:
        PURE = False


def namespace():
    names = {'owned_v2_need', 'owned_v2_hash', 'current011_reader_contract', 'current011_package_marker',
             'current011_contract_value', 'current011_source_contract', 'current011_projection_contract', 'current011_env_business',
             'current011_build_launcher', 'owned_v2_build_launcher'}
    constants = {'OPERATION', 'OWNED_V2_READER_SELECTION', 'OWNED_V2_READER_CONTRACT', 'OWNED_V2_READER_LAYOUT', 'OWNED_V2_READER_RUNTIME',
                 'CURRENT011_READER_SELECTION', 'CURRENT011_READER_CONTRACT', 'CURRENT011_PACKAGE_MARKER', 'CURRENT011_PRODUCERS'}
    nodes = []
    for node in ast.parse(READER.read_bytes()).body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in node.targets):
            nodes.append(node)
    result = dict(need=need, pin=pin, re=re, json=json, hashlib=hashlib, Path=Path)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), '<pure-current011-helpers>', 'exec'), result)
    return result


class Contracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ns = namespace()
        cls.contract = json.loads((PAYLOAD / 'native/desktop-contract-v1.json').read_bytes())

    def test_current_contract_has_exact_package_pair_and_source(self):
        self.assertIs(invoke(self.ns['current011_contract_value'], self.contract), self.contract)
        self.assertEqual(self.contract['recipe']['expected_test_count'], 91)
        self.assertEqual(len(self.contract['recipe']['payload_files']), 6)
        self.assertEqual(self.contract['actual'], dict(source=None, ref=None, run=None, job=None, artifact=None))

    def test_other_versions_and_test_count_types_never_qualify(self):
        changes = [('version', '0.1.0-1'), ('version', '0.1.2-1'), ('expected_test_count', 81),
                   ('expected_test_count', 91.0), ('expected_test_count', True)]
        for key, value in changes:
            bad = copy.deepcopy(self.contract); bad['recipe'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                invoke(self.ns['current011_contract_value'], bad)

    def test_contract_cannot_claim_actuals_or_other_accepted_source(self):
        for target in ('actual', 'main', 'package'):
            bad = copy.deepcopy(self.contract)
            if target == 'actual': bad['actual']['run'] = '123'
            elif target == 'main': bad['product']['accepted_main'] = 'a' * 40
            else: bad['product']['package_source_commit'] = 'b' * 40
            with self.subTest(target=target), self.assertRaises(ValueError):
                invoke(self.ns['current011_contract_value'], bad)

    def test_current_marker_is_exact_and_typed(self):
        value = dict(package_selection=copy.deepcopy(self.ns['CURRENT011_PACKAGE_MARKER']))
        invoke(self.ns['current011_package_marker'], value)
        for key, replacement in [('schema', True), ('expected_test_count', 91.0), ('version', '0.1.0-1'),
                                 ('source_archive_sha256', 'a' * 64), ('selection', 'desktop-owned-retirement-v2')]:
            bad = copy.deepcopy(value); bad['package_selection'][key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                invoke(self.ns['current011_package_marker'], bad)

    def mapping(self):
        files = {'native/desktop_owned_process_v2.py': dict(self.ns['OWNED_V2_READER_RUNTIME'], mode=0o755)}
        files['native/desktop_owned_process_v2.py'].pop('path')
        for name, sha in self.ns['CURRENT011_PRODUCERS'].items(): files[name] = dict(bytes=100, sha256=sha, mode=0o644)
        files['native/desktop_reader_v1.py'] = dict(bytes=100, sha256='a' * 64, mode=0o644)
        for i in range(199-len(files)): files['synthetic/' + str(i)] = dict(bytes=1, sha256='a' * 64, mode=0o644)
        return dict(schema=1, actual=dict(source=None, ref=None, run=None), desktop_operation='desktop-alpm-v1', files=files,
                    desktop_owned_v2_reader=copy.deepcopy(self.ns['OWNED_V2_READER_CONTRACT']),
                    desktop_current011_reader=copy.deepcopy(self.ns['CURRENT011_READER_CONTRACT']))

    def test_source200_map199_current_contract_and_exact_producer_pins(self):
        mapping = self.mapping(); expected = dict(source='a'*40, ref='refs/heads/codex/SYNTHETIC', run='123', map_sha256='b'*64)
        invoke(self.ns['current011_source_contract'], mapping, expected, expected['map_sha256'])
        for target in ('source', 'map', 'producer', 'count', 'runtime', 'typed_contract'):
            bad = copy.deepcopy(mapping); exp = dict(expected)
            if target == 'source': exp['source'] = None
            elif target == 'map': exp['map_sha256'] = 'c'*64
            elif target == 'producer': bad['files']['native/desktop_tools_v1.py']['sha256'] = 'd'*64
            elif target == 'count': bad['files'].pop('synthetic/0')
            elif target == 'runtime': bad['files']['native/desktop_owned_process_v2.py']['mode'] = 0o644
            else: bad['desktop_current011_reader']['expected_test_count'] = 91.0
            with self.subTest(target=target), self.assertRaises(ValueError):
                invoke(self.ns['current011_source_contract'], bad, exp, expected['map_sha256'])

    def test_projection_keeps_old_runtime_layout_and_adds_current_scope(self):
        binding = dict(source='a'*40, ref='refs/heads/codex/SYNTHETIC', run='123')
        value = dict(binding=binding, source_map_sha256='b'*64, source_producers=self.ns['CURRENT011_PRODUCERS'],
                     omitted_private_scopes=['journey/desktop-alpm-v1/home'], omitted_private_trees_walked=False,
                     original_output_unchanged=True, owned_retirement_reader=self.ns['OWNED_V2_READER_LAYOUT'],
                     current011_reader=self.ns['CURRENT011_READER_CONTRACT'])
        invoke(self.ns['current011_projection_contract'], value, binding, 'b'*64)
        for target in ('scope', 'private', 'runtime'):
            bad = copy.deepcopy(value)
            if target == 'scope': bad['current011_reader']['package_version'] = '0.1.0-1'
            elif target == 'private': bad['omitted_private_trees_walked'] = True
            else: bad['owned_retirement_reader']['runtime']['bytes'] += 1
            with self.subTest(target=target), self.assertRaises(ValueError):
                invoke(self.ns['current011_projection_contract'], bad, binding, 'b'*64)


class Conservation(unittest.TestCase):
    def held(self, name, candidate, expected):
        value = json.loads((HERE/'legacy-ast.json').read_bytes())[name]
        self.assertEqual((value['bytes'],value['sha256']), expected)
        actual = {};segments={};text=candidate.read_text()
        for node in ast.parse(text).body:
            if isinstance(node, ast.FunctionDef): key = 'function:' + node.name
            elif isinstance(node, ast.Assign): key = 'assignment:' + ','.join(t.id for t in node.targets if isinstance(t,ast.Name))
            else: continue
            actual[key] = stable_ast_digest(node)
            segments[key] = hashlib.sha256(ast.get_source_segment(text,node).encode()).hexdigest()
        for key, digest in value['ast'].items(): self.assertEqual(actual[key],digest,key)
        for key,digest in value['source_segments'].items(): self.assertEqual(segments[key],digest,key)

    def test_every_legacy_reader_predicate_and_constant_is_held(self):
        self.held('desktop_reader_v1.py', READER,
                  (140631,'837e3f83cc2b1433a282c3bf5edb3f3e06c1e9d18264362680d28ae97b60a24e'))

    def test_every_legacy_projector_predicate_and_constant_is_held(self):
        self.held('desktop_projection_v1.py', PROJECTOR,
                  (20728,'621598cf1408fe1414637e4d787b67aeca2c8f228e567ea7b7911ec2a05c0b5f'))

    def test_current_dispatch_is_explicit_and_source_verification_precedes_capsule(self):
        nodes = {x.name:x for x in ast.parse(READER.read_bytes()).body if isinstance(x, ast.FunctionDef)}
        function = nodes['validate_current011']
        self.assertEqual(function.args.kw_defaults, [None])
        self.assertIn('retirement_selection == CURRENT011_READER_SELECTION', ast.unparse(function.body[0]))
        calls = [x.func.id for x in ast.walk(function) if isinstance(x, ast.Call) and isinstance(x.func, ast.Name)]
        self.assertIn('current011_source_contract', calls)
        source = ast.unparse(function); self.assertLess(source.index('current011_source_contract('), source.index('open_capsule('))
        self.assertIn('return validate(capsule_path, expected, retirement_selection=retirement_selection)', ast.unparse(nodes['validate_selected']))
        original = nodes['validate']; defaults = dict(zip([x.arg for x in original.args.kwonlyargs], original.args.kw_defaults))
        self.assertEqual(ast.literal_eval(defaults['retirement_selection']), 'legacy834')

    def test_no_actual_reader_or_projection_entry_is_run_by_tests(self):
        self.assertEqual(ATTEMPTS, [])
        self.assertNotIn('validate_current011', namespace())
        self.assertNotIn('project_current011', namespace())


class OuterGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = json.loads((HERE/'source-audit.json').read_bytes())
        cls.closure = json.loads((HERE/'closure.json').read_bytes())
        cls.ns = namespace()
        cls.producer = PAYLOAD if (PAYLOAD/'native/owner.py').is_file() else HERE.parent/'constructor/candidate/scripts/ci/desktop-current011-native-source/payload'

    def common(self, name, extra=None):
        scope = dict(need=need, pin=pin, re=re, hashlib=hashlib, **self.audit['common_constants'])
        scope.update(extra or {})
        exec(compile(ast.parse(self.audit['extracted']['native/common.py'][name]), '<committed-pure-common-helper>', 'exec'),scope)
        return scope[name]

    def test_current_launcher_accepts_only_exact_current_inside_flag(self):
        source = (self.producer/'native/desktop_alpm_v1.py').read_bytes()
        nodes = [x for x in ast.parse(source).body if isinstance(x,ast.FunctionDef) and x.name in ('dockerfile','current011_dockerfile')]
        scope = dict(need=need,json=json,re=re)
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])), '<pure-dockerfile-formatters>', 'exec'),scope)
        scope['_LEGACY_DOCKERFILE'] = scope['dockerfile']
        raw = invoke(scope['current011_dockerfile'],'FROM SYNTHETIC\nUSER alarm\nWORKDIR /tmp\n','a'*64,owned_retirement_v2=True).encode()
        invoke(self.ns['current011_build_launcher'],raw,'a'*64)
        for wrong in (raw.replace(b'--current011 ',b''),raw.replace(b'--current011 ',b'--current012 '),raw.replace(b'--owned-retirement-v2 ',b''),raw.replace(b' -p,',b','),raw.replace(b'a'*64,b'b'*64)):
            if wrong != raw:
                with self.subTest(raw=pin(wrong)),self.assertRaises(ValueError):invoke(self.ns['current011_build_launcher'],wrong,'a'*64)
        with self.assertRaises(ValueError):invoke(self.ns['owned_v2_build_launcher'],raw,'a'*64)

    def test_owner_and_inside_wrappers_reenter_held_admission(self):
        tree = ast.parse((self.producer/'native/owner.py').read_bytes())
        nodes = {n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
        current = ast.unparse(nodes['run_current011'])
        self.assertLess(current.index('current011_selection(args)'),current.index('verify_source(root, args.map_sha256)'))
        self.assertLess(current.index('verify_source(root, args.map_sha256)'),current.index('return run(root, args)'))
        self.assertIn('admission(root, args, os.environ)',ast.unparse(nodes['run'].body[0]))
        self.assertIn('verify_source(root, args.map_sha256)',ast.unparse(nodes['admission'].body[0]))
        self.assertIn("selection='desktop-current011-owned-v2-reader-v1'",current)
        inside = {n.name:n for n in ast.parse((self.producer/'native/desktop_alpm_v1.py').read_bytes()).body if isinstance(n,ast.FunctionDef)}
        body = ast.unparse(inside['current011_inside'])
        self.assertIn('owned_retirement_v2 is True',ast.unparse(inside['current011_inside'].body[0]))
        self.assertIn('return inside(source, map_hash, owned_retirement_v2=True)',body)
        self.assertIn('finally:',body)
        self.assertIn('verify_source(source, map_hash)',ast.unparse(inside['inside']))

    def test_exact_invocation_params_match_reader_cli_and_remain_null(self):
        invocation = json.loads((self.producer/'native/invocation.json').read_bytes())
        value = invocation['operations']['desktop-current011-owned-v2']
        self.assertEqual(value['argv_extra'],['--operation','desktop-alpm-v1','--desktop-owned-retirement-v2','--desktop-current011'])
        self.assertEqual(value['reader_argv_extra'],['--retirement-selection',self.ns['CURRENT011_READER_SELECTION']])
        self.assertEqual(value['matching_reader'],'native/desktop_reader_v1.py')
        self.assertTrue(all(v is None for v in value['actual'].values()))
        self.assertEqual(invocation['operations']['default'],'source184')
        prepare = ast.parse((self.producer.parent/'prepare.py').read_bytes())
        metadata = next(n for n in prepare.body if isinstance(n,ast.FunctionDef) and n.name=='metadata')
        self.assertIn("'params.NULL.json': encoded(dict(NULL_ACTUAL, matching_reader=None))",ast.unparse(metadata))
        self.assertIn("'reader-binding.NULL.json': encoded(NULL_READER)",ast.unparse(metadata))

    def test_common_binding_requires_complete_same_source_manual_first_attempt(self):
        source,ref,run='a'*40,'refs/heads/codex/SYNTHETIC_DATA','123'
        env=dict(GITHUB_SHA=source,GITHUB_WORKFLOW_SHA=source,GITHUB_REF=ref,GITHUB_RUN_ID=run,
                 GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',
                 GITHUB_WORKFLOW_REF='Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-build.yml@'+ref)
        binding=self.common('binding');self.assertEqual(invoke(binding,source,ref,run,env)['attempt'],1)
        for key in env:
            bad=dict(env);bad[key]='SYNTHETIC_WRONG'
            with self.subTest(key=key),self.assertRaises(ValueError):invoke(binding,source,ref,run,bad)
        for params in [(None,ref,run),(source,None,run),(source,ref,None),(source,'refs/heads/main',run)]:
            with self.subTest(params=params),self.assertRaises(ValueError):invoke(binding,*params,env)

    def test_existing_consumer_resource_mount_and_identity_gates_hold(self):
        own=dict(token='SYNTHETIC_TOKEN',source='a'*40);label=self.audit['common_constants']['LABEL']
        row=dict(Name='/developer-'+own['token'],Image='sha256:SYNTHETIC',
                 Config=dict(Labels={label:own['token'],label+'.source':own['source']},User='1000:1000'),
                 HostConfig=dict(NetworkMode='none',ReadonlyRootfs=True,Privileged=False,PidsLimit=256,
                  Memory=4*1024**3,NanoCpus=2_000_000_000,CapDrop=['ALL'],CapAdd=[],SecurityOpt=['no-new-privileges'],
                  Devices=[],DeviceRequests=[],VolumesFrom=[],Tmpfs={'/tmp':'rw,nosuid,nodev,exec,size=2g'}),
                 Mounts=[dict(Type='bind',Destination='/source',Source='/SYNTHETIC_SOURCE',RW=False),
                         dict(Type='bind',Destination='/out',Source='/SYNTHETIC_OUTPUT',RW=True),dict(Type='tmpfs',Destination='/tmp')])
        validate=self.common('consumer_contract');args=(own,'sha256:SYNTHETIC','/SYNTHETIC_SOURCE','/SYNTHETIC_OUTPUT',1000,1000)
        invoke(validate,row,*args)
        for key,value in [('NetworkMode','host'),('ReadonlyRootfs',False),('Privileged',True),('PidsLimit',257),
                          ('Memory',8*1024**3),('NanoCpus',3_000_000_000),('CapAdd',['SYS_ADMIN']),('SecurityOpt',[])]:
            bad=copy.deepcopy(row);bad['HostConfig'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):invoke(validate,bad,*args)
        for key in ('Name','Image'):
            bad=copy.deepcopy(row);bad[key]='SYNTHETIC_WRONG'
            with self.subTest(key=key),self.assertRaises(ValueError):invoke(validate,bad,*args)
        bad=copy.deepcopy(row);bad['Mounts'][0]['RW']=True
        with self.assertRaises(ValueError):invoke(validate,bad,*args)

    def test_current_success_path_retains_outer_and_retirement_guard_calls(self):
        nodes={n.name:n for n in ast.parse(READER.read_bytes()).body if isinstance(n,ast.FunctionDef)}
        current=ast.unparse(nodes['validate_current011'])
        for gate in ('view.verify_manifest(manifest)','current011_source_contract(', 'current011_public_projection(',
                     'retained_consumer_diagnostic(', 'retained_failure_data(', 'retained_image_lifecycle(',
                     'consumer_contract(', 'retained_transport_proof(', 'current011_build_layout(',
                     'current011_retained_desktop_alpm(', 'current011_package_marker(receipt)'):
            self.assertIn(gate,current)
        component=ast.unparse(nodes['current011_retained_desktop_alpm'])
        for gate in ('owned_v2_validate_selection(', 'owned_v2_process_layout(', 'desktop_commands_v2(',
                     'strict_test_signature(', 'current011_build_pair(', 'current011_update_build(',
                     'current011_business(', 'desktop_restoration(', 'exact_agent_absence_v2('):
            self.assertIn(gate,component)
        self.assertIn("native='NOT_ADMITTED'",current)
        self.assertIn("physical_M2='NOT_RUN'",current)
        self.assertNotIn("native='PASS'",current)

    def test_closed_source_gate_is_exercised_only_on_in_memory_data(self):
        bodies={'native/a':b'SYNTHETIC_A','native/b':b'SYNTHETIC_B'}
        mapping=dict(schema=1,actual=dict(source=None,ref=None,run=None),files={n:dict(mode=0o644,**pin(v)) for n,v in bodies.items()})
        raw=encoded(mapping);modes={n:0o644 for n in bodies};aliases=set();extra=[]
        class DataPath(PurePosixPath):
            def absolute(self):return self
            def is_symlink(self):return str(self) in aliases
            def stat(self):return SimpleNamespace(st_mode=modes[str(self.relative_to('/SYNTHETIC'))])
        def walk(root,followlinks=False):
            return [('/SYNTHETIC',['native'],[]),('/SYNTHETIC/native',[],['source-map.json','a','b']+extra)]
        verify=self.common('verify_source',dict(Path=DataPath,MAP='native/source-map.json',os=SimpleNamespace(walk=walk),stat=stat,
                           json=json,read=lambda path:raw,source_bytes=lambda root,name:bodies[name]))
        self.assertEqual(invoke(verify,'/SYNTHETIC',pin(raw)['sha256']),mapping)
        for mutation in ('hash','mode','body','extra','alias','actual'):
            oldraw,oldbody=raw,bodies['native/a']
            if mutation=='hash':checksum='b'*64
            else:checksum=pin(raw)['sha256']
            if mutation=='mode':modes['native/a']=0o755
            elif mutation=='body':bodies['native/a']=b'WRONG'
            elif mutation=='extra':extra.append('unlisted')
            elif mutation=='alias':aliases.add('/SYNTHETIC/native')
            elif mutation=='actual':
                bad=copy.deepcopy(mapping);bad['actual']['run']='123';raw=encoded(bad);checksum=pin(raw)['sha256']
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):invoke(verify,'/SYNTHETIC',checksum)
            raw=oldraw;bodies['native/a']=oldbody;modes['native/a']=0o644;aliases.clear();extra.clear()

    def test_generic_reader_capsule_provision_and_unchanged_caps_are_audited(self):
        self.assertFalse(self.audit['generic_reader']['on_desktop_success_call_path'])
        self.assertFalse(self.audit['generic_reader']['patch_required'])
        self.assertNotIn('native/reader.py',self.audit['python_import_graph']['native/desktop_reader_v1.py'])
        source=self.audit['extracted']['native/capsule.py']['open_capsule']
        self.assertIn('_ordinary(path, CAP)',source);self.assertIn('PAYLOAD_CAP',source);self.assertIn('INDEX_CAP',source)
        self.assertIn('retained payload bytes/hash differs',source)
        provision=self.audit['extracted']['native/provision.py']['admit']
        self.assertLess(provision.index('verify_source('),provision.index('binding('))
        for gate in ('input_contract(',"platform.machine() in ('aarch64', 'arm64')",'os.getuid() == os.geteuid() != 0',"'RUNNER_ARCH'",'args.execute'):
            self.assertIn(gate,provision)
        caps=self.closure['limits']
        self.assertEqual((caps['source_files'],caps['source_map_rows'],caps['source_file_bytes'],caps['source_total_bytes']),(200,199,64*1024**2,96*1024**2))
        self.assertEqual((caps['public_bytes'],caps['payload_bytes'],caps['index_bytes']),(32*1024**2,16*1024**2,1024**2))
        self.assertEqual((caps['capsule_leaves'],caps['capsule_directories'],caps['capsule_depth']),(3001,3000,128))
        self.assertEqual(sum(map(len,self.closure['namespace'].values())),200)


class EnvEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ns = namespace()

    def fixture(self, label='system'):
        prefix = 'journey/desktop-alpm-v1/'
        fixed = Path('/opt/native-desktop-tools-alpm-v1')
        home = fixed/'user-data'/dict(system='system', moved='relocated', updated='updated')[label]
        cli = str(fixed/'user-data/moved-prefix/usr/bin/cachy-asahi-desktop-tools') if label == 'moved' else '/usr/bin/cachy-asahi-desktop-tools'
        logical = '/home/fixture/.local/share/applications/tool.desktop'
        texts = dict(env_unset_capture='env --unset=WAYLAND_DISPLAY tool-link %F',
                     env_unset_audit='env --unset=WAYLAND_DISPLAY tool-link %F',
                     env_unset_path_refusal='env --unset=PATH tool-link %F',
                     env_unset_absolute_capture='env --unset=PATH /usr/bin/tool-link %F',
                     env_unset_restored_capture='env --unset=PATH PATH=/usr/bin tool-link %F',
                     env_unset_malformed_refusal='env --unset= tool-link %F')
        def file(key):
            raw = ('[Desktop Entry]\nType=Application\nName=Current user override\nExec=' + texts[key]
                   + '\nTryExec=tool\nTerminal=true\nNoDisplay=true\nIcon=fixture\nMimeType=text/plain;\n').encode()
            return dict(path=logical, resolved=logical, mode='0o644', symlinks=[], **pin(raw))
        env = pin(b'SYNTHETIC_EXPLICIT_ENVIRONMENT_DATA')
        def inventory(key):
            files = {logical:file(key)}
            for i in range(8): files['/synthetic/'+str(i)] = dict(path='/synthetic/'+str(i), resolved='/synthetic/'+str(i), mode='0o644', symlinks=[], **pin(b''))
            return dict(schema=1, kind='cachy-asahi-desktop-static-inventory-v1', selected=['tool.desktop'], mime=['text/plain'], environment=env, files=files, audit_sha256='a'*64)
        capture = inventory('env_unset_capture')
        audited = dict(schema=1, status='PASS_STAGED_CHECKS', scope='STAGED_DESKTOP_INTEGRATION_ONLY',
                       root=str(home/'moved-staged-root'), pins=capture['files'],
                       applications=[dict(id='tool.desktop', origin='user_override', path=logical,
                           exec=dict(argv_without_file_inputs=['env','--unset=WAYLAND_DISPLAY','tool-link'],
                                     resolution=dict(env_target=dict(file=dict(path='/usr/bin/tool-link')))))])
        capture['audit_sha256'] = hashlib.sha256(json.dumps({k:v for k,v in audited.items() if k!='root'}, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()).hexdigest()
        data = dict(env_unset_capture=capture, env_unset_audit=audited,
                    env_unset_absolute_capture=inventory('env_unset_absolute_capture'), env_unset_restored_capture=inventory('env_unset_restored_capture'))
        for key, error in [('env_unset_path_refusal','env PATH unset; platform default search is not inferred'),
                           ('env_unset_malformed_refusal','invalid env unset variable')]:
            data[key] = dict(status='FAIL_STAGED_CHECKS', applications=[dict(origin='user_override', path=logical,
                             file=file(key), exec=dict(resolution=dict(env_target=dict(error=error))))])
        capture_raw = encoded(capture); captured = pin(capture_raw)
        audited.update(inventory_input=captured, inventory_binding='EXACT_STATIC_INVENTORY')
        keys = ('env_unset_capture','env_unset_audit','env_unset_path_refusal','env_unset_absolute_capture','env_unset_restored_capture','env_unset_malformed_refusal')
        logs, commands, positions = {}, {}, {}
        row = dict(schema=1, selection='GNU_ENV_UNSET_EQUALS_BOUNDED', inventory=captured,
                   inventory_leaf='env-unset-inventory.json', override_logical=logical,
                   override_before=pin(('[Desktop Entry]\nType=Application\nName=Current user override\nExec='+texts['env_unset_capture']+'\nTryExec=tool\nTerminal=true\nNoDisplay=true\nIcon=fixture\nMimeType=text/plain;\n').encode()),
                   override_preserved=True, reports={}, steps={},
                   checks=dict(long_form='PASS_STAGED_CHECKS',path_basename='FAIL_STAGED_CHECKS',absolute='PASS_CAPTURE_INVENTORY',restored='PASS_CAPTURE_INVENTORY',malformed='FAIL_STAGED_CHECKS'), zero_payload_execution=True)
        row['override_after'] = dict(row['override_before'])
        for i,key in enumerate(keys,110):
            raw = encoded(data[key]); leaf = '%03d-%s.log'%(i,key.replace('_','-')); step=label+'-'+key.replace('_','-')
            operation = 'audit' if key=='env_unset_audit' else 'capture'
            argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(home),cli,operation,'--root',str(home/'moved-staged-root'),'--environment',str(home/'environment.json'),'--select','tool.desktop','--mime','text/plain']
            if operation=='audit':argv+=['--inventory',str(home/'env-unset-inventory.json'),'--inventory-sha256',captured['sha256']]
            command=dict(argv=argv,cwd=str(home),expected=1 if key in('env_unset_path_refusal','env_unset_malformed_refusal')else 0,log=leaf,log_pin=pin(raw))
            logs[prefix+leaf]=raw;commands[step]=command;positions[step]=i;row['steps'][key]=step;row['reports'][key]=pin(raw)
        class View:
            def read(self,name):return logs[name]
        value=dict(env_unset=row,environment=env)
        def selected(step):return positions[step],commands[step]
        return dict(value=value,view=View(),selected=selected,logs=logs,commands=commands,positions=positions,home=home,cli=cli,label=label,prefix=prefix,data=data)

    def call(self, fixture):
        return invoke(self.ns['current011_env_business'], fixture['view'], fixture['prefix'], fixture['value'], fixture['selected'], fixture['cli'], fixture['home'], fixture['label'], 100, 200)

    def repin(self, fixture, key, change):
        data=copy.deepcopy(fixture['data'][key]);change(data);step=fixture['value']['env_unset']['steps'][key];command=fixture['commands'][step];raw=encoded(data)
        fixture['logs'][fixture['prefix']+command['log']]=raw;command['log_pin']=pin(raw);fixture['value']['env_unset']['reports'][key]=pin(raw)

    def test_all_six_probes_are_bound_for_system_moved_and_updated(self):
        for label in ('system','moved','updated'):
            with self.subTest(label=label):self.assertEqual(self.call(self.fixture(label)),115)

    def test_presence_types_and_user_preservation_are_required(self):
        for key, value in [('schema',True),('override_preserved',False),('zero_payload_execution',False),
                           ('selection','OTHER'),('inventory_leaf','inventory.json')]:
            fixture=self.fixture();fixture['value']['env_unset'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.call(fixture)
        fixture=self.fixture();fixture['value']['env_unset']['override_after']['sha256']='f'*64
        with self.assertRaises(ValueError):self.call(fixture)
        fixture=self.fixture();fixture['value']['env_unset']['reports'].pop('env_unset_path_refusal')
        with self.assertRaises(ValueError):self.call(fixture)

    def test_actual_argv_outcomes_and_order_cannot_be_replaced_by_claims(self):
        for change in ('argv','expected','cwd','order'):
            fixture=self.fixture();step=fixture['value']['env_unset']['steps']['env_unset_path_refusal'];command=fixture['commands'][step]
            if change=='argv':command['argv'][6]='/usr/bin/true'
            elif change=='expected':command['expected']=0
            elif change=='cwd':command['cwd']='/tmp/other'
            else:fixture['positions'][step]=99
            with self.subTest(change=change),self.assertRaises(ValueError):self.call(fixture)

    def test_self_pinned_wrong_capture_payload_still_refuses(self):
        for key in ('env_unset_capture','env_unset_absolute_capture','env_unset_restored_capture'):
            fixture=self.fixture();logical=fixture['value']['env_unset']['override_logical']
            self.repin(fixture,key,lambda data:data['files'][logical].update(mode='0o755'))
            with self.subTest(key=key),self.assertRaises(ValueError):self.call(fixture)

    def test_self_pinned_audit_must_show_actual_equals_form(self):
        fixture=self.fixture();self.repin(fixture,'env_unset_audit',lambda data:data['applications'][0]['exec'].update(argv_without_file_inputs=['env','--unset','WAYLAND_DISPLAY','tool-link']))
        with self.assertRaises(ValueError):self.call(fixture)
        fixture=self.fixture();self.repin(fixture,'env_unset_audit',lambda data:data.update(inventory_input=pin(b'wrong')))
        with self.assertRaises(ValueError):self.call(fixture)

    def test_self_pinned_refusal_reports_need_source_exact_errors(self):
        for key in ('env_unset_path_refusal','env_unset_malformed_refusal'):
            fixture=self.fixture();self.repin(fixture,key,lambda data:data['applications'][0]['exec']['resolution']['env_target'].update(error='some unrelated failure'))
            with self.subTest(key=key),self.assertRaises(ValueError):self.call(fixture)


if __name__ == '__main__':
    unittest.main(verbosity=2)
