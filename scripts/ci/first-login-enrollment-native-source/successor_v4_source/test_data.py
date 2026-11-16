# SPDX-License-Identifier: MIT
"""Portable inert committed-closure/projection/inverse controls; no actual Source."""
import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
sys.dont_write_bytecode = True


def fence(event, args):
    if event.startswith(('socket.', 'ctypes.')) or event in ('os.system', 'os.fork', 'os.exec', 'resource.setrlimit', 'fcntl.flock'):
        raise RuntimeError('v4 Source DATA fence: '+event)
    if event in ('subprocess.Popen', 'os.posix_spawn'):
        executable, argv = args[:2]
        if executable not in ('/usr/bin/git', 'git') or argv[0] not in ('/usr/bin/git', 'git'):
            raise RuntimeError('only local Git DATA operations permitted')
        if any(item in argv for item in ('fetch', 'push', 'pull', 'clone', 'remote')):
            raise RuntimeError('Git network forbidden')


sys.addaudithook(fence)
spec = importlib.util.spec_from_file_location('delegated_v4_constructor_controls', HERE/'prepare.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='v4-source-MODEL-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.home = Path(cls.temp.name)
        cls.repo = cls.home/'repo'
        cls.repo.mkdir()
        cls.env = dict(PATH='/usr/bin:/bin', HOME=str(cls.home), LC_ALL='C', GIT_CONFIG_NOSYSTEM='1',
                       GIT_CONFIG_GLOBAL='/dev/null', GIT_AUTHOR_NAME='MODEL DATA', GIT_AUTHOR_EMAIL='model@invalid.test',
                       GIT_COMMITTER_NAME='MODEL DATA', GIT_COMMITTER_EMAIL='model@invalid.test')
        def git(*args):
            return subprocess.check_output(['/usr/bin/git', '-C', str(cls.repo), *args], env=cls.env, timeout=15)
        git('init', '--quiet')
        cls.P = M.load_v3()
        cls.roles = {}
        cls.files = {}
        callbacks = dict(context=['validate_delegation', 'validate_context', 'capture_context', 'adopt_pair', 'adopt_selected_pair'],
                         image=['build_stage'], image_executor=['MODEL_executor', 'context_contract', 'owner_main', 'controller_main'],
                         delegated_owner=['run_owned_current_v3', 'open_delegated_session', 'launch_delegated_lifecycle'], route=['run_registered'],
                         retention=['retain_delegated_stage'], public_reader=['MODEL_public_reader'], encoder=['bundle'],
                         hosted_launcher=['MODEL_hosted_launcher', 'checked_inputs', 'preflight'],
                         inputs_assembler=['MODEL_inputs_assembler', 'validate_owner_inputs_v3', 'validate_hosted_inputs_v3', 'stage_inputs'])
        for role in M.ROLES:
            if role in M.BASIS:
                name = M.BASIS[role][0]
                raw = (REPO/name).read_bytes()
            elif role == 'owned_process':
                name = M.OWNED[0]
                raw = (REPO/name).read_bytes()
            elif role == 'encoder':
                name = 'scripts/ci/log_evidence.py'
                raw = (REPO/name).read_bytes()
            elif role == 'policy':
                name, raw = 'MODEL/policy.json', b'{"MODEL_ONLY":true,"actual":null}\n'
            elif role == 'workflow':
                name, raw = '.github/workflows/MODEL.yml', b'name: INERT MODEL\non:\n  workflow_dispatch:\njobs: {}\n'
            else:
                name = 'MODEL/'+role+'.py'
                text = "API='"+M.OWNER_API+"'\n" if role == 'delegated_owner' else ''
                if role == 'retention':text = "API='"+M.RETENTION_API+"'\n"
                raw = (text+''.join('def '+entry+'(*args, **kwargs):\n raise RuntimeError("MODEL NEVER ACTUAL EXECUTION")\n'
                                    for entry in callbacks[role])).encode()
            cls.roles[role] = name
            cls.files[name] = (raw, 0o755 if role == 'owned_process' else 0o644)
        for name in M.RETENTION_DEPENDENCIES:
            cls.files[name] = ((REPO/name).read_bytes(), 0o644)
        name = M.BUILD_VALIDATOR[0]
        cls.files[name] = ((REPO/name).read_bytes(), 0o644)
        context_pin = M.pin(cls.files[cls.roles['context']][0])
        for role in ('image', 'image_executor'):
            name = cls.roles[role]
            raw, mode = cls.files[name]
            cls.files[name] = (raw+('CONTEXT_PROGRAM_PINS='+repr({4:context_pin})+'\n').encode(), mode)
        for name in ('prepare.py', 'README.md'):
            cls.files[M.PREFIX+'/'+name] = ((HERE/name).read_bytes(), 0o644)
        for name, (body, mode) in cls.files.items():
            path = cls.repo/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(mode)
        git('add', '.')
        git('commit', '--quiet', '-m', 'INERT MODEL closure only')
        cls.commit = git('rev-parse', 'HEAD').decode().strip()
        cls.closure = M.closure_template()
        cls.closure.update(commit=cls.commit, roles=cls.roles,
                           files=cls.P.C.descriptors({n: v for n, v in cls.files.items() if not n.startswith(M.PREFIX+'/')}),
                           entrypoints=dict(image_executor='MODEL_executor', public_reader='MODEL_public_reader',
                                            hosted_launcher='MODEL_hosted_launcher', inputs_assembler='MODEL_inputs_assembler'))

    def projection_fixture(self):
        files, roles = {}, {}
        for i, original in enumerate(sorted(M.ALIASES)):
            member = 'carrier/MODEL/member-%02d.DATA'%i
            body = ('MODEL PUBLIC BODY '+original+'\n').encode()
            files[member] = (body, 0o644)
            roles[original] = dict(path=member, **M.pin(body))
        return roles, files

    def test_exact_aliases_project_only_path_key_and_preserve_all59_bodies(self):
        roles, files = self.projection_fixture()
        before = copy.deepcopy(files)
        value = M.project_materials(roles, files)
        self.assertEqual(len(value['materials']), 59)
        for original, alias in value['aliases'].items():
            row = value['materials'][alias]
            self.assertEqual(row, dict(member=roles[original]['path'], **M.pin(files[row['member']][0])))
        self.assertEqual(files, before)
        self.assertEqual(value['aliases']['official/gobject-introspection-runtime/archive'],
                         'official_gobject_introspection_runtime_archive')
        self.assertEqual(value['aliases']['Setup8/current_verification'], 'setup8_current_verification')

    def test_unknown_missing_roles_alias_collisions_and_body_drift_refuse(self):
        roles, files = self.projection_fixture()
        for change in ('missing', 'extra', 'pin', 'body', 'mode', 'unsafe', 'missing_body', 'member_collision'):
            bad, bodies = copy.deepcopy(roles), copy.deepcopy(files)
            name = 'Setup8/archive'
            if change == 'missing':del bad[name]
            if change == 'extra':bad['future/unknown'] = bad[name]
            if change == 'pin':bad[name]['sha256'] = 'f'*64
            if change == 'body':bodies[bad[name]['path']] = (b'MUTATED MODEL', 0o644)
            if change == 'mode':bodies[bad[name]['path']] = (bodies[bad[name]['path']][0], 0o755)
            if change == 'unsafe':bad[name]['path'] = 'carrier/../MODEL'
            if change == 'missing_body':del bodies[bad[name]['path']]
            if change == 'member_collision':bad[name] = dict(bad['Setup8/current_signature'])
            with self.subTest(change=change), self.assertRaises(ValueError):M.project_materials(bad, bodies)
        aliases = dict(M.ALIASES)
        aliases['Setup8/archive'] = aliases['Setup8/current_signature']
        with patch.object(M, 'ALIASES', aliases), self.assertRaises(ValueError):M.project_materials(roles, files)

    def test_complete_single_committed_MODEL_closure_is_data_not_execution(self):
        value, files = M.committed_closure(self.P, self.repo, M.encode(self.closure))
        self.assertEqual(value, self.closure)
        self.assertEqual(set(value['roles']), set(M.ROLES))
        self.assertTrue(all(v is None for v in value['actual'].values()))
        self.assertNotIn(b'def admission', files[value['roles']['route']][0])

    def test_NULL_template_refuses_before_git_or_output(self):
        template = M.closure_template()
        self.assertIsNone(template['commit'])
        self.assertTrue(all(v is None for v in template['roles'].values()))
        with patch.object(self.P, 'commit', side_effect=AssertionError('no Git before complete selectors')):
            with self.assertRaises(ValueError):M.committed_closure(self.P, self.repo, M.encode(template))

    def test_optional_four_roles_and_time_policy_are_explicit_unissued_data(self):
        template = M.closure_template(with_host_prerequisites=True)
        self.assertEqual(set(template['roles']), set(M.ROLES) | set(M.PREREQUISITE_FILES))
        self.assertTrue(all(v is None for v in template['roles'].values()))
        base = dict(executor_current_v3=dict(controller_seconds=7560,stage_seconds=7200,setup_seconds=180,cleanup_seconds=180),Root_issuance=None)
        original = copy.deepcopy(base);candidate = M.prerequisite_policy_candidate(base)
        self.assertEqual(base, original);self.assertEqual(candidate['host_prerequisite_timing_v3']['whole_budget_seconds'],7560)
        self.assertIsNone(candidate['Root_issuance']);self.assertNotIn('approved',candidate)
        candidate['host_prerequisites_current_v3']['scope_limits']['memory.max'] = 'max'
        self.assertEqual(M.PREREQUISITE_POLICY['scope_limits']['memory.max'],'536870912')
        for change in ('widen','authority','conflict'):
            bad = copy.deepcopy(base)
            if change == 'widen':bad['executor_current_v3']['controller_seconds'] = 8055
            elif change == 'authority':bad['Root_issuance'] = True
            else:bad['host_prerequisites_current_v3'] = {}
            with self.subTest(change=change),self.assertRaises(ValueError):M.prerequisite_policy_candidate(bad)

    def test_optional_roster_cannot_be_partial_or_hidden_in_policy(self):
        bad = copy.deepcopy(self.closure);bad['roles']['host_prerequisites'] = 'missing.py'
        with self.assertRaises(ValueError):M.committed_closure(self.P,self.repo,M.encode(bad))

    def test_optional_policy_matches_the_whole_pinned_actual_helper(self):
        member,size,digest = M.PREREQUISITE_FILES['host_prerequisites'];path = REPO/member
        self.assertEqual(M.pin(path.read_bytes()),dict(bytes=size,sha256=digest))
        spec = importlib.util.spec_from_file_location('fenced_actual_prerequisite_policy',path)
        helper = importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        self.assertEqual(M.PREREQUISITE_POLICY,helper.PROPOSAL)

    def test_optional_complete_committed_code_closure_keeps_exact_v3_inverse(self):
        fixture = os.environ.get('CACHY_HOST_PREREQUISITE_FIXTURE')
        bodies = {}
        for role,(member,size,digest) in M.PREREQUISITE_FILES.items():
            path = REPO/member
            if not path.is_file() and fixture and role != 'host_prerequisites':path = Path(fixture)/Path(member).name
            if not path.is_file():self.skipTest('explicit pinned public prerequisite donor code unavailable; no19-role Source claim')
            raw = path.read_bytes();self.assertEqual(M.pin(raw),dict(bytes=size,sha256=digest));bodies[member] = (raw,0o644)
        value = copy.deepcopy(self.closure);files = dict(self.files);files.update(bodies)
        for role,(member,_,_) in M.PREREQUISITE_FILES.items():value['roles'][role] = member
        policy = dict(executor_current_v3=dict(controller_seconds=7560,stage_seconds=7200,setup_seconds=180,cleanup_seconds=180),Root_issuance=None)
        files[value['roles']['policy']] = (M.encode(M.prerequisite_policy_candidate(policy)),0o644)
        member = value['roles']['hosted_launcher'];raw,mode = files[member]
        callbacks = ''.join('def '+name+'(*args,**kwargs):\n raise RuntimeError("MODEL NO ACTOR")\n'for name in sorted(M.PREREQUISITE_CALLBACKS))
        files[member] = (raw+(callbacks+'TIMING='+repr(M.PREREQUISITE_TIMING)+'\n').encode(),mode)
        with tempfile.TemporaryDirectory(prefix='v4-prerequisite-MODEL-') as temporary:
            repo = Path(temporary);env = dict(self.env)
            def git(*args):return subprocess.check_output(['/usr/bin/git','-C',str(repo),*args],env=env,timeout=15)
            git('init','--quiet')
            for member,(raw,mode) in files.items():
                path = repo/member;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode)
            git('add','.');git('commit','--quiet','-m','MODEL complete prerequisite code only')
            value['commit'] = git('rev-parse','HEAD').decode().strip()
            value['files'] = self.P.C.descriptors({n:v for n,v in files.items()if not n.startswith(M.PREFIX+'/')})
            checked,_ = M.committed_closure(self.P,repo,M.encode(value));self.assertEqual(checked,value)
            roles,carrier = self.projection_fixture();C = self.P.C
            carrier.update({n:v for n,v in files.items()if not n.startswith(M.PREFIX+'/')})
            old = dict(schema=1,kind='CURRENT_ONBOARDING_CLOSED_SOURCE_V3',operation=M.OP,actual=dict(Source=None))
            carrier[C.PREFIX+'/owner-program.json'] = (M.encode(dict(materials=roles)),0o644)
            old['files'] = C.descriptors(carrier);mapping = (M.encode(old),0o644)
            carrier['source-map.json'] = carrier['source.lock.json'] = mapping
            # The operational v3 assembler separately supplies the complete basis.
            basis = dict(carrier);closure = dict(value,_repo=repo)
            extended = M.extend_v3(self.P,carrier,closure,M.encode(value))
            program = C.decode(extended[M.PREFIX+'/program.json'][0])
            self.assertEqual(set(program['roles']),set(M.ROLES)|set(M.PREREQUISITE_FILES))
            self.assertEqual(program['delegation_programs']['host_prerequisite_plan']['sha256'],M.PREREQUISITE_FILES['host_prerequisite_plan'][2])
            self.assertEqual(M.inverse_v3(extended),basis)

    def test_immutable_retention_dependencies_cannot_be_missing_or_replaced(self):
        for name in (*M.RETENTION_DEPENDENCIES, M.BUILD_VALIDATOR[0]):
            for change in ('missing', 'hash', 'mode'):
                bad = copy.deepcopy(self.closure)
                if change == 'missing':del bad['files'][name]
                if change == 'hash':bad['files'][name]['sha256'] = '0'*64
                if change == 'mode':bad['files'][name]['mode'] = 0o755
                with self.subTest(name=name, change=change), self.assertRaises(ValueError):
                    M.committed_closure(self.P, self.repo, M.encode(bad))

    def test_real_old_retention_cannot_occupy_new_delegated_role(self):
        bad = copy.deepcopy(self.closure)
        bad['roles']['retention'] = M.FAMILY+'/payload/native/retention_current_v3.py'
        with self.assertRaisesRegex(ValueError, 'callbacks missing: retention'):
            M.committed_closure(self.P, self.repo, M.encode(bad))

    def test_existing_consumer_pin_table_is_literal_and_finite_without_import(self):
        raw = b"CONTEXT_PROGRAM_PINS={4:dict(bytes=12,sha256='"+b'a'*64+b"')}\n"
        self.assertEqual(M.context_program_pins(raw), {4:dict(bytes=12,sha256='a'*64)})
        for body in (b'CONTEXT_PROGRAM_PINS=arbitrary()\n', b'CONTEXT_PROGRAM_PINS={5:{}}\n',
                     b'CONTEXT_PROGRAM_PINS={}\nCONTEXT_PROGRAM_PINS={}\n'):
            with self.subTest(body=body), self.assertRaises(ValueError):M.context_program_pins(body)

    def test_stale_actual_consumer_context_pin_refuses_complete_committed_model(self):
        name = self.roles['image'];path = self.repo/name;original = path.read_bytes()
        actual = M.pin(self.files[self.roles['context']][0])['sha256'].encode()
        self.assertEqual(original.count(actual), 1)
        changed = original.replace(actual, b'f'*64)
        def git(*args):
            return subprocess.check_output(['/usr/bin/git', '-C', str(self.repo), *args], env=self.env, timeout=15)
        try:
            path.write_bytes(changed);git('add', name);git('commit', '--quiet', '-m', 'MODEL stale consumer pin')
            bad = copy.deepcopy(self.closure);bad['commit'] = git('rev-parse', 'HEAD').decode().strip()
            bad['files'][name].update(M.pin(changed))
            with self.assertRaisesRegex(ValueError, 'context whole pin differs from image'):
                M.committed_closure(self.P, self.repo, M.encode(bad))
        finally:path.write_bytes(original)

    def test_missing_role_file_callback_commit_or_future_authority_refuse(self):
        for change in ('role', 'file', 'entrypoint', 'commit', 'authority', 'collision', 'owner_pin', 'mode'):
            bad = copy.deepcopy(self.closure)
            if change == 'role':del bad['roles']['retention']
            if change == 'file':del bad['files'][bad['roles']['policy']]
            if change == 'entrypoint':bad['entrypoints']['public_reader'] = 'missing_actual_reader'
            if change == 'commit':bad['commit'] = '0'*40
            if change == 'authority':bad['actual']['Root_delegation'] = True
            if change == 'collision':bad['roles']['image'] = bad['roles']['context']
            if change == 'owner_pin':bad['files'][bad['roles']['delegated_owner']]['sha256'] = '0'*64
            if change == 'mode':bad['files'][bad['roles']['policy']]['mode'] = 0o755
            with self.subTest(change=change), self.assertRaises(ValueError):M.committed_closure(self.P, self.repo, M.encode(bad))

    def test_uncommitted_body_does_not_replace_committed_body_or_pin(self):
        name = self.roles['context']
        path = self.repo/name
        old = path.read_bytes()
        try:
            path.write_bytes(old+b'# UNCOMMITTED MODEL\n')
            _, files = M.committed_closure(self.P, self.repo, M.encode(self.closure))
            self.assertEqual(files[name][0], old)
            bad = copy.deepcopy(self.closure)
            bad['files'][name].update(M.pin(path.read_bytes()))
            with self.assertRaises(ValueError):M.committed_closure(self.P, self.repo, M.encode(bad))
        finally:path.write_bytes(old)

    def test_pinned_v3_members_refuse_tampering_without_editing_them(self):
        original = Path.read_bytes
        def changed(path):
            body = original(path)
            return body+b'MODEL TAMPER' if path == HERE.parent/'successor_v3/common.py' else body
        with patch.object(Path, 'read_bytes', changed), self.assertRaises(ValueError):M.load_v3()

    def test_model_extension_has_separate_registry_and_exact_full_inverse(self):
        roles, files = self.projection_fixture()
        files.update({n: v for n, v in self.files.items() if not n.startswith(M.PREFIX+'/')})
        files[self.P.C.PREFIX+'/owner-program.json'] = (M.encode(dict(materials=roles, MODEL_ONLY=True)), 0o644)
        value = dict(schema=1, kind=self.P.C.KIND, operation=M.OP, files=self.P.C.descriptors(files), actual=dict(source=None))
        raw = M.encode(value)
        files['source-map.json'] = files['source.lock.json'] = (raw, 0o644)
        basis = dict(files)
        closure = dict(self.closure, _repo=self.repo)
        extended = M.extend_v3(self.P, files, closure, M.encode(self.closure))
        program = self.P.C.decode(extended[M.PREFIX+'/program.json'][0])
        self.assertEqual(program['owner']['member'], self.roles['delegated_owner'])
        self.assertEqual(program['route']['member'], self.roles['route'])
        self.assertEqual(program['owner_callbacks'], dict(build='open_delegated_session', lifecycle='launch_delegated_lifecycle'))
        self.assertEqual(program['v3_registry_scope'], 'PRESERVED_DATA_ONLY_NEVER_DELEGATED_EXECUTION')
        selected = program['delegation_programs']
        self.assertEqual(selected['owner'], program['owner'])
        self.assertEqual(selected['inputs_assembler'], program['roles']['inputs_assembler'])
        self.assertEqual(selected['local_callbacks'], program['roles']['v3_basis_owner'])
        self.assertEqual(selected['build_validator']['member'], M.BUILD_VALIDATOR[0])
        self.assertEqual(program['retention_callback'], 'retain_delegated_stage')
        self.assertNotIn('issuer', selected)
        self.assertEqual(M.inverse_v3(extended), basis)
        self.assertEqual(files, basis)
        self.assertTrue(all(v is None for v in program['actual'].values()))
        broken = dict(extended)
        key = self.roles['retention']
        broken[key] = (broken[key][0]+b'MODEL MUTATION', 0o644)
        with self.assertRaises(ValueError):M.inverse_v3(broken)

    def test_operational_assembly_still_refuses_absent_real_historical_basis(self):
        self.assertFalse((self.repo/'.git/objects/info/alternates').exists())
        with self.assertRaises(ValueError):M.assemble(self.repo, M.encode(self.closure), b'NOT AN ACTUAL CARRIER', b'{}')


if __name__ == '__main__':
    unittest.main()
