# SPDX-License-Identifier: MIT
"""MODEL_ONLY DATA receipts; no actual package, ALPM, key or image execution."""
import sys


def actor_fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.fork', 'os.posix_spawn')) or event in {
        'os.system', 'fcntl.flock', 'resource.setrlimit', 'os.kill', 'os.killpg',
    }:
        raise RuntimeError('MODEL_ONLY_LIFECYCLE_ACTOR_FENCE:' + event)


sys.addaudithook(actor_fence)

import base64
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('MODEL_ONLY_gui_lifecycle', Path(__file__).with_name('lifecycle.py'))
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)


def file_row(raw=b'MODEL_ONLY_NOT_AN_ARTIFACT', *, content=False, owner=None, uid=0):
    row = dict(type='file', mode=0o644, uid=uid, gid=uid, **L.pin(raw))
    if content:
        row.update(content_base64=base64.b64encode(raw).decode(), package_owner=owner)
    return row


def directory(*, user=False):
    return dict(type='directory', mode=0o755, uid=1000 if user else 0, gid=1000 if user else 0,
                package_owner=None if user else 'filesystem')


def model_plan(*, consumer=False):
    def pkg(name, modules):
        return dict(name=name, version=L.VERSIONS[name], architecture='aarch64',
                    path='/work/MODEL_ONLY/' + name + '.pkg.tar.xz', pin=L.pin(b'MODEL_ONLY_' + name.encode()),
                    depends=['glibc'] if name == L.BASE else ['glibc', 'wayland>=1.15'],
                    payload=dict(complete=True, files={'/usr/lib/libQt6' + module + '.so.6.12.0': file_row()
                                                       for module in modules}))
    base, gui = pkg(L.BASE, L.MODULES), pkg(L.GUI, L.GUI_MODULES)
    baseline = {L.BASE: dict(version=L.VERSIONS[L.BASE], depends=['glibc']),
                'glibc': dict(version='2.43-1', depends=[]), 'filesystem': dict(version='1-1', depends=['glibc']),
                'wayland': dict(version='1.23-1', depends=['glibc']), 'unrelated-helper': dict(version='1-1', depends=['glibc'])}
    if consumer:
        baseline['MODEL-qt-consumer'] = dict(version='1-1', depends=['qt6-base>=6.12.0'])
    return L.reviewed_plan(baseline_inventory=baseline, base_package=base, gui_package=gui,
                           pacman_config='/work/MODEL_ONLY/private-pacman.conf', test_gpgdir='/work/MODEL_ONLY/public-TEST-gpgdir',
                           user_roots=['/home/MODEL_ONLY/.config'], protected_config_roots=['/etc/xdg'])


def model_selection():
    return dict(image='sha256:' + L.pin(b'MODEL_ONLY_IMAGE')['sha256'],
                supervisor=dict(code_pin=L.pin(b'MODEL_ONLY_SUPERVISOR_NOT_REAL_CODE'),
                                nonce=L.pin(b'MODEL_ONLY_NOT_ACTUAL_C_NONCE')['sha256'][:32],
                                owner_identity=[1000, 2000, 3000]),
                execution_id=L.pin(b'MODEL_ONLY_MAIN_EXECUTION')['sha256'],
                negative_execution_ids={kind: L.pin(('MODEL_ONLY_SIBLING_' + kind).encode())['sha256']
                                        for kind in ('missing-dependency', 'foreign-file-overlap')})


def command(plan, argv, exit_code=0, stdout='', *, execution_id=None):
    selected = model_selection()
    return dict(argv=argv, exit=exit_code, stdout=stdout, stderr='MODEL_ONLY_NO_ACTOR',
                stdout_pin=L.pin(stdout.encode()), stderr_pin=L.pin(b'MODEL_ONLY_NO_ACTOR'),
                image=selected['image'], supervisor=selected['supervisor'],
                execution_id=execution_id or selected['execution_id'],
                timeout_seconds=120, seconds=0.01, pid=200, pgid=200,
                natural_exit=True, group_absent=True, owned_processes_absent=True)


def model_evidence(plan):
    base_state = copy.deepcopy(plan['baseline_inventory'])
    gui_state = copy.deepcopy(base_state)
    del gui_state[L.BASE]
    gui_state[L.GUI] = dict(version=L.VERSIONS[L.GUI], depends=['glibc', 'wayland>=1.15'])
    removed = copy.deepcopy(base_state)
    del removed[L.BASE]
    states = dict(base=base_state, gui=gui_state, removed=removed)
    def inventory(state):
        return {name: row['version'] for name, row in state.items()}
    def query(state):
        return ''.join(name + ' ' + row['version'] + '\n' for name, row in sorted(state.items()))
    def checks(kind):
        state = states[kind]
        deps = sorted({dep for row in state.values() for dep in row['depends']})
        return dict(inventory=inventory(state), query=command(plan, plan['pacman'] + ['-Q'], stdout=query(state)),
                    dependency_check=command(plan, plan['pacman'] + ['-T', '--'] + deps))
    user = dict(complete=True, roots=plan['user_roots'], entries={
        '/home/MODEL_ONLY/.config': directory(user=True),
        '/home/MODEL_ONLY/.config/Qt.conf': file_row(content=True, uid=1000),
        '/home/MODEL_ONLY/.config/Qt.conf.pacsave': file_row(b'MODEL_ONLY_PACSAVE', content=True, uid=1000),
        '/home/MODEL_ONLY/.config/Qt.conf.pacnew': file_row(b'MODEL_ONLY_PACNEW', content=True, uid=1000),
        '/home/MODEL_ONLY/.config/qt-link': dict(type='symlink', mode=0o777, uid=1000, gid=1000, target='Qt.conf', package_owner=None),
    })
    protected = dict(complete=True, roots=plan['protected_config_roots'], entries={
        '/etc/xdg': directory(), '/etc/xdg/qt.conf': file_row(content=True, owner='filesystem'),
    })
    result = dict(baseline=dict(checks=checks('base'), user=user, protected_config=protected,
                                payload=plan['base_package']['payload']), stages=[], negative_controls={})
    for stage in plan['stages']:
        refused = stage['name'] == 'remove' and 'MODEL-qt-consumer' in base_state
        outcome = 'dependency-refusal' if refused else 'success'
        added = {stage['incoming']: L.VERSIONS[stage['incoming']]} if stage['incoming'] else {}
        removed_pkgs = {stage['outgoing']: L.VERSIONS[stage['outgoing']]} if stage['outgoing'] else {}
        questions = []
        if stage['incoming'] and stage['outgoing']:
            questions.append(dict(type='ALPM_QUESTION_CONFLICT_PKG', numeric_type=4, incoming=stage['incoming'],
                                  remove=stage['outgoing'], reason='qt6-base', answer=True))
        questions.append(dict(type='PACMAN_TRANSACTION_CONFIRM', added=added, removed=removed_pkgs, answer=True))
        kind = stage['before'] if refused else stage['after']
        result['stages'].append(dict(name=stage['name'], outcome=outcome,
            command=command(plan, stage['argv'], 1 if refused else 0),
            alpm=dict(committed=not refused, added={} if refused else added, removed={} if refused else removed_pkgs,
                      error='ALPM_ERR_UNSATISFIED_DEPS' if refused else None, questions=[] if refused else questions,
                      unsatisfied=[dict(target='MODEL-qt-consumer', dependency='qt6-base>=6.12.0', causingpkg=L.GUI)] if refused else []),
            checks=checks(kind), user=copy.deepcopy(user), protected_config=copy.deepcopy(protected),
            payload={'complete': True, 'files': {}} if kind == 'removed' else plan['gui_package' if kind == 'gui' else 'base_package']['payload']))
    for kind in plan['negative_controls']:
        execution_id = model_selection()['negative_execution_ids'][kind]
        state = copy.deepcopy(base_state)
        if kind == 'missing-dependency':
            del state['wayland']
            detail = dict(dependency='wayland>=1.15', removed_package='wayland')
        else:
            existing = file_row(b'MODEL_ONLY_FOREIGN_OWNED_COLLISION', content=True, owner='unrelated-helper')
            detail = dict(path='/usr/lib/libQt6WaylandClient.so.6.12.0', foreign_owner='unrelated-helper',
                          before=existing, after=copy.deepcopy(existing))
        result['negative_controls'][kind] = dict(command=command(plan, plan['negative_controls'][kind]['argv'], 1, execution_id=execution_id),
            alpm_error='ALPM_ERR_UNSATISFIED_DEPS' if kind == 'missing-dependency' else 'ALPM_ERR_FILE_CONFLICTS',
            detail=detail, before_inventory=inventory(state), after_inventory=inventory(state),
            user=copy.deepcopy(user), protected_config=copy.deepcopy(protected), payload=plan['base_package']['payload'],
            post_query=command(plan, plan['pacman'] + ['-Q'], stdout=query(state), execution_id=execution_id),
            post_dependencies=command(plan, plan['pacman'] + ['-T', '--'] + plan['gui_package']['depends'],
                                      127 if kind == 'missing-dependency' else 0,
                                      'wayland>=1.15\n' if kind == 'missing-dependency' else '', execution_id=execution_id))
    return copy.deepcopy(result)


class ModelLifecycle(unittest.TestCase):
    def setUp(self):
        self.plan = model_plan()
        self.selection = model_selection()
        self.evidence = model_evidence(self.plan)

    def validate(self):
        return L.validate_evidence(self.plan, self.evidence, selection=self.selection)

    def test_actor_fence_precedes_implementation_import(self):
        for event in ('subprocess.Popen', 'socket.connect', 'ctypes.dlopen', 'os.system', 'os.exec',
                      'os.fork', 'os.forkpty', 'os.posix_spawn', 'fcntl.flock', 'resource.setrlimit', 'os.kill', 'os.killpg'):
            with self.subTest(event=event), self.assertRaisesRegex(RuntimeError, 'MODEL_ONLY_LIFECYCLE_ACTOR_FENCE'):
                sys.audit(event)

    def test_model_success_retains_actual_unbound_and_never_admits_native(self):
        result = self.validate()
        self.assertFalse(result['native_acceptance'])
        self.assertFalse(result['full72_claim'])
        self.assertTrue(all(value is None for value in self.plan['actual'].values()))
        self.assertEqual(self.plan['module_counts'], dict(base=13, gui=18))
        self.assertEqual(result['removal'], 'success')

    def test_only_atomic_normal_upgrades_and_nonrecursive_saved_config_remove(self):
        for stage in self.plan['stages']:
            self.assertEqual(stage['argv'][:5], self.plan['pacman'])
            self.assertEqual(stage['argv'][5:7], ['-R' if stage['name'] == 'remove' else '-U', '--'])
            self.assertFalse(set(stage['argv']) & {'--ask', '--ask=4', '--nodeps', '-d', '--nosave', '-n', '--overwrite', '-Rdd', '-Rs', '--noconfirm'})
        self.assertEqual(self.plan['stages'][0]['incoming'], L.GUI)
        self.assertEqual(self.plan['stages'][0]['outgoing'], L.BASE)
        self.assertEqual(self.plan['stages'][2]['incoming'], L.BASE)

    def test_normal_remove_refuses_with_retained_qt_consumer(self):
        self.plan = model_plan(consumer=True)
        self.evidence = model_evidence(self.plan)
        self.assertEqual(self.validate()['removal'], 'dependency-refusal')
        self.assertIn(L.GUI, self.evidence['stages'][-1]['checks']['inventory'])

    def test_fake_remove_success_cannot_override_normal_consumer_dependencies(self):
        self.plan = model_plan(consumer=True)
        self.evidence = model_evidence(self.plan)
        self.evidence['stages'][-1]['outcome'] = 'success'
        with self.assertRaisesRegex(ValueError, 'NORMAL_REMOVE_MUST_RESPECT'):
            self.validate()

    def test_no_unrelated_package_change_or_qt_package_coinstallation(self):
        for name in ('unrelated-helper', L.BASE, 'qt6-base'):
            self.evidence = model_evidence(self.plan)
            self.evidence['stages'][0]['checks']['inventory'][name] = 'MODEL_OTHER_VERSION'
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'EXACT_BASELINE_MINUS'):
                self.validate()

    def test_each_stage_requires_normal_post_dependencies_and_inventory_commands(self):
        for index in range(5):
            self.evidence = model_evidence(self.plan)
            self.evidence['stages'][index]['checks']['dependency_check']['argv'].insert(5, '--nodeps')
            with self.subTest(stage=index), self.assertRaisesRegex(ValueError, 'EXACT_NORMAL_PACMAN_COMMAND'):
                self.validate()

    def test_inventory_query_cannot_omit_unrelated_packages(self):
        self.evidence['stages'][1]['checks']['query']['stdout'] = ''
        self.evidence['stages'][1]['checks']['query']['stdout_pin'] = L.pin(b'')
        with self.assertRaisesRegex(ValueError, 'PACMAN_Q_EXACT'):
            self.validate()

    def test_exact_conflict_pair_and_confirmation_only(self):
        for change in ('other', 'extra', 'wrongtype'):
            self.evidence = model_evidence(self.plan)
            questions = self.evidence['stages'][0]['alpm']['questions']
            if change == 'other': questions[0]['remove'] = 'unrelated-helper'
            if change == 'extra': questions.append(dict(type='IMPORT_KEY', answer=True))
            if change == 'wrongtype': questions[0]['numeric_type'] = 64
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'EXACT_NORMAL_ATOMIC_ALPM'):
                self.validate()

    def test_alpm_cannot_claim_pre_remove_then_upgrade_or_unrelated_addition(self):
        self.evidence['stages'][0]['alpm']['removed']['unrelated-helper'] = '1-1'
        with self.assertRaisesRegex(ValueError, 'EXACT_NORMAL_ATOMIC_ALPM'):
            self.validate()

    def test_user_file_content_modes_uid_gid_symlinks_and_pacfiles_preserved(self):
        root = '/home/MODEL_ONLY/.config/'
        for name, field, value in (('Qt.conf', 'content_base64', 'T09QUw=='), ('Qt.conf', 'mode', 0o600),
                                   ('Qt.conf', 'uid', 0), ('Qt.conf', 'gid', 0), ('qt-link', 'target', 'foreign'),
                                   ('Qt.conf', 'package_owner', L.GUI)):
            self.evidence = model_evidence(self.plan)
            self.evidence['stages'][3]['user']['entries'][root + name][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'PRESERVE_ALL_USER'):
                self.validate()
        for name in ('Qt.conf.pacsave', 'Qt.conf.pacnew'):
            self.evidence = model_evidence(self.plan)
            del self.evidence['stages'][-1]['user']['entries'][root + name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'PRESERVE_ALL_USER'):
                self.validate()

    def test_user_snapshot_must_have_full_content_and_current_hash(self):
        self.evidence['baseline']['user']['entries']['/home/MODEL_ONLY/.config/Qt.conf']['content_base64'] = ''
        with self.assertRaisesRegex(ValueError, 'EXACT_COMPLETE_CONTENT'):
            self.validate()

    def test_other_package_config_content_and_owner_are_immutable(self):
        self.evidence['stages'][0]['protected_config']['entries']['/etc/xdg/qt.conf']['package_owner'] = L.GUI
        with self.assertRaisesRegex(ValueError, 'PRESERVE_ALL_USER'):
            self.validate()

    def test_incomplete_baseline_or_package_payload_refused(self):
        self.evidence['baseline']['user']['complete'] = False
        with self.assertRaisesRegex(ValueError, 'COMPLETE_EXTERNAL_PROTECTED'):
            self.validate()
        plan = copy.deepcopy(self.plan)
        plan['gui_package']['payload']['files'].pop('/usr/lib/libQt6WaylandClient.so.6.12.0')
        with self.assertRaisesRegex(ValueError, 'SOURCE_BACKED_MODULE_PAYLOAD'):
            L.validate_evidence(plan, model_evidence(plan), selection=self.selection)

    def test_downgrade_payload_cannot_be_gui_relabelled_as_baseline(self):
        self.evidence['stages'][2]['payload'] = self.plan['gui_package']['payload']
        with self.assertRaisesRegex(ValueError, 'EXACT_CURRENT_PACKAGE_PAYLOAD'):
            self.validate()

    def test_both_negatives_are_mandatory(self):
        for kind in self.plan['negative_controls']:
            self.evidence = model_evidence(self.plan)
            del self.evidence['negative_controls'][kind]
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'BOTH_NORMAL_ALPM_NEGATIVE'):
                self.validate()

    def test_missingdep_negative_must_join_removed_package_and_T_output(self):
        row = self.evidence['negative_controls']['missing-dependency']
        row['detail']['removed_package'] = 'unrelated-helper'
        with self.assertRaisesRegex(ValueError, 'DIRECT_MISSING_PACKAGE_DEPENDENCY_JOIN'):
            self.validate()

    def test_missingdep_negative_cannot_silently_install(self):
        self.evidence['negative_controls']['missing-dependency']['command']['exit'] = 0
        with self.assertRaisesRegex(ValueError, 'EXACT_NORMAL_PACMAN_COMMAND_EXIT'):
            self.validate()

    def test_overlap_negative_must_preserve_foreign_bytes_and_ownership(self):
        self.evidence['negative_controls']['foreign-file-overlap']['detail']['after']['mode'] = 0o600
        with self.assertRaisesRegex(ValueError, 'FOREIGN_OVERLAP_CONTENT_AND_OWNER'):
            self.validate()

    def test_all_processes_must_naturally_exit_and_reap(self):
        for field in ('natural_exit', 'group_absent', 'owned_processes_absent'):
            self.evidence = model_evidence(self.plan)
            self.evidence['stages'][0]['command'][field] = False
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'NATURAL_REAPED'):
                self.validate()

    def test_plan_cannot_inject_grant_trust_skip_signatures_or_claim_native(self):
        for field, value in (('native_acceptance', True), ('full72_claim', True),
                             ('actual', dict(Root_grant='MODEL_FAKE_GRANT'))):
            plan = copy.deepcopy(self.plan)
            plan[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'UNCHANGED_REVIEWED_PLAN'):
                L.validate_evidence(plan, self.evidence, selection=self.selection)

    def test_required_trustedonly_and_separate_public_test_gpgdir_are_planned(self):
        self.assertEqual(self.plan['required_config']['SigLevel'], ['Required', 'TrustedOnly'])
        self.assertEqual(self.plan['required_config']['LocalFileSigLevel'], ['Required', 'TrustedOnly'])
        self.assertEqual(self.plan['required_config']['GPGDir'], self.plan['pacman'][4])

    def test_all_main_command_rows_join_independent_selection(self):
        for field, value in (('image', 'sha256:' + '0' * 64), ('execution_id', '0' * 64),
                             ('supervisor', {**self.selection['supervisor'], 'nonce': '0' * 32})):
            self.evidence = model_evidence(self.plan)
            self.evidence['stages'][0]['command'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'EXTERNAL_IMAGE_EXECUTION_SUPERVISOR_JOIN'):
                self.validate()

    def test_main_selection_cannot_be_self_derived_from_rows(self):
        self.selection['execution_id'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'EXTERNAL_IMAGE_EXECUTION_SUPERVISOR_JOIN'):
            self.validate()

    def test_three_owned_executions_required_even_for_one_immutable_image(self):
        for field in ('missing-dependency', 'foreign-file-overlap'):
            self.selection = model_selection()
            self.selection['negative_execution_ids'][field] = self.selection['execution_id']
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'THREE_DISTINCT_OWNED_EXECUTION_IDS'):
                self.validate()

    def test_negative_commands_cannot_reuse_main_or_other_sibling(self):
        for kind in self.plan['negative_controls']:
            for field in ('command', 'post_query', 'post_dependencies'):
                self.evidence = model_evidence(self.plan)
                self.evidence['negative_controls'][kind][field]['execution_id'] = self.selection['execution_id']
                with self.subTest(kind=kind, field=field), self.assertRaisesRegex(ValueError, 'EXTERNAL_IMAGE_EXECUTION_SUPERVISOR_JOIN'):
                    self.validate()
        self.evidence = model_evidence(self.plan)
        self.evidence['negative_controls']['missing-dependency']['command']['execution_id'] = self.selection['negative_execution_ids']['foreign-file-overlap']
        with self.assertRaisesRegex(ValueError, 'EXTERNAL_IMAGE_EXECUTION_SUPERVISOR_JOIN'):
            self.validate()

    def test_external_nonce_owner_and_original_supervisor_code_must_join(self):
        for field, value in (('nonce', 'f' * 32), ('owner_identity', [1000, 2000, 4000]),
                             ('code_pin', L.pin(b'MODEL_ONLY_OTHER_CODE'))):
            self.evidence = model_evidence(self.plan)
            self.evidence['negative_controls']['foreign-file-overlap']['command']['supervisor'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'EXTERNAL_IMAGE_EXECUTION_SUPERVISOR_JOIN'):
                self.validate()

    def test_exact_runtime_supervisor_nonce32_owner_triplet_schema(self):
        for field, value in (('nonce', 'f' * 64), ('owner_identity', 'MODEL_ONLY'), ('owner_identity', [True, 2, 3])):
            self.selection = model_selection()
            self.selection['supervisor'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'EXTERNAL_ORIGINAL_SUPERVISOR_SELECTION'):
                self.validate()

    def test_complete_command_pipes_must_join_original_retained_pin(self):
        for field in ('stdout_pin', 'stderr_pin'):
            self.evidence = model_evidence(self.plan)
            self.evidence['stages'][0]['command'][field] = L.pin(b'MODEL_ONLY_OTHER_PIPE')
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'ORIGINAL_COMPLETE_COMMAND_PIPE_PINS'):
                self.validate()


if __name__ == '__main__':
    unittest.main()
