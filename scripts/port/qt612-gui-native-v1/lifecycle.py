# SPDX-License-Identifier: MIT
"""Passive normal-ALPM lifecycle contract. No actor, grants or native admission.

Snapshots/ALPM receipts are supplied by a future separately authorized image
supervisor. Checking their internal consistency cannot authenticate that actor,
public trust, package provenance, architecture, or hardware behavior.
"""
import base64
import hashlib
import json
import posixpath
import re

BASE = 'cachy-asahi-qt612-base-source-reference'
GUI = 'cachy-asahi-qt612-gui-source-reference'
VERSIONS = {BASE: '6.12.0-2', GUI: '6.12.0-1'}
MODULES = ('Core', 'Concurrent', 'DBus', 'Gui', 'Network', 'OpenGL', 'OpenGLWidgets',
           'PrintSupport', 'Sql', 'Test', 'Widgets', 'Xml', 'XcbQpa')
GUI_MODULES = MODULES + ('EglFSDeviceIntegration', 'EglFsKmsGbmSupport', 'EglFsKmsSupport',
                         'WaylandClient', 'WlShellIntegration')
SCOPE = 'QT612_GUI_PRIVATE_TEST_IMAGE_LIFECYCLE_DATA_ONLY'
MAX_ENTRIES, MAX_FILE_BYTES, MAX_CONTENT_BYTES = 50000, 2 * 1024**2, 16 * 1024**2


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def absolute(path):
    need(type(path) is str and path.startswith('/') and not path.startswith('//') and path != '/' and
         path == posixpath.normpath(path) and all(ord(c) >= 32 and ord(c) != 127 for c in path) and len(path) <= 1024,
         'CANONICAL_IMAGE_ABSOLUTE_PATH')
    return path


def descriptor(value):
    need(type(value) is dict and set(value) == {'bytes', 'sha256'}
         and type(value['bytes']) is int and 0 < value['bytes'] <= 2 * 1024**3
         and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'EXACT_PUBLIC_DESCRIPTOR')


def dependencies(rows):
    need(type(rows) is list and len(rows) <= 10000
         and all(type(s) is str and re.fullmatch(r'[A-Za-z0-9@_+.:/-]+(?:[<>=]+[A-Za-z0-9@_+.:/-]+)?', s)
                 for s in rows) and rows == sorted(set(rows)), 'FINITE_EXACT_DEPENDENCIES')
    return rows


def graph(value):
    need(type(value) is dict and 1 < len(value) <= 10000, 'COMPLETE_BASELINE_PACKAGE_GRAPH')
    for name, row in value.items():
        need(type(name) is str and re.fullmatch('[a-zA-Z0-9@_+.-]+', name)
             and type(row) is dict and set(row) == {'version', 'depends'}
             and type(row['version']) is str and re.fullmatch('[a-zA-Z0-9@_+.:-]+', row['version']), 'PACKAGE_GRAPH_ROW')
        dependencies(row['depends'])
    return value


def package(value, name):
    need(type(value) is dict and set(value) == {'name', 'version', 'architecture', 'path', 'pin', 'depends', 'payload'}
         and value['name'] == name and value['version'] == VERSIONS[name]
         and value['architecture'] == 'aarch64', 'FIXED_DISTINCT_PACKAGE_IDENTITIES')
    absolute(value['path']); descriptor(value['pin']); dependencies(value['depends'])
    payload = value['payload']
    need(type(payload) is dict and set(payload) == {'complete', 'files'} and payload['complete'] is True
         and type(payload['files']) is dict and 0 < len(payload['files']) <= MAX_ENTRIES, 'COMPLETE_PACKAGE_PAYLOAD')
    for path, row in payload['files'].items():
        absolute(path)
        need(path.startswith(('/usr/', '/opt/')) and type(row) is dict and row.get('type') in ('file', 'directory', 'symlink'), 'PACKAGE_PAYLOAD_SCOPE')
        metadata(row, content=False)
    modules = MODULES if name == BASE else GUI_MODULES
    for module in modules:
        need(payload['files'].get('/usr/lib/libQt6' + module + '.so.6.12.0', {}).get('type') == 'file', 'SOURCE_BACKED_MODULE_PAYLOAD')
    return value


def roots(values, user=False):
    need(type(values) is list and 0 < len(values) <= 32 and len(set(values)) == len(values), 'EXPLICIT_PROTECTED_ROOTS')
    for path in values:
        absolute(path)
        need(not user or path.startswith('/home/'), 'EXPLICIT_USER_OWNED_ROOT')
    need(all(not a.startswith(b + '/') for a in values for b in values if a != b), 'NONOVERLAPPING_PROTECTED_ROOTS')
    return values


def metadata(row, *, content):
    need(type(row) is dict and row.get('type') in ('file', 'directory', 'symlink')
         and all(type(row.get(k)) is int and 0 <= row[k] <= (0o7777 if k == 'mode' else 2**32 - 1)
                 for k in ('mode', 'uid', 'gid')), 'COMPLETE_FILE_MODE_UID_GID')
    fields = {'type', 'mode', 'uid', 'gid'}
    if row['type'] == 'file':
        fields |= {'bytes', 'sha256'}
        need(type(row.get('bytes')) is int and 0 <= row['bytes'] <= 512 * 1024**2
             and type(row.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'FILE_CONTENT_PIN')
        if content:
            fields.add('content_base64')
            need(type(row.get('content_base64')) is str and len(row['content_base64']) <= MAX_FILE_BYTES * 2, 'BOUNDED_COMPLETE_CONTENT')
            try:
                raw = base64.b64decode(row['content_base64'], validate=True)
            except (ValueError, TypeError) as error:
                raise ValueError('VALID_COMPLETE_CONTENT') from error
            need(len(raw) <= MAX_FILE_BYTES and pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'EXACT_COMPLETE_CONTENT')
    if row['type'] == 'symlink':
        fields.add('target')
        need(type(row.get('target')) is str and 0 < len(row['target']) <= 4096 and '\x00' not in row['target'], 'EXACT_SYMLINK_TARGET')
    if content:
        fields.add('package_owner')
    need(set(row) == fields, 'EXACT_FILE_SNAPSHOT_FIELDS')


def _state(plan, kind):
    state = json.loads(encoded(plan['baseline_inventory']))
    if kind == 'gui':
        state.pop(BASE)
        state[GUI] = {k: plan['gui_package'][k] for k in ('version', 'depends')}
    elif kind == 'removed':
        state.pop(BASE)
    return state


def _inventory(state):
    return {name: row['version'] for name, row in state.items()}


def _depvector(state):
    return sorted({item for row in state.values() for item in row['depends']})


def reviewed_plan(*, baseline_inventory, base_package, gui_package, pacman_config, test_gpgdir,
                  user_roots, protected_config_roots):
    """Return reviewable commands; every real actor/trust/image result is UNBOUND."""
    graph(baseline_inventory); package(base_package, BASE); package(gui_package, GUI)
    need(BASE in baseline_inventory and GUI not in baseline_inventory and 'qt6-base' not in baseline_inventory
         and baseline_inventory[BASE] == {k: base_package[k] for k in ('version', 'depends')}, 'EXACT_BASELINE_BASE13_NO_GUI_OR_OTHER_QT_BASE')
    absolute(pacman_config); absolute(test_gpgdir)
    need(pacman_config.startswith('/work/') and test_gpgdir.startswith('/work/')
         and pacman_config != test_gpgdir and not pacman_config.startswith(test_gpgdir + '/'), 'SEPARATE_PRIVATE_TEST_CONFIG_AND_GPGDIR')
    roots(user_roots, True); roots(protected_config_roots)
    need(not any(a == b or a.startswith(b + '/') or b.startswith(a + '/')
                 for a in user_roots for b in protected_config_roots), 'SEPARATE_USER_AND_OTHER_PACKAGE_CONFIG')
    plan = dict(schema_version=1, scope=SCOPE, status='REVIEWED_DATA_PLAN_NOT_EXECUTED',
                baseline_inventory=baseline_inventory, base_package=base_package, gui_package=gui_package,
                user_roots=user_roots, protected_config_roots=protected_config_roots,
                pacman=['/usr/bin/pacman', '--config', pacman_config, '--gpgdir', test_gpgdir],
                required_config=dict(Architecture='aarch64', SigLevel=['Required', 'TrustedOnly'],
                                     LocalFileSigLevel=['Required', 'TrustedOnly'], GPGDir=test_gpgdir),
                execution='SEPARATELY_GRANTED_OWNED_PRIVATE_IMAGE_ONLY',
                signature_trust_provenance='EXTERNAL_COMPONENT_BINDINGS_REQUIRED',
                actual=dict(image=None, Root_grant=None, public_TEST_trust=None, base_signature=None,
                            gui_signature=None, lifecycle=None), native_acceptance=False,
                full72_claim=False, module_counts=dict(base=13, gui=18), stages=[], negative_controls={})
    for name, before, after, incoming, outgoing in (
        ('upgrade', 'base', 'gui', GUI, BASE), ('reinstall', 'gui', 'gui', GUI, None),
        ('downgrade', 'gui', 'base', BASE, GUI), ('upgrade-again', 'base', 'gui', GUI, BASE),
        ('remove', 'gui', 'removed', None, GUI),
    ):
        operand = (base_package if incoming == BASE else gui_package)['path'] if incoming else GUI
        plan['stages'].append(dict(name=name, before=before, after=after, incoming=incoming, outgoing=outgoing,
                                   argv=plan['pacman'] + (['-U', '--', operand] if incoming else ['-R', '--', operand]),
                                   allowed_outcomes=['success', 'dependency-refusal'] if name == 'remove' else ['success']))
    for kind in ('missing-dependency', 'foreign-file-overlap'):
        plan['negative_controls'][kind] = dict(argv=plan['pacman'] + ['-U', '--', gui_package['path']],
                                               scope='SEPARATE_DISPOSABLE_SIBLING_IMAGE', expected='normal-ALPM-refusal')
    need(len(encoded(plan)) <= 32 * 1024**2, 'BOUNDED_REVIEWED_PLAN')
    return json.loads(encoded(plan))


def _snapshot(value, expected_roots, plan, *, user):
    need(type(value) is dict and set(value) == {'complete', 'roots', 'entries'} and value['complete'] is True
         and value['roots'] == expected_roots and type(value['entries']) is dict
         and 0 < len(value['entries']) <= MAX_ENTRIES, 'COMPLETE_EXTERNAL_PROTECTED_SNAPSHOT')
    entries, total = value['entries'], 0
    for root in expected_roots:
        need(entries.get(root, {}).get('type') == 'directory', 'SNAPSHOT_ROOT_PRESENT')
    for path, row in entries.items():
        absolute(path)
        need(any(path == root or path.startswith(root + '/') for root in expected_roots), 'SNAPSHOT_PATH_WITHIN_EXPLICIT_ROOT')
        metadata(row, content=True)
        owner = row['package_owner']
        need(owner is None if user else owner in plan['baseline_inventory'] and owner not in (BASE, GUI), 'UNCHANGED_EXTERNAL_OWNERSHIP')
        if user:
            need(row['uid'] > 0, 'USER_OWNED_SNAPSHOT_UID')
        total += row.get('bytes', 0)
        need(total <= MAX_CONTENT_BYTES, 'BOUNDED_COMPLETE_PROTECTED_CONTENT')
        parent = posixpath.dirname(path)
        if path not in expected_roots:
            need(entries.get(parent, {}).get('type') == 'directory', 'COMPLETE_SNAPSHOT_PARENT_NO_SYMLINK_TRAVERSAL')
    return value


def _selection(selection):
    need(type(selection) is dict and set(selection) == {'image', 'supervisor', 'execution_id', 'negative_execution_ids'}
         and type(selection['image']) is str and re.fullmatch('sha256:[0-9a-f]{64}', selection['image']),
         'EXTERNAL_OWNED_IMAGE_EXECUTION_SELECTION')
    supervisor = selection['supervisor']
    need(type(supervisor) is dict and set(supervisor) == {'code_pin', 'nonce', 'owner_identity'}
         and type(supervisor['nonce']) is str and re.fullmatch('[0-9a-f]{32}', supervisor['nonce'])
         and type(supervisor['owner_identity']) is list and len(supervisor['owner_identity']) == 3
         and all(type(n) is int and n > 0 for n in supervisor['owner_identity']), 'EXTERNAL_ORIGINAL_SUPERVISOR_SELECTION')
    descriptor(supervisor['code_pin'])
    negatives = selection['negative_execution_ids']
    need(type(negatives) is dict and set(negatives) == {'missing-dependency', 'foreign-file-overlap'},
         'TWO_EXTERNAL_SIBLING_EXECUTION_SELECTIONS')
    executions = [selection['execution_id'], *negatives.values()]
    need(all(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) for value in executions)
         and len(set(executions)) == 3, 'THREE_DISTINCT_OWNED_EXECUTION_IDS')


def _command(row, argv, exit_code, selection, execution_id):
    fields = {'argv', 'exit', 'stdout', 'stderr', 'timeout_seconds', 'seconds', 'pid', 'pgid',
              'natural_exit', 'group_absent', 'owned_processes_absent', 'image', 'supervisor',
              'execution_id', 'stdout_pin', 'stderr_pin'}
    need(type(row) is dict and set(row) == fields and row['argv'] == argv
         and type(row['exit']) is int and row['exit'] == exit_code, 'EXACT_NORMAL_PACMAN_COMMAND_EXIT')
    need(row['image'] == selection['image'] and row['supervisor'] == selection['supervisor']
         and row['execution_id'] == execution_id, 'EXTERNAL_IMAGE_EXECUTION_SUPERVISOR_JOIN')
    need(type(row['pid']) is int and row['pid'] == row['pgid'] > 1 and type(row['pgid']) is int
         and row['natural_exit'] is True and row['group_absent'] is True and row['owned_processes_absent'] is True
         and type(row['timeout_seconds']) is int and row['timeout_seconds'] == 120
         and type(row['seconds']) in (int, float) and 0 <= row['seconds'] <= 120, 'NATURAL_REAPED_PACMAN_BOUNDARY')
    need(all(type(row[k]) is str and len(row[k].encode()) <= 1024**2 for k in ('stdout', 'stderr')), 'BOUNDED_COMPLETE_PACMAN_OUTPUT')
    need(all(type(row[k + '_pin']) is dict and set(row[k + '_pin']) == {'bytes', 'sha256'}
             and type(row[k + '_pin']['bytes']) is int and row[k + '_pin'] == pin(row[k].encode())
             for k in ('stdout', 'stderr')), 'ORIGINAL_COMPLETE_COMMAND_PIPE_PINS')


def _checks(row, plan, state, selection):
    need(set(row) == {'inventory', 'query', 'dependency_check'}, 'EXACT_POST_TRANSACTION_CHECKS')
    expected = _inventory(state)
    need(row['inventory'] == expected, 'EXACT_BASELINE_MINUS_BASE_PLUS_GUI_INVENTORY')
    _command(row['query'], plan['pacman'] + ['-Q'], 0, selection, selection['execution_id'])
    observed = {}
    for line in row['query']['stdout'].splitlines():
        fields = line.split()
        need(len(fields) == 2 and fields[0] not in observed, 'COMPLETE_PACMAN_Q_OUTPUT')
        observed[fields[0]] = fields[1]
    need(observed == expected, 'PACMAN_Q_EXACT_INVENTORY_JOIN')
    _command(row['dependency_check'], plan['pacman'] + ['-T', '--'] + _depvector(state), 0, selection, selection['execution_id'])
    need(not row['dependency_check']['stdout'].strip(), 'NORMAL_PACMAN_T_NO_MISSING_DEPENDENCIES')


def _questions(stage, outcome, plan):
    if outcome != 'success':
        return []
    added = {stage['incoming']: VERSIONS[stage['incoming']]} if stage['incoming'] else {}
    removed = {stage['outgoing']: VERSIONS[stage['outgoing']]} if stage['outgoing'] else {}
    questions = []
    if stage['incoming'] and stage['outgoing']:
        questions.append(dict(type='ALPM_QUESTION_CONFLICT_PKG', numeric_type=4,
                              incoming=stage['incoming'], remove=stage['outgoing'], reason='qt6-base', answer=True))
    questions.append(dict(type='PACMAN_TRANSACTION_CONFIRM', added=added, removed=removed, answer=True))
    return questions


def _qt_consumers(plan):
    return [dict(target=name, dependency=dependency, causingpkg=GUI)
            for name, row in sorted(plan['baseline_inventory'].items()) if name != BASE
            for dependency in row['depends']
            if re.split('[<>=]', dependency)[0] in ('qt6-base', GUI)
            or re.split('[<>=]', dependency)[0].startswith('libQt6')]


def validate_evidence(plan, evidence, *, selection):
    """Check consistency against caller-selected image/execution/supervisor custody.

    selection must arrive independently from the evidence, with its runtime
    image and original supervisor authenticated by the composing caller. Three
    owned containers may share one immutable image but must have distinct IDs.
    No comparison here can grant native/hardware admission or prove Root origin.
    """
    _selection(selection)
    canonical = reviewed_plan(**{k: plan[k] for k in ('baseline_inventory', 'base_package', 'gui_package',
                              'user_roots', 'protected_config_roots')}, pacman_config=plan['pacman'][2], test_gpgdir=plan['pacman'][4])
    need(plan == canonical, 'UNCHANGED_REVIEWED_PLAN')
    need(type(evidence) is dict and set(evidence) == {'baseline', 'stages', 'negative_controls'}
         and type(evidence['stages']) is list and len(evidence['stages']) == 5, 'COMPLETE_LIFECYCLE_EVIDENCE')
    baseline = evidence['baseline']
    need(set(baseline) == {'checks', 'user', 'protected_config', 'payload'}, 'BASELINE_SNAPSHOT_FIELDS')
    _checks(baseline['checks'], plan, _state(plan, 'base'), selection)
    _snapshot(baseline['user'], plan['user_roots'], plan, user=True)
    _snapshot(baseline['protected_config'], plan['protected_config_roots'], plan, user=False)
    need(baseline['payload'] == plan['base_package']['payload'], 'BASE13_PAYLOAD_BASELINE')
    for stage, row in zip(plan['stages'], evidence['stages']):
        need(type(row) is dict and set(row) == {'name', 'outcome', 'command', 'alpm', 'checks', 'user', 'protected_config', 'payload'}
             and row['name'] == stage['name'] and row['outcome'] in stage['allowed_outcomes'], 'FINITE_LIFECYCLE_STAGE')
        success = row['outcome'] == 'success'
        consumers = _qt_consumers(plan) if stage['name'] == 'remove' else []
        need(stage['name'] != 'remove' or success != bool(consumers), 'NORMAL_REMOVE_MUST_RESPECT_INSTALLED_QT_CONSUMERS')
        _command(row['command'], stage['argv'], 0 if success else 1, selection, selection['execution_id'])
        added = {stage['incoming']: VERSIONS[stage['incoming']]} if success and stage['incoming'] else {}
        removed = {stage['outgoing']: VERSIONS[stage['outgoing']]} if success and stage['outgoing'] else {}
        need(row['alpm'] == dict(committed=success, added=added, removed=removed,
                                error=None if success else 'ALPM_ERR_UNSATISFIED_DEPS',
                                unsatisfied=[] if success else consumers,
                                questions=_questions(stage, row['outcome'], plan)), 'EXACT_NORMAL_ATOMIC_ALPM_RECEIPT')
        state = stage['after'] if success else stage['before']
        _checks(row['checks'], plan, _state(plan, state), selection)
        need(row['user'] == baseline['user'] and row['protected_config'] == baseline['protected_config'], 'PRESERVE_ALL_USER_AND_OTHER_PACKAGE_CONFIGURATION')
        expected_payload = {'complete': True, 'files': {}} if state == 'removed' else plan['gui_package' if state == 'gui' else 'base_package']['payload']
        need(row['payload'] == expected_payload, 'EXACT_CURRENT_PACKAGE_PAYLOAD_NO_BASELINE_RELABEL')
    _negative_controls(plan, evidence['negative_controls'], baseline, selection)
    return dict(schema_version=1, scope=SCOPE, status='LIFECYCLE_RECEIPTS_CONSISTENT_ONLY',
                native_acceptance=False, full72_claim=False, hardware='NOT_ESTABLISHED',
                signatures_provenance_trust='NOT_ESTABLISHED_BY_THIS_COMPONENT',
                removal=evidence['stages'][-1]['outcome'], selection=json.loads(encoded(selection)))


def _negative_controls(plan, rows, baseline, selection):
    need(type(rows) is dict and set(rows) == set(plan['negative_controls']), 'BOTH_NORMAL_ALPM_NEGATIVE_CONTROLS_REQUIRED')
    original = _inventory(_state(plan, 'base'))
    for kind, row in rows.items():
        need(type(row) is dict and set(row) == {'command', 'alpm_error', 'detail', 'before_inventory',
             'after_inventory', 'user', 'protected_config', 'payload', 'post_query', 'post_dependencies'}, 'EXACT_NEGATIVE_CONTROL_RECEIPT')
        execution_id = selection['negative_execution_ids'][kind]
        _command(row['command'], plan['negative_controls'][kind]['argv'], 1, selection, execution_id)
        need(row['before_inventory'] == row['after_inventory'] and row['payload'] == baseline['payload']
             and row['user'] == baseline['user'] and row['protected_config'] == baseline['protected_config'], 'REFUSAL_LEAVES_INVENTORY_PAYLOAD_CONFIGURATION_UNCHANGED')
        if kind == 'missing-dependency':
            detail = row['detail']
            need(type(detail) is dict and set(detail) == {'dependency', 'removed_package'}
                 and detail['dependency'] in plan['gui_package']['depends']
                 and detail['removed_package'] in original and detail['removed_package'] != BASE,
                 'BOUND_MISSING_DEPENDENCY_SIBLING_IMAGE')
            need(re.split('[<>=]', detail['dependency'])[0] == detail['removed_package'], 'DIRECT_MISSING_PACKAGE_DEPENDENCY_JOIN')
            expected = {k: v for k, v in original.items() if k != detail['removed_package']}
            need(row['alpm_error'] == 'ALPM_ERR_UNSATISFIED_DEPS' and row['before_inventory'] == expected, 'NORMAL_MISSING_DEPENDENCY_REFUSAL')
            _command(row['post_dependencies'], plan['pacman'] + ['-T', '--'] + plan['gui_package']['depends'], 127, selection, execution_id)
            need(row['post_dependencies']['stdout'].splitlines() == [detail['dependency']], 'PACMAN_T_REPORTS_EXACT_MISSING_DEPENDENCY')
        else:
            detail = row['detail']
            need(type(detail) is dict and set(detail) == {'path', 'foreign_owner', 'before', 'after'}
                 and detail['path'] in plan['gui_package']['payload']['files']
                 and detail['foreign_owner'] in original and detail['foreign_owner'] != BASE
                 and row['alpm_error'] == 'ALPM_ERR_FILE_CONFLICTS' and row['before_inventory'] == original,
                 'NORMAL_FOREIGN_OWNED_FILE_OVERLAP_REFUSAL')
            metadata(detail['before'], content=True)
            need(detail['before'] == detail['after'] and detail['before']['package_owner'] == detail['foreign_owner'], 'FOREIGN_OVERLAP_CONTENT_AND_OWNER_PRESERVED')
            _command(row['post_dependencies'], plan['pacman'] + ['-T', '--'] + plan['gui_package']['depends'], 0, selection, execution_id)
            need(not row['post_dependencies']['stdout'].strip(), 'OVERLAP_CONTROL_DEPENDENCIES_PRESENT')
        _command(row['post_query'], plan['pacman'] + ['-Q'], 0, selection, execution_id)
        expected_query = ''.join(name + ' ' + version + '\n' for name, version in sorted(row['after_inventory'].items()))
        need(row['post_query']['stdout'] == expected_query, 'NEGATIVE_CONTROL_COMPLETE_INVENTORY_QUERY')
