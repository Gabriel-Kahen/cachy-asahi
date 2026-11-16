#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Audio-only external Root delegation and provisional poststart context DATA.

No grant is issued here. The caller authenticates the complete external Root
selection. Existing hosted identity, closed Source, freshness and policy gates
are preserved by a finite reversible projection of the exact held context.
"""
import hashlib
from pathlib import Path
import types

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[2]
HELD_MEMBER = 'scripts/ci/first-login-enrollment-native-source/payload/native/delegated_context_v3.py'
HELD_PIN = {'bytes': 21460, 'sha256': 'efa5a2687ac1504ef565763ac0828dd6c98c593563df97b2f540ccf4e0de9d2b'}
OPERATION = 'bankstown-qt3-native-private-test-v1'
DELEGATION = 'ROOT_DELEGATED_BANKSTOWN_QT3_PRIVATE_TEST_V1'
CONTEXT = 'DELEGATED_BANKSTOWN_QT3_NATIVE_CONTEXT_V1'
ISSUER = 'DELEGATED_BANKSTOWN_QT3_CONTEXT_PROGRAM_V1'
SOURCE_KIND = 'BANKSTOWN_QT3_CLOSED_NATIVE_SOURCE_V1'
STAGE = 'qt3'
FINAL = dict(Root_final_acceptance=None, independent_component_acceptance=False,
             hardware_acceptance=False, release_acceptance=False)
AUDIO = dict(bankstown_version='1.1.0-5', rust_compiler='1.99.0', qt_candidate='6.12.0-3',
             frozen_minus2='HELD', legal='HELD', key_freshness='HELD', private_test_only=True)
PROJECTION = (
    ("OPERATION = 'first-login-enrollment-ui-current-v2'", "OPERATION = '"+OPERATION+"'", 1),
    ("DELEGATION = 'ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3'", "DELEGATION = '"+DELEGATION+"'", 1),
    ("CONTEXT = 'DELEGATED_CURRENT_ONBOARDING_CONTEXT_V3'", "CONTEXT = '"+CONTEXT+"'", 1),
    ("ISSUER = 'DELEGATED_CONTEXT_PROGRAM_V3'", "ISSUER = '"+ISSUER+"'", 1),
    ("d['schema'] == 3", "d['schema'] == 1", 1),
    ('schema=3', 'schema=1', 2),
    ('dict(backend=None, ui=None, lifecycle=None)', 'dict(qt3=None)', 1),
    ("d['stage'] in ('backend', 'ui', 'lifecycle')", "d['stage'] in ('qt3',)", 1),
    ("'CURRENT_ONBOARDING_CLOSED_SOURCE_V3'", "'"+SOURCE_KIND+"'", 1),
)


def need(value, code):
    if not value:
        raise ValueError(code)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def projected(raw):
    need(pin(raw) == HELD_PIN, 'EXACT_HELD_CONTEXT_PROGRAM_REQUIRED')
    value = raw.decode('utf-8')
    for old, new, count in PROJECTION:
        need(value.count(old) == count, 'FINITE_CONTEXT_PROJECTION_SITE')
        value = value.replace(old, new)
    inverse = value
    for old, new, count in reversed(PROJECTION):
        need(inverse.count(new) == count, 'FINITE_CONTEXT_INVERSE_SITE')
        inverse = inverse.replace(new, old)
    need(inverse.encode() == raw, 'WHOLE_CONTEXT_INVERSE_REQUIRED')
    return value


def _implementation():
    raw = (SOURCE / HELD_MEMBER).read_bytes()
    module = types.ModuleType('_bankstown_qt3_exact_context_v1')
    module.__file__ = str(HERE / 'context.py')
    exec(compile(projected(raw), str(SOURCE / HELD_MEMBER), 'exec'), module.__dict__)
    return module


H = _implementation()
_validate = H.validate_delegation
encoded, decode, read, whole, descriptor = H.encoded, H.decode, H.read, H.whole, H.descriptor


def validate_delegation(raw, expected_sha256, now=None):
    d = _validate(raw, expected_sha256, now)
    need(type(d['schema']) is int and d['schema'] == 1 and d['stage'] == STAGE
         and d['capability']['stage'] == STAGE and d['capability']['allow_pair_adoption'] is False,
         'AUDIO_ONLY_PRIVATE_STAGE_NO_PAIR_ADOPTION')
    need(d.get('approved') is True, 'EXPLICIT_EXTERNAL_ROOT_APPROVAL')
    need(type(d['capability']['total_seconds']) is int
         and d['capability']['total_seconds'] <= 3600, 'AUDIO_WHOLE_STAGE_MAX_3600')
    need(type(d.get('audio')) is dict and encoded(d['audio']) == encoded(AUDIO),
         'EXACT_AUDIO_INPUTS_AND_HELD_ACCEPTANCE')
    need({'context', 'owner', 'image', 'image_executor', 'owned_process'} <= set(d['programs']),
         'WHOLE_AUDIO_PROGRAM_CLOSURE')
    need(type(d.get('nonce')) is str and len(d['nonce']) == 64
         and all(c in '0123456789abcdef' for c in d['nonce']), 'ROOT_SELECTED_AUDIO_NONCE')
    for key in ('run', 'job'):
        need(d['binding'][key] is None, 'EXTERNAL_DELEGATION_HAS_NO_FUTURE_RUNTIME_IDS')
    need(type(d['binding']['attempt']) is int and d['binding']['attempt'] == 1,
         'EXACT_FIRST_ATTEMPT_ONLY')
    whole(d.get('inputs_pin'))
    selection = d.get('root_selection')
    need(type(selection) is dict and set(selection) == {'directory', 'wait_seconds'},
         'EXPLICIT_EXTERNAL_ROOT_SELECTION_RELAY')
    path = selection['directory']
    need(type(path) is str and path.startswith('/') and len(path) <= 4096
         and all(p not in ('', '.', '..') for p in path[1:].split('/'))
         and all(ord(c) > 32 and ord(c) != 127 for c in path)
         and type(selection['wait_seconds']) is int and 1 <= selection['wait_seconds'] <= 300,
         'FINITE_ROOT_SELECTED_INBOX')
    return d


# Only the isolated instance dispatch changes. No maintained module is mutated.
H.validate_delegation = validate_delegation


def source(d, root):
    return H.source(d, root)


def source_rows(d, root):
    return source(d, root)[1]


def capture_context(raw, sha256, source_root, *, environ=None, jobs_response=None, now=None):
    return H.capture_context(raw, sha256, source_root, environ=environ, jobs_response=jobs_response, now=now)


def validate_context(delegation, context, *, now=None):
    result = H.validate_context(delegation, context, now=now)
    need(context['stage'] == STAGE and context['nonce'] == delegation['nonce'], 'SAME_ROOT_SELECTED_AUDIO_NONCE')
    return result


def resolve_material(delegation, source_root, role):
    return H.resolve_material(delegation, source_root, role)


def material_reference(delegation, source_root, role):
    return H.material_reference(delegation, source_root, role)


def context_contract(delegation, context=None, program=None, source_root=None):
    """Finite audio dispatch only; external SHA admission remains the caller's gate."""
    need(type(delegation.get('schema')) is int and delegation['schema'] == 1
         and delegation.get('kind') == DELEGATION and delegation.get('issuer') == 'Root',
         'AUDIO_CONTEXT_DELEGATION_DISPATCH')
    row = delegation.get('programs', {}).get('context')
    expected = descriptor(row)
    need(row['member'] == 'scripts/ci/bankstown-qt3-native-source/context.py',
         'EXACT_AUDIO_CONTEXT_SOURCE_MEMBER')
    if context is not None:
        need(type(context.get('schema')) is int and context['schema'] == 1
             and context.get('kind') == CONTEXT and context.get('issuer') == ISSUER
             and context.get('operation') == OPERATION and context.get('stage') == STAGE
             and context.get('program_pin') == expected, 'AUDIO_CONTEXT_PROGRAM_IDENTITY')
    if program is not None:
        need(program.OPERATION == OPERATION and program.DELEGATION == DELEGATION
             and program.CONTEXT == CONTEXT and program.ISSUER == ISSUER,
             'ACTUAL_AUDIO_CONTEXT_API')
        path = Path(source_root) / row['member']
        need(Path(program.__file__) == path and pin(read(path, 128*1024)[0]) == expected,
             'ACTUAL_AUDIO_CONTEXT_WHOLE_BODY')
    return 1


def admit(delegation_raw, delegation_sha256, context, source_root, executor):
    """Join selected DATA and the same live maintained executor; never create one."""
    d = validate_delegation(delegation_raw, delegation_sha256)
    validate_context(d, context)
    root, _ = source(d, source_root)
    policy = decode(read(root / d['policy']['member'], 1024**2)[0])
    need(callable(getattr(executor, 'run', None)) and callable(getattr(executor, 'live', None)),
         'SAME_LIVE_OWNED_EXECUTOR_REQUIRED')
    executor.live()
    facts = executor.facts
    need(facts['api'] == 'CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3'
         and facts['binding'] == context['binding'] and facts['stage'] == STAGE
         and facts['nonce'] == context['nonce'] and facts['domain_policy_pin'] == context['policy_pin']
         and facts['code_pin'] == descriptor(d['programs']['image_executor'])
         and facts['supervision_program_pin'] == descriptor(d['programs']['owned_process'])
         and facts['native_architecture'] == 'aarch64' and type(facts['uid']) is int and facts['uid'] > 0
         and type(facts['gid']) is int and facts['gid'] > 0
         and all(facts[k] is True for k in ('daemon_pidfd_held', 'whole_owner_deadline_enforced',
                                           'daemon_deadline_enforced', 'exclusive_daemon'))
         and facts['docker_endpoint'] == policy['image_endpoint_template'].format(nonce=context['nonce'])
         and all(facts.get(k) is v for k, v in FINAL.items()), 'ACTUAL_SAME_AUDIO_EXECUTOR_CUSTODY')
    return d, context, policy
