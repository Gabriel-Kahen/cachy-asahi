#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Bounded audio entry over the exact Source196 corrected hosted transport.

The caller supplies genuine retained773 DATA and fresh external Root selections.
Import only defines the isolated projection; it enters no operational role.
"""
import hashlib
import os
from pathlib import Path
import sys
import types

HERE = Path(__file__).resolve().parent
PREFIX = 'scripts/ci/bankstown-qt3-hosted-v1/'
AUDIO = 'scripts/ci/bankstown-qt3-native-source/'
CAPTURE_COMMIT = '441832e1d687255434c9001d603d400e4932f26a'
BASIS = dict(bytes=66263, sha256='f8387c748f31698b45656998248f099a8207bb58f7f9d7e70ef53a73be286d97')
SOURCE72 = dict(bytes=14203, sha256='5643afddb02e2d4d29f1215f44b8409599d9b17dd3849699e8fd6897eb6c40b8')
POLICY = dict(bytes=5703, sha256='7bd20f3c36cce413b4e732232cb3e60dee5ce9d8f791d9cb046eed19654b03ba')
OWNER = dict(bytes=12524, sha256='c528e8bdf2f16573bb4da0eed6aa77b0e271d476fe0baeac35231a4248e9a634')
CONTROLLER = dict(bytes=3407, sha256='8f17ce98eea2ddf8b2b220736460c2535d4d2fc33de57f1f94829ac521206ebe')


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


PROJECTION = (
    ("launcher_seconds=7740", "launcher_seconds=4170", 1),
    ("cpu_seconds=7740", "cpu_seconds=4170", 1),
    ("r['schema']==3 and r['kind']=='ROOT_AUTHORIZED_CURRENT_HOSTED_LAUNCH_V3'",
     "r['schema']==1 and r['kind']=='ROOT_AUTHORIZED_BANKSTOWN_QT3_HOSTED_LAUNCH_V1'", 1),
    ("value['schema']==3\n        and value['kind']=='ROOT_STAGED_CURRENT_INPUTS_V3'and type(value['owner_inputs'])is dict and set(value['owner_inputs'])=={'image_inputs','stage_inputs'}",
     "value['schema']==1\n        and value['kind']=='ROOT_STAGED_BANKSTOWN_QT3_INPUTS_V1'and type(value['owner_inputs'])is dict and set(value['owner_inputs'])=={'base_lock','bootstrap_profile','baseline_inventory','base_materials','supplemental_materials','keyring_materials','candidate_materials','catalog','official_trust'}", 1),
    ("remaining(plan.timing) if plan.Q else 0", "remaining(plan.timing) if plan.Q else max(.001,started+LIMITS['launcher_seconds']-time.monotonic())", 1),
    ("p['controller_seconds']==7560", "p['controller_seconds']==3960", 1),
    ("if not prerequisite_selected(plan.d):return 7560", "if not prerequisite_selected(plan.d):return 3960", 1),
    ("0<E.runtime_microseconds(properties['RuntimeMaxUSec'])<=7560*1000000",
     "0<E.runtime_microseconds(properties['RuntimeMaxUSec'])<=3960*1000000", 1),
    ("api==['CURRENT_ONBOARDING_DELEGATED_OWNER_V3']and callback is not None",
     "api==[]and pin(owner)==AUDIO_OWNER_PIN and callback is not None", 1),
    ("plan.public_phase='controller'\n        need(not Path('/sys/fs/cgroup/system.slice/cachy-current-controller-'",
     "plan.public_phase='controller'\n        retained_input_mount(plan)\n        need(not Path('/sys/fs/cgroup/system.slice/cachy-current-controller-'", 1),
    ("report.update(status='DELEGATED_HOSTED_CONTROLLER_RETIRED_DATA_ONLY',cleanup=dict(owned_storage_absent=True,error_count=0));plan.public_phase='complete'",
     "report['retained_input_custody']=retained_input_mount(plan)\n        report.update(status='DELEGATED_HOSTED_CONTROLLER_RETIRED_DATA_ONLY',cleanup=dict(owned_storage_absent=True,error_count=0));plan.public_phase='complete'", 1),
)


def projected(raw):
    need(pin(raw) == BASIS, 'EXACT_SOURCE196_CAPTURE_BODY')
    text = raw.decode()
    for before, after, count in PROJECTION:
        need(text.count(before) == count and after not in text, 'EXACT_HOSTED_PROJECTION_SITE')
        text = text.replace(before, after)
    inverse = text
    for before, after, count in reversed(PROJECTION):
        need(inverse.count(after) == count, 'EXACT_HOSTED_INVERSE_SITE')
        inverse = inverse.replace(after, before)
    need(inverse.encode() == raw, 'WHOLE_SOURCE196_CAPTURE_INVERSE')
    return text


def _implementation():
    path = HERE / 'basis/hosted_current_v3.py'
    # Basis body is selected as a closed Source leaf before operational entry.
    need(path == path.resolve() and path.stat().st_nlink == 1, 'ORDINARY_CAPTURE_BASIS')
    raw = path.read_bytes()
    value = types.ModuleType('_bankstown_qt3_corrected_hosted_transport')
    value.__file__ = str(HERE / 'hosted.py')
    value.AUDIO_OWNER_PIN = OWNER
    exec(compile(projected(raw), str(path), 'exec'), value.__dict__)
    return value


H = _implementation()
API = 'BANKSTOWN_QT3_HOSTED_LAUNCHER_V1'
LIMITS, FINAL, SCOPE = H.LIMITS, H.FINAL, H.SCOPE
_request, _program, _preflight = H.request, H.program, H.preflight


def request(path, expected):
    r = _request(path, expected)
    need('material_staging' not in r, 'COMPLETE517_ACQUISITION_IS_NOT_COMPLETE773')
    d = H.decode(r['delegation_json'])
    need(not H.prerequisite_selected(d) and d['capability'].get('allow_material_staging', False) is False,
         'EXPLICIT_PRESTAGED773_PATH_NO_IMPLICIT_HOST_SETUP')
    need(d['stage'] == 'qt3' and d['programs']['owner'] == dict(member=AUDIO+'owner.py', **OWNER)
         and d['programs']['image_executor'] == dict(member=AUDIO+'controller.py', **CONTROLLER)
         and d['programs']['inputs_assembler']['member'] == PREFIX+'inputs.py'
         and r['launcher']['member'] == PREFIX+'hosted.py'
         and d['policy'] == dict(member=PREFIX+'policy.PROPOSAL.json', **POLICY),
         'EXACT_AUDIO_PROGRAMS_AND_SEPARATE_HOSTED_POLICY')
    return r


def program(root, row, name):
    value = _program(root, row, name)
    if row['member'] == AUDIO+'controller.py':
        need(H.descriptor(row) == CONTROLLER, 'EXACT_AUDIO_CONTROLLER_DISPATCH')
        # This is the isolated whole-pinned maintained implementation created by
        # audio/controller.py, including its audio context and re-entry gates.
        return value.E
    return value


def mount_custody(staged):
    """Observe an externally retained finite read-only mount; create nothing."""
    staged = Path(staged)
    need(staged.is_absolute() and staged == staged.resolve() and staged.is_dir()
         and all(ord(c) > 32 and ord(c) < 127 and c != '\\' for c in str(staged)),
         'CANONICAL_RETAINED_INPUT_MOUNT')
    info = staged.stat()
    need(info.st_uid == os.getuid() and info.st_mode & 0o777 == 0o700,
         'EXTERNALLY_SELECTED_PRIVATE_INPUT_MOUNT')
    with open('/proc/self/mountinfo', 'rb') as stream:
        raw = stream.read(2*1024**2+1)
    need(len(raw) <= 2*1024**2, 'BOUNDED_ACTUAL_MOUNTINFO')
    matches = []
    for line in raw.decode('ascii').splitlines():
        words = line.split()
        need(len(words) >= 10 and '-' in words, 'ACTUAL_MOUNTINFO_SHAPE')
        point = Path(words[4])
        need(point == staged or not point.is_relative_to(staged),
             'NO_DESCENDANT_MOUNTS_IN_RETAINED_INPUT_DOMAIN')
        if words[4] == str(staged):
            matches.append(words)
    need(len(matches) == 1 and 'ro' in matches[0][5].split(','),
         'EXACT_INPUT_ROOT_IS_A_READONLY_MOUNT_NOT_A_DIRECTORY_PROMISE')
    space = os.statvfs(staged)
    need(0 < space.f_blocks*space.f_frsize <= 32*1024**3
         and 0 < space.f_files <= 20000, 'FINITE_RETAINED_INPUT_FILESYSTEM')
    row = matches[0]
    return dict(kind='EXTERNAL_ROOT_RETAINED_READONLY_MOUNT_OBSERVATION_V1',
                path=str(staged), mount_id=row[0], parent_mount_id=row[1], device=row[2],
                mount_root=row[3], filesystem=row[row.index('-')+1],
                st_dev=info.st_dev, st_ino=info.st_ino, uid=info.st_uid,
                filesystem_bytes=space.f_blocks*space.f_frsize, filesystem_inodes=space.f_files,
                retirement_owner='Root', retirement_observed_here=False,
                Root_acceptance=None)


def retained_input_mount(plan):
    row = mount_custody(plan.request['staged_root'])
    need(row == plan.input_mount, 'SAME_RETAINED_INPUT_MOUNT_THROUGH_CONTROLLER_RETIREMENT')
    return row


def source72_parent(root):
    raw = H.read(root / (PREFIX+'source72-map.DATA.json'), 1024**2)
    need(pin(raw) == SOURCE72, 'EXACT_SOURCE72_PARENT_MAP')
    previous = H.decode(raw)
    actual = H.decode(H.read(root/'source-map.json', 1024**2))
    need(len(previous['files']) == 70 and all(value is None for value in previous['actual'].values())
         and all(actual['files'].get(name) == row for name, row in previous['files'].items()),
         'ALL_SOURCE72_OPERATIVE_BYTES_AND_MODES_PRESERVED')
    return SOURCE72


def preflight(r, source_root, main_root, control_root, environ, now):
    need(sys.version_info >= (3, 14), 'QUALIFIED_PYTHON314_REQUIRED_NO_IMPLICIT_INSTALL')
    # This observation occurs before metadata/privilege and is rejoined before
    # the controller and after its unchanged owned cleanup.
    observed = mount_custody(r['staged_root'])
    plan = _preflight(r, source_root, main_root, control_root, environ, now)
    source72_parent(plan.root)
    need(pin(H.read(plan.root / (PREFIX+'policy.PROPOSAL.json'))) == POLICY,
         'UNCHANGED_SEPARATELY_REVIEWED_HOSTED_POLICY')
    need(H.read(plan.root/(PREFIX+'inputs.py'), 128*1024)
         == H.read(plan.main/(PREFIX+'inputs.py'), 128*1024), 'SAME_REVIEWED_MAIN_AND_SOURCE_INPUT_VALIDATOR')
    plan.input_mount = observed
    return plan


H.request, H.program, H.preflight = request, program, preflight
H.retained_input_mount = retained_input_mount
fixed_tool, main = H.fixed_tool, H.main

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('HOLD_BANKSTOWN_QT3_HOSTED: '+type(error).__name__, file=sys.stderr)
        raise SystemExit(2)
