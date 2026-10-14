"""Concrete standalone Root-reviewed hosted ARM pair lane; import starts no actor."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

PREFIX = 'scripts/ci/native-pair-lane/'
BASE_SOURCE = '0744f413f47c82e4a5de16e4a16dba0962747483'
BASE_DATA = 'ea1db6b5277d755630568a7fd19f484b0bccacbe'
RECIPE_SHA = 'd44d749724d64c85f363392143cee05fa54b1d057a964aa86793adbac5826753'
RETAINED = []


def need(ok, code):
    if not ok: raise ValueError(code)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def environment():
    # No secret, arbitrary Docker context, Python loader or private Root-plan
    # environment is inherited by any worker/CLI child.
    out = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
           'HOME': '/home/runner', 'PYTHONDONTWRITEBYTECODE': '1'}
    for name in ('GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_WORKFLOW_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        out[name] = os.environ[name]
    return out


class Observer:
    def __init__(self, sources, selection): self.sources, self.selection = sources, selection
    def capture(self, kind):
        need(kind in ('source', 'cleanup'), 'lane-observer-role')
        cleanup = kind == 'cleanup'
        self.sources.verify(cleanup=cleanup); self.selection.verify(cleanup=cleanup)
        return True


def directory(path, guard, slots, *, create=False, mode=0o700):
    path = str(path)
    if create: guard.call(os.mkdir, path, mode)
    before = guard.call(os.lstat, path)
    uid, gid = guard.call(os.getuid), guard.call(os.getgid)
    need(stat.S_ISDIR(before.st_mode) and before.st_uid == uid and before.st_gid == gid and
         stat.S_IMODE(before.st_mode) == mode, 'lane-private-root')
    slot = {'fd': None, 'path': path, 'attempted': True}; slots.append(slot)
    guard.check(); slot['fd'] = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC); guard.check()
    held = guard.call(os.fstat, slot['fd'])
    ident = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_uid, x.st_gid)
    need(ident(before) == ident(held), 'lane-root-open-drift')
    return (path, slot['fd'], ident(held))


def write_private(path, raw, guard, slots):
    need(type(raw) is bytes and len(raw) <= 1024**2, 'lane-private-packet-bound')
    slot = {'fd': None, 'path': str(path), 'attempted': True}; slots.append(slot)
    guard.check(); slot['fd'] = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600); guard.check()
    position = 0
    while position < len(raw):
        count = guard.call(os.write, slot['fd'], raw[position:position + 65536])
        need(type(count) is int and count > 0, 'lane-packet-short-write'); position += count
    guard.call(os.fsync, slot['fd'])
    need(guard.call(os.fstat, slot['fd']).st_size == len(raw), 'lane-packet-size')


def close_slots(slots, guard):
    errors = []; first = None
    for slot in reversed(slots):
        if slot['fd'] is None:
            if slot.get('attempted') and not slot.get('closed'):
                error = ValueError('RootFDOutcomeUnknown')
                primary = guard.record_failure(error, cleanup=True)
                if first is None: first = primary
                errors.append('RootFDOutcomeUnknown')
            continue
        try:
            guard.check(cleanup=True); fd = slot['fd']; slot['fd'] = None; slot['retiring_fd'] = fd
            os.close(fd); slot['closed'] = True; guard.check(cleanup=True)
        except BaseException as error:
            primary = guard.record_failure(error, cleanup=True)
            if first is None: first = primary
            errors.append(type(error).__name__)
    if first is not None: raise first
    return errors


def run(source_root, rows, registration, original_entry, nonce, scratch, *, clock_type, source_type):
    """Called by the registered workflow's pinned entry, never dispatch inputs.

    Source policy grants come from concrete current native selection, whose
    exact Source is reviewed/adopted by Root before registering this workflow.
    """
    guard = clock_type(original_entry); sources = source_type(source_root, rows, guard)
    slots, tools = [], []; selection = None; candidate = None; first = None
    retained = {'sources': sources, 'slots': slots, 'tools': tools, 'guard': guard}; RETAINED.append(retained)
    try:
        need(registration['base_source_commit'] == BASE_SOURCE and registration['data_commit'] == BASE_DATA,
             'lane-isolated-original-base')
        env = environment()
        need(env['GITHUB_REPOSITORY'] == 'Gabriel-Kahen/cachy-asahi' and
             env['GITHUB_SHA'] == env['GITHUB_WORKFLOW_SHA'] == registration['source_commit'], 'lane-registered-job')
        stem = '_root_pair_' + nonce + '_'
        load = lambda name, role: sources.module(PREFIX + name, stem + role)
        driver = load('worker/pair_driver.py', 'driver')
        contract = load('worker/pair_contract.py', 'contract')
        maker = load('worker/prepare_packet.py', 'packet')
        process = load('mechanics/process_owner_recovery.py', 'process')
        intake_module = load('cache_intake.py', 'intake')
        native = load('native_selection.py', 'native')
        guardian = load('pair_guardian.py', 'guardian')
        # Root explicitly admits the selected trusted worker's finite child
        # graph. This Source decision is neither a dispatch-input flag nor a
        # self-issued value read from the private packet.
        trusted_worker_children_stay_owned = True
        with driver.controls(guard.J):
            work_parent = directory('/home/runner/cpw-' + nonce, guard, slots, create=True)
            cache = Path('/home/runner/cpc-' + nonce); evidence = Path('/home/runner/cpe-' + nonce)
            directory(cache, guard, slots, create=True); directory(evidence, guard, slots, create=True)
            donor = PREFIX + 'donor/'
            intake = intake_module.CacheIntake(sources.file(donor + 'native_arm.py'),
                sources.file(donor + 'controller.py'), sources.file(donor + 'packet.lock.json'),
                sources.file('data/scripts/ci/inputs.lock.json'), work_end=guard.E, check=guard.check)
            retained['intake'] = intake
            intake.seed(cache)
            acquisition = intake.acquire(cache, evidence)
            for name in list(os.environ):
                if name.startswith('CACHY_OLD_FOUR_'): os.environ.pop(name, None)
            recipes_raw = sources.file(PREFIX + 'worker/recipe_rows.json')
            need(hashlib.sha256(recipes_raw).hexdigest() == RECIPE_SHA, 'lane-recipe19-manifest')
            recipes = json.loads(recipes_raw)
            for name, expected in recipes.items():
                sources.file(name); need(rows[name] == expected, 'lane-registered-exact-recipe19')
            base = {'source_commit': env['GITHUB_SHA'], 'workflow_commit': env['GITHUB_WORKFLOW_SHA'],
                'run_id': env['GITHUB_RUN_ID'], 'run_attempt': env['GITHUB_RUN_ATTEMPT'], 'nonce': nonce,
                'original_entry': guard.start, 'workflow_end': guard.J, 'uid': 0, 'gid': 0,
                'source_root': str(source_root), 'source_rows': recipes,
                'work_root': work_parent[0] + '/work', 'cache': str(cache),
                'inputs_path': str(Path(source_root) / 'data/scripts/ci/inputs.lock.json'),
                'inventory_path': str(Path(source_root) / 'data/scripts/port/refreshed-desktop/proposed-builder-inventory.lock'),
                'tools': {}, 'tool_closure': {}, 'daemon_id': '', 'socket_identity': [],
                'mechanics': {name: {'path': str(Path(source_root) / PREFIX / 'mechanics' / filename),
                    'sha256': rows[PREFIX + 'mechanics/' + filename]['sha256']} for name, filename in (
                    ('process_owner', 'process_owner_recovery.py'), ('container_owner', 'container_owner.py'),
                    ('custody', 'custody_recovery.py'), ('input_audit', 'input_audit_successor.py'))}}
            disabled = {'execution_granted': False, 'dependencies': {}, 'interpreter': {}, 'stdlib': {},
                        'mapping_grant': {}, 'checker_root': '/home/runner'}
            packet = maker.make_packet(base, disabled, sources=sources)
            import math, hashlib as hashlib_module, re, dataclasses, ctypes, json as json_module
            packet, selection = native.prepare_current_packet(packet, guard=guard, process_owner=process,
                stdlib_modules=dict(math=math, hashlib=hashlib_module, re=re, dataclasses=dataclasses, ctypes=ctypes, json=json_module),
                ctypes_module=ctypes)
            need(type(selection) is native.HeldSelection and packet['pins']['integration']['native'] == selection.native,
                 'lane-Source-issued-native-operation')
            retained['selection'] = selection; guard.execution_granted = True
            value, pins = packet['value'], packet['pins']
            contract.selection(value, env, guard.check(), recipes)
            checker = Path(selection.native['checker_root']); mode = stat.S_IMODE(guard.call(os.lstat, checker).st_mode)
            checker_node = directory(checker, guard, slots, mode=mode)
            python_tool = guard.call(process.VerifiedTool.__new__, process.VerifiedTool); tools.append(python_tool)
            guard.call(python_tool.__init__, selection.native['interpreter']['path'],
                       selection.native['interpreter']['sha256'], end=guard.E)
            docker_tool = guard.call(process.VerifiedTool.__new__, process.VerifiedTool); tools.append(docker_tool)
            guard.call(docker_tool.__init__, '/usr/bin/docker', value['tools']['docker'], end=guard.E)
            packet_raw = json.dumps(packet, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            packet_path = Path(scratch) / 'pair-packet.json'; write_private(packet_path, packet_raw, guard, slots)
            expected_job = contract.job_binding(value, RECIPE_SHA)
            owner_binding = digest({'job': expected_job, 'contract': pins['contract']['sha256'],
                'entry': driver.ENTRY_SHA, 'integration': {k: v for k, v in pins['integration'].items() if k != 'native'}})
            worker_name = PREFIX + 'worker/worker_entry.py'; sources.file(worker_name); node = sources.nodes[worker_name]
            spec = dict(value=value, pins=pins, expected_job=expected_job, native_binding=selection.observation['job'],
                native_selection={'library': dict(native.LIBRARY), 'dependencies': selection.native['dependencies'],
                    'interpreter': selection.native['interpreter'], 'stdlib_binding': selection.observation['job']['stdlib_binding']},
                worker_path=str(node['path']), worker_sha=rows[worker_name]['sha256'],
                worker_node=(str(node['path']), node['fd'], node['identity']), packet_path=str(packet_path),
                packet_sha=hashlib.sha256(packet_raw).hexdigest(), driver_path=str(Path(source_root) / PREFIX / 'worker/pair_driver.py'),
                driver_sha=rows[PREFIX + 'worker/pair_driver.py']['sha256'], cwd=work_parent[0],
                held_roots=[checker_node], work_parent_node=work_parent, owner_source_sha256=owner_binding,
                trusted_worker_children_stay_owned=trusted_worker_children_stay_owned)
            def docker_call(args, end):
                guard.check(cleanup=True); sources.verify(cleanup=True)
                result = process.run(('/usr/bin/docker', '--host=unix:///run/docker.sock', *args), env, work_parent[0],
                    tool=docker_tool, work_end=min(end, guard.J - 180), cleanup_end=min(end, guard.recovery_end), limit=1024**2)
                guard.check(cleanup=True); need(result.code == 0, 'lane-readonly-Docker-observation'); return result.stdout
            stored = []
            intake.verify(); sources.verify(); selection.verify()
            guardian.launch(spec, process_owner=process, python_tool=python_tool, contract=contract, authority=guard,
                observer=Observer(sources, selection), docker_call=docker_call, environment=env, publish=stored.append)
            need(len(stored) == 1 and stored[0]['status'] == 'PRIVATE_ROOT_PUBLICATION_PENDING' and
                 stored[0]['publication_allowed'] is False, 'lane-private-candidate')
            candidate = stored[0]
            candidate['registered_source'] = registration
            candidate['current_native_observation'] = selection.observation
            candidate['transport'] = acquisition
            selection.close(); selection = None
            for tool in reversed(tools): guard.call(tool.close, cleanup=True)
            tools.clear()
            need(not close_slots(slots, guard), 'lane-Root-FD-retirement')
            need(not sources.close(), 'lane-Source-FD-retirement')
        # Control restoration has completed. Only this final Source operation
        # promotes the enclosing pair record; no composed/hardware claim.
        guard.check(publication=True)
        candidate = dict(candidate, status='PAIR_CHECKED_ROOT_JOB_COMPLETION_REQUIRED', publication_allowed=False,
                         worker_source={'packet_sha256': spec['packet_sha'], 'driver_sha256': spec['driver_sha'],
                                        'worker_sha256': spec['worker_sha']},
                         scope='standalone-original501-topmem-fish-pairs', composed_acceptance='NOT RUN')
        raw = json.dumps(candidate, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        need(len(raw) <= 1024**2, 'lane-public-record-cap')
        count = guard.call(sys.stdout.buffer.write, raw, publication=True)
        need(count == len(raw), 'lane-public-short-write'); guard.call(sys.stdout.buffer.flush, publication=True)
        RETAINED.remove(retained); return candidate
    except BaseException as error:
        first = guard.record_failure(error)
        for name in list(os.environ):
            if name.startswith('CACHY_OLD_FOUR_'): os.environ.pop(name, None)
        # Failed resources remain strongly attached; no cached success survives.
        retained['candidate'] = candidate
        try: first.retained_registered_pair_lane = retained
        except BaseException: pass
        raise first
