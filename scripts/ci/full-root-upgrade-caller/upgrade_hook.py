#!/usr/bin/env python3
"""One future native upgrade in a complete copy of the retained persistent root."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

BEFORE = '2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
AFTER = 'dbfe042f77bf61ce8e15a63c53391bcc4f04b94f18e99eeffdfdf85e68aa26ac'
CODE = Path('/upgrade-code')
CONFIG = Path('/upgrade-config.json')
PAIR = Path('/upgrade-pair')
SIGNING = Path('/upgrade-signing')
VOLUME = Path('/measurement')
DRIVER = 'scripts/ci/full-root-upgrade/root_upgrade.py'


def need(ok, reason):
    if not ok: raise ValueError(reason)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ordinary(path, limit=1024**2):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute source required')
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, 'bounded ordinary source required')
    return path


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ordinary(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def configuration(path=CONFIG, code=CODE):
    value = json.loads(ordinary(path).read_bytes())
    need(type(value) is dict and set(value) == {
        'schema_version', 'purpose', 'code_pins', 'external_pins', 'scale',
        'stage_seconds', 'verify_seconds', 'copy_seconds', 'driver_seconds', 'release'}, 'exact caller configuration required')
    need(value['schema_version'] == 1 and value['purpose'] == 'actual587-persistent-root-setup4-test',
         'explicit initial587 upgrade selection required')
    for key, ceiling in (('stage_seconds', 900), ('verify_seconds', 600), ('copy_seconds', 900), ('driver_seconds', 2400)):
        need(type(value[key]) is int and 0 < value[key] <= ceiling, 'finite caller time budget required')
    pins = value['code_pins']
    need(type(pins) is dict and DRIVER in pins and
         'scripts/ci/full-root-upgrade/construct_repository.py' in pins and
         all('scripts/update/' + name + '.py' in pins for name in (
             'aux_copy', 'aux_initialize', 'linked_runtime', 'root_link_selection', 'supervision')),
         'complete explicit code closure required')
    for relative, expected in pins.items():
        need(type(relative) is str and not Path(relative).is_absolute() and '..' not in Path(relative).parts
             and re.fullmatch('[0-9a-f]{64}', expected), 'code source pin shape')
        need(digest(ordinary(code / relative)) == expected, 'selected code bytes changed: ' + relative)
    external = value['external_pins']
    need(type(external) is dict and set(external) == {'/setup4.py', '/footprint.py', '/persistent_scope.py'},
         'exact external helper closure required')
    for name, expected in external.items():
        need(re.fullmatch('[0-9a-f]{64}', expected) and digest(ordinary(name)) == expected,
             'selected external helper bytes changed')
    need(value['scale']['before_lock_sha256'] == BEFORE and value['scale']['after_lock_sha256'] == AFTER
         and value['scale']['platform_mode'] == 'generic-development', 'exact updater-v2/setup4 scale required')
    release = value['release']
    need(type(release) is dict and set(release) == {
        'release_id', 'repo_name', 'namespace', 'sequence', 'issued_utc', 'expires_utc', 'supported_models'}
         and release['supported_models'] == ['m2-air-13', 'm2-air-15'], 'explicit TEST release declarations required')
    return value


def selected_links(code):
    # The frozen literal list is source policy; runtime observations cannot grant it.
    links = load('root_link_selection', code / 'scripts/update/root_link_selection.py')
    need(len(links.CHAIN_PATHS) == 87 and len(links.LINK_NODES) >= 87,
         'Root must freeze the complete actual87 literal link selection before dispatch')


def quiesce(plan, expected, source, composition, roots):
    """Retain the existing keyring guards, with initial587 selection kept explicit."""
    need(len(expected) == 587 and expected.get('cachy-asahi-setup') == '0.1.0-3'
         and expected.get('cachy-asahi-update') == '4.4.2-2', 'initial587 keyring checkpoint required')
    helper = load('initial587_keyring_helper', Path('/setup4.py'))
    measurement = load('initial587_keyring_reads', Path('/footprint.py'))
    core, _provider = composition.lifecycle_helpers(plan['setup4'], source)
    limits = roots.Limits(deadline=time.monotonic() + 120, max_nodes=20000,
                          max_bytes=256 * 1024**2, max_file_bytes=32 * 1024**2)
    helper._keyring_guard(roots, limits)
    need(composition.inventory() == expected, 'initial inventory changed before quiescence')
    before = helper._persistent_state(roots, measurement, limits)
    fingerprints = helper._keyring_fingerprints(core, plan['signer_fingerprint'])
    present = helper._agent_sockets()
    if present:
        helper._bounded_keyring(core, ['/usr/bin/gpgconf', '--homedir', str(helper.KEYRING_HOME), '--kill', 'gpg-agent'])
    need(not helper._agent_sockets(), 'owned initial keyring agent endpoints remain')
    need(helper._keyring_fingerprints(core, plan['signer_fingerprint']) == fingerprints
         and helper._persistent_state(roots, measurement, limits) == before
         and composition.inventory() == expected, 'persistent initial keyring/database changed')
    helper._keyring_guard(roots, limits)
    need(not helper._agent_sockets(), 'initial keyring endpoints reappeared')
    return {'status': 'PASS-absence-verified', 'initial_endpoints': len(present),
            'persistent_keyring_config_preserved': True, 'package_database_inventory_preserved': True}


def driver_command(config, control, stage, signer, code=CODE, pair=PAIR, signing=SIGNING):
    package = pair / 'build-1/artifacts/cachy-asahi-setup-0.1.0-4-any.pkg.tar.xz'
    options = dict(source_root=code, runtime=code / 'scripts/update/linked_runtime.py',
        runtime_sha256=config['code_pins']['scripts/update/linked_runtime.py'],
        initializer=code / 'scripts/update/aux_initialize.py',
        initializer_sha256=config['code_pins']['scripts/update/aux_initialize.py'],
        comparator=code / 'scripts/ci/full-development-composition/audio_aux.py',
        source=stage, workspace=control / 'copy', data=control / 'data',
        scale=control / 'scale.json', scale_sha256=digest(control / 'scale.json'),
        setup4_pair=pair, package=package, provenance=pair / 'build-1/provenance.json',
        gpg_home=signing, signer=signer, copy_seconds=config['copy_seconds'],
        seconds=config['driver_seconds'], **{k: v for k, v in config['release'].items() if k != 'supported_models'})
    # The hook owns supervision. Direct worker avoids a second nested supervisor
    # and uses the driver's existing explicit aux/copy/initializer connection.
    argv = [sys.executable, '-I', '-B', str(code / DRIVER), '--worker', '--auxiliary-runtime']
    for key, value in options.items(): argv.extend(('--' + key.replace('_', '-'), str(value)))
    return argv + ['--supported-models', *config['release']['supported_models']]


def driver_result(row):
    unknown = dict(status='FAIL', phase='driver-worker', commit_started='UNKNOWN',
                   packages_committed='UNKNOWN', checkpoint_changed='UNKNOWN')
    if row.get('termination') is not None or row.get('direct_child_reaped') is not True or row.get('returncode') not in (0, 1):
        return unknown
    try:
        value = json.loads(row['stdout'])
        need(type(value) is dict and value.get('status') in ('PASS', 'FAIL') and
             all(k in value for k in ('commit_started', 'packages_committed', 'checkpoint_changed')),
             'complete driver commit truth required')
        need((row['returncode'] == 0) == (value['status'] == 'PASS'), 'driver exit/status disagreement')
        return value
    except (ValueError, TypeError, KeyError): return unknown



_INITIALIZER_PHASES = ('WORKER_OBSERVE', 'WORKER_CHECKPOINT', 'WORKER_HELPER_PIN', 'WORKER_EXEC', 'PARENT_SOURCE_BEFORE', 'PARENT_ROOT_BEFORE', 'PARENT_ROOT_AFTER', 'PARENT_SOURCE_AFTER')
_INITIALIZER_PROFILE = 'I16K_STATX_V1'
_INITIALIZER_PREFIX = b'UPDATER607_INITIALIZER_TELEMETRY '
_INITIALIZER_MAX = 2**63-1

def _initializer_valid(value, nonce=None):
    if type(value) is not dict or set(value) != {'v','profile','nonce','lane','seq','phase','state','elapsed_ns','remaining_ns','ops','saturated'}:return False
    if type(value['v'])is not int or value['v']!=1 or value['profile']!=_INITIALIZER_PROFILE:return False
    n=value['nonce']
    if type(n)is not str or len(n)!=32 or any(c not in '0123456789abcdef'for c in n)or(nonce is not None and n!=nonce):return False
    lane=value['lane']
    if lane not in ('WORKER','PARENT')or type(value['seq'])is not int or not 0<=value['seq']<(6 if lane=='WORKER'else 8):return False
    if value['phase']not in _INITIALIZER_PHASES or not value['phase'].startswith(lane+'_')or value['state']not in ('STARTED','PROGRESS','RETURNED','REFUSED'):return False
    if type(value['elapsed_ns'])is not int or not 0<=value['elapsed_ns']<=_INITIALIZER_MAX:return False
    r=value['remaining_ns']
    if r is not None and(type(r)is not int or not -_INITIALIZER_MAX<=r<=_INITIALIZER_MAX):return False
    if type(value['ops'])is not list or len(value['ops'])!=8 or any(type(x)is not int or not 0<=x<=_INITIALIZER_MAX for x in value['ops'])or type(value['saturated'])is not bool:return False
    return len(_INITIALIZER_PREFIX)+len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())+1<=768

def _initializer_capture(raw, nonce, complete=True):
    if type(raw)is not bytes or len(raw)>1024**2:return None,0
    lines=[line[len(_INITIALIZER_PREFIX):]for line in raw.splitlines()if line.startswith(_INITIALIZER_PREFIX)]
    if not 1<=len(lines)<=(6 if complete else 128):return None,0
    records=[]
    try:
        for i,line in enumerate(lines):
            if len(line)+len(_INITIALIZER_PREFIX)+1>768:return None,0
            def pairs(items):
                value={}
                for key,item in items:
                    if key in value:raise ValueError('duplicate initializer telemetry key')
                    value[key]=item
                return value
            value=json.loads(line,object_pairs_hook=pairs)
            if not _initializer_valid(value,nonce)or value['lane']!='WORKER'or(complete and value['seq']!=i):return None,0
            if complete and records and(value['elapsed_ns']<records[-1]['elapsed_ns']or any(a<b for a,b in zip(value['ops'],records[-1]['ops']))):return None,0
            records.append(value)
    except(ValueError,TypeError,KeyError,UnicodeError,RecursionError):return None,0
    return records[-1],len(records)

def _initializer_emit(value):
    if not _initializer_valid(value,os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')):return
    raw=_INITIALIZER_PREFIX+json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
    try:os.write(2,raw)
    except OSError as error:
        # Ordinary diagnostic IO loss is not an acceptance predicate. The held
        # phase alarm raises TimeoutError without errno and must still propagate.
        if error.errno is None:raise

def _initializer_wrapper_valid(value,nonce):
    if type(value)is not dict or set(value)!={'v','profile','history','saturated','worker'}or type(value['v'])is not int or value['v']!=1 or value['profile']!=_INITIALIZER_PROFILE or type(value['saturated'])is not bool:return False
    history=value['history']
    if type(history)is not list or len(history)>8:return False
    for i,record in enumerate(history):
        if not _initializer_valid(record,nonce)or record['lane']!='PARENT'or record['seq']!=i:return False
        if i and(record['elapsed_ns']<history[i-1]['elapsed_ns']or any(a<b for a,b in zip(record['ops'],history[i-1]['ops']))):return False
    worker=value['worker']
    if worker is not None:
        if type(worker)is not dict or set(worker)!={'last','records','stderr','returncode','termination','direct_child_reaped','capture_scope'}or worker['capture_scope']!='ORIGINAL_SUPERVISOR_CAPTURE_MAY_BE_PARTIAL':return False
        if type(worker['records'])is not int or not 0<=worker['records']<=6 or type(worker['direct_child_reaped'])is not bool or worker['termination']not in(None,'timeout','output-limit','interrupted'):return False
        if worker['returncode']is not None and(type(worker['returncode'])is not int or not -255<=worker['returncode']<=255):return False
        last=worker['last']
        if worker['records']==0:
            if last is not None:return False
        elif not _initializer_valid(last,nonce)or last['lane']!='WORKER'or last['seq']!=worker['records']-1:return False
        pin=worker['stderr']
        if type(pin)is not dict or set(pin)!={'bytes','sha256'}or type(pin['bytes'])is not int or not 0<=pin['bytes']<=65536 or type(pin['sha256'])is not str or len(pin['sha256'])!=64 or any(c not in '0123456789abcdef'for c in pin['sha256']):return False
    return len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())<=8192

def _initializer_final_emit(result, fallback):
    value=fallback
    driver=result.get('driver')
    if type(driver)is dict:
        initialization=driver.get('initialization')
        if type(initialization)is dict:
            telemetry=initialization.get('initializer_telemetry')
            if _initializer_wrapper_valid(telemetry,os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')):
                worker=telemetry.get('worker')
                if type(worker)is dict and _initializer_valid(worker.get('last'),os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')):value=worker['last']
    _initializer_emit(value)


def run(pacman, plan, expected, source, work, composition):
    result = dict(status='FAIL', phase='selection', committed_transactions=0,
                  commit_started=False, packages_committed=False, checkpoint_changed=False,
                  scope='complete-persistent-payload-in-disposable-container', whole_container_root=False,
                  hardware='NOT RUN', apple_acceptance='NOT ESTABLISHED', outer_cleanup='OWNER REQUIRED')
    _initializer_last=None
    try:
        composition.guard()
        need(plan.get('full_root_upgrade') is True and not plan.get('measurement_only')
             and not ({'audio', 'lifecycle', 'updater_v2'} & set(plan)), 'exclusive initial587 full-root route required')
        need(len(expected) == 587 and hashlib.sha256(''.join(
            f'{name} {version}\n' for name, version in sorted(expected.items())).encode()).hexdigest() == BEFORE,
            'exact initial signed587/updater-v2 inventory required')
        config = configuration()
        sys.path.insert(0, str(CODE / 'scripts/update'))
        selected_links(CODE)
        roots = load('caller_stage_roots', CODE / 'scripts/update/full_root.py')
        supervision = load('caller_upgrade_supervision', CODE / 'scripts/update/supervision.py')
        scope = load('caller_persistent_scope', Path('/persistent_scope.py'))
        need(VOLUME.is_dir() and not VOLUME.is_symlink() and os.stat(VOLUME).st_uid == os.geteuid()
             and not os.stat(VOLUME).st_mode & 0o022, 'owned private volume required')
        control = VOLUME / 'upgrade-control'
        control.mkdir(mode=0o700)
        (control / 'data').mkdir(mode=0o700)
        (control / 'scale.json').write_text(json.dumps(config['scale'], sort_keys=True) + '\n')
        load('caller_scale_validation', CODE / 'scripts/update/scale_update.py').configuration(
            control / 'scale.json', digest(control / 'scale.json'))
        result['phase'] = 'initial-keyring-quiescence'
        result['keyring_quiescence'] = quiesce(plan, expected, source, composition, roots)
        need(composition.inventory() == expected, 'initial inventory changed before staging')
        limits = config['scale']['limits']
        stage_limits = roots.Limits(deadline=time.monotonic() + config['stage_seconds'],
            max_nodes=limits['root_nodes'], max_bytes=limits['root_bytes'],
            max_file_bytes=limits['file_bytes'], max_package_files=limits['package_files'])
        result['phase'] = 'complete-persistent-source'
        stage = control / 'persistent-source'
        result['persistent_source'] = scope.materialize(Path('/'), stage, CODE, stage_limits)
        need(result['persistent_source']['status'] == 'PASS', 'persistent source coverage refused')
        need(composition.inventory() == expected, 'outer inventory changed during staging')
        signer = plan['test_signer_fingerprint']
        need(re.fullmatch('[0-9A-F]{40}', signer) and SIGNING.is_dir() and not SIGNING.is_symlink(),
             'existing external ephemeral TEST signer required')
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'HOME': str(control),
               'TMPDIR': str(control), 'PYTHONDONTWRITEBYTECODE': '1',
               'CACHY_ASAHI_BOUND_UPDATE': os.environ['CACHY_ASAHI_BOUND_UPDATE']}
        need(re.fullmatch('[0-9a-f]{32}', env['CACHY_ASAHI_BOUND_UPDATE']), 'explicit bound-update nonce required')
        result.update(phase='single-copied-root-upgrade', commit_started='UNKNOWN',
                      packages_committed='UNKNOWN', checkpoint_changed='UNKNOWN')
        row = supervision.run(driver_command(config, control, stage, signer), env=env, cwd=str(CODE),
                              timeout=config['driver_seconds'], output_limit=1024**2)
        _initializer_last,_=_initializer_capture(row.get('stderr'),os.environ.get('CACHY_ASAHI_BOUND_UPDATE',''),complete=False)
        _initializer_emit(_initializer_last)
        driver = driver_result(row)
        result['driver'] = driver
        result['worker'] = {k: row[k] for k in ('returncode', 'termination', 'direct_child_reaped', 'group_kill_sent')}
        for key in ('commit_started', 'packages_committed', 'checkpoint_changed'):
            result[key] = driver.get(key, 'UNKNOWN')
        result['committed_transactions'] = driver.get('committed_transactions', 'UNKNOWN')
        need(composition.inventory() == expected, 'outer source inventory changed during copied upgrade')
        result['outer_source_inventory_preserved'] = True
        # Re-observe complete persistent bytes/metadata and all ownership after the
        # driver; the stage must still match its original source, including caches.
        verify_limits = roots.Limits(deadline=time.monotonic() + config['verify_seconds'],
            max_nodes=limits['root_nodes'], max_bytes=limits['root_bytes'],
            max_file_bytes=limits['file_bytes'], max_package_files=limits['package_files'])
        result['persistent_source_after'] = scope.verify(Path('/'), stage, CODE, verify_limits)
        need(result['persistent_source_after']['source_manifest_sha256'] ==
             result['persistent_source']['source_manifest_sha256'], 'persistent baseline changed after staging')
        need(driver.get('status') == 'PASS' and driver.get('committed_transactions') == 1
             and driver.get('copy_cleanup') == 'PASS-owned-workspace-removed', 'one committed disposed-copy upgrade required')
        need(result['persistent_source_after']['status'] == 'PASS', 'persistent outer source preservation refused')
        result.update(status='PASS', phase='completed', committed_transactions=1,
                      persistent_source_preserved=True, transaction_acceptance='GENERIC SOFTWARE ONLY')
    except BaseException as error:
        result.update(status='FAIL', error_type=type(error).__name__, error=str(error)[:512])
    finally:
        _initializer_final_emit(result,_initializer_last)
    return result
