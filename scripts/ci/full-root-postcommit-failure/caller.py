#!/usr/bin/env python3
"""Separate controlled-failure/disposal hook; never normal upgrade acceptance."""
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
DRIVER = 'scripts/ci/full-root-postcommit-failure/run.py'
CASE = 'postcommit-exit87'


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
        'stage_seconds', 'verify_seconds', 'copy_seconds', 'driver_seconds', 'release', 'failure'}, 'exact caller configuration required')
    need(value['schema_version'] == 1 and value['purpose'] == 'actual587-postcommit-failure-disposal-test',
         'explicit initial587 upgrade selection required')
    for key, ceiling in (('stage_seconds', 900), ('verify_seconds', 600), ('copy_seconds', 900), ('driver_seconds', 2400)):
        need(type(value[key]) is int and 0 < value[key] <= ceiling, 'finite caller time budget required')
    need(value['failure'] == dict(case=CASE, exit_code=87, worker_seconds=1200, verify_seconds=600),
         'one exact controlled failure required')
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
    need(value['scale']['limits']['window_bytes']==16777216 and value['scale']['limits']['decoded_bytes']==16777216,
         'held16MiB XZ/decoder budgets required')
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
        seconds=config['driver_seconds'], failure_case=CASE, lane_config=CONFIG,
        lane_config_sha256=digest(CONFIG), **{k: v for k, v in config['release'].items() if k != 'supported_models'})
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


def run(pacman, plan, expected, source, work, composition):
    result = dict(status='FAIL', phase='selection', committed_transactions=0,
                  commit_started=False, packages_committed=False, checkpoint_changed=False,
                  scope='controlled-full587-postcommit-failure-disposal', whole_container_root=False,
                  hardware='NOT RUN', apple_acceptance='NOT ESTABLISHED', outer_cleanup='OWNER REQUIRED')
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
        control = VOLUME / 'failure-control'
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
        result.update(phase='controlled-child-failure-and-disposal', commit_started='UNKNOWN',
                      packages_committed='UNKNOWN', checkpoint_changed='UNKNOWN')
        row = supervision.run(driver_command(config, control, stage, signer), env=env, cwd=str(CODE),
                              timeout=config['driver_seconds'], output_limit=1024**2)
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
        need(driver.get('status') == 'PASS' and driver.get('case') == CASE and type(driver.get('failure_cases')) is int
             and driver.get('failure_cases') == 1 and type(driver.get('committed_transactions')) is int
             and driver.get('committed_transactions') == 1 and driver.get('original_source_preserved') is True
             and driver.get('commit_started') is True and driver.get('packages_committed') is True and driver.get('checkpoint_changed') is False
             and all(driver.get(key) is True for key in ('after587_database_verified','postcommit_payload_verified',
                 'postcommit_preservation_verified')) and driver.get('copy_cleanup') == 'PASS-owned-workspace-removed', 'one exact committed-child interruption and disposed copy required')
        need(result['persistent_source_after']['status'] == 'PASS', 'persistent outer source preservation refused')
        result.update(status='PASS', phase='completed', committed_transactions=1, failure_cases=1, case=CASE,
                      persistent_source_preserved=True, recovery='OWNED-COPY-DISPOSAL-VERIFIED',
                      transaction_acceptance='NOT ESTABLISHED', normal_upgrade_acceptance='NOT ESTABLISHED')
    except BaseException as error:
        result.update(status='FAIL', error_type=type(error).__name__, error=str(error)[:512])
    return result
