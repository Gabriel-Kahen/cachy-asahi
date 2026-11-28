"""Root-selected dual-source launcher for the repository-svg composition."""

import hashlib
import math
import os
from pathlib import Path
import re
import signal
import sys
import time
import types
import urllib.request

REPOSITORY = 'Gabriel-Kahen/cachy-asahi'
REMOTE = 'https://github.com/' + REPOSITORY + '.git'
CODE_PATHS = {
    'launcher': '.github/bootstrap/development-launcher.py',
    'legacy_bootstrap': '.github/bootstrap/development-bootstrap.py',
    'bootstrap': '.github/bootstrap/development-bootstrap-v3.py',
    'issuer': '.github/bootstrap/development-clock-issuer.py',
}
LEGACY_LAUNCHER_SHA = '9628d60dcb203120604b32bf2eebc0daaab8f80079173c559a1aa783e6a6b8a3'
LEGACY_BOOTSTRAP_SHA = '507e5ac1cecbb1a82d38f2bdee077d24cc73e69b4f9f4f8ae1cbbaab05ee92d4'
ISSUER_SHA = '9e3271b8cb21e7be1940c2aa9f17f84357d0a438ed45a19ad34ae226ec9d4581'
DATA_PATHS = {
    'selection_sha256': '.github/bootstrap/development-selection-v3.json',
    'peer_receipt_sha256': '.github/bootstrap/development-source-peer-v3.json',
    'original_source_sha256': '.github/bootstrap/development-original-source-v3.json',
}
PIN_KEYS = {*DATA_PATHS, 'source_rows_sha256', 'source_commit', 'cli_sha256'}
PLAN_KEYS = {'root_pins', 'data_commit', 'composition', 'git_sha256', 'development_sha256',
             'bootstrap_v3_sha256'}
COMPOSITION, LIVE_ROWS = 'repository-svg', 259
PACKET_PATH = 'scripts/ci/development/packet-dual-source.lock.json'
METADATA = {name: 'scripts/ci/' + name + '.lock.json' for name in ('inputs', 'recipes', 'integration')}
CODE_LIMIT, DATA_LIMIT = 256 * 1024, 8 * 1024**2


class Refused(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def pin(value, width=64):
    return type(value) is str and re.fullmatch(f'[a-f0-9]{{{width}}}', value) is not None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def check(end):
    need(type(end) in (int, float) and math.isfinite(end) and 0 < time.monotonic() < end,
         'launcher-deadline')


def validate_plan(plan, environment):
    need(type(plan) is dict and set(plan) == PLAN_KEYS and plan['composition'] == COMPOSITION and
         pin(plan['data_commit'], 40) and
         all(pin(plan[key]) for key in ('git_sha256', 'development_sha256', 'bootstrap_v3_sha256')),
         'Root-launch-plan')
    pins = plan['root_pins']
    need(type(pins) is dict and set(pins) == PIN_KEYS and pin(pins['source_commit'], 40) and
         all(pin(pins[key]) for key in PIN_KEYS - {'source_commit'}) and
         plan['data_commit'] != pins['source_commit'], 'Root-launch-pins')
    need(type(environment) is dict and environment.get('GITHUB_REPOSITORY') == REPOSITORY and
         environment.get('GITHUB_SHA') == environment.get('GITHUB_WORKFLOW_SHA') == pins['source_commit'],
         'workflow-source')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Refused('redirect-refused')


def fetch(commit, path, expected, limit, end):
    need(pin(commit, 40) and path in {*CODE_PATHS.values(), *DATA_PATHS.values()} and pin(expected) and
         type(limit) is int and 0 < limit <= DATA_LIMIT, 'delivery-binding')
    check(end)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request('https://raw.githubusercontent.com/' + REPOSITORY + '/' + commit + '/' + path)
    with opener.open(request, timeout=max(0.001, end - time.monotonic())) as response:
        need(response.status == 200 and response.geturl() == request.full_url, 'delivery-origin')
        raw = bytearray()
        while True:
            check(end)
            part = response.read1(min(65536, limit + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
            need(len(raw) <= limit, 'delivery-byte-bound')
    check(end)
    need(digest(raw) == expected, 'delivery-pin')
    return bytes(raw)


def delivered(delivery, commit, path, expected, limit, end):
    check(end)
    raw = delivery(commit, path, expected, limit, end)
    check(end)
    need(type(raw) is bytes and 0 < len(raw) <= limit and digest(raw) == expected, 'delivery-pin')
    return raw


def load_legacy(plan, delivery, end):
    """Bound the initial dependency fetch before the retained launcher is available."""
    def expired(number, frame):
        raise Refused('launcher-deadline')

    need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'existing-timer-refused')
    previous = signal.signal(signal.SIGALRM, expired)
    try:
        check(end)
        signal.setitimer(signal.ITIMER_REAL, end - time.monotonic())
        raw = delivered(delivery, plan['root_pins']['source_commit'], CODE_PATHS['launcher'],
                        LEGACY_LAUNCHER_SHA, CODE_LIMIT, end)
        legacy = types.ModuleType('trusted_legacy_development_launcher')
        exec(compile(raw, '<Root-pinned-legacy-development-launcher>', 'exec'), legacy.__dict__)
        check(end)
        return legacy
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        finally:
            signal.signal(signal.SIGALRM, previous)


def checkout(legacy, old_bootstrap, prepared, plan, cutoff, runner):
    """Apply the retained checkout grammar to the v3 data-only path set."""
    workspace, owner = prepared['paths']['workspace'], prepared['workspace_owner']
    need(owner.path == workspace, 'workspace-owner-binding')
    owner.verify(cutoff, empty=True)
    tool = Path('/usr/bin/git')
    options = {'limit': 128 * 1024**2, 'owner': 0, 'mode': 0o755}
    raw, node, _ = legacy.read_bootstrap(old_bootstrap, tool, cutoff, **options)
    need(digest(raw) == plan['git_sha256'], 'git-pin')
    prefix = [str(tool), '-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null',
              '-c', 'core.fsmonitor=false', '-c', 'core.autocrlf=false', '-c', 'submodule.recurse=false',
              '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never', '-c', 'http.followRedirects=false']
    source, data = plan['root_pins']['source_commit'], plan['data_commit']
    scoped = prefix + ['-C', str(workspace)]
    transfer = scoped + ['fetch', '--quiet', '--depth=1', '--no-tags', '--no-recurse-submodules', '--', REMOTE]
    commands = (
        prefix + ['init', '--template=', '--', str(workspace)],
        transfer + [source],
        transfer + [data],
        scoped + ['diff', '--name-only', '--no-renames', source, data, '--'],
        scoped + ['checkout', '--quiet', '--detach', source, '--'],
        scoped + ['rev-parse', '--verify', 'HEAD'],
    )
    for index, command in enumerate(commands):
        check(cutoff)
        owner.verify(cutoff)
        raw, found, _ = legacy.read_bootstrap(old_bootstrap, tool, cutoff, **options)
        need(found == node and digest(raw) == plan['git_sha256'], 'git-identity-drift')
        code, reply = runner(command, legacy.git_environment(prepared), None, cutoff, workspace_owner=owner)
        owner.verify(cutoff)
        need(type(code) is int and code == 0, 'checkout-command-failed')
        if index == 3:
            names = reply.decode('ascii').splitlines()
            need(len(names) == len(DATA_PATHS) and set(names) == set(DATA_PATHS.values()), 'data-only-tree-required')
        if index == 5:
            need(reply.strip() == source.encode(), 'checkout-head')


def controller_argv(plan, paths, verified, bindings, entry):
    source, original = paths['workspace'], paths['original']
    need(original.is_absolute() and original == paths['bootstrap'] / 'historical-source' and
         '..' not in original.parts and
         all(not original.is_relative_to(paths[key]) and not paths[key].is_relative_to(original)
             for key in ('workspace', 'output', 'cache')), 'original-source-path')
    pins = verified['metadata_pins']
    need(verified['selected_rows_verified'] == LIVE_ROWS and
         verified['packet_sha256'] == plan['development_sha256'] and type(pins) is dict and
         set(pins) == set(METADATA.values()) and all(pin(value) for value in pins.values()),
         'development-packet-binding')
    argv = [sys.executable, '-E', '-s', '-B', str(source / 'scripts/ci/development/controller.py'),
            '--composition', COMPOSITION, '--development-sha256', plan['development_sha256'],
            '--controller-entry-monotonic', repr(entry), '--packet', str(source / PACKET_PATH),
            '--original-source-root', str(original), '--cache', str(paths['cache']), '--output', str(paths['output'])]
    for flag, name in METADATA.items():
        argv += ['--' + flag + '-sha256', pins[name]]
    for flag, prefix in (('clock', 'CLOCK'), ('execution-grant', 'EXECUTION_GRANT'), ('runtime-contract', 'RUNTIME_CONTRACT')):
        argv += ['--' + flag, bindings['DEVELOPMENT_' + prefix + '_PATH'],
                 '--' + flag + '-sha256', bindings['DEVELOPMENT_' + prefix + '_SHA256']]
    return argv


def bind_packet(old_bootstrap, raw, selection, verified, plan):
    need(digest(raw) == plan['development_sha256'], 'development-packet-pin')
    packet = old_bootstrap.decode(raw)
    selected = old_bootstrap.decode(selection)
    need(packet.get('schema_version') == 3 and packet.get('composition') == COMPOSITION and
         all(key in packet and packet[key] == selected.get(key)
             for key in ('source_files', 'metadata_pins', 'original_source')), 'development-packet-selection')
    original = packet['original_source']
    rows = packet.get('initial_source_files')
    need(type(original) is dict and pin(original.get('integration_lock_sha256')) and
         type(rows) is dict and all(type(rows.get(METADATA[name])) is dict and
                                    pin(rows[METADATA[name]].get('sha256')) for name in ('inputs', 'recipes')),
         'development-packet-invocation')
    pins = {METADATA['integration']: original['integration_lock_sha256'],
            **{METADATA[name]: rows[METADATA[name]]['sha256'] for name in ('inputs', 'recipes')}}
    need(verified['metadata_pins'] == pins, 'development-packet-invocation')


def _launch(legacy, modules, datasets, plan, environment, preparation_end, runner, owner):
    old_bootstrap, bootstrap, issuer = modules
    selection, peer, historical = datasets
    prepared = None
    first = None
    retirement = []
    try:
        with legacy.defer_controls():
            prepared = bootstrap.prepare(old_bootstrap, selection, peer, historical, plan['root_pins'],
                                         environment, preparation_deadline=preparation_end)
            prepared['workspace_owner'] = owner
        check(preparation_end)
        signal.setitimer(signal.ITIMER_REAL, 0)
        issuer_entry = time.monotonic()
        with legacy.defer_controls():
            bindings = issuer.issue(environment, ISSUER_SHA, prepared['execution_grant'], prepared['runtime_contract'])
        entry = time.monotonic()
        cutoff, workflow_end = legacy.clock(old_bootstrap, issuer, bindings, plan, environment, entry, issuer_entry + 10800)
        signal.setitimer(signal.ITIMER_REAL, cutoff - time.monotonic())
        prepared['owned'].verify(cutoff)
        checkout(legacy, old_bootstrap, prepared, plan, cutoff, runner)
        owner.verify(cutoff)
        with legacy.defer_controls():
            verified = bootstrap.verify_checkout(old_bootstrap, prepared, plan['root_pins'], environment, deadline=cutoff)
        packet = prepared['paths']['workspace'] / PACKET_PATH
        raw, _, _ = legacy.read_bootstrap(old_bootstrap, packet, cutoff, mode=0o644)
        bind_packet(old_bootstrap, raw, selection, verified, plan)
        argv = controller_argv(plan, prepared['paths'], verified, bindings, entry)
        prepared['owned'].verify(cutoff)
        owner.verify(cutoff)
        check(cutoff)
        signal.setitimer(signal.ITIMER_REAL, workflow_end - time.monotonic())
        child = {**environment, **bindings, 'PYTHONDONTWRITEBYTECODE': '1'}
        code, _ = runner(argv, child, str(owner.path), workflow_end, spawn_deadline=cutoff, workspace_owner=owner)
        owner.verify(workflow_end)
        need(type(code) is int and 0 <= code <= 255, 'controller-return-code')
        check(workflow_end)
    except BaseException as error:
        first = error
    finally:
        if prepared is not None:
            retirement = legacy.retire(prepared['owned'])
    if first is not None:
        raise first
    need(not retirement, 'bootstrap-retirement-uncertain')
    return {'controller_exit_code': code, 'retained_cutoff': cutoff, 'workflow_end': workflow_end,
            'source_commit': plan['root_pins']['source_commit'], 'data_commit': plan['data_commit'],
            'composition': COMPOSITION}


def launch_composed(plan, environment, *, preparation_entry=None, delivery=fetch, runner=None):
    """Enter only after a Root-registered parent authenticated this plan."""
    validate_plan(plan, environment)
    actual = time.monotonic()
    if preparation_entry is None:
        preparation_entry = actual
    need(type(preparation_entry) in (int, float) and math.isfinite(preparation_entry) and
         0 < preparation_entry <= actual, 'workspace-preparation-entry')
    end = preparation_entry + 60
    legacy = load_legacy(plan, delivery, end)
    source, data = plan['root_pins']['source_commit'], plan['data_commit']
    if runner is None:
        runner = legacy.run
    owner = None
    first = None
    retirement = []
    with legacy.controls(end):
        try:
            modules = tuple(legacy.module(delivered(delivery, source, CODE_PATHS[name], expected, CODE_LIMIT, end),
                                          expected, 'trusted_v3_' + name)
                            for name, expected in (('legacy_bootstrap', LEGACY_BOOTSTRAP_SHA),
                                                   ('bootstrap', plan['bootstrap_v3_sha256']), ('issuer', ISSUER_SHA)))
            datasets = tuple(delivered(delivery, data, path, plan['root_pins'][name], DATA_LIMIT, end)
                             for name, path in DATA_PATHS.items())
            value = modules[0].decode(datasets[0])
            need(type(value) is dict and type(value.get('source_files')) is dict and
                 len(value['source_files']) == LIVE_ROWS and value.get('packet_sha256') == plan['development_sha256'],
                 'selection-packet-binding')
            with legacy.defer_controls():
                owner = legacy.select_workspace(environment, end)
            result = _launch(legacy, modules, datasets, plan, owner.environment, end, runner, owner)
        except BaseException as error:
            first = error
        finally:
            if owner is not None:
                retirement = owner.close()
        if first is not None:
            raise first
        need(not retirement, 'workspace-retirement-uncertain')
        check(result['workflow_end'])
    check(result['workflow_end'])
    return result
