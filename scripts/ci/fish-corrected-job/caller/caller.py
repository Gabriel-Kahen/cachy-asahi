# SPDX-License-Identifier: MIT
"""Common corrected caller, two closed profiles, one inherited aggregate clock."""
import argparse
import ast
import base64
import gzip
import dis
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import secrets
import stat
import sys
import time
from types import CodeType, FunctionType, ModuleType, SimpleNamespace, TracebackType

def bind(profile, base):
    if type(profile) is not str or profile not in ('topmem-v1', 'fish-history-v1'):
        raise ValueError('caller-profile-unselected')
    PROFILE = profile
    if PROFILE == 'topmem-v1':
        ADDON = '4eb3b51f8eb7dcd0bc1ec01dd4b911326d7f0faef0d810517e42b5a9d6272cd7'
        SCOPE = 'topmem-addon'
        KEY_OWNER = 'topmem_key_owner'
        CHILD = 'topmem-child.json'
        PROOF = 'topmem-proof'
        JOB_PREFIX = 'tm-'
        SOURCE_MEMBERS = 18
        PROOF_ROWS = 124
        STATUS = 'PROVISIONAL_TOPMEM_NATIVE_ADDON'
        METADATA_PREFIX = 'TOPMEM_CALLER_METADATA='
    else:
        ADDON = 'a27a13ba1938d2ec27d1ef9159b95a8d2263c06b143bfc9b694e5d3cccd14f5c'
        SCOPE = 'fish-history-addon'
        KEY_OWNER = 'fish_history_key_owner'
        CHILD = 'fish-history-child.json'
        PROOF = 'fish-history-proof'
        JOB_PREFIX = 'fh-'
        SOURCE_MEMBERS = 24
        PROOF_ROWS = 130
        STATUS = 'PROVISIONAL_FISH_HISTORY_NATIVE_ADDON'
        METADATA_PREFIX = 'FISH_HISTORY_CALLER_METADATA='
    BASE = Path(base).resolve()
    ROOT = BASE.parent
    BASELINE = '16498f24649b981e99d803682e87e632bbba289e4bb6d3169d7608d7cecdc617'
    CONTRACT = 'c84168539130394f9fe51bf440d036f44813ff2b923c1e9d77748f97f755c922'
    path = ROOT / 'baseline96/contract.py'
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
        raise ValueError('caller-contract-type')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = os.read(fd, 65537)
    finally:
        os.close(fd)
    if hashlib.sha256(raw).hexdigest() != CONTRACT:
        raise ValueError('caller-contract-pin')
    c = ModuleType('contract')
    c.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), c.__dict__)

    SIGNER_CODES = frozenset(('signer-agent-drift', 'signer-agent-exit', 'signer-agent-handoff', 'signer-agent-identity', 'signer-agent-removal-uncertain', 'signer-agent-socket', 'signer-attempt-not-reserved', 'signer-caller-manifest', 'signer-caller-state', 'signer-certificate-custody', 'signer-command-failed', 'signer-created-fingerprint', 'signer-deadline', 'signer-directory', 'signer-directory-drift', 'signer-disposal-count', 'signer-disposal-depth', 'signer-disposal-directory-drift', 'signer-disposal-file-drift', 'signer-disposal-mode', 'signer-disposal-owner', 'signer-disposal-type', 'signer-entry-source', 'signer-journal-binding', 'signer-journal-bound', 'signer-journal-command', 'signer-journal-custody', 'signer-journal-node', 'signer-journal-owner', 'signer-journal-socket', 'signer-key-list', 'signer-key-state', 'signer-keyhome-absence', 'signer-library-unselected', 'signer-loader-unselected', 'signer-output', 'signer-owner-certificate', 'signer-owner-custody', 'signer-owner-path', 'signer-pidfd-required', 'signer-policy', 'signer-policy-bound', 'signer-policy-custody', 'signer-policy-row', 'signer-prepared-custody', 'signer-process', 'signer-process-bound', 'signer-process-unobserved', 'signer-producer-custody', 'signer-producer-manifest', 'signer-producer-policy', 'signer-producer-source', 'signer-public-certificate', 'signer-python-unselected', 'signer-root-not-fresh', 'signer-script-closure-unselected', 'signer-socket-path-bound', 'signer-spawn-drift', 'signer-spawn-identity', 'signer-sticky-uncertainty', 'signer-tool-elf', 'signer-tool-pin', 'signer-tool-search-override', 'signer-tool-type', 'signer-unbound-agent', 'signer-unselected-subkey', 'signer-write'))
    SIGNER_STAGES = frozenset(('not-attempted', 'start', 'handoff-save', 'handoff-pin', 'prepare', 'prepared'))

    IO_SITES = frozenset(('OTHER', 'START_LAUNCH', 'START_POLL', 'START_LOG_CLOSE',
        'START_LISTENER_CLOSE', 'PROC_STAT_READ', 'PROC_STATUS_READ', 'PROC_EXE_READLINK',
        'PROC_EXE_STAT', 'PROC_CMDLINE_READ', 'JOURNAL_IO', 'DIRECTORY_STAT'))

    IO_ERRORS = (OSError, BlockingIOError, ChildProcessError, ConnectionError, BrokenPipeError,
            ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError, FileExistsError,
            FileNotFoundError, InterruptedError, IsADirectoryError, NotADirectoryError,
            PermissionError, ProcessLookupError, TimeoutError)

    def io_detail(error=None):
        number = None
        if any(type(error) is kind for kind in IO_ERRORS):
            value = error.errno
            if type(value) is int and 1 <= value <= 4095:
                number = value
        return {'operation': 'OTHER' if isinstance(error, OSError) else None, 'errno': number}

    def start_io_detail(error, api, args, end, report):
        # Optional metadata, exact held Source only; never inspect frame locals.
        result = io_detail(error)
        if not any(type(error) is kind for kind in IO_ERRORS):
            return result
        try:
            function = api.signing.start
            if type(function) is not FunctionType:
                return result
            namespace = function.__globals__
            filename = str(BASE / 'signing.py')
            if type(namespace) is not dict or type(namespace.get('__file__')) is not str or namespace['__file__'] != filename:
                return result
            pin = args.manifest['files']['signing.py']
            c.need(type(pin) is dict and set(pin) == {'bytes', 'mode', 'sha256'}
                and type(pin['bytes']) is type(pin['mode']) is int and pin['mode'] == 0o644
                and 0 < pin['bytes'] <= 1024**2 and type(pin['sha256']) is str, 'caller-io-source')
            raw = c.pinned(BASE / 'signing.py', pin['sha256'], end)
            c.need(type(raw) is bytes and len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'], 'caller-io-source')
            compiled = {}
            def codes(code):
                c.need(len(compiled) < 256, 'caller-io-source')
                compiled[code.co_qualname] = code
                for value in code.co_consts:
                    if type(value) is CodeType:
                        codes(value)
            codes(compile(raw, filename, 'exec'))
            bind = namespace.get('bind')
            if function.__code__ != compiled.get('bind.<locals>.start') or type(bind) is not FunctionType or bind.__globals__ is not namespace or bind.__code__ != compiled.get('bind'):
                return result
            expressions = {
                'start': (
                    ('subprocess.Popen(launch, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=logfd, env=env, close_fds=True, start_new_session=True, preexec_fn=setup, pass_fds=(listener.fileno(),))', 'START_LAUNCH'),
                    ('running.poll()', 'START_POLL'), ('os.close(logfd)', 'START_LOG_CLOSE'),
                    ('listener.close()', 'START_LISTENER_CLOSE')),
                'process': (
                    ("(path / 'stat').read_bytes()", 'PROC_STAT_READ'),
                    ("(path / 'status').read_bytes()", 'PROC_STATUS_READ'),
                    ("os.readlink(path / 'exe')", 'PROC_EXE_READLINK'),
                    ("(path / 'exe').stat()", 'PROC_EXE_STAT'),
                    ("(path / 'cmdline').read_bytes()", 'PROC_CMDLINE_READ'))}
            tree = ast.parse(raw)
            declaration = next(node for node in tree.body if type(node) is ast.FunctionDef and node.name == 'bind')
            regions = {}
            for node in declaration.body:
                if type(node) is ast.FunctionDef and node.name in expressions:
                    wanted = {ast.dump(ast.parse(expression, mode='eval').body, include_attributes=False): label
                        for expression, label in expressions[node.name]}
                    regions['bind.<locals>.' + node.name] = tuple((call.lineno, call.end_lineno, call.col_offset, call.end_col_offset,
                        wanted[ast.dump(call, include_attributes=False)]) for call in ast.walk(node)
                        if type(call) is ast.Call and ast.dump(call, include_attributes=False) in wanted)
            labels = {'bind.<locals>.write': 'JOURNAL_IO', 'bind.<locals>.directory': 'DIRECTORY_STAT'}
            trace = error.__traceback__; count = 0
            while trace is not None:
                if type(trace) is not TracebackType or count >= 64:
                    return io_detail(error)
                count += 1; frame = trace.tb_frame; code = frame.f_code; name = code.co_qualname
                if frame.f_globals is namespace and code.co_filename == filename and code == compiled.get(name):
                    if name in labels:
                        result['operation'] = labels[name]
                    position = next((item.positions for item in dis.get_instructions(code, show_caches=True)
                        if item.offset == trace.tb_lasti), None)
                    if position is not None and all(type(value) is int for value in
                            (position.lineno, position.end_lineno, position.col_offset, position.end_col_offset)):
                        for start, stop, column, last_column, label in regions.get(name, ()):
                            if (start, column) <= (position.lineno, position.col_offset) and (position.end_lineno, position.end_col_offset) <= (stop, last_column):
                                result['operation'] = label
                trace = trace.tb_next
        except BaseException as fault:
            if isinstance(fault, KeyboardInterrupt) or type(fault).__name__ == 'Cancelled' or getattr(fault, 'secondary_cancelled', False) is True:
                report['cancelled'] = True
                report['status'] = 'FAIL'
            return io_detail(error)
        return result

    def signing_code(error):
        # Never stringify errors or export argv, stdout, stderr, paths or keys.
        if isinstance(error, KeyboardInterrupt) or type(error).__name__ == 'Cancelled':
            return 'cancelled'
        if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in SIGNER_CODES:
            return error.args[0]
        return 'io-failed' if isinstance(error, OSError) else 'unclassified'

    def diagnostic(stage='not-attempted', code=None):
        return {'stage': stage, 'code': code, 'io': {'operation': None, 'errno': None}}

    def validate_diagnostic(value):
        c.need(type(value) is dict and set(value) == {'stage', 'code', 'io'} and type(value['stage']) is str
               and value['stage'] in SIGNER_STAGES and (value['code'] is None or type(value['code']) is str
               and value['code'] in SIGNER_CODES | {'cancelled', 'io-failed', 'unclassified'}), 'caller-signing-diagnostic')
        c.need(value['stage'] != 'not-attempted' or value['code'] is None, 'caller-signing-diagnostic')
        detail = value['io']
        c.need(type(detail) is dict and set(detail) == {'operation', 'errno'}
            and (detail['errno'] is None or type(detail['errno']) is int and 1 <= detail['errno'] <= 4095), 'caller-signing-io')
        if value['code'] == 'io-failed':
            c.need(type(detail['operation']) is str and detail['operation'] in IO_SITES, 'caller-signing-io')
        else:
            c.need(detail == {'operation': None, 'errno': None}, 'caller-signing-io')
        return value

    def unavailable_journal():
        return {'status': 'UNAVAILABLE', 'phase': None, 'launch_attempted': None, 'agent_bound': None, 'sticky_uncertain': None}

    def signer_journal(api, config, end, report):
        # Validated owner journal projection only; no process/socket/key references.
        try:
            with api.worker.graph(config, end) as (contract, producer, load):
                path = Path(config['jobroot']) / api.signing.SIGNING / 'owner-journal.json'
                row = api.signing.journal_record(contract, path, config, end)
                return {'status': 'OBSERVED', 'phase': row['phase'], 'launch_attempted': row['launch_attempted'],
                        'agent_bound': row['agent'] is not None, 'sticky_uncertain': row['sticky_uncertain']}
        except BaseException as error:
            if signing_code(error) == 'cancelled':
                report['cancelled'] = True
                report['status'] = 'FAIL'
                if report['first_cause'] is None:
                    report['first_cause'] = 'cancelled'
            return unavailable_journal()

    def recovery_summary(value=None):
        fields = {'status', 'agent_absent', 'keyhome_absent', 'cancelled', 'reason'}
        if type(value) is dict and fields <= set(value):
            result = {key: value[key] for key in fields}
            try:
                validate_recovery(result)
                return result
            except ValueError:
                pass
        return {'status': 'UNAVAILABLE', 'agent_absent': None, 'keyhome_absent': None, 'cancelled': None, 'reason': None}

    def validate_recovery(value):
        c.need(type(value) is dict and set(value) == {'status', 'agent_absent', 'keyhome_absent', 'cancelled', 'reason'}
               and type(value['status']) is str and value['status'] in {'PASS', 'FAIL', 'NOT STARTED', 'UNAVAILABLE'}, 'caller-signing-recovery')
        if value['status'] == 'UNAVAILABLE':
            c.need(all(value[key] is None for key in ('agent_absent', 'keyhome_absent', 'cancelled', 'reason')), 'caller-signing-recovery')
        else:
            c.need(all(type(value[key]) is bool for key in ('agent_absent', 'keyhome_absent', 'cancelled'))
                   and type(value['reason']) is str and value['reason'] in {'disposed', 'not-started', 'refused', 'cancelled', 'unobserved'}, 'caller-signing-recovery')
            if value['status'] in {'PASS', 'NOT STARTED'}:
                c.need(value['agent_absent'] is value['keyhome_absent'] is True and value['cancelled'] is False
                       and value['reason'] == ('disposed' if value['status'] == 'PASS' else 'not-started'), 'caller-signing-recovery')
        return value

    def validate_signer_retention(value):
        c.need(type(value) is dict and set(value) == {'before', 'after', 'result'}, 'caller-signer-retention')
        validate_recovery(value['result'])
        for name in ('before', 'after'):
            row = value[name]
            c.need(type(row) is dict and set(row) == {'status', 'phase', 'launch_attempted', 'agent_bound', 'sticky_uncertain'}
                   and type(row['status']) is str and row['status'] in {'OBSERVED', 'UNAVAILABLE'}, 'caller-signer-journal')
            if row['status'] == 'UNAVAILABLE':
                c.need(all(row[key] is None for key in ('phase', 'launch_attempted', 'agent_bound', 'sticky_uncertain')), 'caller-signer-journal')
            else:
                c.need(type(row['phase']) is str and row['phase'] in {'reserved', 'create-attempted', 'bound', 'generating', 'prepared', 'failed', 'disposed'}
                       and all(type(row[key]) is bool for key in ('launch_attempted', 'agent_bound', 'sticky_uncertain')), 'caller-signer-journal')
        return value

    def module(name, path, pin, end=None):
        raw = c.pinned(path, pin, end)
        spec = importlib.util.spec_from_file_location(name, path)
        value = importlib.util.module_from_spec(spec)
        exec(compile(raw, str(path), 'exec'), value.__dict__)
        return value

    def members(root, files, end, max_nodes, max_depth):
        """Reject extra nodes, links and special files without unbounded enumeration."""
        expected = {str(c.relative(name)) for name in files}
        directories = {str(parent) for name in expected for parent in Path(name).parents if str(parent) != '.'}
        observed = set()
        seen_dirs = set()
        count = 0

        def walk(directory, relative, depth):
            nonlocal count
            c.live(end)
            c.need(depth <= max_depth, 'caller-source-depth')
            info = directory.lstat()
            c.need(stat.S_ISDIR(info.st_mode), 'caller-source-directory')
            with os.scandir(directory) as entries:
                for entry in entries:
                    c.live(end)
                    count += 1
                    c.need(count <= max_nodes, 'caller-source-nodes')
                    name = str(relative / entry.name)
                    kind = entry.stat(follow_symlinks=False).st_mode
                    if stat.S_ISDIR(kind):
                        c.need(name in directories, 'caller-source-extra-directory')
                        seen_dirs.add(name)
                        walk(directory / entry.name, Path(name), depth + 1)
                    else:
                        c.need(stat.S_ISREG(kind) and name in expected, 'caller-source-extra-node')
                        observed.add(name)
        walk(root, Path(), 0)
        c.need(observed == expected and seen_dirs == directories, 'caller-source-members')

    def verify(pin, end=None):
        end = time.monotonic() + 30 if end is None else end
        c.live(end)
        manifest = c.decode(c.pinned(BASE / 'manifest.json', pin, end))
        c.need(set(manifest) == {'schema_version', 'baseline_packet_sha256', 'addon_manifest_sha256', 'files', 'tools', 'addon_profile'} and type(manifest['schema_version']) is int and (manifest['schema_version'] == 2 and manifest['addon_profile'] == PROFILE) and (manifest['baseline_packet_sha256'] == BASELINE) and (manifest['addon_manifest_sha256'] == ADDON), 'caller-manifest-binding')
        c.need(set(manifest['files']) == {'caller.py', 'signing.py', 'recovery.py', 'agent_entry.py', 'producer.py', 'repository_adapter.py'}, 'caller-source-members')
        members(BASE, {*manifest['files'], 'manifest.json'}, end, 7, 0)
        for name, row in manifest['files'].items():
            raw = c.pinned(BASE / name, row['sha256'], end)
            c.need(set(row) == {'bytes', 'mode', 'sha256'} and type(row['bytes']) is type(row['mode']) is int and (len(raw) == row['bytes']) and (stat.S_IMODE((BASE / name).lstat().st_mode) == row['mode']), 'caller-source-fields')
        inputs, source = c.verify(ROOT / 'baseline96', BASELINE, end)
        addon = c.decode(c.pinned(ROOT / 'addon/source-manifest.json', ADDON, end))
        c.need(addon['parent_packet_sha256'] == BASELINE and type(addon['files']) is dict and (len(addon['files']) == SOURCE_MEMBERS), 'caller-addon-binding')
        members(ROOT / 'addon', {*addon['files'], 'source-manifest.json'}, end, 64, 4)
        for name, row in addon['files'].items():
            raw = c.pinned(ROOT / 'addon' / c.relative(name), row['sha256'], end)
            c.need(len(raw) == row['bytes'] and stat.S_IMODE((ROOT / 'addon' / name).lstat().st_mode) == row['mode'], 'caller-addon-fields')
        c.need(set(manifest['tools']) == {'/usr/bin/git', '/usr/bin/python3.12', '/usr/bin/docker'}, 'caller-tools')
        return (manifest, inputs, source, addon)

    def modules(manifest, source, addon, end):

        def parent(name, relative):
            return module(name, ROOT / 'baseline96' / relative, source['files'][relative]['sha256'], end)
        controller = parent('selected_baseline_controller', 'controller.py')
        c.live(end)
        runtime, worker, writer = controller.providers(ROOT / 'baseline96', source)
        entry = module('selected_addon_entry', ROOT / 'addon/addon.py', addon['files']['addon.py']['sha256'], end)
        if PROFILE == 'fish-history-v1':
            engine = module('selected_fish_engine', ROOT / 'addon/engine.py', addon['files']['engine.py']['sha256'], end)
            entry = entry.bind(engine)
        signing = module('selected_signing', BASE / 'signing.py', manifest['files']['signing.py']['sha256'], end).bind(PROFILE, ROOT)
        recovery = module('selected_recovery', BASE / 'recovery.py', manifest['files']['recovery.py']['sha256'], end).bind(PROFILE, ROOT)
        producer = module('selected_producer', BASE / 'producer.py', manifest['files']['producer.py']['sha256'], end).bind(PROFILE)
        repository = module('selected_repository', BASE / 'repository_adapter.py', manifest['files']['repository_adapter.py']['sha256'], end).bind(PROFILE)
        c.need(producer.profile == repository.profile == PROFILE, 'caller-profile-providers')
        return SimpleNamespace(controller=controller, runtime=runtime, worker=worker, writer=writer, lane=parent('selected_baseline_lane', 'lane.py'), addon=entry, signing=signing, recovery=recovery, producer=producer, repository=repository)

    def fixed_tools(manifest, end):
        for name, row in manifest['tools'].items():
            path = Path(name)
            before = path.lstat()
            c.need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and (before.st_nlink == 1) and (stat.S_IMODE(before.st_mode) == 493), 'caller-tool-metadata')
            raw = c.read(path, 64 * 1024 ** 2, end)
            c.need(c.sha(raw) == row['sha256'] and type(row['bytes']) is type(row['mode']) is int and (len(raw) == row['bytes']) and (row['mode'] == 493), 'caller-tool-body')
        c.need(Path(sys.executable).resolve() == Path('/usr/bin/python3.12') and sys.flags.isolated == sys.flags.no_site == 1 and sys.dont_write_bytecode, 'caller-interpreter')

    def environment(root):
        return {'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME'], 'LANG': 'C.UTF-8', 'LC_ALL': 'C', 'DOCKER_CONFIG': str(root / 'docker-config'), 'TMPDIR': str(root / 'tmp'), 'PYTHONDONTWRITEBYTECODE': '1', **{k: os.environ[k] for k in ('GITHUB_SHA', 'GITHUB_WORKFLOW_SHA', 'GITHUB_WORKSPACE', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'RUNNER_ARCH', 'RUNNER_OS') if k in os.environ}}

    def process(runtime, runner, argv, end, log):
        c.live(end)
        observation = runtime.RunObservation()
        runner.observation = observation
        result = runner.run(argv, timeout=end - time.monotonic(), log=log)
        state = observation.summary()
        c.need(state['reaping'] == 'COMPLETED' and type(state['natural_poll_code']) is int and (type(state['runner_return_code']) is int) and (state['natural_poll_code'] == state['runner_return_code'] == 0) and (type(result.returncode) is int) and (result.returncode == 0), 'caller-natural-process')
        c.live(end)
        return (result, state)

    def proof(args, manifest, source, addon, api, stamp):
        end = min(stamp['started_at'] + 300, stamp['prefetch_end'])
        c.live(end)
        fixed_tools(manifest, end)
        policy = Path(args.tool_policy).absolute()
        workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve()
        c.need(policy.is_relative_to(workspace), 'caller-committed-policy')
        c.pinned(policy, args.tool_policy_sha256, end)
        directory = Path(args.clock).absolute().parent / PROOF
        api.lane.fresh(directory)
        rows = {ROOT / 'baseline96' / n: r['mode'] for n, r in source['files'].items()}
        rows[ROOT / 'baseline96/packet.json'] = 420
        rows.update({ROOT / 'addon' / n: r['mode'] for n, r in addon['files'].items()})
        rows[ROOT / 'addon/source-manifest.json'] = 420
        rows.update({BASE / n: r['mode'] for n, r in manifest['files'].items()})
        rows[BASE / 'manifest.json'] = 420
        c.need(policy not in rows, 'caller-policy-source-overlap')
        rows[policy] = 420
        c.need(len(rows) == PROOF_ROWS, 'caller-proof-row-count')
        env = environment(directory)
        env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null', GIT_NO_REPLACE_OBJECTS='1')
        with api.runtime.Runner(env, directory, directory / 'logs', deadline_seconds=7200, deadline_at=end) as runner:
            with runner.phase_scope(end):
                git = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '--no-optional-locks', '-C', str(workspace)]
                head = runner.run([*git, 'rev-parse', 'HEAD'], timeout=min(10, end - time.monotonic()), limit=4096)
                c.need(type(head.returncode) is int and head.returncode == 0 and (head.stdout.decode('ascii').strip() == stamp['source_commit']), 'caller-committed-head')
                for path, mode in rows.items():
                    c.live(end)
                    relative = str(path.relative_to(workspace))
                    blob = runner.run([*git, 'show', 'HEAD:' + relative], timeout=min(10, end - time.monotonic()))
                    tree = runner.run([*git, 'ls-tree', 'HEAD', '--', relative], timeout=min(10, end - time.monotonic()), limit=4096)
                    c.need(type(blob.returncode) is type(tree.returncode) is int and blob.returncode == tree.returncode == 0 and (blob.stdout == c.read(path, deadline=end)), 'caller-committed-bytes')
                    words = tree.stdout.decode('ascii').split()
                    c.need(mode in (420, 493) and len(words) >= 4 and (words[:2] == ['100755' if mode == 493 else '100644', 'blob']), 'caller-committed-mode')
                api.writer.save(directory / 'receipt.json', {'schema_version': 1, 'addon_profile': PROFILE, 'status': 'PASS', 'source_commit': stamp['source_commit'], 'clock_sha256': args.clock_sha256, 'caller_manifest_sha256': args.caller_manifest_sha256, 'baseline_packet_sha256': BASELINE, 'addon_manifest_sha256': ADDON, 'tool_policy_sha256': args.tool_policy_sha256, 'deadline_at': end, 'source_rows': len(rows)})
        api.lane.proof(ROOT / 'baseline96', source, api.runtime, api.writer, stamp, Path(args.clock).absolute().parent / 'proof')
        c.live(end)

    def state(private, writer, values, held):
        if held.get('fd') is not None:
            os.close(held.pop('fd'))
        writer.save(private / 'caller-state.json', values)
        path = private / 'caller-state.json'
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        raw = c.read(path, 65536)
        c.need(info.st_uid == os.getuid() and info.st_gid == os.getgid() and (stat.S_IMODE(info.st_mode) == 384) and (info.st_nlink == 1) and stat.S_ISREG(info.st_mode), 'caller-state-custody')
        held.update(fd=fd, path=path, identity=(info.st_dev, info.st_ino), sha256=c.sha(raw))
        return {'sha256': c.sha(raw), 'bytes': len(raw), 'dev': info.st_dev, 'ino': info.st_ino}

    def check_state(held):
        named = held['path'].lstat()
        opened = os.fstat(held['fd'])
        c.need((named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino) == held['identity'] and c.sha(c.read(held['path'], 65536)) == held['sha256'], 'caller-state-drift')

    def addon_admission(api, config, raw_baseline, result):
        if PROFILE == 'fish-history-v1':
            return fish_admission(api, config, raw_baseline, result)
        c.need(config['addon_profile'] == PROFILE, 'caller-profile-config')
        private = Path(config['jobroot'])
        c.need(c.read(private / 'native-worker.json') == raw_baseline, 'caller-original-receipt-drift')
        original = c.decode(raw_baseline)
        api.worker.validate_receipt(original, config)
        c.need(result.get('status') == STATUS and type(result.get('builds')) is int and (result['builds'] == 4) and (type(result.get('comparisons')) is int) and (result['comparisons'] == 2) and (result.get('parent_cleanup_required') is True), 'caller-addon-result')
        commands = c.decode(c.read(private / (SCOPE + '/commands.json'), 65536))
        expected = [[v, k] for v in ('current', 'upgrade-fixture') for k in ('build-1', 'build-2', 'compare')]
        c.need(commands.get('scope') == SCOPE + '-only' and commands.get('started') == commands.get('finished') == expected and (type(commands.get('builds')) is int) and (commands['builds'] == 4) and (type(commands.get('comparisons')) is int) and (commands['comparisons'] == 2), 'caller-addon-counts')
        owner = config[KEY_OWNER]
        key = api.addon.key_contract(c, owner['path'], owner['sha256'], private, config['work_deadline'])
        journal = c.decode(c.read(private / (SCOPE + '/lifecycle-container.json'), 65536))
        c.need(journal.get('attempted') is True and journal.get('result') == 'provisional-zero' and (journal.get('argv') == api.addon.lifecycle_argv(config, original['image_id'], key['fingerprint'])) and (journal.get('image') == original['image_id']) and (journal.get('daemon') == original['daemon']) and (journal.get('nonce') == config['nonce']), 'caller-addon-lifecycle')
        signed = c.decode(b'{"rows":' + c.read(private / (SCOPE + '/signatures.json'), 1024 ** 2) + b'}')['rows']
        c.need(type(signed) is list and 12 <= len(signed) <= 16 and all((type(r) is dict and r.get('status') == 'pass' for r in signed)), 'caller-addon-signing-journal')
        verifies = [r for r in signed if type(r.get('argv')) is list and '--verify' in r['argv']]
        c.need(len(verifies) == 6, 'caller-addon-signature-count')
        keypin = config['repository_producer_sha256']
        c.need(key['repo_add_sha256'] == keypin, 'caller-internal-producer-owner')
        selected_policy = api.signing.policy(c, Path(config['tool_policy']), config['tool_policy_sha256'], config, config['work_deadline'])
        produced = api.repository.admit(c, api.addon, api.producer, config, config['caller_manifest_sha256'], config['work_deadline'], selected_policy)
        return {'builds': 4, 'comparisons': 2, 'signature_observations': 6, 'lifecycle': 1, 'database_productions': produced, 'status': 'PROVISIONAL'}

    def observations(private, end):
        """Finite journal observations; availability never grants acceptance."""
        result = {'baseline': None, 'addon_commands': None, 'addon_signatures': None}
        try:
            raw = c.read(private / 'native-worker.json', 1024 ** 2, deadline=end)
            row = c.decode(raw)
            bounds = {'build_invocations': 8, 'builds_completed': 8, 'comparisons_completed': 4, 'signatures_verified': 249}
            c.need(all((type(row.get(k)) is int and 0 <= row[k] <= v for k, v in bounds.items())), 'caller-observed-baseline')
            result['baseline'] = {'sha256': c.sha(raw), **{k: row[k] for k in bounds}}
        except Exception:
            pass
        try:
            raw = c.read(private / (SCOPE + '/commands.json'), 65536, deadline=end)
            row = c.decode(raw)
            expected = [[v, k] for v in ('current', 'upgrade-fixture') for k in ('build-1', 'build-2', 'compare')]
            c.need(row.get('scope') == SCOPE + '-only' and type(row.get('started')) is list and (type(row.get('finished')) is list) and (len(row['started']) <= 6) and (len(row['finished']) <= len(row['started'])) and (row['started'] == expected[:len(row['started'])]) and (row['finished'] == expected[:len(row['finished'])]), 'caller-observed-addon')
            result['addon_commands'] = {'sha256': c.sha(raw), 'started': len(row['started']), 'finished': len(row['finished']), 'builds_started': sum((k != 'compare' for _, k in row['started'])), 'builds_finished': sum((k != 'compare' for _, k in row['finished'])), 'comparisons_finished': sum((k == 'compare' for _, k in row['finished']))}
        except Exception:
            pass
        try:
            raw = c.read(private / (SCOPE + '/signatures.json'), 1024 ** 2, deadline=end)
            rows = c.decode(b'{"rows":' + raw + b'}')['rows']
            c.need(type(rows) is list and len(rows) <= 16 and all((type(r) is dict and r.get('status') in ('pass', 'fail') and (type(r.get('argv')) is list) and (len(r['argv']) <= 64) and all((type(v) is str and len(v) <= 4096 for v in r['argv'])) for r in rows)), 'caller-observed-signatures')
            count = sum((r['status'] == 'pass' and '--verify' in r['argv'] for r in rows))
            c.need(count <= 6, 'caller-observed-signature-bound')
            result['addon_signatures'] = {'sha256': c.sha(raw), 'entries': len(rows), 'passed_verifications': count}
        except Exception:
            pass
        return result

    def addon_child(args, api, stamp):
        config = c.decode(c.pinned(args.config, args.config_sha256, stamp['guard_end']))
        c.need(config['addon_profile'] == PROFILE and config['source'] == str(ROOT / 'baseline96') and (config['snapshot'] == str(ROOT / 'baseline96/native')) and (config['packet_sha256'] == BASELINE) and (config['source_commit'] == stamp['source_commit']) and (config['work_deadline'] == stamp['guard_end'] - 480), 'caller-child-binding')
        private = Path(config['jobroot'])
        report = {'schema_version': 1, 'addon_profile': PROFILE, 'status': 'FAIL', 'phase': 'signing', 'first_cause': None, 'cancelled': False, 'key_owner': None, 'addon': None, 'provisional_result': None, 'source_commit': config['source_commit'], 'clock_sha256': args.clock_sha256, 'caller_manifest_sha256': args.caller_manifest_sha256, 'baseline_worker_sha256': config['baseline_worker_sha256']}
        report['signing_diagnostic'] = diagnostic('prepare')
        try:
            raw = c.pinned(private / 'native-worker.json', config['baseline_worker_sha256'], config['work_deadline'])
            receipt = c.decode(raw)
            c.need(api.worker.validate_receipt(receipt, config) is receipt, 'caller-child-baseline-identity')
            prepared = api.signing.prepare(api.worker, config, Path(config['tool_policy']), config['tool_policy_sha256'])
            report['signing_diagnostic'] = diagnostic('prepared')
            report['key_owner'] = {'path': str(prepared['key_owner_path']), 'sha256': prepared['key_owner_sha']}
            api.writer.save(private / CHILD, report)
            config[KEY_OWNER] = report['key_owner']
            report['phase'] = 'addon'
            selected = args.manifest['files']['producer.py']
            c.need(config['repository_producer_sha256'] == selected['sha256'], 'caller-child-producer-binding')

            def guard(contract, end):
                return api.signing.policy(contract, Path(config['tool_policy']), config['tool_policy_sha256'], config, end)
            if PROFILE == 'fish-history-v1':
                result = execute_addon(api, receipt, config, args, prepared)
            else:
                with api.repository.selected(api.addon, api.producer, BASE / 'producer.py', selected['sha256'], selected['bytes'], args.caller_manifest_sha256, guard, api.worker, config):
                    result = execute_addon(api, receipt, config, args, prepared)
            report['provisional_result'] = result
            report['addon'] = addon_admission(api, config, raw, result)
            c.live(config['work_deadline'])
            report.update(status='PROVISIONAL', phase='complete')
        except BaseException as error:
            if report['phase'] == 'signing':
                report['signing_diagnostic']['code'] = signing_code(error)
                if report['signing_diagnostic']['code'] == 'io-failed':
                    report['signing_diagnostic']['io'] = io_detail(error)
            report['first_cause'] = report['phase'] + '-failed'
            report['cancelled'] = isinstance(error, KeyboardInterrupt) or type(error).__name__ == 'Cancelled' or getattr(error, 'secondary_cancelled', False) is True
        finally:
            api.writer.save(private / CHILD, report)
        return 0 if report['status'] == 'PROVISIONAL' else 1

    def execute(args, api, stamp, inputs):
        end = stamp['guard_end']
        work_end = end - 480
        cleanup_end = end - 60
        c.live(work_end)
        fixed_tools(args.manifest, end)
        c.need(args.docker_binary == '/usr/bin/docker' and args.docker_sha256 == args.manifest['tools']['/usr/bin/docker']['sha256'] and (args.endpoint == 'unix:///var/run/docker.sock'), 'caller-selected-docker')
        args.deadline_at = end
        args.deadline = 7200
        args.source_commit = stamp['source_commit']
        args.packet_sha256 = BASELINE
        api.controller.ordinary(args)
        proof_row = c.decode(c.read(Path(args.clock).absolute().parent / (PROOF + '/receipt.json'), 65536))
        c.need(proof_row.get('addon_profile') == PROFILE and proof_row.get('status') == 'PASS' and (proof_row.get('source_commit') == stamp['source_commit']) and (proof_row.get('clock_sha256') == args.clock_sha256) and (proof_row.get('caller_manifest_sha256') == args.caller_manifest_sha256) and (proof_row.get('tool_policy_sha256') == args.tool_policy_sha256) and (proof_row.get('baseline_packet_sha256') == BASELINE) and (proof_row.get('addon_manifest_sha256') == ADDON) and (type(proof_row.get('source_rows')) is int) and (proof_row['source_rows'] == PROOF_ROWS) and (type(proof_row.get('deadline_at')) in (int, float)) and math.isfinite(proof_row['deadline_at']) and (proof_row['deadline_at'] == min(stamp['started_at'] + 300, stamp['prefetch_end'])), 'caller-source-proof-required')
        prefetch = c.decode(c.read(Path(args.clock).absolute().parent / 'prefetch/parent-receipt.json'))
        c.need(prefetch.get('status') == 'PASS' and prefetch.get('clock_sha256') == args.clock_sha256, 'caller-prefetch-required')
        expected = Path(os.environ['RUNNER_TEMP']).resolve() / (JOB_PREFIX + stamp['run_id'] + '-' + stamp['run_attempt'])
        if args.output is None:
            args.output = expected
        c.need(Path(args.output).absolute() == expected, 'caller-owned-job-path')
        out = api.controller.output(args.output, ROOT)
        private = out / 'private'
        for name in ('docker-config', 'tmp'):
            (private / name).mkdir(mode=448)
        config = {'addon_profile': PROFILE, 'source': str(ROOT / 'baseline96'), 'snapshot': str(ROOT / 'baseline96/native'), 'adapter': str(ROOT / 'baseline96/providers/adapter'), 'jobroot': str(private), 'docker_binary': args.docker_binary, 'docker_sha256': args.docker_sha256, 'endpoint': args.endpoint, 'nonce': secrets.token_hex(16), 'work_deadline': work_end, 'cleanup_deadline': cleanup_end, 'job_deadline': end, 'producer_timeout': work_end - time.monotonic(), 'baseline_id': c.ID, 'source_commit': stamp['source_commit'], 'packet_sha256': BASELINE, 'contract_sha256': CONTRACT, 'tool_policy': str(private / 'tool-policy.json'), 'tool_policy_sha256': args.tool_policy_sha256, 'caller_source': str(BASE), 'caller_manifest_sha256': args.caller_manifest_sha256, 'repository_producer_sha256': args.manifest['files']['producer.py']['sha256']}
        policy_raw = c.pinned(args.tool_policy, args.tool_policy_sha256, work_end)
        fd = os.open(private / 'tool-policy.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(policy_raw)
            stream.flush()
            os.fsync(stream.fileno())
        flags = {'schema_version': 1, 'baseline_attempted': False, 'addon_attempted': False, 'signing_attempted': False}
        held = {}
        config['caller_state'] = state(private, api.writer, flags, held)
        report = {'schema_version': 1, 'addon_profile': PROFILE, 'status': 'FAIL', 'phase': 'cache', 'first_cause': None, 'cancelled': False, 'baseline': {'status': 'NOT ACCEPTED', 'builds': 0, 'comparisons': 0, 'signature_observations': 0}, 'addon': {'status': 'NOT ACCEPTED', 'builds': 0, 'comparisons': 0, 'signature_observations': 0, 'lifecycle': 0, 'database_productions': 0}, 'recovery': {}, 'hardware': 'NOT RUN', 'release_selected': False, 'public_admission': False}
        report['signing_diagnostic'] = diagnostic()
        report['signer_retention'] = {'before': unavailable_journal(), 'after': unavailable_journal(), 'result': recovery_summary()}
        runner = None
        passed = False
        raw_baseline = None

        def fail(reason, error=None):
            if report['first_cause'] is None:
                report['first_cause'] = reason
            report['status'] = 'FAIL'
            report['cancelled'] |= getattr(error, 'secondary_cancelled', False) is True or isinstance(error, KeyboardInterrupt) or (error is not None and type(error).__name__ == 'Cancelled')
        try:
            with api.runtime.cancellation_handlers():
                try:
                    runner = api.runtime.Runner(environment(private), private, private / 'logs', deadline_seconds=7200, deadline_at=end)
                    api.signing.check_policy(api.worker, config, Path(config['tool_policy']), config['tool_policy_sha256'])
                    with runner.phase_scope(work_end):
                        c.seed_cache(inputs, args.offline_cache, private / 'cache', work_end, runner.check_resources)
                        config['caller_state'] = state(private, api.writer, {**flags, 'baseline_attempted': True}, held)
                        flags['baseline_attempted'] = True
                        api.writer.save(private / 'worker-config.json', config)
                        config_pin = c.sha(c.read(private / 'worker-config.json'))
                        report['phase'] = 'baseline'
                        result, observed = process(api.runtime, runner, [str(Path(sys.executable).resolve()), '-I', '-B', '-S', str(ROOT / 'baseline96/worker.py'), '--config', str(private / 'worker-config.json'), '--config-sha256', config_pin], work_end, 'baseline.log')
                        baseline = api.controller.accept_worker(api.worker, result.returncode, private, config)
                        raw_baseline = c.read(private / 'native-worker.json')
                        config['baseline_worker_sha256'] = c.sha(raw_baseline)
                        config['daemon'] = baseline['daemon']
                        report['baseline'] = {'status': 'ACCEPTED', 'builds': 8, 'comparisons': 4, 'signature_observations': 249, 'receipt_sha256': c.sha(raw_baseline)}
                        check_state(held)
                        flags.update(addon_attempted=True, signing_attempted=True)
                        config['caller_state'] = state(private, api.writer, flags, held)
                        report['phase'] = 'signing'
                        report['signing_diagnostic'] = diagnostic('start')
                        config['agent_handoff'] = api.signing.start(api.worker, config, runner)
                        report['signing_diagnostic'] = diagnostic('handoff-save')
                        api.writer.save(private / 'addon-config.json', config)
                        report['signing_diagnostic'] = diagnostic('handoff-pin')
                        config_pin = c.sha(c.read(private / 'addon-config.json'))
                        report['phase'] = 'addon'
                        result, observed = process(api.runtime, runner, [str(Path(sys.executable).resolve()), '-I', '-B', '-S', str(BASE / 'caller.py'), '--addon-profile', PROFILE, '--phase', 'addon', '--caller-manifest-sha256', args.caller_manifest_sha256, '--clock', str(args.clock), '--clock-sha256', args.clock_sha256, '--config', str(private / 'addon-config.json'), '--config-sha256', config_pin], work_end, 'addon.log')
                        config['addon_process'] = observed
                        check_state(held)
                        child = c.decode(c.read(private / CHILD))
                        c.need(child.get('addon_profile') == PROFILE and child.get('status') == 'PROVISIONAL' and (child.get('cancelled') is False) and (child.get('first_cause') is None) and (child.get('source_commit') == stamp['source_commit']) and (child.get('clock_sha256') == args.clock_sha256) and (child.get('caller_manifest_sha256') == args.caller_manifest_sha256) and (child.get('baseline_worker_sha256') == c.sha(raw_baseline)), 'caller-addon-child')
                        report['signing_diagnostic'] = validate_diagnostic(child['signing_diagnostic'])
                        config[KEY_OWNER] = child['key_owner']
                        c.need(c.read(private / 'native-worker.json') == raw_baseline, 'caller-original-receipt-drift')
                        api.worker.validate_receipt(c.decode(raw_baseline), config)
                        report['addon'] = addon_admission(api, config, raw_baseline, child['provisional_result'])
                        passed = True
                except BaseException as error:
                    if report['phase'] == 'signing':
                        report['signing_diagnostic']['code'] = signing_code(error)
                        if report['signing_diagnostic']['code'] == 'io-failed':
                            report['signing_diagnostic']['io'] = io_detail(error)
                    if flags['addon_attempted'] and runner is not None and hasattr(runner, 'observation'):
                        config['addon_process'] = runner.observation.summary()
                        try:
                            failed_child = c.decode(c.read(private / CHILD, 65536, deadline=end))
                            c.need(failed_child.get('addon_profile') == PROFILE and failed_child.get('source_commit') == stamp['source_commit'] and (failed_child.get('clock_sha256') == args.clock_sha256) and (failed_child.get('caller_manifest_sha256') == args.caller_manifest_sha256) and (failed_child.get('baseline_worker_sha256') == config['baseline_worker_sha256']) and (type(failed_child.get('cancelled')) is bool), 'caller-child-failure-binding')
                            report['cancelled'] |= failed_child['cancelled']
                            report['signing_diagnostic'] = validate_diagnostic(failed_child['signing_diagnostic'])
                        except BaseException:
                            pass
                    fail(report['phase'] + '-failed', error)
                    if report['signing_diagnostic']['stage'] == 'start' and report['signing_diagnostic']['code'] == 'io-failed':
                        report['signing_diagnostic']['io'] = start_io_detail(error, api, args, work_end, report)
                finally:
                    recovery_end = min(cleanup_end, time.monotonic() + 180)
                    with api.runtime.defer_signals() as events:
                        report['phase'] = 'recovery'
                        report['signer_retention']['before'] = signer_journal(api, config, recovery_end, report)
                        for name, fn in (('signer', api.signing.recover), ('addon', api.recovery.recover), ('baseline', api.worker.cleanup)):
                            try:
                                check_state(held)
                                c.live(recovery_end)
                                value = fn(api.worker, config, recovery_end) if name != 'baseline' else fn(config, recovery_end) if flags['baseline_attempted'] else {'status': 'NOT STARTED', 'absence_verified': True, 'owned_image_absence': True, 'cancelled': False}
                                report['recovery'][name] = value
                                if name == 'signer':
                                    report['signer_retention']['result'] = recovery_summary(value)
                                if name == 'signer' and value.get('key_owner') is not None:
                                    config[KEY_OWNER] = value['key_owner']
                                c.need(value.get('status') in ('PASS', 'NOT STARTED') and value.get('cancelled') is False and (value.get('agent_absent') is True and value.get('keyhome_absent') is True if name == 'signer' else value.get('absence_verified') is True) and (name != 'baseline' or value.get('owned_image_absence') is True), 'caller-recovery-result')
                            except BaseException as error:
                                fail(name + '-recovery-failed', error)
                        report['signer_retention']['after'] = signer_journal(api, config, recovery_end, report)
                        if events:
                            fail('cancelled')
                            report['cancelled'] = True
                        if runner is not None:
                            try:
                                runner.close()
                            except BaseException as error:
                                fail('runner-close-failed', error)
                    api.runtime.check_cancelled()
        except BaseException as error:
            fail('finalization-failed', error)
        finally:
            try:
                if held.get('fd') is not None:
                    os.close(held.pop('fd'))
            except BaseException as error:
                fail('finalization-failed', error)
                report['cancelled'] |= isinstance(error, SystemExit)
                report['recovery']['owned_state_close'] = {
                    'status': 'FAIL', 'absence_verified': False,
                    'retry_performed': False, 'cancelled': report['cancelled'],
                    'disposition': 'UNKNOWN'}
        if passed and report['first_cause'] is None and (not report['cancelled']):
            report.update(status='PASS', phase='complete')
        custody = {}
        try:
            c.live(end)
            verify(args.caller_manifest_sha256, end)
            if raw_baseline is not None:
                c.need(c.read(private / 'native-worker.json', deadline=end) == raw_baseline, 'caller-original-final-drift')
            report['observations'] = observations(private, end)
            api.writer.save(private / 'caller-result.json', report)
            validate_diagnostic(report['signing_diagnostic'])
            validate_signer_retention(report['signer_retention'])
            public = {'schema_version': 3, 'signing_diagnostic': report['signing_diagnostic'], 'signer_retention': report['signer_retention'], 'addon_profile': PROFILE, 'status': report['status'], 'first_cause': report['first_cause'], 'cancelled': report['cancelled'], 'baseline_packet_sha256': BASELINE, 'addon_manifest_sha256': ADDON, 'caller_manifest_sha256': args.caller_manifest_sha256, 'repository_producer_sha256': config['repository_producer_sha256'], 'source_commit': stamp['source_commit'], 'clock_sha256': args.clock_sha256, 'baseline': report['baseline'], 'addon': report['addon'], 'observations': report['observations'], 'owned_image_absence': report['recovery'].get('baseline', {}).get('owned_image_absence') is True, 'hardware': 'NOT RUN', 'release_selected': False, 'public_admission': False}
            with api.runtime.cancellation_handlers():
                c.publish(out / 'public/status.json', public, custody, end)
                c.live(end)
                verify(args.caller_manifest_sha256, end)
                if raw_baseline is not None:
                    c.need(c.read(private / 'native-worker.json', deadline=end) == raw_baseline, 'caller-original-final-drift')
                api.runtime.check_cancelled()
        except BaseException as error:
            fail('publication-failed', error)
            try:
                report['public_retirement'] = c.retire(custody)
            except BaseException:
                report['public_retirement'] = 'UNKNOWN'
            try:
                api.writer.save(private / 'caller-result.json', report)
            except BaseException:
                pass
        return report

    def retained(value, args, stamp):
        keys = {'signing_diagnostic', 'signer_retention', 'addon_profile', 'schema_version', 'status', 'first_cause', 'cancelled', 'baseline_packet_sha256', 'addon_manifest_sha256', 'caller_manifest_sha256', 'repository_producer_sha256', 'source_commit', 'clock_sha256', 'baseline', 'addon', 'observations', 'owned_image_absence', 'hardware', 'release_selected', 'public_admission'}
        c.need(type(value) is dict and set(value) == keys and (type(value['schema_version']) is int) and (value['schema_version'] == 3 and value['addon_profile'] == PROFILE) and (value['status'] in ('PASS', 'FAIL')) and (type(value['cancelled']) is type(value['owned_image_absence']) is bool) and (value['hardware'] == 'NOT RUN') and (value['release_selected'] is value['public_admission'] is False), 'caller-retained-fields')
        validate_diagnostic(value['signing_diagnostic'])
        validate_signer_retention(value['signer_retention'])
        causes = {None, 'cancelled', 'finalization-failed', 'publication-failed', 'runner-close-failed', 'cache-failed', 'baseline-failed', 'signing-failed', 'addon-failed', 'signer-recovery-failed', 'addon-recovery-failed', 'baseline-recovery-failed'}
        c.need(value['first_cause'] in causes and value['baseline_packet_sha256'] == BASELINE and (value['addon_manifest_sha256'] == ADDON) and (value['caller_manifest_sha256'] == args.caller_manifest_sha256) and (value['repository_producer_sha256'] == args.manifest['files']['producer.py']['sha256']) and (value['source_commit'] == stamp['source_commit']) and (value['clock_sha256'] == args.clock_sha256), 'caller-retained-binding')
        for name, bounds in (('baseline', {'builds': 8, 'comparisons': 4, 'signature_observations': 249}), ('addon', {'builds': 4, 'comparisons': 2, 'signature_observations': 6, 'lifecycle': 1, 'database_productions': 2})):
            row = value[name]
            status = 'ACCEPTED' if name == 'baseline' else 'PROVISIONAL'
            expected = {'status', *bounds}
            if name == 'baseline' and row.get('status') == 'ACCEPTED':
                expected.add('receipt_sha256')
                c.need(type(row['receipt_sha256']) is str and len(row['receipt_sha256']) == 64 and (set(row['receipt_sha256']) <= set('0123456789abcdef')), 'caller-retained-hash')
            c.need(type(row) is dict and set(row) == expected and (row['status'] in (status, 'NOT ACCEPTED')) and all((type(row[k]) is int and row[k] == (v if row['status'] == status else 0) for k, v in bounds.items())), 'caller-retained-counts')
        bounds = {'baseline': {'build_invocations': 8, 'builds_completed': 8, 'comparisons_completed': 4, 'signatures_verified': 249}, 'addon_commands': {'started': 6, 'finished': 6, 'builds_started': 4, 'builds_finished': 4, 'comparisons_finished': 2}, 'addon_signatures': {'entries': 16, 'passed_verifications': 6}}
        c.need(type(value['observations']) is dict and set(value['observations']) == set(bounds), 'caller-retained-observations')
        for name, limits in bounds.items():
            row = value['observations'][name]
            if row is None:
                continue
            c.need(type(row) is dict and set(row) == {'sha256', *limits} and all((type(row[k]) is int and 0 <= row[k] <= v for k, v in limits.items())), 'caller-retained-observation-fields')
            c.need(type(row['sha256']) is str and len(row['sha256']) == 64 and (set(row['sha256']) <= set('0123456789abcdef')), 'caller-retained-hash')
        if value['status'] == 'PASS':
            c.need(value['signing_diagnostic'] == diagnostic('prepared') and value['signer_retention']['result']['status'] == 'PASS', 'caller-retained-signer-pass')
            c.need(value['first_cause'] is None and value['cancelled'] is False and (value['owned_image_absence'] is True) and (value['baseline']['status'] == 'ACCEPTED') and (value['addon']['status'] == 'PROVISIONAL'), 'caller-retained-pass')
        return value

    def main():
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--addon-profile', choices=('topmem-v1', 'fish-history-v1'), required=True)
        parser.add_argument('--phase', choices=('verify', 'proof', 'native', 'addon', 'retain'), required=True)
        parser.add_argument('--caller-manifest-sha256', required=True)
        for name in ('clock', 'tool-policy', 'output', 'offline-cache', 'config'):
            parser.add_argument('--' + name, type=Path)
        for name in ('clock-sha256', 'tool-policy-sha256', 'config-sha256'):
            parser.add_argument('--' + name)
        parser.add_argument('--docker-binary', default='/usr/bin/docker')
        parser.add_argument('--docker-sha256', default='94128e4afada0d46de642165e79dd70beb08e6775014648013283ed901b68248')
        parser.add_argument('--endpoint', default='unix:///var/run/docker.sock')
        args = parser.parse_args()
        try:
            c.need(args.addon_profile == PROFILE, 'caller-cli-profile')
            if args.phase == 'verify':
                verify(args.caller_manifest_sha256)
                return 0
            peek = c.decode(c.pinned(args.clock, args.clock_sha256))
            c.live(peek['deadline_at'])
            lane = module('topmem_clock_bootstrap', ROOT / 'baseline96/lane.py', 'eee4feb256967fc7be90174ab026e08897d2f89aaa0f626653ba1f4cc0b62d20', peek['deadline_at'])
            stamp = lane.clock(args.clock, args.clock_sha256)
            manifest, inputs, source, addon = verify(args.caller_manifest_sha256, stamp['deadline_at'])
            args.manifest = manifest
            api = modules(manifest, source, addon, stamp['deadline_at'])
            if args.phase == 'proof':
                proof(args, manifest, source, addon, api, stamp)
                return 0
            if args.phase == 'addon':
                return addon_child(args, api, stamp)
            if args.phase == 'native':
                return int(execute(args, api, stamp, inputs)['status'] != 'PASS')
            c.live(stamp['deadline_at'])
            raw = c.read(args.output / 'public/status.json', 65536)
            value = c.decode(raw)
            value = retained(value, args, stamp)
            raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
            print(METADATA_PREFIX + base64.b64encode(gzip.compress(raw, mtime=0)).decode(), flush=True)
            c.live(stamp['deadline_at'])
            return 0
        except BaseException:
            print(SCOPE + '-caller-failed', file=sys.stderr)
            return 1

    def execute_addon(api, receipt, config, args, prepared):
        c.need(api.worker.validate_receipt(receipt, config) is receipt, 'caller-execute-baseline-identity')
        c.need(config['addon_profile'] == PROFILE, 'caller-execute-profile')
        if PROFILE != 'fish-history-v1':
            return api.addon.execute(api.worker, receipt, config, ADDON, prepared['key_owner_path'], prepared['key_owner_sha'])
        end = config['work_deadline']
        private = Path(config['jobroot'])
        key = api.addon.key_contract(c, prepared['key_owner_path'], prepared['key_owner_sha'], private, end)
        socket = api.signing.prepared_custody(c, config, end)

        def guard(contract, cutoff):
            c.need(cutoff == end and config['addon_profile'] == PROFILE, 'caller-fish-cutoff')
            selected = api.signing.policy(contract, Path(config['tool_policy']), config['tool_policy_sha256'], config, cutoff)
            c.need(api.signing.prepared_custody(contract, config, cutoff) == socket, 'caller-fish-agent-drift')
            return selected
        guard(c, end)
        with api.runtime.Runner(environment(private), private, private / 'fish-lifecycle-logs', deadline_seconds=7200, deadline_at=end, allowed_sockets={str(socket[0]): socket[1]}) as runner:
            service = SimpleNamespace(poll=lambda: guard(c, end))
            invoke = bridge_bind(c, api.runtime, runner, api.addon, config, receipt['image_id'], key['fingerprint'], service)

            def repository_admit(contract, selected_config, selected_key, cutoff):
                c.need(selected_config is config and selected_key == key and (cutoff == end), 'caller-fish-database-selection')
                policy = guard(contract, cutoff)
                return api.repository.admit(contract, api.addon, api.producer, config, args.caller_manifest_sha256, cutoff, policy)
            facade = SimpleNamespace(graph=api.worker.graph, owner=api.worker.owner, validate_receipt=api.worker.validate_receipt, environment=api.worker.environment, addon_lifecycle=invoke, addon_repository_admit=repository_admit)
            selected = args.manifest['files']['producer.py']
            with api.repository.selected(api.addon, api.producer, BASE / 'producer.py', selected['sha256'], selected['bytes'], args.caller_manifest_sha256, guard, facade, config):
                return api.addon.execute(facade, receipt, config, ADDON, prepared['key_owner_path'], prepared['key_owner_sha'])

    def fish_admission(api, config, raw_baseline, result):
        c.need(config['addon_profile'] == PROFILE, 'caller-fish-profile')
        admitted = fish_admit(c, api, config, raw_baseline, result)
        end = config['work_deadline']
        private = Path(config['jobroot'])
        owner = config[KEY_OWNER]
        key = api.addon.key_contract(c, owner['path'], owner['sha256'], private, end)
        c.need(key['repo_add_sha256'] == config['repository_producer_sha256'], 'caller-fish-v2-owner')
        policy = api.signing.policy(c, Path(config['tool_policy']), config['tool_policy_sha256'], config, end)
        names = api.recovery.repository_names(private / SCOPE / 'repo', end)
        with api.addon.repository_custody(private / SCOPE / 'repo', private, names, key['certificate_sha256'], end) as check:
            produced = api.repository.admit(c, api.addon, api.producer, config, config['caller_manifest_sha256'], end, policy)
            check()
        c.need(type(produced) is int and produced == 2, 'caller-fish-database-count')
        return {'builds': 4, 'comparisons': 2, 'signature_observations': 6, 'lifecycle': 1, 'database_productions': 2, 'status': 'PROVISIONAL'}

    def bridge_bind(contract, runtime, runner, addon, config, image, fingerprint, service):
        root = Path(config['jobroot'])
        cutoff = config['work_deadline']
        frozen = {k: config[k] for k in ('jobroot', 'work_deadline', 'nonce', 'docker_binary', 'endpoint')}
        contract.need(addon.scope == 'fish-history-addon', 'caller-bridge-profile')
        contract.need(runner.env['HOME'] == os.environ['HOME'], 'caller-bridge-home')
        contract.need(callable(getattr(service, 'poll', None)), 'caller-bridge-custody')

        def addon_lifecycle(selected, argv, out, end):
            contract.live(cutoff)
            contract.need(selected is config and end == cutoff and ({k: selected[k] for k in frozen} == frozen), 'caller-bridge-selection')
            contract.need(type(argv) is list and argv == addon.lifecycle_argv(config, image, fingerprint) and (Path(out) == root / 'fish-history-addon'), 'caller-bridge-argv')
            observation = runtime.RunObservation()
            previous = getattr(runner, 'observation', None)
            runner.observation = observation
            try:
                with runner.phase_scope(cutoff):
                    result = runner.run(argv, timeout=min(600, cutoff - time.monotonic()), log='fish-history-lifecycle.log', service=service)
                return (result, observation.summary())
            finally:
                runner.observation = previous
        return addon_lifecycle

    def fish_admit(c, api, config, raw_baseline, result):
        end = config['work_deadline']
        c.live(end)
        private = Path(config['jobroot'])
        c.need(c.read(private / 'native-worker.json', deadline=end) == raw_baseline, 'caller-original-receipt-drift')
        original = c.decode(raw_baseline)
        c.need(api.worker.validate_receipt(original, config) is original, 'caller-addon-baseline-identity')
        c.need(type(result) is dict and set(result) == {'status', 'builds', 'comparisons', 'parent_cleanup_required', 'parent_worker_receipt_unchanged', 'hardware', 'release_selected'}, 'caller-addon-result')
        c.need(result['status'] == 'PROVISIONAL_FISH_HISTORY_NATIVE_ADDON' and type(result['builds']) is int and (result['builds'] == 4) and (type(result['comparisons']) is int) and (result['comparisons'] == 2) and (result['parent_cleanup_required'] is True) and (result['parent_worker_receipt_unchanged'] is True) and (result['hardware'] == 'NOT RUN') and (result['release_selected'] is False), 'caller-addon-result')
        c.need(api.addon.scope == 'fish-history-addon', 'caller-addon-profile')
        out = private / api.addon.scope
        commands = c.decode(c.read(out / 'commands.json', 65536, deadline=end))
        expected = [[v, k] for v in ('current', 'upgrade-fixture') for k in ('build-1', 'build-2', 'compare')]
        c.need(type(commands) is dict and set(commands) == {'scope', 'started', 'finished', 'builds', 'comparisons'} and (commands['scope'] == 'fish-history-addon-only') and (commands['started'] == commands['finished'] == expected) and (type(commands['builds']) is int) and (commands['builds'] == 4) and (type(commands['comparisons']) is int) and (commands['comparisons'] == 2), 'caller-addon-counts')
        owner = config['fish_history_key_owner']
        key = api.addon.key_contract(c, owner['path'], owner['sha256'], private, end)
        journal = c.decode(c.read(out / 'lifecycle-container.json', 65536, deadline=end))
        c.need(type(journal) is dict and set(journal) == {'scope', 'image', 'daemon', 'nonce', 'name', 'argv', 'attempted', 'result', 'cleanup', 'natural', 'evidence_sha256'}, 'caller-addon-lifecycle')
        argv = api.addon.lifecycle_argv(config, original['image_id'], key['fingerprint'])
        c.need(journal['scope'] == 'fish-history-addon-lifecycle' and journal['attempted'] is True and (journal['result'] == 'provisional-zero') and (journal['argv'] == argv) and (journal['image'] == original['image_id']) and (journal['daemon'] == original['daemon']) and (journal['nonce'] == config['nonce']) and (journal['name'] == argv[argv.index('--name') + 1]) and (journal['cleanup'] == 'PARENT RECOVERY REQUIRED'), 'caller-addon-lifecycle')
        api.addon.natural(journal['natural'])
        raw = c.read(out / 'lifecycle-evidence.json', 1024 * 1024, deadline=end)
        c.need(c.sha(raw) == journal['evidence_sha256'], 'caller-addon-evidence-drift')
        body = c.decode(raw)
        api.addon.validate_lifecycle(body)
        c.need(body['nonce'] == config['nonce'] and body['deadline'] == end and (body['fingerprint'] == key['fingerprint']), 'caller-addon-evidence-binding')
        signed = c.decode(b'{"rows":' + c.read(out / 'signatures.json', 1024 * 1024, deadline=end) + b'}')['rows']
        names = api.addon.signing_journal(signed, private, key)
        with api.addon.repository_custody(out / 'repo', private, names, key['certificate_sha256'], end) as check:
            check()
        c.live(end)
        return {'builds': 4, 'comparisons': 2, 'signature_observations': 6, 'lifecycle': 1, 'phases': 7, 'status': 'PROVISIONAL'}
    return SimpleNamespace(main=main, verify=verify, modules=modules, environment=environment, process=process, proof=proof, execute=execute, addon_child=addon_child, addon_admission=addon_admission, retained=retained, execute_addon=execute_addon, fish_admission=fish_admission, c=c, PROFILE=PROFILE, ROOT=ROOT, BASE=BASE, ADDON=ADDON, SCOPE=SCOPE, PROOF_ROWS=PROOF_ROWS)
if __name__ == '__main__':
    selector = argparse.ArgumentParser(add_help=False)
    selector.add_argument('--addon-profile', choices=('topmem-v1', 'fish-history-v1'), required=True)
    chosen, remaining = selector.parse_known_args()
    raise SystemExit(bind(chosen.addon_profile, Path(__file__).resolve().parent).main())
