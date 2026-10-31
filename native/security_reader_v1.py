# SPDX-License-Identifier: MIT
"""Passive finite security component DATA validation; no runtime execution."""
import base64
import json
from pathlib import Path
import re
from common import consumer_contract, need, pin

STATUS = 'PASS_SECURITY_TEST_ALPM_LIFECYCLE_V1'
PAIR = {'archive_equal', 'payload_equal', 'buildinfo_equal', 'pkginfo_equal'}
LIFECYCLE = {'required_signatures', 'installed', 'removed', 'payload_absent', 'inventory_restored',
             'user_data_preserved', 'moved_prefix_absent', 'global_trust_unchanged', 'global_config_unchanged', 'private_homes_absent'}


CLEANUP_MARKER = b'SECURITY_CLEANUP_FAILURE_DATA '
CLEANUP_REFUSAL_MARKER = b'SECURITY_CLEANUP_DIAGNOSTIC_REFUSED '
CLEANUP_LOG_LIMIT = 16 * 1024**2
CLEANUP_LINE_LIMIT = 8192
CLEANUP_ERRORS = {None, 'ValueError', 'OSError', 'PermissionError', 'FileNotFoundError', 'TimeoutExpired', 'Other'}


def _cleanup_require(value):
    if not value:
        raise ValueError('bounded cleanup diagnostic DATA required')


def _cleanup_pin(value, limit):
    _cleanup_require(type(value) is dict and set(value) == {'bytes', 'sha256'}
                     and type(value['bytes']) is int and 0 <= value['bytes'] <= limit
                     and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']))


def validate_cleanup_data(value, map_hash):
    """Validate finite failure DATA only; no cleanup qualification follows."""
    _cleanup_require(type(map_hash) is str and re.fullmatch('[0-9a-f]{64}', map_hash))
    _cleanup_require(type(value) is dict and set(value) == {'schema', 'status', 'source_map_sha256',
        'operation', 'native', 'scope', 'flags', 'retirement'}
        and type(value['schema']) is int and value['schema'] == 1
        and value['status'] == 'SECURITY_INNER_CLEANUP_FAILURE_DATA_ONLY'
        and value['source_map_sha256'] == map_hash and value['operation'] == 'security-alpm-v1'
        and value['native'] == 'NOT_ADMITTED' and value['scope'] == 'DISPOSABLE_IMAGE_INNER_CLEANUP')
    flags = value['flags']
    _cleanup_require(type(flags) is dict and set(flags) == LIFECYCLE
                     and all(flag is None or type(flag) is bool for flag in flags.values()))
    rows = value['retirement']
    _cleanup_require(type(rows) is list and len(rows) == 2)
    roles = []
    for row in rows:
        _cleanup_require(type(row) is dict and set(row) == {'role', 'retired', 'error', 'commands'}
                         and row['role'] in ('signing', 'trust') and type(row['retired']) is bool
                         and (row['error'] is None or type(row['error']) is str)
                         and row['error'] in CLEANUP_ERRORS)
        roles.append(row['role'])
        commands = row['commands']
        _cleanup_require(type(commands) is list and len(commands) <= 2)
        for command in commands:
            _cleanup_require(type(command) is dict and set(command) == {'step', 'exit', 'stdout', 'stderr'}
                             and command['step'] in ('retire-test-home', 'no-autostart-proof')
                             and type(command['exit']) is int and -255 <= command['exit'] <= 255)
            _cleanup_pin(command['stdout'], 262144)
            _cleanup_pin(command['stderr'], 262144)
    _cleanup_require(set(roles) == {'signing', 'trust'})
    return value


def _cleanup_unknown(refused=False):
    value = dict(status='REFUSED_SECURITY_INNER_CLEANUP_DATA_ONLY' if refused else 'ABSENT_SECURITY_INNER_CLEANUP_DATA_ONLY',
                 inner_cleanup='UNKNOWN', native='NOT_ADMITTED', physical_M2='NOT_RUN', release='NOT_ADMITTED')
    if refused:
        value['code'] = 'ORIGINAL_TOOLS_CLEANUP_DATA_UNAVAILABLE_OR_REFUSED'
    return value


def _cleanup_pairs(pairs):
    result = {}
    for key, value in pairs:
        _cleanup_require(key not in result)
        result[key] = value
    return result


def _cleanup_constant(value):
    raise ValueError('bounded cleanup diagnostic DATA required')


def parse_cleanup_data(raw, map_hash):
    """Parse at most four identical literal/BuildKit lines from bounded bytes."""
    try:
        _cleanup_require(type(raw) is bytes and len(raw) <= CLEANUP_LOG_LIMIT)
        found = []
        for line in raw.splitlines():
            if b'SECURITY_CLEANUP_' not in line:
                continue
            _cleanup_require(len(line) <= CLEANUP_LINE_LIMIT)
            match = re.fullmatch(br'(?:(?:#[0-9]+ )?[0-9]+\.[0-9]+ )?(SECURITY_CLEANUP_FAILURE_DATA |SECURITY_CLEANUP_DIAGNOSTIC_REFUSED )([^\r\n]+)', line)
            _cleanup_require(match is not None)
            found.append((match[1], match[2]))
            _cleanup_require(len(found) <= 4 and all(row == found[0] for row in found))
        if not found:
            return _cleanup_unknown()
        marker, encoded = found[0]
        value = json.loads(encoded.decode('utf-8'), object_pairs_hook=_cleanup_pairs, parse_constant=_cleanup_constant)
        if marker == CLEANUP_REFUSAL_MARKER:
            _cleanup_require(type(value) is dict and set(value) == {'schema', 'status', 'source_map_sha256', 'code'}
                             and type(value['schema']) is int and value['schema'] == 1
                             and value['status'] == 'REFUSED_INNER_CLEANUP_DIAGNOSTIC'
                             and value['source_map_sha256'] == map_hash
                             and value['code'] == 'SOURCE_DIAGNOSTIC_SCHEMA_OR_OUTPUT_REFUSED')
            return _cleanup_unknown(True)
        value = validate_cleanup_data(value, map_hash)
        return dict(status='VALIDATED_SECURITY_INNER_CLEANUP_FAILURE_DATA_ONLY', data=value,
                    inner_cleanup='REPORTED_FAILURE_DATA_ONLY', native='NOT_ADMITTED', physical_M2='NOT_RUN', release='NOT_ADMITTED')
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        return _cleanup_unknown(True)


def retained_cleanup_failure(view, files, receipt, binding, map_hash):
    """Read only the same-source original tools-build actor's pinned public log."""
    try:
        _cleanup_require(type(receipt) is dict and receipt.get('binding') == binding
                         and receipt.get('source_map_sha256') == map_hash)
        output = receipt['output_root']; work = Path(output).parent
        _cleanup_require(type(output) is str and Path(output).is_absolute() and '..' not in Path(output).parts
                         and str(Path(output)) == output)
        prefix = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock', 'build', '--network=none',
                  '--pull=false', '--no-cache', '--platform=linux/arm64', '--tag',
                  'native-developer-tools:' + binding['token'], '--label',
                  'org.cachy-asahi.native-developer=' + binding['token'], '--label',
                  'org.cachy-asahi.native-developer.source=' + binding['source']]
        argv = prefix + ['--iidfile', str(work / 'overlay/image-id'), str(work / 'overlay/context')]
        rows = receipt['actors']
        _cleanup_require(type(rows) is list)
        candidates = [(index, row) for index, row in enumerate(rows)
                      if type(row) is dict and row.get('argv') == argv]
        if not candidates:
            return _cleanup_unknown()
        _cleanup_require(len(candidates) == 1)
        index, row = candidates[0]
        _cleanup_require(row.get('log') == str(work / 'actors' / ('%04d.log' % index)))
        name = row.get('public_log')
        _cleanup_require(type(name) is str and re.fullmatch(r'actor-logs/[0-9]{4}\.log', name)
                         and name in files and files[name]['kind'] == 'file')
        expected_pin = {key: files[name][key] for key in ('bytes', 'sha256')}
        _cleanup_pin(expected_pin, CLEANUP_LOG_LIMIT)
        _cleanup_pin(row.get('log_pin'), CLEANUP_LOG_LIMIT)
        _cleanup_require(row['log_pin'] == expected_pin)
        raw = view.read(name)
        _cleanup_require(type(raw) is bytes and len(raw) <= CLEANUP_LOG_LIMIT and pin(raw) == expected_pin)
        return parse_cleanup_data(raw, map_hash)
    except (ValueError, TypeError, KeyError, OSError, UnicodeError, RecursionError, OverflowError):
        return _cleanup_unknown(True)


def validate_result(value, map_hash, inventory):
    need(type(value) is dict and value.get('status') == STATUS and value.get('architecture') == 'aarch64'
         and value.get('source_map_sha256') == map_hash and value.get('packages') == inventory
         and value.get('physical_M2') == 'NOT_RUN' and value.get('native_16K') == 'NOT_QUALIFIED',
         'exact native security identity and non-hardware scope required')
    pair = value.get('pair')
    need(type(pair) is dict and all(pair.get(k) is True for k in PAIR)
         and pair.get('checks') == 'ORIGINAL_CHECK_BOTH', 'two checked clean archives and exact comparison outcomes required')
    archives=pair.get('archives')
    need(type(archives) is dict and set(archives)=={'one','two'},'both original native archives retained as bounded DATA')
    decoded={}
    for label,encoded in archives.items():
        need(type(encoded) is str and len(encoded)<=1024**2,'bounded archive DATA')
        try:raw=base64.b64decode(encoded,validate=True)
        except (ValueError,TypeError):raise ValueError('canonical base64 package DATA required')
        need(base64.b64encode(raw).decode()==encoded and pin(raw)==pair.get(label),'actual retained archive pin differs')
        decoded[label]=raw
    need(decoded['one']==decoded['two'],'actual two archive bytes must compare equal')
    need(value.get('release')=='NOT_ADMITTED' and value.get('remediation')=='NOT_ESTABLISHED','no remediation or release claim')
    lifecycle = value.get('lifecycle')
    need(type(lifecycle) is dict and all(lifecycle.get(k) is True for k in LIFECYCLE),
         'all required-signature install/remove/preservation and private-home outcomes required')
    flows = value.get('workflows')
    need(type(flows) is dict and set(flows) == {'installed', 'moved'}
         and set(flows.values()) == {'PASS_OFFLINE_SECURITY_WORKFLOWS'}, 'both actual packaged offline workflows required')
    return value


def validate_component(view, files, receipt, cleanup, binding, expected, R):
    """Reuse original191 custody, bootstrap, actors, resources and transport rules."""
    map_hash = expected['map_sha256']
    diagnostic = R.retained_consumer_diagnostic(view, files, receipt, binding, map_hash)
    if receipt['status'] != STATUS or cleanup['status'] != 'PASS_EXACT_OWNED_RESOURCES_RETIRED' or not diagnostic['positive_candidate']:
        return dict(status='VALIDATED_NATIVE_SECURITY_FAILURE_DATA_ONLY', binding=binding,
                    owner_status=receipt['status'], cleanup_status=cleanup['status'],
                    consumer_diagnostic=diagnostic,
                    inner_cleanup_diagnostic=retained_cleanup_failure(view, files, receipt, binding, map_hash), native='NOT_ADMITTED', physical_M2='NOT_RUN', release='NOT_ADMITTED')
    R.retained_consumer_diagnostic(view, files, receipt, binding, map_hash, positive=True)
    R.retained_failure_data(view, files, receipt.get('bootstrap_failure_data'), binding, map_hash)
    R.retained_image_lifecycle(view, files, receipt, cleanup, binding, map_hash)
    runner = view.load('bootstrap-proof/bootstrap-runner.json')
    need(runner['kernel']['machine'] in ('aarch64', 'arm64') and runner['docker_server_arch'] in ('aarch64', 'arm64')
         and runner['commit'] == binding['source'] and runner['run_id'] == binding['run']
         and runner['docker_endpoint'] in ('unix:///var/run/docker.sock', 'unix:///run/docker.sock')
         and type(runner['page_size']) is int and runner['page_size'] > 0, 'actual native host/local daemon provenance')
    before, after = view.load('consumer-inspect.json'), view.load('consumer-after.json')
    for row in (before, after):
        need(row['Id'] == receipt['consumer']['container'], 'retained exact security export consumer ID')
        consumer_contract(row, binding, receipt['consumer']['image'], receipt['source_root'], receipt['output_root'], runner['uid'], runner['gid'])
        need(row['Config']['Entrypoint'] == ['/usr/bin/python3']
             and row['Config']['Cmd'] == ['-I', '-B', '/source/native/security_native_v1.py', '--export',
                  '--output', '/out/journey', '--map-sha256', map_hash], 'exact finite security DATA export consumer')
    need(after['State'] == receipt['consumer']['state'] and after['State']['Running'] is False
         and after['State']['ExitCode'] == 0 and after['State']['Status'] == 'exited', 'actual completed security export consumer')
    phases = receipt['provisioning']
    R.retained_transport_proof(view, files, phases['transport'], binding, map_hash)
    need(phases['proof']['status'] == 'PASS_EXACT_PUBLISHED_SOURCE_PROOF_ONLY'
         and phases['transport']['status'] == 'PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY'
         and phases['cache']['status'] == 'PASS_EIGHT_INPUT_CACHE_DATA_ONLY', 'complete hosted source and input DATA provisioning')
    for phase in phases.values():
        need(phase['binding'] == binding and phase['source_map_sha256'] == map_hash, 'all provisioning same exact source and run')
    for row in phases['proof']['actors'] + phases['transport']['actors'] + receipt['actors'] + cleanup['actors']:
        name = row.get('public_log')
        need(name in files and files[name]['kind'] == 'file' and row['status'] == 'PASS' and row['exit'] == 0
             and row['natural_exit'] is True and row['group_absent'] is True and row['retirement'] == 'REAPED'
             and row['exit_observed_via_waitpid'] is True and row['ownership_lost'] is False and row['forced_cleanup'] is False
             and row['leader_held_until_group_inspection'] is True and pin(view.read(name)) == row['log_pin'],
             'original direct owned actor retirement and exact retained logs required')
    guest = validate_result(view.load('journey/result.json'), map_hash, receipt['input_inventory'])
    need(not any(name.startswith('journey/') and name != 'journey/result.json' for name in files),
         'security export retains only the finite public result; no original private workflow trees')
    return dict(status='VALIDATED_NATIVE_SECURITY_TEST_ALPM_COMPONENT_EVIDENCE_ONLY', binding=binding,
                execution_scope='DISPOSABLE_NATIVE_IMAGE_BUILD_STAGE; consumer exports finite DATA only',
                native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN', remediation='NOT_ESTABLISHED', release='NOT_ADMITTED')
