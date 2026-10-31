# SPDX-License-Identifier: MIT
"""Passive finite security component DATA validation; no runtime execution."""
import base64
import json
from pathlib import Path
import re
from common import consumer_contract, load, need, pin, read

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


UPGRADE_PROTOCOL='signed-prior-to-current-v1'
UPGRADE_FLAGS=frozenset(('prior_clean_checked','prior_installed','prior_payload_owned','tampered_signature_refused',
    'declined_precommit_preserved','version_upgrade','candidate_payload_owned','old_payload_absent',
    'repeat_same_version_reinstalled','user_data_preserved','removed','reinstalled','final_removed'))
UPGRADE_STEPS=('prior-required-install','prior-inventory','upgrade-signature-refusal','refusal-prior-inventory',
    'decline-upgrade-precommit','declined-prior-inventory','required-install','installed-inventory',
    'repeat-current','repeated-inventory','remove','removed-inventory','reinstall-current',
    'reinstalled-inventory','remove-reinstalled','final-removed-inventory')


def validate_observation(value,policy):
    """A real callback/filesystem witness; no interrupted-commit or recovery credit."""
    need(type(policy)is dict and policy['schema']==1 and policy['protocol']=='first-real-upgrade-zero-observation-v1'
         and policy['phase']=='AFTER_OLD_REMOVAL_BEFORE_CANDIDATE_EXTRACTION' and policy['record_cap']==16384 and policy['value_cap']==32768
         and policy['libalpm_version']=='16.0.1' and pin(policy['source'].encode('ascii'))==policy['source_pin'],
         'exact source-pinned finite ALPM observer policy')
    keys={'schema','protocol','phase','observer_source','observer_compiled','raw_pin','records','runtime','owner_pid',
          'witness_paths','source_binary_correspondence','interruption','recovery','raw_ascii','compiler_retirement'}
    need(type(value)is dict and set(value)==keys and type(value['schema'])is int and value['schema']==1
         and value['protocol']==policy['protocol'] and value['phase']==policy['phase']
         and value['observer_source']==policy['source_pin'] and value['witness_paths']=={k:policy[k]for k in('old_only','new_only')}
         and value['source_binary_correspondence']=='OPEN' and value['interruption']==value['recovery']=='NOT_RUN',
         'closed observation-only scope; no invented interruption/recovery claim')
    need(len(json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii'))<=policy['value_cap'],
         'bounded serialized observation role')
    for row,cap in ((value['observer_compiled'],1024**2),(value['raw_pin'],policy['record_cap'])):
        _cleanup_pin(row,cap);need(row['bytes']>0,'nonempty bounded observer DATA')
    retired=value['compiler_retirement']
    need(type(retired)is dict and set(retired)=={'pid','exit','natural_exit','group_absent',
         'leader_held_until_group_inspection','exit_observed_via_waitpid','ownership_lost','retirement',
         'forced_cleanup','cleanup_member_uids','elapsed_seconds'}
         and type(retired['pid'])is int and retired['pid']>1 and type(retired['exit'])is int and retired['exit']==0
         and all(retired[k]is True for k in('natural_exit','group_absent','leader_held_until_group_inspection','exit_observed_via_waitpid'))
         and retired['ownership_lost']is retired['forced_cleanup']is False and retired['retirement']=='REAPED'
         and retired['cleanup_member_uids']==[] and type(retired['elapsed_seconds'])in(int,float)
         and 0<=retired['elapsed_seconds']<=195,'new compiler role requires bounded natural reserved owned retirement')
    runtime=value['runtime'];need(type(runtime)is dict and set(runtime)=={'pacman','libalpm'},'actual binary identity roles')
    for label,row in runtime.items():
        need(type(row)is dict and set(row)=={'bytes','sha256','inode'},'closed runtime binary pin')
        _cleanup_pin({k:row[k]for k in('bytes','sha256')},16*1024**2)
        need(type(row['inode'])is list and len(row['inode'])==2 and all(type(x)is int and x>0 for x in row['inode']),
             'actual runtime device/inode')
    need(runtime['libalpm']['sha256']==policy['libalpm_sha256'],'pinned original actual libalpm16 binary')
    raw=value['raw_ascii'];need(type(raw)is str and 0<len(raw)<=policy['record_cap'] and raw.isascii()
         and raw.endswith('\n') and len(raw.splitlines())==2 and pin(raw.encode('ascii'))==value['raw_pin'],
         'complete bounded original callback bytes and external pin')
    def pairs(values):
        result={}
        for key,entry in values:
            need(key not in result,'duplicate callback record field');result[key]=entry
        return result
    rows=value['records'];need(type(rows)is list and len(rows)==2
         and rows==[json.loads(line,object_pairs_hook=pairs)for line in raw.splitlines()],
         'exact original callback plus normal-exit observer records')
    point,end=rows
    need(type(point)is dict and set(point)=={'type','pid','ppid','event','percent','howmany','current','old_only_errno',
         'new_only_errno','old_desc_errno','new_desc_errno','lock','pacman_inode','libalpm_inode','symbol_object_verified'},'closed genuine callback DATA')
    need(point['type']=='FIRST_UPGRADE_ZERO' and type(point['pid'])is int and point['pid']>1
         and type(value['owner_pid'])is int and value['owner_pid']>1 and point['ppid']==value['owner_pid']
         and point['pid']!=point['ppid'] and all(type(point[k])is int for k in('ppid','event','percent','howmany','current',
               'old_only_errno','new_only_errno','old_desc_errno','new_desc_errno'))
         and type(point['symbol_object_verified'])is int and point['symbol_object_verified']==1
         and (point['event'],point['percent'],point['howmany'],point['current'])==(1,0,1,1),
         'first real exact-package one-target UPGRADE0 callback')
    need(all(point[k]==2 for k in('old_only_errno','new_only_errno','old_desc_errno','new_desc_errno')),
         'direct ENOENT old-only/new-only and old/new desc witnesses required; no intact old DB claim')
    lock=point['lock'];need(type(lock)is dict and set(lock)=={'dev','ino','mode','uid','gid','nlink','bytes'}
         and all(type(v)is int for v in lock.values())and lock['dev']>0 and lock['ino']>0
         and (lock['mode'],lock['uid'],lock['gid'],lock['nlink'],lock['bytes'])==(0o100000,0,0,1,0),
         'actual live libalpm empty mode000 root-owned lock, never unlink it here')
    need(point['pacman_inode']==runtime['pacman']['inode']and point['libalpm_inode']==runtime['libalpm']['inode'],
         'callback actual pacman/libalpm identity joins')
    need(type(end)is dict and set(end)=={'type','pid','registrations','hits','errors'}and end['type']=='END'
         and all(type(end[k])is int for k in('pid','registrations','hits','errors'))
         and (end['pid'],end['registrations'],end['hits'],end['errors'])==(point['pid'],1,1,0),
         'normal exit observer, one registration, one first callback, no observation error')
    return value


def validate_upgrade(value, contract, baseline):
    """Closed version-transition DATA; this never runs ALPM or grants Root acceptance."""
    need(type(contract)is dict and type(contract.get('schema'))is int and contract['schema']==1
         and contract.get('protocol')==UPGRADE_PROTOCOL and contract.get('from_version')=='0.1.0-1'
         and contract.get('to_version')=='0.1.0-2','reviewed genuine prior-to-current source contract')
    need(type(baseline)is bytes and len(baseline)<=1024**2 and len(baseline.splitlines())==349,'whole retained349 baseline DATA')
    need(type(value)is dict,'finite native upgrade result DATA')
    upgrade=value.get('upgrade')
    need(type(upgrade)is dict and set(upgrade)=={'schema','protocol','from_version','to_version','prior_source',
         'prior_archive','prior_archive_base64','prior_payload','flags','inventories','abort_scope','repeat_scope',
         'upgrade_scope','decline_input','observation'} and type(upgrade['schema'])is int and upgrade['schema']==1
         and upgrade['protocol']==UPGRADE_PROTOCOL and upgrade['from_version']==contract['from_version']
         and upgrade['to_version']==contract['to_version'],'closed actual upgrade protocol/version DATA')
    need(upgrade['prior_source']=={name:contract['prior_'+name]for name in ('bundle','profile','adapter')},'actual upgrade binds genuine prior source/profile/adapter')
    for row in upgrade['prior_source'].values():
        _cleanup_pin(row,2*1024**2);need(row['bytes']>0,'nonempty original prior source inputs')
    encoded=upgrade['prior_archive_base64'];need(type(encoded)is str and len(encoded)<=1024**2,'bounded genuine prior native archive DATA')
    try:raw=base64.b64decode(encoded,validate=True)
    except (ValueError,TypeError):raise ValueError('canonical prior native archive DATA required')
    need(0<len(raw)<=1024**2 and base64.b64encode(raw).decode()==encoded and pin(raw)==upgrade['prior_archive'],'actual prior archive bytes/pin')
    _cleanup_pin(upgrade['prior_archive'],1024**2)
    payload=upgrade['prior_payload'];expected={'usr/'+name:{key:row[key]for key in ('bytes','sha256')}for name,row in contract['prior_payload_files'].items()}
    need(type(payload)is dict and len(expected)==27 and set(payload)==set(expected)|{'.PKGINFO','.BUILDINFO','.MTREE'}
         and all(payload[name]==row for name,row in expected.items()),'complete27 original prior payload plus native metadata pins')
    for row in payload.values():
        _cleanup_pin(row,8*1024**2);need(row['bytes']>0,'nonempty original prior package DATA')
    flags=upgrade['flags'];need(type(flags)is dict and set(flags)==UPGRADE_FLAGS and all(flag is True for flag in flags.values()),'all mandatory upgrade/refusal/abort/repeat/reinstall/preservation DATA required')
    need(upgrade['abort_scope']=='OPERATOR_DECLINED_BEFORE_COMMIT; NOT_SIGNAL_OR_POWERLOSS'
         and upgrade['repeat_scope']=='SAME_VERSION_REINSTALL' and upgrade['upgrade_scope']=='ONE_PACKAGE_VERSION_TRANSITION_ONLY'
         and upgrade['decline_input']==pin(b'n\n'),'precise operator-abort/repeat limits; no midcommit crash claim')
    prior=pin(b''.join(sorted(baseline.splitlines(keepends=True)+[b'cachy-asahi-security-maintenance 0.1.0-1\n'])))
    current=pin(b''.join(sorted(baseline.splitlines(keepends=True)+[b'cachy-asahi-security-maintenance 0.1.0-2\n'])))
    wanted={name:pin(baseline)for name in ('baseline','removed','final')}
    wanted.update({name:prior for name in ('prior_installed','after_refusal','after_decline')})
    wanted.update({name:current for name in ('upgraded','repeated','reinstalled')})
    need(upgrade['inventories']==wanted,'exact349/350 real version transition/refusal/abort/reinstall inventory pins')
    commands=value.get('commands');need(type(commands)is list and 1<=len(commands)<=512,'finite actual version transition command records')
    negative={'unknown-key-refusal','required-untrusted-install-refusal','upgrade-signature-refusal','decline-upgrade-precommit'}
    counts={}
    for row in commands:
        need(type(row)is dict and set(row)=={'step','exit','stdout','stderr'} and type(row['step'])is str
             and re.fullmatch('[a-z][a-z0-9-]{0,63}',row['step']) and type(row['exit'])is int
             and -255<=row['exit']<=255,'finite original upgrade command schema')
        for channel in ('stdout','stderr'):_cleanup_pin(row[channel],2*1024**2)
        need(row['exit']==1 if row['step']in ('upgrade-signature-refusal','decline-upgrade-precommit') else (row['exit']!=0 if row['step']in negative else row['exit']==0),'actual required success/refusal/decline exit')
        counts[row['step']]=counts.get(row['step'],0)+1
    need(tuple(row['step']for row in commands if row['step']in UPGRADE_STEPS)==UPGRADE_STEPS
         and all(counts.get(name)==1 for name in negative),'actual distinct ordered upgrade/refusal/abort/repeat/reinstall commands')
    need(all(counts.get(name)==27 for name in ('prior-owner','refused-prior-owner','declined-prior-owner'))
         and all(counts.get(name)==29 for name in ('candidate-owner','repeated-owner','reinstalled-owner')),
         'both versions repeated actual ALPM payload ownership checks')
    validate_observation(upgrade['observation'],contract['observation'])
    steps=[row['step']for row in commands]
    need(counts.get('compile-upgrade-observer')==1
         and steps.index('declined-prior-inventory')<steps.index('compile-upgrade-observer')<steps.index('required-install'),
         'one new reserved compiler role after decline and before genuine upgrade')
    return upgrade


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
    root=Path(__file__).resolve().parents[1]
    baseline=read(root/'native/expected349.lock');need(pin(baseline)==inventory,'upgrade baseline matches original retained dependency inventory')
    validate_upgrade(value,load(root/'native/security-contract-v1.json')['upgrade'],baseline)
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
    return dict(status='VALIDATED_NATIVE_SECURITY_SIGNED_UPGRADE_WITH_CHECKPOINT_OBSERVATION_COMPONENT_EVIDENCE_ONLY', binding=binding,
                upgrade_protocol=UPGRADE_PROTOCOL,from_version='0.1.0-1',to_version='0.1.0-2',
                abort_scope=guest['upgrade']['abort_scope'],repeat_scope=guest['upgrade']['repeat_scope'],
                upgrade_scope='ONE_PACKAGE_VERSION_TRANSITION_ONLY',
                prior_scope='GENUINE_PRIOR_RECIPE_REBUILT_NOW; NOT_PREVIOUS_NATIVE_RELEASE',
                execution_scope='DISPOSABLE_NATIVE_IMAGE_BUILD_STAGE; consumer exports finite DATA only',
                native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN', remediation='NOT_ESTABLISHED', release='NOT_ADMITTED')
