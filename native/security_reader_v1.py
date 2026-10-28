# SPDX-License-Identifier: MIT
"""Passive finite security component DATA validation; no runtime execution."""
import base64
import re
from common import consumer_contract, need, pin

STATUS = 'PASS_SECURITY_TEST_ALPM_LIFECYCLE_V1'
PAIR = {'archive_equal', 'payload_equal', 'buildinfo_equal', 'pkginfo_equal'}
LIFECYCLE = {'required_signatures', 'installed', 'removed', 'payload_absent', 'inventory_restored',
             'user_data_preserved', 'moved_prefix_absent', 'global_trust_unchanged', 'global_config_unchanged', 'private_homes_absent'}


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
                    consumer_diagnostic=diagnostic, native='NOT_ADMITTED', physical_M2='NOT_RUN', release='NOT_ADMITTED')
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
