# SPDX-License-Identifier: MIT
"""Passive capsule DATA reader; refuse NULL selectors before opening capsule.

Symlink targets are ordinary DATA payloads. No capsule member is extracted,
imported or followed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import consumer_contract, load, need, pin, uv_policy
from capsule import open_capsule


def validate(capsule_path, expected):
    need(type(expected) is dict and set(expected) == {'source', 'ref', 'run', 'map_sha256'}
         and re.fullmatch('[0-9a-f]{40}', expected.get('source') or '')
         and isinstance(expected.get('ref'), str) and expected['ref'].startswith('refs/heads/codex/')
         and re.fullmatch('[1-9][0-9]*', expected.get('run') or '')
         and re.fullmatch('[0-9a-f]{64}', expected.get('map_sha256') or ''), 'NULL/unbound actual native evidence refused before reading')
    view = open_capsule(capsule_path)
    binding = {k: expected[k] for k in ('source', 'ref', 'run')}
    binding.update(attempt=1, token=hashlib.sha256((binding['source'] + ':' + binding['ref'] + ':' + binding['run']).encode()).hexdigest()[:24])
    manifest = view.load('artifacts.json')
    need(manifest['schema'] == 1 and manifest['binding'] == binding
         and manifest['source_map_sha256'] == expected['map_sha256'], 'actual binding differs')
    files = manifest['files']
    need(type(files) is dict and all(type(row.get('bytes')) is int and row['bytes'] >= 0
         and re.fullmatch('[0-9a-f]{64}', row.get('sha256') or '') for row in files.values()), 'typed artifact pins')
    need(0 < len(files) <= 3000 and sum(row['bytes'] for row in files.values()) <= 32*1024**2, 'bounded artifact namespace')
    view.verify_manifest(manifest)
    if 'provision-diagnostic.json' in files:
        diagnostic = view.load('provision-diagnostic.json')
        need(diagnostic['binding'] == binding and diagnostic['source_map_sha256'] == expected['map_sha256']
             and diagnostic['status'] == 'DIAGNOSTIC_HOSTED_INPUT_PROVISIONING_ONLY'
             and diagnostic['native'] == diagnostic['GPG'] == diagnostic['ALPM'] == 'NOT_RUN', 'actual DATA diagnostic only')
        return dict(status='VALIDATED_INPUT_PROVISIONING_DIAGNOSTIC_NOT_NATIVE', binding=binding, native='NOT_RUN', physical_M2='NOT_RUN')
    receipt = view.load('receipt.json'); cleanup = view.load('cleanup.json')
    need(receipt['binding'] == binding and receipt['source_map_sha256'] == expected['map_sha256']
         and receipt['status'] == 'PASS_NATIVE_DEVELOPER_COMPONENTS_ONLY'
         and cleanup['status'] == 'PASS_EXACT_OWNED_RESOURCES_RETIRED', 'all native components plus actual resource retirement required')
    runner = view.load('bootstrap-proof/bootstrap-runner.json')
    need(runner['kernel']['machine'] in ('aarch64', 'arm64') and runner['docker_server_arch'] in ('aarch64', 'arm64')
         and runner['commit'] == binding['source'] and runner['run_id'] == binding['run']
         and runner['docker_endpoint'] in ('unix:///var/run/docker.sock', 'unix:///run/docker.sock')
         and type(runner['page_size']) is int and runner['page_size'] > 0, 'actual native host/local daemon provenance')
    before = view.load('consumer-inspect.json'); after = view.load('consumer-after.json')
    for row in (before, after):
        need(row['Id'] == receipt['consumer']['container'], 'retained exact consumer ID')
        consumer_contract(row, binding, receipt['consumer']['image'], receipt['source_root'], receipt['output_root'], runner['uid'], runner['gid'])
    need(after['State'] == receipt['consumer']['state'] and after['State']['Running'] is False
         and after['State']['ExitCode'] == 0 and after['State']['Status'] == 'exited', 'actual completed consumer daemon state')
    phases = receipt['provisioning']
    need(phases['proof']['status'] == 'PASS_EXACT_PUBLISHED_SOURCE_PROOF_ONLY'
         and phases['transport']['status'] == 'PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY'
         and phases['cache']['status'] == 'PASS_EIGHT_INPUT_CACHE_DATA_ONLY', 'complete hosted source and input DATA provisioning')
    for phase in phases.values():
        need(phase['binding'] == binding and phase['source_map_sha256'] == expected['map_sha256'], 'all provisioning same exact source and run')
    for row in phases['proof']['actors'] + phases['transport']['actors'] + receipt['actors'] + cleanup['actors']:
        need(row.get('public_log') in files and files[row['public_log']]['kind'] == 'file', 'actor log must be a retained ordinary artifact')
        need(row['status'] == 'PASS' and row['exit'] == 0 and row['natural_exit'] is True
             and row['group_absent'] is True and row['retirement'] == 'REAPED'
             and row['exit_observed_via_waitpid'] is True and row['ownership_lost'] is False
             and row['forced_cleanup'] is False and row['leader_held_until_group_inspection'] is True
             and pin(view.read(row['public_log'])) == row['log_pin'], 'direct owned wait and retained actor output required')
    guest = view.load('journey/result.json')
    need(guest['status'] == receipt['status'] and guest['architecture'] == 'aarch64'
         and guest['packages'] == receipt['input_inventory'] and guest['physical_M2'] == 'NOT_RUN'
         and guest['native_16K'] == 'NOT_QUALIFIED', 'actual guest identity and non-hardware boundary')
    need(guest['python']['status'] == 'PASS_LOCAL_PYTHON_PEP517_WORKFLOW'
         and guest['python']['build_protocol'] == 'FORCE_PEP517_PRIVATE_PINNED_UV_BUILD_NO_BUILD_ISOLATION_NO_INDEX'
         and guest['extension']['status'] == 'PASS_LOCAL_COMPILED_PYTHON_WORKFLOW'
         and set(guest['build_systems']['project_workflows']) == {'cmake', 'meson'}
         and {r['status'] for r in guest['build_systems']['project_workflows'].values()} == {'PASS_REAL_PROJECT_WORKFLOW'}, 'all component outcomes including actual PEP517')
    for name, feature in [('python', guest['python']), ('extension', guest['extension']), ('build-systems', guest['build_systems'])]:
        need(feature['commands'], 'actual feature commands')
        for row in feature['commands']:
            log = 'journey/' + name + '/' + row['log']
            need(log in files and files[log]['kind'] == 'file' and pin(view.read(log)) == row['log_pin'], 'raw feature command log pin differs')
            state = row['supervision']
            need(row['success'] is True and state['reaped'] is True and state['ownership'] == 'REAPED'
                 and state['group_census'] == 'EMPTY_TWICE' and state['output_complete'] is True
                 and state['error'] is None and not state['timeout'] and not state['signals'], 'feature owned retirement required')
    builds = [row['argv'] for row in guest['python']['commands'] if 'build' in row['argv']]
    need(builds and all('--force-pep517' in row and '--no-build-isolation' in row and '--offline' in row and '--no-index' in row for row in builds), 'actual forced offline PEP517 argv')
    need(guest['python']['installed_backend']['identity']['version'] == '0.11.28'
         and guest['python']['installed_backend']['identity']['builtin_frontend'] is False, 'real separate backend import identity')
    policy = uv_policy(Path(__file__).resolve().parents[1])
    frontend = next(row for row in policy['artifacts'] if row['role'] == 'frontend')
    backend = next(row for row in policy['artifacts'] if row['role'] == 'backend')
    need(guest['python']['frontend']['file'] == {k:frontend['member'][k] for k in ('bytes','sha256')}
         and guest['python']['backend'] == backend, 'exact source-pinned frontend and separate backend receipt')
    installed = guest['python']['installed_backend']
    for name, expected_file in installed['files'].items():
        need(name.startswith('/out/journey/python/venv/'), 'backend receipt path confined to private venv')
        relative = name.removeprefix('/out/')
        need(relative in files and files[relative]['kind'] == 'file'
             and {k:files[relative][k] for k in ('bytes','sha256')} == expected_file, 'retained backend installation bytes')
    for member in backend['verified_members']:
        target = installed['identity']['backend'] if member['name'].endswith('.data/scripts/uv-build') else str(Path(installed['identity']['module']).parent / member['name'].removeprefix('uv_build/'))
        need(installed['files'].get(target) == {k:member[k] for k in ('bytes','sha256')}, 'actual backend binary/shim equals original wheel payload')
    return dict(status='VALIDATED_NATIVE_DEVELOPER_COMPONENT_EVIDENCE_ONLY', binding=binding,
                python_wheel='ACTUAL_PEP517_COMPONENT_PASS', native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN', release='NOT_ADMITTED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capsule', type=Path, required=True, help='ordinary public-tree.tar; directory ingress is unsupported')
    parser.add_argument('--binding', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.capsule, load(args.binding)), sort_keys=True))
