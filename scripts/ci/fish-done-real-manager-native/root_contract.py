#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root's offline original-byte replay. Requires explicit actual source/run/attempt."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import closed as C


def read(path):
    return json.loads(C.read(path))


def actual_delivery(result, binding, outer):
    C.need(result['native_arch'] == dict(name='aarch64', elf_machine=183) and
           result['package_context'] == 'alpm-installed' and result['native_arm'] == 'ACTUAL_AARCH64_ONLY' and
           outer['exit'] == 0 and outer['process_group_absent'] is True and
           binding['package_context'] == 'alpm-installed' and
           binding['installed']['status'] == 'VERIFIED_ALPM_INSTALLED_PAYLOAD', 'actual native installed delivery required')


def validate(public, source_sha, run_id, attempt, *, require_retained_pass=True):
    C.safe(public)
    C.need(re.fullmatch('[0-9a-f]{40}', source_sha) and re.fullmatch('[1-9][0-9]{0,19}', run_id) and
           re.fullmatch('[1-9][0-9]{0,9}', attempt), 'explicit exact actual source/run/attempt required')
    retention = read(public/'retention.json')
    if require_retained_pass:
        C.need(retention['status'] == 'PASS_NATIVE_INSTALLED_REAL_MANAGER_RETIRED' and not retention['errors'],
               'native public retention is failed or incomplete')
    actual = {}
    for path in public.rglob('*'):
        C.need(not path.is_symlink(), 'public evidence aliases refused')
        if path.is_file() and path != public/'retention.json':
            actual[str(path.relative_to(public))] = C.pin(C.read(path))
    C.need(actual == retention['files'] and len(actual) <= 1024 and
           sum(r['bytes'] for r in actual.values()) == retention['total_bytes'] <= 96*1024**2,
           'whole retained original-byte membership/hash/size differs')
    source = public/'source'
    proof = read(public/'source-proof.json')
    manifest = C.verify(source, proof['manifest_sha256'])
    reserved = C.load(source/C.DATA/'reserved_process.py', 'root_reserved_process_receipt_gate')
    C.need(proof['status'] == 'SOURCE_PROOF_PASS' and proof['source_sha'] == proof['workflow_sha'] == source_sha and
           proof['run_id'] == run_id and proof['run_attempt'] == attempt, 'actual source/workflow/run join differs')
    token = hashlib.sha256(('fish-done-real-manager:'+run_id+':'+attempt+':'+source_sha).encode()).hexdigest()[:32]
    C.need(proof['consumer_token'] == token, 'exact current consumer token differs')
    base = read(public/'base/report.json')
    owner = read(public/'runtime/owner.json')
    runtime = read(public/'runtime/report.json')
    ordered = read(public/'ordered-cleanup.json')
    C.need(base['status'] == 'PASS_NATIVE_OFFLINE_574_TRANSACTION' and
           base['ownership']['token'] == proof['job_token'] and
           base['owned_cleanup']['status'] == 'PASS' and
           base['owned_cleanup']['image'] == dict(id=base['image'], absence_verified=True) and
           base['owned_cleanup']['probe']['absence_verified'] is True, 'original574 ownership/retirement absent')
    C.need(C.read(public/'base/installed-packages.lock') == C.read(source/C.DATA/'inventory574.lock'),
           'actual original574 inventory differs')
    C.need(runtime['status'] == 'PASS_NATIVE_BUILD_AND_INSTALLED_REAL_MANAGER_PENDING_RETIREMENT' and
           runtime['image'] == owner['image'] == base['image'] and owner['token'] == runtime['ownership_token'] == token and
           runtime['base_lock_sha256'] == C.digest(public/'base/installed-packages.lock') and
           len(owner['containers']) == len(set(owner['containers'])) == 2 and
           [r['phase'] for r in runtime['phases']] == ['build', 'trial'], 'two exact registered consumers required')
    C.need(ordered['status'] == 'PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP' and
           ordered['consumer']['status'] == 'PASS_CONSUMERS_RETIRED' and
           [r['container'] for r in ordered['consumer']['containers']] == list(reversed(owner['containers'])) and
           all(r['absence_verified'] is True and r['status'] == 'PASS' for r in ordered['consumer']['containers']) and
           ordered['producer'] == base['owned_cleanup'], 'trial/build then original producer retirement required')
    for phase in ('build', 'trial'):
        directory = public/'runtime'/phase
        report = read(directory/'report.json')
        row = next(r for r in runtime['phases'] if r['phase'] == phase)
        C.need(row['report_sha256'] == C.digest(directory/'report.json') and
               row['export_map_sha256'] == C.digest(directory/'export-map.json') and
               report['phase'] == phase and report['ordinary_uid'] == 1000 and
               report['ordinary_absent'] is True and type(report['adopted_reaping']) is list,
               'actual ordinary phase/retained receipt join differs')
        exports = read(directory/'export-map.json')
        physical = {str(p.relative_to(directory/'export')): C.pin(C.read(p))
                    for p in (directory/'export').rglob('*') if p.is_file()}
        C.need(exports == physical, 'phase export map/original bytes differ')
        C.need(read(directory/'export/wrapper/commands.json') == report['commands'] and
               all(r['exit'] == 0 and r['group_absent'] is True for r in report['commands']),
               'ordinary wrapper command registry/retirement differs')
        for command in report['commands']:
            reserved.assert_verified(command['supervision'])
            C.need(command['exit'] == command['supervision']['exit'] and
                   command['pid'] == command['supervision']['pid'] and
                   command['group_absent'] is command['supervision']['group_absent'],
                   'wrapper status must equal actual reserved-process receipt')
            C.need(type(command['index']) is int and 0 < command['index'] < 256, 'bounded wrapper command index required')
            for suffix in ('stdout','stderr'):
                path=directory/'export/wrapper'/('command-'+str(command['index'])+'.'+suffix)
                C.need(C.pin(C.read(path)) == command[suffix], 'original wrapper stream/hash differs')
    built = public/'runtime/build/export'
    build = read(built/'native-build-result.json')
    C.need(build['status'] == 'PASS_NATIVE_AARCH64_HEADLESS_DEPENDENCY_BUILD_ONLY' and not build['errors'] and
           build['native_arch'] == 'aarch64' and type(build['page_size']) is int and build['page_size'] > 0 and
           build['installed_delivery'] == 'NOT_RUN' and build['context_sha256'] == manifest['context_sha256'] and
           len(build['commands_planned']) == 5 and all(r['exit'] == 0 and r['group_absent'] is True
                                                     for r in build['commands']), 'actual offline native build incomplete')
    C.need(read(public/'runtime/build/report.json')['status'] == 'PASS_NATIVE_HEADLESS_BUILD',
           'ordinary native build wrapper failed')
    C.need(read(built/'commands.json') == build['commands'], 'original command registry differs')
    for row in build['commands']:
        reserved.assert_verified(row['supervision'])
        C.need(row['exit'] == row['supervision']['exit'] and row['pid'] == row['supervision']['pid'] and
               row['group_absent'] is row['supervision']['group_absent'], 'native status/reservation receipt differs')
        C.need(re.fullmatch(r'command-[1-9][0-9]{0,2}\.log', row['log']) and
               C.pin(C.read(built/row['log'])) == {k: row[k] for k in ('bytes', 'sha256')},
               'original native command log/hash differs')
    # Metadata-only reuse of the exact reviewed recipe ELF checker. No native executable runs.
    checker = C.load(source/C.DATA/'native_build.py', 'root_native_elf_metadata')
    for name in ('tools/sway', 'tools/swaymsg', 'libs/libwlroots-0.19.so'):
        raw = C.read(built/name)
        checker.elf(raw, aligned=True)
        C.need(C.pin(raw) == {k: build['outputs'][name][k] for k in ('bytes', 'sha256')},
               'retained native ELF/output provenance differs')
    trial_dir = public/'runtime/trial'
    trial = read(trial_dir/'report.json')
    C.need(trial['status'] == 'PASS_NATIVE_INSTALLED_REAL_MANAGER_12_AND_OLD18', 'actual installed wrapper failed')
    observations=read(trial_dir/'export/alpm-observations.json')
    base_inventory=dict(line.split() for line in C.read(source/C.DATA/'inventory574.lock').decode().splitlines())
    done=read(source/C.DATA/'delivery/done-lock.json')
    C.need(observations == trial['alpm_observations'] and [r['phase'] for r in observations] == ['install','remove'] and
           observations[0]['inventory'] == base_inventory | {done['name']:done['version']} and
           observations[1]['inventory'] == base_inventory and
           observations[1]['ordinary_before'] == observations[1]['ordinary_after'] and
           all(r['protected_preserved'] is True for r in observations) and trial['protected_preserved'] is True and
           trial['base_restored_sha256'] == C.digest(source/C.DATA/'inventory574.lock') and
           trial['trust'] == 'UNSIGNED_LOCAL_TEST_PACKAGE_ONLY', 'actual575 install/574 restoration/preservation differs')
    orphans=read(trial_dir/'export/orphan-reaping.json')
    C.need(orphans['remaining'] == [] and orphans['adopted'] == trial['adopted_reaping'] and
           trial['remaining_ordinary_processes'] == [], 'ordinary backend/orphan retirement absent')
    delivered = trial_dir/'export/delivery'
    result = read(delivered/'result.json')
    binding = read(delivered/'bindings.json')
    outer = read(delivered/'outer.json')
    replay = C.load(source/C.DATA/'delivery/replay.py', 'root_real_wire_replay')
    replay.validate(result)
    actual_delivery(result, binding, outer)
    C.need(binding['installed'] == trial['installed_payload'] == observations[0]['payload'] and
           binding['installed']['files'] == {name:row['sha256'] for name,row in done['payload'].items()},
           'namespace actual installed payload and ALPM observations differ')
    lock = read(source/C.DATA/'build.lock.json')
    C.need(result['daemon']['sha256'] == lock['native_mako_payload']['/usr/bin/mako'] and
           binding['inputs']['tools']['mako']['sha256'] == result['daemon']['sha256'],
           'real selected native Mako executable differs')
    for name in ('sway', 'swaymsg'):
        C.need(binding['inputs']['tools'][name]['sha256'] == build['outputs']['tools/'+name]['sha256'],
               'actual delivery compositor differs from actual native build')
    C.need(len(binding['inputs']['libraries']) == 1 and
           binding['inputs']['libraries'][0]['sha256'] == build['outputs']['libs/libwlroots-0.19.so']['sha256'] and
           set(binding['diagnostic_sources']) == set(read(source/C.DATA/'delivery/source-pins.json')) and
           binding['diagnostic_sources'] == {name: C.digest(source/C.DATA/'delivery'/name)
                                            for name in binding['diagnostic_sources']}, 'delivery library/helper differs')
    old = read(trial_dir/'export/old18/receipt.json')
    C.need(old['status'] == 'PASS' and old['machine'] == 'aarch64' and len(old['cases']) == 18 and
           all(r['exit'] == 0 for r in old['cases'].values()), 'unchanged installed18 controls incomplete')
    payload = read(source/C.DATA/'delivery/done-lock.json')['payload']
    C.need(old['wrapper_sha256'] == payload['usr/share/cachy-asahi/fish-done/opt-in.fish']['sha256'] and
           old['runtime_sha256'] == payload['usr/share/cachy-asahi/fish-done/done.fish']['sha256'],
           'old18 did not invoke exact installed module')
    for code in ('7', '143'):
        C.need(any('Failed ('+code+')' in p['argv'][6] for p in old['cases']['background']['proofs']),
               'real PROCESS_EXIT failure/signal proof absent')
    timeout_path = trial_dir/'export/old18/transport-timeout/notifications.jsonl'
    raw = C.read(timeout_path)
    timeout_rows = [json.loads(line) for line in raw.splitlines()]
    C.need(len(timeout_rows) == 1 and trial['timeout_pid_proof'] ==
           dict(pid=timeout_rows[0]['pid'], absent=True, raw_sha256=C.pin(raw)['sha256']) and
           old['cases']['transport-timeout']['proofs'][0]['invocation']['argv'] == timeout_rows[0]['argv'] and
           old['cases']['transport-timeout']['proofs'][0]['elapsed_seconds'] < 4.5,
           'exact forced-timeout named PID absence/raw join missing')
    return dict(status='PASS_ROOT_REPLAY_NATIVE_BUILD_AND_INSTALLED_MANAGER', source_sha=source_sha,
                run_id=run_id, attempt=attempt, manager_cases=12, real_notifications=4,
                installed_original_controls=18, scope='GENERIC_NATIVE_CPU_SWAY_PRIVATE_MAKO_ONLY',
                physical_M2='NOT_RUN', Hyprland_presentation='NOT_QUALIFIED', release='NOT_ADMITTED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public', type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--attempt', required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.public.absolute(), args.source_sha, args.run_id, args.attempt), indent=2))
