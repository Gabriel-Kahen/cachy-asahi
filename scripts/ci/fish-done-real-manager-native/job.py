#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact hosted proof, accepted ordered retirement and finite original-byte retention."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import closed as C


def prove(root, output):
    manifest = C.verify(root)
    caller = C.load(root/'scripts/ci/welcome-native/ci/caller.py', 'held_done_source_caller')
    result = caller.prove(root, manifest, os.environ)
    result['manifest_sha256'] = C.digest(root/C.MANIFEST)
    result['consumer_token'] = hashlib.sha256(('fish-done-real-manager:'+result['run_id']+':'+
        result['run_attempt']+':'+result['source_sha']).encode()).hexdigest()[:32]
    C.save(output, result)
    return result


def cleanup(root, base, runtime, proof_path, output, transport=None):
    proof = json.loads(C.read(proof_path))
    C.verify(root, proof['manifest_sha256'])
    if transport is not None and (transport/'report.json').exists():
        transferred = json.loads(C.read(transport/'report.json'))
        if transferred['status'] == 'FAIL_RETAINED_INPUT_TRANSPORT_DATA':
            C.need(transferred['proof'] == proof and not any(os.path.lexists(p) for p in (base, runtime)),
                   'same-owner failed transport without native evidence required')
            carrier = C.safe(Path(transferred['carrier_path']))
            C.need(carrier == C.safe(Path(transferred['runner_temp']))/'fish-done-retained574' and
                   not carrier.is_relative_to(root) and not root.is_relative_to(carrier),
                   'failed DATA must remain outside source')
            result = dict(status='INPUT_TRANSPORT_FAILED_BEFORE_NATIVE_ACTORS_DIAGNOSTIC_ONLY',
                proof=proof, transport_report_sha256=C.digest(transport/'report.json'),
                partial_data_path=str(carrier), partial_data_preserved=True,
                native='NOT_RUN', native_cleanup='NOT_ESTABLISHED', acceptance=False)
            C.save(output, result)
            return result
    held = C.held_job(root)
    result = dict(status='FAIL', consumer='NOT_OBSERVED', producer='NOT_RETIRED')
    try:
        result['consumer'] = held.retire_consumers(runtime, base, proof)
        if (base/'report.json').exists():
            row = held.invoke(['python3', '-I', '-B', str(root/'scripts/ci/maintained_desktop574.py'),
                'cleanup', '--inputs', str(root/'scripts/ci/maintained-desktop574-inputs.json'),
                '--output', str(base), '--job-token', proof['job_token']])
            C.need(row.returncode == 0, 'accepted original574 cleanup failed; unknown ownership preserved')
            result['producer'] = json.loads(C.read(base/'report.json'))['owned_cleanup']
            C.need(result['producer']['status'] == 'PASS', 'producer retirement not verified')
        else:
            result['producer'] = 'NOT_STARTED'
        result['status'] = 'PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP'
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error)[:1024])
    C.save(output, result)
    return result


def retain(root, base, runtime, proof_path, cleanup_path, output, transport=None):
    proof = json.loads(C.read(proof_path))
    C.verify(root, proof['manifest_sha256'])
    C.need(not output.exists(), 'fresh finite public evidence directory required')
    output.mkdir(mode=0o755)
    report = dict(status='FAIL_OR_INCOMPLETE', files={}, errors=[], total_bytes=0,
                  native_hardware='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED')

    def copy(path, name, cap=16*1024**2):
        try:
            raw = C.read(path, cap)
            C.need(len(report['files']) < 1024 and report['total_bytes']+len(raw) <= 96*1024**2,
                   'closed public count/byte limit')
            target = output/name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            report['files'][name] = C.pin(raw)
            report['total_bytes'] += len(raw)
        except Exception as error:
            report['errors'].append(name+': '+str(error)[:256])

    copy(proof_path, 'source-proof.json')
    copy(cleanup_path, 'ordered-cleanup.json')
    if transport is not None:
        copy(transport/'report.json', 'transport/report.json')
        copy(transport/'commands.json', 'transport/commands.json')
        try:
            rows = json.loads(C.read(transport/'commands.json'))
            C.need(type(rows) is list and len(rows) <= 5, 'bounded partial transport commands required')
            for row in rows:
                C.need(type(row['index']) is int and 1 <= row['index'] <= 5, 'fixed transport stream index required')
                for suffix in ('stdout', 'stderr'):
                    name = 'command-'+str(row['index'])+'.'+suffix
                    copy(transport/name, 'transport/'+name, 2*1024**2)
        except Exception as error:
            report['errors'].append('transport streams: '+str(error)[:512])
    for name in sorted(C.files(root)):
        copy(root/name, 'source/'+name)
    for name in ('report.json', 'installed-packages.lock', 'retained-inputs.json'):
        copy(base/name, 'base/'+name)
    for name in ('owner.json', 'report.json'):
        copy(runtime/name, 'runtime/'+name)
    for phase in ('build', 'trial'):
        directory = runtime/phase
        for name in ('report.json', 'command.json', 'stdout', 'stderr', 'export-map.json'):
            copy(directory/name, 'runtime/'+phase+'/'+name)
        try:
            runner = C.load(C.HERE/'run.py', 'closed_done_export_gate')
            rows = runner.export_gate(directory)
            for name in sorted(rows):
                C.need(not Path(name).is_absolute() and '..' not in Path(name).parts,
                       'safe phase export path required')
                copy(directory/'export'/name, 'runtime/'+phase+'/export/'+name)
                C.need(report['files']['runtime/'+phase+'/export/'+name] == rows[name],
                       'retained original export byte differs')
        except Exception as error:
            report['errors'].append(phase+' export: '+str(error)[:512])
    C.save(output/'retention.json', report)
    try:
        gate = C.load(C.HERE/'root_contract.py', 'independent_done_root_contract')
        gate.validate(output, proof['source_sha'], proof['run_id'], proof['run_attempt'], require_retained_pass=False)
        C.need(not report['errors'], 'finite public retention incomplete')
        report['status'] = 'PASS_NATIVE_INSTALLED_REAL_MANAGER_RETIRED'
    except Exception as error:
        report['errors'].append(str(error)[:1024])
    C.save(output/'retention.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('proof', 'cleanup', 'retain'))
    for name in ('source', 'base', 'runtime', 'proof', 'cleanup', 'output', 'transport'):
        parser.add_argument('--'+name, type=Path)
    args = parser.parse_args()
    root = C.safe(args.source.absolute())
    if args.phase == 'proof':
        value = prove(root, args.proof.absolute())
    elif args.phase == 'cleanup':
        value = cleanup(root, args.base.absolute(), args.runtime.absolute(), args.proof.absolute(), args.output.absolute(),
                        args.transport.absolute() if args.transport else None)
    else:
        value = retain(root, args.base.absolute(), args.runtime.absolute(), args.proof.absolute(),
                       args.cleanup.absolute(), args.output.absolute(), args.transport.absolute() if args.transport else None)
    print(json.dumps(value, indent=2))
    raise SystemExit(value['status'] not in ('SOURCE_PROOF_PASS',
        'PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP', 'PASS_NATIVE_INSTALLED_REAL_MANAGER_RETIRED'))
