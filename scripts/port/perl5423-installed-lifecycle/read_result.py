#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Read-only finite result consistency checks; Root retains acceptance authority."""
import argparse
import importlib.util
import io
from pathlib import Path
import tarfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('perl_installed_common', HERE / 'common.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)


def review(args):
    evidence = Path(args.evidence); source = Path(args.inputs)
    C.source(source, args.source_map_sha256)
    raw = C.read(evidence / 'producer-report.json', 8*1024**2)
    C.need(C.pin(raw)['sha256'] == args.producer_report_sha256, 'externally retained original producer report hash')
    producer = C.decode(raw)
    C.need(producer['source_map_sha256'] == args.source_map_sha256
           and producer['status'] == 'PASS_PRODUCED_PERL_INSTALLED_LIFECYCLE_DATA_REQUIRES_INDEPENDENT_ROOT_REVIEW'
           and producer['first_failure'] is None
           and producer['cleanup'] == dict(status='OWNED_CONTAINER_REMOVED', natural=True), 'complete naturally retired original producer')
    C.need([row['step'] for row in producer['commands']] == ['image','daemon-architecture','daemon-storage','create',
        'inspect-before','run','inspect-after','export','cleanup-inspect','remove-owned'], 'exact finite producer command sequence')
    for row in producer['commands']:
        C.need(row['success'] is True and row['returncode'] == row['lifecycle'].get('exit') == 0
               and C.natural(row['lifecycle']), 'natural successful producer command')
        for channel in ('stdout','stderr'):
            body = C.read(evidence / (row['step'] + '.' + channel),64*1024**2) if row[channel]['bytes'] else b''
            C.need(C.pin(body) == row[channel], 'original producer command channel pin')
    exported = C.read(evidence / 'export.stdout', 64*1024**2)
    members = {}; total = 0
    with tarfile.open(fileobj=io.BytesIO(exported), mode='r:') as archive:
        for member in archive:
            parts = Path(member.name).parts
            C.need(parts and parts[0] == 'result' and len(parts) <= 2 and '..' not in parts, 'flat exact original actor export')
            if len(parts) == 1:
                C.need(member.isdir(), 'ordinary result root'); continue
            name = parts[1]
            C.need(name not in members and member.isfile() and not member.sparse and 0 <= member.size <= 16*1024**2,
                   'unique bounded actor result file')
            total += member.size; C.need(total <= 64*1024**2 and len(members) < 160, 'actor export budget')
            body = archive.extractfile(member).read(member.size + 1)
            C.need(len(body) == member.size, 'complete actor export')
            members[name] = body
    actor_raw = members.get('report.json', b'')
    C.need(actor_raw and C.pin(actor_raw) == producer['actor_report']
           and C.read(evidence / 'data/report.json', 16*1024**2) == actor_raw, 'same original exported actor report')
    actor = C.decode(actor_raw)
    C.need(actor['status'] == 'PASS_FINITE_NATIVE_ARM4K_PERL_INSTALLED_LIFECYCLE'
           and actor['source_map_sha256'] == args.source_map_sha256
           and actor['admission_sha256'] == producer['admission_sha256'] and actor['first_failure'] is None
           and actor['cleanup']['failures'] == [] and actor['cleanup']['user_fixture_absent'] is True,
           'same admitted complete actor lifecycle')
    C.need(actor['stages'] == ['baseline','upgrade','repeat','noop','rollback'], 'all five actual lifecycle stages')
    required = {'unknown-test-key','tampered-signature','trusted-upgrade','trusted-repeat','trusted-noop','trusted-rollback'}
    C.need(required <= {r['step'] for r in actor['commands']}, 'all trusted transitions/refusals required')
    for row in actor['commands']:
        C.need(row['success'] is True and C.natural(row['lifecycle'])
               and row['returncode'] == row['lifecycle']['exit'], 'actual natural actor command')
        C.need(row['returncode'] != 0 if row['expected'] is None else row['returncode'] == row['expected'], 'exact positive/refusal command result')
        for channel in ('stdout','stderr'):
            name = row['step'] + '.' + channel
            C.need(name in members and C.pin(members[name]) == row[channel], 'original actual actor channel pin')
    expected = C.inventory(C.read(source / 'expected349.lock'))
    for row in actor['commands']:
        if row['step'].startswith('inventory-'):
            actual = C.inventory(members[row['step'] + '.stdout'],
                dict(line.split(' ',1) for line in members[row['step']+'.stdout'].decode().splitlines())['perl'])
            C.need(actual == dict(expected,perl=actual['perl']) and actual['perl'] in ('5.42.3-1','5.42.3-1.3'),
                   'all349 ordinary package versions; exact Perl substitution only')
    for stage in actor['stages']:
        C.need(C.decode(members['probe-' + stage + '.stdout']) == actor[stage]['probe'], 'same actual installed Perl probe')
        C.need(actor[stage]['probe']['libperl_maps'] == ['/usr/lib/perl5/5.42/core_perl/CORE/libperl.so'],
               'actual installed libperl mapping')
    C.need(actor['baseline']['database']['normalized'] == actor['rollback']['database']['normalized']
           and actor['rollback_comparison']['status'] == 'PASS'
           and actor['rollback_comparison']['account_residuals'] == [], 'exact rollback database/account comparison')
    C.need(actor['native16K'] == actor['M2'] == actor['performance'] == 'NOT_RUN'
           and actor['release'] == 'NOT_ACCEPTED', 'bounded installed-component scope')
    return dict(schema=1, status='PASS_READONLY_ORIGINAL_RESULT_CONSISTENCY_ONLY',
                source_map_sha256=args.source_map_sha256, producer_report=C.pin(raw), actor_report=C.pin(actor_raw),
                native_acceptance='ROOT_INDEPENDENT_REVIEW_REQUIRED', M2='NOT_RUN', release='NOT_ACCEPTED')


if __name__ == '__main__':
    C.need(__import__('sys').flags.isolated, 'isolated Python required')
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('evidence','inputs','source-map-sha256','producer-report-sha256'):
        p.add_argument('--' + name, required=True)
    print(C.encode(review(p.parse_args())).decode(), end='')
