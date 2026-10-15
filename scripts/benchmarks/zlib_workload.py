#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare existing benchmark configs and run fixed, verified zlib roundtrips.

Elapsed time includes Python, process startup, file I/O and verification. This
adapter never grants hardware or optimization acceptance and never builds code.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import zlib

import benchmark

EXPERIMENTS = {
    'ARM-C01': ('lto', '288f19f4459ea0aa7c8bfac217c3cc649933f999', '45ffafb3f060a00f6933c1c6146a58b989187c88725572370627071be38e63a9'),
    'ARM-C02': ('o3', '98a7fea506bda1e69abb0fa7c8a9b23cbcb6c3a8', 'b76784832a577cc05ce16090300ff09031631c377f5f8c5a30dcf24641305812'),
    'ARM-C03': ('pgo', '8e6d0c46b5f6ca0789e2b3da45b456599f832b7b', '4ea105b5d7e51175f8fd46f73b09c114c8555d754593a9df3dadd69383131f61'),
    'ARM-C04': ('m2', '330deff795cd53373c45e6677fb9dd3fd74658ad', '5de4c689959e8b82c904505c4415827e8630e95d0c39eecc1702f6545cd360ae')}
SOURCE_SHA = 'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
MAX_PAYLOAD = 64 * 1024**2
MAX_FILE = 8 * 1024**2
OPERATOR_FIELDS = {'experiment_id', 'machine_id', 'base_id', 'execution_context', 'hardware_gate_evidence',
                   'order', 'minimum_trials', 'timeout_seconds', 'sample_seconds', 'controls', 'thresholds'}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def file_bytes(path, limit=MAX_FILE):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'bounded regular input required: ' + str(path))
    return path.read_bytes()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(file_bytes(path).decode('utf-8'))


def bounds(payload_bytes, iterations):
    need(type(payload_bytes) is int and 1 <= payload_bytes <= MAX_PAYLOAD, 'payload bytes must be 1..67108864')
    need(type(iterations) is int and 1 <= iterations <= 32, 'iterations must be 1..32')


def materials(root, archive_manifest, experiment=None):
    """Check only the exact selected programs and held-out input; never execute."""
    root = root.resolve(strict=True)
    need(root.is_dir(), 'extracted artifact directory required')
    receipt_bytes = file_bytes(archive_manifest)
    receipt = json.loads(receipt_bytes.decode('utf-8'))
    selected = [key for key in EXPERIMENTS if receipt.get('purpose') == key + '-same-job-followup']
    need(len(selected) == 1 and (experiment is None or selected[0] == experiment), 'native export experiment differs')
    experiment = selected[0]
    variant, source, manifest_sha = EXPERIMENTS[experiment]
    need(sha(receipt_bytes) == manifest_sha, 'exact native archive manifest hash differs')
    need(receipt.get('source_commit') == source and receipt.get('source_sha256') == SOURCE_SHA
         and receipt.get('development_only') is True and receipt.get('selected_for_release') is False,
         'native export source or development scope differs')
    pins = receipt['files']
    names = ('baseline-1/minigzip', variant + '-1/minigzip', 'corpus/manifest.json', 'corpus/heldout-source.bin')
    for name in names:
        need(sha(file_bytes(root / name)) == pins.get(name), 'native export file hash differs: ' + name)
    manifest = read_json(root / 'corpus/manifest.json')
    rows = manifest['files']
    need(len({r['path'] for r in rows}) == len(rows), 'duplicate corpus paths refused')
    selected = [row for row in rows if row.get('path') == 'heldout-source.bin']
    need(len(selected) == 1 and selected[0].get('role') == 'heldout' and selected[0].get('kind') == 'input',
         'heldout-source.bin must be held-out input, never training')
    payload = file_bytes(root / 'corpus/heldout-source.bin')
    need(payload and selected[0].get('bytes') == len(payload) and selected[0].get('sha256') == sha(payload),
         'held-out corpus bytes differ')
    return experiment, root, payload


def prepare_config(args):
    bounds(args.payload_bytes, args.iterations)
    experiment, root, _ = materials(args.artifact_root, args.archive_manifest, args.experiment)
    operator = read_json(args.operator_config)
    need(OPERATOR_FIELDS <= set(operator) and set(operator) <= OPERATOR_FIELDS | {'power_domains'},
         'operator config must provide actual required fields without adapter overrides')
    need(operator['execution_context'] == 'physical', 'physical operator config required')
    need(isinstance(operator['hardware_gate_evidence'], str) and Path(operator['hardware_gate_evidence']).is_absolute(),
         'absolute operator hardware-gate evidence path required')
    variant = EXPERIMENTS[experiment][0]
    baseline, candidate = str(root / 'baseline-1/minigzip'), str(root / (variant + '-1/minigzip'))
    python, driver = str(Path(sys.executable).resolve()), str(Path(__file__).resolve())
    archive = str(args.archive_manifest.resolve(strict=True))
    corpus_manifest, heldout = str(root / 'corpus/manifest.json'), str(root / 'corpus/heldout-source.bin')
    config = {**operator, 'workload_id': f'{experiment}-heldout-roundtrip-{args.payload_bytes}B-{args.iterations}x-level6',
              'change': {'variable': 'compiled-zlib-variant', 'environment_key': 'ZLIB_MINIGZIP',
                         'baseline': baseline, 'candidate': candidate,
                         'rationale': experiment + ' exact native baseline versus ' + variant + '; no gain assumed'},
              'argv': [python, '-B', driver, 'run', '--archive-manifest', archive, '--corpus-manifest', corpus_manifest,
                       '--input', heldout, '--payload-bytes', str(args.payload_bytes), '--iterations', str(args.iterations)],
              'inputs': [python, driver, str(Path(benchmark.__file__).resolve()), archive, corpus_manifest, heldout],
              'env': {'LC_ALL': 'C'},
              'variant_env': {'baseline': {'ZLIB_MINIGZIP': baseline}, 'candidate': {'ZLIB_MINIGZIP': candidate}},
              'variant_inputs': {'baseline': [baseline], 'candidate': [candidate]}, 'allowed_state_changes': []}
    benchmark.validate_config(config)
    benchmark.write_json(args.output, config)
    return config


def run_workload(args):
    bounds(args.payload_bytes, args.iterations)
    root = args.corpus_manifest.resolve(strict=True).parent.parent
    experiment, root, heldout = materials(root, args.archive_manifest)
    need(args.corpus_manifest.resolve(strict=True) == root / 'corpus/manifest.json'
         and args.input.resolve(strict=True) == root / 'corpus/heldout-source.bin', 'exact retained held-out input required')
    selected = Path(os.environ.get('ZLIB_MINIGZIP', ''))
    allowed = [root / 'baseline-1/minigzip', root / (EXPERIMENTS[experiment][0] + '-1/minigzip')]
    need(selected.is_absolute() and selected in allowed, 'selected minigzip must be a pinned experiment artifact')
    need(selected.stat().st_mode & 0o111, 'retained minigzip must remain executable')
    cwd = Path.cwd()
    need(not any(cwd.iterdir()), 'empty isolated workload cwd required')
    payload = (heldout * ((args.payload_bytes + len(heldout) - 1) // len(heldout)))[:args.payload_bytes]
    payload_file = cwd / 'payload.bin'
    with payload_file.open('xb') as stream:
        stream.write(payload)
    checks = []
    for iteration in range(args.iterations):
        encoded, decoded = cwd / 'encoded.gz', cwd / 'decoded.bin'
        for phase, argv, source, target in (
                ('encode', [str(selected), '-6'], payload_file, encoded),
                ('decode', [str(selected), '-d'], encoded, decoded)):
            errors = cwd / f'{iteration:02d}-{phase}.stderr'
            with source.open('rb') as stdin, target.open('xb') as stdout, errors.open('xb') as stderr:
                # Stay in the existing benchmark process group for its cleanup.
                result = subprocess.run(argv, stdin=stdin, stdout=stdout, stderr=stderr, timeout=60)
            file_bytes(errors, 4 * 1024**2)
            need(result.returncode == 0, 'minigzip ' + phase + ' failed')
            if phase == 'encode':
                compressed = file_bytes(encoded, MAX_PAYLOAD + 1024**2)
            else:
                output = file_bytes(decoded, MAX_PAYLOAD)
        decoder = zlib.decompressobj(31)
        independent = decoder.decompress(compressed, len(payload) + 1)
        need(output == payload and independent == payload and decoder.eof
             and not decoder.unused_data and not decoder.unconsumed_tail, 'minigzip or independent gzip roundtrip differs')
        checks.append({'iteration': iteration, 'encoded_sha256': sha(compressed), 'decoded_sha256': sha(output)})
        encoded.unlink(); decoded.unlink()
    report = {'status': 'PASS', 'experiment': experiment, 'minigzip': str(selected), 'minigzip_sha256': sha(file_bytes(selected)),
              'heldout_sha256': sha(heldout), 'payload_sha256': sha(payload), 'payload_bytes': len(payload),
              'iterations': args.iterations, 'compression_level': 6, 'checks': checks,
              'timing_scope': 'Whole driver including Python, process startup, file I/O and correctness verification',
              'hardware_validation': 'NOT RUN', 'optimization_acceptance': 'NOT RUN'}
    print(json.dumps(report, sort_keys=True))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare-config', help='Validate retained inputs and write ordinary benchmark config; no execution')
    prepare.add_argument('--experiment', choices=EXPERIMENTS, required=True)
    prepare.add_argument('--artifact-root', type=Path, required=True)
    prepare.add_argument('--operator-config', type=Path, required=True)
    prepare.add_argument('--output', type=Path, required=True)
    run = commands.add_parser('run', help='Run only the selected pinned minigzip against fixed held-out bytes')
    run.add_argument('--corpus-manifest', type=Path, required=True)
    run.add_argument('--input', type=Path, required=True)
    for command in (prepare, run):
        command.add_argument('--archive-manifest', type=Path, required=True)
        command.add_argument('--payload-bytes', type=int, default=32 * 1024**2)
        command.add_argument('--iterations', type=int, default=8)
    args = parser.parse_args(argv)
    try:
        prepare_config(args) if args.command == 'prepare-config' else run_workload(args)
    except (ValueError, OSError, KeyError, TypeError, zlib.error, subprocess.SubprocessError) as error:
        print('zlib workload refused: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
