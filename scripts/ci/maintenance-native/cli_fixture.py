#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Fresh actual-time signed TEST DATA through the staged/installed maintenance CLI."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import time

MODULES = tuple('scripts/maintenance/' + n + '.py' for n in
    ('health', 'update_plan', 'rebuild_plan', 'signing_expiry', 'security_advisories')) + tuple(
    'scripts/release/' + n + '.py' for n in ('check_source_pins', 'compare_releases', 'release', 'source_delivery'))
ENV = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', TZ='UTC')
CAP = 2 * 1024**2
LABELS = ('authenticated-context', 'health-json-one', 'health-json-two', 'health-text-one', 'health-text-two',
          'all-observations-unavailable', 'wrong-signer', 'wrong-release-digest', 'wrong-observations-digest',
          'wrong-observation-generation', 'symlink-index', 'tampered-signed-payload')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute path required')
    return path


def snapshot(root):
    values = {}
    for path in sorted(root.rglob('*')):
        need(len(values) < 256, 'fixture node bound')
        info = path.lstat()
        if path.is_symlink():
            values[path.relative_to(root).as_posix()] = dict(type='link', target=os.readlink(path))
        elif path.is_file():
            need(info.st_size <= CAP, 'fixture file byte bound')
            values[path.relative_to(root).as_posix()] = dict(type='file', mode=stat.S_IMODE(info.st_mode),
                uid=info.st_uid, gid=info.st_gid, **pin(path.read_bytes()))
        else:
            need(path.is_dir(), 'fixture special file refused')
    return values


def packaged(cli):
    cli = ordinary(cli)
    need(cli.is_file() and cli.name == 'cachy-asahi-maintenance', 'installed maintenance executable required')
    runtime = cli.parents[1] / 'lib/cachy-asahi/maintenance'
    need({p.relative_to(runtime).as_posix() for p in runtime.rglob('*') if p.is_file()} == set(MODULES),
         'exact nine-file installed private closure required')
    sources = {name: pin(ordinary(runtime / name).read_bytes()) for name in MODULES}
    proof = json.loads(ordinary(cli.parents[1] / 'share/doc/cachy-asahi-maintenance/source-provenance.json').read_bytes())
    need({name: {k: row[k] for k in ('bytes', 'sha256')} for name, row in proof['files'].items()} == sources,
         'packaged source provenance differs from private bytes')
    spec = importlib.util.spec_from_file_location('maintenance_fixture_health', runtime / MODULES[0])
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    need(h.ROOT == runtime, 'health imported a checkout instead of installed closure')
    return h, runtime, sources


def run(cli, work):
    cli, work = ordinary(cli), ordinary(work)
    info = work.stat()
    need(work.is_dir() and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700
         and not list(work.iterdir()), 'owned empty 0700 work directory required')
    h, runtime, sources = packaged(cli)
    cli_pin, receipts = pin(cli.read_bytes()), []

    def save(name, value):
        path = work / name
        need(not path.exists() and not path.is_symlink(), 'fresh fixture output required')
        raw = value if type(value) is bytes else encoded(value)
        need(len(raw) <= CAP, 'fixture output byte bound')
        with path.open('xb') as stream:
            stream.write(raw)
        path.chmod(0o600)
        return dict(path=str(path), sha256=pin(raw)['sha256'])

    def command(label, argv, expected=0):
        need(re.fullmatch('[a-z0-9-]{1,80}', label) and len(receipts) < 32, 'bounded command identity required')
        result = subprocess.run(list(map(str, argv)), cwd=work, env=dict(ENV, HOME=str(work)),
                                capture_output=True, timeout=60)
        need(len(result.stdout) + len(result.stderr) <= CAP, 'command output byte bound')
        save(label + '.stdout', result.stdout)
        save(label + '.stderr', result.stderr)
        receipts.append(dict(case=label, argv=list(map(str, argv)), returncode=result.returncode,
                             expected_returncode=expected, stdout=pin(result.stdout), stderr=pin(result.stderr)))
        need(result.returncode == expected, label + ': ' + result.stderr.decode(errors='replace')[-1200:])
        if expected:
            need(not result.stdout and b'Traceback' not in result.stderr, 'clean input refusal required')
        return result.stdout

    signing = work / 'TEST-signing-secret'
    signing.mkdir(mode=0o700)
    repository = work / 'synthetic-repository'
    repository.mkdir(mode=0o700)
    gpg = ['/usr/bin/gpg', '--no-options', '--batch', '--homedir', str(signing),
           '--no-auto-key-retrieve', '--pinentry-mode', 'loopback', '--passphrase', '']
    started = int(time.time())
    try:
        command('generate-actual-time-test-key', gpg + ['--quick-generate-key',
                'TEST ONLY maintenance fixture <maintenance@test.invalid>', 'ed25519', 'sign', '1d'])
        listing = command('list-actual-time-test-key', gpg + ['--with-colons', '--list-keys']).decode()
        fingerprints = [row.split(':')[9] for row in listing.splitlines() if row.startswith('fpr:')]
        need(len(fingerprints) == 1 and re.fullmatch('[A-F0-9]{40}', fingerprints[0]), 'one fresh TEST signer required')
        key = fingerprints[0]
        key_created = int(next(row.split(':')[5] for row in listing.splitlines() if row.startswith('pub:')))
        need(started <= key_created <= int(time.time()), 'fresh actual-time key creation required')
        public = command('export-test-public-certificate', gpg + ['--armor', '--export', key])
        certificate = save('TEST-public.asc', public)
        keyenv = dict(ENV, HOME=str(signing), GNUPGHOME=str(signing))
        releases = []
        for number, version in ((1, '1.0-1'), (2, '1.1-1')):
            inputs = work / ('release-inputs-' + str(number))
            inputs.mkdir(mode=0o700)
            archive = inputs / ('fixture-' + version + '-any.pkg.tar.gz')
            metadata = ('pkgname = fixture\npkgver = ' + version + '\npkgdesc = Synthetic TEST only\n'
                'url = https://invalid.example/fixture\nbuilddate = ' + str(int(time.time())) + '\n'
                'packager = TEST ONLY\nsize = 8\narch = any\nlicense = MIT\ndepend = virtual-runtime>=2\n')
            with tarfile.open(archive, 'w:gz') as tar:
                for name, raw in {'.PKGINFO': metadata.encode(), 'usr/share/fixture/config': b'TEST fixture\n'}.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(raw)
                    tar.addfile(member, io.BytesIO(raw))
            base = dict(schema_version=1, snapshot_id='synthetic-snapshot', target_arch='aarch64',
                kind='complete-target-transaction', packages=[
                    dict(name='linux-asahi', version='1-1', arch='aarch64', depend=[], provides=[],
                         conflict=[], files=['boot/asahi-fixture']),
                    dict(name='runtime', version='2-1', arch='aarch64', depend=[], provides=['virtual-runtime=2'],
                         conflict=[], files=['usr/lib/fixture.so'])])
            (inputs / 'base.json').write_bytes(encoded(base))
            (inputs / 'provenance.json').write_bytes(encoded(dict(schema_version=1,
                artifact_sha256=h.r.sha(archive), package=dict(name='fixture', version=version, arch='any'),
                source_commit='a' * 40, recipe_sha256='b' * 64, licenses=['MIT'],
                sources=[dict(url='fixture://synthetic-test-source', sha256='c' * 64)],
                build=dict(execution='synthetic', architecture='aarch64', environment='TEST fixture only',
                           snapshot_id='synthetic-snapshot'))))
            def ref(name):
                return dict(path=name, sha256=h.r.sha(inputs / name))
            specification = dict(schema_version=1, release_id='fixture-' + str(number), synthetic=True,
                target_arch='aarch64', repo_name='fixture', source_commit='a' * 40,
                base=dict(ref('base.json'), snapshot_id='synthetic-snapshot'),
                packages=[dict(artifact=ref(archive.name), provenance=ref('provenance.json'))],
                policy=dict(supported_models=['m2-air-13'], selected_packages=['fixture'],
                            protected_packages=['linux-asahi'], coordinated_sets=[
                                dict(name='synthetic-runtime', versions={'runtime': '2-1'})]), evidence=[])
            specpath = inputs / 'spec.json'
            specpath.write_bytes(encoded(specification))
            staged = h.r.stage(argparse.Namespace(spec=str(specpath)), repository, key, keyenv)
            releases.append(Path(staged['path']))
        predecessor, release = releases
        created = datetime.fromisoformat(json.loads((release / 'release.json').read_bytes())['created_utc']).timestamp()
        deadline = time.monotonic() + 2
        while int(time.time()) < created:
            need(time.monotonic() < deadline, 'actual clock did not advance past release creation')
            time.sleep(0.02)
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        epoch = h.expiry.timestamp(now)
        public_home = work / 'public-verifier'
        public_home.mkdir(mode=0o700)
        command('dearmor-public-certificate', ['/usr/bin/gpg', '--no-options', '--batch', '--no-autostart',
                '--homedir', str(public_home), '--dearmor', '--output', str(public_home / 'pubring.gpg'), certificate['path']])
        before_public = snapshot(public_home)
        digest = h.r.sha(release / 'release.json')
        with h.verification_env(public_home, release) as env:
            ctx = h.context(release, digest, key, env)
            binding = ctx['binding']
            graph = dict(schema_version=1, metadata_role='pre-change-release',
                release_id=binding['release_id'], snapshot_id=binding['snapshot_id'], packages=ctx['packages'],
                sources=[], build_dependencies=[], changed=dict(sources=[], toolchains=[], advisories=[]),
                capacity=dict(native_aarch64_slots=None, owner=None, reference=None))
            for name, source in ctx['sources'].items():
                graph['sources'].append(dict(id=name, **{k: source[k] for k in ('recipe_sha256', 'sources')}))
                graph['build_dependencies'].append(dict(package=name, source_id=name, makedepend=[], checkdepend=[],
                    toolchain=[], owner=None, disposition='hold', hold_reason='Synthetic TEST fixture; no maintenance authority'))
                graph['changed']['sources'].append(name)
            inventory = [{k: row[k] for k in ('name', 'version', 'arch', 'provides')} for row in ctx['packages']]
            advisory = [dict(name='AVG-1', packages=['fixture'], status='Fixed', severity='Unknown',
                type='SYNTHETIC TEST ONLY; no security allegation', affected='1.0-1', fixed='1.1-1', issues=[], advisories=[])]
            raws = dict(inventory=h.a.encoded(inventory), advisories=h.a.encoded(advisory), graph=h.a.encoded(graph))
            provenance = dict(url=h.a.URL, retrieved_at=now, **h.a.pin(raws['advisories']))
            raws['provenance'] = h.a.encoded(provenance)
            advisory_report = h.a.report(inventory, advisory,
                h.a.provenance(provenance, raws['advisories'], h.a.utc(now), 24), now)
            advisory_report['inputs'] = {name + '.json': h.a.pin(raws[name]) for name in ('inventory', 'advisories', 'provenance')}
            raws['advisory_report'] = h.a.encoded(advisory_report)
            maintenance = h.update.plan(raws, now)
            candidate_ref = save('candidate.json', dict(schema_version=1, packages=list(ctx['sources'].values())))
            source_report = h.pins.check_source_pins(release, Path(candidate_ref['path']), candidate_ref['sha256'], key, env)
            comparison = h.comparison.compare_releases(predecessor, release, key, env)
        # Packaged certificate inspection uses explicit --as-of semantics;
        # signatures are generated and verified at actual system time throughout.
        signing_report = h.expiry.report(h.expiry.inspect(public, epoch), key, epoch, 30)
        signing_report['certificate'] = h.a.pin(public)
        def entry(inputs):
            return dict(binding=binding, observed_at=now, inputs=inputs)
        observations = dict(schema_version=1, observations=dict(
            signing=entry(dict(certificate=certificate, report=save('signing-report.json', signing_report))),
            maintenance=entry(dict({name: save(name + '.json', raw) for name, raw in raws.items()},
                                   report=save('maintenance-report.json', maintenance))),
            sources=entry(dict(candidate=candidate_ref, report=save('source-report.json', source_report))),
            comparison=entry(dict(predecessor=dict(path=str(predecessor), sha256=h.r.sha(predecessor / 'release.json')),
                                  report=save('comparison-report.json', comparison))),
            operations=entry(dict(record=save('operations.json', dict(roles={name: None for name in h.ROLES},
                package_owners={row['name']: None for row in inventory}, capacity=dict(native_aarch64_slots=None,
                builder_owner=None, builder_reference=None, repository_owner=None, repository_reference=None)))))))
        index = save('observations.json', observations)
    finally:
        try:
            stopped = subprocess.run(['/usr/bin/gpgconf', '--homedir', str(signing), '--kill', 'all'],
                                     env=dict(ENV, HOME=str(work)), capture_output=True, timeout=20)
            need(stopped.returncode == 0, 'own TEST signing agent cleanup failed')
        finally:
            shutil.rmtree(signing)
    need(not signing.exists(), 'TEST signing secrets remain')
    selected_inputs = {path: pin(path.read_bytes()) for path in work.glob('*.json')}
    release_before = snapshot(repository)
    producer_inputs = {path: snapshot(path) for path in work.glob('release-inputs-*')}
    command_base = [str(cli), '--release', str(release), '--release-sha256', digest, '--key', key,
                    '--gpg-home', str(public_home), '--as-of', now]
    selected = ['--observations', index['path'], '--observations-sha256', index['sha256']]
    need(json.loads(command('authenticated-context', command_base + ['--context-only'])) == binding,
         'authenticated context differs')
    for fmt in ('json', 'text'):
        left = command('health-' + fmt + '-one', command_base + selected + ['--format', fmt])
        right = command('health-' + fmt + '-two', command_base + selected + ['--format', fmt])
        need(left == right, 'repeated report bytes differ')
    value = json.loads((work / 'health-json-one.stdout').read_bytes())
    need(value['status'] == 'OFFLINE_HEALTH_REVIEW_REQUIRED' and value['arm_security_status'] == 'UNKNOWN'
         and value['maintenance_acceptance'] == 'NOT_ESTABLISHED', 'synthetic review cannot grant acceptance')
    need(set(value['checks']) == set(h.KINDS) and all(row['status'] != 'UNAVAILABLE' for row in value['checks'].values()),
         'all five observations must replay')
    need(value['implementation_dependencies'] == sources, 'private dependency receipts differ')
    unavailable = json.loads(command('all-observations-unavailable', command_base))
    need(unavailable['summary']['EVIDENCE_UNAVAILABLE'] == 5, 'missing observations not visible')
    for label, flag, replacement in (('wrong-signer', '--key', 'F' * 40),
                                     ('wrong-release-digest', '--release-sha256', '0' * 64)):
        vector = list(command_base)
        vector[vector.index(flag) + 1] = replacement
        command(label, vector + selected, 2)
    command('wrong-observations-digest', command_base + selected[:-1] + ['0' * 64], 2)
    mismatch = copy.deepcopy(observations)
    mismatch['observations']['sources']['binding']['release_sha256'] = 'e' * 64
    wrong = save('wrong-generation.json', mismatch)
    command('wrong-observation-generation', command_base + ['--observations', wrong['path'],
            '--observations-sha256', wrong['sha256']], 2)
    alias = work / 'index-alias'
    alias.symlink_to(index['path'])
    command('symlink-index', command_base + ['--observations', str(alias),
            '--observations-sha256', index['sha256']], 2)
    damaged = work / 'tampered-release'
    shutil.copytree(release, damaged, symlinks=True)
    manifest = json.loads((damaged / 'release.json').read_bytes())
    artifact = damaged / 'repo' / manifest['packages'][0]['filename']
    artifact.write_bytes(artifact.read_bytes() + b'TAMPER')
    vector = list(command_base)
    vector[vector.index('--release') + 1] = str(damaged)
    command('tampered-signed-payload', vector + selected, 2)
    need(all(pin(path.read_bytes()) == row for path, row in selected_inputs.items()) and
         snapshot(repository) == release_before and all(snapshot(path) == row for path, row in producer_inputs.items()),
         'original fixture inputs changed')
    need(snapshot(public_home) == before_public, 'caller public verifier changed')
    need(pin(cli.read_bytes()) == cli_pin and all(pin((runtime / name).read_bytes()) == row for name, row in sources.items()),
         'installed CLI/private payload changed')
    controls = [row for row in receipts if row['argv'][0] == str(cli)]
    need(tuple(row['case'] for row in controls) == LABELS, 'complete ordered controls required')
    save('command-receipts.json', receipts)
    evidence = {}
    for path in sorted(work.rglob('*')):
        if path.is_file() and not path.is_symlink():
            need(len(evidence) < 128 and path.stat().st_size <= CAP, 'finite public file bound')
            evidence[path.relative_to(work).as_posix()] = pin(path.read_bytes())
    need(sum(row['bytes'] for row in evidence.values()) <= 16 * 1024**2, 'finite public retention byte bound')
    result = dict(status='PASS_MAINTENANCE_INSTALLED_SIGNED_TEST_CONTROLS', architecture=os.uname().machine,
        page_size=os.sysconf('SC_PAGE_SIZE'), uid=os.getuid(), command_count=len(receipts), controls=controls,
        source_files=sources, cli_sha256=cli_pin['sha256'], binding=binding, signer=key, as_of=now,
        started_epoch=started, key_created_epoch=key_created, evaluation_epoch=epoch, finished_epoch=int(time.time()),
        summary=value['summary'], all_five_observations_replayed=True, input_data_preserved=True,
        public_home_preserved=True, installed_payload_preserved=True, signing_secret_removed=True,
        fake_signature_time_used=False, signature_verification=dict(fingerprint=key, clock='ACTUAL_SYSTEM_TIME'),
        certificate_evaluation='PACKAGED_EXPLICIT_AS_OF_INSPECTION_ONLY', public_evidence=evidence,
        arm_security_status='UNKNOWN', maintenance_acceptance='NOT_ESTABLISHED', physical_m2='NOT_RUN', release='NOT_ADMITTED')
    need(len(encoded(result)) <= 128 * 1024, 'bounded proof transport required')
    save('fixture-proof.json', result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(argv)
    if args.report:
        ordinary(args.report)
        need(args.report.parent.is_dir() and not args.report.exists(), 'fresh report path required')
    result = run(args.cli, args.work)
    if args.report:
        with args.report.open('xb') as stream:
            stream.write(encoded(result))
        args.report.chmod(0o600)
    print(encoded(result).decode(), end='')


if __name__ == '__main__':
    main()
