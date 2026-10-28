#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bootstrap one offline ARM container for retained setup3→4 package lifecycle."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import traceback

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT / 'scripts/ci'), str(ROOT / 'scripts/checks')]
import native_arm as native
from package_checks import package, PACKAGE_METADATA

INPUTS = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
BASE = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
ARCHIVES = (
    ('0.1.0-3', 14496, '85ab7b964cd628ef21f5df6133aa9d046d32ea35cd6af3de0e5b888341550f0c',
     '465bf53545e1d83053bf3c412e210493961b74ae', '5ee9111f43f049817e46faa5c883ea56ae5291095175e3f59674110dd0a46fab'),
    ('0.1.0-4', 22632, 'c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a',
     '98fecf28a3cde63a9dd7531501c2187825349310', 'ec816728a154f77723d34e56bcbf04bb39ef436be1d883fb90c1af8d43dae31e'),
)
HELPERS = ('scripts/ci/full-development-composition/container.py', 'scripts/ci/full-development-composition/run.py')


def need(ok, message):
    if not ok: raise ValueError(message)


def archives():
    rows = []
    for version, size, digest, source, pkgbuild in ARCHIVES:
        filename = 'cachy-asahi-setup-' + version + '-any.pkg.tar.xz'
        path = HERE / 'fixtures' / filename
        need(not path.is_symlink() and path.is_file() and path.stat().st_size == size and native.sha(path) == digest,
             'retained original archive bytes differ: ' + filename)
        report = package(path); fields = report['metadata']['.PKGINFO']
        need(not report['errors'] and fields['pkgname'] == ['cachy-asahi-setup'] and fields['pkgver'] == [version]
             and report['metadata']['.BUILDINFO']['pkgbuild_sha256sum'] == [pkgbuild], 'actual archive metadata differs')
        payload = {name: {'mode': row['mode'], 'sha256': row['sha256']} for name, row in report['members'].items()
                   if name not in PACKAGE_METADATA and row['type'] != '5'}
        expected = {'usr/bin/cachy-asahi-setup', 'usr/share/doc/cachy-asahi-setup/README.md',
                    'usr/share/licenses/cachy-asahi-setup/NOTICE', 'usr/share/licenses/cachy-asahi-setup/LICENSE'}
        if version == '0.1.0-4': expected |= {'usr/bin/cachy-asahi-repository', 'usr/share/doc/cachy-asahi-setup/repository-enrollment.md'}
        need(set(payload) == expected and payload['usr/bin/cachy-asahi-setup']['sha256'] ==
             '3e652bff75f6202cd3c13c327e50a298f7b25149b3c5cb55cdf4912d35af5919', 'retained payload differs')
        rows.append({'name':'cachy-asahi-setup', 'version':version, 'filename':filename, 'size':size,
                     'sha256':digest, 'source_commit':source, 'payload':payload})
    return rows


def local_context():
    contexts = json.loads(native.run(['docker','context','inspect'], timeout=10))
    need(len(contexts) == 1 and contexts[0]['Endpoints']['docker']['Host'] in
         ('unix:///var/run/docker.sock', 'unix:///run/docker.sock'), 'active Docker context is not local')


def preflight(args):
    need(re.fullmatch('[0-9a-f]{40}', args.source_commit or ''), 'exact lifecycle Source required')
    need(native.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], timeout=10) == args.source_commit,
         'lifecycle checkout differs')
    subprocess.run(['git', '-C', str(ROOT), 'diff', '--exit-code', 'HEAD', '--', 'scripts/ci', 'scripts/checks',
                    'scripts/build'], check=True, stdout=subprocess.DEVNULL, timeout=10)
    need(os.getuid() == os.geteuid() > 0 and not any(os.environ.get(k) for k in
         ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_API_VERSION')), 'ordinary local Docker caller required')
    paths = (ROOT, args.cache, args.output)
    need(all(p.is_absolute() and '..' not in p.parts and not any(c in str(p) for c in ',\n\r') and
             not any(q.is_symlink() for q in (p, *p.parents)) for p in paths), 'canonical ordinary paths required')
    need(args.cache.is_dir() and not args.output.exists() and
         all(not a.is_relative_to(b) and not b.is_relative_to(a) for i,a in enumerate(paths) for b in paths[i+1:]),
         'source, seeded cache and new output must be separate')
    local_context()
    rows = archives()
    return native.load_pinned(ROOT / 'scripts/ci/inputs.lock.json', INPUTS), rows


def cleanup(docker, name, output, bootstrap_started, container_started):
    result = {'status':'PASS', 'container':'NOT CREATED', 'image':'NOT CREATED'}
    if container_started:
        try:
            found = native.run(docker + ['container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}'], timeout=10)
            need(found in ('', name), 'ambiguous owned container')
            if found: native.run(docker + ['rm','-f',name], timeout=20)
            need(not native.run(docker + ['container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}'], timeout=10), 'owned container remains')
            result['container'] = {'name':name,'absence_verified':True}
        except (OSError, ValueError, subprocess.SubprocessError): result.update(status='FAIL',container='ABSENCE UNKNOWN')
    try:
        path = output / 'native/image-id'
        if path.exists():
            image = path.read_text().strip(); need(re.fullmatch('sha256:[0-9a-f]{64}', image), 'owned image required')
            native.run(docker + ['image','rm','--no-prune',image], timeout=30)
            need(image not in native.run(docker + ['image','ls','-a','--no-trunc','-q'], timeout=10).splitlines(), 'owned image remains')
            result['image'] = {'id':image,'absence_verified':True}
        elif bootstrap_started: result.update(status='FAIL',image='ABSENCE UNKNOWN')
    except (OSError, ValueError, subprocess.SubprocessError): result.update(status='FAIL',image='ABSENCE UNKNOWN')
    return result


def container_command(docker, name, image, mounts, nonce):
    argv = docker + ['run','--rm','--name',name,'--pull=never','--platform=linux/arm64','--user=0:0',
        '--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128','--memory=1g','--cpus=2',
        '--tmpfs=/tmp:rw,nosuid,nodev,exec,size=128m','--env=CACHY_ASAHI_COMPOSITION='+nonce,
        '--env=PYTHONDONTWRITEBYTECODE=1']
    for cap in ('CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID','SYS_CHROOT','SETFCAP'): argv += ['--cap-add='+cap]
    for source, target, readonly in mounts:
        argv += ['--mount','type=bind,src='+str(source)+',dst='+target+(',readonly' if readonly else '')]
    return argv + ['--entrypoint=python3', image, '-I','-B','/lifecycle.py']


def run(args):
    inputs, rows = preflight(args)
    output = args.output; output.mkdir(mode=0o700)
    bootstrap = output / 'native'; bootstrap.mkdir()
    summary = output / 'summary'; summary.mkdir()
    results = output / 'lifecycle'; results.mkdir()
    incoming = output / 'inputs'; incoming.mkdir()
    docker = ['docker','--host=unix:///var/run/docker.sock']
    name = 'repository-installed-' + secrets.token_hex(8)
    report = {'status':'FAIL','source_commit':args.source_commit,'hardware':'NOT RUN', 'target_installation':'NOT RUN',
              'production_trust':'NOT ACCEPTED','archives':rows,'cancelled':False}
    bootstrap_started = container_started = False
    def cancel(*_): raise KeyboardInterrupt()
    previous = {sig:signal.signal(sig,cancel) for sig in (signal.SIGINT,signal.SIGTERM)}
    try:
        native.save(bootstrap / 'inputs.lock.json', inputs)
        # Pin daemon-contacting probe commands even if context config changes afterward.
        old_host = os.environ.get('DOCKER_HOST')
        os.environ['DOCKER_HOST'] = 'unix:///var/run/docker.sock'
        try: probe = native.probe(bootstrap)
        finally:
            if old_host is None: os.environ.pop('DOCKER_HOST', None)
            else: os.environ['DOCKER_HOST'] = old_host
        docker = ['docker','--host='+probe['docker_endpoint']]
        native.audit(inputs, args.cache, bootstrap); bootstrap_started = True
        image = native.build(inputs, args.cache, bootstrap, {})
        need(native.sha(bootstrap / 'packages.lock') == BASE, 'builder inventory differs')
        for row in rows: shutil.copyfile(HERE/'fixtures'/row['filename'], incoming/row['filename'])
        shutil.copyfile(bootstrap/'packages.lock', incoming/'packages.lock')
        native.save(incoming/'packages.json', rows)
        mounts = [(incoming,'/inputs',True),(results,'/results',False),(HERE/'container.py','/lifecycle.py',True),
                  (ROOT/HELPERS[0],'/helpers/composition-container.py',True),(ROOT/HELPERS[1],'/helpers/composition-run.py',True)]
        argv = container_command(docker, name, image, mounts, secrets.token_hex(16))
        native.save(summary/'command.json', argv); container_started = True
        native.run(argv, results/'driver.log', 600)
        observed = json.loads((results/'result.json').read_text())
        need(observed['status'] == 'PASS' and observed.get('private_fixture_cleanup') is True and
             observed.get('final_package_count') == 341, 'installed lifecycle or private cleanup failed')
        report.update(status='PASS', lifecycle=observed)
    except (KeyboardInterrupt, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report.update(error=str(error),traceback=traceback.format_exc(limit=10),cancelled=isinstance(error,KeyboardInterrupt))
    finally:
        interrupted = []
        for sig in previous: signal.signal(sig,lambda signum,_:interrupted.append(signum))
        try:
            report['cleanup'] = cleanup(docker,name,output,bootstrap_started,container_started)
            if report['cleanup']['status'] != 'PASS': report['status'] = 'FAIL'
            if interrupted: report.update(status='FAIL',cancelled=True)
            native.save(summary/'result.json',report)
        finally:
            for sig,handler in previous.items(): signal.signal(sig,handler)
    return int(report['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-commit',required=True)
    parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    return run(parser.parse_args())


if __name__ == '__main__': raise SystemExit(main())
