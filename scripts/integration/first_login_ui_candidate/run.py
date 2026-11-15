#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Finite signed disposable x86 UI build/install/user/removal diagnostic."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = 'archlinux@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae'
LIMITS = ['--cpus=2', '--memory=4g', '--memory-swap=4g', '--pids-limit=256', '--ulimit=core=0:0']
UI_FILES = {'usr/bin/cachy-asahi-first-login-ui': 'cachy-asahi-first-login-ui',
 'usr/lib/cachy-asahi/first-login-ui/bridge.py': 'bridge.py',
 'usr/lib/cachy-asahi/first-login-ui/gui.py': 'gui.py',
 'usr/share/applications/io.github.GabrielKahen.CachyAsahiFirstLogin.desktop': 'io.github.GabrielKahen.CachyAsahiFirstLogin.desktop',
 **{'usr/share/doc/cachy-asahi-first-login-ui/' + n: n for n in ('README.md', 'source-provenance.json')},
 **{'usr/share/licenses/cachy-asahi-first-login-ui/' + n: n for n in ('LICENSE', 'NOTICE')}}


def pin(path):
    if not stat.S_ISREG(path.lstat().st_mode): raise ValueError('ordinary pinned file required')
    with path.open('rb') as stream: digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'bytes': path.stat().st_size, 'sha256': digest}


def load(name, path, digest):
    if pin(path)['sha256'] != digest: raise ValueError('shared helper source changed')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module; spec.loader.exec_module(module)
    return module


def resources(value, readonly, user):
    h = value['HostConfig']
    if not (h['NanoCpus'] == 2000000000 and h['Memory'] == h['MemorySwap'] == 4 * 1024**3
            and h['PidsLimit'] == 256 and h['NetworkMode'] == 'none' and h['Init']
            and h['ReadonlyRootfs'] == readonly and h['CapDrop'] == ['ALL']
            and not h['CapAdd'] and not h['Privileged'] and not h['Devices']
            and h['SecurityOpt'] == ['no-new-privileges'] and h['PidMode'] == ''
            and h['IpcMode'] == 'private' and value['Config']['User'] == user):
        raise ValueError('actor confinement differs')
    return {k: h[k] for k in ('NanoCpus', 'Memory', 'MemorySwap', 'PidsLimit', 'NetworkMode',
                              'ReadonlyRootfs', 'CapDrop', 'CapAdd', 'SecurityOpt', 'Init')}


def absent(argv, output):
    name = argv[-1]; prefix = 'Error response from daemon: '
    return output.strip() == {'rm': prefix + 'No such container: ' + name,
        'volume': prefix + 'get ' + name + ': no such volume',
        'image': prefix + 'No such image: ' + name}.get(argv[1])


def main():
    if not sys.flags.isolated or sys.flags.optimize: raise ValueError('use isolated unoptimized Python')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('first-login', 'setup', 'fish', 'zsh', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    profile = json.loads((HERE / 'inputs.json').read_text())
    recipe = ROOT / 'packages/tools/cachy-asahi-first-login-ui'
    def verify():
        if {p.name for p in recipe.iterdir() if p.is_file()} != set(profile['recipe_files']):
            raise ValueError('candidate source namespace changed')
        for name, expected in profile['recipe_files'].items():
            if pin(recipe / name) != expected: raise ValueError('candidate source changed: ' + name)
        for name, expected in profile['archives'].items():
            if pin(getattr(args, name)) != {k: expected[k] for k in ('bytes', 'sha256')}:
                raise ValueError('archive pin differs: ' + name)
        for name, expected in profile['helpers'].items():
            if pin(HERE / name) != expected: raise ValueError('reused GUI control source changed')
    verify()
    reader = load('bounded_reader', ROOT / 'scripts/update/archive_stream.py', '10f1a4c0ac5b98852d9ebb150af28f9ce345c800935a64fa463bc90f72fcb838')
    runtime = load('finite_runtime', ROOT / 'scripts/port/fdk-native-stage/runtime.py', '253494be99c21c83743b384b2c06cd1627023ffaf54f0cbbd271bde80572f70a')
    out = args.output.absolute()
    if out.exists() or any(p.is_symlink() for p in (out, *out.parents)): raise ValueError('new private output required')
    out.mkdir(mode=0o700); (out / 'logs').mkdir(mode=0o700)
    inputs = out / 'inputs'; inputs.mkdir(mode=0o755)
    for name in ('materials', 'recipe', 'templates'): (inputs / name).mkdir(mode=0o755)
    shutil.copyfile(HERE / 'inputs.json', inputs / 'inputs.json')
    shutil.copyfile(HERE / 'build.sh', inputs / 'build.sh')
    for path in recipe.iterdir():
        if path.is_file(): shutil.copyfile(path, inputs / 'recipe' / path.name)
    rows = {}
    for name, info in profile['archives'].items():
        target = inputs / 'materials' / info['name']; shutil.copyfile(getattr(args, name), target)
        limits = reader.Limits(1024**2, 1024**2, 8*1024**2, 200, 2*1024**2, 128*1024**2, time.monotonic()+15)
        nodes = reader.archive_payload(target, limits)
        with tarfile.open(target) as archive:
            controls = {member.name.removeprefix('./') for member in archive if member.name.removeprefix('./').startswith('.')}
        if not controls <= {'.PKGINFO', '.BUILDINFO', '.MTREE'}:
            raise ValueError('unexpected package control/script member')
        rows[name] = {p: r for p, r in nodes.items() if r['type'] == 'file'}
        if name in ('setup', 'first_login') and any(r['type'] not in ('file', 'directory') for r in nodes.values()):
            raise ValueError('unexpected nonordinary backend payload')
        if any(not p.startswith('usr/') or '/autostart/' in p or p.startswith(('usr/lib/systemd/', 'usr/share/libalpm/hooks/')) for p in nodes if p != 'usr'):
            raise ValueError('unexpected source package namespace')
        if name in ('fish', 'zsh'):
            member = 'usr/share/cachy-asahi/' + name + '/config.' + name
            with tarfile.open(target) as archive:
                data = archive.extractfile(member).read(2*1024**2+1)
            if hashlib.sha256(data).hexdigest() != rows[name][member]['sha256']: raise ValueError('template content differs')
            path = inputs / 'templates' / name / ('config.' + name); path.parent.mkdir(mode=0o755)
            path.write_bytes(data)
    if len(rows['first_login']) != 6 or len(rows['setup']) != 10: raise ValueError('backend payload count differs')
    for package, file, fixture in (('first_login', 'usr/lib/cachy-asahi/first-login/first_login.py', 'first-login-fixture.py'),
                                  ('setup', 'usr/bin/cachy-asahi-setup', 'setup8-fixture.py')):
        if rows[package][file]['sha256'] != profile['recipe_files'][fixture]['sha256']:
            raise ValueError('real archive backend differs from tested implementation')
    payloads = {'first_login': rows['first_login'], 'setup': rows['setup'], 'ui': {
        path: {'sha256': profile['recipe_files'][name]['sha256'], 'mode': 0o755 if path.startswith('usr/bin/') else 0o644}
        for path, name in UI_FILES.items()}}
    (inputs / 'payloads.json').write_text(json.dumps(payloads, sort_keys=True))
    for path in inputs.rglob('*'):
        if path.is_file(): path.chmod(0o444)
    token = uuid.uuid4().hex[:16]
    names = {k: 'ui-candidate-' + k + '-' + token for k in ('provision', 'backend', 'build', 'lifecycle', 'work', 'secret')}
    images = {k: 'cachy-asahi-ui-candidate-' + k + ':' + token for k in ('deps', 'backends')}
    env = {k:v for k,v in os.environ.items() if k in ('PATH','HOME','XDG_RUNTIME_DIR','DOCKER_HOST','DOCKER_CONTEXT')}
    runner = runtime.Runner(2400, env, out / 'logs')
    report = {'schema': 1, 'status': 'HOLD', 'base': BASE, 'inputs': profile, 'operations': [], 'cleanup': [],
        'nested_namespace': 'Default Docker denies unshare; no capability/seccomp bypass. Optional bwrap not a prerequisite.',
        'holds': ['host x86 software only', 'native ARM/M2/release NOT RUN'],
        'source': {p.name:pin(p) for p in HERE.iterdir() if p.is_file()}}
    def command(argv, seconds=60, check=True):
        try: result = runner.run(argv, timeout=seconds, log=f"{len(report['operations']):02d}.log")
        except BaseException as error:
            report['operations'].append({'argv': argv, 'failure': type(error).__name__+': '+str(error)}); raise
        report['operations'].append({'argv': argv, 'code': result.returncode})
        if check and result.returncode: raise ValueError('operation failed: '+str(len(report['operations'])-1))
        return result
    def mount(source, target, kind='bind', readonly=True):
        return ['--mount', f'type={kind},src={source},dst={target}' + (',readonly' if readonly else '')]
    common = ['--init', *LIMITS, '--security-opt=no-new-privileges']
    def inspect(name, readonly, user):
        value = json.loads(command(['docker','inspect',names[name]]).stdout)[0]
        report[name+'_resources'] = resources(value, readonly, user)
        expected = {'/inputs':('bind',False), '/work':('volume',True)} if name=='build' else {
            '/driver':('bind',False),'/work':('volume',True),'/signing':('volume',True),
            **({'/inputs':('bind',False)} if name=='backend' else {})}
        observed = {r['Destination']:(r['Type'],r['RW']) for r in value['Mounts']}
        if observed != expected: raise ValueError('unexpected actor mount/source access')
    try:
        with runtime.cancellation_handlers():
            command(['docker','image','inspect',BASE])
            command(['docker','create','--name',names['provision'],*common,'--network=host',
                *mount(HERE,'/driver'),'--entrypoint=/usr/bin/bash',BASE,'/driver/provision.sh'])
            command(['docker','start','--attach',names['provision']],900)
            command(['docker','commit',names['provision'],images['deps']],120)
            for name in ('work','secret'): command(['docker','volume','create',names[name]])
            shared = [*mount(HERE,'/driver'),*mount(names['work'],'/work','volume',False),
                      *mount(names['secret'],'/signing','volume',False)]
            command(['docker','create','--name',names['backend'],*common,'--network=none','--cap-drop=ALL','--user=0:0',
                *shared,*mount(inputs,'/inputs'),'--entrypoint=/usr/bin/python3',images['deps'],'-I','/driver/owner.py','backend'])
            inspect('backend',False,'0:0')
            command(['docker','start','--attach',names['backend']],240)
            command(['docker','commit',names['backend'],images['backends']],120)
            command(['docker','create','--name',names['build'],*common,'--network=none','--read-only','--cap-drop=ALL','--user=1000:1000',
                '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1000,gid=1000',
                *mount(inputs,'/inputs'),*mount(names['work'],'/work','volume',False),
                '--entrypoint=/usr/bin/bash',images['backends'],'/inputs/build.sh'])
            inspect('build',True,'1000:1000')
            result = command(['docker','start','--attach',names['build']],300,False)
            command(['docker','cp',names['build']+':/work/build/output',str(out/'build')],60)
            if result.returncode: raise ValueError('ordinary dependency-checked makepkg failed; retain exact check output')
            command(['docker','create','--name',names['lifecycle'],*common,'--network=none','--cap-drop=ALL','--user=0:0',
                *shared,'--entrypoint=/usr/bin/sleep',images['backends'],'900'])
            inspect('lifecycle',False,'0:0')
            command(['docker','start',names['lifecycle']])
            for who, script, operation, seconds in (('0:0','owner.py','install',180),
                ('1000:1000','user_journey.py','run',150),('0:0','owner.py','remove',90),
                ('1000:1000','user_journey.py','verify-removal',30)):
                command(['docker','exec','--user='+who,names['lifecycle'],'/usr/bin/python3','-I','/driver/'+script,operation],seconds)
            command(['docker','cp',names['lifecycle']+':/work/lifecycle/user',str(out/'user')],60)
            command(['docker','cp',names['lifecycle']+':/work/public',str(out/'public')],60)
            verify()
            report['status'] = 'PASS dependency-checked host build, TEST install, installed/moved GUI, removal/restoration'
    except BaseException as error:
        report['failure'] = type(error).__name__+': '+str(error); raise
    finally:
        cleanup = runtime.Runner(180,env,out/'logs')
        with runtime.defer_signals():
            for name in ('lifecycle','build','backend'):
                try: cleanup.run(['docker','cp',names[name]+':/work/public',str(out/('public-'+name))],timeout=20)
                except BaseException: pass
            actions = [['docker','rm','-f',names[n]] for n in ('lifecycle','build','backend','provision')]
            actions += [['docker','volume','rm',names[n]] for n in ('work','secret')]
            actions += [['docker','image','rm',images[n]] for n in ('backends','deps')]
            for argv in actions:
                try:
                    result=cleanup.run(argv,timeout=15);text=result.stdout.decode(errors='replace')
                    report['cleanup'].append({'argv':argv,'code':result.returncode,'absent':absent(argv,text),'output':text[-2048:]})
                except BaseException as error: report['cleanup'].append({'argv':argv,'error':str(error)})
        if any(x.get('code')!=0 and not x.get('absent') for x in report['cleanup']):
            report['status']='HOLD cleanup requires review'
        report['output_files']={str(p.relative_to(out)):pin(p) for p in out.rglob('*') if p.is_file() and inputs not in p.parents}
        (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(report['status'])
    return 0 if report['status'].startswith('PASS ') else 2


if __name__=='__main__': raise SystemExit(main())
