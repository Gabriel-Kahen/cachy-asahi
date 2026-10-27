#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the selected real builder unchanged, observing its actual local Docker run."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import stat
import sys
import time
import tempfile

DOCKER = ('/usr/bin/docker', '--host=unix:///var/run/docker.sock')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def save(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(value, indent=2, sort_keys=True) + '\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try: os.unlink(temporary)
        except FileNotFoundError: pass


def check_inspection(row, observation):
    """Check observed daemon state, never infer mount protection from CLI text."""
    output = Path(observation['output']); host = row['HostConfig']
    need(row['Name'] == '/' + observation['name'] and row['Image'] == observation['image']
         and row['Config']['User'] == observation['user'], 'actual build identity')
    need(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True
         and host['AutoRemove'] is True and host['Privileged'] is False
         and host['PidsLimit'] == 512 and host['Memory'] == 4 * 1024**3
         and host['NanoCpus'] == 4_000_000_000 and set(host['CapDrop']) == {'ALL'}
         and not host.get('CapAdd') and host['SecurityOpt'] == ['no-new-privileges']
         and not host.get('Devices') and not host.get('DeviceRequests') and not host.get('VolumesFrom'),
         'actual unchanged builder isolation')
    expected = {('/inputs', str(output / 'inputs'), False, 'bind'),
                ('/out', str(output / 'artifacts'), True, 'bind'),
                ('/builder-entry.sh', str(Path(observation['feature_root']) / 'scripts/build/container-entry-v2.sh'), False, 'bind'),
                ('/expected-packages.lock', str(output / 'expected-packages.lock'), False, 'bind'),
                ('/offline-sources', str(output / 'source-material/srcdest'), False, 'bind')}
    actual = {(m['Destination'], m['Source'], m['RW'], m['Type']) for m in row['Mounts'] if m['Type'] == 'bind'}
    need(len([m for m in row['Mounts'] if m['Type']=='bind'])==5
         and len({m['Destination'] for m in row['Mounts']})==len(row['Mounts']),
         'unique exact bind and tmpfs destinations')
    need(actual == expected and len(row['Mounts']) in (5, 6)
         and all(m['Type'] == 'bind' or (m['Type'] == 'tmpfs' and m['Destination'] == '/tmp') for m in row['Mounts'])
         and set(host['Tmpfs']) == {'/tmp'}
         and set(host['Tmpfs']['/tmp'].split(',')) == {'rw', 'nosuid', 'nodev', 'exec', 'size=4g'},
         'actual exact readonly source mount; no source-cache bind')
    need('CACHY_ASAHI_OFFLINE_SOURCES=1' in row['Config']['Env'], 'actual offline-source entry contract')


_OWNED=None

def owned_child():
    global _OWNED
    if _OWNED is None:
        name='_pgo_driver_owned_child'
        spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name('owned_child.py'))
        _OWNED=importlib.util.module_from_spec(spec);sys.modules[name]=_OWNED;spec.loader.exec_module(_OWNED)
    return _OWNED


def require_retired(lifecycle):
    need(lifecycle.get('natural_exit')is True and lifecycle.get('group_absent')is True
         and lifecycle.get('leader_held_until_group_inspection')is True
         and lifecycle.get('exit_observed_via_waitpid')is True and lifecycle.get('ownership_lost')is False
         and lifecycle.get('forced_cleanup')is False
         and lifecycle.get('retirement')=='REAPED',
         'observed synchronous owned-child retirement required')


PACKAGE_LIMIT=512*1024**2

def file_pin(path):
    path=Path(path);before=path.stat()
    need(not any(p.is_symlink()for p in(path,*path.parents))and stat.S_ISREG(before.st_mode)
         and before.st_nlink==1 and before.st_size<=PACKAGE_LIMIT,'bounded ordinary package inspection input')
    digest=hashlib.sha256();size=0
    with path.open('rb')as stream:
        for block in iter(lambda:stream.read(1024**2),b''):
            size+=len(block);need(size<=PACKAGE_LIMIT,'package inspection byte limit');digest.update(block)
    after=path.stat()
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
         and size==before.st_size,'package changed during inspection hash')
    return dict(bytes=size,sha256=digest.hexdigest())

def inspect_package(path,original_package,rows,run=None):
    """Keep the frozen checker on its pure tar branch after owned decompression."""
    path=Path(path).absolute();before=file_pin(path);row=dict(status='FAIL',artifact=path.name,
        original=before,original_unchanged=False,parser_kind='PURE_PYTHON_PACKAGE_PARSE')
    rows.append(row)
    try:
        if path.name.endswith('.zst'):
            row['parser_kind']='OWNED_ZSTD_THEN_ORIGINAL_PURE_TAR';lifecycle={};row['owned_child']=lifecycle
            runner=owned_child().run if run is None else run
            temporary_root=Path(os.environ['RUNNER_TEMP']).absolute()
            need(temporary_root.is_dir()and not any(p.is_symlink()for p in(temporary_root,*temporary_root.parents)),
                 'ordinary existing RUNNER_TEMP for owned package parse')
            with tempfile.NamedTemporaryFile(mode='w+b',prefix='pgo-owned-package-',suffix='.tar',dir=temporary_root)as stream:
                row['command']=['zstd','-dc','--',str(path)];row['timeout_seconds']=120;row['stdout_limit']=PACKAGE_LIMIT
                result=runner(row['command'],stdout=stream,stderr=subprocess.PIPE,timeout=120,
                    stdout_limit=PACKAGE_LIMIT,lifecycle=lifecycle)
                require_retired(lifecycle)
                need(result.returncode==lifecycle.get('exit')==0,'owned zstd direct observed exit zero')
                stream.flush();row['decoded_tar']=file_pin(Path(stream.name));row['parser_input_suffix']='.tar'
                report=original_package(Path(stream.name))
        else:report=original_package(path)
        after=file_pin(path);need(after==before,'original compressed package changed while parsed')
        row['original_after']=after;row['original_unchanged']=True
        report=dict(report);report['artifact']=path.name;report['sha256']=before['sha256']
        row['reported_artifact']=report['artifact'];row['reported_sha256']=report['sha256'];row['status']='PASS'
        return report
    finally:
        # No child operation occurs here. Retain immutable-original evidence even
        # if owned decompression or pure parsing refused; NamedTemporaryFile owns
        # only its local file and removes it as the with block exits.
        after=file_pin(path);row['original_after']=after;row['original_unchanged']=after==before
        if after!=before:
            row['status']='FAIL';raise ValueError('original package changed during owned inspection')


def run_builder(args):
    sys.path.insert(0, str(args.feature_root / 'scripts/build'))
    spec = importlib.util.spec_from_file_location('selected_actual_build_v2', args.feature_root / 'scripts/build/build_v2.py')
    builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
    spec=importlib.util.spec_from_file_location('_pgo_native_plan',args.feature_root/'scripts/experiments/zlib_pgo_native_plan.py')
    planner=importlib.util.module_from_spec(spec);spec.loader.exec_module(planner)
    producer=json.loads(args.producer_binding.read_text());lock=args.lock.read_bytes()
    need(producer['schema']==1 and producer['status']=='PASS_FRESH_OWNED_RUNTIME_IMAGE_AND_FULL341_LOCK'
         and producer['identity']['source_sha']==args.source_sha and producer['image']==args.image
         and producer['package_count']==341 and len(lock.splitlines())==341
         and producer['packages']==dict(bytes=len(lock),sha256=__import__('hashlib').sha256(lock).hexdigest())
         and __import__('hashlib').sha256(lock).hexdigest()=='fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25',
         'live owned producer/full emitted lock must bind before native-plan')
    prepared=planner.prepare(args.preparation,args.image,args.lock,root=args.feature_root)
    args.output=args.preparation/'native-build'
    def snapshot():
        return {p.relative_to(args.preparation/'seed-cache').as_posix():dict(bytes=p.stat().st_size,sha256=__import__('hashlib').sha256(p.read_bytes()).hexdigest(),mode=p.stat().st_mode&0o777)
                for p in sorted((args.preparation/'seed-cache').rglob('*'))if p.is_file()}
    before=snapshot();save(args.preparation/'source-cache-before.json',before)
    original_run = owned_child().run; prior_run = subprocess.run; original_argv = sys.argv
    observation = None;package_inspections=[];original_package=builder.package
    def checked_package(path):return inspect_package(path,original_package,package_inspections,original_run)
    def observed_run(argv, *positional, **kwargs):
        nonlocal observation
        command = list(map(str, argv))
        if not command or command[0] != 'docker':
            return original_run(argv, *positional, **kwargs)
        forwarded = [*DOCKER, *command[1:]]  # Only select the already admitted local daemon.
        if command[1:2] != ['run']:
            return original_run(forwarded, *positional, **kwargs)
        need(observation is None and '--rm' in command and '--name' in command, 'one actual clean builder run')
        name = command[command.index('--name') + 1]
        need(re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', name), 'actual runner-owned fresh name')
        observation = dict(status='STARTED_NOT_YET_OBSERVED', name=name, command=command,
                           forwarded_command=forwarded, image=args.image, output=str(args.output),
                           feature_root=str(args.feature_root), source_sha=args.source_sha,
                           user=f'{os.getuid()}:{os.getgid()}')
        save(args.observation, observation)  # Cancellation can now identify this exact run.
        deadline=time.monotonic()+30;observed=[];inspections=[];consumer_lifecycle={};completed=None;consumer_admitted=False
        observation['consumer_child']=consumer_lifecycle
        def inspect_running():
            if observed or time.monotonic()>=deadline or len(inspections)>=128:return
            lifecycle={};inspections.append(lifecycle)
            result=original_run([*DOCKER,'inspect',name],capture_output=True,text=True,
                timeout=min(5,max(.001,deadline-time.monotonic())),lifecycle=lifecycle)
            require_retired(lifecycle)
            need(result.returncode==lifecycle.get('exit'),'inspection direct waitpid code')
            if result.returncode==0:
                rows=json.loads(result.stdout)
                if len(rows)==1 and rows[0]['State']['Running']is True:observed.append(rows[0])
        try:
            need('on_tick'not in kwargs and 'lifecycle'not in kwargs,'single owned consumer inspection pulse')
            completed=original_run(forwarded,*positional,on_tick=inspect_running,lifecycle=consumer_lifecycle,**kwargs)
            require_retired(consumer_lifecycle)
            need(completed.returncode==consumer_lifecycle.get('exit')==0,'consumer direct waitpid successful code')
            consumer_admitted=True
            return completed
        finally:
            # No thread exists. Inspect children finish synchronously while the
            # main child remains owned, before this call can return or raise.
            observation['observer_joined']=True
            observation['observer_kind']='SYNCHRONOUS_OWNED_CHILD_PULSE'
            observation['inspection_children']=inspections
            if observed:
                observation['inspection']=observed[0]
                save(args.observation,observation)
                check_inspection(observed[0],observation)
                observation['status']='PASS_ACTUAL_DAEMON_BUILD_MOUNTS_OBSERVED'if consumer_admitted else'PARTIAL_MOUNTS_OBSERVED_CHILD_NOT_ADMITTED'
            save(args.observation,observation)
    try:
        subprocess.run = observed_run
        builder.package = checked_package
        sys.argv = ['build_v2.py', *prepared['command'][3:]]
        code = builder.main()
        need(code == 0 and observation is not None and observation['observer_joined'] is True
             and observation['status'] == 'PASS_ACTUAL_DAEMON_BUILD_MOUNTS_OBSERVED',
             'actual build and mount observation must both complete')
        return 0
    finally:
        subprocess.run = prior_run; sys.argv = original_argv;builder.package=original_package
        if observation is not None:
            observation['package_inspections']=package_inspections;save(args.observation,observation)
        after=snapshot();save(args.preparation/'source-cache-after.json',after)
        need(before==after,'offline source cache changed during real native build')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('feature-root','preparation','lock','observation','producer-binding'):
        parser.add_argument('--'+key,type=Path,required=True)
    for key in ('image','source-sha'):
        parser.add_argument('--'+key,required=True)
    parser.add_argument('--execute', action='store_true'); args = parser.parse_args()
    need(args.execute and platform.machine() in ('aarch64', 'arm64') and os.getuid() == os.geteuid() != 0
         and os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ARCH') == 'ARM64',
         'explicit real hosted native ARM builder required')
    socket_events = []
    def deny_socket(event, values):
        if event.startswith('socket.'):
            socket_events.append(event)
            raise ValueError('Python network operations forbidden during offline build')
    sys.addaudithook(deny_socket)
    previous_run=subprocess.run
    try:
        subprocess.run=owned_child().run
        return run_builder(args)
    finally:
        subprocess.run=previous_run
        if args.observation.is_file():
            row = json.loads(args.observation.read_text()); row['python_socket_events'] = socket_events
            save(args.observation, row)


if __name__ == '__main__':
    raise SystemExit(main())
