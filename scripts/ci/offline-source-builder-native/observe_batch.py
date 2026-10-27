# SPDX-License-Identifier: MIT
"""Bounded observation of five owned v2 attempts, with one real owned fault.

No builder adapter or production test hook is installed. The parent runs the
selected batch CLI and supplies its bounded, logged Docker capture transport.
"""
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time

DOCKER = ('/usr/bin/docker', '--host=unix:///var/run/docker.sock')
BASELINE = 'cachy-asahi-zlib-baseline'
LTO = 'cachy-asahi-zlib-lto'
ATTEMPTS = (('batch-a', BASELINE, 1), ('batch-a', LTO, 1),
            ('batch-a', BASELINE, 2), ('batch-b', BASELINE, 1), ('batch-b', LTO, 1))
MAX_BYTES = 4 * 1024**2


def need(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def ordinary(path):
    path = Path(path).absolute()
    need(path == path.resolve() and not any(c in str(path) for c in ('\n', '\r', '\x00', ',')),
         'ordinary nonsymlink observation path required')
    return path


def read(path):
    path = Path(path)
    before = path.lstat()  # Missing future attempt files are deliberately retryable.
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_BYTES
         and not any(p.is_symlink() for p in path.parents), 'unsafe existing observation input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        key = lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(key(opened) == key(before), 'observation input changed before read')
        chunks, count = [], 0
        while block := os.read(fd, 65536):
            count += len(block); need(count <= MAX_BYTES, 'observation input byte cap')
            chunks.append(block)
        need(key(opened) == key(os.fstat(fd)) == key(path.lstat()) and count == before.st_size,
             'observation input changed during read')
        return b''.join(chunks)
    finally:
        os.close(fd)


def decode(raw):
    def pairs(items):
        value = {}
        for k,v in items:
            need(k not in value, 'duplicate observed JSON field'); value[k] = v
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _:need(False, 'nonfinite observed JSON value'))


def write(path, raw):
    need(type(raw) is bytes and len(raw) <= MAX_BYTES, 'bounded observation bytes required')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def save(path, value):
    write(path, encoded(value))


def capture_local(argv, seconds):
    """Actual local CLI transport; the parent normally substitutes its actor log wrapper."""
    need(tuple(argv[:2]) == DOCKER, 'selected local Docker transport required')
    return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=seconds)


def captured(capture, argv, seconds):
    result = capture(argv, seconds)
    need(type(result.returncode) is int, 'exact Docker exit code required')
    raw = lambda p: p.encode() if type(p) is str else p
    stdout, stderr = raw(result.stdout), raw(result.stderr)
    need(type(stdout) is bytes and type(stderr) is bytes and len(stdout) + len(stderr) <= MAX_BYTES,
         'bounded Docker capture bytes required')
    return result.returncode, stdout, stderr


def mounts(feature, output):
    return {(str(output/'inputs'), '/inputs', False),
            (str(output/'artifacts'), '/out', True),
            (str(feature/'scripts/build/container-entry-v2.sh'), '/builder-entry.sh', False),
            (str(output/'expected-packages.lock'), '/expected-packages.lock', False),
            (str(output/'source-material/srcdest'), '/offline-sources', False)}


def check_provenance(record, feature, output, image, entry_sha):
    need(type(record) is dict and record.get('status') == 'building', 'attempt finished before running observation')
    name = record.get('clean_environment_id')
    need(type(name) is str and re.fullmatch('cachy-asahi-[0-9a-f]{16}', name), 'fresh owned builder name required')
    need(record.get('image') == record.get('image_id') == image and record.get('mode') == 'native'
         and record.get('network') == 'none' and record.get('entry_script_sha256') == entry_sha,
         'observed builder source/image/mode differs')
    need(record.get('builder_host_arch') in ('aarch64','arm64'), 'native Docker host receipt required')
    need(record.get('recipe_metadata',{}).get('pkgname') == [output.parents[1].name]
         and type(record.get('source_date_epoch')) is int and record['source_date_epoch'] >= 0,
         'expected package/epoch provenance required')
    material = record.get('source_material')
    need(type(material) is dict and material.get('purpose') == 'offline-build-sources'
         and material.get('legal_acceptance') is False and material.get('source_completeness_accepted') is False
         and material.get('recipe_inputs') == record.get('recipe_inputs'), 'offline source provenance required')
    command = record.get('command')
    expected = {'type=bind,src='+s+',dst='+d+('' if rw else ',readonly') for s,d,rw in mounts(feature,output)}
    need(type(command) is list and all(type(p) is str for p in command) and len(command) > 5
         and command[:5] == ['docker','run','--rm','--name',name] and command[-2] == image
         and {command[i+1] for i,p in enumerate(command[:-1]) if p == '--mount'} == expected
         and command.count('--mount') == 5, 'owned v2 command/image/mounts differ')
    return name


def check_inspection(row, feature, output, image, name, epoch=None):
    need(type(row) is dict and row.get('Name') == '/'+name and row.get('Image') == image
         and row.get('Config',{}).get('Image') == image
         and row['Config'].get('User') == f'{os.getuid()}:{os.getgid()}', 'live owned container identity differs')
    state = row.get('State',{})
    need(state.get('Running') is True and state.get('Status') == 'running' and type(state.get('Pid')) is int
         and state['Pid'] > 0 and state.get('Paused') is False and state.get('Restarting') is False,
         'actual running unpaused container required')
    need(type(row.get('Id')) is str and re.fullmatch('[0-9a-f]{64}',row['Id']), 'actual container ID required')
    host = row['HostConfig']
    need(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True and host['AutoRemove'] is True
         and host['Privileged'] is False and type(host['PidsLimit']) is int and host['PidsLimit'] == 512
         and type(host['Memory']) is int and host['Memory'] == 4*1024**3
         and type(host['NanoCpus']) is int and host['NanoCpus'] == 4_000_000_000
         and host['CapDrop'] == ['ALL'] and not host.get('CapAdd')
         and host['SecurityOpt'] == ['no-new-privileges'] and not host.get('Devices')
         and not host.get('DeviceRequests') and not host.get('VolumesFrom'), 'live v2 isolation/resource limits differ')
    need(set(host['Tmpfs']) == {'/tmp'} and set(host['Tmpfs']['/tmp'].split(',')) == {'rw','nosuid','nodev','exec','size=4g'},
         'live private tmpfs differs')
    rows = row['Mounts']
    need(type(rows) is list and len(rows) in (5,6) and all(type(p) is dict for p in rows), 'finite live mount list required')
    binds = [p for p in rows if p.get('Type') == 'bind']
    need(len(binds) == 5 and all(type(p.get('RW')) is bool for p in binds)
         and {(p.get('Source'),p.get('Destination'),p['RW']) for p in binds} == mounts(feature,output)
         and all(p.get('Type') == 'bind' or (p.get('Type') == 'tmpfs' and p.get('Destination') == '/tmp' and p.get('RW') is True) for p in rows),
         'exact five live v2 attempt mounts required; no cache bind')
    env = row['Config']['Env']
    need(type(env) is list and env.count('CACHY_ASAHI_OFFLINE_SOURCES=1') == env.count('CACHY_ASAHI_CONTAINER=1') == 1,
         'live offline builder environment required')
    if epoch is not None:
        need(env.count('SOURCE_DATE_EPOCH='+str(epoch)) == 1, 'live source epoch differs')


def observe(source_feature, work, image, stop, capture, *, timeout=900, interval=.03):
    """Watch batch-a fault/resume and fresh batch-b while the parent runs actors.

    capture(argv, seconds) returns a CompletedProcess with bounded stdout/stderr.
    Call this in a thread before the first execute CLI. The parent must check the
    returned status, stop/join the observer, and validate final batch outcomes.
    """
    feature, work = ordinary(source_feature), ordinary(work)
    need(feature.is_dir() and work.is_dir(), 'existing feature/work roots required')
    need(type(image) is str and re.fullmatch('sha256:[0-9a-f]{64}', image), 'exact selected image ID required')
    need(type(timeout) in (int,float) and math.isfinite(timeout) and 0 < timeout <= 1800
         and type(interval) in (int,float) and math.isfinite(interval) and .001 <= interval <= .25,
         'finite observer timeout/poll bounds required')
    entry_sha = sha(read(feature/'scripts/build/container-entry-v2.sh'))
    directory = work/'batch-observations'
    directory.mkdir(mode=0o700, exist_ok=False)
    expectations = []
    for batch, package, index in ATTEMPTS:
        key = batch+'.'+package+f'.attempt-{index:03d}'
        output = work/batch/package/f'attempt-{index:03d}'/'build'
        expectations.append(dict(key=key,batch=batch,package=package,attempt=index,
            output=str(output),fault=(batch,package,index)==('batch-a',BASELINE,1)))
    save(directory/'request.json',dict(schema_version=1,feature_root=str(feature),work=str(work),
        image=image,entry_sha256=entry_sha,attempts=expectations,
        started_utc=now(),timeout=timeout,interval=interval))
    deadline = time.monotonic()+timeout
    seen, names, ids = {}, set(), set()
    fault = None
    error = None
    try:
        while len(seen) < len(expectations) and not stop.is_set() and time.monotonic() < deadline:
            for expected in expectations:
                key = expected['key']
                if key in seen:
                    continue
                if stop.is_set() or time.monotonic() >= deadline:
                    break
                output = Path(expected['output'])
                try:
                    provenance_raw = read(output/'provenance.json')
                except FileNotFoundError:
                    continue
                try:
                    provenance = decode(provenance_raw)
                except json.JSONDecodeError:
                    continue  # The real builder writes this file without atomic replacement.
                name = check_provenance(provenance,feature,output,image,entry_sha)
                argv = [*DOCKER,'container','inspect',name]
                code,stdout,stderr = captured(capture,argv,5)
                if code != 0:
                    need(b'No such' in stderr and name.encode() in stderr, 'Docker inspection failed without confirmed not-yet-present container')
                    continue
                rows = decode(stdout)
                need(type(rows) is list and len(rows)==1 and type(rows[0]) is dict, 'one actual inspected container required')
                row = rows[0]
                if row.get('State',{}).get('Running') is False:
                    continue
                provenance_file = key+'.provenance.json'
                inspect_file = key+'.inspect.json'
                stdout_file = key+'.inspect.stdout'
                write(directory/provenance_file,provenance_raw)
                write(directory/stdout_file,stdout)
                save(directory/inspect_file,row)
                write(directory/(key+'.inspect.stderr'),stderr)
                # Retain even a rejected live inspection for diagnosis. Only the
                # separately written observation receipt denotes passing guards.
                check_inspection(row,feature,output,image,name,provenance['source_date_epoch'])
                need(name not in names and row['Id'] not in ids, 'five distinct clean container executions required')
                observation = dict(schema_version=1,status='ACTUAL_OWNED_RUNNING_V2_ATTEMPT_OBSERVED',
                    **expected,name=name,container_id=row['Id'],image=image,feature_root=str(feature),
                    observed_utc=now(),inspect_argv=argv,inspect_returncode=code,
                    provenance_file=provenance_file,provenance_sha256=sha(provenance_raw),
                    inspection_file=inspect_file,inspection_sha256=sha(encoded(row)),
                    inspect_stdout_file=stdout_file,inspect_stdout_sha256=sha(stdout),
                    inspect_stderr_sha256=sha(stderr))
                save(directory/(key+'.observation.json'),observation)
                seen[key] = observation; names.add(name); ids.add(row['Id'])
                if expected['fault']:
                    need(fault is None, 'only one intentional actual fault permitted')
                    # Both the live inspection and building provenance are durable
                    # before invoking the actual targeted kill command.
                    kill_argv = [*DOCKER,'kill','--signal=KILL',name]
                    requested = now()
                    kill_code,killed,killed_error = captured(capture,kill_argv,10)
                    write(directory/'fault-kill.stdout',killed)
                    write(directory/'fault-kill.stderr',killed_error)
                    killed_ok = kill_code==0 and killed==(name+'\n').encode() and not killed_error
                    fault = dict(schema_version=1,status='ACTUAL_OWNED_RUNNING_CONTAINER_KILL_RETURNED' if killed_ok else 'FAULT_NOT_ESTABLISHED',
                        key=key,name=name,container_id=row['Id'],image=image,argv=kill_argv,returncode=kill_code,
                        requested_utc=requested,returned_utc=now(),provenance_sha256=sha(provenance_raw),
                        inspection_sha256=sha(encoded(row)),observation_sha256=sha(encoded(observation)),
                        stdout_sha256=sha(killed),stderr_sha256=sha(killed_error))
                    save(directory/'fault.json',fault)
                    need(killed_ok, 'actual owned container kill did not establish the intentional fault')
            if len(seen) < len(expectations) and not stop.is_set():
                stop.wait(min(interval,max(0,deadline-time.monotonic())))
    except (OSError,ValueError,KeyError,TypeError,IndexError,AttributeError,subprocess.SubprocessError) as failed:
        error = dict(kind=type(failed).__name__,message=str(failed))
    complete = len(seen)==len(expectations) and fault is not None and fault['status']=='ACTUAL_OWNED_RUNNING_CONTAINER_KILL_RETURNED' and error is None
    report = dict(schema_version=1,status='PASS_FIVE_ACTUAL_RUNNING_V2_ATTEMPTS_ONE_OWNED_KILL' if complete else 'FAIL_REQUIRED_ACTUAL_OBSERVATIONS_OR_FAULT_NOT_ESTABLISHED',
        expected_count=len(expectations),observed_count=len(seen),observations=seen,fault=fault,
        missing=[p['key'] for p in expectations if p['key'] not in seen],error=error,
        stopped=stop.is_set(),deadline_reached=time.monotonic()>=deadline,finished_utc=now(),
        build_success='PARENT_MUST_VERIFY_FINAL_PROVENANCE_AND_BATCH_STATES',
        hardware='NOT_RUN',release='NOT_ADMITTED')
    save(directory/'report.json',report)
    return report
