#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify an explicitly reviewed immutable native TEST signer image.

Only prepare acquires the exact public OCI digest. Signing never runs here.
No package installation, production credentials, or host keyring use.
The command helper supports bounded, explicitly owned image-build state.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time

CONTRACT_PURPOSE = 'GUI-FRESH-TEST-SIGNER-IMAGE'
PURPOSE = 'GUI-FRESH-TEST-SIGNER-ENVIRONMENT'
LIMIT = 1024 * 1024
TOOLS = ('/usr/bin/python3', '/usr/bin/gpg', '/usr/bin/gpgconf',
         '/usr/bin/gpg-agent', '/usr/bin/pacman')
CAPS = ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb')
ENDPOINTS = ('unix:///var/run/docker.sock', 'unix:///run/docker.sock')
DOCKER_CONFIG = None


def need(condition, message):
    if not condition:
        raise ValueError(message)


def enc(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(items):
    value = {}
    for key, item in items:
        need(key not in value, 'duplicate contract/receipt field')
        value[key] = item
    return value


def decode(raw):
    need(len(raw) <= LIMIT, 'bounded environment JSON')
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: need(False, 'finite environment JSON'))


def read(path, limit=LIMIT):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve() and
         not any(p.is_symlink() for p in (path, *path.parents)), 'canonical ordinary environment path')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
         'bounded ordinary environment input')
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    pin = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                     s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(len(raw) == info.st_size <= limit and pin(info) == pin(after) == pin(path.lstat()),
         'stable complete environment input')
    return raw


def save(path, value):
    raw = enc(value)
    need(len(raw) <= LIMIT, 'bounded environment receipt')
    with path.open('xb') as stream:
        stream.write(raw)
    path.chmod(0o600)


def validate(value):
    need(type(value) is dict and set(value) == {
        'schema_version', 'purpose', 'source_sha', 'oci_ref', 'image_id', 'alarm_uid',
        'alarm_gid', 'packages_sha256', 'tools'}, 'exact reviewed image contract fields')
    need(type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['purpose'] == CONTRACT_PURPOSE, 'explicit TEST signer image contract')
    for key, pattern in (('source_sha', r'[0-9a-f]{40}'), ('image_id', r'sha256:[0-9a-f]{64}'),
                         ('packages_sha256', r'[0-9a-f]{64}')):
        need(type(value[key]) is str and re.fullmatch(pattern, value[key]) is not None,
             'resolved full image/source/package identity')
    reference = value['oci_ref']
    need(type(reference) is str and len(reference) <= 512 and re.fullmatch(
        r'[a-z0-9]+(?:[.-][a-z0-9]+)+(?:\:[0-9]{1,5})?/'
        r'[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*'
        r'@sha256:[0-9a-f]{64}', reference) is not None,
        'fully qualified public OCI digest required; tags and implicit registries refused')
    need(type(value['alarm_uid']) is int and 0 < value['alarm_uid'] < 2**31 and
         type(value['alarm_gid']) is int and 0 <= value['alarm_gid'] < 2**31,
         'resolved non-root alarm UID/GID')
    need(type(value['tools']) is dict and set(value['tools']) == set(TOOLS),
         'complete exact signer executable inventory')
    for row in value['tools'].values():
        need(type(row) is dict and set(row) == {'bytes', 'sha256'} and
             type(row['bytes']) is int and 0 < row['bytes'] <= 128 * 1024**2 and
             type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is not None,
             'resolved executable size and SHA-256')
    return value


@contextlib.contextmanager
def cancellation():
    previous = signal.getsignal(signal.SIGTERM)
    def terminate(signum, frame):
        raise KeyboardInterrupt('environment cancellation')
    signal.signal(signal.SIGTERM, terminate)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


@contextlib.contextmanager
def retirement():
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    for sig in previous:
        signal.signal(sig, signal.SIG_IGN)
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


@contextlib.contextmanager
def docker_config(out):
    """An empty owned config prevents use of ambient registry credentials."""
    global DOCKER_CONFIG
    path = out / 'docker-config'
    if not path.exists():
        path.mkdir(mode=0o700)
    info = path.lstat()
    need(not path.is_symlink() and stat.S_ISDIR(info.st_mode) and
         info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700 and
         not any(path.iterdir()), 'empty owned Docker config without ambient credentials')
    previous, DOCKER_CONFIG = DOCKER_CONFIG, str(path)
    try:
        yield
    finally:
        DOCKER_CONFIG = previous


def _directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextlib.contextmanager
def _buildx_state(argv, path):
    """Pin separate empty private state before the one owned build actor."""
    need(type(argv) is list and len(argv) >= 3 and argv[:2] == ['docker', 'build'],
         'Buildx state is restricted to the owned Docker build invocation')
    need(isinstance(path, Path), 'explicit Buildx state Path required')
    credential = Path(DOCKER_CONFIG)
    need(path.is_absolute() and path == path.resolve() and
         credential.is_absolute() and credential == credential.resolve() and
         not any(p.is_symlink() for p in (path, *path.parents, credential, *credential.parents)),
         'canonical nonalias Buildx and credential directories')
    need(path != credential and not path.is_relative_to(credential) and
         not credential.is_relative_to(path), 'disjoint Buildx and Docker credential directories')
    pins = []
    try:
        for directory in (credential, path):
            before = directory.lstat()
            need(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid() and
                 before.st_gid == os.getgid() and stat.S_IMODE(before.st_mode) == 0o700 and
                 before.st_nlink in (1, 2), 'owned mode0700 ordinary empty state directory')
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            pins.append((directory, fd, _directory_identity(before)))
            need(_directory_identity(before) == _directory_identity(os.fstat(fd)) and
                 not os.listdir(fd), 'fresh empty pinned state directory')
        need(pins[0][2][:2] != pins[1][2][:2], 'state directories cannot alias one inode')
        for directory, fd, pin in pins:
            need(pin == _directory_identity(os.fstat(fd)) == _directory_identity(directory.lstat()),
                 'unchanged state directory identity before build')
        yield str(path)
    finally:
        for _, fd, _ in reversed(pins):
            os.close(fd)


def command(argv, timeout=60, *, required=True, buildx_config=None):
    """Bound command output and terminate only its owned process group."""
    need(DOCKER_CONFIG is not None, 'explicit empty private Docker config required')
    state = contextlib.nullcontext(None) if buildx_config is None else _buildx_state(argv, buildx_config)
    with state as selected, tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as diagnostic:
        environment = dict(PATH='/usr/local/bin:/usr/bin:/bin', LANG='C.UTF-8',
                           HOME=os.environ['HOME'], DOCKER_CONFIG=DOCKER_CONFIG)
        if selected is not None:
            environment['BUILDX_CONFIG'] = selected
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=diagnostic, start_new_session=True,
                                   env=environment)
        try:
            process.wait(timeout=timeout)
        except BaseException:
            # Retain an unreaped leader until the last group signal; its PID
            # reserves this session/group identity against numeric reuse.
            if process.returncode is not None:
                raise
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            try:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                        break
                    time.sleep(0.05)
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            finally:
                process.wait(timeout=5)
            raise
        output.seek(0)
        diagnostic.seek(0)
        raw, err = output.read(LIMIT + 1), diagnostic.read(LIMIT + 1)
        need(len(raw) <= LIMIT and len(err) <= LIMIT, 'bounded Docker environment command output')
    need(not required or process.returncode == 0, 'environment Docker command failed')
    return process.returncode, raw


def inspect_image(identifier):
    if identifier.startswith('sha256:'):
        # Failed inspect is not evidence of absence: that could misclassify a
        # preexisting image as newly acquired and authorize its later removal.
        _, inventory = command(['docker', 'image', 'ls', '--no-trunc', '--quiet'])
        ids = inventory.decode('ascii').splitlines()
        need(all(re.fullmatch(r'sha256:[0-9a-f]{64}', value) for value in ids),
             'complete immutable local image-ID inventory')
        if identifier not in ids:
            return None
    _, raw = command(['docker', 'image', 'inspect', identifier])
    rows = decode(raw)
    need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict,
         'one inspected immutable image')
    row = rows[0]
    return dict(id=row['Id'], architecture=row['Architecture'], os=row['Os'],
                repo_digests=sorted(row.get('RepoDigests') or []), repo_tags=sorted(row.get('RepoTags') or []))


def host(contract):
    need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64')
         and os.getuid() != 0, 'native non-root Linux ARM coordinator required')
    need((os.getuid(), os.getgid()) == (contract['alarm_uid'], contract['alarm_gid']),
         'reviewed alarm UID/GID must match this runner')
    need(all(shutil.which(name) for name in ('docker', 'lscpu')),
         'host Docker/probe tools required; no host installation')
    _, architecture = command(['docker', 'info', '--format', '{{.Architecture}}'])
    need(architecture.strip() in (b'aarch64', b'arm64'), 'native ARM Docker server required')
    _, raw = command(['docker', 'context', 'inspect'])
    context = decode(raw)
    need(type(context) is list and len(context) == 1 and
         context[0]['Endpoints']['docker']['Host'] in ENDPOINTS and
         os.environ.get('DOCKER_HOST', context[0]['Endpoints']['docker']['Host']) in ENDPOINTS,
         'native local Docker endpoint only')


# Executed only by the reviewed image's pinned Python, in an offline, capability-
# free, read-only, private-tmpfs container with no host filesystem binds.
QUALIFY = r'''
import hashlib,json,os,platform,pwd,re,stat,subprocess,sys
from pathlib import Path
c=json.loads(sys.argv[1]);uid=int(sys.argv[2]);gid=int(sys.argv[3])
def need(ok,why):
 if not ok:raise ValueError(why)
need(platform.system()=='Linux'and platform.machine()=='aarch64','native image runtime')
need(os.geteuid()==uid==c['alarm_uid']and os.getegid()==gid==c['alarm_gid']and uid!=0 and pwd.getpwuid(uid).pw_name=='alarm','exact alarm mapping')
marker=Path('/.dockerenv');need(marker.is_file()and not marker.is_symlink()and marker.stat().st_uid==0,'Docker marker')
status=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if':'in line)
caps={k:int(status.get(k,'-1').strip(),16)for k in('CapEff','CapPrm','CapBnd','CapInh','CapAmb')}
need(all(v==0 for v in caps.values())and int(status.get('NoNewPrivs','0'))==1,'capability-free NNP')
interfaces=sorted(p.name for p in Path('/sys/class/net').iterdir());need(interfaces==['lo'],'no network')
need(not any(Path(p).exists()for p in('/run/docker.sock','/var/run/docker.sock')),'no Docker socket')
mounts={}
for line in Path('/proc/self/mountinfo').read_text().splitlines():
 f=line.split();i=f.index('-');mounts[f[4]]=(f[i+1],set(f[5].split(',')))
need(mounts.get('/',('',set()))[0]in('overlay','fuse-overlayfs')and'ro'in mounts['/'][1],'read-only root')
need(mounts.get('/tmp',('',set()))[0]=='tmpfs'and{'rw','nosuid','nodev'}<=mounts['/tmp'][1],'private tmpfs')
t=Path('/tmp').stat();need(t.st_uid==uid and t.st_gid==gid and stat.S_IMODE(t.st_mode)==0o700,'private tmpfs ownership')
tools={}
for name,want in c['tools'].items():
 p=Path(name).resolve(strict=True);s=p.stat();need(str(p).startswith('/usr/')and stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and os.access(p,os.X_OK)and s.st_size==want['bytes'],'ordinary exact executable')
 with p.open('rb')as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
 need(digest==want['sha256'],'executable hash');tools[name]=dict(bytes=s.st_size,sha256=digest,resolved=str(p))
r=subprocess.run(['/usr/bin/pacman','-Q'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
need(r.returncode==0 and len(r.stdout)<=1024**2 and not r.stderr,'bounded complete package query')
lines=r.stdout.decode('ascii').splitlines();need(0<len(lines)<=4096 and len({x.split(' ')[0]for x in lines})==len(lines)and all(re.fullmatch(r'[a-z0-9@_+.-]+ [A-Za-z0-9._+:~@-]+',x)for x in lines),'canonical complete package inventory')
raw=('\n'.join(sorted(lines))+'\n').encode();digest=hashlib.sha256(raw).hexdigest();need(digest==c['packages_sha256'],'complete package lock')
guard=dict(arch=platform.machine(),uid=uid,gid=gid,user='alarm',capabilities=caps,no_new_privs=1,root_read_only=True,tmpfs_private=True,interfaces=interfaces,local_docker_socket_exposed=False)
print(json.dumps(dict(guard=guard,tools=tools,packages_sha256=digest,packages_count=len(lines)),sort_keys=True,separators=(',',':')))
'''


def remove_container(name, nonce, image):
    need(re.fullmatch(r'[0-9a-f]{32}', nonce) is not None and
         name == 'cachy-asahi-gui-signer-env-' + nonce and
         re.fullmatch(r'sha256:[0-9a-f]{64}', image) is not None,
         'exact owned qualification name, nonce, and image')
    _, raw = command(['docker', 'container', 'ls', '-a', '--no-trunc', '--filter',
                      'name=^/' + name + '$', '--format', '{{.ID}}'], 5)
    if not raw.strip():
        return dict(status='PASS', container_absent=True)
    identifier = raw.strip().decode('ascii')
    need(re.fullmatch(r'[0-9a-f]{64}', identifier) is not None,
         'one full qualification container ID')
    _, raw = command(['docker', 'container', 'inspect', identifier], 5)
    rows = decode(raw)
    need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict,
         'one inspected qualification container')
    row = rows[0]
    need(row['Id'] == identifier and row['Name'] == '/' + name and row['Image'] == image and
         type(row.get('Config')) is dict and type(row['Config'].get('Labels')) is dict and
         row['Config']['Labels'].get('org.cachy-asahi.gui-signer-environment') == nonce,
         'exact qualification container identity before removal')
    # A replacement reusing the name cannot redirect this immutable-ID removal.
    command(['docker', 'rm', '-f', identifier], 10)
    _, raw = command(['docker', 'container', 'ls', '-a', '--no-trunc', '--filter',
                      'id=' + identifier, '--format', '{{.ID}}'], 5)
    need(not raw.strip(), 'qualification container ID absent after cleanup')
    return dict(status='PASS', container_absent=True)


def qualify(contract, nonce):
    name = 'cachy-asahi-gui-signer-env-' + nonce
    _, present = command(['docker', 'container', 'ls', '-a', '--no-trunc', '--filter',
                          'name=^/' + name + '$', '--format', '{{.ID}}'], 10)
    need(not present.strip(), 'fresh qualification container name before actor')
    argv = ['docker', 'run', '--rm', '--name', name, '--pull=never', '--platform=linux/arm64',
            '--label', 'org.cachy-asahi.gui-signer-environment=' + nonce,
            '--user', str(os.getuid()) + ':' + str(os.getgid()), '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--read-only', '--network=none',
            '--cgroupns=private', '--pids-limit=128', '--memory=512m', '--cpus=2',
            '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=128m,mode=0700,uid=' +
            str(os.getuid()) + ',gid=' + str(os.getgid()), '--entrypoint=/usr/bin/python3',
            contract['image_id'], '-I', '-B', '-c', QUALIFY, enc(contract).decode(),
            str(os.getuid()), str(os.getgid())]
    try:
        _, raw = command(argv, 90)
        result = decode(raw)
        need(type(result) is dict and set(result) == {'guard', 'tools', 'packages_sha256', 'packages_count'},
             'exact qualification receipt')
        return result
    finally:
        with retirement():
            remove_container(name, nonce, contract['image_id'])


def prepare(args):
    raw = read(args.contract, 65536)
    need(re.fullmatch(r'[0-9a-f]{64}', args.sha256 or '') and sha(raw) == args.sha256,
         'Root-reviewed image contract hash')
    contract = validate(decode(raw))
    need(os.environ.get('SOURCE_SHA') == contract['source_sha'], 'contract joins exact workflow source')
    out = args.output
    need(out.is_absolute() and not out.exists() and not out.is_symlink() and
         out.parent == out.parent.resolve(), 'fresh private environment output')
    out.mkdir(mode=0o700)
    (out / 'contract.json').write_bytes(raw)
    (out / 'contract.json').chmod(0o600)
    receipt = dict(schema_version=1, purpose=PURPOSE, status='FAIL', source_sha=contract['source_sha'],
                   contract_sha256=args.sha256, image_id=contract['image_id'], oci_ref=contract['oci_ref'],
                   uid=os.getuid(), gid=os.getgid(), preexisting_image=None, acquired_image=False,
                   nonce=os.urandom(16).hex(), image_observation=None, qualification=None,
                   container_cleanup=dict(status='NOT_RUN', container_absent=True), error=None)
    try:
        with docker_config(out):
            host(contract)
            image = inspect_image(contract['image_id'])
            receipt['preexisting_image'] = image is not None
            if image is None:
                # There is no tag fallback and no build/install path.
                command(['docker', 'pull', '--platform=linux/arm64', contract['oci_ref']], 240)
                image = inspect_image(contract['oci_ref'])
                receipt['acquired_image'] = image is not None and image['id'] == contract['image_id']
            receipt['image_observation'] = image
            need(image is not None and image['id'] == contract['image_id'] and
                 image['architecture'] == 'arm64' and image['os'] == 'linux', 'exact native immutable image')
            receipt['qualification'] = qualify(contract, receipt['nonce'])
            receipt['container_cleanup'] = dict(status='PASS', container_absent=True)
            receipt['status'] = 'PASS'
    except BaseException as error:
        receipt['error'] = type(error).__name__
        raise
    finally:
        with retirement():
            save(out / 'environment.json', receipt)


def cleanup(args):
    out = args.output
    info = out.lstat()
    need(out == out.resolve() and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and stat.S_IMODE(info.st_mode) == 0o700, 'owned private environment output')
    receipt = decode(read(out / 'environment.json'))
    raw = read(out / 'contract.json', 65536)
    contract = validate(decode(raw))
    need(receipt['schema_version'] == 1 and receipt['purpose'] == PURPOSE and
         receipt['contract_sha256'] == sha(raw) and receipt['image_id'] == contract['image_id'] and
         receipt['oci_ref'] == contract['oci_ref'] and receipt['source_sha'] == contract['source_sha'] and
         receipt['uid'] == os.getuid() and receipt['gid'] == os.getgid(), 'owned environment contract receipt')
    result = dict(schema_version=1, purpose=PURPOSE, status='FAIL', source_sha=contract['source_sha'],
                  contract_sha256=sha(raw), image_id=contract['image_id'],
                  preserved_preexisting=False, removed_new_image=False, error=None)
    try:
        if receipt['preexisting_image'] is not False or receipt['acquired_image'] is not True:
            result.update(status='PASS', preserved_preexisting=receipt['preexisting_image'] is True)
            return
        with docker_config(out):
            host(contract)
            image = inspect_image(contract['image_id'])
            if image is None:
                result['status'] = 'PASS'
                return
            need(image['id'] == contract['image_id'] and image['repo_digests'] == [contract['oci_ref']]
                 and not image['repo_tags'], 'only the newly acquired sole-reference image may be removed')
            _, users = command(['docker', 'container', 'ls', '-a', '--no-trunc', '--filter',
                                'ancestor=' + contract['image_id'], '--format', '{{.ID}}'])
            need(not users.strip(), 'no foreign container may use the newly acquired image')
            # Remove only our exact digest reference. A concurrent foreign tag/ref
            # must survive; never force-remove the image ID or prune its parents.
            command(['docker', 'image', 'rm', '--no-prune', contract['oci_ref']], 30)
            need(inspect_image(contract['image_id']) is None, 'new image absent after bounded removal')
            result.update(status='PASS', removed_new_image=True)
    except BaseException as error:
        result['error'] = type(error).__name__
        raise
    finally:
        with retirement():
            save(out / 'cleanup.json', result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    setup = commands.add_parser('prepare')
    setup.add_argument('--contract', type=Path, required=True)
    setup.add_argument('--sha256', required=True)
    setup.add_argument('--output', type=Path, required=True)
    retire = commands.add_parser('cleanup')
    retire.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        with cancellation():
            (prepare if args.command == 'prepare' else cleanup)(args)
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(json.dumps(dict(status='FAIL', purpose=PURPOSE, error=type(error).__name__)))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
