#!/usr/bin/env python3
"""Optional container-owned 574 transaction; never replaces the held build guard."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import time
import uuid

HELPER = '27ba4be42cf2bd41675073e07cccc917ae033f9d68b07a33cfd7f074ac27b760'
INPUTS = 'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'
INVENTORY = 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
LABEL = 'org.cachy-asahi.bootstrap574.active-job'
ENV = {'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8', 'LC_ALL':'C.UTF-8'}


class ClientFenceError(ValueError):
    """The caller must preserve daemon resources when child reaping failed."""


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def private(path):
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute directory required')
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077, 'private owned directory required')


def regular(path):
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink input forbidden')
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022, 'ordinary owned input required')


def membership(path, wanted):
    observed = set()
    for item in path.rglob('*'):
        need(not item.is_symlink(), 'context symlink forbidden')
        if item.is_dir():
            need(item.relative_to(path).as_posix() in ('keys','deps'), 'extra context directory')
        else:
            regular(item)
            observed.add(item)
    need(observed == wanted, 'extra/missing context input')


def save(path, value):
    temporary = path.with_suffix('.partial')
    with temporary.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    temporary.replace(path)


def command(argv, log, env, seconds):
    """Fence our child session; a daemon executor is fenced separately by CID."""
    with log.open('xb') as stream:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                                 env=env, start_new_session=True)
        pending = None
        try:
            code = child.wait(timeout=seconds)
            need(code == 0, 'owned client command failed')
        except BaseException as error:
            pending = error
            raise
        finally:
            mask = signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
            try:
                reap(child)
            except BaseException as error:
                failure = ClientFenceError('owned client/session fence unproved')
                failure.cancelled = isinstance(pending,KeyboardInterrupt)
                raise failure from error
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK,mask)


def reap(child):
    # Descendants can survive a client that has already exited.
    for sig, duration in ((signal.SIGTERM, 2), (signal.SIGKILL, 3)):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            break
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            child.poll()
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired as error:
        raise ClientFenceError('owned client remains unreaped') from error
    try:
        os.killpg(child.pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise ClientFenceError('owned client process group remains')


class Docker:
    def __init__(self, out):
        self.out = out
        self.env = dict(ENV, HOME=str(out))
        self.serial = 0
        self.uncertain = False

    def run(self, *args, seconds=20, raw=False):
        self.serial += 1
        log = self.out / ('client-%03d.log' % self.serial)
        self.uncertain = True
        command(['/usr/bin/docker', *map(str,args)], log, self.env, seconds)
        self.uncertain = False
        need(log.stat().st_size <= 1024**2, 'bounded client output required')
        text = log.read_text()
        return text if raw else text.strip()


class Owner:
    def __init__(self, docker, token):
        need(re.fullmatch('[0-9a-f]{16}', token), 'invalid token')
        self.d = docker
        self.token = token
        self.before = self.images()
        self.images_owned = []
        self.containers = []
        self.names = {kind:'cachy-asahi-574-active-'+token+'-'+kind for kind in ('build','probe')}
        self.tags = {kind:'cachy-asahi-574-active:'+token+'-'+kind for kind in ('root','result')}
        for tag in self.tags.values():
            need(not self.d.run('image','ls','-a','--filter','reference='+tag,'-q'), 'tag collision')
        need(not self.d.run('image','ls','-a','--filter','label='+LABEL+'='+token,'-q'), 'label collision')
        for name in self.names.values():
            need(not self.named(name), 'container name collision')

    def images(self):
        values = self.d.run('image','ls','-a','--no-trunc','-q').splitlines()
        need(all(re.fullmatch('sha256:[0-9a-f]{64}',v) for v in values), 'invalid image list')
        return sorted(set(values))

    def named(self, name):
        rows = self.d.run('container','ls','-a','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}}').splitlines()
        need(len(rows) <= 1 and all(re.fullmatch('[0-9a-f]{64}',v) for v in rows), 'ambiguous name')
        return rows

    def image(self, image, tag):
        need(re.fullmatch('sha256:[0-9a-f]{64}', image) and image not in self.before, 'initial/invalid image preserved')
        rows = json.loads(self.d.run('image','inspect',image)); need(len(rows)==1, 'ambiguous image')
        row = rows[0]
        need(row['Id']==image and row['Os']=='linux' and row['Architecture']=='arm64' and
             (row['Config'].get('Labels') or {}).get(LABEL)==self.token and
             set(row.get('RepoTags') or [])=={tag} and not row.get('RepoDigests'), 'image identity/references differ')
        return image

    def admit_image(self, kind):
        tag = self.tags[kind]
        ids = self.d.run('image','ls','-a','--no-trunc','--filter','reference='+tag,'-q').splitlines()
        need(len(ids)==1, 'image creation outcome unknown')
        image = self.image(ids[0], tag)
        need(image not in [row['id'] for row in self.images_owned], 'image alias refused')
        self.images_owned.append({'id':image,'tag':tag})
        return image

    def inspect_container(self, cid, name, image):
        rows = json.loads(self.d.run('container','inspect',cid)); need(len(rows)==1, 'ambiguous container')
        row = rows[0]
        need(row['Id']==cid and row['Name']=='/'+name and row['Image']==image and
             (row['Config'].get('Labels') or {}).get(LABEL)==self.token, 'container identity differs')
        return row

    def create(self, kind, image, argv, extra=()):
        name = self.names[kind]
        value = self.d.run('container','create','--name',name,'--label',LABEL+'='+self.token,
                           '--pull=never','--network=none',*extra,'--entrypoint',argv[0],image,*argv[1:])
        need(re.fullmatch('[0-9a-f]{64}',value), 'invalid created CID')
        self.inspect_container(value,name,image)
        self.containers.append({'cid':value,'name':name,'image':image})
        return value

    def cleanup(self, client_fenced):
        result = {'status':'FAIL','client_fenced':client_fenced,'containers':[], 'images':[],
                  'initial_image_ids':self.before,'initial_image_ids_preserved':False,
                  'captured_containers':list(self.containers),'captured_images':list(self.images_owned)}
        try:
            need(client_fenced, 'client/creation/commit outcome unknown; preserve resources')
            # Exact captured CIDs only. Never recover an ambiguous create by name.
            for row in reversed(self.containers):
                cid,name,image = (row[k] for k in ('cid','name','image'))
                present = self.named(name)
                by_id = self.d.run('container','ls','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}').splitlines()
                need(present in ([],[cid]) and by_id in ([],[cid]) and present==by_id, 'container handle/name differs')
                if present:
                    self.inspect_container(cid,name,image)
                    self.d.run('container','rm','-f',cid)
                need(not self.named(name) and not self.d.run('container','ls','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}'), 'container remains')
                result['containers'].append(dict(row,absence_verified=True))
            for row in reversed(self.images_owned):
                image,tag = row['id'],row['tag']
                self.image(image,tag)
                need(not self.d.run('container','ls','-a','--filter','ancestor='+image,'--format','{{.ID}}'), 'foreign container reference preserved')
                self.d.run('image','rm','--no-prune',image)
                need(image not in self.images() and not self.d.run('image','ls','-a','--filter','reference='+tag,'-q'), 'image remains')
                result['images'].append(dict(row,absence_verified=True))
            result['status'] = 'PASS'
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
            result['error_kind'] = type(error).__name__
        try:
            result['after_image_ids'] = self.images()
            result['initial_image_ids_preserved'] = set(self.before) <= set(result['after_image_ids'])
        except (OSError,ValueError,subprocess.SubprocessError):
            pass
        if not result['initial_image_ids_preserved']:
            result['status'] = 'FAIL'
        return result


def context(here, path):
    private(path)
    helper = here/'maintained_desktop574.py'; inputs = here/'maintained-desktop574-inputs.json'
    need(digest(helper)==HELPER and digest(inputs)==INPUTS, 'held source differs')
    spec = importlib.util.spec_from_file_location('active574_held',helper)
    held = importlib.util.module_from_spec(spec); spec.loader.exec_module(held)
    value = json.loads(inputs.read_bytes())
    planned = held.plan(value,path)
    for row in planned:
        file = row['target']; regular(file)
        need(file.stat().st_size==row['size'] and digest(file)==row['sha256'], 'prepared input differs')
    lock = ''.join('{} {}\n'.format(p['name'],p['version']) for p in sorted(value['packages'],key=lambda p:p['name']))
    expected = {'Dockerfile':held.DOCKERFILE,'finish-keyring.py':held.KEYRING_FINALIZER,
                'pacman.conf':held.PACMAN,'disabled-hooks.txt':''.join(h+'\n' for h in sorted(set(value['bootstrap_hook_masks']))),
                'expected-packages.lock':lock}
    for name,text in expected.items():
        regular(path/name); need((path/name).read_bytes()==text.encode(), 'prepared generated input differs')
    membership(path,{row['target'] for row in planned} | {path/name for name in expected})
    need(hashlib.sha256(lock.encode()).hexdigest()==INVENTORY, '574 inventory differs')
    transaction = held.DOCKERFILE.split('\nRUN ',1)[1].replace('\\\n','').strip()
    return transaction, lock


def execute(owner, prepared, transaction, lock, out):
    result = {'status':'FAIL','scope':'OPTIONAL_CONTAINER_OWNED_574_TRANSACTION','hardware':'NOT_RUN',
              'cancelled':False,'phase':'root-import','helper_sha256':HELPER,'inputs_sha256':INPUTS,
              'token':owner.token,'initial_image_ids':owner.before,'active_executor':None}
    pending = None
    fenced = False
    try:
        save(out/'result.json',result)
        owner.d.run('image','import','--platform','linux/arm64','--change','LABEL '+LABEL+'='+owner.token,
                    prepared/'rootfs.tar.gz',owner.tags['root'],seconds=120)
        image = owner.admit_image('root')
        result['phase'] = 'build-create'
        cid = owner.create('build',image,['/bin/sh','-ec',transaction])
        result['phase'] = 'build-copy'
        transfer = out/'transfer'; transfer.mkdir(mode=0o700)
        for name in ('pacman.conf','finish-keyring.py'):
            (transfer/name).write_bytes((prepared/name).read_bytes())
            (transfer/name).chmod(0o644)  # Held Dockerfile's two explicit COPY --chmod directives.
        for name,target in (('keys/.','/usr/share/pacman/keyrings/'),('deps','/tmp/'),('pacman.conf','/etc/pacman.conf'),
                            ('disabled-hooks.txt','/tmp/disabled-hooks.txt'),('expected-packages.lock','/expected-packages.lock'),
                            ('finish-keyring.py','/tmp/finish-keyring.py')):
            source = str(transfer/name) if name in ('pacman.conf','finish-keyring.py') else str(prepared)+'/'+name
            owner.d.run('container','cp',source,cid+':'+target,seconds=120)
        # Unlike opaque `docker build`, this daemon executor has a known CID.
        result.update(phase='active-build',active_executor=dict(owner.containers[-1]))
        save(out/'result.json',result)
        owner.d.run('container','start','-a',cid,seconds=2400)
        state = owner.inspect_container(cid,owner.names['build'],image)['State']
        need(state['Running'] is False and state['ExitCode']==0, '574 transaction failed')
        result['phase'] = 'commit'
        owner.d.run('container','commit','--change','LABEL '+LABEL+'='+owner.token,cid,owner.tags['result'],seconds=120)
        final = owner.admit_image('result')
        result['phase'] = 'probe-create'
        probe = owner.create('probe',final,['/bin/cat','/builder-packages.lock'],
                             ('--read-only','--cap-drop=ALL','--security-opt=no-new-privileges'))
        result.update(phase='active-probe',active_executor=dict(owner.containers[-1]))
        save(out/'result.json',result)
        observed = owner.d.run('container','start','-a',probe,seconds=60,raw=True)
        state = owner.inspect_container(probe,owner.names['probe'],final)['State']
        need(state['Running'] is False and state['ExitCode']==0 and observed==lock, 'installed inventory differs')
        result.update(status='PASS',packages=574,inventory_sha256=INVENTORY,phase='completed')
        fenced = True
    except BaseException as error:
        pending = error
        result.update(error_kind=type(error).__name__,cancelled=isinstance(error,KeyboardInterrupt) or getattr(error,'cancelled',False))
        # Start/attach does not create resources: an exact CID already fences its executor.
        # Other client failures can leave an unobservable in-flight import/create/commit/copy.
        fenced = result['phase'] in ('active-build','active-probe') and not isinstance(error,ClientFenceError)
    finally:
        # A second TERM/INT cannot skip exact-CID cleanup; restore the caller mask.
        mask = signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        try:
            result['cleanup'] = owner.cleanup(fenced)
            if result['cleanup']['status']!='PASS': result['status']='FAIL'
            if signal.sigpending() & {signal.SIGINT,signal.SIGTERM}:
                result.update(status='FAIL',cancelled=True)
            save(out/'result.json',result)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK,mask)
    if isinstance(pending,KeyboardInterrupt): raise pending
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-ci',required=True,type=Path)
    parser.add_argument('--prepared-context',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args = parser.parse_args(); os.umask(0o077)
    need(platform.system()=='Linux' and platform.machine() in ('aarch64','arm64') and os.getuid()==os.geteuid()>0, 'ordinary native ARM required')
    need(not any(k.startswith('DOCKER_') for k in os.environ), 'Docker overrides forbidden')
    prepared,out = args.prepared_context.absolute(),args.output.absolute()
    private(prepared)
    need(not out.exists() and not any(p.is_symlink() for p in (out,*out.parents)) and
         not out.is_relative_to(prepared) and not prepared.is_relative_to(out), 'fresh separate output required')
    fd = os.open(prepared,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    old = {}
    try:
        transaction,lock = context(args.source_ci.absolute(),prepared)
        out.mkdir(mode=0o700)
        docker = Docker(out)
        need(docker.run('context','show')=='default', 'default daemon required')
        info = json.loads(docker.run('context','inspect','default'))
        need(len(info)==1 and info[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock', 'local daemon required')
        need(docker.run('info','--format','{{.Architecture}}') in ('aarch64','arm64'), 'native daemon required')
        def cancel(*_): raise KeyboardInterrupt()
        for sig in (signal.SIGINT,signal.SIGTERM): old[sig]=signal.signal(sig,cancel)
        owner = Owner(docker,uuid.uuid4().hex[:16])
        result = execute(owner,prepared,transaction,lock,out)
        return int(result['status']!='PASS')
    finally:
        for sig,handler in old.items(): signal.signal(sig,handler)
        os.close(fd)


if __name__=='__main__':
    raise SystemExit(main())
