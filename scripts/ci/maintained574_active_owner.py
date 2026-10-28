#!/usr/bin/env python3
"""Optional container-owned 574 transaction; never replaces the held build guard."""
import argparse
import base64
from contextlib import ExitStack
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import socket
import stat
import subprocess
import tarfile
import time
import uuid
from urllib.parse import quote

HELPER = '27ba4be42cf2bd41675073e07cccc917ae033f9d68b07a33cfd7f074ac27b760'
INPUTS = 'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'
INVENTORY = 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
LABEL = 'org.cachy-asahi.bootstrap574.active-job'
ENV = {'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8', 'LC_ALL':'C.UTF-8'}
TRUST_PATHS = tuple('/etc/pacman.d/gnupg/'+name for name in (
    'pubring.kbx','pubring.gpg','trustdb.gpg','tofu.db','gpg.conf','gpg-agent.conf',
    'common.conf','public-keys.d/pubring.db')) + ('/etc/pacman.conf',)
TRUST_FAILURE = b'ValueError: ordinary bounded producer trust/config required'
COPY_CONTROLS = ('/etc/pacman.conf','/tmp/finish-keyring.py','/tmp/disabled-hooks.txt','/expected-packages.lock')
COPY_LIMIT = 2*1024**3


class MetadataConnection(http.client.HTTPConnection):
    """Only the already-admitted local daemon; never a TCP/remote fallback."""
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/var/run/docker.sock')


class HeaderReader:
    def __init__(self, response, limit=65536):
        self.response = response
        self.remaining = limit

    def read(self, size=-1):
        need(self.remaining > 0, 'archive header bound')
        amount = min(self.remaining,size if size >= 0 else self.remaining)
        data = self.response.read(amount)
        self.remaining -= len(data)
        return data


def trust_header(cid, path):
    need(re.fullmatch('[0-9a-f]{64}',cid) and path in TRUST_PATHS,'fixed metadata target required')
    client = MetadataConnection('local-docker',timeout=3)
    response = None
    try:
        client.request('GET','/containers/'+cid+'/archive?path='+quote(path,safe=''))
        response = client.getresponse()
        need(type(response.status) is int and 100<=response.status<=599,'HTTP status differs')
        if response.status != 200:
            return {'path':path,'status':'HTTP_ERROR','http_status':response.status}
        with tarfile.open(fileobj=HeaderReader(response),mode='r|') as archive:
            member = archive.next()
            need(member is not None and member.name==Path(path).name,'archive root identity differs')
            need(type(member.uid) is int and 0<=member.uid<=2**32-1 and
                 type(member.gid) is int and 0<=member.gid<=2**32-1 and
                 type(member.size) is int and 0<=member.size<=2**63-1,'archive numeric metadata differs')
            kind = 'regular' if member.isreg() else 'symlink' if member.issym() else 'directory' if member.isdir() else 'other'
            return {'path':path,'status':'PRESENT','archive_type':kind,'uid':member.uid,'gid':member.gid,
                    'mode':member.mode & 0o7777,'bytes':member.size,
                    'fails_regular_uid_size_predicate':kind!='regular' or member.uid!=0 or member.size>32*1024**2}
    finally:
        if response is not None: response.close()
        client.close()


def trust_identity(owner, row, created=False):
    """Recheck the stopped owner through the same read-only Unix connection."""
    client = MetadataConnection('local-docker',timeout=3)
    response = None
    try:
        need(re.fullmatch('[0-9a-f]{64}',row['cid']),'fixed container CID required')
        client.request('GET','/containers/'+row['cid']+'/json')
        response = client.getresponse()
        need(response.status==200,'container metadata unavailable')
        raw = response.read(65537); need(len(raw)<=65536,'container metadata bound')
        value = json.loads(raw)
        need(value['Id']==row['cid'] and value['Name']=='/'+row['name'] and value['Image']==row['image'] and
             (value['Config'].get('Labels') or {}).get(LABEL)==owner.token,'container metadata identity differs')
        state = value['State']
        need(state['Running'] is False and type(state['ExitCode']) is int,'stopped container required')
        if created: need(state['ExitCode']==0 and state['Status']=='created','unstarted build required')
        else: need(state['ExitCode']!=0,'failed build required')
    finally:
        if response is not None: response.close()
        client.close()


def trust_metadata(owner):
    """Fixed-path archive headers only, after failure and before existing cleanup."""
    value = {'status':'UNAVAILABLE','method':'fixed-path-docker-archive-headers','rows':[]}
    previous = signal.getsignal(signal.SIGALRM)
    timer = signal.setitimer(signal.ITIMER_REAL,0)
    def expired(*_): raise TimeoutError('metadata deadline')
    try:
        signal.signal(signal.SIGALRM,expired); signal.setitimer(signal.ITIMER_REAL,30)
        need(len(owner.containers)==1,'one failed build container required')
        row = owner.containers[0]
        need(row['name']==owner.names['build'],'build name differs')
        trust_identity(owner,row)
        value['container'] = dict(row)
        for path in TRUST_PATHS:
            try: value['rows'].append(trust_header(row['cid'],path))
            except Exception as error:
                value['rows'].append({'path':path,'status':'UNAVAILABLE','error_kind':type(error).__name__})
                if isinstance(error,TimeoutError): raise
        value['status'] = 'OBSERVED'
    except Exception as error:
        value['error_kind'] = type(error).__name__
    finally:
        signal.setitimer(signal.ITIMER_REAL,0); signal.signal(signal.SIGALRM,previous)
        signal.setitimer(signal.ITIMER_REAL,*timer)
    return value


class ClientFenceError(ValueError):
    """The caller must preserve daemon resources when child reaping failed."""


class ClientCommandError(ValueError):
    def __init__(self, code, log):
        super().__init__('owned client command failed')
        self.diagnostic = None
        try:
            with log.open('rb') as stream:
                size = os.fstat(stream.fileno()).st_size
                stream.seek(max(0, size - 4096))
                tail = stream.read(4096)
            self.diagnostic = dict(returncode=code, log_bytes=size,
                tail_bytes=len(tail), tail_sha256=hashlib.sha256(tail).hexdigest(),
                tail_base64=base64.b64encode(tail).decode('ascii'))
        except OSError:
            pass


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


def command(argv, log, env, seconds, stdin_path=None):
    """Fence our child session; a daemon executor is fenced separately by CID."""
    with ExitStack() as stack:
        stream = stack.enter_context(log.open('xb'))
        if stdin_path is not None: regular(stdin_path)
        incoming = stack.enter_context(stdin_path.open('rb')) if stdin_path is not None else subprocess.DEVNULL
        child = subprocess.Popen(argv, stdin=incoming, stdout=stream, stderr=subprocess.STDOUT,
                                 env=env, start_new_session=True)
        pending = None
        try:
            code = child.wait(timeout=seconds)
            if code != 0:
                raise ClientCommandError(code, log)
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

    def run(self, *args, seconds=20, raw=False, stdin_path=None):
        self.serial += 1
        log = self.out / ('client-%03d.log' % self.serial)
        self.uncertain = True
        if stdin_path is None:
            command(['/usr/bin/docker', *map(str,args)], log, self.env, seconds)
        else:
            command(['/usr/bin/docker', *map(str,args)], log, self.env, seconds, stdin_path=stdin_path)
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


def copy_archive(prepared, path):
    """Encode COPY's container-root ownership, never chown host source files."""
    members = {}
    deps = prepared/'deps'; private(deps); private(prepared/'keys')
    members['/tmp/deps'] = {'type':'directory','mode':stat.S_IMODE(deps.stat().st_mode),'bytes':0,'sha256':None}
    sources = []
    for folder,target in (('keys','/usr/share/pacman/keyrings'),('deps','/tmp/deps')):
        for source in sorted((prepared/folder).iterdir()): sources.append((source,target+'/'+source.name))
    for target in COPY_CONTROLS: sources.append((prepared/Path(target).name,target))
    need(len(sources)<=1155 and len({target for _,target in sources})==len(sources),'copy member bound')
    total = 0
    for source,target in sources:
        regular(source); info=source.stat(); total+=info.st_size
        need(total<=COPY_LIMIT,'copy byte bound')
        mode = 0o644 if target in COPY_CONTROLS[:2] else stat.S_IMODE(info.st_mode)
        members[target] = {'type':'regular','mode':mode,'bytes':info.st_size,'sha256':digest(source)}
    with path.open('xb') as output:
        path.chmod(0o600)
        with tarfile.open(fileobj=output,mode='w',format=tarfile.PAX_FORMAT) as archive:
            for target,row in members.items():
                member=tarfile.TarInfo(target.lstrip('/'))
                member.uid=member.gid=0; member.uname=member.gname='root'; member.mtime=0
                member.mode=row['mode']; member.size=row['bytes']
                if row['type']=='directory':
                    member.type=tarfile.DIRTYPE;archive.addfile(member)
                else:
                    source=next(source for source,destination in sources if destination==target)
                    with source.open('rb') as stream: archive.addfile(member,stream)
    need(path.stat().st_size<=COPY_LIMIT,'copy archive bound')
    return members,{'bytes':path.stat().st_size,'sha256':digest(path)}


def verify_copy_scope(cid, path, expected):
    """Stream back owned COPY members; no extraction or payload retention."""
    scopes=('/usr/share/pacman/keyrings','/tmp/deps',*COPY_CONTROLS)
    need(re.fullmatch('[0-9a-f]{64}',cid) and path in scopes,'fixed copy scope required')
    client=MetadataConnection('local-docker',timeout=15);response=None;seen=set()
    try:
        client.request('GET','/containers/'+cid+'/archive?path='+quote(path,safe=''))
        response=client.getresponse();need(response.status==200,'copied scope unavailable')
        limit=COPY_LIMIT if path=='/tmp/deps' else 64*1024**2 if path==scopes[0] else 1024**2
        with tarfile.open(fileobj=HeaderReader(response,limit),mode='r|') as archive:
            for member in archive:
                name=member.name.rstrip('/');parts=PurePosixPath(name)
                need(name==str(parts) and not parts.is_absolute() and '..' not in parts.parts,'copied archive path differs')
                root=Path(path).name
                need(name==root or name.startswith(root+'/'),'copied archive root differs')
                target=path+name[len(root):]
                if target not in expected:
                    # COPY merges these three keys into the imported keyring directory.
                    # Retain unrelated preexisting keys; never claim them as our copy.
                    need(path==scopes[0],'unexpected copied member')
                    continue
                row=expected[target]
                need(target not in seen and member.uid==member.gid==0 and member.mode==row['mode'] and
                     member.size==row['bytes'],'copied ownership/mode/size differs')
                need(member.isdir() if row['type']=='directory' else member.isreg(),'copied type differs')
                if member.isreg():
                    hasher=hashlib.sha256()
                    with archive.extractfile(member) as stream:
                        while block:=stream.read(1024**2):hasher.update(block)
                    need(hasher.hexdigest()==row['sha256'],'copied bytes differ')
                seen.add(target)
        return seen
    finally:
        if response is not None:response.close()
        client.close()


def verify_copy(owner, expected, archive):
    need(len(owner.containers)==1,'one copy executor required')
    row=owner.containers[0];need(row['name']==owner.names['build'],'copy executor name differs')
    previous=signal.getsignal(signal.SIGALRM);timer=signal.setitimer(signal.ITIMER_REAL,0)
    def expired(*_):raise TimeoutError('copy verification deadline')
    try:
        signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,300)
        trust_identity(owner,row,created=True)
        seen=set()
        for path in ('/usr/share/pacman/keyrings','/tmp/deps',*COPY_CONTROLS):
            observed=verify_copy_scope(row['cid'],path,expected)
            need(not seen&observed,'duplicate copy observation');seen.update(observed)
        need(seen==set(expected),'copied member set differs')
        trust_identity(owner,row,created=True)
        return {'status':'PASS_ROOT_OWNED_COPY','container':dict(row),'archive':archive,
                'files_verified':sum(v['type']=='regular' for v in expected.values()),'directories_verified':1,
                'uid':0,'gid':0,'members_sha256':hashlib.sha256(json.dumps(expected,sort_keys=True).encode()).hexdigest(),
                'controls':[dict(path=path,uid=0,gid=0,**expected[path]) for path in COPY_CONTROLS]}
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
        signal.setitimer(signal.ITIMER_REAL,*timer)


def execute(owner, prepared, transaction, lock, out):
    result = {'status':'FAIL','scope':'OPTIONAL_CONTAINER_OWNED_574_TRANSACTION','hardware':'NOT_RUN',
              'cancelled':False,'phase':'root-import','helper_sha256':HELPER,'inputs_sha256':INPUTS,
              'token':owner.token,'initial_image_ids':owner.before,'active_executor':None}
    pending = None
    fenced = False
    inspect_trust = False
    try:
        save(out/'result.json',result)
        owner.d.run('image','import','--platform','linux/arm64','--change','LABEL '+LABEL+'='+owner.token,
                    prepared/'rootfs.tar.gz',owner.tags['root'],seconds=120)
        image = owner.admit_image('root')
        result['phase'] = 'build-create'
        cid = owner.create('build',image,['/bin/sh','-ec',transaction])
        result['phase'] = 'build-copy'
        transfer=out/'copy-inputs.tar'
        expected,archive=copy_archive(prepared,transfer)
        owner.d.run('container','cp','--archive','-',cid+':/',seconds=240,stdin_path=transfer)
        result['copy_metadata']=verify_copy(owner,expected,archive)
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
        # Only this fixed public-input transaction's output is eligible. Other
        # commands and seed/controller logs stay outside the public projection.
        if result['phase'] == 'active-build' and isinstance(error, ClientCommandError) and error.diagnostic is not None:
            result['build_failure'] = error.diagnostic
            inspect_trust = TRUST_FAILURE in base64.b64decode(error.diagnostic['tail_base64'])
        # Start/attach does not create resources: an exact CID already fences its executor.
        # Other client failures can leave an unobservable in-flight import/create/commit/copy.
        fenced = result['phase'] in ('active-build','active-probe') and not isinstance(error,ClientFenceError)
    finally:
        # A second TERM/INT cannot skip exact-CID cleanup; restore the caller mask.
        mask = signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        try:
            if inspect_trust:
                try: result['trust_metadata'] = trust_metadata(owner)
                except Exception as error:
                    result['trust_metadata'] = {'status':'UNAVAILABLE','method':'fixed-path-docker-archive-headers',
                                                'rows':[],'error_kind':type(error).__name__}
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
