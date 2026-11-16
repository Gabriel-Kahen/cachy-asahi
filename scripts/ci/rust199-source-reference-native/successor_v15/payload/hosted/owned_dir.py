# SPDX-License-Identifier: MIT
"""One fresh external job directory, held by FD until bounded retirement."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

STATUS = 'OWNED_EXTERNAL_JOB_DIRECTORY_PRIVATE_BIND_ONLY'
OPERATION = 'rust199-source-reference-native-v1'
FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
MAX_NODES = 2000000
MAX_DEPTH = 64


def need(ok, message):
    if not ok: raise ValueError(message)


def canonical(value):
    need(type(value) is str and 1 < len(value) <= 4096 and all(32 < ord(c) < 127 and c not in ',:\\' for c in value), 'finite local path')
    p = Path(value)
    need(p.is_absolute() and not value.startswith('//') and p.as_posix() == value and all(x not in ('.', '..') for x in value.split('/')[1:]), 'canonical local path')
    return p


def node(s):
    return dict(device=s.st_dev, inode=s.st_ino, uid=s.st_uid, gid=s.st_gid, mode=stat.S_IMODE(s.st_mode))


def mount_id(fd):
    rows = [line.split(':', 1)[1].strip() for line in Path('/proc/self/fdinfo/'+str(fd)).read_text().splitlines() if line.startswith('mnt_id:')]
    need(len(rows) == 1 and rows[0].isdigit() and int(rows[0]) > 0, 'held FD kernel mount identity')
    return int(rows[0])


def open_root(path):
    fd = os.open('/', FLAGS)
    try:
        for part in path.parts[1:]:
            child = os.open(part, FLAGS, dir_fd=fd); os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd); raise


def daemon(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 1024**2, 'bounded projected daemon body')
    def pairs(items):
        value = {}
        for k, v in items:
            need(k not in value, 'duplicate daemon key'); value[k] = v
        return value
    value = json.loads(raw, object_pairs_hook=pairs)
    need(type(value) is dict and set(value) == {'ID','DockerRootDir','OSType','Architecture','CgroupVersion','SecurityOptions','OperatingSystem'}, 'exact projected daemon fields')
    need(type(value['ID']) is str and 0 < len(value['ID']) <= 256 and value['OSType'] == 'linux' and value['Architecture'] in ('arm64','aarch64') and value['CgroupVersion'] == '2' and type(value['SecurityOptions']) is list and all(type(x) is str and 'rootless' not in x.lower() for x in value['SecurityOptions']) and type(value['OperatingSystem']) is str and 'docker desktop' not in value['OperatingSystem'].lower(), 'rootful native local Linux cgroupv2 daemon')
    canonical(value['DockerRootDir'])
    return value


def validate(value, volume, labels):
    keys = {'schema','status','endpoint','daemon_inspect','daemon_root','volume','labels','job_root','job_root_node','job_root_mount_id','work_source','stage0_source','workspace_node','workspace_mount_id','nonce','producer','bind_propagation','native_acceptance','holds_preserved'}
    need(type(value) is dict and set(value) == keys and type(value['schema']) is int and value['schema'] == 15 and value['status'] == STATUS and value['endpoint'] == 'unix:///var/run/docker.sock' and value['volume'] == volume and value['labels'] == labels and value['bind_propagation'] == 'rprivate' and value['native_acceptance'] is False and value['holds_preserved'] is True, 'whole owned external directory proof')
    need(type(volume) is str and re.fullmatch(r'rust199-(?:qual-)?[0-9a-f]{24}-work', volume), 'exact source token workspace basename')
    envelope = value['daemon_inspect']; need(type(envelope) is dict and set(envelope) == {'json','pin'} and type(envelope['json']) is str, 'whole projected daemon envelope')
    raw = envelope['json'].encode(); need(envelope['pin'] == dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()), 'whole daemon body pin')
    info = daemon(raw); root = canonical(value['job_root']); work = canonical(value['work_source']); storage = canonical(info['DockerRootDir'])
    need(value['daemon_root'] == str(storage) and work == root/volume and value['stage0_source'] == str(work/'build/stage0') and not any(a.is_relative_to(b) or b.is_relative_to(a) for a,b in ((root,storage),)), 'fresh direct job child outside actual daemon root')
    for key in ('job_root_node','workspace_node'):
        row = value[key]; need(type(row) is dict and set(row) == {'device','inode','uid','gid','mode'} and all(type(x) is int for x in row.values()) and row['device'] >= 0 and row['inode'] > 0 and row['uid'] == row['gid'] == 1001 and row['mode'] == 0o700, 'exact ordinary job/work owner and mode')
    need(value['job_root_node']['device'] == value['workspace_node']['device'] and value['job_root_node']['inode'] != value['workspace_node']['inode'] and type(value['job_root_mount_id']) is int and value['job_root_mount_id'] > 0 and type(value['workspace_mount_id']) is int and value['workspace_mount_id'] == value['job_root_mount_id'], 'disjoint held directories on same kernel mount')
    producer = value['producer']; need(type(producer) is dict and set(producer) == {'source','token','operation'} and producer['operation'] == OPERATION and type(producer['source']) is dict, 'explicit producer identity')
    token = hashlib.sha256((json.dumps(producer['source'],sort_keys=True,indent=2,allow_nan=False)+'\n').encode()).hexdigest()[:24]
    need(producer['token'] == token and volume in ('rust199-'+token+'-work','rust199-qual-'+token+'-work') and labels == {'cachy-asahi.operation':OPERATION,'cachy-asahi.source':producer['source']['sha'],'cachy-asahi.run':producer['source']['run'],'cachy-asahi.job':producer['source']['job'],'cachy-asahi.token':token,'cachy-asahi.role':'qualification-volume' if '-qual-' in volume else 'volume'}, 'source/run/job/token/role binding')
    need(type(value['nonce']) is str and re.fullmatch('[0-9a-f]{64}',value['nonce']), 'fresh creator nonce')
    return value


class Lease:
    def __init__(self, work, volume, daemon_raw, bindings, source_root):
        self.root = canonical(str(work)); self.path = self.root/volume; self.rootfd = self.fd = None; self.created = False
        info = daemon(daemon_raw); storage = canonical(info['DockerRootDir']); source_root = canonical(str(source_root))
        need(not any(a.is_relative_to(b) or b.is_relative_to(a) for a,b in ((self.root,storage),(self.path,source_root))), 'owned job workspace disjoint from daemon storage/source')
        need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 1001, 'ordinary admitted native job uid/gid1001')
        need(re.fullmatch(r'rust199-(?:qual-)?[0-9a-f]{24}-work',volume), 'fixed direct workspace child')
        try:
            self.rootfd = open_root(self.root); self.rootnode = node(os.fstat(self.rootfd)); self.mount = mount_id(self.rootfd)
            need(stat.S_ISDIR(os.fstat(self.rootfd).st_mode) and self.rootnode['uid'] == self.rootnode['gid'] == 1001 and self.rootnode['mode'] == 0o700, 'already admitted private ordinary job root')
            os.mkdir(volume,0o700,dir_fd=self.rootfd); self.created = True
            self.fd = os.open(volume,FLAGS,dir_fd=self.rootfd); self.worknode = node(os.fstat(self.fd))
            need(self.worknode['uid'] == self.worknode['gid'] == 1001 and self.worknode['mode'] == 0o700 and not os.listdir(self.fd) and mount_id(self.fd) == self.mount, 'fresh empty1001:1001/0700 directory on held job mount')
            source = {'sha':bindings['cachy-asahi.source'],'run':bindings['cachy-asahi.run'],'job':bindings['cachy-asahi.job']}
            # Full source identity is supplied by the caller before any actor.
            self.proof = dict(schema=15,status=STATUS,endpoint='unix:///var/run/docker.sock',daemon_inspect=dict(json=daemon_raw.decode(),pin=dict(bytes=len(daemon_raw),sha256=hashlib.sha256(daemon_raw).hexdigest())),daemon_root=str(storage),volume=volume,labels=bindings,job_root=str(self.root),job_root_node=self.rootnode,job_root_mount_id=self.mount,work_source=str(self.path),stage0_source=str(self.path/'build/stage0'),workspace_node=self.worknode,workspace_mount_id=mount_id(self.fd),nonce=secrets.token_hex(32),producer=dict(source=source,token=bindings['cachy-asahi.token'],operation=OPERATION),bind_propagation='rprivate',native_acceptance=False,holds_preserved=True)
            self.check()
        except BaseException as error:
            # Only the newly created empty inode is eligible for rollback.
            absent = not self.created
            try:
                if self.created and self.fd is not None:
                    held = node(os.fstat(self.fd))
                    need(held['uid'] == held['gid'] == 1001 and held['mode'] == 0o700 and mount_id(self.fd) == self.mount and not os.listdir(self.fd) and node(os.stat(volume,dir_fd=self.rootfd,follow_symlinks=False)) == held, 'refuse unsafe allocation rollback')
                    os.rmdir(volume,dir_fd=self.rootfd)
                    try: os.stat(volume,dir_fd=self.rootfd,follow_symlinks=False)
                    except FileNotFoundError: absent = True
                need(absent, 'WORKSPACE_ALLOCATION_RETIREMENT_HOLD: '+str(self.path))
            except BaseException as cleanup:
                raise ValueError('WORKSPACE_ALLOCATION_RETIREMENT_HOLD: '+str(self.path)+'; '+str(cleanup)) from error
            finally: self.close()
            raise

    def bind_source(self, source):
        self.proof['producer']['source'] = source
        validate(self.proof,self.path.name,self.proof['labels'])
        return self.proof

    def check(self):
        need(self.fd is not None and self.rootfd is not None, 'workspace FDs still held')
        current = open_root(self.root)
        try: need(node(os.fstat(self.rootfd)) == self.rootnode == node(os.fstat(current)) and mount_id(self.rootfd) == self.mount == mount_id(current), 'same canonical no-symlink admitted job root inode/owner/mode/mount')
        finally: os.close(current)
        need(stat.S_ISDIR(os.fstat(self.fd).st_mode) and node(os.fstat(self.fd)) == self.worknode and node(os.stat(self.path.name,dir_fd=self.rootfd,follow_symlinks=False)) == self.worknode and mount_id(self.fd) == self.mount, 'same held workspace inode/owner/mode/mount')

    def retire(self, tick):
        self.check(); count = [0]
        def walk(fd, depth, remove):
            tick(); need(depth <= MAX_DEPTH and mount_id(fd) == self.mount, 'bounded same-mount retirement')
            with os.scandir(fd) as rows:
                for entry in rows:
                    tick(); count[0] += 1; need(count[0] <= MAX_NODES, 'bounded workspace retirement node count')
                    before = os.stat(entry.name,dir_fd=fd,follow_symlinks=False)
                    need(node(before)['uid'] == node(before)['gid'] == 1001 and before.st_dev == self.worknode['device'], 'foreign ownership/device retirement refusal')
                    if stat.S_ISDIR(before.st_mode):
                        child = os.open(entry.name,FLAGS,dir_fd=fd)
                        try:
                            need(node(before) == node(os.fstat(child)) and mount_id(child) == self.mount, 'same ordinary child; no mounted subtree')
                            walk(child,depth+1,remove)
                            need(node(before) == node(os.stat(entry.name,dir_fd=fd,follow_symlinks=False)), 'same child before exact rmdir')
                            if remove: os.rmdir(entry.name,dir_fd=fd)
                        finally: os.close(child)
                    else:
                        need(stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode), 'ordinary files or owned leaf symlinks only; no target traversal')
                        leaf = os.open(entry.name,os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,dir_fd=fd)
                        try:
                            need(node(before) == node(os.fstat(leaf)) == node(os.stat(entry.name,dir_fd=fd,follow_symlinks=False)) and mount_id(leaf) == self.mount, 'same ordinary leaf before unlink; no mounted file')
                            if remove: os.unlink(entry.name,dir_fd=fd)
                        finally: os.close(leaf)
        # Refuse unsafe trees before removing anything; recheck every deletion.
        walk(self.fd,0,False); count[0] = 0; walk(self.fd,0,True); self.check()
        need(not os.listdir(self.fd), 'exact owned workspace empty after bounded retirement')
        os.rmdir(self.path.name,dir_fd=self.rootfd)
        try: os.stat(self.path.name,dir_fd=self.rootfd,follow_symlinks=False)
        except FileNotFoundError: pass
        else: raise ValueError('workspace absence not established')
        return dict(status='RETIRED_ABSENT',workspace_node=self.worknode,nonce=self.proof['nonce'],nodes=count[0],fd_held_until_absence=True)

    def close(self):
        for key in ('fd','rootfd'):
            fd = getattr(self,key,None)
            if fd is not None: os.close(fd); setattr(self,key,None)
