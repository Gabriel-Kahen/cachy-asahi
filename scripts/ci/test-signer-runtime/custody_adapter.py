# SPDX-License-Identifier: MIT
"""Deferred no-key node/journal custody. Root issues all authority externally."""
from pathlib import Path
import hashlib
import json
import math
import re
import stat


class Refused(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def normalized(value):
    return type(value) is str and value.startswith('/') and str(Path(value)) == value and '..' not in Path(value).parts


_CODES = frozenset(('FD-identity-unproved', 'IO-control-owner', 'IO-listener-owner', 'Root-admission', 'Root-classes', 'Source-policy', 'actual-runtime-owner', 'alias-drift', 'alias-row', 'base-custody', 'base-identity', 'base-selection', 'borrowed-file-drift', 'borrowed-file-owner', 'closure-byte-bound', 'created-directory', 'custody-original-deadline', 'directory-drift', 'disposal-endpoint', 'file-EOF', 'file-closure', 'file-content-drift', 'file-pin', 'file-read', 'file-row', 'foreign-FD', 'foreign-disposal-FD', 'foreign-journal-FD', 'foreign-keyhome', 'foreign-listener-FD', 'foreign-root', 'foreign-runtime', 'foreign-socket', 'frame', 'helper-absence-unproved', 'job-name', 'journal-binding', 'journal-bound', 'journal-custody', 'journal-readback', 'journal-result', 'journal-write', 'listener-identity', 'nonce', 'one-allocation', 'one-shot-quarantine', 'original-birth-unproved', 'original-endpoint', 'original-task-live', 'original8/13', 'partial-directory', 'policy-row-binding', 'remaining-owner', 'runtime-owner', 'runtime-owner-binding', 'selection-shape', 'signer-disposal-count', 'signer-disposal-depth', 'signer-disposal-directory-drift', 'signer-disposal-file-drift', 'signer-disposal-mode', 'signer-disposal-name', 'signer-disposal-owner', 'signer-disposal-type', 'signer-keyhome-absence', 'socket-absence-unproved', 'socket-drift', 'socket-mode', 'socket-owner', 'socket-path-bound', 'state-incomplete', 'task-owner', 'unbound-launch-intent'))


_QUARANTINED_SOCKETS = []  # Strong references on failed detach; never blind GC close.


class CustodyAdapter:
    """Constructor is pure. All OS/socket effects are explicit method dispatches.

    base/file handles are borrowed. No JSON or matching bool mints admission.
    Root must authenticate this class, APIs, classes and issuing entry graph.
    """
    def __init__(self, *, os_api, socket_api, clock, cancelled, selection,
                 work_end, cleanup_end, admission=None, expected_admission=None,
                 held_fd_type=None, cancel_type=None):
        need(not _QUARANTINED_SOCKETS, 'one-shot-quarantine')
        need(type(admission) is object and admission is expected_admission, 'Root-admission')
        fields = {'base_path','base_fd','base_identity','job_name','uid','gid','nonce','generation',
                  'source_commit','policy_sha256','entry','outer_work_end','outer_cleanup_end','files','aliases'}
        need(type(selection) is dict and set(selection) == fields, 'selection-shape')
        s = dict(selection)
        need(normalized(s['base_path']) and type(s['base_fd']) is int and s['base_fd'] >= 0, 'base-selection')
        need(type(s['job_name']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', s['job_name']), 'job-name')
        need(all(type(s[k]) is int and s[k] > 0 for k in ('uid','gid','generation')), 'runtime-owner')
        need(type(s['nonce']) is str and re.fullmatch(r'[0-9a-f]{32}', s['nonce']), 'nonce')
        need(type(s['source_commit']) is str and re.fullmatch(r'[0-9a-f]{40}', s['source_commit']) and
             type(s['policy_sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', s['policy_sha256']), 'Source-policy')
        for name in ('entry','outer_work_end','outer_cleanup_end'):
            need(type(s[name]) in (int,float) and math.isfinite(s[name]) and s[name] > 0, 'frame')
        need(work_end == min(s['entry']+8,s['outer_work_end']) and
             cleanup_end == min(s['entry']+13,s['outer_cleanup_end']) and s['entry'] < work_end < cleanup_end, 'original8/13')
        need(type(held_fd_type) is type and type(cancel_type) is type and callable(clock) and callable(cancelled), 'Root-classes')
        need(type(s['base_identity']) in (tuple,list) and len(s['base_identity']) == 9 and all(type(x) is int and x >= 0 for x in s['base_identity']), 'base-identity')
        need(type(s['files']) is dict and {'compiled-shim','agent-executable','policy-source'} <= set(s['files']) and
             3 <= len(s['files']) <= 64 and type(s['aliases']) is list and len(s['aliases']) <= 128, 'file-closure')
        files = {}
        for role, row in s['files'].items():
            need(type(role) is str and re.fullmatch(r'[A-Za-z0-9_.:/-]{1,160}',role) and type(row) is dict and
                 set(row) == {'handle','path','identity','bytes','sha256'}, 'file-row')
            need(normalized(row['path']) and type(row['identity']) in (tuple,list) and len(row['identity']) == 9 and all(type(x) is int and x >= 0 for x in row['identity']) and
                 type(row['bytes']) is int and 0 < row['bytes'] <= 64*1024**2 and
                 type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}',row['sha256']), 'file-pin')
            files[role] = {**row, 'identity': tuple(row['identity'])}
        need(sum(row['bytes'] for row in files.values()) <= 512*1024**2, 'closure-byte-bound')
        need(files['policy-source']['sha256'] == s['policy_sha256'], 'policy-row-binding')
        aliases = []
        for row in s['aliases']:
            need(type(row) is dict and set(row) == {'path','target','identity'} and normalized(row['path']) and
                 type(row['target']) is str and 0 < len(row['target']) <= 1024 and
                 type(row['identity']) in (tuple,list) and len(row['identity']) == 9 and all(type(x) is int and x >= 0 for x in row['identity']), 'alias-row')
            aliases.append({**row, 'identity': tuple(row['identity'])})
        self.os,self.socket,self.clock,self.cancelled = os_api,socket_api,clock,cancelled
        s['base_identity']=tuple(s['base_identity'])
        self.s,self.files,self.aliases = s,files,aliases
        self.work_end,self.cleanup_end = work_end,cleanup_end
        self.admission,self.held_type,self.cancel_type = admission,held_fd_type,cancel_type
        self.io = None
        self.io_type = None
        self._state = None
        self.runtime_absent = False
        self.owned_close_uncertain = False
        self.handles,self.nodes,self.journals = {},{},{}
        self.listener = None
        self.socket_identity = None
        self.listener_identity = None
        self.listener_close_attempted = False
        self.launch_attempted = self.task_absent = self.keyhome_absent = self.socket_absent = False
        self.first_cause = None
        self.sticky_cancelled = self.uncertain = self.closed = False
        self.sequence = 0
        self.root = Path(s['base_path']) / s['job_name']

    def _remember(self, error):
        if self.first_cause is None:
            self.first_cause = error.args[0] if type(error) is Refused and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in _CODES else 'IO_FAILED' if type(error) in (OSError,FileNotFoundError,PermissionError,InterruptedError) else 'CANCELLED' if isinstance(error,KeyboardInterrupt) or type(error) is self.cancel_type else 'OTHER'
        if isinstance(error, KeyboardInterrupt) or type(error) is self.cancel_type:
            self.sticky_cancelled = True
        self.uncertain = True

    def _live(self, end, *, cleanup=False):
        need(end in (self.work_end,self.cleanup_end) and type(end) in (int,float), 'original-endpoint')
        need(self.clock() < end, 'custody-original-deadline')
        if self.cancelled():
            self.sticky_cancelled = True
            if self.first_cause is None:self.first_cause='CANCELLED'
            if not cleanup:
                raise self.cancel_type()

    def _base(self):
        held = identity(self.os.fstat(self.s['base_fd']))
        named = identity(self.os.stat(self.s['base_path'],follow_symlinks=False))
        need(held == named and held[:5] == tuple(self.s['base_identity'])[:5] and
             stat.S_ISDIR(held[2]) and held[3:5] == (self.s['uid'],self.s['gid']) and
             stat.S_IMODE(held[2]) == 0o700, 'base-custody')

    def _directory(self, name):
        row = self.nodes[name]
        need(row['identity'] is not None and row['fd'] is not None, 'partial-directory')
        held = identity(self.os.fstat(row['fd']))
        named = identity(self.os.stat(row['name'],dir_fd=row['parent_fd'],follow_symlinks=False))
        need(held == named and held[:5] == row['identity'][:5] and stat.S_ISDIR(held[2]) and
             held[3:5] == (self.s['uid'],self.s['gid']) and stat.S_IMODE(held[2]) == 0o700, 'directory-drift')
        return held

    def _create(self, role, parent_fd, name, path, end):
        self._live(end)
        row = {'name':name,'path':path,'parent_fd':parent_fd,'fd':None,'identity':None,'created':False,'removed':False}
        self.nodes[role] = row
        self.os.mkdir(name,mode=0o700,dir_fd=parent_fd)
        row['created'] = True
        self._live(end)
        named = identity(self.os.stat(name,dir_fd=parent_fd,follow_symlinks=False))
        need(stat.S_ISDIR(named[2]) and named[3:5] == (self.s['uid'],self.s['gid']) and
             stat.S_IMODE(named[2]) == 0o700, 'created-directory')
        row['identity'] = named
        fd = self.os.open(name,self.os.O_RDONLY|self.os.O_DIRECTORY|self.os.O_NOFOLLOW|self.os.O_CLOEXEC,dir_fd=parent_fd)
        row['fd'] = fd
        self.handles[fd] = {'identity':named,'node':role,'attempted':False}
        self._live(end)
        self._directory(role)

    def allocate(self, end):
        try:
            need(not self.nodes and not self.closed, 'one-allocation')
            self._live(end)
            need((self.os.getuid(),self.os.getgid()) == (self.s['uid'],self.s['gid']), 'actual-runtime-owner')
            self._base()
            self._create('root',self.s['base_fd'],self.s['job_name'],self.root,end)
            for role in ('keyhome','public','runtime'):
                self._directory('root')
                self._create(role,self.nodes['root']['fd'],role,self.root/role,end)
            self._live(end)
            self.listener = self.socket.socket(self.socket.AF_UNIX,self.socket.SOCK_STREAM)
            self.listener_identity = identity(self.os.fstat(self.listener.fileno()))
            need(stat.S_ISSOCK(self.listener_identity[2]), 'listener-identity')
            path = self.root/'keyhome/S.gpg-agent'
            need(len(str(path).encode()) <= 100, 'socket-path-bound')
            self.listener.bind(str(path))
            # Bind is now an owned effect even if its following observation fails.
            self.socket_absent = False
            info = identity(self.os.stat(path,follow_symlinks=False))
            need(stat.S_ISSOCK(info[2]) and info[3:5] == (self.s['uid'],self.s['gid']), 'socket-owner')
            self.socket_identity = info
            self.os.chmod(path,0o600,follow_symlinks=False)
            info2 = identity(self.os.stat(path,follow_symlinks=False))
            need(info2[:2] == info[:2] and stat.S_ISSOCK(info2[2]) and info2[3:5] == info[3:5] and
                 stat.S_IMODE(info2[2]) == 0o600, 'socket-mode')
            self.socket_identity = info2
            self.listener.listen(16)
            self._live(end)
            return self.state()
        except BaseException as error:
            self._remember(error)
            raise

    def state(self):
        need(all(role in self.nodes for role in ('root','keyhome','public','runtime')) and
             self.socket_identity is not None, 'state-incomplete')
        if self._state is not None:return self._state
        self._state = {'root':str(self.root),'home':str(self.root/'keyhome'),'public':str(self.root/'public'),'runtime':str(self.root/'runtime'),
                'agent_listener':self.listener,'root_inode':self.nodes['root']['identity'][:2],
                'home_inode':self.nodes['keyhome']['identity'][:2],'socket_inode':self.socket_identity[:2]}
        return self._state

    def bind_runtime(self, io, selected_io_type, selected_held_type):
        need(self.io is None and type(io) is selected_io_type and selected_held_type is self.held_type and
             io.owner is self.admission and io.generation == self.s['generation'], 'runtime-owner-binding')
        self.io = io
        self.io_type = selected_io_type

    def _file(self, role, end):
        row = self.files[role];h = row['handle']
        self._live(end,cleanup=end==self.cleanup_end)
        need(type(h) is self.held_type and h.owner is self.admission and h.generation == self.s['generation'] and
             not h.closed and type(h.fd) is int and h.fd >= 0, 'borrowed-file-owner')
        before = identity(self.os.fstat(h.fd));named_before = identity(self.os.stat(row['path'],follow_symlinks=False))
        need(before == named_before == row['identity'] and stat.S_ISREG(before[2]) and before[5] == 1 and
             before[6] == row['bytes'], 'borrowed-file-drift')
        body = bytearray()
        while len(body) < row['bytes']:
            self._live(end,cleanup=end==self.cleanup_end)
            chunk = self.os.pread(h.fd,min(65536,row['bytes']-len(body)),len(body))
            need(type(chunk) is bytes and 0 < len(chunk) <= min(65536,row['bytes']-len(body)), 'file-read')
            body.extend(chunk)
        need(self.os.pread(h.fd,1,len(body)) == b'', 'file-EOF')
        after = identity(self.os.fstat(h.fd));named_after = identity(self.os.stat(row['path'],follow_symlinks=False))
        need(before == after == named_after and hashlib.sha256(body).hexdigest() == row['sha256'], 'file-content-drift')
        self._live(end,cleanup=end==self.cleanup_end)
        return before,named_before,bytes(body),after,named_after

    def file_observation(self, role, end, custody_module):
        try:
            before,named_before,body,after,named_after = self._file(role,end)
            return custody_module.HeldFile(self.files[role]['handle'].token,custody_module.Snapshot(*before),
                custody_module.Snapshot(*after),custody_module.Snapshot(*named_before),custody_module.Snapshot(*named_after),body)
        except BaseException as error:
            self._remember(error)
            raise

    def custody_guard(self, end):
        try:
            self._live(end,cleanup=end==self.cleanup_end);self._base()
            for role in ('root','keyhome','public','runtime'):
                self._directory(role)
            info = identity(self.os.stat(self.root/'keyhome/S.gpg-agent',follow_symlinks=False))
            need(self.socket_identity is not None and info == self.socket_identity and stat.S_ISSOCK(info[2]), 'socket-drift')
            for role in self.files:
                self._file(role,end)
            for row in self.aliases:
                need(identity(self.os.stat(row['path'],follow_symlinks=False)) == row['identity'] and
                     self.os.readlink(row['path']) == row['target'] and
                     identity(self.os.stat(row['path'],follow_symlinks=False)) == row['identity'], 'alias-drift')
            self._live(end,cleanup=end==self.cleanup_end)
            return True,True
        except BaseException as error:
            self._remember(error)
            raise

    def journal(self, binding, phase, result, cleanup_end):
        try:
            need(binding is self._state and self._state is not None and phase in ('reserved','create-attempted','failed','disposed') and
                 type(result) is dict and cleanup_end == self.cleanup_end and self.sequence < 16, 'journal-binding')
            self._live(cleanup_end,cleanup=True);self._directory('root')
            if phase == 'create-attempted':self.launch_attempted = True
            # Closed metadata projection: never private argv, fd numbers, raw errors or key bytes.
            projected = {name:result.get(name) for name in ('status','first_cause','cancelled','image_witness','task_absent','keyhome_absent','socket_absent')}
            need(type(projected['status']) is str and re.fullmatch(r'[A-Z0-9_ -]{1,80}',projected['status']) and
                 (projected['first_cause'] is None or type(projected['first_cause']) is str and
                  re.fullmatch(r'[A-Za-z0-9_.:-]{1,96}',projected['first_cause'])) and
                 all(type(projected[k]) is bool for k in ('cancelled','image_witness','task_absent','keyhome_absent','socket_absent')), 'journal-result')
            if projected['first_cause'] is not None and self.first_cause is None:self.first_cause=projected['first_cause']
            self.sticky_cancelled |= projected['cancelled']
            raw = (json.dumps({'schema_version':1,'purpose':'NO_KEY_RUNTIME_CUSTODY','Source':self.s['source_commit'],
                'policy_sha256':self.s['policy_sha256'],'nonce':self.s['nonce'],'generation':self.s['generation'],
                'phase':phase,'result':projected,'sticky_cancelled':self.sticky_cancelled,'uncertain':self.uncertain},
                sort_keys=True,separators=(',',':'))+'\n').encode()
            need(len(raw)<=65536,'journal-bound')
            name='owner-journal.%02d.json'%self.sequence;self.sequence+=1
            fd=self.os.open(name,self.os.O_RDWR|self.os.O_CREAT|self.os.O_EXCL|self.os.O_NOFOLLOW|self.os.O_CLOEXEC,0o600,dir_fd=self.nodes['root']['fd'])
            self.handles[fd]={'identity':None,'node':None,'attempted':False,'journal':name}
            self._live(cleanup_end,cleanup=True)
            before=identity(self.os.fstat(fd));named=identity(self.os.stat(name,dir_fd=self.nodes['root']['fd'],follow_symlinks=False))
            need(before==named and stat.S_ISREG(before[2]) and before[3:6]==(self.s['uid'],self.s['gid'],1) and
                 stat.S_IMODE(before[2])==0o600,'journal-custody')
            self.handles[fd]['identity']=before
            offset=0
            while offset<len(raw):
                self._live(cleanup_end,cleanup=True)
                count=self.os.write(fd,raw[offset:offset+65536]);need(type(count) is int and 0<count<=len(raw)-offset,'journal-write');offset+=count
            after=identity(self.os.fstat(fd));named=identity(self.os.stat(name,dir_fd=self.nodes['root']['fd'],follow_symlinks=False))
            need(after==named and after[:6]==before[:6] and after[6]==len(raw) and self.os.pread(fd,len(raw)+1,0)==raw,'journal-readback')
            self.handles[fd]['identity']=after;self.journals[name]=after
            self._close(fd)
            self._live(cleanup_end,cleanup=True)
        except BaseException as error:
            self._remember(error)
            raise

    def _task_clear(self, end):
        if self.io is None:
            need(not self.launch_attempted,'unbound-launch-intent')
            return True
        need(type(self.io) is self.io_type and self.io.owner is self.admission and self.io.generation==self.s['generation'], 'task-owner')
        need(type(self.io.helper_attempted) is bool and type(self.io.helper_task_absent) is bool and
             type(self.io.agent_attempted) is bool and
             (not self.io.helper_attempted or self.io.helper_task_absent is True), 'helper-absence-unproved')
        if self.task_absent:return True
        if not self.io.agent_attempted:return True
        h=self.io.original_pidfd
        need(type(h) is self.held_type and h.owner is self.admission and h.generation==self.s['generation'] and
             h.kind=='pidfd' and not h.closed, 'original-birth-unproved')
        self._live(end,cleanup=True)
        need(self.io.live_pidfd(h) is False,'original-task-live')
        self._live(end,cleanup=True);self.task_absent=True
        return True

    def _close(self, fd):
        try:return self._close_owned(fd)
        except BaseException as error:
            self.owned_close_uncertain=True;self._remember(error);raise

    def _close_owned(self, fd):
        row=self.handles[fd]
        if row['attempted']:return
        row['attempted']=True
        expected=row['identity'];need(expected is not None,'FD-identity-unproved')
        current=identity(self.os.fstat(fd))
        need(current[:5]==expected[:5] if stat.S_ISDIR(expected[2]) else current[:6]==expected[:6],'foreign-FD')
        if row['node'] is not None:self._directory(row['node'])
        else:
            self._directory('root')
            need(identity(self.os.stat(row['journal'],dir_fd=self.nodes['root']['fd'],follow_symlinks=False))==current,'foreign-journal-FD')
        self.os.close(fd)

    def _walk(self, role, end):
        """Reviewed signing.remove_home bounds, with named/held guards and one close."""
        row=self.nodes[role];fd=row['fd'];count=[0]
        def walk(fd, path, anchor, depth):
            self._live(end,cleanup=True);need(depth<=8,'signer-disposal-depth')
            need(identity(self.os.fstat(fd))[:5]==anchor[:5] and
                 identity(self.os.stat(path,follow_symlinks=False))[:5]==anchor[:5],'signer-disposal-directory-drift')
            for name in self.os.listdir(fd):
                self._live(end,cleanup=True);count[0]+=1;need(count[0]<=512,'signer-disposal-count')
                need(type(name) is str and name not in ('.','..') and '/' not in name,'signer-disposal-name')
                info=identity(self.os.stat(name,dir_fd=fd,follow_symlinks=False))
                need(info[3:5]==(self.s['uid'],self.s['gid']) and info[0]==anchor[0],'signer-disposal-owner')
                if stat.S_ISDIR(info[2]):
                    need(stat.S_IMODE(info[2])==0o700,'signer-disposal-mode')
                    child=self.os.open(name,self.os.O_RDONLY|self.os.O_DIRECTORY|self.os.O_NOFOLLOW|self.os.O_CLOEXEC,dir_fd=fd)
                    self.handles[child]={'identity':info,'node':None,'attempted':False,'nested':(fd,name)}
                    primary=None
                    try:
                        need(identity(self.os.fstat(child))==info,'signer-disposal-directory-drift')
                        walk(child,path/name,info,depth+1)
                    except BaseException as error:
                        primary=error;self._remember(error);raise
                    finally:
                        close=self.handles[child]
                        if not close['attempted']:
                            close['attempted']=True
                            try:
                                need(identity(self.os.fstat(child))[:5]==info[:5] and
                                     identity(self.os.stat(name,dir_fd=fd,follow_symlinks=False))[:5]==info[:5],'foreign-disposal-FD')
                                self.os.close(child)
                            except BaseException as error:
                                self.owned_close_uncertain=True;self._remember(error)
                                if primary is None:raise
                    need(identity(self.os.stat(name,dir_fd=fd,follow_symlinks=False))[:5]==info[:5],'signer-disposal-directory-drift')
                    self.os.rmdir(name,dir_fd=fd)
                else:
                    need(stat.S_ISREG(info[2]) and info[5]==1 and info[6]<=8*1024**2 and
                         stat.S_IMODE(info[2]) in (0o600,0o644),'signer-disposal-type')
                    need(identity(self.os.stat(name,dir_fd=fd,follow_symlinks=False))==info,'signer-disposal-file-drift')
                    self.os.unlink(name,dir_fd=fd)
                self._live(end,cleanup=True)
        self._directory(role);walk(fd,row['path'],row['identity'],0)
        self._directory(role);self._close(fd)
        self.os.rmdir(row['name'],dir_fd=row['parent_fd']);row['removed']=True
        self._live(end,cleanup=True)
        try:self.os.stat(row['name'],dir_fd=row['parent_fd'],follow_symlinks=False)
        except FileNotFoundError:return
        raise Refused('signer-keyhome-absence')

    def dispose_verified(self, end):
        try:
            need(end==self.cleanup_end,'disposal-endpoint');self._task_clear(end)
            self._base()
            root=self.nodes.get('root')
            if root is None or not root['created']:
                # No owned root creation: independently verify no child effect.
                try:self.os.stat(self.s['job_name'],dir_fd=self.s['base_fd'],follow_symlinks=False)
                except FileNotFoundError:
                    self.keyhome_absent=self.socket_absent=self.runtime_absent=True
                    return {'keyhome_absent':True,'socket_absent':True}
                raise Refused('foreign-root')
            self._directory('root')
            home=self.nodes.get('keyhome')
            if home is not None and home['created']:
                self._directory('keyhome')
                path=self.root/'keyhome/S.gpg-agent'
                self._close_listener(end)
                try:current=identity(self.os.stat(path,follow_symlinks=False))
                except FileNotFoundError:pass
                else:
                    need(self.socket_identity is not None and current==self.socket_identity,'foreign-socket')
                    self.os.unlink('S.gpg-agent',dir_fd=home['fd'])
                try:self.os.stat(path,follow_symlinks=False)
                except FileNotFoundError:self.socket_absent=True
                else:raise Refused('socket-absence-unproved')
                self._walk('keyhome',end);self.keyhome_absent=True
            else:
                try:self.os.stat('keyhome',dir_fd=root['fd'],follow_symlinks=False)
                except FileNotFoundError:self.keyhome_absent=self.socket_absent=True
                else:raise Refused('foreign-keyhome')
            runtime=self.nodes.get('runtime')
            if runtime is not None and runtime['created']:
                self._walk('runtime',end);self.runtime_absent=True
            else:
                try:self.os.stat('runtime',dir_fd=root['fd'],follow_symlinks=False)
                except FileNotFoundError:self.runtime_absent=True
                else:raise Refused('foreign-runtime')
            self._live(end,cleanup=True)
            return {'keyhome_absent':True,'socket_absent':True}
        except BaseException as error:
            self._remember(error)
            raise

    def _detach(self, sock):
        try:sock.detach()
        except BaseException as error:
            _QUARANTINED_SOCKETS.append(sock)
            self.owned_close_uncertain=True;self._remember(error)

    def _close_listener(self, end):
        try:return self._close_owned_listener(end)
        except BaseException as error:
            self.owned_close_uncertain=True;self._remember(error)
            if self.listener is not None:
                self._detach(self.listener)
                self.listener=None
            raise

    def _close_owned_listener(self, end):
        if self.listener is None or self.listener_close_attempted:return
        listener=self.listener
        self.listener_close_attempted=True
        try:
            self._live(end,cleanup=True)
            need(self.listener_identity is not None and
                 identity(self.os.fstat(listener.fileno()))[:6]==self.listener_identity[:6],'foreign-listener-FD')
            if self.socket_identity is not None:
                self._directory('keyhome')
                need(identity(self.os.stat(self.root/'keyhome/S.gpg-agent',follow_symlinks=False))==self.socket_identity,'socket-drift')
        except BaseException as primary:
            self._remember(primary)
            self._detach(listener)
            self.listener=None
            raise primary
        self.listener=None
        listener.close()
        self._live(end,cleanup=True)

    def _close_io_effects(self, end):
        if self.io is None:return
        primary=None
        listener=self.io.listener
        if listener is not None and not listener.closed:
            try:
                need(type(listener) is self.held_type and listener.owner is self.admission and
                     listener.generation==self.s['generation'],'IO-listener-owner')
                self.io.close(listener)
                self._live(end,cleanup=True)
            except BaseException as error:
                primary=error;self.owned_close_uncertain=True;self._remember(error)
        control=self.io.control
        if control is not None and not self.io.control_retired:
            self.io.control_retired=True
            try:
                expected=getattr(self.io,'control_identity',None)
                try:
                    need(expected is not None and identity(self.os.fstat(control.fileno()))[:6]==tuple(expected)[:6],'IO-control-owner')
                except BaseException as original:
                    self._remember(original);self._detach(control);self.io.control=None
                    raise original
                control.close();self._live(end,cleanup=True)
            except BaseException as error:
                if primary is None:primary=error
                self.owned_close_uncertain=True;self._remember(error)
        if primary is not None:raise primary

    def cleanup_remaining(self, io, result, end):
        try:
            need(io is self.io and end==self.cleanup_end,'remaining-owner')
            self._live(end,cleanup=True)
            if io is not None and io.close_uncertain:
                self.owned_close_uncertain=True
            if not self.keyhome_absent or not self.runtime_absent:self.dispose_verified(end)
        except BaseException as error:self._remember(error)
        try:self._close_io_effects(end)
        except BaseException as error:
            self.owned_close_uncertain=True;self._remember(error)
        try:self._close_listener(end)
        except BaseException as error:self._remember(error)
        for fd,row in list(self.handles.items()):
            if row['attempted'] or row['node'] in ('root','public'):continue
            try:self._close(fd);self._live(end,cleanup=True)
            except BaseException as error:self._remember(error)
        return not self.uncertain and not self.sticky_cancelled and not self.owned_close_uncertain

    def close(self):
        if self.closed:return self.summary()
        self.closed=True
        try:self._close_io_effects(self.cleanup_end)
        except BaseException as error:self.owned_close_uncertain=True;self._remember(error)
        try:self._close_listener(self.cleanup_end)
        except BaseException as error:self.owned_close_uncertain=True;self._remember(error)
        for fd,row in reversed(list(self.handles.items())):
            if row['attempted']:continue
            try:
                self._live(self.cleanup_end,cleanup=True);self._close(fd);self._live(self.cleanup_end,cleanup=True)
            except BaseException as error:self.owned_close_uncertain=True;self._remember(error)
        # Cancellation is sampled once even if an earlier endpoint refused close.
        try:
            if self.cancelled():
                self.sticky_cancelled=True
                if self.first_cause is None:self.first_cause='CANCELLED'
        except BaseException as error:self._remember(error)
        return self.summary()

    def summary(self):
        return {'runtime_absent':self.runtime_absent,'keyhome_absent':self.keyhome_absent,
                'socket_absent':self.socket_absent,'uncertain':self.uncertain,
                'owned_close_uncertain':self.owned_close_uncertain or bool(self.io is not None and self.io.close_uncertain),
                'cancelled':self.sticky_cancelled,'first_cause':self.first_cause}
