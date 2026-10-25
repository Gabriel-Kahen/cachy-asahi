# SPDX-License-Identifier: MIT
"""Fresh native package-payload/raw-DB/known-ancestry witness, NOT whole root.

No /dev,/proc,/sys traversal or claim about unowned files outside the explicit
/etc,/home,/root trees. Runtime file mount IDs are observed and must remain
identical; this is separate from an ordinary copied-root single-mount proof.
"""
import errno
import hashlib
import os
from pathlib import Path
import stat
import time

MAX_NODES = 200000
MAX_BYTES = 6*1024**3
MAX_FILE = 1024**3
DB = 'var/lib/pacman/local'
NAME = 'cachy-asahi-boot-report'
SELECTED_DB = DB+'/'+NAME+'-0.1.0-1'
SELECTED_FILES = frozenset(('usr/bin/'+NAME,
    'usr/share/doc/'+NAME+'/README.md',
    'usr/share/licenses/'+NAME+'/LICENSE',
    'usr/share/licenses/'+NAME+'/NOTICE'))
SELECTED_DIRS = frozenset(('usr/share/doc/'+NAME, 'usr/share/licenses/'+NAME))
INSERTION_PARENTS = frozenset(('usr/bin','usr/share/doc','usr/share/licenses',DB))

def need(ok, message):
    if not ok:
        raise ValueError(message)

def key(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def valid(name):
    need(type(name) is str and name and not name.startswith('/') and Path(name).as_posix() == name and
         not {'.','..'} & set(name.split('/')) and len(Path(name).parts) <= 128, 'bounded relative known graph')
    return name

def selected(name):
    return name in SELECTED_FILES|SELECTED_DIRS or name == SELECTED_DB or name.startswith(SELECTED_DB+'/')

def capture(root, packages, *, deadline, extra_trees=('etc','home','root')):
    root = Path(root)
    need(root.is_absolute() and '..' not in root.parts and type(deadline) in (int,float), 'absolute native root/finite deadline')
    def tick():
        need(time.monotonic() < deadline, 'native package graph observation deadline')
    # Traverse fresh no-follow ancestry for every node. No observation cache.
    directory_flags = os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    def rootfd():
        fd = os.open('/', directory_flags)
        try:
            for part in root.parts[1:]:
                child = os.open(part, directory_flags, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise
    def mount(fd):
        tick()
        value = Path('/proc/self/fdinfo/'+str(fd)).read_bytes()
        need(len(value) <= 65536, 'bounded fresh descriptor mount evidence')
        rows = [line.split(b':',1)[1].strip() for line in value.splitlines() if line.startswith(b'mnt_id:')]
        need(len(rows) == 1 and rows[0].isdigit(), 'one fresh descriptor mount ID')
        return int(rows[0])
    def parentfd(name):
        fd = rootfd()
        try:
            for part in name.split('/')[:-1]:
                child = os.open(part, directory_flags, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise
    # These shared insertion parents must already exist at baseline; adding a
    # future selected package must not change which protected ancestors we see.
    names = {'usr/bin','usr/share/doc','usr/share/licenses',DB,'var/lib/pacman'}
    owners = {}
    complete_directories = {}
    def opened_directory(name):
        parent=parentfd(name)
        try:
            return os.open(name.rsplit('/',1)[-1],directory_flags,dir_fd=parent)
        finally:os.close(parent)
    for package in packages:
        tick()
        need(set(package) == {'name','version','arch','depend','provides','conflict','files'}, 'whole original database API row')
        record = DB+'/'+package['name']+'-'+package['version']
        valid(record)
        for name in package['files']:
            valid(name)
            need(name not in owners, 'package ownership overlap')
            owners[name] = package['name']
            names.add(name)
        directory=opened_directory(record)
        try:
            before=key(os.fstat(directory));leaves=sorted(os.listdir(directory))
            # Every record leaf (including optional mtree/install) is retained.
            for leaf in leaves:
                valid(leaf)
                need('/' not in leaf, 'ordinary DB member name')
                need(stat.S_ISREG(os.stat(leaf,dir_fd=directory,follow_symlinks=False).st_mode),'ordinary raw ALPM record leaf')
                names.add(record+'/'+leaf)
            need(key(os.fstat(directory))==before and sorted(os.listdir(directory))==leaves,'raw DB record graph changed while collecting names')
            complete_directories[record]=leaves
        finally:os.close(directory)
        names.add(record)
    names.add(DB+'/ALPM_DB_VERSION')
    complete_directories[DB]=sorted(['ALPM_DB_VERSION',*(r['name']+'-'+r['version'] for r in packages)])
    # These source-owned old-native scopes remain complete, including unknown
    # user/config files. No live journal, pstore, /dev or device content is read.
    for tree in extra_trees:
        valid(tree)
        try:
            initial=opened_directory(tree)
        except FileNotFoundError:
            continue
        else:os.close(initial)
        names.add(tree)
        stack = [tree]
        while stack:
            tick()
            prefix = stack.pop()
            directory=opened_directory(prefix)
            try:
                before=key(os.fstat(directory));leaves=sorted(os.listdir(directory))
                for leaf in leaves:
                    name=valid(prefix+'/'+leaf)
                    info=os.stat(leaf,dir_fd=directory,follow_symlinks=False)
                    names.add(name)
                    need(len(names)<=MAX_NODES,'bounded complete user/config graph')
                    if stat.S_ISDIR(info.st_mode):stack.append(name)
                need(key(os.fstat(directory))==before and sorted(os.listdir(directory))==leaves,'user/config complete names changed while collecting')
                complete_directories[prefix]=leaves
            finally:os.close(directory)
    for name in tuple(names):
        parent = name.rpartition('/')[0]
        while parent:
            names.add(parent)
            parent = parent.rpartition('/')[0]
    names.add('')
    need(len(names) <= MAX_NODES, 'bounded complete known package graph')
    def childproof(parent):
        tick()
        leaves = sorted(os.listdir(parent))
        need(len(leaves) <= MAX_NODES, 'bounded complete insertion-parent child proof')
        proof = {}
        for leaf in leaves:
            tick()
            before = os.stat(leaf,dir_fd=parent,follow_symlinks=False)
            mode = before.st_mode
            kind = 'directory' if stat.S_ISDIR(mode) else 'file' if stat.S_ISREG(mode) else 'symlink' if stat.S_ISLNK(mode) else None
            need(kind is not None, 'special insertion-parent child refused')
            row = dict(kind=kind,identity=key(before))
            if kind == 'symlink':
                row['link'] = os.readlink(leaf,dir_fd=parent)
                row['parent_mount_id'] = mount(parent)
            else:
                fd = os.open(leaf,(directory_flags if kind=='directory' else os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),dir_fd=parent)
                try:
                    need(key(os.fstat(fd)) == key(before), 'insertion-parent child rebound')
                    row['mount_id'] = mount(fd)
                    try:
                        row['capability'] = os.getxattr(fd,'security.capability').hex()
                    except OSError as error:
                        if error.errno != errno.ENODATA:
                            raise
                        row['capability'] = None
                    need(key(os.fstat(fd)) == key(before), 'insertion-parent child metadata changed')
                finally:
                    os.close(fd)
            need(key(os.stat(leaf,dir_fd=parent,follow_symlinks=False)) == key(before), 'insertion-parent named child rebound')
            proof[leaf] = row
        need(sorted(os.listdir(parent)) == leaves, 'insertion-parent child set changed')
        return proof
    result, spent = {}, 0
    for name in sorted(names):
        tick()
        parent = parentfd(name) if name else rootfd()
        try:
            leaf = name.rsplit('/',1)[-1] if name else '.'
            before = os.stat(leaf,dir_fd=parent,follow_symlinks=False)
            mode = before.st_mode
            kind = 'directory' if stat.S_ISDIR(mode) else 'file' if stat.S_ISREG(mode) else 'symlink' if stat.S_ISLNK(mode) else None
            need(kind is not None, 'special node in observed package/user/config graph')
            row = dict(kind=kind,identity=key(before))
            if kind == 'symlink':
                row['link'] = os.readlink(leaf,dir_fd=parent)
                row['parent_mount_id'] = mount(parent)
            else:
                fd = os.open(leaf, (directory_flags if kind == 'directory' else os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC), dir_fd=parent)
                try:
                    need(key(os.fstat(fd)) == key(before), 'opened known node rebound')
                    row['mount_id'] = mount(fd)
                    if kind == 'directory':
                        row['children'] = sorted(os.listdir(fd))
                        need(len(row['children']) <= MAX_NODES, 'bounded complete known parent names')
                        if name in complete_directories:
                            need(row['children']==complete_directories[name],'complete declared DB/user/config tree acquired no missing/extra members')
                        if name in INSERTION_PARENTS:
                            row['children_detail'] = childproof(fd)
                            need(sorted(row['children_detail']) == row['children'], 'insertion-parent child proof closure')
                    else:
                        need(before.st_size <= MAX_FILE, 'known file byte bound')
                        spent += before.st_size
                        need(spent <= MAX_BYTES, 'whole known package graph byte bound')
                        digest, size = hashlib.sha256(), 0
                        while True:
                            tick()
                            block = os.read(fd,min(1024**2,before.st_size-size+1))
                            if not block:
                                break
                            size += len(block)
                            need(size <= before.st_size, 'known file grew')
                            digest.update(block)
                        need(size == before.st_size, 'complete known file bytes')
                        row['sha256'] = digest.hexdigest()
                    try:
                        row['capability'] = os.getxattr(fd,'security.capability').hex()
                    except OSError as error:
                        if error.errno != errno.ENODATA:
                            raise
                        row['capability'] = None
                    need(key(os.fstat(fd)) == key(before), 'known descriptor changed while reading')
                finally:
                    os.close(fd)
            need(key(os.stat(leaf,dir_fd=parent,follow_symlinks=False)) == key(before), 'known named node changed')
            result[name] = row
        finally:
            os.close(parent)
    # Full independent named identity/mount/graph revalidation after ALL reads.
    for name, row in result.items():
        tick()
        parent = parentfd(name) if name else rootfd()
        try:
            leaf = name.rsplit('/',1)[-1] if name else '.'
            need(key(os.stat(leaf,dir_fd=parent,follow_symlinks=False)) == row['identity'], 'known graph final identity changed')
            if row['kind'] == 'symlink':
                need(os.readlink(leaf,dir_fd=parent) == row['link'] and mount(parent) == row['parent_mount_id'], 'known final alias/parent mount changed')
            else:
                fd = os.open(leaf,(directory_flags if row['kind']=='directory' else os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),dir_fd=parent)
                try:
                    need(key(os.fstat(fd)) == row['identity'] and mount(fd) == row['mount_id'], 'known graph final descriptor/mount rebound')
                    if row['kind'] == 'directory':
                        need(sorted(os.listdir(fd)) == row['children'], 'known parent final names changed')
                        if name in INSERTION_PARENTS:
                            need(childproof(fd) == row['children_detail'], 'complete insertion-parent final child identities/capabilities/mounts changed')
                finally:
                    os.close(fd)
        finally:
            os.close(parent)
    groups = {}
    for name, row in result.items():
        if row['kind'] != 'file':
            continue
        dev,ino,_,_,_,nlink,*_ = row['identity']
        if nlink > 1:
            groups.setdefault((dev,ino,nlink),[]).append(name)
    for (_,_,nlink), members in groups.items():
        need(len(members) == nlink, 'hardlink aliases outside observed package/user/config graph refused')
        need(not any(selected(n) for n in members) or all(selected(n) for n in members), 'selected/protected hardlink refused')
    return dict(scope='COMPLETE_PACKAGE_PAYLOAD_RAW_DB_KNOWN_ANCESTRY_PLUS_ETC_HOME_ROOT_NOT_WHOLE_ROOT',
                packages=packages,nodes=result,bytes_read=spent,
                hardlinks=[dict(nlink=k[2],members=v) for k,v in sorted(groups.items())])


def protected(before, after, *, lock_witness):
    a,b = before['nodes'],after['nodes']
    need(before['scope'] == after['scope'] == 'COMPLETE_PACKAGE_PAYLOAD_RAW_DB_KNOWN_ANCESTRY_PLUS_ETC_HOME_ROOT_NOT_WHOLE_ROOT', 'exact native known-graph scope')
    need([r for r in before['packages'] if r['name'] != NAME] == [r for r in after['packages'] if r['name'] != NAME], 'all nonselected complete database rows held')
    changed_selected = {n for n in a.keys()|b.keys() if selected(n) and a.get(n) != b.get(n)}
    parents = {n.rpartition('/')[0] for n in changed_selected}
    counter_modes = {}
    for name in a.keys()|b.keys():
        if selected(name):
            continue
        left,right = a.get(name),b.get(name)
        need(left is not None and right is not None, 'protected known node missing/extra')
        if left['kind'] != 'directory' or right['kind'] != 'directory':
            need(left == right, 'protected known payload/raw DB identity/hash/capability changed')
            continue
        if left == right:
            continue
        added = set(right['children'])-set(left['children'])
        removed = set(left['children'])-set(right['children'])
        changed = added|removed
        if name in parents:
            need(all(selected((name+'/' if name else '')+leaf) for leaf in changed), 'protected known parent child-name change')
            need(left['identity'][:5] == right['identity'][:5] and
                 {k:v for k,v in left.items() if k not in ('identity','children','children_detail')} ==
                 {k:v for k,v in right.items() if k not in ('identity','children','children_detail')}, 'selected parent stable inode/owner/mode/capability/mount')
            prefix = name+'/' if name else ''
            need(all(prefix+n in b for n in added) and all(prefix+n in a for n in removed), 'selected parent changed entry present in complete known graph')
            delta = sum(b[prefix+n]['kind']=='directory' for n in added)-sum(a[prefix+n]['kind']=='directory' for n in removed)
            need(name in INSERTION_PARENTS, 'finite Boot insertion parent only')
            left_children,right_children = left.get('children_detail'),right.get('children_detail')
            need(type(left_children) is dict and type(right_children) is dict and
                 sorted(left_children) == left['children'] and sorted(right_children) == right['children'],
                 'complete fresh insertion-parent child identities required')
            for leaf in left_children.keys()|right_children.keys():
                child = prefix+leaf
                old,new = left_children.get(leaf),right_children.get(leaf)
                if selected(child):
                    for observed,known in ((old,a.get(child)),(new,b.get(child))):
                        need((observed is None) == (known is None), 'selected child proof presence differs')
                        if observed is not None:
                            need(all(known.get(k) == v for k,v in observed.items()), 'selected child identity/type/mount/capability proof differs from full known graph')
                else:
                    need(old is not None and new is not None and old == new, 'protected immediate child full identity/type/mount/capability changed')
            oldlinks,newlinks = left['identity'][5],right['identity'][5]
            if oldlinks == newlinks == 1:
                counter_modes[name] = 'CONSTANT_ONE_WITH_COMPLETE_INDEPENDENT_CHILD_PROOF'
            else:
                need(oldlinks >= 2 and newlinks >= 2 and newlinks-oldlinks == delta,
                     'exact selected child-directory arithmetic nlink delta')
                counter_modes[name] = 'ARITHMETIC_CHILD_DIRECTORY_DELTA'

        elif name == 'var/lib/pacman':
            need(type(lock_witness) is dict and lock_witness.get('path') == name and
                 lock_witness.get('lock_created') is lock_witness.get('lock_removed') is True and
                 lock_witness.get('before') == left['identity'] and lock_witness.get('after') == right['identity'] and
                 left['identity'][:6] == right['identity'][:6] and lock_witness.get('names') == left['children'] == right['children'] and
                 {k:v for k,v in left.items() if k!='identity'} == {k:v for k,v in right.items() if k!='identity'}, 'actual transient ALPM lock lifetime exact parent witness')
        else:
            need(left == right, 'protected full known directory metadata changed')
    return dict(status='PROTECTED_KNOWN606_GRAPH_HELD',directory_counter_modes=counter_modes,whole_root=False)
