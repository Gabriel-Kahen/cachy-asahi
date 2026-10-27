#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read actual ALPM9 ownership and every owned payload node, never declared counts alone."""
import hashlib
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time
SELECTED={'cachy-asahi-doctor','cachy-asahi-orphans'}
CAP=64*1024**2

def need(ok,why):
    if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def read(path):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size<=CAP,'bounded ordinary snapshot required');return json.loads(path.read_bytes())
def load_db(path):
    spec=importlib.util.spec_from_file_location('managed607_actual_alpm',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def capabilities():
    sibling=Path(__file__).with_name('file_capabilities.py')
    path=sibling if sibling.is_file() else Path(__file__).resolve().parents[2]/'apps/file_capabilities.py'
    spec=importlib.util.spec_from_file_location('current607_owned_capabilities',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def observe(root,helper,expected,*,deadline=600):
    end=time.monotonic()+deadline;rows=helper.database(root,max_packages=607)
    need({r['name']:r['version'] for r in rows}==expected and len(rows)==607,'exact actual607 ALPM inventory required')
    def records():
        result={}
        for row in rows:
            base='var/lib/pacman/local/'+row['name']+'-'+row['version']
            with helper.directory(root,base) as parent:
                for name in sorted(os.listdir(parent)):
                    need(name in ('desc','files','mtree','install'),'unknown ALPM record')
                    result[base+'/'+name]=digest(helper.read_record(parent,name,4*1024**2))
        return result
    initial_database=records()
    @contextmanager
    def directory(name):
        if name:
            with helper.directory(root,name) as fd:yield fd
        else:
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:yield fd
            finally:os.close(fd)
    caps=capabilities()
    class Limits:
        def tick(self):need(time.monotonic()<end,'complete payload/capability deadline')
    limits=Limits()
    with directory('') as fd:mount=caps._mount(fd,limits)
    capability_map={}
    root_identity=helper.identity(root.lstat())
    nodes={};owners={};groups={};total=0
    for row in rows:
        need(row['name'] not in owners,'duplicate actual owner');owners[row['name']]=row['files']
        for name in row['files']:
            need(name not in nodes and time.monotonic()<end,'overlap/deadline in complete actual payload')
            parent,_,leaf=name.rpartition('/')
            with directory(parent) as parentfd:
                before=os.stat(leaf,dir_fd=parentfd,follow_symlinks=False)
                value=dict(mode=stat.S_IMODE(before.st_mode),uid=before.st_uid,gid=before.st_gid)
                if stat.S_ISLNK(before.st_mode):
                    value.update(type='symlink',target=os.readlink(leaf,dir_fd=parentfd))
                    fd=os.open(leaf,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)
                    try:
                        need(helper.identity(before)==helper.identity(os.fstat(fd)) and caps._mount(fd,limits)==mount,'symlink capability descriptor/mount differs')
                        need(caps._attrs(fd,'symlink',limits,parentfd,leaf) is None,'capability on symlink refused')
                    finally:os.close(fd)
                else:
                    need(stat.S_ISREG(before.st_mode) and before.st_size<=1024**3,'ordinary bounded owned payload required')
                    fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)
                    try:
                        need(helper.identity(before)==helper.identity(os.fstat(fd)) and caps._mount(fd,limits)==mount,'payload descriptor identity/mount differs')
                        capability=caps._attrs(fd,'file',limits)
                        if capability is not None:capability_map[name]=capability
                        need(len(capability_map)<=caps.MAX_CAPS,'owned capability map bound')
                        h=hashlib.sha256();size=0
                        while raw:=os.read(fd,1024**2):
                            size+=len(raw);need(time.monotonic()<end and size<=before.st_size,'payload deadline/length');h.update(raw)
                        need(size==before.st_size and helper.identity(before)==helper.identity(os.fstat(fd)) and caps._attrs(fd,'file',limits)==capability,'payload/capability drift')
                    finally:os.close(fd)
                    total+=size;need(total<=6*1024**3,'original full payload byte bound')
                    value.update(type='file',bytes=size,sha256=h.hexdigest())
                    if before.st_nlink>1:groups.setdefault((before.st_dev,before.st_ino),[]).append((name,before.st_nlink))
                need(helper.identity(before)==helper.identity(os.stat(leaf,dir_fd=parentfd,follow_symlinks=False)),'named payload drift')
                nodes[name]=value;need(len(nodes)<=200000,'original full payload node bound')
    links=[]
    for members in groups.values():
        need(len(members)==members[0][1] and len({n for _,n in members})==1,'complete actual payload hardlink set required')
        aliases=sorted(name for name,_ in members);present=set(aliases)&capability_map.keys()
        need(not present or present==set(aliases) and len({capability_map[n] for n in aliases})==1,'complete capability hardlink aliases required')
        links.append(aliases)
    need(helper.database(root,max_packages=607)==rows and records()==initial_database and root_identity==helper.identity(root.lstat()) and time.monotonic()<end,'database/root drift or deadline across complete payload read')
    selected_prefixes=tuple('var/lib/pacman/local/'+r['name']+'-'+r['version']+'/' for r in rows if r['name'] in SELECTED)
    database={n:v for n,v in initial_database.items() if not n.startswith(selected_prefixes)}
    return dict(schema_version=1,packages=expected,ownership=owners,nodes=nodes,hardlinks=sorted(links),nonselected_database=database,
                capabilities=capability_map,payload_bytes=total,qualification='ACTUAL_INSTALLED_PAYLOAD_AND_ALPM_METADATA_NOT_ARCHIVE_OR_HARDWARE_ATTESTATION')

# SPDX-License-Identifier: MIT
def preservation_failure_DATA(actual, baseline, writer=None):
    """Best-effort bounded DATA only; caller must re-raise its original failure.

    Inline this function verbatim. A supplied writer accepts bytes and returns
    their written count, like os.write. No values containing file data are
    printed. Paths are diagnostic map keys, escaped and clipped. The first
    difference is in map insertion/list order, not a complete sorted diff.
    """
    try:
        import hashlib
        import json
        import os

        prefix = b'INSTALLED607_PRESERVATION_DIFF_DATA '
        categories = ('schema_version', 'packages', 'ownership', 'nodes',
                      'hardlinks', 'nonselected_database', 'capabilities',
                      'payload_bytes', 'qualification')
        visited_limit, entry_limit, depth_limit = 4096, 6, 16
        string_limit, key_limit, path_limit, capsule_limit = 4096, 256, 160, 2048
        if type(actual) is not dict or type(baseline) is not dict:
            return False
        # Only the known observer schema is diagnosed; no arbitrary object hooks.
        if len(actual) != len(categories) or len(baseline) != len(categories):
            return False
        if any(k not in actual or k not in baseline for k in categories):
            return False
        entries, states, scans = [], {}, {}
        omitted = 0

        def path(parent, key):
            if type(key) is int:
                part = '[' + str(key) + ']'
            else:
                part = ''.join(c if ' ' <= c <= '~' else '?' for c in key[:80])
                if len(key) > 80:
                    part += '~length=' + str(len(key))
            value = parent + '/' + part
            if len(value) > path_limit:
                value = value[:60] + '...' + value[-(path_limit - 63):]
            return value

        def summary(value):
            kind = type(value)
            if kind is str:
                result = {'type': 'str', 'characters': len(value)}
                if len(value) <= string_limit:
                    result['sha256'] = hashlib.sha256(value.encode('utf-8', 'surrogatepass')).hexdigest()
                else:
                    result['hash'] = 'omitted_oversize'
                return result
            if kind in (dict, list):
                return {'type': 'dict' if kind is dict else 'list', 'length': len(value)}
            if kind is int:
                return {'type': 'int', 'value': value} if value.bit_length() <= 64 else {'type': 'int', 'bits': value.bit_length()}
            if kind is bool:
                return {'type': 'bool', 'value': value}
            if value is None:
                return {'type': 'null'}
            return {'type': 'unsupported'}

        for category in categories:
            visited, limited, difference = 0, False, None

            def record(where, left, right, reason='value'):
                nonlocal difference
                difference = {'path': where, 'reason': reason,
                              'actual': summary(left), 'baseline': summary(right)}

            def walk(left, right, where, depth):
                nonlocal visited, limited
                if difference is not None:
                    return
                if visited >= visited_limit:
                    limited = True
                    return
                visited += 1
                if depth > depth_limit:
                    limited = True
                    return
                kind = type(left)
                if kind is not type(right):
                    record(where, left, right, 'type')
                elif kind is dict:
                    # Iterator use and recursion are both bounded. No full key
                    # union, sorting, serialization, equality, or work queue.
                    for key in left:
                        if visited >= visited_limit:
                            limited = True
                            break
                        visited += 1
                        if type(key) is not str or len(key) > key_limit:
                            limited = True
                            continue
                        location = path(where, key)
                        if key not in right:
                            record(location, left[key], None, 'missing_baseline_key')
                        else:
                            walk(left[key], right[key], location, depth + 1)
                        if difference is not None:
                            return
                    for key in right:
                        if visited >= visited_limit:
                            limited = True
                            break
                        visited += 1
                        if type(key) is not str or len(key) > key_limit:
                            limited = True
                            continue
                        if key not in left:
                            record(path(where, key), None, right[key], 'missing_actual_key')
                            return
                    if len(left) != len(right):
                        record(where, left, right, 'length')
                elif kind is list:
                    if len(left) != len(right):
                        record(where, left, right, 'length')
                        return
                    for index in range(len(left)):
                        if visited >= visited_limit:
                            limited = True
                            break
                        walk(left[index], right[index], path(where, index), depth + 1)
                        if difference is not None:
                            return
                elif kind is str:
                    if len(left) != len(right):
                        record(where, left, right, 'length')
                    elif len(left) > string_limit:
                        limited = True
                    elif left != right:
                        record(where, left, right)
                elif kind in (int, bool) or left is None:
                    if kind is int and (left.bit_length() > 64 or right.bit_length() > 64):
                        limited = True
                    elif left != right:
                        record(where, left, right)
                else:
                    limited = True

            walk(actual[category], baseline[category], category, 0)
            states[category] = 'different' if difference is not None else 'scan_limited' if limited else 'equal'
            scans[category] = {'visited': visited, 'limited': limited}
            if difference is not None:
                if len(entries) < entry_limit:
                    entries.append(difference)
                else:
                    omitted += 1

        result = {'schema': 1, 'status': 'FAILURE_DIAGNOSTIC_DATA_ONLY',
                  'categories': states, 'differences': entries, 'omitted': omitted,
                  'scan': scans, 'limits': {'visited_per_category': visited_limit,
                  'entries': entry_limit, 'depth': depth_limit, 'string': string_limit,
                  'key': key_limit, 'path': path_limit, 'capsule_bytes': capsule_limit},
                  'order': 'insertion_then_list_index', 'complete': False}
        while True:
            raw = prefix + json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii') + b'\n'
            if len(raw) <= capsule_limit:
                break
            if not entries:
                return False
            entries.pop()
            result['omitted'] += 1
        return (os.write(2, raw) if writer is None else writer(raw)) == len(raw)
    except BaseException:
        # Diagnostics must never replace the already established preservation
        # failure, including failures from encoding, malformed objects, or I/O.
        return False

def verify(actual,baseline):
    try:
        need(actual==baseline,'complete installed inventory/payload/hardlink/nonselected DB preservation differs')
    except ValueError:
        try:preservation_failure_DATA(actual,baseline)
        except Exception:pass
        raise
    return True

def main():
    mode,root,helper_path,expected_path,snapshot_path=sys.argv[1:]
    need(mode in ('capture','verify') and os.geteuid()==0,'owned fixture/guarded guest root only')
    expected=dict(line.split() for line in Path(expected_path).read_text().splitlines())
    actual=observe(Path(root),load_db(Path(helper_path)),expected)
    snapshot=Path(snapshot_path)
    if mode=='capture':
        need(not snapshot.exists(),'fresh snapshot required');raw=encoded(actual);need(len(raw)<=CAP,'snapshot64MiB bound');snapshot.write_bytes(raw);snapshot.chmod(0o444)
    else:verify(actual,read(snapshot))
    print(json.dumps(dict(status='PASS_COMPLETE_ACTUAL607_'+mode.upper(),packages=607,nodes=len(actual['nodes']),
        payload_bytes=actual['payload_bytes'],capability_files=len(actual['capabilities']),capability_map_sha256=digest(encoded(actual['capabilities'])),snapshot_sha256=digest(snapshot.read_bytes()),hardware='NOT_RUN')))
if __name__=='__main__':main()
