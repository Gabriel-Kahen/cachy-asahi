#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Standalone original baseline DATA observation; never mutates or qualifies ALPM."""
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time

MIB = 1024**2
FILE_CAP = 16*MIB
JSON_CAP = 32*MIB
SECONDS = 60
STATUS = 'ORIGINAL_BASELINE_OBSERVATION_DATA_ONLY_NOT_MUTATION_QUALIFICATION'
HOOK_ROOTS = ('/builder-disabled-hooks', '/etc/pacman.d/hooks', '/usr/share/libalpm/hooks')
CONFIG = '/etc/pacman.conf'
LOCK = '/builder-packages.lock'
EXPECTED349 = '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
CAPS = ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')
CGROUP = {'cpu.max':'200000 100000','memory.max':'536870912','memory.swap.max':'0','pids.max':'64'}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    raw = (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    need(len(raw) <= JSON_CAP, 'observation JSON exceeds 32 MiB')
    return raw


def binding_data(binding):
    need(type(binding) is dict and set(binding) == {'source','ref','run','job','image','token','policy_sha256'}, 'exact public observer binding required')
    for name,width in (('source',40),('token',24),('policy_sha256',64)):
        need(type(binding[name]) is str and re.fullmatch('[0-9a-f]{'+str(width)+'}',binding[name]), 'concrete observer binding: '+name)
    need(type(binding['ref']) is str and re.fullmatch(r'refs/heads/codex/[A-Za-z0-9._/-]+',binding['ref']) and '..' not in binding['ref'].split('/'), 'exact new Source ref required')
    need(type(binding['image']) is str and re.fullmatch('sha256:[0-9a-f]{64}',binding['image']), 'exact caller-selected immutable image required')
    need(all(type(binding[k]) is str and re.fullmatch('[1-9][0-9]{0,19}',binding[k]) for k in ('run','job')), 'concrete run/job binding required')


def readonly_root(raw):
    roots = []
    for line in raw.splitlines():
        left,sep,right = line.partition(' - ')
        fields = left.split()
        need(sep and len(fields) >= 6 and len(right.split()) >= 3, 'complete fixed mountinfo required')
        if fields[4] == '/':
            roots.append(set(fields[5].split(',')))
    need(len(roots) == 1 and 'ro' in roots[0] and 'rw' not in roots[0], 'one readonly observer root required')


def domain(runtime):
    need(type(runtime) is dict and set(runtime) == {'uid','euid','gid','egid','status','cgroup','cgroup_membership','mountinfo','interfaces','namespaces','pid','ppid','starttime'}, 'closed fixed kernel observation shape required')
    need(all(type(runtime[k]) is int and runtime[k] == 0 for k in ('uid','euid','gid','egid')), 'actual Root0 observer credentials required')
    status = runtime['status']
    need(type(status) is dict and set(status) == {'Uid','Gid',*CAPS,'NoNewPrivs'}, 'fixed kernel status fields only')
    need(status['Uid'].split() == ['0']*4 and status['Gid'].split() == ['0']*4, 'kernel Root0 credentials required')
    need(all(type(status[k]) is str and re.fullmatch('[0-9a-fA-F]{1,16}',status[k]) and int(status[k],16) == 0 for k in CAPS) and status['NoNewPrivs'] == '1', 'all cap0 and NNP1 required')
    need(runtime['cgroup'] == CGROUP and runtime['interfaces'] == ['lo'], 'exact 2CPU/512MiB/64PID/no-network observer domain required')
    need(type(runtime['cgroup_membership']) is str and len(runtime['cgroup_membership']) <= 4096 and len(runtime['cgroup_membership'].splitlines()) == 1 and runtime['cgroup_membership'].startswith('0::/'), 'bounded unified cgroup membership required')
    need(type(runtime['mountinfo']) is str and len(runtime['mountinfo'].encode()) <= 128*1024, 'bounded fixed mountinfo required')
    need(type(runtime['namespaces']) is dict and set(runtime['namespaces']) == {'user','mnt','net','pid','cgroup'} and all(type(value) is str and re.fullmatch(name+r':\[[1-9][0-9]{0,19}\]',value) for name,value in runtime['namespaces'].items()), 'literal actual namespace metadata required')
    need(type(runtime['pid']) is int and 0 < runtime['pid'] < 2**31 and type(runtime['ppid']) is int and 0 <= runtime['ppid'] < 2**31 and type(runtime['starttime']) is int and 0 < runtime['starttime'] < 2**64, 'concrete process identity metadata required')
    readonly_root(runtime['mountinfo'])


def bounded(path, cap):
    with Path(path).open('rb',buffering=0) as stream:
        raw = stream.read(cap+1)
    need(len(raw) <= cap, 'kernel metadata bound exceeded')
    return raw


def runtime_context():
    before = bounded('/proc/self/stat',4096).decode().rpartition(') ')[2].split()
    rows = dict(line.split(':',1) for line in bounded('/proc/self/status',16384).decode().splitlines() if ':' in line)
    runtime = dict(uid=os.getuid(),euid=os.geteuid(),gid=os.getgid(),egid=os.getegid(),
        status={k:rows[k].strip() for k in ('Uid','Gid',*CAPS,'NoNewPrivs')},
        cgroup={k:bounded(Path('/sys/fs/cgroup')/k,128).decode().strip() for k in CGROUP},
        cgroup_membership=bounded('/proc/self/cgroup',4096).decode(),
        mountinfo=bounded('/proc/self/mountinfo',128*1024).decode(),
        interfaces=sorted(p.name for p in Path('/sys/class/net').iterdir()),
        namespaces={k:os.readlink('/proc/self/ns/'+k) for k in ('user','mnt','net','pid','cgroup')},
        pid=os.getpid(),ppid=os.getppid(),starttime=int(before[19]))
    after = bounded('/proc/self/stat',4096).decode().rpartition(') ')[2].split()
    need(before[19] == after[19] and before[1] == after[1], 'observer process identity changed')
    domain(runtime)
    return runtime


def identity(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def tick(deadline):
    need(time.monotonic() < deadline, '60-second metadata deadline exhausted')


def node(path, contents, budget, deadline):
    tick(deadline)
    budget['nodes'] = budget.get('nodes',0)+1
    need(budget['nodes'] <= 8192, '8192 aggregate metadata node bound')
    path = Path(path)
    need(not any(p.is_symlink() for p in path.parents), 'metadata ancestry alias refused')
    try:
        before = path.lstat()
    except FileNotFoundError:
        return {'type':'absent'}
    row = dict(mode=stat.S_IMODE(before.st_mode),uid=before.st_uid,gid=before.st_gid)
    if stat.S_ISDIR(before.st_mode):
        return dict(row,type='directory')
    if stat.S_ISLNK(before.st_mode):
        target = os.readlink(path)
        need(0 < len(target) <= 4096 and identity(before) == identity(path.lstat()), 'bounded stable link metadata required')
        return dict(row,type='symlink',target=target)
    result,raw = regular_file(path,before,budget,deadline)
    need(str(path) not in contents, 'duplicate raw metadata path')
    contents[str(path)] = base64.b64encode(raw).decode('ascii')
    return result


def regular_file(path, before, budget, deadline):
    need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= FILE_CAP, 'bounded regular metadata required')
    budget['bytes'] += before.st_size
    need(budget['bytes'] <= FILE_CAP, '16 MiB aggregate metadata file bound')
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(identity(before) == identity(os.fstat(fd)), 'metadata changed before FD read')
        raw = bytearray()
        while block := os.read(fd,min(65536,FILE_CAP+1-len(raw))):
            tick(deadline)
            raw.extend(block)
            need(len(raw) <= before.st_size, 'metadata grew during read')
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'metadata changed during read')
    finally:
        os.close(fd)
    return dict(type='file',mode=stat.S_IMODE(before.st_mode),uid=before.st_uid,gid=before.st_gid,bytes=len(raw),sha256=sha(raw)),bytes(raw)


def package_fields(raw):
    lines = raw.decode().splitlines()
    result = {}
    for field in ('NAME','VERSION'):
        indexes = [i for i,line in enumerate(lines) if line == '%'+field+'%']
        need(len(indexes) == 1, 'one scalar ALPM '+field+' field required')
        index = indexes[0]
        need(index+1 < len(lines) and lines[index+1] and (index+2 == len(lines) or not lines[index+2]), 'complete scalar ALPM field required')
        result[field.lower()] = lines[index+1]
    need(re.fullmatch('[A-Za-z0-9@._+-]{1,128}',result['name']) and re.fullmatch('[A-Za-z0-9._+:~+-]{1,128}',result['version']), 'literal ALPM name/version required')
    return result


def inventory_database(root, expected_lock, budget, deadline):
    """Read only fixed local-package desc leaves; never invoke ALPM or read scripts."""
    root = Path(root)
    need(root.is_dir() and not root.is_symlink() and not any(p.is_symlink() for p in root.parents), 'ordinary local ALPM database root required')
    files,contents = {},{}
    rows = {}
    for directory in sorted(root.iterdir()):
        tick(deadline)
        info = directory.lstat()
        if directory.name == 'ALPM_DB_VERSION':
            need(stat.S_ISREG(info.st_mode), 'ordinary untouched ALPM version marker required')
            continue
        need(stat.S_ISDIR(info.st_mode) and len(files) < 349, '349 ordinary ALPM package directories required')
        path = directory/'desc'
        before = path.lstat()
        budget['nodes'] = budget.get('nodes',0)+1
        need(budget['nodes'] <= 8192, '8192 aggregate metadata node bound')
        record,raw = regular_file(path,before,budget,deadline)
        fields = package_fields(raw)
        need(directory.name == fields['name']+'-'+fields['version'] and fields['name'] not in rows, 'exact unique ALPM name/version directory required')
        rows[fields['name']] = fields['version']
        relative = directory.name+'/desc'
        files[relative] = dict(record,**fields)
        contents[relative] = base64.b64encode(raw).decode('ascii')
    inventory = ''.join(name+' '+version+'\n' for name,version in sorted(rows.items()))
    need(len(files) == len(rows) == 349 and inventory.encode() == expected_lock and sha(expected_lock) == EXPECTED349, 'actual complete349 local database must equal exact builder lock')
    return dict(root='/var/lib/pacman/local',fields=['NAME','VERSION'],inventory=inventory,files=files,contents=contents)


def snapshot(root, contents, budget, deadline):
    root = Path(root)
    rows = {'.':node(root,contents,budget,deadline)}
    if rows['.']['type'] == 'absent':
        return rows
    need(rows['.']['type'] == 'directory', 'hook root must be real directory or absent')
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            tick(deadline)
            name = path.relative_to(root).as_posix()
            need(len(name) <= 4096 and len(rows) < 4096, 'hook root path/count bound')
            row = node(path,contents,budget,deadline)
            need(row['type'] != 'absent', 'hook node disappeared')
            rows[name] = row
            if row['type'] == 'directory':
                pending.append(path)
    return rows


def file_row(row):
    need(type(row) is dict and set(row) == {'type','mode','uid','gid','bytes','sha256'} and row['type'] == 'file', 'complete file metadata row required')
    need(type(row['bytes']) is int and 0 <= row['bytes'] <= FILE_CAP and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']), 'bounded exact file hash/size required')


def metadata_row(row):
    need(type(row) is dict and row.get('type') in ('absent','directory','symlink','file'), 'known passive metadata type required')
    if row['type'] == 'absent':
        need(set(row) == {'type'}, 'exact absent node metadata')
        return
    need(type(row.get('mode')) is int and 0 <= row['mode'] <= 0o7777 and all(type(row.get(k)) is int and 0 <= row[k] < 2**32 for k in ('uid','gid')), 'exact mode/uid/gid metadata required')
    if row['type'] == 'file':
        file_row(row)
    elif row['type'] == 'directory':
        need(set(row) == {'type','mode','uid','gid'}, 'exact directory metadata')
    else:
        need(set(row) == {'type','mode','uid','gid','target'} and type(row['target']) is str and 0 < len(row['target']) <= 4096 and '\0' not in row['target'], 'exact symlink metadata')


def validate(value):
    need(type(value) is dict and set(value) == {'schema','status','binding','machine','page_bytes','runtime','package_inventory','package_database','config_files','hook_snapshots','file_contents','metadata_file_bytes','observed_seconds'}, 'closed original observation DATA shape required')
    need(value['schema'] == 1 and value['status'] == STATUS and value['machine'] == 'aarch64' and value['page_bytes'] == 4096, 'original native ARM4K observation DATA only')
    binding_data(value['binding'])
    domain(value['runtime'])
    need(type(value['observed_seconds']) in (int,float) and math.isfinite(value['observed_seconds']) and 0 <= value['observed_seconds'] <= SECONDS, 'finite 60-second metadata interval required')
    inventory = value['package_inventory']
    need(type(inventory) is dict and set(inventory) == {'file','packages','perl'} and inventory['packages'] == 349 and inventory['perl'] == '5.42.3-1', 'baseline Perl349 inventory shape required')
    metadata_row(inventory['file']);file_row(inventory['file'])
    need(type(value['config_files']) is dict and set(value['config_files']) == {CONFIG}, 'only fixed pacman config metadata required')
    metadata_row(value['config_files'][CONFIG]);file_row(value['config_files'][CONFIG])
    files = {LOCK:inventory['file'],CONFIG:value['config_files'][CONFIG]}
    hooks = value['hook_snapshots']
    need(type(hooks) is dict and set(hooks) == set(HOOK_ROOTS), 'exact three fixed hook roots required')
    count = 2
    for root,rows in hooks.items():
        need(type(rows) is dict and '.' in rows and 1 <= len(rows) <= 4096, 'bounded complete hook root map required')
        count += len(rows)
        need(rows['.']['type'] in ('directory','absent') and (rows['.']['type'] != 'absent' or len(rows) == 1), 'hook root type/absence differs')
        for name,row in rows.items():
            path = PurePosixPath(name)
            need(type(name) is str and len(name) <= 4096 and (name == '.' or (not path.is_absolute() and path.as_posix() == name and all(p not in ('', '.', '..') for p in path.parts))), 'contained complete hook path required')
            metadata_row(row)
            if name != '.':
                parent = str(path.parent)
                need(parent in rows and rows[parent]['type'] == 'directory' and row['type'] != 'absent', 'complete real hook ancestry required')
            if row['type'] == 'file':
                files[str(PurePosixPath(root)/name)] = row
    database = value['package_database']
    need(type(database) is dict and set(database) == {'root','fields','inventory','files','contents'} and database['root'] == '/var/lib/pacman/local' and database['fields'] == ['NAME','VERSION'] and type(database['files']) is dict and len(database['files']) == 349, 'exact observed local349 database shape required')
    need(type(database['contents']) is dict and set(database['contents']) == set(database['files']), 'original bytes for exactly349 desc paths required')
    database_rows = {}
    database_bytes = 0
    for name,row in database['files'].items():
        need(type(row) is dict and set(row) == {'type','mode','uid','gid','bytes','sha256','name','version'}, 'exact observed ALPM desc metadata fields required')
        metadata_row({k:v for k,v in row.items() if k not in ('name','version')})
        file_row({k:v for k,v in row.items() if k not in ('name','version')})
        need(type(row['name']) is str and re.fullmatch('[A-Za-z0-9@._+-]{1,128}',row['name']) and type(row['version']) is str and re.fullmatch('[A-Za-z0-9._+:~+-]{1,128}',row['version']) and name == row['name']+'-'+row['version']+'/desc' and row['name'] not in database_rows, 'unique contained ALPM desc/name/version join required')
        body = database['contents'][name]
        need(type(body) is str and len(body) <= ((FILE_CAP+2)//3)*4, 'bounded original desc DATA required')
        try:
            raw = base64.b64decode(body,validate=True)
        except (ValueError,base64.binascii.Error) as error:
            raise ValueError('invalid original desc base64') from error
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'] and base64.b64encode(raw).decode('ascii') == body, 'original desc byte/hash/encoding join required')
        need(package_fields(raw) == {k:row[k] for k in ('name','version')}, 'original desc NAME/VERSION parsed fields differ')
        database_rows[row['name']] = row['version']
        database_bytes += len(raw)
        need(database_bytes <= FILE_CAP, '16 MiB aggregate original desc byte bound')
    count += len(database['files'])
    need(count <= 8192, '8192 total observed-node bound')
    contents = value['file_contents']
    need(type(contents) is dict and set(contents) == set(files), 'raw contents must match only every fixed config/hook/inventory file')
    total = 0
    lock = None
    for name,row in files.items():
        body = contents[name]
        need(type(body) is str and len(body) <= ((FILE_CAP+2)//3)*4, 'bounded base64 file DATA required')
        try:
            raw = base64.b64decode(body,validate=True)
        except (ValueError,base64.binascii.Error) as error:
            raise ValueError('invalid base64 file DATA') from error
        total += len(raw)
        need(total <= FILE_CAP and len(raw) == row['bytes'] and sha(raw) == row['sha256'] and base64.b64encode(raw).decode('ascii') == body, 'exact raw file byte/hash/encoding join required')
        if name == LOCK:
            lock = raw
    total += database_bytes
    need(total <= FILE_CAP and type(value['metadata_file_bytes']) is int and value['metadata_file_bytes'] == total, 'exact aggregate metadata byte accounting required')
    rows = lock.decode().splitlines()
    need(sha(lock) == EXPECTED349 and len(rows) == 349 and rows == sorted(set(rows)) and dict(row.split(' ',1) for row in rows).get('perl') == '5.42.3-1', 'exact fixed349 baseline lock bytes required')
    actual_inventory = ''.join(name+' '+version+'\n' for name,version in sorted(database_rows.items()))
    need(database['inventory'] == actual_inventory == lock.decode(), 'actual ALPM database inventory must equal builder lock')
    encode(value)
    return dict(status='VALID_ORIGINAL_BASELINE_OBSERVATION_DATA_ONLY',mutation_qualification='NOT_ISSUED',metadata_file_bytes=total,nodes=count)


def observe(binding):
    binding_data(binding)
    start = time.monotonic()
    deadline = start+SECONDS
    runtime = runtime_context()  # No image metadata is touched before this guard.
    machine,page = os.uname().machine,os.sysconf('SC_PAGE_SIZE')
    need(machine == 'aarch64' and page == 4096, 'native ARM4K observer required')
    contents,budget = {},{'bytes':0}
    lock = node(Path(LOCK),contents,budget,deadline)
    lock_bytes = base64.b64decode(contents[LOCK])
    database = inventory_database(Path('/var/lib/pacman/local'),lock_bytes,budget,deadline)
    configs = {CONFIG:node(Path(CONFIG),contents,budget,deadline)}
    hooks = {root:snapshot(Path(root),contents,budget,deadline) for root in HOOK_ROOTS}
    value = dict(schema=1,status=STATUS,binding=dict(binding),machine=machine,page_bytes=page,runtime=runtime,
        package_inventory=dict(file=lock,packages=349,perl='5.42.3-1'),package_database=database,config_files=configs,hook_snapshots=hooks,
        file_contents=contents,metadata_file_bytes=budget['bytes'],observed_seconds=time.monotonic()-start)
    validate(value)
    tick(deadline)
    value['observed_seconds'] = time.monotonic()-start
    return value


def decode_binding(raw):
    need(len(raw.encode()) <= 16384, 'bounded public binding JSON required')
    def pairs(rows):
        result = {}
        for key,value in rows:
            need(key not in result, 'duplicate public binding field')
            result[key] = value
        return result
    value = json.loads(raw,object_pairs_hook=pairs)
    binding_data(value)
    return value


if __name__ == '__main__':
    need(sys.flags.isolated and not sys.flags.optimize, 'isolated unoptimized observer entry required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binding-json',required=True)
    args = parser.parse_args()
    sys.stdout.buffer.write(encode(observe(decode_binding(args.binding_json))))
