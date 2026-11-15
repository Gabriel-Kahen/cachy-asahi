#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Future offline independent Reader; import has no operational side effects.

Root authenticates the binding, provider observations and whole original archive.
This driver independently replays DATA checks; it executes no Source code.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import resource
import stat
import struct
import sys
import tarfile
import tempfile
import time
import zipfile

HERE = Path(__file__).resolve().parent
MIB, GIB = 1024**2, 1024**3
PREFIX = '/opt/cachy-asahi/llvm23-source-reference'
END = None


def need(ok, why):
    if not ok:
        raise ValueError(why)
    need_time()


def need_time():
    if END is not None and time.monotonic() >= END:
        raise ValueError('Reader wall bound exhausted')


def path(value):
    p = Path(value)
    need(p.is_absolute() and '..' not in p.parts and not any(x.is_symlink() for x in (p, *p.parents)), 'ordinary absolute DATA path required')
    return p


def hashed(p, limit=8*GIB):
    p = path(p)
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, 'bounded single-link DATA required')
        h = hashlib.sha256()
        while block := stream.read(MIB):
            need_time();h.update(block)
        after = os.fstat(stream.fileno())
    key = lambda s: (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(key(before) == key(after) == key(p.lstat()), 'DATA changed while hashed')
    return {'bytes':before.st_size, 'sha256':h.hexdigest()}


def read(p, limit=16*MIB):
    pin = hashed(p, limit)
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb') as stream:
        info = os.fstat(stream.fileno());need(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'ordinary bounded reread required')
        raw = stream.read(limit+1)
    need(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'], 'DATA changed while read')
    return raw


def decode(raw):
    def pairs(rows):
        out = {}
        for k,v in rows:
            need(k not in out, 'duplicate JSON key');out[k] = v
        return out
    def bad(_): raise ValueError('nonfinite JSON refused')
    def real(text):
        value = float(text);need(math.isfinite(value), 'nonfinite JSON number');return value
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=bad, parse_float=real)
    pending = [(value,0)];count = 0
    while pending:
        item,depth = pending.pop();count += 1
        need(depth <= 40 and count <= 500000, 'JSON structure bound')
        if isinstance(item,dict):pending.extend((v,depth+1) for v in item.values())
        elif isinstance(item,list):pending.extend((v,depth+1) for v in item)
    return value


def load(p, limit=16*MIB): return decode(read(p, limit))
def canonical(obj): return (json.dumps(obj,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def digest(value, width=64): return type(value) is str and re.fullmatch('[0-9a-f]{'+str(width)+'}', value) is not None


def check_binding(b, pins):
    need(b['schema'] == 1 and b['scope'] == 'ROOT_BOUND_LLVM23_INDEPENDENT_READER_V2' and b['operation'] == pins['operation'] and b['holds_preserved'] is True, 'Root Reader scope/holds required')
    a = b['actual']
    need(set(a) == {'source','ref','run','job','attempt','approval','authority','image','artifact','reader'} and all(v is not None for v in a.values()), 'all actual selectors remain unbound until Root')
    need(a['source'] == pins['source'] and a['ref'] == pins['ref'], 'exact published v2 Source identity')
    need(digest(a['source'],40) and digest(a['approval']) and re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+',a['ref']) and a['attempt'] == 1, 'exact first Source/ref/approval required')
    need(all(type(a[k]) is str and re.fullmatch('[1-9][0-9]{0,19}',a[k]) for k in ('run','job','artifact')), 'actual numeric selectors required')
    need(type(a['authority']) is str and a['authority'].strip() and type(a['reader']) is str and a['reader'].strip() and re.fullmatch('sha256:[0-9a-f]{64}',a['image']), 'Root authority/reader/image bindings required')
    for k in ('provider_sha256','source_commit_sha256','export_sha256','package_sha256','reader_sha256','pins_sha256'):
        need(digest(b[k]), 'whole external Root material pin required: '+k)
    need(b['source_map_sha256'] == pins['source_map_sha256'] and b['source_tree'] == pins['source_tree'] and b['policy_sha256'] == pins['files']['policy.json']['sha256'], 'different frozen Source/policy')
    for row in (b['original_archive'], b['full_original_decode']):
        need(type(row['bytes']) is int and 0 < row['bytes'] <= 8*GIB, 'bounded actual archive/decode bytes required')
    need(digest(b['original_archive']['sha256']) and digest(b['full_original_decode']['map_sha256']) and type(b['full_original_decode']['files']) is int and 0 < b['full_original_decode']['files'] <= 4096, 'whole Original decode binding required')


def safe_name(name):
    need(type(name) is str and re.fullmatch('[A-Za-z0-9._+/-]{1,300}',name) and not name.startswith('/') and all(x not in ('','.','..') for x in name.split('/')), 'literal contained DATA member required')
    return name


def full_zip(original, output, expected):
    """Decode every member, verify CRC by EOF, retain only nonexecutable DATA."""
    need(not output.exists(), 'fresh complete Original decode destination required')
    output.mkdir(mode=0o700)
    rows = {};seen = set();total = 0
    with zipfile.ZipFile(original) as archive:
        need(len(archive.infolist()) <= 4096, 'ZIP member count bound')
        for item in archive.infolist():
            name = safe_name(item.filename.rstrip('/'))
            need(name not in seen and not item.flag_bits & 1 and item.compress_type in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED), 'duplicate/encrypted/unsupported ZIP member')
            seen.add(name)
            mode = item.external_attr >> 16
            need(not mode or stat.S_IFMT(mode) in (0,stat.S_IFREG,stat.S_IFDIR), 'ZIP links/devices refused')
            target = output/name
            if item.is_dir():target.mkdir(parents=True,exist_ok=True);continue
            need(item.file_size <= 4*GIB, 'ZIP single-member cap')
            total += item.file_size
            need(total <= 8*GIB, 'ZIP complete decoded-byte cap')
            target.parent.mkdir(parents=True,exist_ok=True)
            h = hashlib.sha256();size = 0
            with archive.open(item) as source,target.open('xb') as destination:
                while block := source.read(MIB):
                    need_time();size += len(block);need(size <= item.file_size, 'ZIP expanded size drift')
                    h.update(block);destination.write(block)
            target.chmod(0o400)
            need(size == item.file_size, 'incomplete ZIP decode')
            rows[name] = {'bytes':size,'sha256':h.hexdigest()}
    actual = {'files':len(rows),'bytes':total,'map_sha256':hashlib.sha256(canonical(rows)).hexdigest()}
    need(actual == expected, 'full Original decode membership/bytes/map differs')
    return rows


def git_oid(kind, raw): return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()


def source_tree(root, pins, commit_raw, actual_source):
    need(git_oid('commit',commit_raw) == actual_source and commit_raw.startswith(('tree '+pins['source_tree']+'\n').encode()), 'Root Source commit/tree object differs')
    return source_namespace(root,pins)


def source_namespace(root,pins):
    """Independent closed-map and Git blob/tree replay; no Git or Source import."""
    need(hashed(root/'source-map.json')['sha256'] == pins['source_map_sha256'], 'whole frozen Source map differs')
    manifest = load(root/'source-map.json');files = manifest['files']
    need(all(v is None for v in manifest['actual'].values()), 'published Source must preserve null author selectors')
    found = {};dirs = set();total = 0;nodes = 0
    for current, names, leaves in os.walk(root,followlinks=False):
        names.sort()
        for name in names:
            p = Path(current)/name;need(not p.is_symlink(), 'Source directory alias');dirs.add(p.relative_to(root).as_posix())
        for name in leaves:
            p = Path(current)/name;relative = p.relative_to(root).as_posix();safe_name(relative)
            row = hashed(p,64*MIB);mode = stat.S_IMODE(p.stat().st_mode)
            need(mode in (0o644,0o755), 'canonical Source mode required')
            if relative != 'source-map.json':need(dict(row,mode=mode) == files[relative], 'Source byte/mode drift: '+relative)
            total += row['bytes'];nodes += 1
            raw = read(p,64*MIB)
            found[relative] = dict(row,mode=mode,blob=git_oid('blob',raw))
    expected = set(files)|{'source-map.json'}
    need(set(found) == expected and nodes == pins['source_files'] and total == pins['source_bytes'], 'complete Source membership/count/bytes')
    need(dirs == {str(p) for name in expected for p in PurePosixPath(name).parents if str(p) != '.'}, 'complete Source directory membership')
    def tree(prefix=''):
        children = {}
        for name,row in found.items():
            if not name.startswith(prefix):continue
            part = name[len(prefix):].split('/',1)[0]
            children[part] = None if prefix+part != name else row
        body = bytearray()
        for name,row in sorted(children.items(),key=lambda x:(x[0]+('/' if x[1] is None else '')).encode()):
            mode,oid = ('40000',tree(prefix+name+'/')) if row is None else ('100755' if row['mode'] == 0o755 else '100644',row['blob'])
            body.extend(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(oid))
        return git_oid('tree',body)
    need(tree() == pins['source_tree'], 'independent full Source Git tree differs')
    # Full original dependency Source is already included in the outer closed map.
    original = load(root/'original/native/source-map.json')
    need(all(v is None for v in original['actual'].values()) and all('original/'+name in found for name in original['files']), 'full Original dependency Source missing')
    for name,row in original['files'].items():
        need(dict(hashed(root/'original'/name),mode=stat.S_IMODE((root/'original'/name).stat().st_mode)) == row, 'Original dependency byte/mode drift')
    return found


def source_successor(source,parent,pins,found):
    """Replay the complete parent inverse using independently retained DATA bytes."""
    before = source_namespace(parent,pins['parent']);meta = load(source/'successor-v2.json')
    expected_parent = dict(source=pins['parent']['source'],files=248,bytes=40788233,map_sha256=pins['parent']['source_map_sha256'],tree=pins['parent']['source_tree'])
    need(meta['parent'] == expected_parent and meta['outer_operation'] == pins['operation'] and meta['inner_operation'] == pins['inner_operation'] and meta['candidate_unchanged'] is True and all(v is None for v in meta['actual'].values()), 'exact parent/outer-v2/inner-v1 inverse metadata')
    describe = lambda row: None if row is None else {k:row[k] for k in ('bytes','sha256','mode')}
    changes = {n for n in set(found)|set(before) if n not in ('source-map.json','successor-v2.json') and found.get(n) != before.get(n)}
    need(set(meta['changed']) == changes, 'complete inverse change membership')
    restored = dict(found);restored.pop('successor-v2.json');restored.pop('source-map.json')
    for name,row in meta['changed'].items():
        need(row['before'] == describe(before.get(name)) and row['after'] == describe(found.get(name)), 'inverse actual before/after byte-mode operands')
        if name in before:restored[name] = before[name]
        else:restored.pop(name)
    restored['source-map.json'] = before['source-map.json'];need(restored == before, 'whole parent inverse differs')
    frozen = {'actor/entry.py','actor/runtime.py','actor/container_mode.py','actor/runtime-derivation.json'}
    need(set(meta['frozen_python']) == frozen and all(found[n] == before[n] and meta['frozen_python'][n] == describe(before[n]) for n in frozen), 'frozen v1 Python actor/runtime differs')
    for prefix in ('packages/','original/'):
        need({n:r for n,r in found.items() if n.startswith(prefix)} == {n:r for n,r in before.items() if n.startswith(prefix)}, 'candidate or original subtree changed')
    need(found['candidate-map.json'] == before['candidate-map.json'] and len([n for n in found if n.startswith('original/')]) == 200, 'whole candidate map/original200 differs')
    for name,row in pins['files'].items():need(describe(found.get(name)) == row, 'explicit source operand differs: '+name)
    old = read(parent/'actor/entry.sh');line = b'exec /usr/bin/python3 -I -B /inputs/actor/entry.py\n'
    need(old.count(line) == 1 and read(source/'actor/entry.sh') == old.replace(line,b'/usr/bin/python3 -I -B /inputs/actor/work_check.py\n'+line), 'exact narrow preentry shell derivation')
    contract = load(source/'contract.json')
    need(contract['operation'] == pins['inner_operation'] and contract['outer_delegation'] == dict(operation=pins['operation'],inner_operation=pins['inner_operation'],frozen_python_actor=True,volume_preentry='EXACT_NONMUTATING_WORK_ROOT_CHECK'), 'explicit unchanged inner contract delegation')
    need(load(source/'policy.json') == pins['policy'] and read(source/'.github/workflows/native-arm-build.yml') == read(source/'.github/workflows/native-arm-llvm23-source-reference-v2.yml'), 'exact new policy and workflow aliases')
    return before


def volume_owner(a):
    token = hashlib.sha256((a['source']+':'+a['run']+':'+a['job']).encode()).hexdigest()[:24];actor = 'llvm23v2-'+token
    return dict(source=a['source'],run=a['run'],job=a['job'],operation='llvm23-source-reference-native-v2',token=token,actor=actor,init=actor+'-init',volume=actor+'-work')


def volume_labels(owner,role):
    return {'cachy-asahi.operation':owner['operation'],'cachy-asahi.llvm-work.source':owner['source'],'cachy-asahi.llvm-work.token':owner['token'],'cachy-asahi.llvm-work.role':role}


def no_copy(row,owner,only=False):
    declared = row['HostConfig']['Mounts'];work = [m for m in declared if m['Target'] == '/work']
    need((not only or len(declared) == 1) and len(work) == 1 and work[0]['Type'] == 'volume' and work[0]['Source'] == owner['volume'] and work[0]['VolumeOptions']['NoCopy'] is True, 'exact owned volume-nocopy declaration')


def initializer(row,owner,image,pins):
    h,c = row['HostConfig'],row['Config'];cmd = c['Cmd']
    need(row['Name'] == '/'+owner['init'] and digest(row['Id']) and row['Image'] == image and c['User'] == '0:0' and c['WorkingDir'] == '/' and c['Entrypoint'] == ['/usr/bin/python3'], 'exact Root0 initializer identity')
    need(cmd[:3] == ['-I','-B','-c'] and len(cmd) == 5 and hashlib.sha256(cmd[3].encode()).hexdigest() == pins['initializer_code_sha256'] and cmd[4] == canonical(owner).decode(), 'whole pinned initializer code and exact owner input')
    need(all(c['Labels'].get(k) == v for k,v in volume_labels(owner,'initializer').items()), 'initializer source/token/role labels')
    need(h['ReadonlyRootfs'] is True and h['NetworkMode'] == 'none' and h['CapDrop'] == ['ALL'] and h['CapAdd'] == ['CHOWN'] and h['SecurityOpt'] == ['no-new-privileges'] and h['Privileged'] is False and not h['Devices'] and not h.get('DeviceRequests') and not h.get('Init') and h.get('UsernsMode','') == '', 'minimal CHOWN-only offline initializer domain')
    need(h['Memory'] == h['MemorySwap'] == 512*MIB and h['NanoCpus'] == 10**9 and h['PidsLimit'] == 64, 'initializer 512MiB/oneCPU/64task limits')
    need(len(row['Mounts']) == 1 and row['Mounts'][0]['Type'] == 'volume' and row['Mounts'][0]['Name'] == owner['volume'] and row['Mounts'][0]['Destination'] == '/work' and row['Mounts'][0]['RW'] is True, 'only owned initializer volume')
    no_copy(row,owner,only=True)


def builder_command(owner,producer,image,volume_sha):
    docker = ['/usr/bin/docker','--host=unix:///var/run/docker.sock']
    return docker+['create','--name',owner['actor'],*[x for k,v in volume_labels(owner,'builder').items() for x in ('--label',k+'='+v)],'--cpus=2','--memory=8g','--memory-swap=8g','--pids-limit=512','--init','--read-only','--network=none','--hostname=llvm23-native','--cap-drop=ALL','--security-opt=no-new-privileges','--user=1001:1001','--ulimit=nofile=1024:1024','--ulimit=core=0:0','--workdir=/work','--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001','--tmpfs=/run:rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001','--mount','type=volume,src='+owner['volume']+',dst=/work,volume-nocopy','--mount','type=bind,src='+producer['inputs_path']+',dst=/inputs,readonly','--mount','type=bind,src='+producer['source_intake']['root']+',dst=/source,readonly','--env','ADMISSION_SHA256='+producer['admission_sha256'],'--env','WORK_VOLUME_ADMISSION_SHA256='+volume_sha,'--entrypoint=/usr/bin/bash',image,'--noprofile','--norc','/inputs/actor/entry.sh']


def volume_initialization(evidence,producer,a,pins):
    """Independently join actual command outputs, identities, order and preentry."""
    owner = volume_owner(a);base = evidence/'llvm-build'
    need(producer['volume_owner'] == owner and producer['inner_operation'] == pins['inner_operation'] and all(producer[k] == owner[k] for k in ('actor','init','volume')), 'exact v2 source/token owner and inner-v1 delegation')
    before = load(base/'volume-before.json')
    need(before['Name'] == owner['volume'] and before['Driver'] == before['Scope'] == 'local' and not before.get('Options') and before['Labels'] == volume_labels(owner,'work'), 'exact owned local volume; no foreign resource')
    initial = load(base/'initializer-before.json');finished = load(base/'initializer-after.json')
    initializer(initial,owner,a['image'],pins);initializer(finished,owner,a['image'],pins)
    need(initial['Id'] == finished['Id'] and initial['State']['Status'] == 'created' and initial['State']['Pid'] == 0 and initial['State']['Running'] is False, 'same created initializer before start')
    need(finished['State']['Status'] == 'exited' and finished['State']['ExitCode'] == 0 and finished['State']['Pid'] == 0 and finished['State']['Running'] is False and finished['State']['OOMKilled'] is False and not finished['State'].get('Error'), 'natural initializer completion')
    observed = load(base/'volume-initialization.json');need(observed == producer['volume_initialization'] == load(base/'inputs/volume-initialization.json'), 'whole initializer receipt continuity')
    need(observed['schema'] == 1 and observed['status'] == 'INITIALIZED_EMPTY_WORK_VOLUME' and observed['binding'] == owner and observed['recursive'] is False and observed['capabilities'] == 'CHOWN_ONLY_CHMOD_BEFORE_CHOWN' and observed['limits'] == {'cpu.max':'100000 100000','memory.max':'536870912','memory.swap.max':'0','pids.max':'64'}, 'actual bounded initializer receipt')
    old,new = observed['before'],observed['after']
    for row in (old,new):need(set(row) == {'device','inode','uid','gid','mode'} and all(type(v) is int and v >= 0 for v in row.values()) and row['inode'] > 0, 'actual ordinary directory stat required')
    need(old['uid'] == old['gid'] == 0 and new['uid'] == new['gid'] == 1001 and new['mode'] == 0o700 and (old['device'],old['inode']) == (new['device'],new['inode']), 'same initialized 1001:1001/0700 work volume')
    admission = load(base/'inputs/volume-admission.json');volume_sha = hashed(base/'inputs/volume-admission.json')['sha256']
    need(admission == dict(schema=1,outer_operation=pins['operation'],inner_operation=pins['inner_operation'],binding=owner,expected_owner=dict(uid=1001,gid=1001,mode=0o700),native_acceptance=False) and volume_sha == producer['volume_admission_sha256'], 'exact preentry admission and digest')
    actor = load(base/'actor-inspect.json');done = load(base/'actor-finished.json');actor_inspect(actor,done,producer,a['image']);no_copy(actor,owner)
    need(actor['State']['Status'] == 'created' and actor['State']['Pid'] == 0 and actor['State']['Running'] is False and done['State']['Pid'] == 0 and done['State']['Running'] is False, 'builder remains unstarted before initialization and naturally absent after completion')
    need(all(actor['Config']['Labels'].get(k) == v for k,v in volume_labels(owner,'builder').items()) and 'WORK_VOLUME_ADMISSION_SHA256='+volume_sha in actor['Config']['Env'] and 'ADMISSION_SHA256='+producer['admission_sha256'] in actor['Config']['Env'], 'actual nonroot builder label/admission joins')
    rows = load(evidence/'bootstrap/operations.json');docker = ['/usr/bin/docker','--host=unix:///var/run/docker.sock']
    def one(predicate):
        matches = [(i,r) for i,r in enumerate(rows) if predicate(r['argv'])];need(len(matches) == 1, 'one actual initialization-stage operation required');i,row = matches[0];natural(row['lifecycle']);need(row['returncode'] == row['lifecycle']['exit'] == 0, 'natural successful stage command')
        for channel in ('stdout','stderr'):need(hashed(evidence/safe_name(row[channel]),16*MIB) == row[channel+'_pin'], 'whole stage raw output binding')
        return i,row
    def create(name):return one(lambda argv:argv[:3] == docker+['create'] and '--name' in argv and argv[argv.index('--name')+1] == name)
    bi,bc = create(owner['actor']);ii,ic = create(owner['init']);si,start = one(lambda argv:argv == docker+['start','--attach',owner['init']]);ai,build = one(lambda argv:argv == docker+['start','--attach',owner['actor']])
    need(max(bi,ii) < si < ai, 'both nocopy containers must be created before final initialization and builder start')
    elapsed = start['lifecycle']['elapsed_seconds'];need(type(elapsed) in (int,float) and math.isfinite(elapsed) and 0 <= elapsed <= 120, 'actual initializer120-second envelope')
    need(read(evidence/bc['stdout']).decode().strip() == actor['Id'] and read(evidence/ic['stdout']).decode().strip() == initial['Id'], 'created IDs must match observed owned containers')
    def inspections(name,expected):
        matches = [(i,row) for i,row in enumerate(rows) if row['argv'] == docker+['inspect',name]]
        need(len(matches) == len(expected), 'complete exact direct inspect sequence')
        for (index,row),value in zip(matches,expected):
            natural(row['lifecycle']);need(row['returncode'] == row['lifecycle']['exit'] == 0, 'natural inspect command')
            for channel in ('stdout','stderr'):need(hashed(evidence/safe_name(row[channel]),16*MIB) == row[channel+'_pin'], 'whole inspect raw output')
            need(load(evidence/row['stdout']) == [value], 'inspect raw output/retained identity differs')
        return [index for index,_ in matches]
    ib,ie = inspections(owner['init'],[initial,finished]);ab,ae = inspections(owner['actor'],[actor,done])
    need(ii < ib < si < ie < ai and bi < ab < si and ai < ae, 'actual before/after inspect ordering differs')

    need(load(evidence/start['stdout']) == observed, 'actual initializer stdout differs from receipt')
    first = read(evidence/build['stdout'],16*MIB).split(b'\n',1)[0];need(len(first) <= 16384, 'bounded preentry observation')
    need(decode(first) == dict(status='NONROOT_WORK_VOLUME_VERIFIED',binding=owner,actual=new,write_probe=False), 'actual uid1001 empty/writable same-volume preentry observation')
    init_command = docker+['create','--name',owner['init'],*[x for k,v in volume_labels(owner,'initializer').items() for x in ('--label',k+'='+v)],'--user=0:0','--init=false','--workdir=/','--cpus=1','--memory=512m','--memory-swap=512m','--pids-limit=64','--network=none','--read-only','--cap-drop=ALL','--cap-add=CHOWN','--security-opt=no-new-privileges','--mount','type=volume,src='+owner['volume']+',dst=/work,volume-nocopy','--entrypoint=/usr/bin/python3',a['image'],*initial['Config']['Cmd']]
    need(ic['argv'] == init_command and bc['argv'] == builder_command(owner,producer,a['image'],volume_sha), 'exact finite initializer and ordinary builder create operands')
    return observed


def natural(life):
    need(all(life.get(k) is True for k in ('natural_exit','group_absent','leader_held_until_group_inspection','exit_observed_via_waitpid')) and life.get('retirement') == 'REAPED' and life.get('ownership_lost') is False and life.get('forced_cleanup') is False and type(life.get('exit')) is int and not life.get('cleanup_error'), 'natural exclusive retirement unproven/forced')


def runtime(value):
    entry,parent = value['entry'],value['parent']
    for row in (entry,parent):
        need(all(row[k] == 1001 for k in ('uid','euid','gid','egid')) and row['architecture'] == 'aarch64' and row['page_bytes'] == 4096, 'actual native AArch64 4K alarm1001 required')
        need(row['limits'] == {'cpu.max':'200000 100000','memory.max':'8589934592','memory.swap.max':'0','pids.max':'512'} and row['interfaces'] == ['lo'] and row['hostname'] == 'llvm23-native', 'actual resource/network profile differs')
        need(all(int(row['status'][k],16) == 0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')) and row['status']['NoNewPrivs'] == '1' and row['status']['Seccomp'] == '2' and int(row['status']['Seccomp_filters']) > 0, 'actual cap0/NNP/seccomp domain')
        need(row['uid_map'] == row['gid_map'] == [[0,0,4294967295]], 'actual unremapped Rootful maps differ')
        need(set(row['namespaces']) == {'user','mnt','net','pid'} and all(re.fullmatch(k+r':\[[1-9][0-9]*\]',v) for k,v in row['namespaces'].items()), 'actual namespace identities missing')
        need(type(row['cgroup']) is str and re.fullmatch(r'0::/[A-Za-z0-9._/-]*\n',row['cgroup']), 'actual unified cgroup observation required')
        mounts = {}
        for line in row['mountinfo'].splitlines():
            left,sep,right = line.partition(' - ');parts = left.split();tail = right.split()
            need(sep and len(parts) >= 6 and len(tail) == 3, 'complete mountinfo required')
            if parts[4] in ('/','/inputs','/source','/work','/tmp','/run'):
                need(parts[4] not in mounts, 'duplicate required mount');mounts[parts[4]] = (set(parts[5].split(',')),tail)
        need(set(mounts) == {'/','/inputs','/source','/work','/tmp','/run'}, 'required mount observations absent')
        for name in ('/','/inputs','/source'):need('ro' in mounts[name][0] and 'rw' not in mounts[name][0], 'readonly domain changed')
        need('rw' in mounts['/work'][0] and 'ro' not in mounts['/work'][0], 'writable work absent')
        for name,size in (('/tmp',64*MIB),('/run',8*MIB)):
            flags,tail = mounts[name];opts = set(tail[2].split(','))
            need({'rw','noexec','nosuid','nodev'} <= flags and tail[0] == 'tmpfs' and {'uid=1001','gid=1001'} <= opts, 'owned safe tmpfs differs')
            text = next((x[5:] for x in opts if x.startswith('size=')), '')
            match = re.fullmatch('([1-9][0-9]*)([kmg]?)',text.lower())
            need(match and int(match[1])*{'':1,'k':1024,'m':MIB,'g':GIB}[match[2]] == size, 'tmpfs size differs')
    need(entry['pid'] > 1 and entry['ppid'] == parent['pid'] == 1 and 0 < parent['starttime'] <= entry['starttime'], 'actual init/entry lineage')
    need(entry['cmdline'] == ['/usr/bin/python3','-I','-B','/inputs/actor/entry.py'] and re.fullmatch('/usr/bin/python3(?:\\.[0-9]{1,2})?',entry['exe']) and entry['cwd'] == '/work/recipe', 'actual entry identity differs')
    need(Path(parent['exe']).name in ('docker-init','tini') and parent['cmdline'][-5:] == ['--','/usr/bin/bash','--noprofile','--norc','/inputs/actor/entry.sh'], 'actual init launcher differs')
    need(all(entry[k] == parent[k] for k in ('namespaces','uid_map','gid_map','groups','cgroup')), 'init/entry domain continuity differs')


def actor_inspect(actual, finished, producer, image):
    h,c = actual['HostConfig'],actual['Config']
    need(actual['Name'] == '/'+producer['actor'] and actual['Image'] == finished['Image'] == image and c['User'] == '1001:1001' and c['Hostname'] == 'llvm23-native' and c['WorkingDir'] == '/work', 'actual actor identity')
    need(h['ReadonlyRootfs'] is True and h['NetworkMode'] == 'none' and h['CapDrop'] == ['ALL'] and not h.get('CapAdd') and h['SecurityOpt'] == ['no-new-privileges'] and h['Privileged'] is False and h.get('UsernsMode','') == '' and not h.get('Devices') and not h.get('DeviceRequests'), 'actual container domain differs')
    need(h['Memory'] == h['MemorySwap'] == 8*GIB and h['NanoCpus'] == 2000000000 and h['PidsLimit'] == 512 and h['Init'] is True, 'actual inspected resources differ')
    mounts = {r['Destination']:r for r in actual['Mounts']}
    need(len(actual['Mounts']) == len(mounts) == 3 and set(mounts) == {'/work','/inputs','/source'}, 'exact actor mount membership')
    need(mounts['/work']['Type'] == 'volume' and mounts['/work']['Name'] == producer['volume'] and mounts['/work']['RW'] is True, 'actual owned work volume')
    for name,source in (('/inputs',producer['inputs_path']),('/source',producer['source_intake']['root'])):
        need(mounts[name]['Type'] == 'bind' and mounts[name]['Source'] == source and mounts[name]['RW'] is False, 'exact readonly source/input mount differs')
    need(c['Entrypoint'] == ['/usr/bin/bash'] and c['Cmd'] == ['--noprofile','--norc','/inputs/actor/entry.sh'], 'fixed actual actor entry')
    need(actual['Id'] == finished['Id'] and finished['Name'] == actual['Name'] and finished['State']['Status'] == 'exited' and finished['State']['ExitCode'] == 0 and finished['State']['OOMKilled'] is False and not finished['State'].get('Error'), 'natural same-container completion unproven')


def elf(stream, size, name):
    header = stream.read(64)
    if header[:4] != b'\x7fELF':return None
    need(len(header) == 64 and header[4:6] == b'\x02\x01' and struct.unpack_from('<H',header,18)[0] == 183, 'package ELF must be LE AArch64 ELF64')
    kind = struct.unpack_from('<H',header,16)[0]
    need(kind in (1,2,3), 'unexpected packaged ELF type')
    if kind == 1:return {'kind':1,'needed':[],'rpaths':[],'soname':None}
    offset = struct.unpack_from('<Q',header,32)[0];width,count = struct.unpack_from('<HH',header,54)
    need(width == 56 and 0 < count <= 1024 and offset+width*count <= size, 'ELF program-header bound')
    stream.seek(offset);segments = [struct.unpack('<IIQQQQQQ',stream.read(56)) for _ in range(count)]
    loads = [r for r in segments if r[0] == 1]
    need(all(r[2]+r[5] <= size and r[5] <= r[6] for r in loads), 'ELF file-backed segment bound')
    need(loads and all(r[7] >= 16384 and r[7] & (r[7]-1) == 0 and r[2]%16384 == r[3]%16384 for r in loads), 'actual ELF 16K PT_LOAD geometry refused')
    dynamic = next((r for r in segments if r[0] == 2), None)
    result = {'kind':kind,'needed':[],'rpaths':[],'soname':None}
    if dynamic:
        need(dynamic[2]+dynamic[5] <= size and dynamic[5] <= MIB and dynamic[5]%16 == 0, 'ELF dynamic bound')
        stream.seek(dynamic[2]);pairs = [struct.unpack('<qQ',stream.read(16)) for _ in range(dynamic[5]//16)]
        end = next((i for i,r in enumerate(pairs) if r[0] == 0),None);need(end is not None, 'ELF dynamic terminator absent');pairs = pairs[:end]
        address = next((v for k,v in pairs if k == 5),None);length = next((v for k,v in pairs if k == 10),0)
        segment = next((r for r in loads if address is not None and r[3] <= address and address+length <= r[3]+r[5]),None)
        need(segment is not None and 0 < length <= 16*MIB, 'ELF string-table bound')
        stream.seek(segment[2]+address-segment[3]);strings = stream.read(length)
        def text(index):
            need(index < len(strings) and b'\0' in strings[index:], 'ELF string index')
            return strings[index:strings.index(b'\0',index)].decode()
        result['needed'] = [text(v) for k,v in pairs if k == 1]
        result['soname'] = next((text(v) for k,v in pairs if k == 14),None)
        for k,v in pairs:
            if k not in (15,29):continue
            for item in text(v).split(':'):
                expanded = item.replace('${ORIGIN}',posixpath.dirname('/'+name)).replace('$ORIGIN',posixpath.dirname('/'+name))
                target = posixpath.normpath(expanded)
                need(item and '$' not in expanded and (target == PREFIX or target.startswith(PREFIX+'/')) and not any(x in item for x in ('/work','/source','/inputs','/tmp')), 'non-private ELF RPATH')
                result['rpaths'].append(target)
        if any(n.startswith('libLLVM') for n in result['needed']):need(PREFIX+'/lib' in result['rpaths'], 'LLVM consumer missing private runtime path')
    return result


# Bounded tar framing follows the pinned hosted reader's MIT-licensed TarInfo
# approach; validation/ELF/Root binding and execution are independent here.
def tar_info(maximum):
    state = {'headers':0,'ended':False}
    class Info(tarfile.TarInfo):
        @classmethod
        def fromtarfile(cls,archive):return cls._fromtarfile(archive)
        @classmethod
        def _fromtarfile(cls,archive,*,dircheck=True):
            block = archive.fileobj.read(512)
            if block == bytes(512):state['ended'] = True
            else:
                state['headers'] += 1;need(state['headers'] <= maximum, 'raw tar header bound')
            item = cls._frombuf(block,archive.encoding,archive.errors,dircheck=dircheck) if hasattr(cls,'_frombuf') else cls.frombuf(block,archive.encoding,archive.errors)
            item.offset = archive.fileobj.tell()-512
            return item._proc_member(archive)
        def _proc_pax(self,archive):
            need(0 <= self.size <= 65536, 'PAX metadata bound');return super()._proc_pax(archive)
        def _proc_gnulong(self,archive):
            need(0 <= self.size <= 65536, 'long-name metadata bound');return super()._proc_gnulong(archive)
        def _proc_sparse(self,*args):raise ValueError('sparse tar refused')
        _proc_gnusparse_00 = _proc_sparse
        _proc_gnusparse_01 = _proc_sparse
        _proc_gnusparse_10 = _proc_sparse
    return Info,state


def tar_end(archive,state):
    total = 0
    while block := archive.fileobj.read(65536):
        total += len(block);need(not any(block) and total <= 16*MIB, 'zero-only bounded tar tail')
    need(state['ended'] and total >= 512 and archive.fileobj.tell()%512 == 0, 'complete tar termination required')


def export_data(original,output):
    need(not output.exists(), 'fresh flat export DATA required');output.mkdir(mode=0o700)
    info,state = tar_info(256);seen = set();total = 0
    with tarfile.open(original,'r|',tarinfo=info) as archive:
        for item in archive:
            need(not item.sparse and not any(k.startswith('GNU.sparse') for k in item.pax_headers), 'sparse export refused')
            name = item.name.removeprefix('./').rstrip('/')
            if item.isdir():need(name == 'output', 'only flat export root allowed');continue
            safe_name(name);parts = name.split('/')
            need(len(parts) == 2 and parts[0] == 'output' and item.isfile() and name not in seen, 'flat regular unique export DATA')
            seen.add(name);total += item.size
            need(len(seen) <= 64 and 0 <= item.size <= (2*GIB if name.endswith('.pkg.tar.zst') else 64*MIB) and total <= 4*GIB, 'export byte/member bound')
            with archive.extractfile(item) as source,(output/parts[1]).open('xb') as dest:
                while block := source.read(MIB):need_time();dest.write(block)
            (output/parts[1]).chmod(0o400);archive.members.clear()
        tar_end(archive,state)


def package_data(package,temporary):
    need(sys.version_info >= (3,14), 'Python >=3.14 stdlib zstd required; no subprocess fallback')
    import compression.zstd
    rows = {};elfs = {};metadata = {};total = 0
    info,state = tar_info(400000)
    with compression.zstd.ZstdFile(package,'rb') as source,tarfile.open(fileobj=source,mode='r|',tarinfo=info) as archive:
        for item in archive:
            need(not item.sparse and not any(k.startswith('GNU.sparse') for k in item.pax_headers), 'sparse package refused')
            name = item.name.removeprefix('./').rstrip('/')
            if name in ('','.'):continue
            safe_name(name);need(name not in rows and len(rows) < 200000, 'unique finite package namespace')
            row = {'mode':item.mode & 0o777}
            need(not item.mode & 0o7000, 'setid/sticky package payload refused')
            if item.isdir():row['kind'] = 'dir'
            elif item.issym():row.update(kind='link',target=item.linkname)
            else:
                need(item.isfile() and 0 <= item.size <= 2*GIB, 'bounded regular package payload')
                total += item.size;need(total <= 16*GIB, 'package logical-byte bound')
                stream = archive.extractfile(item);first = stream.read(min(64,item.size));h = hashlib.sha256(first);size = len(first)
                with tempfile.TemporaryFile(dir=temporary) as spool:
                    selected = first[:4] == b'\x7fELF'
                    if selected:spool.write(first)
                    body = bytearray(first) if name in ('.PKGINFO','.BUILDINFO') else None
                    while block := stream.read(MIB):
                        need_time();h.update(block);size += len(block);need(size <= item.size, 'package payload size drift')
                        if selected:spool.write(block)
                        if body is not None:need(len(body)+len(block) <= 4*MIB, 'package metadata bound');body.extend(block)
                    need(size == item.size, 'truncated package payload')
                    if selected:spool.seek(0);elfs[name] = elf(spool,size,name)
                    if body is not None:metadata[name] = bytes(body)
                if name.endswith(('/libunwind.a','/libclang_rt.builtins-aarch64.a','/libclang_rt.profile-aarch64.a')):
                    need(first[:8] == b'!<arch>\n', 'required static runtime archive header')
                row.update(kind='file',bytes=size,sha256=h.hexdigest())
            rows[name] = row;archive.members.clear()
        tar_end(archive,state)
    prefix = PREFIX.lstrip('/')
    for name,row in rows.items():
        need(name in ('.PKGINFO','.BUILDINFO','.MTREE') or name == prefix or name.startswith(prefix+'/') or row['kind'] == 'dir' and prefix.startswith(name+'/'), 'package ownership escaped private prefix')
        if row['kind'] == 'link':
            target = row['target'];need(not target.startswith('/'), 'absolute package symlink refused')
            destination = posixpath.normpath(posixpath.join(posixpath.dirname(name),target))
            need(destination.startswith(prefix+'/') and destination in rows, 'escaping/broken package symlink')
    def resolved(name):
        seen = set()
        while rows.get(name,{}).get('kind') == 'link':
            need(name not in seen and len(seen) < 16, 'package symlink cycle/bound');seen.add(name)
            name = posixpath.normpath(posixpath.join(posixpath.dirname(name),rows[name]['target']))
        return name
    for name,row in rows.items():
        if row['kind'] == 'link':need(rows[resolved(name)]['kind'] in ('dir','file'), 'all package symlinks terminate')
    for tool in ('llvm-config','clang','clang++','ld.lld','llvm-ar','llvm-ranlib'):
        name = resolved(prefix+'/bin/'+tool)
        need(name in elfs and elfs[name]['kind'] in (2,3) and rows[name]['mode'] & 0o111, 'required native tool ELF absent: '+tool)
    need(any(name.startswith(prefix+'/lib/') and data['kind'] == 3 and data['soname'] and data['soname'].startswith('libLLVM') for name,data in elfs.items()), 'shared LLVM SONAME missing')
    for name in ('lib/libunwind.a','lib/clang/23/lib/linux/libclang_rt.builtins-aarch64.a','lib/clang/23/lib/linux/libclang_rt.profile-aarch64.a'):
        need(rows.get(prefix+'/'+name,{}).get('kind') == 'file', 'required static runtime missing')
    need(any(name.startswith(prefix+'/lib/libunwind.so') and obj['kind'] == 3 for name,obj in elfs.items()), 'shared libunwind ELF missing')
    for name,data in elfs.items():
        for dependency in data['needed']:
            need('/' not in dependency, 'ELF absolute dependency refused')
            if dependency.startswith('libLLVM'):
                target = resolved(prefix+'/lib/'+dependency)
                need(target in elfs and elfs[target]['kind'] == 3 and elfs[target]['soname'] == dependency, 'LLVM dependency must resolve to package-owned matching ELF SONAME')
    return rows,elfs,metadata


def tuple_join(value,a,map_sha):
    for key in ('source','ref','run','job','approval'):
        need(value[key] == a[key], 'same Root '+key+' required')
    need(value['source_map_sha256'] == map_sha, 'same Root source map required')


def commands(data,source):
    for name,maximum in [('probe',60),('tools',10800),('runtimes',1800),('check',600),('makepkg',13800),('pkginfo',60),('buildinfo',60),('tool-owners',30),('packages-unsorted',30)]:
        row = load(data/(name+'.json'));natural(row['lifecycle'])
        need(row['success'] is True and row['returncode'] == row['lifecycle']['exit'] == 0 and 0 < row['timeout_seconds'] <= row['requested_seconds'] == maximum, 'complete bounded command required')
        need(safe_name(row['log']) == name+'.log' and hashed(data/row['log']) == row['log_pin'], 'whole command log join')
        if name in ('probe','tools','runtimes','check'):
            need(row['argv'] == ['/usr/bin/bash','/inputs/packages/port/llvm23-source-reference/build.sh',name], 'exact private Source build command')
        elif name == 'makepkg':need(row['argv'] == ['/usr/bin/makepkg','--config','/work/makepkg.conf','--cleanbuild','--nosign','--noconfirm','--log'], 'ordinary dependency-checked makepkg command')
    for filename,expected in [('tools-CMakeCache.txt',{'CMAKE_INSTALL_PREFIX':PREFIX,'CMAKE_C_COMPILER':'/usr/bin/gcc','CMAKE_CXX_COMPILER':'/usr/bin/g++','LLVM_TARGETS_TO_BUILD':'AArch64','LLVM_ENABLE_PROJECTS':'clang;lld','LLVM_BUILD_LLVM_DYLIB':'ON','LLVM_LINK_LLVM_DYLIB':'ON'}),('runtimes-CMakeCache.txt',{'CMAKE_INSTALL_PREFIX':PREFIX,'CMAKE_C_COMPILER':PREFIX+'/bin/clang','CMAKE_CXX_COMPILER':PREFIX+'/bin/clang++','LLVM_ENABLE_RUNTIMES':'compiler-rt;libunwind','LIBUNWIND_INSTALL_LIBRARY_DIR':'lib','COMPILER_RT_BUILD_PROFILE':'ON'})]:
        cache = {}
        for line in read(data/filename).decode().splitlines():
            match = re.fullmatch('([^:#=]+):[^=]+=(.*)',line)
            if match:cache[match[1]] = match[2]
        need(all(cache.get(k) == v for k,v in expected.items()), 'actual CMake cache differs: '+filename)
        for kind in ('EXE','SHARED','MODULE'):need('-z,max-page-size=16384' in cache.get('CMAKE_'+kind+'_LINKER_FLAGS',''), 'actual 16K linker flags missing')
    lock = read(source/'expected349.lock');baseline = dict(line.split(' ',1) for line in lock.decode().splitlines())
    need(len(baseline) == 349 and read(data/'packages.txt') == lock, 'complete actual349 inventory differs')
    tools = load(data/'tools.json')['tools'];names = ('bash','uname','grep','gcc','g++','gcc-ar','gcc-ranlib','ld','as','cmake','ninja','python','bsdtar','make','perl','pkg-config','fakeroot','pacman','zstd','env','sort','cp','timeout')
    need([row['name'] for row in tools] == list(names), 'complete native bootstrap tool set')
    owners = read(data/'tool-owners.log').decode().splitlines();need(len(owners) == len(tools), 'complete ALPM tool ownership')
    for row,owner in zip(tools,owners):
        need(row['owner'] == owner and row['owner_version'] == baseline[owner] and row['path'] == '/usr/bin/'+row['name'] and row['resolved'].startswith('/usr/') and digest(row['sha256']) and 0 < row['bytes'] <= 256*MIB and row['mode'] & 0o111, 'actual native tool bytes/ALPM ownership binding')
        current = row['path']
        need(len(row['links']) <= 8, 'tool link bound')
        for link in row['links']:
            need(link['path'] == current, 'tool link chain discontinuity')
            current = posixpath.normpath(link['target'] if link['target'].startswith('/') else posixpath.join(posixpath.dirname(current),link['target']))
            need(current.startswith('/usr/'), 'tool link escapes qualified usr')
        need(current == row['resolved'], 'tool resolved path mismatch')

    expected_commands = {
        'packages-unsorted':['/usr/bin/pacman','-Q'],
        'tool-owners':['/usr/bin/pacman','-Qqo','--',*['/usr/bin/'+n for n in names]],
        'pkginfo':['/usr/bin/bsdtar','-xOf','/work/output/cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst','.PKGINFO'],
        'buildinfo':['/usr/bin/bsdtar','-xOf','/work/output/cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst','.BUILDINFO']}
    for name,argv in expected_commands.items():
        need(load(data/(name+'.json'))['argv'] == argv, 'exact native ownership/package inspection command')


def retirement(evidence,producer,image):
    rows = load(evidence/'bootstrap/operations.json');need(type(rows) is list and 0 < len(rows) <= 4096, 'complete bounded hosted operation list')
    docker = ['/usr/bin/docker','--host=unix:///var/run/docker.sock']
    for row in rows:
        natural(row['lifecycle']);need(row['returncode'] == row['lifecycle']['exit'], 'host command natural exit mismatch')
        for channel in ('stdout','stderr'):
            safe_name(row[channel]);need(hashed(evidence/row[channel],16*MIB) == row[channel+'_pin'], 'complete raw host command output')
    def last(argv):
        candidates = [row for row in rows if row['argv'] == docker+argv]
        need(candidates, 'actual retirement/absence command missing');return candidates[-1]
    for owned in (producer['actor'],producer['init']):
        removal = last(['rm','-f',owned]);need(removal['returncode'] == 0, 'owned container removal failed')
    volume_removal = last(['volume','rm',producer['volume']]);need(volume_removal['returncode'] == 0, 'owned volume removal failed')
    for argv,absent in [(['container','ls','--all','--format','{{.Names}}'],{producer['actor'],producer['init']}),(['volume','ls','--quiet'],{producer['volume']})]:
        row = last(argv)
        removals = [last(['volume','rm',producer['volume']])] if argv[0] == 'volume' else [last(['rm','-f',owned]) for owned in absent]
        need(all(rows.index(row) > rows.index(removal) for removal in removals), 'resource absence preceded retirement')
        need(row['returncode'] == 0 and not absent & set(read(evidence/row['stdout']).decode().splitlines()), 'actual owned resources remain or absence failed')
    removal = last(['image','rm',image]);need(removal['returncode'] == 0, 'owned image removal failed')
    row = last(['image','inspect',image]);need(rows.index(row) > rows.index(removal), 'image absence preceded retirement')
    need(row['returncode'] == 1 and not read(evidence/row['stdout']).strip() and read(evidence/row['stderr']).decode().strip() == 'Error response from daemon: No such image: '+image, 'actual exact image absence unproven')
    natural(producer['export']['lifecycle'])
    need(producer['export']['lifecycle'] == producer['export_lifecycle'] and producer['export']['lifecycle']['exit'] == 0, 'natural complete export retirement')


def daemon(evidence):
    row = load(evidence/'daemon.json');info,host,version = row['info'],row['host'],row['version']['Server']
    need(host['system'] == 'Linux' and host['machine'] == 'aarch64' and host['uid'] == host['gid'] == 1001 and version['Os'] == info['OSType'] == 'linux' and version['Arch'] in ('arm64','aarch64') and info['Architecture'] in ('arm64','aarch64'), 'actual native host and daemon required')
    need(info['CgroupVersion'] == '2' and all(info.get(k) is True for k in ('CpuCfsQuota','MemoryLimit','SwapLimit','PidsLimit')) and not any('rootless' in x or 'userns' in x for x in info['SecurityOptions']), 'actual Rootful cgroup enforcement differs')
    need(row['socket']['path'] == '/var/run/docker.sock' and row['socket']['uid'] == 0 and row['socket']['socket'] is True and row['socket']['stable'] is True, 'actual stable Root-owned daemon identity')
    delta = load(evidence/'bootstrap/private-prefix-delta.json')
    expected = '\nUSER root\nRUN mkdir -p /opt/cachy-asahi && ln -s /work/dest/opt/cachy-asahi/llvm23-source-reference /opt/cachy-asahi/llvm23-source-reference\nUSER alarm\nWORKDIR /tmp\n'
    need(delta['append'] == expected and delta['package_additions'] == [] and digest(delta['before']['sha256']) and digest(delta['after']['sha256']) and delta['after']['bytes'] == delta['before']['bytes']+len(expected), 'exact private-prefix-only bootstrap delta')


def signatures(evidence,admission,actual,map_sha,source):
    need(hashed(evidence/'bootstrap/packages.lock')['sha256'] == '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453', 'signed349 bootstrap lock differs')
    inputs = load(evidence/'bootstrap/inputs.lock.json')
    original = load(source/'original/bootstrap/scripts/ci/inputs.lock.json')
    additions = load(source/'original/native/input-profile.json')['additions']['rows']
    need(inputs == dict(original,packages=original['packages']+additions), 'complete Source-bound original248 plus fixed8 input derivation')
    rows = load(evidence/'bootstrap/signatures.json')
    need(set(rows) == {inputs['rootfs']['filename']} | {row['filename'] for row in inputs['packages']}, 'complete signed payload filename membership')
    need(len(rows) == 257 and hashed(evidence/'bootstrap/signatures.json')['sha256'] == admission['input_signature_audit_sha256'], 'complete signed input observation join')
    signer = '68B3537F39A313B3E574D06777193F152BDBE6A6'
    for name,row in rows.items():
        need(row['command'][-3] == '--verify' and PurePosixPath(row['command'][-2]).name == name+'.sig' and PurePosixPath(row['command'][-1]).name == name, 'actual same-payload signature command')
        lines = [line.split() for line in row['status'].splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        need(row['exit_code'] == 0 and len(lines) == 1 and signer in (lines[0][2],lines[0][-1]) and not any(word in row['status'] for word in ('BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG')), 'approved input signer/exit observation differs')
    proof = load(evidence/'bootstrap/proof.json')
    need(proof['status'] == 'PASS_FRESH_SIGNED349_BOOTSTRAP' and proof['image'] == admission['image'], 'same signed349 bootstrap proof')
    tuple_join(proof['binding'],actual,map_sha)
    image = load(evidence/'bootstrap/image-inspect.json')
    token = hashlib.sha256((actual['source']+':'+actual['ref']+':'+actual['run']).encode()).hexdigest()[:24]
    need(image['Id'] == actual['image'] and image['Architecture'] == 'arm64' and image['Os'] == 'linux' and image['Config']['Labels']['cachy-asahi.hosted-llvm23'] == token and image['Config']['Labels']['cachy-asahi.hosted-llvm23.source'] == actual['source'] and image['RepoTags'] == ['llvm23-native-base:'+token], 'actual owned native bootstrap image inspection differs')
    for name,key in [('inputs.lock.json','inputs_sha256'),('acquisition.json','acquisition_sha256'),('signatures.json','signatures_sha256'),('image-inspect.json','image_inspect_sha256'),('input-data-preparation.json','preparation_sha256'),('fixed-eight-cache.json','cache_additions_sha256')]:
        need(hashed(evidence/'bootstrap'/name)['sha256'] == proof[key], 'complete bootstrap material proof differs')


def stage_join(data,inventory,source,admission):
    staged = load(data/'staged-tree.json')['files']
    built,checked,prepared = (load(data/(name+'.json')) for name in ('built','checked','prepared'))
    need(built == checked and all(built[k] == v for k,v in prepared.items()) and prepared == {'admission_sha256':hashed(data/'admission.json')['sha256'],'source_tree_sha256':admission['source_tree_sha256']}, 'prepare/build/check stage receipt continuity')
    groups = {}
    for name,row in staged.items():
        safe_name(name);need(inventory.get(name) == row, 'package differs from checked staged payload')
        groups.setdefault(posixpath.dirname(name),[]).append((name,row))
    h = hashlib.sha256()
    def walk(parent):
        rows = sorted(groups.get(parent,[]))
        for name,row in rows:
            content = row.get('sha256','') if row['kind'] == 'file' else row.get('target','')
            h.update((json.dumps([name,row['kind'],row['mode'],content],separators=(',',':'))+'\n').encode())
        for name,row in rows:
            if row['kind'] == 'dir':walk(name)
    walk('')
    need(h.hexdigest() == built['staged_tree_sha256'], 'independent checked-stage inventory hash')
    base = PREFIX.lstrip('/')+'/share/licenses/llvm23-source-reference/'
    inputs = load(source/'packages/port/llvm23-source-reference/inputs.json')
    expected = {base+component+'-LICENSE.TXT':checksum for component,checksum in inputs['notices'].items()}
    for name in ('LICENSE.packaging','inputs.json','build.sh'):
        expected[base+name] = hashed(source/'packages/port/llvm23-source-reference'/name)['sha256']
    for name,checksum in expected.items():
        need(inventory.get(name,{}).get('sha256') == checksum, 'exact package-owned notice/provenance missing')
    for name,row in inventory.items():
        if name in staged or name in expected or name in ('.PKGINFO','.BUILDINFO','.MTREE'):continue
        need(row['kind'] == 'dir' and any(n.startswith(name+'/') for n in expected), 'unexplained payload added after checked stage')


def replay(b,source,evidence,temporary):
    """Only called in a future externally Root-bound operational Reader."""
    a = b['actual'];h = load(evidence/'hosted.json');producer = load(evidence/'llvm-build/producer.json')
    tuple_join(h['binding'],a,b['source_map_sha256']);tuple_join(producer['binding'],a,b['source_map_sha256'])
    need(h['status'] == 'LLVM23_BUILD_EXPORTED_RETIRED_PENDING_INDEPENDENT_READER' and h['mode'] == 'ROOTFUL_CONTAINER_NO_BWRAP_V1' and h['cleanup']['image_absent'] is True and h['cleanup']['gpg_agent_absent'] is True and h['cleanup']['bootstrap_probe_absent'] is True and not h['cleanup']['errors'], 'hosted success/retirement incomplete')
    need(producer['status'] == 'COMPLETED_EXPORTED_RETIRED' and producer['image'] == a['image'] and producer['actor_completed'] is True and producer['owned_resources_absent'] is True and not producer.get('error') and not producer.get('cleanup_errors'), 'producer incomplete/failed')
    export = evidence/'llvm-build/export.tar';need(hashed(export,4*GIB) == {k:producer['export'][k] for k in ('bytes','sha256')} and hashed(export)['sha256'] == b['export_sha256'], 'whole export binding')
    retirement(evidence,producer,a['image'])
    volume_initialization(evidence,producer,a,load(HERE/'pins.json'))
    daemon(evidence)
    data = temporary/'actor-data';export_data(export,data)
    result = load(data/'actor-result.json')
    need(result['status'] == 'PASS_LLVM23_ACTOR_DATA' and result['native_acceptance'] is False and result['mode'] == 'ROOTFUL_CONTAINER_NO_BWRAP_V1' and result['source'] == {'sha':a['source'],'ref':a['ref'].removeprefix('refs/heads/')} and all(result[k] == a[k] for k in ('run','job','image')), 'actual actor tuple/result')
    need(set(p.name for p in data.iterdir()) == set(result['output_files'])|{'actor-result.json'}, 'complete actor output membership')
    for name,row in result['output_files'].items():
        need('/' not in safe_name(name) and hashed(data/name) == {k:row[k] for k in ('bytes','sha256')}, 'whole actor output content')
    observed = load(data/'runtime.json');runtime(observed)
    need(observed['admission_sha256'] == result['admission_sha256'] == producer['admission_sha256'] == hashed(data/'admission.json')['sha256'], 'actor admission content join')
    admission = load(data/'admission.json');contract = load(source/'contract.json');source_input = load(data/'source-input.json')
    need(admission['operation'] == 'llvm23-source-reference-native-v1' and admission['mode'] == 'ROOTFUL_CONTAINER_NO_BWRAP_V1' and admission['holds_preserved'] is True and admission['source'] == result['source'] and all(admission[k] == a[k] for k in ('run','job','approval','image')) and admission['source_map_sha256'] == b['source_map_sha256'] and admission['contract_sha256'] == hashed(source/'contract.json')['sha256'], 'same actual actor Source/policy/approval')
    for key in ('candidate_files','actor_files','owned_child'):
        need(source_input[key] == contract[key], 'actual source/helper inputs differ')
    need(source_input['archive'] == contract['source'] and source_input['source_tree_sha256'] == admission['source_tree_sha256'], 'actual archive/extracted source join')
    acquisition = load(evidence/'llvm-material/acquisition.json')
    need(acquisition['status'] == 'EXACT_ARCHIVE_AND_SOURCE_DATA_RETAINED' and {k:acquisition[k] for k in ('bytes','sha256')} == contract['source'] and 1 <= len(acquisition['requests']) <= 4 and acquisition['body_bytes'] == acquisition['bytes'] and 0 <= acquisition['elapsed_seconds'] <= 600, 'bounded authenticated source intake observation')
    signatures(evidence,admission,a,b['source_map_sha256'],source)
    actor_inspect(load(evidence/'llvm-build/actor-inspect.json'),load(evidence/'llvm-build/actor-finished.json'),producer,a['image'])
    commands(data,source)
    package = data/'cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst'
    need(hashed(package,2*GIB) == result['package'] and result['package']['sha256'] == b['package_sha256'], 'whole package Root/output binding')
    inventory,elfs,metadata = package_data(package,temporary)
    need(inventory == load(data/'packaged-tree.json')['files'], 'whole package ownership/path/mode/content differs from staged provenance')
    stage_join(data,inventory,source,admission)
    for member,exported in (('.PKGINFO','PKGINFO'),('.BUILDINFO','BUILDINFO')):
        need(metadata[member] == read(data/exported,4*MIB), 'package metadata byte equality')
    pkg = metadata['.PKGINFO'].decode().splitlines()
    need(all(s in pkg for s in ('pkgname = cachy-asahi-llvm23-source-reference','pkgver = 23.1.1-1','arch = aarch64')) and not any(s.startswith(('provides =','replaces =','conflict =','install =')) for s in pkg), 'private package identity/providers')
    need({s.removeprefix('depend = ') for s in pkg if s.startswith('depend = ')} == {'glibc','libgcc','libstdc++','zlib','zstd'}, 'private package runtime dependency ownership')
    expected = {'installed = '+s.replace(' ','-',1) for s in read(source/'expected349.lock').decode().splitlines()}
    need({s for s in metadata['.BUILDINFO'].decode().splitlines() if s.startswith('installed = ')} == expected, 'complete349 package BUILDINFO')
    original = read(source/'packages/port/llvm23-source-reference/PKGBUILD')
    old = b'  python -I "$startdir/reference.py" "$1" --work "$srcdir" "${@:2}"'
    new = b'  python -I -B /inputs/actor/container_mode.py "$1" --work "$srcdir" "${@:2}"'
    need(original.count(old) == 1 and read(data/'PKGBUILD-original') == original and read(data/'PKGBUILD-effective') == original.replace(old,new), 'whole explicit separate-mode recipe inverse')
    need('pkgbuild_sha256sum = '+hashlib.sha256(original.replace(old,new)).hexdigest() in metadata['.BUILDINFO'].decode().splitlines(), 'actual BUILDINFO/effective recipe byte join')
    # Source readback is joined to independently replayed Git blob identities by main.
    return {'package':result['package'],'payload_entries':len(inventory),'elf_objects':len(elfs),'runtime_domain':'ROOTFUL_CONTAINER_NO_BWRAP_V1','observed_native_page_bytes':4096}


def main():
    global END
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binding','source','parent-source','original','provider','approval','source-commit','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--binding-sha256',required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS,(256*MIB,256*MIB));resource.setrlimit(resource.RLIMIT_CORE,(0,0));END = time.monotonic()+1800
    need(sys.flags.isolated and not sys.flags.optimize, 'python -I without optimization required')
    binding_path = path(args.binding);need(hashed(binding_path)['sha256'] == args.binding_sha256, 'external Root binding digest differs')
    b = load(binding_path);pins = load(HERE/'pins.json');check_binding(b,pins)
    need(hashed(HERE/'reader.py')['sha256'] == b['reader_sha256'] and hashed(HERE/'pins.json')['sha256'] == b['pins_sha256'], 'Root selected Reader code/pins differ')
    source = path(args.source);output = path(args.output)
    need(output.parent.stat().st_uid == os.geteuid() and not output.parent.stat().st_mode & 0o022, 'owned private Reader parent required')
    need(not output.exists() and output.parent.is_dir() and source not in output.parents and output not in source.parents and output != source, 'fresh separate ordinary Reader output required')
    space = os.statvfs(output.parent);need(space.f_bavail*space.f_frsize >= 20*GIB and space.f_favail >= 10000, 'Reader DATA disk/inode reserve unavailable')
    need(hashed(args.original) == b['original_archive'] and hashed(args.provider)['sha256'] == b['provider_sha256'] and hashed(args.approval)['sha256'] == b['actual']['approval'] and hashed(args.source_commit)['sha256'] == b['source_commit_sha256'], 'external whole archive/provider/approval/commit inputs differ')
    approval = load(args.approval);a = b['actual']
    need(approval['status'] == 'ROOT_ADMITTED_SINGLE_NATIVE_LLVM23_ATTEMPT' and approval['authority'] == a['authority'] and approval['source_reviewed'] is True and approval['holds_preserved'] is True and approval['operation'] == pins['operation'] and approval['source'] == a['source'] and approval['ref'] == a['ref'] and approval['source_map_sha256'] == pins['source_map_sha256'] and approval['resources'] == pins['policy'], 'exact external Root Source/policy admission')
    provider = load(args.provider);run,job,artifact = provider['run'],provider['job'],provider['artifact']
    need(str(run['id']) == a['run'] and run['run_attempt'] == 1 and run['event'] == 'workflow_dispatch' and run['head_sha'] == a['source'] and run['head_branch'] == a['ref'].removeprefix('refs/heads/') and run['repository']['full_name'] == 'Gabriel-Kahen/cachy-asahi' and run['status'] == 'completed' and run['conclusion'] == 'success', 'externally authenticated completed run differs')
    need(str(job['id']) == a['job'] and str(job['run_id']) == a['run'] and job['head_sha'] == a['source'] and job['name'] == 'llvm23-native-v2' and job['status'] == 'completed' and job['conclusion'] == 'success', 'actual completed job differs')
    need(str(artifact['id']) == a['artifact'] and artifact['expired'] is False and artifact['name'] == 'llvm23-native-v2-'+a['run']+'-1' and str(artifact['workflow_run']['id']) == a['run'] and artifact['workflow_run']['head_sha'] == a['source'], 'actual original artifact identity differs')
    commit = read(args.source_commit,MIB);need([line for line in commit.split(b'\n\n',1)[0].splitlines() if line.startswith(b'parent ')] == [('parent '+pins['parent']['source']).encode()], 'exact sole v1 parent')
    blobs = source_tree(source,pins,commit,a['source']);source_successor(source,path(args.parent_source),pins,blobs)
    output.mkdir(mode=0o700)
    # Only a terminal report can claim parity; any exception leaves no PASS file.
    evidence = output/'full-original';full_zip(args.original,evidence,b['full_original_decode'])
    readback = load(evidence/'source-readback.json')
    need(readback['status'] == 'PASS_EXACT_HOSTED_SOURCE_READBACK' and readback['files'] == blobs, 'actual full Source Git readback differs')
    need(all(readback['binding'][k] == a[k] for k in ('source','ref','run','approval')) and readback['binding']['source_map_sha256'] == b['source_map_sha256'], 'actual Source readback tuple')
    result = replay(b,source,evidence,output)
    report = dict(schema=1,status='PASS_INDEPENDENT_ROOT_BOUND_LLVM23_DATA_ONLY',binding_sha256=args.binding_sha256,actual=a,full_original_decode=b['full_original_decode'],source_tree=pins['source_tree'],**result,native_acceptance=False,holds='original4/source108/native16K/M2/performance/release remain held',scope='Offline Root-authenticated observations, full Original decode, independent ELF/package DATA checks; not independent-machine execution or release admission')
    (output/'reader.json').write_bytes(canonical(report))
    print(json.dumps(report,sort_keys=True))


if __name__ == '__main__':
    try:main()
    except (ValueError,KeyError,TypeError,OSError,MemoryError,struct.error,zipfile.BadZipFile,tarfile.TarError) as error:
        print('REFUSED: '+str(error),file=sys.stderr);sys.exit(2)
