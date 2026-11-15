# SPDX-License-Identifier: MIT
"""Bounded stage0 DATA verification/assembly primitives; no runtime or authority.

Root owns admission and invocation. Import and verify_specs do not extract files.
assemble writes only a fresh private prefix, never invokes an installer or tool.
"""
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time

MIB = 1024**2
CHUNK = 65536
MAX_ARCHIVE = 128*MIB
MAX_LOGICAL = 1024*MIB
MAX_FILE = 256*MIB
MAX_NODES = 2048


def need(ok, why):
    if not ok:
        raise ValueError(why)


def name(value):
    need(type(value) is str and value and not value.startswith('/') and '\\' not in value and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'literal contained name required')
    while value.startswith('./'):
        value = value[2:]
    clean = value.rstrip('/')
    need(clean and all(p not in ('','.','..') for p in clean.split('/')), 'escaping or ambiguous name refused')
    return clean


def ordinary(value):
    p = Path(value)
    need(p.is_absolute() and '..' not in p.parts and not any(x.is_symlink() for x in (p,*p.parents)), 'ordinary absolute path required')
    return p


def identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def regular(path, cap):
    p = ordinary(path)
    fd = os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap, 'bounded single-link regular DATA required')
        return os.fdopen(fd,'rb'),before
    except BaseException:
        os.close(fd)
        raise


def pin(path, cap=MAX_ARCHIVE):
    source,before = regular(path,cap)
    with source:
        h = hashlib.sha256()
        while block := source.read(CHUNK):h.update(block)
        need(identity(before) == identity(os.fstat(source.fileno())) == identity(Path(path).lstat()), 'DATA changed while hashed')
    return {'bytes':before.st_size,'sha256':h.hexdigest()}


def load(path):
    source,before = regular(path,4*MIB)
    with source:
        raw = source.read(4*MIB+1)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(source.fileno())) == identity(Path(path).lstat()), 'metadata changed while read')
    def pairs(rows):
        out = {}
        for k,v in rows:need(k not in out,'duplicate JSON key');out[k] = v
        return out
    def bad(_):raise ValueError('nonfinite JSON refused')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=bad)


def checksum(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def tree_digest(nodes):
    """Same ordered path/kind/mode/content model as the retained join.py."""
    children = {}
    for path,row in nodes.items():
        need(name(path) == path and row['kind'] in ('file','dir'), 'invalid prefix node')
        parent = PurePosixPath(path).parent.as_posix()
        need(parent == '.' or nodes.get(parent,{}).get('kind') == 'dir', 'missing prefix directory parent')
        children.setdefault(parent,[]).append(path)
    h = hashlib.sha256()
    def visit(parent):
        selected = sorted(children.get(parent,[]))
        for path in selected:
            row = nodes[path]
            h.update((json.dumps([path,row['kind'],row['mode'],row['content']],separators=(',',':'))+'\n').encode())
        for path in selected:
            if nodes[path]['kind'] == 'dir':visit(path)
    visit('.')
    return h.hexdigest()


def tree_inventory(root):
    root = ordinary(root)
    need(root.is_dir(), 'real prefix directory required')
    rows = {}
    for current,dirs,files in os.walk(root,followlinks=False):
        for leaf in sorted(dirs+files):
            p = Path(current)/leaf;info = p.lstat();relative = p.relative_to(root).as_posix()
            need(not p.is_symlink() and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)), 'nonordinary assembled prefix node')
            rows[relative] = {'kind':'dir' if stat.S_ISDIR(info.st_mode) else 'file','mode':stat.S_IMODE(info.st_mode),'content':'' if stat.S_ISDIR(info.st_mode) else pin(p,MAX_FILE)['sha256']}
            need(len(rows) <= MAX_NODES, 'assembled prefix node bound')
    return rows


def verify_specs(data_root, spec):
    """Read/join small pinned metadata; does not read/extract source archives.

    Return archives[name]={pin,inventory,elfs}, model, notices and summary.
    Metadata authenticity and exact source/spec pinning remain Root premises.
    """
    data_root = ordinary(data_root)
    need(data_root.is_dir() and type(spec['archives']) is dict and len(spec['archives']) == 3, 'three finite stage0 archive declarations required')
    plans,model,notice_sources,elfs = {},{},{},{}
    components = set();file_bytes = 0;elf_count = 0
    for archive,p in spec['archives'].items():
        need(name(archive) == archive and '/' not in archive and archive.endswith('.tar.xz') and checksum(p['sha256']) and type(p['bytes']) is int and 0 < p['bytes'] <= MAX_ARCHIVE, 'bounded local archive identity required')
        root,component = name(p['root']),name(p['component'])
        need('/' not in root and '/' not in component and component not in components, 'unique literal archive root/component required');components.add(component)
        relative = name(p['inventory']);need(relative.startswith('records/') and relative.endswith('.inventory.json'), 'reviewed inventory path required')
        records = load(data_root/relative)
        need(type(records) is list and 1 <= len(records) <= 1024, 'finite complete inventory required')
        indexed = {};prefix = root+'/'+component+'/'
        for row in records:
            member = name(row['path']);kind = row['kind'];mode = row['mode']
            need(member == row['path'] and (member == root or member.startswith(root+'/')) and member not in indexed, 'unique complete pinned-root inventory required')
            need(kind in ('file','dir') and type(mode) is int and mode in (0o644,0o755) and (kind != 'dir' or mode == 0o755), 'only reviewed regular/directory modes supported')
            need(type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_FILE and (kind != 'dir' or row['bytes'] == 0) and (kind != 'file' or checksum(row['sha256'])), 'bounded complete file identity required')
            indexed[member] = row
            if row.get('retained_data_path','').startswith('records/notices/'):
                key = name(row['retained_data_path'])
                need(key not in notice_sources or notice_sources[key] == {'bytes':row['bytes'],'sha256':row['sha256']}, 'conflicting retained notice identity')
                notice_sources[key] = {'bytes':row['bytes'],'sha256':row['sha256']}
            if not member.startswith(prefix):continue
            target = member[len(prefix):]
            if target == 'manifest.in':
                need(kind == 'file', 'component manifest must be regular');continue
            node = {'kind':kind,'mode':mode,'content':row.get('sha256','')}
            need(target not in model or model[target] == node, 'nonidentical component collision')
            if target not in model and kind == 'file':file_bytes += row['bytes']
            model[target] = node
        need(indexed.get(root,{}).get('kind') == indexed.get(root+'/'+component,{}).get('kind') == 'dir' and prefix+'manifest.in' in indexed, 'observed component layout/manifest missing')
        for member,row in indexed.items():
            parent = PurePosixPath(member).parent.as_posix()
            need(member == root or indexed.get(parent,{}).get('kind') == 'dir', 'complete archive directory ancestry required')
        facts = load(data_root/(relative.removesuffix('.inventory.json')+'.elf.json'))
        need(type(facts) is dict and len(facts) <= 14, 'finite ELF facts required')
        elf_count += len(facts)
        for member,fact in facts.items():
            need(member in indexed and indexed[member]['kind'] == 'file' and member.startswith(prefix) and member != prefix+'manifest.in', 'ELF fact does not join reviewed component file')
            need(fact['elf_class'] == 64 and fact['endianness'] == 'little' and fact['machine'] == 183 and fact['type'] in (2,3) and fact['load_segments_16k_congruence_and_alignment'] is True, 'AArch64 16K static ELF facts required')
            headers = fact['program_headers'];need(type(headers) is list and 1 <= len(headers) <= 128, 'bounded ELF program headers required')
            loads = [h for h in headers if h['type'] == 1]
            need(loads and all(h['align'] >= 16384 and h['offset']%16384 == h['vaddr']%16384 for h in loads), 'static ELF16K geometry mismatch')
            need(all(0 <= h['offset'] <= h['offset']+h['filesz'] <= indexed[member]['bytes'] and 0 <= h['filesz'] <= h['memsz'] for h in headers), 'ELF segment exceeds reviewed file')
            target = member[len(prefix):]
            need(target not in elfs or elfs[target] == fact, 'conflicting ELF facts for merged component file')
            elfs[target] = fact
        plans[archive] = {'pin':p,'inventory':indexed,'elfs':facts}
    need(components == {'cargo','rustc','rust-std-aarch64-unknown-linux-gnu'} and elf_count == len(elfs) == 14, 'complete three-component/14-ELF join required')
    need(len(model) <= MAX_NODES and file_bytes <= MAX_LOGICAL, 'combined component model resource bound')
    declared = spec['model'];need(name(declared['file']).startswith('records/'), 'reviewed component model required')
    need(load(data_root/declared['file']) == model and tree_digest(model) == declared['tree_sha256'], 'reviewed component model/tree differs')
    summary = {'nodes':len(model),'files':sum(row['kind'] == 'file' for row in model.values()),'file_bytes':file_bytes,'tree_sha256':tree_digest(model),'elf_files':len(elfs),'compatibility':'UNQUALIFIED'}
    need(all(summary[k] == declared[k] for k in ('nodes','files','file_bytes')), 'component model count/byte join differs')
    need(type(spec['notices']) is dict and set(spec['notices']) == set(notice_sources) and len(notice_sources) == 12, 'all twelve retained notice copies required')
    targets = set()
    for source,row in spec['notices'].items():
        target = name(row['target'])
        need(target == row['target'] and target.startswith('share/licenses/retained-stage0/') and target not in targets and target not in model and not any(target.startswith(n+'/') for n,v in model.items() if v['kind'] == 'file'), 'unique separate notice target required')
        need(not any(target.startswith(n+'/') or n.startswith(target+'/') for n in targets) and not any(n.startswith(target+'/') for n in model), 'notice file/ancestor collision')
        targets.add(target)
        need({k:row[k] for k in ('bytes','sha256')} == notice_sources[source] == pin(data_root/source,4*MIB), 'retained notice byte join differs')
    return {'archives':plans,'model':model,'notices':spec['notices'],'summary':summary}


class _XZStream:
    """One XZ stream, 128 MiB decoder cap, bounded output on every call."""
    def __init__(self, source, expected):
        self.source,self.expected = source,expected
        self.decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=128*MIB)
        self.h = hashlib.sha256();self.compressed = self.logical = 0;self.finished = False
    def _read(self):
        block = self.source.read(CHUNK);self.compressed += len(block);self.h.update(block)
        need(self.compressed <= self.expected['bytes'], 'compressed archive byte bound')
        return block
    def _finish(self):
        tail = self.decoder.unused_data;length = len(tail)
        need(not tail.strip(b'\0'), 'extra concatenated XZ stream/trailer refused')
        while block := self._read():
            length += len(block);need(not block.strip(b'\0'), 'extra compressed trailer refused')
        need(length%4 == 0 and self.compressed == self.expected['bytes'] and self.h.hexdigest() == self.expected['sha256'], 'complete compressed archive identity differs')
        self.finished = True
    def read(self, amount):
        need(type(amount) is int and 0 <= amount <= CHUNK, 'bounded XZ read required')
        if not amount or self.finished:return b''
        while True:
            if self.decoder.eof:self._finish();return b''
            raw = self._read() if self.decoder.needs_input else b''
            need(not self.decoder.needs_input or raw, 'truncated XZ archive')
            block = self.decoder.decompress(raw,max_length=amount)
            self.logical += len(block);need(self.logical <= MAX_LOGICAL, 'logical archive byte bound')
            if block:return block


def _tar_info():
    state = {'headers':0,'ended':False}
    class Info(tarfile.TarInfo):
        @classmethod
        def fromtarfile(cls, archive):return cls._fromtarfile(archive)
        @classmethod
        def _fromtarfile(cls, archive, *, dircheck=True):
            raw = archive.fileobj.read(512)
            if raw == bytes(512):state['ended'] = True
            else:
                state['headers'] += 1;need(state['headers'] <= 4096, 'physical tar header bound')
            item = cls._frombuf(raw,archive.encoding,archive.errors,dircheck=dircheck) if hasattr(cls,'_frombuf') else cls.frombuf(raw,archive.encoding,archive.errors)
            item.offset = archive.fileobj.tell()-512
            return item._proc_member(archive)
        def _proc_pax(self, archive):
            need(0 <= self.size <= CHUNK, 'PAX metadata bound');return super()._proc_pax(archive)
        def _proc_gnulong(self, archive):
            need(0 <= self.size <= CHUNK, 'long-name metadata bound');return super()._proc_gnulong(archive)
        def _proc_sparse(self, *args):raise ValueError('sparse archive member refused')
        _proc_gnusparse_00 = _proc_sparse
        _proc_gnusparse_01 = _proc_sparse
        _proc_gnusparse_10 = _proc_sparse
    return Info,state


def _tar_end(archive, state):
    total = 0
    while block := archive.fileobj.read(CHUNK):
        total += len(block);need(not any(block) and total <= MIB, 'extra nonzero/unbounded tar tail refused')
    need(state['ended'] and total >= 512 and archive.fileobj.tell()%512 == 0, 'complete two-block tar termination required')


def _parents(destination, target):
    selected = destination/target
    for parent in reversed(selected.parents):
        if parent == destination or destination in parent.parents:
            if parent.exists():need(parent.is_dir() and not parent.is_symlink(), 'prefix ancestor collision')
            else:parent.mkdir(mode=0o700)
    return selected


def assemble(materials, destination, data_root, spec, *, guard=None):
    """Future Root-only streamed DATA assembly into a fresh absent directory.

    Complete compressed identities and reviewed inventories are checked, including
    all skipped metadata/installers. No automatic cleanup hides a failed attempt.
    Success returns component/full-tree summaries, never runtime qualification.
    """
    last=[0.0]
    def checkpoint(force=False):
        now=time.monotonic()
        if guard is not None and (force or now-last[0]>=.5):guard();last[0]=now
    checkpoint(True)
    materials,destination,data_root = ordinary(materials),ordinary(destination),ordinary(data_root)
    checked = verify_specs(data_root,spec)
    need(materials.is_dir() and not destination.exists() and destination.parent.is_dir(), 'fresh absent private prefix required')
    need(destination.parent.stat().st_uid == os.geteuid() and not destination.parent.stat().st_mode & 0o022 and materials != destination and materials not in destination.parents and destination not in materials.parents and data_root != destination and data_root not in destination.parents and destination not in data_root.parents, 'owned disjoint private prefix parent required')
    # Refuse absent/changed archive bytes before allocating any prefix.
    for archive,plan in checked['archives'].items():
        checkpoint()
        expected = plan['pin'];need(pin(materials/archive) == {k:expected[k] for k in ('bytes','sha256')}, 'exact local archive identity required: '+archive)
    destination.mkdir(mode=0o700);written = {}
    for archive,plan in checked['archives'].items():
        expected,indexed = plan['pin'],plan['inventory'];base = expected['root']+'/'+expected['component']+'/'
        source,before = regular(materials/archive,MAX_ARCHIVE)
        with source:
            reader = _XZStream(source,expected);info,state = _tar_info();seen = set()
            with tarfile.open(fileobj=reader,mode='r|',tarinfo=info,bufsize=CHUNK) as stream:
                for item in stream:
                    checkpoint()
                    member = name(item.name)
                    need(member not in seen and member in indexed and not item.sparse and not any(k.startswith('GNU.sparse') for k in item.pax_headers), 'duplicate/extra/sparse archive member refused')
                    seen.add(member);row = indexed[member]
                    kind = 'dir' if item.isdir() else 'file' if item.isfile() else None
                    need(kind == row['kind'] and item.mode == row['mode'] and item.size == row['bytes'], 'reviewed archive kind/mode/size differs')
                    selected = member.startswith(base) and member != base+'manifest.in'
                    target = member[len(base):] if selected else None
                    node = {'kind':kind,'mode':row['mode'],'content':row.get('sha256','')}
                    if selected:
                        need(target not in written or written[target] == node, 'nonidentical component collision')
                        path = _parents(destination,target)
                        if kind == 'dir':
                            if path.exists():need(path.is_dir() and not path.is_symlink(), 'component directory collision')
                            else:path.mkdir(mode=0o700)
                    if kind == 'file':
                        output = None
                        try:
                            if selected and target not in written:output = path.open('xb')
                            h = hashlib.sha256();size = 0
                            with stream.extractfile(item) as payload:
                                while block := payload.read(CHUNK):
                                    checkpoint()
                                    size += len(block);need(size <= row['bytes'], 'member expanded byte bound');h.update(block)
                                    if output is not None:output.write(block)
                            need(size == row['bytes'] and h.hexdigest() == row['sha256'], 'complete reviewed member checksum differs')
                            if output is not None:os.fchmod(output.fileno(),row['mode'])
                        finally:
                            if output is not None:output.close()
                    if selected:written[target] = node
                    stream.members.clear()
                _tar_end(stream,state)
            need(reader.finished and seen == set(indexed), 'incomplete archive namespace/stream refused')
            need(identity(before) == identity(os.fstat(source.fileno())) == identity((materials/archive).lstat()), 'archive changed during assembly')
    for target,row in checked['model'].items():
        if row['kind'] == 'dir':(destination/target).chmod(row['mode'])
    actual = tree_inventory(destination)
    need(actual == checked['model'] and tree_digest(actual) == spec['model']['tree_sha256'], 'assembled component tree differs from reviewed model')
    for source,row in checked['notices'].items():
        target = _parents(destination,row['target'])
        need(not target.exists(), 'notice target collision')
        raw,before = regular(data_root/source,4*MIB)
        with raw,target.open('xb') as output:
            h = hashlib.sha256();size = 0
            while block := raw.read(CHUNK):h.update(block);size += len(block);output.write(block)
            need(size == row['bytes'] and h.hexdigest() == row['sha256'] and identity(before) == identity(os.fstat(raw.fileno())) == identity((data_root/source).lstat()), 'notice changed during copy')
            os.fchmod(output.fileno(),0o644)
    # Only new notice parents remain at temporary construction mode0700.
    for current,dirs,_ in os.walk(destination,followlinks=False):
        for leaf in dirs:
            p = Path(current)/leaf
            if p.relative_to(destination).as_posix() not in checked['model']:p.chmod(0o755)
    destination.chmod(0o755)
    full = tree_inventory(destination)
    checkpoint(True)
    return {'schema':1,'scope':'PRIVATE_PREFIX_DATA_ASSEMBLY_ONLY','component':checked['summary'],'notice_files':len(checked['notices']),'full_tree_sha256':tree_digest(full),'full_nodes':len(full),'installer_execution':False,'compatibility':'UNQUALIFIED'}
