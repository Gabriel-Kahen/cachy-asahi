#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Static checksum-bound ELF observations; never extract or execute payloads."""
import argparse
from collections import Counter, deque
from contextlib import contextmanager
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import posixpath
import re
import stat
import struct
import tarfile
import time

MIB = 1024**2
ARCHIVE_LIMIT, COMPRESSED_LIMIT = 300000000, 2*1024**3
FILE_LIMIT, DECODED_LIMIT, TOTAL_DECODED = 512*MIB, 1024**3, 8*1024**3
NODE_LIMIT, TOTAL_NODES, JSON_LIMIT = 100000, 500000, 64*MIB
PH_LIMIT, SH_LIMIT, DYNAMIC_LIMIT, STRING_LIMIT = 256, 65534, 4096, 4096
PACKAGE_COUNT = 624
PAYLOAD_SOURCE = 'a7cb3a1c469f88fdb37d17e2414eb283bc53e0ef7211d0723af2b9037fa7689c'
ARTIFACTS = Path(__file__).resolve().parents[2] / 'artifacts'


class Refusal(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise Refusal(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def reference_schema(row, maximum):
    need(type(row) is dict and set(row) == {'path','size','sha256'} and
         type(row['path']) is str and '\0' not in row['path'] and Path(row['path']).is_absolute() and
         type(row['size']) is int and 0 < row['size'] <= maximum and
         type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}', row['sha256']), 'reference-schema')


@contextmanager
def snapshot(row, maximum):
    reference_schema(row, maximum)
    fd = os.open(row['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row['size'], 'reference-file')
        data = stream.read(row['size'] + 1); after = os.fstat(stream.fileno())
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns), 'reference-drift')
        need(len(data) == row['size'] and sha(data) == row['sha256'], 'reference-checksum')
    with io.BytesIO(data) as captured:
        yield captured


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'duplicate-json-key'); value[key] = item
    return value


def load_ref(row):
    with snapshot(row, JSON_LIMIT) as stream:
        return json.loads(stream.read(), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refusal('json-number')))


def normalized(path):
    need(type(path) is str and 0 < len(path) <= 4096 and not re.search('[\x00-\x1f\x7f]', path), 'node-path')
    path = path.removeprefix('./').removesuffix('/')
    need(path and not path.startswith('/') and all(p not in ('','.','..') for p in path.split('/')), 'node-traversal')
    return path


def parse_elf(data):
    """Parse file-backed ELF tables, not a target loader or section/symbol ABI."""
    if data[:4] != b'\x7fELF':
        return None
    need(len(data) >= 16 and data[4] in (1,2) and data[5] in (1,2) and data[6] == 1, 'elf-identification')
    bits = 32 if data[4] == 1 else 64; endian = '<' if data[5] == 1 else '>'
    ehsize, phsize, shsize = (52,32,40) if bits == 32 else (64,56,64)
    need(ehsize <= len(data) <= FILE_LIMIT, 'elf-header-bound')
    fields = struct.unpack_from(endian + ('HHIIIIIHHHHHH' if bits == 32 else 'HHIQQQIHHHHHH'), data, 16)
    kind,machine,version,entry,phoff,shoff,flags,header_size,phent,phnum,shent,shnum,shstr = fields
    need(version == 1 and header_size == ehsize, 'elf-header-size-version')
    need(phnum != 65535 and shstr != 65535 and not (shnum == 0 and shoff), 'elf-extended-numbering-unsupported')
    need(phnum <= PH_LIMIT and shnum <= SH_LIMIT, 'elf-table-count')
    def ranged(offset, size):
        need(0 <= offset <= len(data) and 0 <= size <= len(data)-offset, 'elf-file-range')
        return offset
    if phnum:
        need(phent == phsize and phoff >= ehsize, 'elf-program-table'); ranged(phoff, phnum*phent)
    else:
        need(phoff == 0 and phent in (0,phsize), 'elf-empty-program-table')
    if shnum:
        need(shent == shsize and shoff >= ehsize and shstr < shnum, 'elf-section-table'); ranged(shoff, shnum*shent)
        for index in range(shnum):
            s = struct.unpack_from(endian + ('IIIIIIIIII' if bits == 32 else 'IIQQQQIIQQ'), data, shoff+index*shent)
            if s[1] not in (0,8): ranged(s[4], s[5])  # NULL and NOBITS have no file data.
    else:
        need(shstr == 0 and shent in (0,shsize), 'elf-empty-section-table')
    loads, interps, dynamics = [], [], []
    for index in range(phnum):
        p = struct.unpack_from(endian + ('IIIIIIII' if bits == 32 else 'IIQQQQQQ'), data, phoff+index*phent)
        typ,off,va,pa,filesz,memsz,pflags,align = p if bits == 32 else (p[0],p[2],p[3],p[4],p[5],p[6],p[1],p[7])
        if typ == 0: continue  # PT_NULL's remaining fields are undefined.
        ranged(off, filesz)
        if typ == 1:
            need(filesz <= memsz and va+memsz <= 2**bits and (align in (0,1) or align & (align-1) == 0), 'elf-load-shape')
            need(not loads or va >= loads[-1]['virtual_address'], 'elf-load-order')
            loads.append({'offset':off,'virtual_address':va,'file_bytes':filesz,'memory_bytes':memsz,'flags':pflags,
                          'alignment':align,'declared_alignment_at_least_16384':align >= 16384,
                          'offset_vaddr_congruent_declared_alignment':align <= 1 or off % align == va % align,
                          'offset_vaddr_congruent_mod_16384':off % 16384 == va % 16384})
        elif typ == 3:
            need(1 < filesz <= STRING_LIMIT and len(interps) == 0 and not loads, 'elf-interpreter-shape')
            raw = data[off:off+filesz]
            need(raw[-1] == 0 and 0 not in raw[:-1], 'elf-interpreter-termination')
            text = bytes(raw[:-1]).decode('ascii');need(not re.search('[\x00-\x20\x7f]', text), 'elf-interpreter-string')
            interps.append(text)
        elif typ == 2:
            need(len(dynamics) == 0, 'elf-duplicate-dynamic'); dynamics.append((off,va,filesz,memsz))
    result = {'class':bits,'byte_order':'little' if endian == '<' else 'big','machine':machine,
              'type':kind,'type_form':{1:'relocatable-object',2:'executable',3:'shared-object-or-PIE'}.get(kind,'other'),'osabi':data[7],'abi_version':data[8],'entry':entry,'flags':flags,'interpreter':interps[0] if interps else None,'PT_LOAD':loads,
              'needed':[],'soname':None,'rpath':None,'runpath':None,'dynamic_present':bool(dynamics),
              'classification':'aarch64-loadable-elf' if bits == 64 and endian == '<' and machine == 183 and flags == 0 and data[7] in (0,3) and kind in (2,3) and loads
              else 'relocatable-elf-data' if kind == 1 else 'other-elf-data-or-runtime-scope-unresolved',
              'static_16K_observation':'load-congruence-observed' if loads and all(p['offset_vaddr_congruent_mod_16384'] for p in loads)
              else 'load-congruence-not-observed' if loads else 'no-load-segments',
              'insufficient_declared_16K_alignment':bool(loads) and any(p['alignment'] < 16384 for p in loads),
              'runtime_load_verified':False}
    def mapped_file(address, extent, code):
        need(address+extent <= 2**bits, code+'-overflow')
        mappings = [p['offset']+address-p['virtual_address'] for p in loads if
                    p['virtual_address'] <= address and extent <= p['file_bytes']-(address-p['virtual_address'])]
        need(len(mappings) == 1, code+'-mapping')
        return ranged(mappings[0],extent)
    result['PT_DYNAMIC'] = None
    if dynamics:
        off,address,size,memory = dynamics[0];step = 8 if bits == 32 else 16
        need(size >= step and size % step == 0 and size//step <= DYNAMIC_LIMIT, 'elf-dynamic-bound')
        # The loader uses p_vaddr and p_memsz, not an independent p_offset table.
        # Conservatively require the complete memory table to be file-backed.
        need(memory == size, 'elf-dynamic-memory-extent')
        mapped = mapped_file(address,memory,'elf-dynamic')
        need(mapped == off, 'elf-dynamic-offset-disagreement')
        result['PT_DYNAMIC'] = {'offset':off,'virtual_address':address,'file_bytes':size,
                                'memory_bytes':memory,'file_backed_mapping_verified':True}

        tags, terminated = {}, False
        for index in range(size//step):
            tag,value = struct.unpack_from(endian + ('iI' if bits == 32 else 'qQ'), data, off+index*step)
            if tag == 0: terminated = True;break
            tags.setdefault(tag,[]).append(value)
        need(terminated, 'elf-dynamic-termination')
        result['PT_DYNAMIC']['entries_after_DT_NULL'] = size//step-index-1
        # Entries after DT_NULL are ignored by the format, never provider evidence.
        result['PT_DYNAMIC']['nonzero_entries_after_DT_NULL'] = sum(
            any(struct.unpack_from(endian+('iI' if bits == 32 else 'qQ'),data,off+n*step))
            for n in range(index+1,size//step))
        for tag in (5,10,14,15,29): need(len(tags.get(tag,[])) <= 1, 'elf-duplicate-dynamic-tag')
        strings = {tag:tags[tag] for tag in (1,14,15,29) if tag in tags}
        if strings or 5 in tags or 10 in tags:
            need(5 in tags and 10 in tags and 0 <= tags[10][0] <= FILE_LIMIT and (tags[10][0] > 0 or not strings), 'elf-string-table')
            addr,size = tags[5][0],tags[10][0]
            # d_ptr is a virtual address. Require one unambiguous file-backed mapping.
            start = mapped_file(addr,size,'elf-string-table')
            need(size == 0 or data[start] == data[start+size-1] == 0, 'elf-string-table-boundaries')
            def string(value, allow_empty=False):
                need(value < size, 'elf-string-offset')
                end = data.find(b'\0',start+value,min(start+size,start+value+STRING_LIMIT+1))
                need(end >= 0 and (allow_empty or end > start+value), 'elf-string-termination')
                text = bytes(data[start+value:end]).decode('ascii')
                need(not re.search('[\x00-\x1f\x7f]', text), 'elf-string-control');return text
            result['needed'] = [string(value) for value in tags.get(1,[])]
            for tag,key in ((14,'soname'),(15,'rpath'),(29,'runpath')):
                if tag in tags: result[key] = string(tags[tag][0], allow_empty=tag in (15,29))
    return result


class Counted:
    def __init__(self, stream, budget, deadline):
        self.stream,self.budget,self.decoded,self.started,self.deadline = stream,budget,0,time.monotonic(),deadline
    def read(self, size):
        need(0 <= size <= MIB and time.monotonic() <= min(self.deadline,self.started+300), 'decoded-read-deadline')
        size = min(size, DECODED_LIMIT-self.decoded+1, TOTAL_DECODED-self.budget['decoded']+1)
        need(size >= 0, 'decoded-budget')
        data = self.stream.read(size);self.decoded += len(data);self.budget['decoded'] += len(data)
        need(self.decoded <= DECODED_LIMIT and self.budget['decoded'] <= TOTAL_DECODED, 'decoded-bound')
        need(time.monotonic() <= min(self.deadline,self.started+300), 'decoded-read-deadline');return data


def inspect_archive(row, package, budget, deadline):
    expected = {node['path']:node for node in package['nodes']}
    expected.update(package['controls']);seen,objects = set(),[]
    with snapshot(row['archive'],ARCHIVE_LIMIT) as raw, lzma.LZMAFile(raw) as decoded:
        counted = Counted(decoded,budget,deadline)
        with tarfile.open(fileobj=counted,mode='r|') as archive:
            for member in archive:
                if member.name in ('.','./') and member.isdir():continue
                name = normalized(member.name)
                need(name not in seen and len(seen) < NODE_LIMIT and budget['nodes'] < TOTAL_NODES, 'archive-node-bound-duplicate')
                seen.add(name);budget['nodes'] += 1
                need(member.sparse is None and not any(k.startswith('GNU.sparse.') for k in member.pax_headers), 'archive-sparse')
                typ = 'directory' if member.isdir() else 'file' if member.isfile() else 'symlink' if member.issym() else 'hardlink' if member.islnk() else None
                need(typ is not None and 0 <= member.size <= FILE_LIMIT and name in expected, 'archive-member-shape')
                prior = expected[name];need(prior['type'] == typ and prior['bytes'] == member.size and prior['mode'] == member.mode, 'payload-node-binding')
                if typ in ('symlink','hardlink'):need(member.linkname == prior['target'], 'payload-link-binding')
                if typ != 'file':continue
                stream = archive.extractfile(member);digest = hashlib.sha256();capture = bytearray();size = 0;is_elf = None
                while block := stream.read(MIB):
                    size += len(block);need(size <= member.size and time.monotonic() <= deadline, 'member-read-bound-deadline');digest.update(block)
                    if is_elf is None:is_elf = block[:4] == b'\x7fELF'
                    if is_elf:capture.extend(block)
                need(size == member.size and digest.hexdigest() == prior['sha256'], 'payload-file-hash-binding')
                if is_elf:
                    item = {'name':row['name'],'version':package['version'],'path':name,'bytes':size,'sha256':digest.hexdigest()}
                    try:
                        info=parse_elf(capture)
                        if name.startswith(('usr/lib/firmware/','lib/firmware/')):info['classification']='firmware-elf-data-observed'
                        item.update(status='elf-parsed-as-data',ELF=info)
                    except (Refusal,UnicodeError,struct.error) as error:
                        item.update(status='elf-parser-refused',reason=str(error) if type(error) is Refusal else type(error).__name__)
                    objects.append(item)
        while counted.read(MIB):pass
    need(seen == set(expected), 'payload-member-set-binding')
    return objects


def resolve(path, namespace):
    """Archive namespace only: no host lookup, symlink following or cwd guess."""
    need(type(path) is str and 0 < len(path) <= 4096 and not re.search('[\x00-\x1f\x7f]', path), 'lookup-path')
    pending,resolved,visited,expansions = deque(path.lstrip('/').split('/')),[],set(),0
    while pending:
        part = pending.popleft()
        if part in ('','.'):continue
        if part == '..':
            if not resolved:return {'status':'escapes-observed-root'}
            resolved.pop();continue
        key = '/'.join([*resolved,part]);node = namespace.get(key)
        if node and node['type'] in ('symlink','hardlink'):
            state=(key,tuple(pending))
            if state in visited:return {'status':'link-cycle'}
            if expansions == 40:return {'status':'link-depth-bound'}
            visited.add(state);expansions += 1;target=node['target']
            need(type(target) is str and 0 < len(target) <= 4096 and not re.search('[\x00-\x1f\x7f]',target), 'lookup-link')
            if node['type'] == 'hardlink':
                target = normalized(target)
                peer = namespace.get(target)
                if not peer or peer['type'] != 'file' or peer['name'] != node['name']:return {'status':'hardlink-target-unverified'}
                resolved.clear()
            elif target.startswith('/'):resolved.clear()
            pending.extendleft(reversed(target.split('/')))
            if sum(len(x)+1 for x in [*resolved,*pending]) > 8192:return {'status':'link-path-bound'}
            continue
        if node is None:return {'status':'target-not-observed','path':key}
        if pending and node['type'] != 'directory':return {'status':'non-directory-ancestor','path':key}
        resolved.append(part)
    key='/'.join(resolved)
    return {'status':'observed-path','path':key} if key in namespace else {'status':'target-not-observed','path':key}


def providers(objects, namespace):
    candidates,paths = {},{}
    for obj in objects:
        if obj['status'] != 'elf-parsed-as-data' or obj['ELF']['classification'] != 'aarch64-loadable-elf':continue
        paths[obj['path']]=obj
        if obj['ELF']['type'] == 3 and obj['ELF']['interpreter'] is None:
            for name in {posixpath.basename(obj['path']),obj['ELF']['soname']} - {None}:
                candidates.setdefault(name,{})[obj['path']]=obj
    link_findings=[]
    for path,node in namespace.items():
        if node['type'] not in ('symlink','hardlink'):continue
        result=resolve(path,namespace)
        if result['status'] != 'observed-path':link_findings.append({'path':path,'resolution':result});continue
        obj=paths.get(result['path'])
        if obj and obj['ELF']['type'] == 3 and obj['ELF']['interpreter'] is None:
            candidates.setdefault(posixpath.basename(path),{})[obj['path']]=obj
    need(sum(len(obj['ELF']['needed'])+bool(obj['ELF']['interpreter']) for obj in paths.values()) <= TOTAL_NODES, 'loader-request-bound')
    requests=[]
    for obj in paths.values():
        elf=obj['ELF']
        if elf['interpreter']:
            resolution=resolve(elf['interpreter'],namespace) if elf['interpreter'].startswith('/') else {'status':'relative-interpreter-unresolved'}
            found=paths.get(resolution.get('path')) if resolution['status']=='observed-path' else None
            requests.append({'name':obj['name'],'path':obj['path'],'kind':'interpreter','requested':elf['interpreter'],
                             'status':'observed-aarch64-interpreter-candidate' if found else 'interpreter-not-observed-as-aarch64-loadable',
                             'resolution':resolution,'candidates':[{'name':found['name'],'path':found['path'],'sha256':found['sha256']}] if found else []})
        for needed in elf['needed']:
            if '$' in needed:matched=[];status='dynamic-token-search-unresolved'
            elif '/' in needed:
                result=resolve(needed,namespace) if needed.startswith('/') else {'status':'relative-needed-path-unresolved'}
                found=paths.get(result.get('path')) if result['status']=='observed-path' else None
                matched=[found] if found and found['ELF']['type']==3 else [];status='absolute-path-candidate' if matched else result['status']
            else:
                matched=list(candidates.get(needed,{}).values());status='missing-observed-provider' if not matched else 'ambiguous-observed-providers' if len(matched)>1 else 'one-observed-provider-candidate'
            requests.append({'name':obj['name'],'path':obj['path'],'kind':'DT_NEEDED','requested':needed,'status':status,
                             'candidates':[{'name':p['name'],'path':p['path'],'sha256':p['sha256']} for p in matched]})
    return {'requests':requests,'unresolved_namespace_links':link_findings,'actual_loader_search_verified':False,
            'scope':'global observed candidates; RPATH/RUNPATH, environment, cache, hwcaps, symbols and transitive loader selection not executed'}


def run(contract):
    need(type(contract) is dict and set(contract)=={'schema_version','payload_contract','payload_report','payload_handoff','authentication_bindings'} and
         type(contract['schema_version']) is int and contract['schema_version']==1, 'input-contract')
    payload=load_ref(contract['payload_contract']);report=load_ref(contract['payload_report']);handoff=load_ref(contract['payload_handoff']);auth=load_ref(contract['authentication_bindings'])
    need(report['kind']=='inert-exact-package-payload-link-hook-observation' and report['source_sha256']==PAYLOAD_SOURCE and
         report['inputs']==payload and report['archive_unavailable_packages']==[] and report['observed_non_directory_overlaps']==[], 'payload-report-binding')
    need(handoff['payload_contract']==contract['payload_contract'] and handoff['payload_report']==contract['payload_report'] and
         handoff['authentication_bindings']==contract['authentication_bindings'] and handoff['status']=='ACTUAL-PASS-all624-supplied-archives-inspected-as-data', 'payload-handoff-binding')
    need(auth['installed_image_authenticated'] is False and auth['source_grants_complete'] is False, 'authentication-scope')
    rows=payload['archives'];need(type(rows) is list and len(rows) == PACKAGE_COUNT, 'archive-count')
    packages={p['name']:p for p in report['packages']};need(len(packages)==len(report['packages'])==len(rows), 'package-count')
    need(all(type(value) is int and value==PACKAGE_COUNT for value in (report['selected_final_count'],report['inspected_package_count'],handoff['selected_final_packages'],handoff['supplied_archives'],handoff['inspected_archives'])), 'full-inventory-count')
    seen=set();namespace={};node_count=0
    for row in rows:
        need(type(row) is dict and set(row)=={'name','archive'} and type(row['name']) is str and row['name'] in packages and row['name'] not in seen, 'archive-row')
        seen.add(row['name']);reference_schema(row['archive'],ARCHIVE_LIMIT);p=packages[row['name']]
        need(p['archive']==row['archive'] and p['status']=='payload-inspected-as-data' and not p['missing_declared_paths'] and not p['undeclared_archive_paths'], 'package-report-binding')
        need(type(p['nodes']) is list and type(p['controls']) is dict and '.PKGINFO' in p['controls'] and set(p['controls']) <= {'.PKGINFO','.BUILDINFO','.MTREE','.INSTALL'} and all(node['path']==key for key,node in p['controls'].items()), 'payload-node-collection')
        local=set()
        for node in [*p['nodes'],*p['controls'].values()]:
            node_count += 1;need(node_count <= TOTAL_NODES and len(local) < NODE_LIMIT, 'node-preflight-bound')
            path=normalized(node['path']);need(path not in local, 'duplicate-package-path');local.add(path)
            need(node['type'] in ('directory','file','symlink','hardlink') and type(node['bytes']) is int and 0 <= node['bytes'] <= FILE_LIMIT and type(node['mode']) is int and 0 <= node['mode'] <= 0o7777, 'namespace-node-type')
            if node['type']=='file':need(type(node['sha256']) is str and re.fullmatch('[a-f0-9]{64}',node['sha256']), 'namespace-file-hash')
            if path in p['controls']:
                need(node['type']=='file', 'payload-control-type');continue
            if path in namespace:need(node['type']==namespace[path]['type']=='directory', 'ambiguous-namespace-path')
            namespace[path]=node|{'name':row['name']}
    need(sum(row['archive']['size'] for row in rows)<=COMPRESSED_LIMIT and len(namespace)<=TOTAL_NODES, 'aggregate-preflight-bound')
    deadline=time.monotonic()+1195;budget={'decoded':0,'nodes':0};objects=[];results=[]
    for row in rows:
        need(time.monotonic()<=deadline, 'aggregate-deadline')
        try:
            found=inspect_archive(row,packages[row['name']],budget,deadline);objects.extend(found)
            results.append({'name':row['name'],'archive':row['archive'],'status':'archive-checksum-and-payload-correlated','ELF_count':len(found)})
        except (ValueError,OSError,EOFError,tarfile.TarError,lzma.LZMAError) as error:
            results.append({'name':row['name'],'archive':row['archive'],'status':'archive-refused','reason':str(error) if type(error) is Refusal else type(error).__name__})
    lookup=providers(objects,namespace);need(time.monotonic()<=deadline,'aggregate-deadline')
    lookup['candidate_inventory_complete']=all(p['status']=='archive-checksum-and-payload-correlated' for p in results) and all(p['status']=='elf-parsed-as-data' for p in objects)
    return {'schema_version':1,'kind':'static-elf-loader-data-observation','source_sha256':sha(Path(__file__).read_bytes()),'inputs':contract,
            'status':'PASS-static-data-inspection' if all(p['status']=='archive-checksum-and-payload-correlated' for p in results) and all(p['status']=='elf-parsed-as-data' for p in objects) else 'FAIL-static-data-inspection',
            'packages':results,'objects':objects,'ELF_counts':dict(Counter(p.get('ELF',{}).get('classification','parser-refused') for p in objects)),
            'loader':lookup,'read_bounds':budget,'archive_signatures_verified_by_this_helper':False,'installed_image_authenticated':False,
            'runtime_abi_verified':False,'actual_16K_execution_verified':False,'hardware_accepted':False,'payloads_executed':False,'system_mutation':False}


def write_private(path, report):
    path=Path(os.path.abspath(path));need(path.is_relative_to(ARTIFACTS) and not any(p.is_symlink() for p in [path.parent,*path.parent.parents]),'output-path')
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd);need(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700,'output-directory')
        data=(json.dumps(report,sort_keys=True,indent=2,allow_nan=False)+'\n').encode();need(len(data)<=JSON_LIMIT,'output-bound')
        out=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        with os.fdopen(out,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--contract',type=Path,required=True);parser.add_argument('--contract-sha256',required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        report=run(load_ref({'path':str(args.contract.absolute()),'size':args.contract.stat().st_size,'sha256':args.contract_sha256}));write_private(args.output,report)
        print(json.dumps({'status':report['status'],'ELF_counts':report['ELF_counts'],'payloads_executed':False}));return 0 if report['status']=='PASS-static-data-inspection' else 1
    except (ValueError,OSError,KeyError,TypeError) as error:
        print('ELF audit refused: '+(str(error) if type(error) is Refusal else type(error).__name__),file=__import__('sys').stderr);return 2


if __name__=='__main__':raise SystemExit(main())
