#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only Qt Declarative staged payload contract; does not load any ELF."""
import argparse,hashlib,json,os,re,stat,struct
from pathlib import Path,PurePosixPath
from source import PACKAGE,need,ordinary,document

def elf_info(body, machine=183):
    """Bounded ELF64 byte parser; no loader, readelf, or external providers."""
    need(len(body) >= 64 and body[:7] == b'\x7fELF\x02\x01\x01', 'ELF64 little-endian required')
    kind, actual, version = struct.unpack_from('<HHI', body, 16)
    need(machine == actual == 183 and kind in (2, 3) and version == 1, 'ELF AArch64 architecture/type/version mismatch')
    phoff = struct.unpack_from('<Q', body, 32)[0]
    ehsize, phentsize, phnum = struct.unpack_from('<HHH', body, 52)
    need(ehsize == 64 and phentsize == 56 and 0 < phnum < 1024
         and phoff >= 64 and phoff + phentsize * phnum <= len(body), 'ELF program headers malformed')
    segments = [struct.unpack_from('<IIQQQQQQ', body, phoff + n * phentsize) for n in range(phnum)]
    interpreters = [s for s in segments if s[0] == 3]
    need(len(interpreters) <= 1, 'ELF duplicate interpreter segment')
    interpreter = None
    if interpreters:
        segment = interpreters[0]
        need(1 < segment[5] <= 4096 and segment[2] + segment[5] <= len(body),
             'ELF bounded interpreter segment required')
        raw = body[segment[2]:segment[2] + segment[5]]
        need(raw[-1:] == b'\0' and b'\0' not in raw[:-1]
             and all(32 < c < 127 for c in raw[:-1]), 'ELF interpreter string malformed')
        interpreter = raw[:-1].decode('ascii')
    loads = [s for s in segments if s[0] == 1]
    need(loads, 'ELF load segments required')
    for segment in segments:
        need(segment[2] + segment[5] <= len(body), 'ELF segment outside file')
    for s in loads:
        need(s[5] <= s[6] and s[3] + s[6] < 2**64
             and s[7] >= 16384 and not s[7] & (s[7] - 1)
             and s[2] % s[7] == s[3] % s[7], 'ELF 16K load geometry required')

    def offset(address, size):
        matches = [s for s in loads if s[3] <= address and address + size <= s[3] + s[5]]
        need(size > 0 and len(matches) == 1, 'ELF metadata outside unique file-backed load segment')
        return matches[0][2] + address - matches[0][3]

    dynamic = [s for s in segments if s[0] == 2]
    need(len(dynamic) <= 1, 'ELF duplicate dynamic segment')
    tags, needed_offsets = {}, []
    if dynamic:
        segment = dynamic[0]
        need(segment[5] and segment[5] % 16 == 0 and segment[5] // 16 <= 65536,
             'ELF dynamic segment malformed')
        need(offset(segment[3], segment[5]) == segment[2], 'ELF dynamic segment load mapping mismatch')
        terminated = False
        for start in range(segment[2], segment[2] + segment[5], 16):
            tag, value = struct.unpack_from('<qQ', body, start)
            if tag == 0:
                terminated = True
                break
            if tag == 1:
                needed_offsets.append(value)
            else:
                if tag in (5, 10, 14, 0x6ffffffc, 0x6ffffffd, 0x6ffffffe, 0x6fffffff):
                    need(tag not in tags, 'ELF duplicate dynamic metadata tag')
                tags[tag] = value
        need(terminated, 'ELF dynamic segment unterminated')
    uses_strings = needed_offsets or any(t in tags for t in (14, 0x6ffffffc, 0x6ffffffe))
    table, table_bytes = 0, 0
    if uses_strings:
        need(5 in tags and 10 in tags and 0 < tags[10] <= len(body), 'ELF dynamic string table missing')
        table_bytes = tags[10]
        table = offset(tags[5], table_bytes)

    def text(index):
        need(0 <= index < table_bytes, 'ELF dynamic string outside table')
        end = body.find(b'\0', table + index, table + table_bytes)
        need(end > table + index, 'ELF dynamic string unterminated/empty')
        raw = body[table + index:end]
        need(all(32 < c < 127 for c in raw) and b'/' not in raw, 'ELF metadata string must be printable basename')
        return raw.decode('ascii')

    def versions(address_tag, count_tag, definitions):
        need((address_tag in tags) == (count_tag in tags), 'ELF GNU version table/count pair required')
        if address_tag not in tags:
            return None
        count = tags[count_tag]
        need(0 < count <= 4096, 'ELF GNU version count bound')
        address, result, visited, total_aux = tags[address_tag], [], set(), 0
        for number in range(count):
            need(address not in visited, 'ELF GNU version chain cycle')
            visited.add(address)
            start = offset(address, 20 if definitions else 16)
            if definitions:
                version, flags, index, aux_count, digest, aux, next_entry = struct.unpack_from('<HHHHIII', body, start)
                row = dict(flags=flags, index=index, hash=digest, names=[])
            else:
                version, aux_count, filename, aux, next_entry = struct.unpack_from('<HHIII', body, start)
                row = dict(file=text(filename), versions=[])
            need(version == 1 and 0 < aux_count <= 4096 and aux > 0, 'ELF GNU version record malformed')
            total_aux += aux_count
            need(total_aux <= 65536, 'ELF GNU total auxiliary bound')
            aux_address, aux_seen = address + aux, set()
            for auxiliary in range(aux_count):
                need(aux_address not in aux_seen, 'ELF GNU version auxiliary cycle')
                aux_seen.add(aux_address)
                start = offset(aux_address, 8 if definitions else 16)
                if definitions:
                    name, next_aux = struct.unpack_from('<II', body, start)
                    row['names'].append(text(name))
                else:
                    digest, flags, other, name, next_aux = struct.unpack_from('<IHHII', body, start)
                    row['versions'].append(dict(name=text(name), hash=digest, flags=flags, other=other))
                need(bool(next_aux) == (auxiliary + 1 < aux_count), 'ELF GNU auxiliary chain count mismatch')
                aux_address += next_aux
            result.append(row)
            need(bool(next_entry) == (number + 1 < count), 'ELF GNU version chain count mismatch')
            address += next_entry
        return result

    return dict(type=kind, machine=actual, interpreter=interpreter, soname=text(tags[14]) if 14 in tags else None,
        needed=[text(index) for index in needed_offsets],
        version_needs=versions(0x6ffffffe, 0x6fffffff, False),
        version_definitions=versions(0x6ffffffc, 0x6ffffffd, True),
        load_segments=[dict(offset=s[2], virtual_address=s[3], file_bytes=s[5], memory_bytes=s[6], alignment=s[7]) for s in loads],
        geometry_16k=True, metadata_scope='ELF_BYTES_ONLY_NO_NATIVE_OR_PROVIDER_ACCEPTANCE')

def qml_contract(root,rows):
 for r in rows:
  base=Path(root)/r['uri'].replace('.','/');raw=ordinary(base/'qmldir').decode();need(re.search(r'^module '+re.escape(r['uri'])+r'$',raw,re.M),'QML module identity '+r['uri']);plugins=re.findall(r'^(?:optional )?plugin ([A-Za-z0-9_]+)(?: ([^\n]+))?$',raw,re.M)
  if r['plugin'] is None:need(not plugins,'unexpected plugin in no-plugin module')
  else:
   need(len(plugins)==1,'one actual QML plugin '+r['uri']);name,where=plugins[0];need(not where or where=='.','plugin must reside in own QML directory');need(r['plugin']=='FROM_QMLDIR'or name==r['plugin'],'QML plugin target identity');need((base/('lib'+name+'.so')).is_file(),'QML dynamic plugin body '+r['uri'])
  need('typeinfo plugins.qmltypes'in raw and (base/'plugins.qmltypes').is_file(),'installed QML type registration '+r['uri'])
 return len(rows)
def check(root,contract,notices):
 root=Path(root);need(root.is_absolute()and root==root.resolve()and root!=Path('/'),'canonical separate stage');d=document(contract);nodes=list(root.rglob('*'));need(len(nodes)<=65536,'finite stage namespace');files={};elf={};total=0
 for p in nodes:
  n=p.relative_to(root).as_posix();s=p.lstat();need((n=='usr'or n.startswith('usr/'))and not(s.st_mode&0o6000),'only usr payload; no special privilege bits')
  if stat.S_ISDIR(s.st_mode):continue
  if stat.S_ISLNK(s.st_mode):
   target=os.readlink(p);need(not Path(target).is_absolute()and p.resolve().is_relative_to(root)and p.resolve().is_file(),'bounded internal file alias');continue
  need(not(s.st_mode&0o022),'no writable public payload')
  need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=128*1024**2,'ordinary bounded staged file');b=p.read_bytes();total+=len(b);need(total<=1024**3,'finite payload byte cap');files[n]=b
  if b.startswith(b'\x7fELF'):elf[n]=elf_info(b)
 need(not any(n.startswith(('usr/bin/pacman','usr/lib/systemd','usr/share/libalpm','usr/etc'))for n in files),'no package hooks or system mutation service')
 for module in d['required_shared_modules']:
  name='usr/lib/libQt6'+module+'.so.6.12.0';need(name in elf,'required AArch64 shared module '+module);need(elf[name]['soname']=='libQt6'+module+'.so.6','exact major SONAME '+module);need('usr/lib/cmake/Qt6'+module+'/Qt6'+module+'Config.cmake'in files,'CMake API '+module)
 for module in ('Qml','Quick'):
  need(any(n.startswith('usr/include/qt6/Qt'+module+'/6.12.0/Qt'+module+'/private/')for n in files),'required exact-version private headers '+module)
 for package in d['required_cmake_packages']:need('usr/lib/cmake/'+package+'/'+package+'Config.cmake'in files,'installed private/build API '+package)
 for name in d['required_pkgconfig']:need('usr/lib/pkgconfig/'+name+'.pc'in files,'normal pkgconfig consumer API '+name)
 for helper in d['required_cmake_helpers']:need('usr/lib/cmake/'+helper in files,'installed QML build helper '+helper)
 for name in d['required_tools']:
  found=[n for n in('usr/lib/qt6/'+name,'usr/lib/qt6/bin/'+name)if n in elf];need(len(found)==1,'one normal Qt tool '+name)
 qml=qml_contract(root/'usr/lib/qt6/qml',d['qml_modules'])
 policy=document(notices)['source_notices']
 for n,sha in policy.items():need(hashlib.sha256(files.get('usr/share/licenses/'+PACKAGE+'/source/'+n,b'')).hexdigest()==sha,'complete packaged source notice '+n)
 qtneeded={x for row in elf.values()for x in row['needed']if x.startswith('libQt6')};own={row['soname']for row in elf.values()if row['soname']};external=sorted(qtneeded-own);allowed={'libQt6'+m+'.so.6'for m in('Core','Gui','Network','Widgets','OpenGL','OpenGLWidgets','Sql','Concurrent','Test','DBus','Svg','ShaderTools')};need(set(external)<=allowed,'undeclared Qt dependency '+str(set(external)-allowed))
 return dict(status='PASS_STAGED_BYTES_ONLY',files=len(files),bytes=total,ELF=len(elf),QML_modules=qml,external_Qt_dependencies=external,all_DT_NEEDED=sorted({x for row in elf.values()for x in row['needed']}),native_execution=None,hardware=None,Root_acceptance=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--contract',type=Path,required=True);p.add_argument('--notices',type=Path,required=True);a=p.parse_args();print(json.dumps(check(a.root,a.contract,a.notices),indent=2,sort_keys=True))
