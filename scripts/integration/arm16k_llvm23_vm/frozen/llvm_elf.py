# SPDX-License-Identifier: MIT
# Exact passive elf() body from the reviewed independent LLVM v2 Reader.
import struct,posixpath
MIB=1024**2
PREFIX='/opt/cachy-asahi/llvm23-source-reference'
def need(value,why):
 if not value:raise ValueError(why)

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
