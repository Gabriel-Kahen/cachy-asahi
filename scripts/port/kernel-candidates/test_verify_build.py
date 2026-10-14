# SPDX-License-Identifier: MIT
import gzip
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import harness
import verify_build as verifier

TEXT_ADDR = 0xffff800000000000
IDENTITIES = {
    't8112-j413.dtb': {'model': b'Apple MacBook Air (13-inch, M2, 2022)\0',
                      'compatible': b'apple,j413\0apple,t8112\0apple,arm-platform\0'},
    't8112-j415.dtb': {'model': b'Apple MacBook Air (15-inch, M2, 2023)\0',
                      'compatible': b'apple,j415\0apple,t8112\0apple,arm-platform\0'}}


def fdt(identity):
    names = b'compatible\0model\0device_type\0'
    body = bytearray(struct.pack('>I', 1) + b'\0' * 4)
    for name, value in identity.items():
        body.extend(struct.pack('>III', 3, len(value), names.index(name.encode() + b'\0')) + value)
        body.extend(b'\0' * (-len(body) % 4))
    body.extend(struct.pack('>I', 1) + b'cpu@0\0\0\0')
    body.extend(struct.pack('>III', 3, 4, names.index(b'device_type')) + b'cpu\0')
    body.extend(struct.pack('>III', 2, 2, 9))
    strings = 56 + len(body)
    return struct.pack('>10I', 0xd00dfeed, strings + len(names), 56, strings, 40, 17, 16, 0, len(names), len(body)) + b'\0' * 16 + body + names


def elf_bytes(text, module=False, modinfo=b'', export='kernel_export'):
    # Real ELF encodings, synthetic code/data: no execution or build claim.
    sections = [('','',0,0,0,0,0,0), ('.text',text,1,6,0 if module else TEXT_ADDR,16,0,0)]
    if module:
        sections += [('.modinfo',modinfo,1,2,0,1,0,0),
                     ('.gnu.linkonce.this_module',b'\0' * 512,1,3,0,8,0,0)]
        defs = [(export,1,0,4,0x12), ('__this_module',3,0,512,0x11)]
    else:
        sections += [('.bss',0x4000,8,3,TEXT_ADDR + 0x4000,16384,0,0)]
        defs = [('_text',1,TEXT_ADDR,0,0x10), ('_end',2,TEXT_ADDR + 0x8000,0,0x10),
                (export,1,TEXT_ADDR + 64,4,0x12)]
    strings = b'\0'; symbols = bytearray(24)
    for name, index, value, size, info in defs:
        at = len(strings); strings += name.encode() + b'\0'
        symbols.extend(struct.pack('<IBBHQQ',at,info,0,index,value,size))
    symindex = len(sections)
    sections += [('.symtab',bytes(symbols),2,0,0,8,24,symindex + 1), ('.strtab',strings,3,0,0,1,0,0)]
    if module:
        sections += [('.rela.text',struct.pack('<QQq',0,0,0),4,0,0,8,24,symindex)]
    names = b'\0'
    for row in sections[1:]:
        names += row[0].encode() + b'\0'
    names += b'.shstrtab\0'; sections += [('.shstrtab',names,3,0,0,1,0,0)]
    data = bytearray(64 if module else 176); rows = [b'\0' * 64]
    text_offset = 0
    for index, (name,payload,kind,flags,addr,alignment,entrysize,link) in enumerate(sections[1:],1):
        boundary = 16384 if not module and name == '.text' else alignment
        data.extend(b'\0' * (-len(data) % boundary))
        offset = len(data)
        if name == '.text': text_offset = offset
        size = payload if kind == 8 else len(payload)
        if kind != 8: data.extend(payload)
        info = 1 if name in ('.symtab','.rela.text') else 0
        rows.append(struct.pack('<IIQQQQIIQQ',names.index(name.encode()+b'\0'),kind,flags,addr,offset,size,link,info,alignment,entrysize))
    data.extend(b'\0' * (-len(data) % 8)); shoff = len(data)
    data.extend(b''.join(rows))
    data[:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    struct.pack_into('<HHIQQQIHHHHHH',data,16,1 if module else 3,183,1,0 if module else TEXT_ADDR,
                     0 if module else 64,shoff,0,64,0 if module else 56,0 if module else 2,64,len(rows),len(rows)-1)
    if not module:
        struct.pack_into('<IIQQQQQQ',data,64,1,5,text_offset,TEXT_ADDR,TEXT_ADDR,len(text),len(text),16384)
        struct.pack_into('<IIQQQQQQ',data,120,1,6,0,TEXT_ADDR + 0x4000,TEXT_ADDR + 0x4000,0,0x4000,16384)
    return bytes(data)


def flat_kernel_bytes(text, data_lma=0x8000, readonly_kind=1):
    """Source-shaped section projection: removed note, zero gaps, data and BSS."""
    payload = b'owned_data_block'
    readonly = {1:b'owned_readonly_block',3:b'\0owned_dynamic_string\0',
                4:struct.pack('<QQq',TEXT_ADDR+64,0,0),11:b'\0'*24}[readonly_kind]
    readonly_name = {1:'.rodata',3:'.dynstr',4:'.rela.dyn',11:'.dynsym'}[readonly_kind]
    note = struct.pack('<III',4,4,3) + b'GNU\0' + b'abcd'
    raw = bytearray(0xc000 + len(payload))
    raw[0x4000:0x4000+len(text)] = text
    raw[0x8000:0x8000+len(note)] = note
    raw[0x8020:0x8020+len(readonly)] = readonly
    raw[0xc000:] = payload
    sections = [('',0,0,0,0,0,0,0,0,0),
                ('.text',1,6,TEXT_ADDR,0x4000,len(text),0,0,16,0),
                ('.note.gnu.build-id',7,2,TEXT_ADDR+0x4000,0x8000,len(note),0,0,4,0),
                (readonly_name,readonly_kind,2,TEXT_ADDR+0x4020,0x8020,len(readonly),
                 8 if readonly_kind==4 else 9 if readonly_kind==11 else 0,0 if readonly_kind==4 else 1 if readonly_kind==11 else 0,
                 16,24 if readonly_kind in (4,11) else 0),
                ('.data',1,3,TEXT_ADDR+0x8000,0xc000,len(payload),0,0,16,0),
                ('.bss',8,3,TEXT_ADDR+0x8000+len(payload),len(raw),0x8000-len(payload),0,0,16,0)]
    symbols = bytearray(24); strings = b'\0'
    for name,index,value,size,info in [('_text',1,TEXT_ADDR,0,0x10),('_end',5,TEXT_ADDR+0x10000,0,0x10),
                                       ('kernel_export',1,TEXT_ADDR+64,4,0x12)]:
        nameoff = len(strings); strings += name.encode()+b'\0'
        symbols.extend(struct.pack('<IBBHQQ',nameoff,info,0,index,value,size))
    for name,kind,flags,content,align,link,info,entry in [('.debug_info',1,0,b'unallocated_debug_fixture',1,0,0,0),
                                                       ('.comment',1,0,b'unallocated_comment',1,0,0,0),
                                                       ('.symtab',2,0,bytes(symbols),8,9,1,24),
                                                       ('.strtab',3,0,strings,1,0,0,0)]:
        raw.extend(b'\0'*(-len(raw)%align)); offset=len(raw); raw.extend(content)
        sections.append((name,kind,flags,0,offset,len(content),link,info,align,entry))
    names = b'\0' + b''.join(row[0].encode()+b'\0' for row in sections[1:]) + b'.shstrtab\0'
    offset=len(raw); raw.extend(names)
    sections.append(('.shstrtab',3,0,0,offset,len(names),0,0,1,0))
    raw.extend(b'\0'*(-len(raw)%8)); shoff=len(raw)
    raw.extend(b'\0'*64)
    for row in sections[1:]:
        raw.extend(struct.pack('<IIQQQQIIQQ',names.index(row[0].encode()+b'\0'),*row[1:]))
    raw[:16] = b'\x7fELF\x02\x01\x01' + b'\0'*9
    struct.pack_into('<HHIQQQIHHHHHH',raw,16,3,183,1,TEXT_ADDR,64,shoff,0,64,56,3,64,len(sections),len(sections)-1)
    for index,values in enumerate([(1,5,0x4000,TEXT_ADDR,0x100000,len(text),len(text),16384),
                                    (1,4,0x8000,TEXT_ADDR+0x4000,0x104000,32+len(readonly),32+len(readonly),16384),
                                    (1,6,0xc000,TEXT_ADDR+0x8000,0x100000+data_lma,len(payload),0x8000,16384)]):
        struct.pack_into('<IIQQQQQQ',raw,64+index*56,*values)
    image = bytearray(max(0x4020+len(readonly),data_lma+len(payload)))
    image[:len(text)] = text
    image[0x4020:0x4020+len(readonly)] = readonly
    image[data_lma:data_lma+len(payload)] = payload
    return bytes(raw),bytes(image)


class BuildChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.expected = self.root / 'expected-config'; self.actual = self.root / 'actual-config'
        self.text = '\n'.join(harness.GUARDS) + '\n' + '\n'.join([
            'CONFIG_HZ=1000','CONFIG_MODULES=y','CONFIG_IKCONFIG=y','CONFIG_RELOCATABLE=y',
            'CONFIG_SMP=y','CONFIG_PREEMPT_BUILD=y','CONFIG_MODULE_UNLOAD=y',
            '# CONFIG_MODVERSIONS is not set','CONFIG_RANDSTRUCT_NONE=y']) + '\n'
        self.expected.write_text(self.text); self.actual.write_text('# generated header\n' + self.text)
        self.source = self.root / 'source'; self.source.mkdir()
        # Source binding itself is separately tested against hashed source bytes.
        mock = patch.object(verifier,'source_evidence',return_value=IDENTITIES)
        mock.start(); self.addCleanup(mock.stop)

    def outputs(self):
        build = self.root / 'build'; build.mkdir()
        (build / '.config').write_text(self.text)
        release = '7.1.13-ARCH-cachy-asahi-kernel-c01'
        for name, content in {'include/config/kernel.release':release + '\n',
                              'include/generated/utsrelease.h':'#define UTS_RELEASE "' + release + '"\n'}.items():
            path = build / name; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(content)
        header = bytearray(64); header[56:60] = b'ARMd'
        struct.pack_into('<IIQQQ',header,0,0xd503201f,0x14000010,0,0x8000,12)
        text = bytes(header) + b'\x1f\x20\x03\xd5' * 4 + b'IKCFG_ST' + gzip.compress(self.text.encode(),mtime=0) + b'IKCFG_ED'
        image = build / 'arch/arm64/boot/Image'; image.parent.mkdir(parents=True); image.write_bytes(text)
        (build / 'vmlinux').write_bytes(elf_bytes(text))
        dtbs = build / 'arch/arm64/boot/dts/apple'; dtbs.mkdir(parents=True)
        for name, identity in IDENTITIES.items(): (dtbs / name).write_bytes(fdt(identity))
        modules = list(verifier.APPLE_MODULES.values())
        (build / 'modules.order').write_text(''.join(name[:-3] + '.o\n' for name in modules))
        symvers = ['0x00000000\tkernel_export\tvmlinux\tEXPORT_SYMBOL\t\n']
        for index, name in enumerate(modules):
            modname = Path(name).stem.replace('-','_')
            modinfo = b'\0'.join((b'name=' + modname.encode(),
                                 b'vermagic=' + (release + ' SMP preempt mod_unload aarch64').encode(),
                                 b'license=GPL',b'depends=')) + b'\0'
            path = build / name; path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(elf_bytes(b'\x1f\x20\x03\xd5' * 4,module=True,modinfo=modinfo,export='module_export_' + str(index)))
            symvers.append('0x00000000\tmodule_export_' + str(index) + '\t' + name[:-3] + '\tEXPORT_SYMBOL_GPL\tAPPLE\n')
        (build / 'Module.symvers').write_text(''.join(symvers))
        return build

    def verify(self, build):
        return verifier.verify_outputs(build,self.source,self.expected)

    def mutate(self, path, offset, fmt, value):
        data = bytearray(path.read_bytes()); struct.pack_into(fmt,data,offset,value); path.write_bytes(data)

    def test_config_all_settings_identical_despite_generated_comment(self):
        self.assertEqual(verifier.verify_config(self.expected,self.actual)['status'],'CONFIG_IDENTICAL')

    def test_config_changed_unprotected_setting_still_refused(self):
        self.actual.write_text(self.actual.read_text().replace('CONFIG_HZ=1000','CONFIG_HZ=250'))
        with self.assertRaises(ValueError): verifier.verify_config(self.expected,self.actual)

    def test_config_duplicate_refused(self):
        self.actual.write_text(self.actual.read_text() + 'CONFIG_HZ=1000\n')
        with self.assertRaises(ValueError): verifier.verify_config(self.expected,self.actual)

    def test_complete_synthetic_structures_never_claim_execution_or_hardware(self):
        result = self.verify(self.outputs())
        self.assertEqual(result['status'],'BUILD_OUTPUT_STRUCTURE_VERIFIED')
        self.assertEqual(result['hardware_validation'],'NOT RUN')
        self.assertEqual(result['runtime_correctness'],'NOT RUN')
        self.assertEqual(result['performance'],'NOT MEASURED')
        self.assertEqual(len(result['modules']),3)
        self.assertEqual(result['export_count'],4)
        self.assertEqual(set(result['embedded_config_sha256'].values()),{hashlib.sha256(self.text.encode()).hexdigest()})

    def test_old_minimal_false_positive_dtbs_refused(self):
        build = self.outputs(); path = build / 'arch/arm64/boot/dts/apple/t8112-j413.dtb'
        path.write_bytes(struct.pack('>II',0xd00dfeed,8))
        with self.assertRaises(ValueError): self.verify(build)

    def test_fdt_header_bounds_alignment_overlap_version_refused(self):
        build = self.outputs(); path = build / 'arch/arm64/boot/dts/apple/t8112-j413.dtb'; original = path.read_bytes()
        for offset,value in [(4,len(original)-1),(8,57),(12,56),(16,41),(20,16),(24,18),(32,2**32-1),(36,2**32-1)]:
            with self.subTest(offset=offset,value=value):
                path.write_bytes(original); self.mutate(path,offset,'>I',value)
                with self.assertRaises(ValueError): self.verify(build)

    def test_fdt_reservation_terminator_required(self):
        build = self.outputs(); path = build / 'arch/arm64/boot/dts/apple/t8112-j413.dtb'
        data = bytearray(path.read_bytes()); struct.pack_into('>QQ',data,40,0x1000,0x1000); path.write_bytes(data)
        with self.assertRaises(ValueError): self.verify(build)

    def test_fdt_missing_end_unknown_token_bad_name_reference_refused(self):
        build = self.outputs(); path = build / 'arch/arm64/boot/dts/apple/t8112-j413.dtb'; original = path.read_bytes()
        end = struct.unpack_from('>I',original,12)[0]
        for offset,value in [(end-4,4),(56,42),(72,2**32-1),(64,2)]:
            with self.subTest(offset=offset):
                path.write_bytes(original); self.mutate(path,offset,'>I',value)
                with self.assertRaises(ValueError): self.verify(build)

    def test_fdt_identity_must_match_exact_pinned_source_board(self):
        build = self.outputs(); path = build / 'arch/arm64/boot/dts/apple/t8112-j413.dtb'
        for identity in [IDENTITIES['t8112-j415.dtb'],dict(IDENTITIES['t8112-j413.dtb'],model=b'fake\0'),
                         dict(IDENTITIES['t8112-j413.dtb'],compatible=b'apple,j413\0')]:
            path.write_bytes(fdt(identity))
            with self.assertRaises(ValueError): self.verify(build)

    def test_fdt_property_duplicate_and_unterminated_string_refused(self):
        build = self.outputs(); path = build / 'arch/arm64/boot/dts/apple/t8112-j413.dtb'; original = path.read_bytes()
        data = bytearray(original)
        # Replace the second property name reference with the first one's name.
        first_len = struct.unpack_from('>I',data,68)[0]
        next_prop = (76 + first_len + 3) & ~3
        struct.pack_into('>I',data,next_prop+8,struct.unpack_from('>I',data,72)[0]); path.write_bytes(data)
        with self.assertRaises(ValueError): self.verify(build)
        path.write_bytes(original[:-1] + b'X')
        with self.assertRaises(ValueError): self.verify(build)

    def test_image_endianness_page_size_placement_reserved_size_refused(self):
        build = self.outputs(); path = build / 'arch/arm64/boot/Image'; original = path.read_bytes()
        for offset,fmt,value in [(24,'<Q',13),(24,'<Q',10),(24,'<Q',4),(24,'<Q',28),(8,'<Q',0x80000),
                                 (16,'<Q',0),(16,'<Q',64),(32,'<Q',1),(4,'<I',0)]:
            with self.subTest(offset=offset,value=value):
                path.write_bytes(original); self.mutate(path,offset,fmt,value)
                with self.assertRaises(ValueError): self.verify(build)

    def test_elf_identity_type_version_arch_header_refused(self):
        build = self.outputs(); path = build / 'vmlinux'; original = path.read_bytes()
        for offset,fmt,value in [(6,'<B',0),(16,'<H',0),(16,'<H',2),(18,'<H',62),(20,'<I',0),(52,'<H',0),(54,'<H',0),(60,'<H',0)]:
            with self.subTest(offset=offset):
                path.write_bytes(original); self.mutate(path,offset,fmt,value)
                with self.assertRaises(ValueError): self.verify(build)

    def test_elf_wx_alignment_entry_segments_refused(self):
        build = self.outputs(); path = build / 'vmlinux'; original = path.read_bytes()
        for offset,fmt,value in [(68,'<I',7),(112,'<Q',2048),(88,'<Q',TEXT_ADDR+1),(24,'<Q',TEXT_ADDR+0x4000),
                                 (96,'<Q',2**32),(104,'<Q',1),(136,'<Q',TEXT_ADDR)]:
            with self.subTest(offset=offset):
                path.write_bytes(original); self.mutate(path,offset,fmt,value)
                with self.assertRaises(ValueError): self.verify(build)

    def test_check001_reports_first_false_conjunct_without_operands(self):
        build = self.outputs(); path = build / 'vmlinux'; original = path.read_bytes()
        cases = (
            ('ALIGN_MIN', ((112, 2048),)),
            ('ALIGN_POWER_TWO', ((112, 6144),)),
            ('VA_ALIGN', ((80, TEXT_ADDR + 8),)),
            ('PA_ALIGN', ((88, 0x100008),)),
            ('VA_16K', ((112, 4096), (80, TEXT_ADDR + 4096))),
            ('PA_16K', ((112, 4096), (88, 0x101000))),
            ('PERMISSIONS', ((68, 7),)),
            ('MEMORY_SIZE', ((96, 0), (104, 0))),
        )
        for label, changes in cases:
            with self.subTest(label=label):
                path.write_bytes(original)
                for offset, value in changes:
                    self.mutate(path, offset, '<I' if offset == 68 else '<Q', value)
                with self.assertRaises(ValueError) as caught:
                    self.verify(build)
                self.assertEqual(caught.exception.args, ('16K ELF load geometry/permissions required; WX refused [' + label + ']',))
        path.write_bytes(original)
        self.assertEqual(self.verify(build)['status'], 'BUILD_OUTPUT_STRUCTURE_VERIFIED')

    def test_small_declared_elf_alignment_keeps_16k_layout(self):
        build = self.outputs(); path = build / 'vmlinux'; original = path.read_bytes()
        for alignment in (4096, 8192, 16384):
            with self.subTest(alignment=alignment):
                path.write_bytes(original); self.mutate(path,112,'<Q',alignment)
                self.assertEqual(self.verify(build)['status'], 'BUILD_OUTPUT_STRUCTURE_VERIFIED')
        for field in (80, 88):
            with self.subTest(field=field):
                path.write_bytes(original); self.mutate(path,112,'<Q',4096)
                self.mutate(path,field,'<Q',(TEXT_ADDR if field == 80 else 0x100000)+4096)
                with self.assertRaisesRegex(ValueError,'16K ELF load geometry'):
                    self.verify(build)

    def test_image_body_byte64_mutation_rejected_despite_unchanged_vmlinux(self):
        build = self.outputs(); image = build / 'arch/arm64/boot/Image'
        original_elf = (build / 'vmlinux').read_bytes()
        raw = bytearray(image.read_bytes()); raw[64] ^= 1; image.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'Image body differs'):
            self.verify(build)
        self.assertEqual((build / 'vmlinux').read_bytes(),original_elf)

    def test_full_source_shaped_section_projection_and_removed_note(self):
        build = self.outputs(); path = build / 'arch/arm64/boot/Image'
        text = bytearray(path.read_bytes()); struct.pack_into('<Q',text,16,0x10000)
        elf,image = flat_kernel_bytes(bytes(text)); (build / 'vmlinux').write_bytes(elf); path.write_bytes(image)
        result = self.verify(build)
        relation = result['image_elf_relation']
        self.assertEqual(relation['status'],'IMAGE_ELF_BYTES_VERIFIED')
        self.assertEqual(relation['bytes'],len(image))
        self.assertLess(len(image),result['image_effective_bytes'])
        self.assertEqual([row['name'] for row in relation['copied_sections']],['.text','.rodata','.data'])
        self.assertEqual(relation['removed_allocated_sections'],['.note.gnu.build-id'])
        self.assertGreater(relation['zero_gap_bytes'],0)
        with verifier.ELF(build / 'vmlinux',3,4*1024**3) as reader:
            offset=reader.by_name['.note.gnu.build-id']['offset']
        # Removed note bytes do not change the binary projection.
        self.mutate(build / 'vmlinux',offset+16,'<I',0x12345678)
        self.assertEqual(self.verify(build)['image_sha256'],result['image_sha256'])

    def test_projection_rejects_copied_body_gap_and_length_mutations(self):
        build = self.outputs(); path = build / 'arch/arm64/boot/Image'
        text = bytearray(path.read_bytes()); struct.pack_into('<Q',text,16,0x10000)
        elf,image = flat_kernel_bytes(bytes(text)); (build / 'vmlinux').write_bytes(elf)
        for position in (64,0x8000,0x4020,0x4000,len(text)+4):
            raw=bytearray(image); raw[position]^=1; path.write_bytes(raw)
            with self.assertRaises(ValueError): self.verify(build)
        for raw in (image[:-1],image+b'\0'):
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError,'Image length differs'):
                self.verify(build)

    def test_projection_preserves_allocated_dynamic_data_types(self):
        for kind in (3,4,11):
            elf,image=flat_kernel_bytes(b'synthetic_dynamic_data',readonly_kind=kind)
            path=self.root/'dynamic.elf'; output=self.root/'dynamic.Image'
            path.write_bytes(elf); output.write_bytes(image)
            with verifier.ELF(path,3,4*1024**3) as reader:
                result=verifier.image_relation(reader,output,TEXT_ADDR)
            self.assertEqual(result['copied_sections'][1]['name'],{3:'.dynstr',4:'.rela.dyn',11:'.dynsym'}[kind])

    def test_projection_uses_load_addresses_and_rejects_overlap(self):
        text=b'own_data_only_header_and_code'
        elf,image = flat_kernel_bytes(text,data_lma=0xc000)
        path=self.root/'mapped.elf'; output=self.root/'mapped.Image'
        path.write_bytes(elf); output.write_bytes(image)
        with verifier.ELF(path,3,4*1024**3) as reader:
            result=verifier.image_relation(reader,output,TEXT_ADDR)
        self.assertEqual(result['copied_sections'][-1]['image_offset'],0xc000)
        # Same VMA/file bytes, invalid copied physical overlap.
        self.mutate(path,64+2*56+24,'<Q',0x100000)
        with verifier.ELF(path,3,4*1024**3) as reader:
            with self.assertRaisesRegex(ValueError,'overlapping copied'):
                verifier.image_relation(reader,output,TEXT_ADDR)

    def test_elf_image_header_and_effective_size_correspondence_required(self):
        build = self.outputs(); image = build / 'arch/arm64/boot/Image'
        self.mutate(image,16,'<Q',0x10000)
        with self.assertRaises(ValueError): self.verify(build)

    def test_embedded_config_missing_changed_truncated_duplicate_refused(self):
        build = self.outputs(); path = build / 'arch/arm64/boot/Image'; original = path.read_bytes()
        for data in [original.replace(b'IKCFG_ST',b'XXXXXXXX'),original[:-8],original + original[80:],
                     original[:80] + b'IKCFG_ST' + gzip.compress(b'wrong\n',mtime=0) + b'IKCFG_ED']:
            path.write_bytes(data)
            with self.assertRaises(ValueError): self.verify(build)

    def test_embedded_vmlinux_config_cannot_be_swapped(self):
        build = self.outputs(); path = build / 'vmlinux'; path.write_bytes(path.read_bytes().replace(b'IKCFG_ST',b'XXXXXXXX'))
        with self.assertRaises(ValueError): self.verify(build)

    def test_generated_release_and_utsrelease_binding_required(self):
        build = self.outputs(); path = build / 'include/generated/utsrelease.h'
        path.write_text('#define UTS_RELEASE "different"\n')
        with self.assertRaises(ValueError): self.verify(build)

    def test_no_missing_extra_duplicate_escaping_compressed_symlink_module(self):
        build = self.outputs(); order = build / 'modules.order'; original = order.read_text()
        for data in ['',original + original.splitlines()[0] + '\n','../outside.o\n',original.replace('.o','.ko')]:
            with self.subTest(data=data[:40]):
                order.write_text(data)
                with self.assertRaises(ValueError): self.verify(build)
        order.write_text(original)
        extra = build / 'extra.ko'; extra.write_bytes(b'fake')
        with self.assertRaises(ValueError): self.verify(build)
        extra.unlink()
        module = build / next(iter(verifier.APPLE_MODULES.values())); raw = module.read_bytes(); module.unlink()
        with self.assertRaises(ValueError): self.verify(build)
        module.symlink_to(build / 'vmlinux')
        with self.assertRaises(ValueError): self.verify(build)
        module.unlink(); module.write_bytes(raw)
        compressed = module.with_name(module.name + '.zst'); compressed.write_bytes(b'fake')
        with self.assertRaises(ValueError): self.verify(build)

    def test_configured_apple_module_cannot_be_removed_from_order_and_inventory(self):
        build = self.outputs(); order = build / 'modules.order'; name = order.read_text().splitlines()[0]
        order.write_text('\n'.join(order.read_text().splitlines()[1:])+'\n'); (build / (name[:-2]+'.ko')).unlink()
        with self.assertRaises(ValueError): self.verify(build)

    def test_module_arch_type_vermagic_name_descriptor_relocation_refused(self):
        build = self.outputs(); path = build / next(iter(verifier.APPLE_MODULES.values())); original = path.read_bytes()
        for data in [original.replace(b'SMP preempt',b'SMP xxxxxxx'),original.replace(b'name=snd_',b'name=bad_')]:
            path.write_bytes(data)
            with self.assertRaises(ValueError): self.verify(build)
        for offset,fmt,value in [(16,'<H',3),(18,'<H',62),(20,'<I',0),(24,'<Q',1)]:
            path.write_bytes(original); self.mutate(path,offset,fmt,value)
            with self.assertRaises(ValueError): self.verify(build)
        path.write_bytes(original)
        with verifier.ELF(path,1,1024**3) as reader:
            descriptor = reader.by_name['.gnu.linkonce.this_module']['index']
            reloc = reader.by_name['.rela.text']['offset']
        shoff = struct.unpack_from('<Q',original,40)[0]
        for offset,fmt,value in [(shoff + descriptor*64 + 8,'<Q',0),(reloc+8,'<Q',9999<<32),(reloc,'<Q',9999)]:
            path.write_bytes(original); self.mutate(path,offset,fmt,value)
            with self.assertRaises(ValueError): self.verify(build)

    def test_symvers_requires_actual_owner_defined_symbols_and_strict_fields(self):
        build = self.outputs(); path = build / 'Module.symvers'; original = path.read_text()
        for data in ['synthetic-symbol\n',original.replace('kernel_export','missing_export'),original.replace('vmlinux','fakeowner'),
                     original.replace('EXPORT_SYMBOL\t','EXPORT_FAKE\t'),original + original.splitlines()[0] + '\n',
                     original.replace('0x00000000','0x00000001'),original.replace('\tAPPLE\n','\tbad namespace\n')]:
            with self.subTest(data=data[:80]):
                path.write_text(data)
                with self.assertRaises(ValueError): self.verify(build)

    def test_real_source_module_namespaces_and_tail_globs_accepted(self):
        build = self.outputs(); path = build / 'Module.symvers'
        original = path.read_text()
        for namespace in ('module:btrfs','module:kvm','module:kvm,kvm-amd,kvm-intel','module:ext4-test',
                          'module:btrfs,kvm*','module:*'):
            path.write_text(original.replace('\tAPPLE\n','\t' + namespace + '\n'))
            self.assertEqual(self.verify(build)['export_count'],4)
        for namespace in ('module:','module:,btrfs','module:btrfs,','module:btrfs,,kvm','module:k*vm',
                          'module:btrfs,btrfs','module:../btrfs','module:btrfs kvm','module:btrfs:extra','module:'+'a'*513):
            path.write_text(original.replace('\tAPPLE\n','\t' + namespace + '\n'))
            with self.assertRaises(ValueError): self.verify(build)

    def test_outputs_reject_cyclic_source_before_producing_acceptance(self):
        build = self.outputs()
        (self.source / 'cycle-a').symlink_to('cycle-b')
        (self.source / 'cycle-b').symlink_to('cycle-a')
        with self.assertRaisesRegex(ValueError,'cyclic/dangling'):
            self.verify(build)

    def test_unreadable_source_or_module_subtrees_cannot_be_silently_skipped(self):
        build = self.outputs()
        original = verifier.os.scandir
        for root in (self.source,build):
            denied = root / 'denied'; denied.mkdir()
            def scan(path):
                if Path(path) == denied:
                    raise PermissionError('fixture inaccessible subtree')
                return original(path)
            with patch.object(verifier.os,'scandir',side_effect=scan):
                with self.assertRaises(PermissionError): self.verify(build)
            denied.rmdir()

    def test_source_symlink_budget_enforced(self):
        target = self.source / 'file'; target.write_bytes(b'owned')
        for index in range(256):
            (self.source / ('link-' + str(index))).symlink_to('file')
        self.assertEqual(verifier.source_links(self.source)['symlinks'],256)
        (self.source / 'one-too-many').symlink_to('file')
        with self.assertRaisesRegex(ValueError,'symlink budget'):
            verifier.source_links(self.source)

    def test_inventory_bounds_and_unexpected_link_directory(self):
        build = self.outputs(); link = build / 'linked'; link.symlink_to(self.source,target_is_directory=True)
        with self.assertRaises(ValueError): self.verify(build)

    def test_non_native_preflight_refused_before_any_input_use(self):
        with patch.object(verifier.platform,'machine',return_value='x86_64'):
            with self.assertRaises(ValueError): verifier.preflight(None)

    def test_pinned_receipt_parse_uses_same_authenticated_snapshot(self):
        path = self.root / 'receipt.json'; unreviewed = b'{"status":"UNREVIEWED"}'
        reviewed = b'{"status":"REVIEWED_NATIVE_KERNEL_BUILDER"}'
        path.write_bytes(unreviewed); pin = hashlib.sha256(unreviewed).hexdigest()
        # Old read_json(path)->digest(path) swap route is no longer used.
        with patch.object(harness,'read_json',side_effect=AssertionError('separate JSON read forbidden')):
            self.assertEqual(verifier.pinned_json(path,pin)['status'],'UNREVIEWED')
            path.write_bytes(reviewed)
            with self.assertRaises(ValueError): verifier.pinned_json(path,pin)
        path.write_bytes(unreviewed)
        real_loads = verifier.json.loads
        def swap_after_authentication(data, **kwargs):
            path.write_bytes(reviewed)
            return real_loads(data, **kwargs)
        with patch.object(verifier.json,'loads',side_effect=swap_after_authentication):
            self.assertEqual(verifier.pinned_json(path,pin)['status'],'UNREVIEWED')

    def test_pinned_receipt_duplicate_keys_and_links_refused(self):
        path = self.root / 'receipt.json'; data = b'{"status":"A","status":"B"}'; path.write_bytes(data)
        with self.assertRaises(ValueError): verifier.pinned_json(path,hashlib.sha256(data).hexdigest())
        path.unlink(); path.symlink_to(self.expected)
        with self.assertRaises(ValueError): verifier.pinned_json(path,hashlib.sha256(self.expected.read_bytes()).hexdigest())

    def test_fdt_reservation_ranges_and_future_compatible_version(self):
        path = self.root / 'board.dtb'; original = fdt(IDENTITIES['t8112-j413.dtb'])
        def reserves(rows):
            extra = b''.join(struct.pack('>QQ',*row) for row in rows)
            raw = bytearray(original[:40] + extra + original[40:])
            for offset in (4,8,12):
                struct.pack_into('>I',raw,offset,struct.unpack_from('>I',original,offset)[0]+len(extra))
            return raw
        for rows in [[(0x1000,0x100),(0x2000,0x100)],[(0,0x100)]]:
            raw = reserves(rows); struct.pack_into('>II',raw,20,18,17); path.write_bytes(raw)
            self.assertEqual(verifier.verify_dtb(path,IDENTITIES['t8112-j413.dtb'])['reservations'],len(rows))
        for rows in [[(0x1000,0x1000),(0x1100,0x100)],[(2**64-1,10)],[(0x1000,0)]]:
            path.write_bytes(reserves(rows))
            with self.assertRaises(ValueError): verifier.verify_dtb(path,IDENTITIES['t8112-j413.dtb'])

    def test_efi_header_valid_source_geometry_and_malformed_fields(self):
        path = self.root / 'efi-Image'; raw = bytearray(32768)
        raw[:2] = b'MZ'; struct.pack_into('<I',raw,60,64)
        raw[64:68] = b'PE\0\0'
        struct.pack_into('<HHIIIHH',raw,68,0xaa64,2,0,0,0,160,0x206)
        optional = 88
        struct.pack_into('<H',raw,optional,0x20b)
        struct.pack_into('<I',raw,optional+16,16384)
        struct.pack_into('<II',raw,optional+32,16384,512)
        struct.pack_into('<II',raw,optional+56,65536,16384)
        struct.pack_into('<H',raw,optional+68,10)
        struct.pack_into('<I',raw,optional+108,6)
        for index,(name,virtual,va,size,flags) in enumerate([(b'.text',4096,16384,4096,0x60000020),(b'.data',45056,20480,12288,0xc0000040)]):
            struct.pack_into('<8sIIIIIIHHI',raw,248+40*index,name,virtual,va,size,va,0,0,0,0,flags)
        path.write_bytes(raw)
        verifier.image_efi_header(path,bytes(raw[:64]),{'CONFIG_EFI':'y'},65536)
        for offset,fmt,value in [(60,'<I',0),(68,'<H',62),(70,'<H',1),(optional,'<H',0),(optional+16,'<I',0),
                                 (optional+32,'<I',4096),(optional+56,'<I',0),(optional+68,'<H',3),(248+36,'<I',0xe0000020)]:
            path.write_bytes(raw); self.mutate(path,offset,fmt,value)
            with self.assertRaises(ValueError): verifier.image_efi_header(path,path.read_bytes()[:64],{'CONFIG_EFI':'y'},65536)
        path.write_bytes(raw[:100])
        with self.assertRaises(ValueError): verifier.image_efi_header(path,bytes(raw[:64]),{'CONFIG_EFI':'y'},65536)

    def test_output_file_size_caps_refuse_sparse_oversize_without_reading(self):
        build = self.outputs()
        for name,size in [('arch/arm64/boot/Image',256*1024**2+1),('vmlinux',4*1024**3+1),
                          (next(iter(verifier.APPLE_MODULES.values())),1024**3+1),
                          ('arch/arm64/boot/dts/apple/t8112-j413.dtb',4*1024**2+1)]:
            path = build / name; original = path.read_bytes()
            with path.open('wb') as stream: stream.truncate(size)
            with self.assertRaises(ValueError): self.verify(build)
            path.write_bytes(original)

    def test_embedded_config_gzip_bomb_and_extra_gzip_member_refused(self):
        path = self.root / 'configblob'
        for payload in [gzip.compress(b'A'*(verifier.LIMIT_CONFIG+1),mtime=0),
                        gzip.compress(self.text.encode(),mtime=0)+gzip.compress(b'extra',mtime=0)]:
            path.write_bytes(b'IKCFG_ST'+payload+b'IKCFG_ED')
            with self.assertRaises(ValueError): verifier.embedded_config(path,self.text.encode())

    def test_preflight_unreviewed_receipt_swap_cannot_use_reviewed_metadata(self):
        path = self.root / 'receipt.json'; data = b'{"status":"UNREVIEWED"}'
        path.write_bytes(data)
        args = SimpleNamespace(builder=path,builder_sha256=hashlib.sha256(data).hexdigest())
        def obsolete_read(*unused):
            path.write_bytes(data)
            return {'status':'REVIEWED_NATIVE_KERNEL_BUILDER','image_id':'sha256:' + 'a' * 64}
        with patch.object(verifier.platform,'machine',return_value='aarch64'), \
             patch.object(verifier.os,'getuid',return_value=1000), \
             patch.object(verifier.os,'geteuid',return_value=1000), \
             patch.object(harness,'read_json',side_effect=obsolete_read) as old:
            with self.assertRaisesRegex(ValueError,'reviewed immutable builder'):
                verifier.preflight(args)
            old.assert_not_called()

    def test_source_link_cycles_dangling_and_outside_refused(self):
        for target in ('cycle','absent',str(self.root / 'expected-config')):
            path = self.source / 'cycle'; path.symlink_to(target)
            with self.assertRaises(ValueError): verifier.source_links(self.source)
            path.unlink()
        target = self.source / 'file'; target.write_text('owned')
        (self.source / 'okay').symlink_to('file')
        verifier.source_links(self.source)


class SourceBindings(unittest.TestCase):
    def test_actual_retained_source_pins_and_identities_when_available(self):
        source = harness.ROOT / 'artifacts/kernel-candidates/full-baseline-20261012/source-tree/linux-asahi-7.1.13-3'
        if not source.exists(): self.skipTest('retained private source unavailable; run source closure gate before build')
        self.assertEqual(verifier.source_evidence(source),IDENTITIES)

    def test_source_byte_pin_enforced_before_identity_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            pins = {}
            for board in ('j413','j415'):
                identity = IDENTITIES['t8112-' + board + '.dtb']
                compatible = ', '.join('"' + value.decode() + '"' for value in identity['compatible'].rstrip(b'\0').split(b'\0'))
                data = '/ {\n compatible = ' + compatible + ';\n model = "' + identity['model'][:-1].decode() + '";\n};\n'
                name = 'arch/arm64/boot/dts/apple/t8112-' + board + '.dts'; path = source / name
                path.parent.mkdir(parents=True,exist_ok=True); path.write_text(data); pins[name] = hashlib.sha256(data.encode()).hexdigest()
            with patch.object(verifier,'SOURCE_PINS',pins):
                self.assertEqual(verifier.source_evidence(source),IDENTITIES)
                path.write_text(path.read_text().replace('2023','2024'))
                with self.assertRaises(ValueError): verifier.source_evidence(source)


if __name__ == '__main__':
    unittest.main()
