# SPDX-License-Identifier: MIT
"""Synthetic inert ELF DATA controls. No target binary or loader is executed."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('closed_aarch64_elf_data', HERE/'elf64le_aarch64.py')
elf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf)


def fixture(*, needed=(), soname=None, interp=None, runpath=None, rpath=None,
            kind=3, dynamic=True, extra=()):
    """ELF structure only, not executable machine code or native evidence."""
    raw=bytearray(2048);raw[:16]=b'\x7fELF\x02\x01\x01'+b'\0'*9
    strings=bytearray(b'\0');tags=[]
    for tag,value in [(1,name)for name in needed]+[(14,soname),(15,rpath),(29,runpath)]:
        if value is not None:
            tags.append((tag,len(strings)));strings.extend(value.encode()+b'\0')
    tags.extend(extra)
    tags.extend([(5,1024),(10,len(strings)),(0,0)])
    table=b''.join(struct.pack('<qQ',*row)for row in tags)
    headers=[]
    if interp is not None:
        text=interp.encode()+b'\0';raw[320:320+len(text)]=text
        headers.append((3,4,320,320,0,len(text),len(text),1))
    headers.append((1,5,0,0,0,len(raw),len(raw),16384))
    if dynamic:headers.append((2,4,512,512,0,len(table),len(table),8))
    struct.pack_into('<HHIQQQIHHHHHH',raw,16,kind,183,1,128,64,0,0,64,56,len(headers),0,0,0)
    for index,row in enumerate(headers):struct.pack_into('<IIQQQQQQ',raw,64+56*index,*row)
    if dynamic:raw[512:512+len(table)]=table;raw[1024:1024+len(strings)]=strings
    return bytes(raw)


def header(raw,index,field,value):
    raw=bytearray(raw);values=list(struct.unpack_from('<IIQQQQQQ',raw,64+index*56));values[field]=value
    struct.pack_into('<IIQQQQQQ',raw,64+index*56,*values);return bytes(raw)


def row(raw,mode=0o644):return dict(raw=raw,mode=mode)


def relocatable():
    """Ordinary AArch64 .o header shape used by the retained Python config."""
    raw=bytearray(776);raw[:16]=b'\x7fELF\x02\x01\x01'+b'\0'*9
    struct.pack_into('<HHIQQQIHHHHHH',raw,16,1,183,1,0,0,584,0,64,0,0,64,3,2)
    raw[64:68]=b'\0'*4;names=b'\0.text\0.shstrtab\0';raw[68:68+len(names)]=names
    struct.pack_into('<IIQQQQIIQQ',raw,648,1,1,6,0,64,4,0,0,4,0)
    struct.pack_into('<IIQQQQIIQQ',raw,712,7,3,0,0,68,len(names),0,0,1,0)
    return bytes(raw)


def rootfs():
    loader=fixture(soname='ld-linux-aarch64.so.1')
    return {
        'usr/bin/busybox':row(fixture(kind=2,dynamic=False),0o755),
        'usr/bin/python3.14':row(fixture(needed=('libpython3.14.so.1.0','libc.so.6'),interp='/lib/ld-linux-aarch64.so.1'),0o755),
        'usr/bin/bwrap':row(fixture(needed=('libc.so.6',),interp='/lib/ld-linux-aarch64.so.1'),0o755),
        'lib/ld-linux-aarch64.so.1':row(loader,0o755),
        'usr/lib/ld-linux-aarch64.so.1':row(loader,0o755),
        'usr/lib/libpython3.14.so.1.0':row(fixture(needed=('libm.so.6','libc.so.6'),soname='libpython3.14.so.1.0')),
        'usr/lib/libm.so.6':row(fixture(needed=('libc.so.6',),soname='libm.so.6')),
        'usr/lib/libc.so.6':row(fixture(needed=('ld-linux-aarch64.so.1',),soname='libc.so.6')),
        'usr/lib/python3.14/lib-dynload/_demo.so':row(fixture(needed=('libdemo.so.1',))),
        'usr/lib/libdemo.so.1':row(fixture(needed=('libc.so.6',),soname='libdemo.so.1')),
        'usr/lib/python3.14/encodings/__init__.py':row(b'# inert Python source\n')}


class ElfControls(unittest.TestCase):
    def refused(self,raw):
        with self.assertRaises((ValueError,UnicodeError,struct.error)):elf.parse_elf(raw)

    def test_parse_interpreter_needed_soname_and_runpath(self):
        value=elf.parse_elf(fixture(needed=('liba.so.1','libc.so.6'),soname='libfixture.so.1',
            interp='/lib/ld-linux-aarch64.so.1',runpath='$ORIGIN/../lib'))
        self.assertEqual(value['needed'],['liba.so.1','libc.so.6'])
        self.assertEqual(value['interpreter'],'/lib/ld-linux-aarch64.so.1')
        self.assertEqual(value['soname'],'libfixture.so.1')
        self.assertEqual(value['runpath'],'$ORIGIN/../lib')

    def test_static_busybox_and_nonelf_data(self):
        value=elf.parse_elf(fixture(kind=2,dynamic=False))
        self.assertFalse(value['dynamic']);self.assertIsNone(value['interpreter']);self.assertEqual(value['needed'],[])
        self.assertIsNone(elf.parse_elf(b'# pure stdlib source\n'))

    def test_wrong_arch_class_endian_and_nonloadable_type_refuse(self):
        for offset,value in ((4,1),(5,2),(7,255),(8,1),(18,62),(16,1)):
            raw=bytearray(fixture());raw[offset]=value
            with self.subTest(offset=offset):self.refused(bytes(raw))

    def test_relocatable_is_explicit_preserved_nonloadable_data(self):
        raw=relocatable();metadata=elf.parse_elf(raw)
        self.assertEqual(metadata,dict(type=1,machine='AArch64',classification='NONLOADABLE_ET_REL_DATA',sections=3))
        files=rootfs();path='usr/lib/python3.14/config-3.14-aarch64-linux-gnu/python.o';files[path]=row(raw)
        report=elf.audit_closure(files)
        self.assertEqual(report['nonloadable_DATA'],{path:metadata})
        self.assertEqual(report['files'],len(files));self.assertIn(path,report['rootfs_pins'])
        self.assertNotIn(path,report['elf_files'])

    def test_relocatable_cannot_be_root_interpreter_or_dependency(self):
        raw=relocatable();files=rootfs();files['usr/share/python.o']=row(raw)
        with self.assertRaisesRegex(ValueError,'required root'):elf.audit_closure(files,roots=['usr/share/python.o'])
        for target in ('usr/lib/libdemo.so.1','lib/ld-linux-aarch64.so.1'):
            files=rootfs();files[target]=row(raw)
            if target.startswith('lib/'):files['usr/'+target]=row(raw)
            with self.subTest(target=target),self.assertRaises(ValueError):elf.audit_closure(files)
        files=rootfs();files['usr/share/python.o']=row(raw,0o755)
        with self.assertRaisesRegex(ValueError,'nonexecutable DATA'):elf.audit_closure(files)

    def test_relocatable_requires_bounded_ordinary_sections_and_no_program_headers(self):
        for offset,value,fmt in ((24,1,'<Q'),(32,64,'<Q'),(54,56,'<H'),(56,1,'<H'),
                (40,2**64-1,'<Q'),(58,63,'<H'),(60,65535,'<H'),(62,3,'<H'),
                (648+4,6,'<I'),(648+24,2**64-1,'<Q'),(648+40,3,'<I'),(648+48,3,'<Q'),
                (648,999999,'<I'),(712+4,1,'<I')):
            raw=bytearray(relocatable());struct.pack_into(fmt,raw,offset,value)
            with self.subTest(offset=offset):self.refused(bytes(raw))

    def test_truncated_header_program_table_and_extended_count_refuse(self):
        for size in (4,16,63,100):
            with self.subTest(size=size):self.refused(fixture()[:size])
        for offset,value,fmt in ((32,2**64-1,'<Q'),(54,55,'<H'),(56,65535,'<H'),(52,63,'<H')):
            raw=bytearray(fixture());struct.pack_into(fmt,raw,offset,value);self.refused(bytes(raw))

    def test_load_and_dynamic_virtual_file_mapping_are_required(self):
        base=fixture()
        for raw in (header(base,0,6,1),header(base,0,7,3),header(base,1,2,600),
                    header(base,1,3,2**64-1),header(base,1,6,0),header(base,1,5,15)):
            self.refused(raw)
        # Two LOADs mapping the same dynamic address must not select arbitrarily.
        raw=bytearray(base);struct.pack_into('<H',raw,56,3)
        struct.pack_into('<IIQQQQQQ',raw,64+2*56,1,4,0,0,0,2048,2048,1)
        self.refused(bytes(raw))

    def test_interpreter_must_be_absolute_unique_and_nul_terminated(self):
        self.refused(fixture(interp='relative-loader'))
        raw=bytearray(fixture(interp='/lib/ld-linux-aarch64.so.1'));raw[320+len('/lib/ld-linux-aarch64.so.1')]=1;self.refused(bytes(raw))
        self.refused(fixture(interp='/lib/../outside'))

    def test_dynamic_strings_termination_duplicates_and_unsupported_loader_tags(self):
        self.refused(fixture(needed=('libc.so.6','libc.so.6')))
        self.refused(fixture(needed=('libc.so.6',),extra=((5,1024),)))
        raw=bytearray(fixture(needed=('libc.so.6',)));raw[1024+len(b'\0libc.so.6')]=ord('x');self.refused(bytes(raw))
        for tag in elf.UNSUPPORTED_TAGS:
            with self.subTest(tag=tag):self.refused(fixture(extra=((tag,1),)))
        self.refused(fixture(extra=((0x6ffffffb,0x800),)))

    def test_dynamic_table_and_strtab_do_not_trust_independent_offsets(self):
        raw=bytearray(fixture(needed=('libc.so.6',)))
        # d_ptr must map through LOAD; it is not a file offset hint.
        struct.pack_into('<Q',raw,512+16+8,2**64-1);self.refused(bytes(raw))
        raw=bytearray(fixture(needed=('libc.so.6',)));struct.pack_into('<Q',raw,512+8,99999);self.refused(bytes(raw))
        raw=bytearray(fixture());raw[512+32:512+48]=struct.pack('<qQ',1,0);self.refused(bytes(raw))

    def test_records_after_first_dt_null_are_ignored_not_provider_evidence(self):
        original=fixture(needed=('libc.so.6',))
        raw=bytearray(original)
        # Four active table records end with DT_NULL. Extend the declared table
        # with an unused nonzero NULL value and a spurious needed-string record.
        raw[576:608]=struct.pack('<qQqQ',0,1321,1,999999)
        modified=header(header(bytes(raw),1,5,96),1,6,96)
        parsed=elf.parse_elf(modified)
        self.assertEqual(parsed['needed'],['libc.so.6'])
        self.assertEqual(parsed['ignored_dynamic_records'],2)
        self.assertEqual(parsed['ignored_nonzero_dynamic_records'],2)
        files=rootfs();files['usr/lib/libdemo.so.1']=row(modified)
        report=elf.audit_closure(files)
        self.assertEqual([edge['requested']for edge in report['edges']if edge['requester']=='usr/lib/libdemo.so.1'],['libc.so.6'])

    def test_complete_closure_includes_interpreter_and_transitive_extension_deps(self):
        files=rootfs();report=elf.audit_closure(files,['usr/bin/busybox','usr/bin/python3.14','usr/bin/bwrap'])
        self.assertEqual(report['status'],'PASS_STATIC_AARCH64_ELF_DEPENDENCY_CLOSURE')
        self.assertTrue(report['audited_all_selected_ELFs']);self.assertEqual(report['runtime_execution'],'NOT_RUN')
        self.assertIn('usr/lib/python3.14/lib-dynload/_demo.so',report['elf_files'])
        edges={(edge['requester'],edge['requested'],edge['provider'])for edge in report['edges']}
        self.assertIn(('usr/lib/python3.14/lib-dynload/_demo.so','libdemo.so.1','usr/lib/libdemo.so.1'),edges)
        self.assertIn(('usr/lib/libdemo.so.1','libc.so.6','usr/lib/libc.so.6'),edges)

    def test_missing_interpreter_cannot_borrow_canonical_alias(self):
        files=rootfs();files.pop('lib/ld-linux-aarch64.so.1')
        with self.assertRaisesRegex(ValueError,'literal PT_INTERP'):elf.audit_closure(files)

    def test_missing_python_extension_dependency_is_not_omitted(self):
        files=rootfs();files['usr/lib/python3.14/lib-dynload/_tkinter.so']=row(fixture(needed=('libtk8.6.so','libtcl8.6.so')))
        with self.assertRaisesRegex(ValueError,'libtk8.6.so'):elf.audit_closure(files,['usr/bin/python3.14'])

    def test_filename_presence_is_not_provider_proof(self):
        for bad in (b'not ELF',fixture(kind=2),fixture(soname='wrong.so'),fixture(interp='/lib/ld-linux-aarch64.so.1',extra=((0x6ffffffb,0x08000000),))):
            files=rootfs();files['usr/lib/libdemo.so.1']=row(bad)
            with self.subTest(raw=bad[:20]),self.assertRaises(ValueError):elf.audit_closure(files)

    def test_provider_transitive_dependency_and_soname_conflict_refuse(self):
        files=rootfs();files['usr/lib/libdemo.so.1']=row(fixture(needed=('missing-leaf.so',),soname='libdemo.so.1'))
        with self.assertRaisesRegex(ValueError,'missing-leaf.so'):elf.audit_closure(files)
        files=rootfs();files['usr/lib/private/libdemo.so.1']=row(fixture(soname='libdemo.so.1'))
        with self.assertRaisesRegex(ValueError,'conflicting selected SONAME'):elf.audit_closure(files)

    def test_origin_runpath_selects_actual_bound_provider(self):
        files=rootfs();files['usr/bin/python3.14']=row(fixture(needed=('libprivate.so.1',),interp='/lib/ld-linux-aarch64.so.1',runpath='$ORIGIN/../private'),0o755)
        files['usr/private/libprivate.so.1']=row(fixture(needed=('libc.so.6',),soname='libprivate.so.1'))
        report=elf.audit_closure(files)
        edge=next(edge for edge in report['edges']if edge['requester']=='usr/bin/python3.14'and edge['kind']=='DT_NEEDED')
        self.assertEqual(edge['provider'],'usr/private/libprivate.so.1')

    def test_runpath_is_not_inherited_by_grandchildren(self):
        files=rootfs();files['usr/bin/python3.14']=row(fixture(needed=('libparent.so.1',),interp='/lib/ld-linux-aarch64.so.1',runpath='/usr/private'),0o755)
        files['usr/private/libparent.so.1']=row(fixture(needed=('libchild.so.1',),soname='libparent.so.1'))
        files['usr/private/libchild.so.1']=row(fixture(soname='libchild.so.1'))
        with self.assertRaisesRegex(ValueError,'libchild.so.1'):elf.audit_closure(files)

    def test_unsupported_rpath_empty_cwd_tokens_and_escape_refuse(self):
        for options in (dict(rpath='/usr/lib'),dict(runpath=''),dict(runpath=':/usr/lib'),
                        dict(runpath='relative'),dict(runpath='$LIB'),dict(runpath='$ORIGIN/../../../outside')):
            files=rootfs();files['usr/bin/bwrap']=row(fixture(needed=('libc.so.6',),**options),0o755)
            with self.subTest(options=options),self.assertRaises(ValueError):elf.audit_closure(files)

    def test_legacy_rpath_is_ignored_only_when_runpath_present(self):
        files=rootfs();files['usr/bin/bwrap']=row(fixture(needed=('libc.so.6',),rpath='/not-used',runpath='/usr/lib'),0o755)
        self.assertEqual(elf.audit_closure(files)['status'],'PASS_STATIC_AARCH64_ELF_DEPENDENCY_CLOSURE')

    def test_absolute_needed_requires_exact_physical_path(self):
        files=rootfs();files['usr/bin/bwrap']=row(fixture(needed=('/usr/lib/libc.so.6',)),0o755)
        self.assertEqual(elf.audit_closure(files)['status'],'PASS_STATIC_AARCH64_ELF_DEPENDENCY_CLOSURE')
        files['usr/bin/bwrap']=row(fixture(needed=('private/libc.so.6',)),0o755)
        with self.assertRaises(ValueError):elf.audit_closure(files)

    def test_aliases_must_be_materialized_and_identical(self):
        files=rootfs();files['lib/libdemo.so.1']=copy.deepcopy(files['usr/lib/libdemo.so.1'])
        elf.audit_closure(files)
        files['lib/libdemo.so.1']=row(fixture(soname='libdemo.so.1'))
        with self.assertRaisesRegex(ValueError,'conflicting materialized'):elf.audit_closure(files)
        files=rootfs();files['lib/libdemo.so.1']=files.pop('usr/lib/libdemo.so.1')
        with self.assertRaisesRegex(ValueError,'canonical /usr/lib'):elf.audit_closure(files)

    def test_reserved_paths_modes_links_and_collisions_refuse(self):
        for path in ('probe/tool','init','proc/x','dev/null','tmp/cache','home/alarm/x','var/lib/pacman/local/x','../escape','/usr/file'):
            files=rootfs();files[path]=row(b'not ELF')
            with self.subTest(path=path),self.assertRaises(ValueError):elf.audit_closure(files)
        for mode in (0o4755,0o120777,0o100644,True):
            files=rootfs();files['usr/bin/busybox']['mode']=mode
            with self.subTest(mode=mode),self.assertRaises(ValueError):elf.audit_closure(files)
        files=rootfs();files['usr']=row(b'file collides with descendants')
        with self.assertRaisesRegex(ValueError,'collision'):elf.audit_closure(files)

    def test_cache_preload_and_hwcaps_cannot_shadow_audited_providers(self):
        for path in ('etc/ld.so.cache','etc/ld.so.preload','usr/lib/glibc-hwcaps/a/libc.so.6','usr/lib/tls/libc.so.6'):
            files=rootfs();files[path]=row(fixture(soname='libother.so'))
            with self.subTest(path=path),self.assertRaises(ValueError):elf.audit_closure(files)

    def test_whole_file_map_row_and_byte_caps(self):
        with self.assertRaisesRegex(ValueError,'row count'):elf.audit_closure({'usr/share/item'+str(i):row(b'')for i in range(elf.MAX_ROWS+1)})
        files=rootfs();files['usr/share/nonimmutable']=row(bytearray(b'changed'))
        with self.assertRaises(ValueError):elf.audit_closure(files)
        files=rootfs();files['usr/share/large']=row(b'x'*(elf.MAX_FILE+1))
        with self.assertRaises(ValueError):elf.audit_closure(files)


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ElfControls))
    print(json.dumps(dict(status='PASS'if result.wasSuccessful()else'FAIL',tests=result.testsRun,failures=len(result.failures),
        errors=len(result.errors),skipped=len(result.skipped),evidence='SYNTHETIC_ELF_BYTES_NOT_EXECUTED',
        ELF_execution=0,readelf_subprocess=0,download=0,guest_native='NOT_RUN'),sort_keys=True))
    raise SystemExit(not result.wasSuccessful()or bool(result.skipped))
