# SPDX-License-Identifier: MIT
"""Synthetic inert ELF/archive fixtures. No installed or target execution."""
import copy
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('elf_audit',Path(__file__).with_name('elf_audit.py'))
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)


def elf(bits=64,endian='<',machine=183,kind=3,needed=('libc.so.6',),soname=None,interp='/lib/ld-linux-aarch64.so.1',rpath=None):
    size=2048;data=bytearray(size);cls=1 if bits==32 else 2
    data[:16]=b'\x7fELF'+bytes([cls,1 if endian=='<' else 2,1,0])+b'\0'*8
    eh,ph=(52,32) if bits==32 else (64,56)
    strings=bytearray(b'\0');tags=[]
    for tag,value in [(1,n) for n in needed]+[(14,soname),(15,rpath)]:
        if value is not None:tags.append((tag,len(strings)));strings.extend(value.encode()+b'\0')
    tags.extend([(5,512),(10,len(strings)),(0,0)])
    step=8 if bits==32 else 16
    dynamic=b''.join(struct.pack(endian+('iI' if bits==32 else 'qQ'),*tag) for tag in tags)
    headers=[]
    if interp:
        raw=interp.encode()+b'\0';data[256:256+len(raw)]=raw;headers.append((3,256,256,0,len(raw),len(raw),4,1))
    headers += [(1,0,0,0,size,size,5,16384),(2,320,320,0,len(dynamic),len(dynamic),4,8)]
    fields=(kind,machine,1,0,eh,0,0,eh,ph,len(headers),0,0,0)
    struct.pack_into(endian+('HHIIIIIHHHHHH' if bits==32 else 'HHIQQQIHHHHHH'),data,16,*fields)
    for index,p in enumerate(headers):
        values=p if bits==32 else (p[0],p[6],p[1],p[2],p[3],p[4],p[5],p[7])
        struct.pack_into(endian+('IIIIIIII' if bits==32 else 'IIQQQQQQ'),data,eh+index*ph,*values)
    data[320:320+len(dynamic)]=dynamic;data[512:512+len(strings)]=strings
    return data


def header(data,index,field,value):
    fields=list(struct.unpack_from('<IIQQQQQQ',data,64+index*56));fields[field]=value
    struct.pack_into('<IIQQQQQQ',data,64+index*56,*fields);return data


class ParserTests(unittest.TestCase):
    def test_dynamic_identity_interpreter_needed_soname(self):
        result=a.parse_elf(elf(soname='libdemo.so',needed=('liba.so','libb.so'),rpath='$ORIGIN/../lib'))
        self.assertEqual(result['needed'],['liba.so','libb.so']);self.assertEqual(result['soname'],'libdemo.so')
        self.assertEqual(result['rpath'],'$ORIGIN/../lib');self.assertEqual(result['interpreter'],'/lib/ld-linux-aarch64.so.1')
        self.assertEqual(result['classification'],'aarch64-loadable-elf');self.assertFalse(result['runtime_load_verified'])
    def test_32_and_big_endian_are_parsed_but_not_target_provider_identity(self):
        for bits,order,machine in [(32,'<',40),(32,'>',164),(64,'>',183),(64,'<',247),(64,'<',0)]:
            with self.subTest(bits=bits,order=order,machine=machine):
                result=a.parse_elf(elf(bits=bits,endian=order,machine=machine))
                self.assertEqual(result['machine'],machine);self.assertEqual(result['needed'],['libc.so.6'])
                self.assertNotEqual(result['classification'],'aarch64-loadable-elf')
    def test_bpf_relocatable_is_data(self):
        result=a.parse_elf(elf(machine=247,kind=1));self.assertEqual(result['classification'],'relocatable-elf-data')
    def test_non_elf_not_labeled(self):self.assertIsNone(a.parse_elf(b'not executable'))
    def test_every_header_truncation_refuses(self):
        data=elf()
        for length in range(4,64):
            with self.subTest(length=length),self.assertRaises(ValueError):a.parse_elf(data[:length])
    def test_identification_and_header_version_size(self):
        for offset,value in [(4,0),(5,0),(6,0),(20,0),(52,0)]:
            data=elf();data[offset]=value
            with self.subTest(offset=offset),self.assertRaises(ValueError):a.parse_elf(data)
    def test_program_table_bad_ranges_sizes_and_extended_counts(self):
        for offset,fmt,value in [(32,'Q',2**64-1),(32,'Q',1),(54,'H',55),(56,'H',257),(56,'H',65535)]:
            data=elf();struct.pack_into('<'+fmt,data,offset,value)
            with self.subTest(offset=offset,value=value),self.assertRaises(ValueError):a.parse_elf(data)
    def test_section_table_range_extended_and_nobits(self):
        data=elf();struct.pack_into('<Q',data,40,1600);struct.pack_into('<H',data,58,64);struct.pack_into('<H',data,60,1)
        struct.pack_into('<IIQQQQIIQQ',data,1600,0,8,0,0,2**63,100,0,0,1,0)
        self.assertIsNotNone(a.parse_elf(data))
        for offset,fmt,value in [(40,'Q',2040),(60,'H',0),(62,'H',1),(62,'H',65535)]:
            bad=data.copy();struct.pack_into('<'+fmt,bad,offset,value)
            with self.subTest(offset=offset,value=value),self.assertRaises(ValueError):a.parse_elf(bad)
        struct.pack_into('<I',data,1604,1)
        with self.assertRaisesRegex(ValueError,'elf-file-range'):a.parse_elf(data)
    def test_segments_file_ranges_memory_overflow_and_alignment(self):
        for field,value in [(2,2**63),(5,4096),(6,1),(3,2**64-1),(7,3)]:
            with self.subTest(field=field),self.assertRaises(ValueError):a.parse_elf(header(elf(),1,field,value))
    def test_16k_congruence_and_alignment_are_separate_observations(self):
        data=header(elf(),1,7,4096);r=a.parse_elf(data)
        self.assertTrue(r['insufficient_declared_16K_alignment']);self.assertEqual(r['static_16K_observation'],'load-congruence-observed')
        # File and virtual address agree modulo4K but disagree modulo16K.
        data=header(data,1,3,4096);data=header(data,2,3,4416)
        # Relocate DT_STRTAB pointer to match the changed virtual-address mapping.
        struct.pack_into('<Q',data,320+16+8,4608)
        r=a.parse_elf(data);self.assertEqual(r['static_16K_observation'],'load-congruence-not-observed')
        self.assertTrue(r['PT_LOAD'][0]['offset_vaddr_congruent_declared_alignment']);self.assertFalse(r['runtime_load_verified'])
    def test_interp_duplicates_termination_and_order(self):
        data=elf();data[256+len('/lib/ld-linux-aarch64.so.1')]=1
        with self.assertRaisesRegex(ValueError,'elf-interpreter-termination'):a.parse_elf(data)
        for index in (1,2):
            data=header(elf(),index,0,3)
            with self.subTest(index=index),self.assertRaises(ValueError):a.parse_elf(data)
    def test_causal_dynamic_virtual_mapping_three_counterexamples(self):
        for address,reason in ((4096,'elf-dynamic-mapping'),(1024,'elf-dynamic-offset-disagreement'),(2**64-1,'elf-dynamic-overflow')):
            data=elf(interp=None,needed=('not-real-loader-needed.so',),soname='libproof.so')
            header(data,1,3,address)
            with self.subTest(address=address),self.assertRaisesRegex(ValueError,reason):a.parse_elf(data)
    def test_dynamic_memory_extent_and_entry_boundary_refusal(self):
        for memory in (0,1,48,63,65,80,2**64-1):
            with self.subTest(memory=memory),self.assertRaisesRegex(ValueError,'elf-dynamic-memory-extent'):
                a.parse_elf(header(elf(),2,6,memory))
        # A terminator exists physically after the declared file/memory table.
        data=header(header(elf(),2,5,48),2,6,48)
        with self.assertRaisesRegex(ValueError,'elf-dynamic-termination'):a.parse_elf(data)
        data=header(header(elf(),2,5,65),2,6,65)
        with self.assertRaisesRegex(ValueError,'elf-dynamic-bound'):a.parse_elf(data)
    def test_dynamic_bss_and_ambiguous_load_mapping_refusal(self):
        data=header(header(elf(),1,6,4096),2,3,2048)
        with self.assertRaisesRegex(ValueError,'elf-dynamic-mapping'):a.parse_elf(data)
        data=elf(interp=None);struct.pack_into('<H',data,56,3)
        struct.pack_into('<IIQQQQQQ',data,176,1,5,0,0,0,2048,2048,16384)
        with self.assertRaisesRegex(ValueError,'elf-dynamic-mapping'):a.parse_elf(data)
    def test_dynamic_trailing_entries_never_seed_needed_or_soname(self):
        data=header(header(elf(),2,5,80),2,6,80)
        struct.pack_into('<qQ',data,384,1,2**64-1)
        result=a.parse_elf(data)
        self.assertEqual(result['needed'],['libc.so.6']);self.assertIsNone(result['soname'])
        self.assertEqual(result['PT_DYNAMIC']['entries_after_DT_NULL'],1)
        self.assertEqual(result['PT_DYNAMIC']['nonzero_entries_after_DT_NULL'],1)
    def test_valid_nonzero_load_offset_and_dynamic_address_all_formats(self):
        for bits,endian in ((32,'<'),(32,'>'),(64,'<'),(64,'>')):
            data=elf(bits=bits,endian=endian,interp=None,soname='libproof.so')
            eh,ph,step=(52,32,8) if bits==32 else (64,56,16)
            dynformat=endian+('iI' if bits==32 else 'qQ');phformat=endian+('IIIIIIII' if bits==32 else 'IIQQQQQQ')
            original=list(struct.unpack_from(phformat,data,eh+ph))
            extent=original[4] if bits==32 else original[5]
            dynamic=bytearray(data[320:320+extent]);strings=b''
            for offset in range(0,extent,step):
                tag,value=struct.unpack_from(dynformat,dynamic,offset)
                if tag==10:strings=bytes(data[512:512+value])
                if tag==5:struct.pack_into(dynformat,dynamic,offset,tag,16640+1024-256)
            data[768:768+extent]=dynamic;data[1024:1024+len(strings)]=strings
            load=(1,256,16640,0,1792,1792,5,16384)
            dyn=(2,768,16640+768-256,0,extent,extent,4,8)
            for index,p in enumerate((load,dyn)):
                values=p if bits==32 else (p[0],p[6],p[1],p[2],p[3],p[4],p[5],p[7])
                struct.pack_into(phformat,data,eh+index*ph,*values)
            with self.subTest(bits=bits,endian=endian):
                result=a.parse_elf(data);self.assertEqual(result['needed'],['libc.so.6']);self.assertEqual(result['soname'],'libproof.so')
                self.assertEqual(result['PT_DYNAMIC']['offset'],768);self.assertEqual(result['PT_DYNAMIC']['virtual_address'],17152)
                self.assertTrue(result['PT_DYNAMIC']['file_backed_mapping_verified'])
    def test_dynamic_requires_null_and_aligned_bounded_entries(self):
        data=elf();data[320:384]=b'\xff'*64
        with self.assertRaises(ValueError):a.parse_elf(data)
        for size in (15,16*4097):
            with self.subTest(size=size),self.assertRaises(ValueError):a.parse_elf(header(elf(),2,5,size))
    def test_duplicate_singleton_tags_and_missing_string_table(self):
        for tag in (5,10):
            data=elf();struct.pack_into('<q',data,320,tag)
            with self.subTest(tag=tag),self.assertRaisesRegex(ValueError,'duplicate-dynamic-tag'):a.parse_elf(data)
        data=elf();struct.pack_into('<q',data,336,11)
        with self.assertRaisesRegex(ValueError,'elf-string-table'):a.parse_elf(data)
    def test_string_table_virtual_mapping_and_bss_refusal(self):
        for pointer in (2048,2**64-1):
            data=elf();struct.pack_into('<Q',data,344,pointer)
            with self.subTest(pointer=pointer),self.assertRaisesRegex(ValueError,'elf-string-table-overflow' if pointer==2**64-1 else 'elf-string-table-mapping'):a.parse_elf(data)
    def test_ambiguous_file_backed_string_mapping_refused(self):
        data=elf(interp=None);struct.pack_into('<H',data,56,3)
        struct.pack_into('<IIQQQQQQ',data,176,1,5,512,512,0,1536,1536,16384)
        with self.assertRaisesRegex(ValueError,'elf-string-table-mapping'):a.parse_elf(data)
    def test_nonlinux_osabi_and_nonzero_aarch64_flags_not_provider_identity(self):
        for offset,value in ((7,9),(48,1)):
            data=elf();data[offset]=value
            with self.subTest(offset=offset):self.assertNotEqual(a.parse_elf(data)['classification'],'aarch64-loadable-elf')
    def test_unterminated_control_and_outside_string_indices(self):
        for index in (2000,2**64-1):
            data=elf();struct.pack_into('<Q',data,328,index)
            with self.subTest(index=index),self.assertRaisesRegex(ValueError,'string-offset'):a.parse_elf(data)
        for mutation in ('no-null','control'):
            data=elf();data[522]=ord('x') if mutation=='no-null' else 10
            if mutation=='no-null':struct.pack_into('<Q',data,360,11)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):a.parse_elf(data)
    def test_unreferenced_strtab_still_validated(self):
        data=elf(needed=(),interp=None);struct.pack_into('<Q',data,328,2**64-1)
        with self.assertRaisesRegex(ValueError,'mapping'):a.parse_elf(data)
    def test_empty_string_table_and_first_last_boundary(self):
        self.assertEqual(a.parse_elf(elf(needed=()))['needed'],[])
        empty=elf(needed=(),interp=None);struct.pack_into('<Q',empty,344,0)
        self.assertEqual(a.parse_elf(empty)['needed'],[])
        for offset in (512,522):
            data=elf();data[offset]=1
            with self.subTest(offset=offset),self.assertRaisesRegex(ValueError,'string-table-boundaries'):a.parse_elf(data)
    def test_empty_search_path_preserved(self):self.assertEqual(a.parse_elf(elf(rpath=''))['rpath'],'')


class NamespaceTests(unittest.TestCase):
    def setUp(self):
        self.ns={'usr':{'type':'directory'},'usr/lib':{'type':'directory'},'usr/lib/liba.so.1':{'type':'file','name':'liba'},
                 'lib':{'type':'symlink','target':'usr/lib','name':'filesystem'},'usr/lib/liba.so':{'type':'symlink','target':'liba.so.1','name':'liba'}}
    def object(self,path='usr/lib/liba.so.1',name='liba',soname='liba.so.1',interp=None,needed=()):
        return {'name':name,'path':path,'sha256':'a'*64,'status':'elf-parsed-as-data','ELF':a.parse_elf(elf(soname=soname,interp=interp,needed=needed))}
    def test_prefix_symlink_resolution_and_alias_provider_dedup(self):
        self.assertEqual(a.resolve('/lib/liba.so',self.ns),{'status':'observed-path','path':'usr/lib/liba.so.1'})
        objects=[self.object(),self.object('usr/bin/app','app',None,'/lib/liba.so.1',('liba.so','liba.so.1'))]
        result=a.providers(objects,self.ns)
        self.assertEqual([r['status'] for r in result['requests']],['observed-aarch64-interpreter-candidate','one-observed-provider-candidate','one-observed-provider-candidate'])
        self.assertFalse(result['actual_loader_search_verified'])
    def test_missing_ambiguous_and_tokens_are_conservative(self):
        objects=[self.object(),self.object('opt/lib/liba.so.1','other'),self.object('usr/bin/app','app',None,None,('liba.so.1','missing.so','$ORIGIN/x','relative/x'))]
        statuses=[r['status'] for r in a.providers(objects,self.ns)['requests']]
        self.assertEqual(statuses,['ambiguous-observed-providers','missing-observed-provider','dynamic-token-search-unresolved','relative-needed-path-unresolved'])
    def test_foreign_relocatable_not_provider(self):
        obj=self.object();obj['ELF']['classification']='relocatable-elf-data'
        consumer=self.object('usr/bin/app','app',None,None,('liba.so.1',))
        self.assertEqual(a.providers([obj,consumer],self.ns)['requests'][0]['status'],'missing-observed-provider')
    def test_interp_bearing_soname_library_is_candidate_and_alias_deduplicated(self):
        self.ns.update({'usr/lib/libc.so.6':{'type':'file','name':'glibc'},
                        'usr/lib/libc.so':{'type':'symlink','target':'libc.so.6','name':'glibc'},
                        'usr/lib/ld-linux-aarch64.so.1':{'type':'file','name':'glibc'}})
        lib=self.object('usr/lib/libc.so.6','glibc','libc.so.6','/lib/ld-linux-aarch64.so.1',('ld-linux-aarch64.so.1',))
        linker=self.object('usr/lib/ld-linux-aarch64.so.1','glibc','ld-linux-aarch64.so.1')
        consumer=self.object('usr/bin/app','app',None,None,('libc.so.6','libc.so','/lib/libc.so.6'))
        result=a.providers([lib,linker,consumer],self.ns)
        rows=[r for r in result['requests'] if r['path']=='usr/bin/app']
        self.assertEqual([r['status'] for r in rows],['one-observed-provider-candidate','one-observed-provider-candidate','absolute-path-candidate'])
        self.assertTrue(all(len(r['candidates'])==1 and r['candidates'][0]['path']=='usr/lib/libc.so.6' for r in rows))
        self.assertFalse(result['actual_loader_search_verified'])
    def test_executable_or_no_soname_pie_never_provider_by_name_alias_or_absolute_path(self):
        for kind,soname,interp in ((2,'liba.so.1',None),(3,None,'/lib/ld-linux-aarch64.so.1')):
            producer=self.object();producer['ELF']=a.parse_elf(elf(kind=kind,soname=soname,interp=interp,needed=()))
            consumer=self.object('usr/bin/app','app',None,None,('liba.so.1','liba.so','/lib/liba.so.1'))
            with self.subTest(kind=kind,soname=soname,interp=interp):
                rows=[r for r in a.providers([producer,consumer],self.ns)['requests'] if r['path']=='usr/bin/app']
                self.assertEqual([r['status'] for r in rows],['missing-observed-provider','missing-observed-provider','absolute-path-not-observed-as-library-candidate'])
                self.assertTrue(all(r['candidates']==[] for r in rows))
    def test_no_interp_no_soname_candidate_preserves_basename_alias_and_absolute_route(self):
        producer=self.object(soname=None,interp=None)
        consumer=self.object('usr/bin/app','app',None,None,('liba.so.1','liba.so','/lib/liba.so.1'))
        result=a.providers([producer,consumer],self.ns)
        rows=[r for r in result['requests'] if r['path']=='usr/bin/app']
        self.assertEqual([r['status'] for r in rows],['one-observed-provider-candidate','one-observed-provider-candidate','absolute-path-candidate'])
        self.assertTrue(all(len(r['candidates'])==1 and r['candidates'][0]['path']=='usr/lib/liba.so.1' for r in rows))
        self.assertFalse(result['actual_loader_search_verified'])
    def test_interp_bearing_soname_candidates_remain_ambiguous(self):
        objects=[self.object(interp='/lib/ld-linux-aarch64.so.1'),
                 self.object('opt/lib/liba.so.1','other',interp='/different/loader'),
                 self.object('usr/bin/app','app',None,None,('liba.so.1',))]
        request=[r for r in a.providers(objects,self.ns)['requests'] if r['path']=='usr/bin/app'][0]
        self.assertEqual(request['status'],'ambiguous-observed-providers');self.assertEqual(len(request['candidates']),2)
    def test_actual_bound_libperl_and_lmdb_metadata_preserves_three_requests(self):
        # Projection of historical report294e9576...; actual hashes/version/roles.
        # This checks provider metadata only, never executes these package files.
        def observed(name,version,path,digest,soname,interp,needed):
            return {'name':name,'version':version,'path':path,'sha256':digest,'status':'elf-parsed-as-data',
                    'ELF':{'classification':'aarch64-loadable-elf','type':3,'soname':soname,'interpreter':interp,'needed':needed}}
        perl=observed('perl','5.42.3-1','usr/lib/perl5/5.42/core_perl/CORE/libperl.so',
                      'e297d19f8975344a28bf0828cf4d9cfadb7fbfb88e188d53684fed8638a04b43',None,None,
                      ['libm.so.6','libcrypt.so.2','libc.so.6','ld-linux-aarch64.so.1'])
        lmdb=observed('lmdb','0.9.35-1','usr/lib/liblmdb.so',
                      '659e9d3ed8c90fbb3a04ce4dff973050cbdb55522f1a8388551d0b26db6cccf5',None,None,
                      ['libc.so.6','ld-linux-aarch64.so.1'])
        app=observed('perl','5.42.3-1','usr/bin/perl',
                     '056a9ecb8dd9192027b2849190a266aea08c3c4197e6bbac754205cf9115f7dc',None,'/lib/ld-linux-aarch64.so.1',
                     ['libperl.so','libc.so.6'])
        tex=observed('texinfo','7.3-1','usr/lib/texi2any/lib/libtexinfo-main.so.0.0.0',
                     '6b2c88a6321e56fd3dc2458926d69f7ebc0836c03fcdb3fe3445cbc8a42ce683','libtexinfo-main.so.0',None,
                     ['libtexinfo-convert.so.1','libtexinfoxs.so.1','libtexinfo.so.1','libunistring.so.5','libperl.so','libc.so.6','ld-linux-aarch64.so.1'])
        krb=observed('krb5','1.22.2-1','usr/lib/krb5/plugins/kdb/klmdb.so',
                     '50e95f8bc78d05d489b8bdc531c55b527eaa7e049bc10a1fb1680e3ae1cbb8c8','klmdb.so.0',None,
                     ['libkadm5srv_mit.so.12','libkdb5.so.10','libgssrpc.so.4','libgssapi_krb5.so.2','libkrb5.so.3','libk5crypto.so.3','libcom_err.so.2','libkrb5support.so.0','libkeyutils.so.1','libresolv.so.2','liblmdb.so','libc.so.6','ld-linux-aarch64.so.1'])
        result=a.providers([perl,lmdb,app,tex,krb],{})
        rows=[r for r in result['requests'] if r['requested'] in ('libperl.so','liblmdb.so')]
        self.assertEqual(len(rows),3)
        self.assertEqual({(r['name'],r['requested']) for r in rows},{('perl','libperl.so'),('texinfo','libperl.so'),('krb5','liblmdb.so')})
        for r in rows:
            self.assertEqual(r['status'],'one-observed-provider-candidate');self.assertEqual(len(r['candidates']),1)
            self.assertEqual(r['candidates'][0]['path'],perl['path'] if r['requested']=='libperl.so' else lmdb['path'])
        self.assertFalse(result['actual_loader_search_verified'])
    def test_invalid_soname_type_cannot_seed_candidate(self):
        for soname in ('',True,1,[],{}):
            producer=self.object();producer['ELF']['soname']=soname
            consumer=self.object('usr/bin/app','app',None,None,('liba.so.1',))
            with self.subTest(soname=soname):
                row=a.providers([producer,consumer],self.ns)['requests'][-1]
                self.assertEqual(row['status'],'missing-observed-provider');self.assertEqual(row['candidates'],[])
    def test_cycles_escape_file_ancestor_and_depth(self):
        for target,status in [('liba.so','link-cycle'),('../../../../outside','escapes-observed-root'),('liba.so.1/child','non-directory-ancestor')]:
            ns=copy.deepcopy(self.ns);ns['usr/lib/liba.so']['target']=target
            self.assertEqual(a.resolve('usr/lib/liba.so',ns)['status'],status)
        ns={f'p{i}':{'type':'symlink','target':f'p{i+1}','name':'a'} for i in range(41)};ns['p41']={'type':'file','name':'a'}
        self.assertEqual(a.resolve('p0',ns)['status'],'link-depth-bound')
    def test_hardlink_same_package_regular_only(self):
        ns=copy.deepcopy(self.ns);ns['hard']={'type':'hardlink','target':'usr/lib/liba.so.1','name':'liba'}
        self.assertEqual(a.resolve('hard',ns)['path'],'usr/lib/liba.so.1')
        ns['hard']['name']='foreign';self.assertEqual(a.resolve('hard',ns)['status'],'hardlink-target-unverified')


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='elf-inert-fixture-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def reference(self,path):return {'path':str(path),'size':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    def package(self,entries):
        stream=io.BytesIO();nodes=[]
        with tarfile.open(fileobj=stream,mode='w') as tar:
            for name,data in entries:
                member=tarfile.TarInfo(name);member.size=len(data);member.mode=0o755;tar.addfile(member,io.BytesIO(data))
                nodes.append({'path':name,'type':'file','bytes':len(data),'mode':0o755,'sha256':hashlib.sha256(data).hexdigest()})
        path=self.root/'archive.tar.xz';path.write_bytes(lzma.compress(stream.getvalue()))
        return {'name':'fixture','archive':self.reference(path)},{'name':'fixture','version':'1-1','nodes':nodes,'controls':{}}
    def inspect(self,row,p,budget=None):return a.inspect_archive(row,p,budget or {'decoded':0,'nodes':0},a.time.monotonic()+10)
    def test_actual_inert_archive_and_whole_file_hash_correlation(self):
        row,p=self.package([('usr/bin/demo',elf()),('usr/share/text',b'plain data')]);result=self.inspect(row,p)
        self.assertEqual(len(result),1);self.assertEqual(result[0]['status'],'elf-parsed-as-data')
    def test_firmware_elf_not_a_runtime_provider(self):
        row,p=self.package([('usr/lib/firmware/device/image',elf())]);result=self.inspect(row,p)
        self.assertEqual(result[0]['ELF']['classification'],'firmware-elf-data-observed')
    def test_parser_refusal_retained_as_data_failure(self):
        row,p=self.package([('usr/bin/demo',b'\x7fELFbroken')]);result=self.inspect(row,p)
        self.assertEqual(result[0]['status'],'elf-parser-refused')
    def test_archive_duplicate_traversal_and_declared_hash_refused(self):
        for entries in ([('x',b'x'),('x',b'x')],[('../x',b'x')]):
            row,p=self.package(entries)
            with self.subTest(entries=entries),self.assertRaises(ValueError):self.inspect(row,p)
        row,p=self.package([('x',b'x')]);p['nodes'][0]['sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'hash-binding'):self.inspect(row,p)
    def test_pre_cap_deadline_node_and_decoded_failures(self):
        row,p=self.package([('x',b'x')])
        with mock.patch.object(a,'FILE_LIMIT',0),self.assertRaises(ValueError):self.inspect(row,p)
        with mock.patch.object(a,'TOTAL_NODES',0),self.assertRaises(ValueError):self.inspect(row,p)
        with mock.patch.object(a,'TOTAL_DECODED',1),self.assertRaises(ValueError):self.inspect(row,p)
        with self.assertRaisesRegex(ValueError,'deadline'):a.inspect_archive(row,p,{'decoded':0,'nodes':0},0)
    def test_reference_snapshot_survives_path_replacement_and_refuses_symlink_hardlink(self):
        row,p=self.package([('x',b'x')]);path=Path(row['archive']['path']);original=path.read_bytes()
        with a.snapshot(row['archive'],a.ARCHIVE_LIMIT) as captured:
            path.unlink();path.write_bytes(b'replaced');self.assertEqual(captured.read(),original)
        link=self.root/'symlink';link.symlink_to(path)
        with self.assertRaises(OSError):
            with a.snapshot(self.reference(link),a.ARCHIVE_LIMIT):pass
        hard=self.root/'hard';os.link(path,hard)
        with self.assertRaisesRegex(ValueError,'reference-file'):
            with a.snapshot(self.reference(path),a.ARCHIVE_LIMIT):pass
    def test_reference_bad_sizes_refuse_before_open(self):
        for value in (True,False,-1,0,1.0,None,'1',a.ARCHIVE_LIMIT+1):
            row={'path':'/tmp/not-read','size':value,'sha256':'a'*64}
            with self.subTest(value=value),mock.patch.object(a.os,'open') as opened,self.assertRaises(ValueError):
                with a.snapshot(row,a.ARCHIVE_LIMIT):pass
            opened.assert_not_called()
    def test_write_owned_bounded_fresh_private_output(self):
        directory=self.root/'private';directory.mkdir(mode=0o700);path=directory/'report.json'
        with mock.patch.object(a,'ARTIFACTS',self.root):
            a.write_private(path,{'data':'inert'});self.assertEqual(path.stat().st_mode&0o7777,0o600)
            with self.assertRaises(FileExistsError):a.write_private(path,{})
            with mock.patch.object(a,'JSON_LIMIT',1),self.assertRaises(ValueError):a.write_private(directory/'too-large',{})
            self.assertFalse((directory/'too-large').exists())


class RunTests(unittest.TestCase):
    def setUp(self):
        self.fixture=ArchiveTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        row,p=self.fixture.package([('usr/bin/demo',elf()),('.PKGINFO',b'pkgname = fixture\npkgver = 1-1\narch = aarch64\n')])
        control=p['nodes'].pop();p['controls']={'.PKGINFO':control}
        p.update(archive=row['archive'],status='payload-inspected-as-data',missing_declared_paths=[],undeclared_archive_paths=[])
        self.payload={'archives':[row]}
        self.report={'kind':'inert-exact-package-payload-link-hook-observation','source_sha256':a.PAYLOAD_SOURCE,
                     'inputs':self.payload,'archive_unavailable_packages':[],'observed_non_directory_overlaps':[],
                     'selected_final_count':1,'inspected_package_count':1,'packages':[p]}
        self.auth={'installed_image_authenticated':False,'source_grants_complete':False}
        self.counter=0
        self.contract=self.freeze()
    def put(self,data):
        self.counter+=1;path=self.fixture.root/('input'+str(self.counter)+'.json');path.write_text(json.dumps(data))
        return self.fixture.reference(path)
    def freeze(self):
        payload=self.put(self.payload);report=self.put(self.report);auth=self.put(self.auth)
        handoff={'payload_contract':payload,'payload_report':report,'authentication_bindings':auth,
                 'status':'ACTUAL-PASS-all624-supplied-archives-inspected-as-data','selected_final_packages':1,'supplied_archives':1,'inspected_archives':1}
        return {'schema_version':1,'payload_contract':payload,'payload_report':report,'payload_handoff':self.put(handoff),'authentication_bindings':auth}
    def run_fixture(self):
        # The one-package fixture mocks only the fixed624 count, never ELF/read/hash code.
        with mock.patch.object(a,'PACKAGE_COUNT',1):return a.run(self.contract)
    def test_full_fixture_pipeline_retains_missing_provider_without_runtime_acceptance(self):
        result=self.run_fixture();self.assertEqual(result['status'],'PASS-static-data-inspection')
        self.assertTrue(result['loader']['candidate_inventory_complete']);self.assertEqual(len(result['objects']),1)
        self.assertEqual(result['loader']['requests'][-1]['status'],'missing-observed-provider')
        for flag in ('payloads_executed','system_mutation','installed_image_authenticated','actual_16K_execution_verified','hardware_accepted'):self.assertFalse(result[flag])
    def test_report_and_handoff_binding_refused_before_archive_reads(self):
        for key,value in [('source_sha256','f'*64),('archive_unavailable_packages',['missing']),('observed_non_directory_overlaps',[{}]),('selected_final_count',True)]:
            original=copy.deepcopy(self.report);self.report[key]=value;self.contract=self.freeze()
            with self.subTest(key=key),mock.patch.object(a,'inspect_archive') as inspected,self.assertRaises(ValueError):self.run_fixture()
            inspected.assert_not_called();self.report=original
        self.contract['schema_version']=True
        with mock.patch.object(a,'inspect_archive') as inspected,self.assertRaises(ValueError):self.run_fixture()
        inspected.assert_not_called()
    def test_bad_reference_accounting_before_capture(self):
        for size in (True,-1,0,1.5,None,a.ARCHIVE_LIMIT+1):
            original=copy.deepcopy(self.payload);self.payload['archives'][0]['archive']['size']=size
            self.report['inputs']=self.payload;self.report['packages'][0]['archive']=self.payload['archives'][0]['archive'];self.contract=self.freeze()
            with self.subTest(size=size),mock.patch.object(a,'inspect_archive') as inspected,self.assertRaises(ValueError):self.run_fixture()
            inspected.assert_not_called();self.payload=original;self.report['inputs']=self.payload;self.report['packages'][0]['archive']=self.payload['archives'][0]['archive']
    def test_aggregate_bound_before_archive_capture(self):
        self.contract=self.freeze()
        with mock.patch.object(a,'COMPRESSED_LIMIT',1),mock.patch.object(a,'inspect_archive') as inspected,self.assertRaisesRegex(ValueError,'aggregate-preflight'):self.run_fixture()
        inspected.assert_not_called()
    def test_real_two_gib_accounting_boundary_without_payload_allocation(self):
        original=copy.deepcopy(self.report['packages'][0]);sizes=[300000000]*7+[2*1024**3-2100000000]
        for over in (False,True):
            rows=[];packages=[]
            for index,size in enumerate(sizes):
                ref={'path':str(self.fixture.root/('never-read'+str(index))),'size':size+(1 if over and index==7 else 0),'sha256':'a'*64}
                row={'name':'fixture'+str(index),'archive':ref};p=copy.deepcopy(original)
                p.update(name=row['name'],archive=ref);p['nodes'][0]['path']='usr/bin/demo'+str(index)
                rows.append(row);packages.append(p)
            payload={'archives':rows};report=copy.deepcopy(self.report)
            report.update(inputs=payload,packages=packages,selected_final_count=8,inspected_package_count=8)
            payloadref=self.put(payload);reportref=self.put(report);authref=self.put(self.auth)
            hand={'payload_contract':payloadref,'payload_report':reportref,'authentication_bindings':authref,
                  'status':'ACTUAL-PASS-all624-supplied-archives-inspected-as-data','selected_final_packages':8,'supplied_archives':8,'inspected_archives':8}
            contract={'schema_version':1,'payload_contract':payloadref,'payload_report':reportref,'payload_handoff':self.put(hand),'authentication_bindings':authref}
            with self.subTest(over=over),mock.patch.object(a,'PACKAGE_COUNT',8),mock.patch.object(a,'inspect_archive',return_value=[]) as inspected:
                if over:
                    with self.assertRaisesRegex(ValueError,'aggregate-preflight'):a.run(contract)
                    inspected.assert_not_called()
                else:
                    self.assertEqual(a.run(contract)['status'],'PASS-static-data-inspection');self.assertEqual(inspected.call_count,8)
    def test_duplicate_paths_controls_and_node_caps_before_capture(self):
        package=self.report['packages'][0]
        for case in ('duplicate','control-path','node-cap'):
            original=copy.deepcopy(package)
            if case=='duplicate':package['nodes'].append(package['nodes'][0])
            if case=='control-path':package['controls']['.PKGINFO']['path']='other'
            self.contract=self.freeze()
            with self.subTest(case=case),mock.patch.object(a,'inspect_archive') as inspected,mock.patch.object(a,'TOTAL_NODES',1 if case=='node-cap' else 500000),self.assertRaises(ValueError):self.run_fixture()
            inspected.assert_not_called();package.clear();package.update(original)
    def test_dynamic_refusal_leaves_incomplete_provider_inventory(self):
        data=header(elf(interp=None,needed=('not-real-loader-needed.so',),soname='libproof.so'),1,3,1024)
        row,p=self.fixture.package([('usr/bin/demo',data),('.PKGINFO',b'pkgname = fixture\npkgver = 1-1\narch = aarch64\n')])
        control=p['nodes'].pop();p['controls']={'.PKGINFO':control}
        p.update(archive=row['archive'],status='payload-inspected-as-data',missing_declared_paths=[],undeclared_archive_paths=[])
        self.payload={'archives':[row]};self.report.update(inputs=self.payload,packages=[p]);self.contract=self.freeze()
        result=self.run_fixture();self.assertEqual(result['status'],'FAIL-static-data-inspection')
        self.assertFalse(result['loader']['candidate_inventory_complete']);self.assertEqual(result['loader']['requests'],[])
        self.assertEqual(result['objects'][0]['status'],'elf-parser-refused')
        self.assertEqual(result['objects'][0]['reason'],'elf-dynamic-offset-disagreement')
    def test_mutated_archive_receipt_is_retained_failure_and_incomplete_candidates(self):
        path=Path(self.payload['archives'][0]['archive']['path']);path.write_bytes(b'changed')
        result=self.run_fixture();self.assertEqual(result['status'],'FAIL-static-data-inspection')
        self.assertFalse(result['loader']['candidate_inventory_complete']);self.assertEqual(result['packages'][0]['status'],'archive-refused')


if __name__=='__main__':unittest.main()
