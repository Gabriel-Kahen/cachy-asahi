#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New archive custody DATA controls using exact frozen public payload bytes."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
SOURCE=Path(os.environ['PLATFORM_NATIVE_SOURCE']).absolute()
NATIVE=SOURCE/'native'
sys.dont_write_bytecode=True
sys.path.insert(0,str(NATIVE))
def deny(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in {'os.system','os.exec','os.posix_spawn','os.fork'}:
        raise AssertionError('archive DATA controls forbid actors:'+event)
sys.addaudithook(deny)
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
P=module('platform_archive_projection_tested',NATIVE/'platform_projection_v1.py')
R=module('platform_archive_reader_tested',NATIVE/'platform_reader_v1.py')
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

class View:
    def __init__(self,root):self.root=root
    def read(self,name):return (self.root/name).read_bytes()
    def load(self,name):return json.loads(self.read(name))

def make_tar(rows,format=tarfile.USTAR_FORMAT):
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w',format=format) as archive:
        for original,raw in rows:
            member=copy.copy(original);member.size=0 if raw is None else len(raw)
            archive.addfile(member,None if raw is None else io.BytesIO(raw))
    return buffer.getvalue()

class ArchivePrivacyControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract=json.loads((NATIVE/'platform-contract-v1.json').read_bytes())
        bundle=cls.contract['bundle'];raw=(SOURCE/bundle['path']).read_bytes()
        assert P.C.pin(raw)=={k:bundle[k] for k in ('bytes','sha256')}
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
            recipe={member.name.removeprefix('recipe/'):archive.extractfile(member).read() for member in archive}
        assert len(recipe)==13
        for name,pin in cls.contract['recipe']['source_files'].items():assert P.C.pin(recipe[name])=={k:pin[k] for k in ('bytes','sha256')}
        with tarfile.open(fileobj=io.BytesIO(recipe['private-source.tar.gz']),mode='r:gz') as archive:
            originals={member.name:archive.extractfile(member).read() for member in archive}
        payload={}
        for name,pin in cls.contract['recipe']['payload_files'].items():
            prefix='usr/lib/cachy-asahi/platform-tools/'
            raw=originals['private/'+name[len(prefix):]] if name.startswith(prefix+'scripts/') else recipe[Path(name).name]
            assert P.C.pin(raw)=={k:pin[k] for k in ('bytes','sha256')}
            payload[name]=raw
        assert len(payload)==23
        cls.payload=payload
        cls.metadata={'.PKGINFO':(HERE/'fixtures/PKGINFO').read_bytes(),
            '.BUILDINFO':('format = 2\npkgname = cachy-asahi-platform-tools\npkgbase = cachy-asahi-platform-tools\npkgver = 0.1.0-1\npkgarch = any\n'
             'pkgbuild_sha256sum = '+cls.contract['recipe']['source_files']['PKGBUILD']['sha256']+'\nbuildenv = check\n'+
             ''.join('installed = '+row+'\n' for row in cls.contract['buildinfo_installed'])).encode(),
            '.MTREE':b'ORIGINAL INERT METADATA MODEL; no native result\n'}
    def setUp(self):
        self.rows=[]
        ancestors={str(parent) for name in self.payload for parent in Path(name).parents if str(parent)!='.'}
        for name in sorted(ancestors):
            member=tarfile.TarInfo(name);member.type=tarfile.DIRTYPE;member.mode=0o755;self.rows.append((member,None))
        for name,raw in sorted({**self.payload,**self.metadata}.items()):
            member=tarfile.TarInfo(name);member.mode=self.contract['recipe']['payload_files'].get(name,{'mode':0o644})['mode'];self.rows.append((member,raw))
        self.raw=make_tar(self.rows)
    def row(self,raw=None,label='a',index=0):
        raw=self.raw if raw is None else raw;fixed=Path(self.contract['invocation']['source']).parent
        return dict(step='archive-'+label,log='%03d-archive-%s.log'%(index,label),expected=0,
                    argv=['/usr/bin/zstd','-dc',str(fixed/'build-inputs'/label/self.contract['recipe']['archive'])],log_pin=P.C.pin(raw))
    def checked(self,raw=None,row=None,index=0):
        raw=self.raw if raw is None else raw;row=self.row(raw,index=index) if row is None else row
        projected=P.archive_custody(raw,row,self.contract,index)
        independent=R.platform_archive_custody(raw,row,self.contract,index,P.PRIVATE_MARKER)
        self.assertEqual(projected,independent)
        return projected
    def refused(self,raw,row=None,index=0):
        row=self.row(raw,index=index) if row is None else row
        for function,args in ((P.archive_custody,(raw,row,self.contract,index)),(R.platform_archive_custody,(raw,row,self.contract,index,P.PRIVATE_MARKER))):
            with self.subTest(parser=function.__name__),self.assertRaises(Exception):function(*args)
    def altered(self,name,transform):
        return make_tar([(member,transform(raw) if member.name==name else raw) for member,raw in self.rows])
    def test_real23_public_source_identifier_has_exact_custody(self):
        body=self.payload['usr/lib/cachy-asahi/platform-tools/scripts/platform/authenticate_missing.py']
        self.assertIn(b'private_key_access',body);self.assertIsNotNone(P.PRIVATE_MARKER.search(self.raw))
        result=self.checked();self.assertEqual(result['payload_files'],23);self.assertEqual(result['raw_pin'],P.C.pin(self.raw))
        self.assertGreaterEqual(result['framing']['zero_trailer_bytes'],1024)
    def test_both_exact_decoder_labels_and_source_rows(self):
        self.checked(row=self.row(label='b',index=7),index=7)
    def test_changed_public_source_body_refuses_after_repin(self):
        name='usr/lib/cachy-asahi/platform-tools/scripts/platform/authenticate_missing.py'
        self.refused(self.altered(name,lambda raw:raw+b'\n# altered public code\n'))
    def test_metadata_marker_refused_without_payload_change(self):
        self.refused(self.altered('.MTREE',lambda raw:raw+b'password=must-not-export\n'))
    def test_header_marker_refused_with_valid_tar_checksum(self):
        rows=copy.deepcopy(self.rows);rows[0][0].uname='PRIVATE_KEY';self.refused(make_tar(rows))
    def test_nonzero_file_padding_refused(self):
        with tarfile.open(fileobj=io.BytesIO(self.raw),mode='r:') as archive:
            member=next(member for member in archive if member.isfile() and member.size%512)
        raw=bytearray(self.raw);raw[member.offset_data+member.size]=1;self.refused(bytes(raw))
    def test_trailing_marker_refused_after_valid_end_blocks(self):
        self.refused(self.raw+b'PRIVATE_KEY'+bytes(512-len(b'PRIVATE_KEY')))
    def test_negative_member_size_refused(self):
        with tarfile.open(fileobj=io.BytesIO(self.raw),mode='r:') as archive:member=next(member for member in archive if member.name=='.MTREE')
        raw=bytearray(self.raw);header=bytearray(raw[member.offset:member.offset+512]);header[124:136]=b'-0000000001\0';header[148:156]=b'        '
        header[148:156]=('%06o\0 '%sum(header)).encode();raw[member.offset:member.offset+512]=header;self.refused(bytes(raw))
    def test_single_zero_end_block_refused(self):
        with tarfile.open(fileobj=io.BytesIO(self.raw),mode='r:') as archive:members=list(archive)
        last=members[-1];cursor=last.offset_data+((last.size+511)//512)*512;self.refused(self.raw[:cursor+512])
    def test_unaligned_trailer_refused(self):self.refused(self.raw+b'\0')
    def test_hidden_gnu_long_header_refused(self):
        rows=copy.deepcopy(self.rows);index=next(i for i,(member,raw) in enumerate(rows) if member.name in self.payload)
        member,body=rows[index];hidden=tarfile.TarInfo('././@LongLink');hidden.type=tarfile.GNUTYPE_LONGNAME;hidden.mode=0o644
        alias=copy.copy(member);alias.name='alias';rows[index:index+1]=[(hidden,member.name.encode()+b'\0'),(alias,body)]
        self.refused(make_tar(rows))
    def test_pax_header_refused(self):
        rows=copy.deepcopy(self.rows);rows[0][0].pax_headers={'comment':'original inert header'};self.refused(make_tar(rows,tarfile.PAX_FORMAT))
    def test_symlink_member_refused(self):
        rows=copy.deepcopy(self.rows);index=next(i for i,(member,raw) in enumerate(rows) if member.name in self.payload)
        member,raw=rows[index];member.type=tarfile.SYMTYPE;member.linkname='not-followed';rows[index]=(member,None);self.refused(make_tar(rows))
    def test_unknown_or_duplicate_member_refused(self):
        member=tarfile.TarInfo('unknown');member.mode=0o644;self.refused(make_tar(self.rows+[(member,b'INERT')]))
        self.refused(make_tar(self.rows+[self.rows[-1]]))
    def test_wrong_step_argv_log_or_rawpin_refused(self):
        for key,value in [('step','build-a'),('argv',['/usr/bin/zstd','-dc','/wrong/source']),('log','001-archive-a.log'),('log_pin',dict(bytes=len(self.raw),sha256='0'*64)),('expected',False)]:
            row=self.row();row[key]=value;self.refused(self.raw,row)
    def projection_model(self,raw=None,row=None):
        temporary=tempfile.TemporaryDirectory(prefix='platform-archive-privacy-data-');self.addCleanup(temporary.cleanup);base=Path(temporary.name)
        source=base/'source';public=base/'public';source.mkdir(mode=0o700);public.mkdir(mode=0o700)
        producers={}
        for name in P.PRODUCERS:
            body=(SOURCE/name).read_bytes();path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body);producers[name]=P.C.pin(body)['sha256']
        binding=dict(source='a'*40,ref='refs/heads/codex/archive-data-model',run='1',attempt=1)
        binding['token']=hashlib.sha256((binding['source']+':'+binding['ref']+':'+binding['run']).encode()).hexdigest()[:24]
        raw=self.raw if raw is None else raw;row=self.row(raw) if row is None else row
        def put(name,body):
            path=public/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body);path.chmod(0o600)
        put('receipt.json',encoded(dict(binding=binding,source_map_sha256='b'*64)))
        prefix='journey/platform-alpm-v1/'
        put(prefix+'result.json',encoded(dict(schema_version=1,operation='platform-alpm-v1',status='FAIL',source_map_sha256='b'*64,commands=[row])))
        put(prefix+'commands.json',encoded([row]));put(prefix+row['log'],raw)
        return source,public,base/'projected',producers,binding
    def project(self,model):
        source,public,destination,producers,binding=model
        with mock.patch.object(P,'PRODUCERS',producers),contextlib.redirect_stdout(io.StringIO()):return P.project(source,public,destination)
    def read_projection(self,model):
        source,public,destination,producers,binding=model;view=View(destination);files=view.load('artifacts.json')['files']
        with mock.patch.object(R,'PRODUCERS',producers),mock.patch.object(R,'platform_contract',return_value=self.contract):return R.retained_public_projection(view,files,binding,'b'*64)
    def test_real_source_archive_projects_with_independent_custody_receipt(self):
        model=self.projection_model();receipt=self.project(model);key='journey/platform-alpm-v1/000-archive-a.log'
        self.assertEqual(set(receipt['archive_custody']),{key});self.assertEqual(receipt['archive_custody'][key]['payload_files'],23)
        self.assertEqual(self.read_projection(model)['status'],'VALIDATED_FINITE_PLATFORM_PUBLIC_DATA_PROJECTION_ONLY')
        self.assertEqual((model[2]/key).read_bytes(),self.raw)
    def test_ordinary_log_marker_remains_refused(self):
        raw=b'PRIVATE_KEY';row=dict(step='build-a',log='000-build-a.log',expected=0,argv=['/usr/bin/never-executed'],log_pin=P.C.pin(raw));model=self.projection_model(raw,row)
        with self.assertRaises(Exception):self.project(model)
        self.assertFalse(model[2].exists())
    def test_archive_shaped_log_with_wrong_step_remains_refused(self):
        row=self.row();row['step']='build-a';model=self.projection_model(row=row)
        with self.assertRaises(Exception):self.project(model)
        self.assertFalse(model[2].exists())
    def test_reader_rejects_forged_custody_summary(self):
        model=self.projection_model();self.project(model);path=model[2]/'public-projection.json';value=json.loads(path.read_bytes())
        key='journey/platform-alpm-v1/000-archive-a.log';value['archive_custody'][key]['framing']['zero_trailer_bytes']+=512
        path.write_bytes(P.C._json(value));manifest=model[2]/'artifacts.json';doc=json.loads(manifest.read_bytes());doc['files']['public-projection.json'].update(P.C.pin(path.read_bytes()));manifest.write_bytes(P.C._json(doc))
        with self.assertRaisesRegex(ValueError,'independently parsed'):self.read_projection(model)

if __name__=='__main__':unittest.main(verbosity=2)
