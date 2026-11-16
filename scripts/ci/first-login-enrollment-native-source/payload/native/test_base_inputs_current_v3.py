# SPDX-License-Identifier: MIT
"""Tiny inert DATA shapes and real selector metadata; no operational fixture."""
import copy
import importlib.util
import os
import re
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
        raise RuntimeError('FENCED base-input component DATA: '+event)
sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[4]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
P=module('finite_base_inputs',HERE/'base_inputs_current_v3.py')
IMAGE=Path(os.environ.get('CACHY_CURRENT_INPUTS_IMAGE',str(HERE/'image_current_v3.py')))
assert P.pin(IMAGE.read_bytes())==dict(bytes=55783,sha256='f4e590532d7f6115f830215810f9dee5f2a1eb714351a9a7e572d22c5a255f90'),'exact committedbc5df257 image consumer'
I=module('committed_image_input_selector',IMAGE)

def put(path,raw,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode);return P.ref(path,P.pin(raw))
def data(path,value,mode=0o600):return put(path,P.encoded(value),mode)
def vector(rows):return ''.join(n+' '+v+'\n'for n,v in sorted(rows.items())).encode()

class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='FENCED-base349-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.source=self.root/'source';self.source.mkdir();self.cache=self.root/'cache';self.cache.mkdir(mode=0o700)
        self.names={};self.base_versions={};root_records=[]
        for n in range(165):
            name='fenced-%03d'%n;self.base_versions[name]='0.0-1';root_records.append(dict(name=[name],version=['0.0-1'],arch=['aarch64']))
        def row(name,kind='package'):
            filename=name+'.pkg.tar.xz'if kind=='package'else name;ar=put(self.cache/filename,('FENCED '+filename).encode());sig=put(self.cache/(filename+'.sig'),('FENCED signature '+filename).encode())
            value=dict(filename=filename,size=ar['bytes'],sha256=ar['sha256'],signature_size=sig['bytes'],signature_sha256=sig['sha256'],url='https://example.invalid/'+filename)
            if kind=='package':value.update(name=name,version='0.0-1',arch='any'if name in P.EXTRAS else'aarch64')
            return value
        rootfs=row('fenced-rootfs.tar.gz','rootfs');packages=[]
        for n in range(93,341):
            name='fenced-%03d'%n;self.base_versions[name]='0.0-1';packages.append(row(name))
        extras=[row(name)for name in sorted(P.EXTRAS)];keyrings=[]
        for name in sorted(P.KEYRINGS):
            ref=put(self.cache/name,b''if name.endswith('revoked')else('FENCED '+name).encode())
            keyrings.append(dict(filename=name,size=ref['bytes'],sha256=ref['sha256'],url='https://example.invalid/'+name))
        self.lock=dict(FENCED='NOT_NATIVE_INPUTS',rootfs=rootfs,rootfs_packages=root_records,packages=packages,keyring_files=keyrings,
            signer_fingerprint='A'*40,keyring_commit='b'*40)
        self.profile=dict(FENCED='NOT_NATIVE_INPUTS',original341=dict(package_count=341,packages=self.base_versions),
            additions=dict(rows=extras,count=8,expected_augmented_package_count=349,unresolved=[]))
        expected=dict(self.base_versions,**{name:'0.0-1'for name in P.EXTRAS});self.lock_ref=data(self.root/'lock.json',self.lock);self.profile_ref=data(self.root/'bootstrap-profile.json',self.profile)
        self.inventory=put(self.source/P.INVENTORY,vector(expected),0o644)
        factory=dict(FENCED='NOT_SOURCE_ADMISSION',parent_files={name:dict(wanted,mode=0o644)for name,wanted in(
            ('bootstrap/scripts/ci/inputs.lock.json',P.pin(P.encoded(self.lock))),('native/input-profile.json',P.pin(P.encoded(self.profile))),('native/expected349.lock',P.pin(vector(expected))))})
        factory_ref=data(self.source/P.FACTORY,factory,0o644)
        source_map=dict(schema=1,kind='CURRENT_ONBOARDING_CLOSED_SOURCE_V3',operation='first-login-enrollment-ui-current-v2',FENCED='METADATA_ONLY_NOT_OPERATIONAL_SOURCE',actual=dict.fromkeys(P.ACTUAL),files={P.FACTORY:dict(P.pin(P.encoded(factory)),mode=0o644),P.INVENTORY:dict(P.pin(vector(expected)),mode=0o644)})
        self.map_ref=data(self.source/'source-map.json',source_map,0o644)
        data(self.source/'source.lock.json',source_map,0o644)
        self.addCleanup(patch.stopall)
        for name,value in(('FACTORY_PIN',P.pin(P.encoded(factory))),('LOCK_PIN',P.pin(P.encoded(self.lock))),('PROFILE_PIN',P.pin(P.encoded(self.profile))),('INVENTORY_PIN',P.pin(vector(expected)))):
            patch.object(P,name,value).start()
        self.args=dict(cache_root=self.cache,source_root=self.source,source_map=self.map_ref,base_lock=self.lock_ref,bootstrap_profile=self.profile_ref)

    def metadata(self):return P.metadata(**{k:v for k,v in self.args.items()if k!='cache_root'})

    def selected(self):
        plan=self.metadata()
        return {name:P.ref(self.cache/name,{k:row[k]for k in('bytes','sha256')})for name,row in plan['files'].items()}

    def selected_args(self):return {k:v for k,v in self.args.items()if k!='cache_root'}

    def test_partial512_explicit_refs_no_enumeration_all_missing_pins_and_no_writes(self):
        materials=self.selected();plan=self.metadata()
        missing={self.lock['rootfs']['filename'],self.lock['rootfs']['filename']+'.sig',*P.KEYRINGS}
        for name in missing:del materials[name]
        put(self.cache/'undeclared-unused-carrier-leaf',b'FENCED never read');calls=[];real=P.stream
        before={str(p):p.read_bytes()for p in self.root.rglob('*')if p.is_file()}
        def stream(value,*a,**kw):
            if Path(value['path']).parent==self.cache:calls.append(value['path'])
            return real(value,*a,**kw)
        with patch.object(P.os,'scandir',side_effect=AssertionError('no discovery')),patch.object(P,'stream',side_effect=stream):
            result=P.assess_selected_references(materials=materials,**self.selected_args())
        self.assertFalse(result['complete']);self.assertEqual(result['status'],'HOLD_MISSING_EXPLICIT_MATERIALS')
        self.assertEqual(result['verified_files'],512);self.assertEqual(len(calls),512);self.assertEqual(len(set(calls)),512)
        self.assertEqual(result['missing_materials'],{name:plan['files'][name]for name in sorted(missing)})
        self.assertEqual(result['missing_materials']['archlinuxarm-revoked']['bytes'],0)
        self.assertEqual([len(result[k])for k in('base_materials','supplemental_materials','keyring_materials')],[496,16,0])
        self.assertTrue(all(v is None for v in result['actual'].values()))
        with self.assertRaisesRegex(P.MissingInput,'materials/'):
            P.assembler_fields(result)
        self.assertEqual(before,{str(p):p.read_bytes()for p in self.root.rglob('*')if p.is_file()})

    def test_complete_selected_split_carriers_without_directory_mode_or_namespace_assumptions(self):
        materials=self.selected();name=next(iter(materials));other=self.root/'other-carrier';other.mkdir(mode=0o755)
        moved=other/'content-addressed-body';Path(materials[name]['path']).rename(moved);materials[name]['path']=str(moved)
        put(self.cache/'unused',b'FENCED unused')
        with patch.object(P.os,'scandir',side_effect=AssertionError('no discovery')):
            result=P.build_selected_references(materials=materials,**self.selected_args())
        self.assertTrue(result['complete']);self.assertEqual(result['cache_files'],517);self.assertEqual(result['archive_streams'],517)
        self.assertEqual(result['base_materials'][name],materials[name]);self.assertEqual(result['missing_materials'],{})
        self.assertEqual(result['keyring_materials']['archlinuxarm-revoked']['bytes'],0)

    def test_selected_unknown_stale_pin_or_duplicate_path_refuses_before_body_streams(self):
        original=self.selected();name,second=list(original)[:2];real=P.stream
        for mutation in(lambda v:v.update(unknown=v[name]),lambda v:v[name].update(sha256='0'*64),
            lambda v:v[second].update(path=v[name]['path'])):
            materials=copy.deepcopy(original);mutation(materials);calls=[]
            def stream(value,*a,**kw):
                if Path(value['path']).parent==self.cache:calls.append(value['path'])
                return real(value,*a,**kw)
            with self.subTest(mutation=mutation),patch.object(P,'stream',side_effect=stream),self.assertRaises(ValueError):
                P.assess_selected_references(materials=materials,**self.selected_args())
            self.assertEqual(calls,[])

    def test_selected_partial_builder_refuses_and_stale_body_never_becomes_missing_hold(self):
        materials=self.selected();name=next(iter(materials));value=materials.pop(name)
        with self.assertRaisesRegex(P.MissingInput,'materials/'):
            P.build_selected_references(materials=materials,**self.selected_args())
        materials[name]=value;Path(value['path']).write_bytes(b'stale selected body')
        with self.assertRaises(ValueError):P.assess_selected_references(materials=materials,**self.selected_args())

    def test_complete517_once_no_copies_writes_or_authority(self):
        calls=[];real=P.stream;before={str(p):p.read_bytes()for p in self.root.rglob('*')if p.is_file()}
        def stream(ref,*a,**kw):
            if Path(ref['path']).parent==self.cache:calls.append(ref['path'])
            return real(ref,*a,**kw)
        with patch.object(P,'stream',side_effect=stream):result=P.build_references(**self.args)
        self.assertEqual(len(calls),517);self.assertEqual(len(set(calls)),517)
        self.assertEqual([len(result[k])for k in('base_materials','supplemental_materials','keyring_materials')],[498,16,3])
        self.assertEqual(len(result['packages']),349);self.assertTrue(all(v is None for v in result['actual'].values()));self.assertEqual(result['archive_copies'],0)
        self.assertEqual(before,{str(p):p.read_bytes()for p in self.root.rglob('*')if p.is_file()})
        fields=P.assembler_fields(result)
        self.assertEqual(set(fields),{'base_lock','bootstrap_profile','base_materials','supplemental_materials','keyring_materials'})
        self.assertEqual(fields['supplemental_materials'],result['supplemental_materials'])

    def test_missing_named_cache_or_authoritative_profile(self):
        name=next(iter(self.cache.iterdir()));name.unlink()
        with self.assertRaisesRegex(P.MissingInput,'cache/'):P.build_references(**self.args)
        self.args['bootstrap_profile']=None
        with self.assertRaisesRegex(P.MissingInput,'native/input-profile.json'):P.build_references(**self.args)

    def test_extra_consumed_operand_refuses_before_archive_stream(self):
        put(self.cache/'extra',b'FENCED extra')
        real=P.stream;cache_calls=[]
        def stream(ref,*a,**kw):
            if Path(ref['path']).parent==self.cache:cache_calls.append(ref['path'])
            return real(ref,*a,**kw)
        with patch.object(P,'stream',side_effect=stream),self.assertRaises(ValueError):P.build_references(**self.args)
        self.assertEqual(cache_calls,[])
        (self.cache/'extra').unlink();names=list(self.metadata()['files'])
        with self.assertRaises(ValueError):P.build_references(**self.args,consumed_names=names+['extra'])

    def test_alias_hardlink_and_changed_whole_body_refuse(self):
        first,second=list(self.cache.iterdir())[:2];body=first.read_bytes();first.unlink();first.symlink_to(second)
        with self.assertRaises(ValueError):P.build_references(**self.args)
        first.unlink();os.link(second,first)
        with self.assertRaises(ValueError):P.build_references(**self.args)
        first.unlink();put(first,b'X'*len(body))
        with self.assertRaises(ValueError):P.build_references(**self.args)

    def test_previously_streamed_operand_moves_before_final_join_refuses(self):
        real=P.stream;changed=[False]
        def stream(ref,*a,**kw):
            result=real(ref,*a,**kw)
            if Path(ref['path']).parent==self.cache and not changed[0]:
                changed[0]=True;Path(ref['path']).write_bytes(b'changed after verified stream')
            return result
        with patch.object(P,'stream',side_effect=stream),self.assertRaisesRegex(ValueError,'moved or changed'):P.build_references(**self.args)

    def test_typed_real_metadata_and_wrong_inventory_or_signature_pin_refuse(self):
        metadata=self.metadata();self.assertEqual(metadata['signer_fingerprint'],'A'*40)
        broken=copy.deepcopy(self.lock_ref);broken['sha256']='0'*64
        with self.assertRaises(ValueError):P.build_references(**dict(self.args,base_lock=broken))
        (self.source/P.INVENTORY).write_bytes(b'stale inventory')
        with self.assertRaises(ValueError):self.metadata()
        for raw in(b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e999}'):
            with self.assertRaises(ValueError):P.decode(raw)

    def test_plan_preserves22_names_public14_and_only_pinned_base5_plus16(self):
        plan=P.acquisition_plan(self.metadata(),cache_root=self.cache,public14_root=self.root/'public14',retained_root=self.root/'retained',
            retained_git=self.root/'retained-git',helper_root=self.root/'helpers',deadline=1234.5)
        self.assertEqual(len(plan['existing_secret_names']),22);self.assertIsNone(plan['secret_values'])
        self.assertEqual(plan['public14']['source'],'04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd')
        self.assertEqual(len(plan['remaining_base5_and_supplement8']),21);self.assertIsNone(plan['Root_admission'])
        workflow=(HERE.parent/'.github/workflows/native-arm-build.yml').read_text()
        actual=set(re.findall(r'\$\{\{ secrets\.(CACHY_[A-Z0-9_]+) \}\}',workflow))
        self.assertEqual(set(plan['existing_secret_names']),actual)

class RealSelectorMetadata(unittest.TestCase):
    def test_genuine_original341_plus_fixed8_matches_committed_image_consumer(self):
        lock_path=REPO/'scripts/ci/inputs.lock.json';lock=P.decode(lock_path.read_bytes())
        profile=P.decode((REPO/'scripts/ci/desktop-current011-native-source/fixtures/native/input-profile.json').read_bytes())
        vector_path=HERE.parent.parent/'fixtures/expected349.lock';raw=vector_path.read_bytes()
        original={r['name'][0]:r['version'][0]for r in lock['rootfs_packages']};original.update({r['name']:r['version']for r in lock['packages']})
        self.assertEqual(len(original),341);self.assertEqual(profile['original341']['packages'],original)
        augmented=dict(original,**{r['name']:r['version']for r in profile['additions']['rows']})
        self.assertEqual(len(augmented),349);self.assertEqual(vector(augmented),raw)
        self.assertEqual(P.pin(lock_path.read_bytes()),P.LOCK_PIN);self.assertEqual(P.pin(raw),P.INVENTORY_PIN)
        operands={}
        for row in[lock['rootfs'],*lock['packages']]:
            operands[row['filename']]=dict(path='/FENCED_NOT_AVAILABLE/'+row['filename'],bytes=row['size'],sha256=row['sha256'])
            operands[row['filename']+'.sig']=dict(path='/FENCED_NOT_AVAILABLE/'+row['filename']+'.sig',bytes=row['signature_size'],sha256=row['signature_sha256'])
        supplements={};keyrings={}
        for row in profile['additions']['rows']:
            for suffix in('', '.sig'):
                name=row['filename']+suffix;supplements[name]=dict(path='/FENCED_NOT_AVAILABLE/'+name,bytes=row['signature_size']if suffix else row['size'],sha256=row['signature_sha256']if suffix else row['sha256'])
        for row in lock['keyring_files']:
            keyrings[row['filename']]=dict(path='/FENCED_NOT_AVAILABLE/'+row['filename'],bytes=row['size'],sha256=row['sha256'])
        inputs=dict(base_lock=P.ref(lock_path,P.LOCK_PIN),baseline_inventory=P.ref(vector_path,P.INVENTORY_PIN),base_materials=operands,
            bootstrap_profile=P.ref(REPO/'scripts/ci/desktop-current011-native-source/fixtures/native/input-profile.json',P.PROFILE_PIN),supplemental_materials=supplements,keyring_materials=keyrings)
        actual,rows,baseline=I.base_inputs(inputs,REPO)
        self.assertEqual(actual,lock);self.assertEqual(baseline,augmented);self.assertEqual(len(rows),257)
        self.assertEqual({r['name']for r in rows if r['name']in P.EXTRAS},P.EXTRAS)
        with self.assertRaisesRegex(P.MissingInput,'complete517_reference_result'):P.assembler_fields(None)

if __name__=='__main__':unittest.main()
