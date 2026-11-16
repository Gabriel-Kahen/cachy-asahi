#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Actual frozen consumers over explicit MODEL metadata/bytes; no native actors."""
import copy
import importlib.util
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn'):
        raise RuntimeError('MODEL consumer controls: no actor or network')
sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('passive_consumer_controls',HERE/'passive.py');D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)
SOURCE=Path(os.environ.get('BANKSTOWN_QT3_TEST_SOURCE',str(HERE.parents[2]))).resolve()
P=D.consumers(SOURCE);A=P.A
spec=importlib.util.spec_from_file_location('frozen_bankstown_guard',SOURCE/A.RECIPE/'build_guard.py');G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)

def elf(*,needed=None,soname=None,machine=183):
    raw=bytearray(512)
    struct.pack_into('<16sHHIQQQIHHHHHH',raw,0,b'\x7fELF\x02\x01\x01'+b'\0'*9,3,machine,1,0,64,0,0,64,56,2,0,0,0)
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0,0,len(raw),len(raw),16384)
    strings=b'\0';tags=[(5,320)]
    for tag,word in((1,needed),(14,soname)):
        if word:tags.append((tag,len(strings)));strings+=word.encode()+b'\0'
    tags.extend(((10,len(strings)),(0,0)))
    struct.pack_into('<IIQQQQQQ',raw,120,2,4,192,192,0,len(tags)*16,len(tags)*16,8)
    for i,row in enumerate(tags):struct.pack_into('<qQ',raw,192+i*16,*row)
    raw[320:320+len(strings)]=strings;return bytes(raw)

class Consumers(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='MODEL-bankstown-consumers-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)

    def put(self,logical,raw,mode=0o644):
        path=self.root/logical.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode);return path

    def catalog(self):
        lock=A.decoded(P.held(SOURCE/(P.BASE+'qtbase-successor/candidate.lock.json'),P.LOCK_PIN))
        parent=A.decoded(P.held(SOURCE/(P.BASE+'qtbase-successor/parent-binding.json'),P.PARENT_PIN))
        baseline=A.decoded(P.held(SOURCE/(P.BASE+'inputs.lock.json'),parent['files']['inputs.lock.json']))
        rust=A.decoded(P.held(SOURCE/P.RUST,P.RUST_PIN))
        selected={n:r for n,r in baseline['packages'].items()if n!='qt6-base'}|lock['new_packages'];self.assertEqual(len(selected),333)
        packages={}
        for name,row in selected.items():
            packages[name]=dict(metadata={'/.PKGINFO':dict(pkgname=[name],pkgver=[row['version']],arch=[row['arch']],depend=row['depends'],provides=row['provides'])},
                entries={},signature=dict(status='VALID_SIGNATURE_MATHEMATICS',signer=lock['signer_primary'],key_freshness='NOT_ESTABLISHED',source_acceptance='NOT_ESTABLISHED'))
        # These are real retained descriptors in MODEL catalog metadata, not read
        # Rust bodies or genuine signature observations.
        packages['rust']['entries']={path:dict(type='file',mode=0o644,**row)for path,row in rust['files'].items()}
        catalog=dict(MODEL_ONLY='NOT_AN_AUTHENTICATED_333_CATALOG',purpose='bankstown-optional-qtbase6.12.0-3-input-candidate',candidate='EXPLICIT_OPTIONAL_QT_BASE_6.12.0-3',
            complete=True,original_minus2_hold='UNCHANGED',protected_input_count=275,native_tools_profile='NOT_PRODUCED',source_legal_freshness_acceptance='HELD',payload_execution='NOT_RUN',
            candidate_lock=P.LOCK_PIN,parent_binding=P.PARENT_PIN,missing_inputs=[],unresolved_package_dependencies=[],unresolved_elf_dependencies=[],unresolved_GNU_versions=[],packages=packages)
        materials={}
        for field,name in(('version_parser','elf_versions.py'),('source_facts','source-facts.json')):
            member=P.BASE+'qtbase-successor/'+name;materials[member]=catalog[field]=A.pin((SOURCE/member).read_bytes())
        inventory={n:r['version']for n,r in selected.items()}|{'make':'MODEL','pacman':'MODEL','fakeroot':'MODEL'}
        raw=''.join(n+' '+v+'\n'for n,v in sorted(inventory.items())).encode();self.put('model/inventory.lock',raw)
        materials['model/inventory.lock']=A.pin(raw)
        d=dict(materials=materials,image=dict(inventory=A.pin(raw)),selected_files=copy.deepcopy(rust['files']))
        return d,catalog,lock,baseline,rust

    def check_catalog(self,d,catalog,lock,baseline,rust):
        raw=A.encoded(catalog);d=dict(d,catalog=A.pin(raw))
        with patch.object(P,'SOURCE',self.root):return P._catalog(raw,d,lock,baseline,rust)

    def projection(self):
        bodies={path:elf(needed='libMODEL.so')for path in A.TOOLS.values()}
        bodies['/usr/lib/libMODEL.so']=elf(soname='libMODEL.so');bodies['/usr/lib/Scrt1.o']=b'MODEL_NOT_A_RETAINED_CRT'
        d=dict(selected_files={},tool_paths=dict(A.TOOLS),closure=dict(non_elf_support=['/usr/lib/Scrt1.o']),catalog=A.pin(b'MODEL_CATALOG'),image=dict(MODEL_ONLY=True))
        entries={};joins=[]
        for path,raw in bodies.items():
            observed=P.elf(raw);mode=0o755 if observed else 0o644;self.put(path,raw,mode)
            row=dict(type='file',mode=mode,**A.pin(raw))
            if observed is not None:row['elf']=observed
            entries[path]=row;d['selected_files'][path]=A.pin(raw)
            if path in A.TOOLS.values():joins.append(dict(consumer=path,needed='libMODEL.so',provider='/usr/lib/libMODEL.so'))
        return d,dict(elf_dependency_joins=joins),entries

    def project(self,d,c,entries):
        return P._project(d,c,entries,self.root,None,time.monotonic()+5)

    def test_exact_frozen_relocated_loader_and_actual_metadata_pins(self):
        self.assertEqual(P.SOURCE,SOURCE);self.assertEqual(Path(P.__file__),SOURCE/D.FAMILY/'profile.py')
        self.assertEqual(A.pin((SOURCE/P.RUST).read_bytes()),P.RUST_PIN)
        self.assertEqual(A.pin((SOURCE/A.RECIPE/'build_guard.py').read_bytes()),P.RECIPE_PINS['build_guard.py'])
        with self.assertRaises(OSError):D.consumers(self.root)

    def test_retained_profile_and_admission_code_are_not_reopened_for_execution(self):
        for relative in D.PINS:
            target=self.root/relative;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes((SOURCE/relative).read_bytes())
        original=D.read
        def swapping(path,**kwargs):
            raw=original(path,**kwargs)
            if Path(path).name in ('profile.py','admission.py'):
                Path(path).write_bytes(b"raise RuntimeError('UNPINNED_CODE_EXECUTED')\n")
            return raw
        with patch.object(D,'read',side_effect=swapping):
            loaded=D.consumers(self.root)
        self.assertEqual(loaded.SOURCE,self.root)
        self.assertTrue(callable(loaded.export_profile));self.assertTrue(callable(loaded.A.validate_trial))

    def test_actual_catalog_exact333_and_real_rust137_metadata_join(self):
        args=self.catalog();catalog,entries=self.check_catalog(*args)
        self.assertEqual(len(catalog['packages']),333);self.assertEqual(len(catalog['packages']['rust']['entries']),137)
        self.assertEqual(catalog['packages']['qt6-base']['metadata']['/.PKGINFO']['pkgver'],['6.12.0-3']);self.assertTrue(entries)

    def test_catalog_version_dependency_provider_freshness_and_missing_closure_refuse(self):
        original=self.catalog()
        mutations=(lambda c:c['packages']['qt6-base']['metadata']['/.PKGINFO'].update(pkgver=['6.12.0-2']),
            lambda c:c['packages']['qt6-base']['metadata']['/.PKGINFO'].update(depend=['MODEL_MISSING']),
            lambda c:c['packages']['rust']['metadata']['/.PKGINFO'].update(provides=[]),
            lambda c:c['packages']['rust']['signature'].update(key_freshness='ACCEPTED'),lambda c:c.update(unresolved_GNU_versions=['MODEL_MISSING']))
        for mutate in mutations:
            args=copy.deepcopy(original);mutate(args[1])
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.check_catalog(*args)

    def test_catalog_missing_rust_descriptor_or_selected_rust_payload_refuses(self):
        args=self.catalog();args[1]['packages']['rust']['entries'].pop('/usr/bin/rustc')
        with self.assertRaisesRegex(ValueError,'RUST137'):self.check_catalog(*args)
        args=self.catalog();args[0]['selected_files'].pop('/usr/bin/rustc')
        with self.assertRaisesRegex(ValueError,'RUST_FILES'):self.check_catalog(*args)

    def test_actual_project_elf_mode_hash_support_and_held_authority(self):
        d,c,e=self.projection();result=self.project(d,c,e)
        self.assertEqual(result['files'],d['selected_files']);self.assertEqual(result['legal'],'HELD');self.assertIsNone(result['admission_pin'])
        self.assertIsNone(result['Root_acceptance']);self.assertFalse(result['native_component_acceptance'])
        self.put('/usr/bin/rustc',b'CHANGED',0o755)
        with self.assertRaises(ValueError):self.project(d,c,e)
        d,c,e=self.projection();(self.root/'usr/bin/rustc').chmod(0o644)
        with self.assertRaisesRegex(ValueError,'MODE'):self.project(d,c,e)
        d,c,e=self.projection();e['/usr/bin/rustc']['elf']['machine']=62
        with self.assertRaisesRegex(ValueError,'ELF'):self.project(d,c,e)

    def test_actual_project_missing_provider_join_and_wrong_soname_refuse(self):
        d,c,e=self.projection();d['selected_files'].pop('/usr/lib/libMODEL.so')
        with self.assertRaisesRegex(ValueError,'PROVIDER'):self.project(d,c,e)
        d,c,e=self.projection();c['elf_dependency_joins'].pop()
        with self.assertRaisesRegex(ValueError,'JOIN'):self.project(d,c,e)
        d,c,e=self.projection();raw=elf(soname='wrongMODEL.so');self.put('/usr/lib/libMODEL.so',raw,0o755)
        d['selected_files']['/usr/lib/libMODEL.so']=A.pin(raw);e['/usr/lib/libMODEL.so']=dict(type='file',mode=0o755,elf=P.elf(raw),**A.pin(raw))
        with self.assertRaisesRegex(ValueError,'SONAME'):self.project(d,c,e)

    def test_actual_project_logical_tool_link_stays_inside_model_root(self):
        d,c,e=self.projection();cc=self.root/'usr/bin/cc';cc.rename(cc.with_name('gcc'));cc.symlink_to('/usr/bin/gcc')
        e['/usr/bin/gcc']=e.pop('/usr/bin/cc');e['/usr/bin/cc']=dict(type='symlink',target='/usr/bin/gcc',resolved='/usr/bin/gcc')
        d['selected_files']['/usr/bin/gcc']=d['selected_files'].pop('/usr/bin/cc')
        for join in c['elf_dependency_joins']:
            if join['consumer']=='/usr/bin/cc':join['consumer']='/usr/bin/gcc'
        self.assertIn('/usr/bin/gcc',self.project(d,c,e)['files'])
        cc.unlink();cc.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError,'LINK_DIFFERS'):self.project(d,c,e)

    def test_actual_hardlink_inode_and_escape_cycle_refusals(self):
        d,c,e=self.projection();alias=self.root/'usr/lib/MODEL.a';target=self.root/'usr/lib/Scrt1.o';os.link(target,alias)
        e['/usr/lib/MODEL.a']=dict(type='hardlink',target='usr/lib/Scrt1.o',resolved='/usr/lib/Scrt1.o',mode=0o644);d['selected_files']['/usr/lib/MODEL.a']=A.pin(target.read_bytes())
        self.assertIn('/usr/lib/MODEL.a',self.project(d,c,e)['files']);raw=alias.read_bytes();alias.unlink();alias.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'HARDLINK'):self.project(d,c,e)
        for target in('../../../../etc/passwd','/usr/bin/cc'):
            p=self.root/'usr/bin/cc';p.unlink();p.symlink_to(target);e['/usr/bin/cc']=dict(type='symlink',target=target,resolved='/usr/bin/cc')
            with self.subTest(target=target),self.assertRaises(ValueError):P.resolve('/usr/bin/cc',e,self.root)

    def guard_model(self):
        files={path:elf()for path in G.TOOLS.values()}
        for name in('std','core','alloc','compiler_builtins'):files['/usr/lib/rustlib/aarch64-unknown-linux-gnu/lib/lib'+name+'-MODEL.rlib']=b'MODEL_NOT_RETAINED_RUST_'+name.encode()
        for path,raw in files.items():self.put(path,raw)
        rust=dict(MODEL_ONLY=True,files={p:A.pin(b)for p,b in files.items()if p in('/usr/bin/cargo','/usr/bin/rustc')or p.startswith('/usr/lib/')})
        rust_raw=A.encoded(rust);self.put('model/native-rust.json',rust_raw)
        profile=dict(MODEL_ONLY='NOT_QUALIFIED_NATIVE_TOOLS',schema=1,purpose='bankstown-1.1.0-5-native-toolchain',target='aarch64-unknown-linux-gnu',compiler_version='1.99.0',tools=dict(G.TOOLS),files={p:A.pin(b)for p,b in files.items()},Root_acceptance=None)
        return profile,rust_raw

    def call_guard(self,profile,rust_raw,expected=None):
        path=self.put('model/profile.json',A.encoded(profile));calls=[];real_path=Path
        class ModelPath(type(Path())):
            def resolve(self,*args,**kwargs):
                # Do not follow the host's /usr symlinks. All body reads below
                # map these logical MODEL paths into this owned temporary root.
                return self if str(self).startswith('/usr/')else super().resolve(*args,**kwargs)
        def relocated_read(value,limit=256*1024**2):
            text=str(value);calls.append(text)
            if text.startswith('/usr/'):selected=self.root/text[1:]
            elif text==str(real_path(G.__file__).parent/'native-rust-inputs.json'):selected=self.root/'model/native-rust.json'
            else:selected=real_path(value)
            return D.read(selected,cap=limit)
        with patch.object(G,'Path',ModelPath),patch.object(G,'read',side_effect=relocated_read),patch.object(G,'NATIVE_RUST_PIN',G.sha(rust_raw)):
            result=G.native_tools(path,expected or G.sha(A.encoded(profile)))
        self.assertTrue(any(p.startswith('/usr/')for p in calls));return result

    def test_actual_guard_native_tools_api_model_relocation_only(self):
        profile,rust=self.guard_model();self.assertEqual(self.call_guard(profile,rust),profile)

    def test_actual_guard_model_hash_foreign_tool_and_missing_target_library_refuse(self):
        profile,rust=self.guard_model()
        with self.assertRaisesRegex(ValueError,'PIN_REQUIRED'):self.call_guard(profile,rust,'0'*64)
        self.put('/usr/bin/rustc',elf(machine=62));profile['files']['/usr/bin/rustc']=A.pin(elf(machine=62))
        with self.assertRaisesRegex(ValueError,'AARCH64'):self.call_guard(profile,rust)
        profile,rust=self.guard_model();name=next(p for p in profile['files']if '/liballoc-'in p);profile['files'].pop(name)
        # Keep MODEL Rust association consistent to reach the target-library gate.
        value=A.decoded(rust);value['files'].pop(name);rust=A.encoded(value);self.put('model/native-rust.json',rust)
        with self.assertRaisesRegex(ValueError,'TARGET_LIBRARY'):self.call_guard(profile,rust)

    def test_public_export_refuses_unissued_data_and_runtime_relocated_root(self):
        raw=A.encoded(dict(MODEL_ONLY='UNISSUED_NO_ROOT_AUTHORITY'))
        with self.assertRaisesRegex(ValueError,'ROOT_TRIAL_SCHEMA'):
            P.export_profile(admission_raw=raw,admission_sha256=A.pin(raw)['sha256'],catalog_path=self.root/'absent',root=self.root,output=self.root/'unissued.json')
        self.assertFalse((self.root/'unissued.json').exists())
        with self.assertRaisesRegex(ValueError,'RUNTIME_ACTUAL_ROOT'):
            P.verify_profile(admission_raw=raw,admission_sha256=A.pin(raw)['sha256'],catalog_path=self.root/'absent',root=self.root,profile_path=self.root/'absent',profile_sha256='0'*64)

if __name__=='__main__':unittest.main()
