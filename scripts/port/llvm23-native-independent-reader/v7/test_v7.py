#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic349 metadata controls; no operational Reader or artifact-code entry."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in (
            'resource.setrlimit','fcntl.flock','os.exec','os.fork','os.system','os.posix_spawn'):
        raise RuntimeError('Reader7 DATA controls forbid '+event)


sys.addaudithook(fence)
r=load('Reader7_DATA',HERE/'reader.py');v=r.v;helper=r.B.buildinfo


def fixture():
    def item(i,version):
        name='test-package-'+str(i);arch='any' if i%7 == 0 else 'aarch64'
        return dict(name=name,version=version,arch=arch,
                    filename=name+'-'+version+'-'+arch+'.pkg.tar.xz',sha256='a'*64)
    rootfs=[{k:[item(i,'1.0-1')[k]] for k in ('name','version','arch')} for i in range(165)]
    selected=[item(i,'1.0-1' if i == 0 else '2.0-1') for i in list(range(72))+list(range(165,341))]
    additions=[item(i,'3:2.0+git_abc~rc1-1.2') for i in range(341,349)]
    original=dict(rootfs_packages=rootfs,packages=selected)
    merged={p['name'][0]:dict(version=p['version'][0],arch=p['arch'][0]) for p in rootfs}
    merged.update({p['name']:p for p in selected+additions})
    lock=''.join(n+' '+p['version']+'\n' for n,p in sorted(merged.items())).encode()
    installed=['installed = '+n+'-'+p['version']+'-'+p['arch'] for n,p in sorted(merged.items())]
    return original,additions,lock,installed


class Controls(unittest.TestCase):
    def setUp(self):
        self.original,self.additions,self.lock,self.installed=fixture()
    def raw(self):return ('format = 2\n'+'\n'.join(self.installed)+'\n').encode()
    def check(self):return helper.validate(self.raw(),self.lock,self.original,self.additions)
    def test_complete349_with_source_selected_version_replacements_and_epochs(self):
        verdict=self.check()
        self.assertEqual(verdict['rows'],349);self.assertEqual(verdict['selected_version_replacements'],71)
        self.assertEqual(sum(verdict['architectures'].values()),349)
        self.assertFalse(verdict['output_BUILDINFO_used_as_architecture_authority'])
        self.assertIsNone(verdict['required_external_architecture_input'])
    def test_order_is_not_architecture_authority(self):
        self.installed.reverse();self.original['rootfs_packages'].reverse();self.original['packages'].reverse()
        self.check()
    def test_unencoded_and_unknown_or_doubled_architectures_refuse(self):
        original=self.installed[0]
        for literal in (original.rsplit('-',1)[0],original.rsplit('-',1)[0]+'-x86_64',
                        original+'-any',original+'-aarch64',original+'-ANY',original+'-'):
            self.installed[0]=literal
            with self.subTest(literal=literal),self.assertRaises(ValueError):self.check()
    def test_known_but_incorrect_architecture_refuses(self):
        self.installed[0]=self.installed[0].rsplit('-',1)[0]+'-aarch64'
        with self.assertRaises(ValueError):self.check()
    def test_wrong_name_or_version_refuses(self):
        original=self.installed[0]
        for value in (original.replace('test-package-0','counterfeit-package'),original.replace('1.0-1','1.0-9'),
                      original.replace('1.0-1','1.0-1-any')):
            self.installed[0]=value
            with self.subTest(value=value),self.assertRaises(ValueError):self.check()
    def test_duplicate_and_counterfeit349_cardinality_refuse(self):
        self.installed[0]=self.installed[1]
        with self.assertRaises(ValueError):self.check()
        self.installed=fixture()[3];self.installed[-1]='installed = counterfeit-1.0-1-any'
        with self.assertRaises(ValueError):self.check()
        self.installed=fixture()[3];self.installed.append(self.installed[0])
        with self.assertRaises(ValueError):self.check()
        self.installed=fixture()[3][:-1]
        with self.assertRaises(ValueError):self.check()
    def test_malformed_installed_key_and_whitespace_refuse(self):
        original=self.installed[0]
        for value in (original.replace('installed = ','installed='), ' '+original,
                      original.replace('installed = ','installed  = '),original+' ',original+'\r'):
            self.installed[0]=value
            with self.subTest(value=value),self.assertRaises(ValueError):self.check()
    def test_duplicate_or_malformed_lock_rows_refuse(self):
        lines=self.lock.splitlines(keepends=True)
        for raw in (b''.join([lines[1]]+lines[1:]),self.lock[:-1],self.lock+b'\n',
                    self.lock.replace(b' 1.0-1\n',b' 1.0-1-any\n',1),self.lock.replace(b' ',b'  ',1)):
            self.lock=raw
            with self.subTest(raw=raw[:100]),self.assertRaises(ValueError):self.check()
        self.lock=fixture()[2].replace(b'test-package-0 ',b'../escape ')
        with self.assertRaises(ValueError):self.check()
    def test_duplicate_rootfs_selected_and_addition_names_refuse(self):
        for target in ('rootfs','selected','additions'):
            self.original,self.additions,self.lock,self.installed=fixture()
            rows={'rootfs':self.original['rootfs_packages'],'selected':self.original['packages'],'additions':self.additions}[target]
            rows[0]=copy.deepcopy(rows[1])
            with self.subTest(target=target),self.assertRaises(ValueError):self.check()
    def test_selected_addition_name_collision_refuses(self):
        self.additions[0]=copy.deepcopy(self.original['packages'][0])
        with self.assertRaises(ValueError):self.check()
    def test_epoch_truncated_filename_refuses(self):
        row=self.additions[0];row['filename']=row['filename'].replace('-3:','-')
        with self.assertRaisesRegex(ValueError,'filename binding'):self.check()
    def test_missing_or_multivalued_rootfs_arch_cannot_be_invented(self):
        for arch in ([],['any','aarch64'],['x86_64'],'any',None):
            self.original['rootfs_packages'][0]['arch']=arch
            with self.subTest(arch=arch),self.assertRaises(ValueError):self.check()
    def test_source_arch_conflict_unknown_or_filename_mismatch_refuse(self):
        first=self.original['packages'][0]
        for key,value in [('arch','aarch64'),('arch','x86_64'),('filename','counterfeit.pkg.tar.xz'),('sha256','invented')]:
            self.original['packages'][0]=dict(first,**{key:value})
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.check()
        changed=dict(first,arch='aarch64',filename=first['filename'].replace('-any.pkg','-aarch64.pkg'))
        self.original['packages'][0]=changed
        with self.assertRaisesRegex(ValueError,'conflicting rootfs/selected architecture'):self.check()
    def test_wrong_source_name_version_and_class_counts_refuse(self):
        self.original['packages'][0]['version']='9.0-1'
        self.original['packages'][0]['filename']=self.original['packages'][0]['filename'].replace('-1.0-1-','-9.0-1-')
        with self.assertRaisesRegex(ValueError,'complete349 Source input name/version join'):self.check()
        self.original,self.additions,self.lock,self.installed=fixture();self.original['rootfs_packages'].pop()
        with self.assertRaises(ValueError):self.check()
        self.original,self.additions,self.lock,self.installed=fixture();self.additions.pop()
        with self.assertRaises(ValueError):self.check()
    def test_check_whole_source_pins_and_independent_rootfs_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'source';evidence=Path(d)/'evidence';(evidence/'bootstrap').mkdir(parents=True)
            bodies={'expected349.lock':self.lock,
              'original/bootstrap/scripts/ci/inputs.lock.json':v.canonical(self.original),
              'original/native/input-profile.json':v.canonical({'additions':{'rows':self.additions}})}
            profile={'files':{}}
            for name,body in bodies.items():
                path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)
                profile['files'][name]=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
            (evidence/'bootstrap/inputs.lock.json').write_bytes(v.canonical(dict(self.original,packages=self.original['packages']+self.additions)))
            (evidence/'bootstrap/rootfs-inventory.json').write_bytes(v.canonical(self.original['rootfs_packages']))
            helper.check(self.raw(),source,evidence,v,profile)
            (evidence/'bootstrap/rootfs-inventory.json').write_bytes(b'[]')
            with self.assertRaises(ValueError):helper.check(self.raw(),source,evidence,v,profile)
            (source/'expected349.lock').write_bytes(self.lock+b'counterfeit')
            with self.assertRaises(ValueError):helper.check(self.raw(),source,evidence,v,profile)
    def test_installer_exact_inverse_and_inherited_predicates(self):
        legacy=load('Held_Reader6_DATA',HERE.parent/'v6/reader.py')
        old_retirement=v.retirement;old_commands=v.commands
        proof=r.B.install(v.load(HERE/'pins.json')['output_namespace'],lambda *a:None)
        self.assertEqual(proof['buildinfo']['seams'],1)
        self.assertEqual(proof['buildinfo']['inverse'],'EXACT_FUNCTION_BYTES')
        self.assertEqual(proof['absent_image_stdout'],r.B.held.absence_proof)
        self.assertIs(v.retirement,old_retirement);self.assertIsNot(v.commands,old_commands)
        self.assertIs(v.replay.__globals__['commands'],v.commands)
        self.assertIs(v.replay.__globals__['retirement'],v.retirement)
        self.assertIs(v.replay.__globals__['buildinfo349'],v.buildinfo349)
        self.assertNotIn('buildinfo349',legacy.v.replay.__code__.co_names)
        self.assertIn('buildinfo349',v.replay.__code__.co_names)
        r.B.install(v.load(HERE/'pins.json')['output_namespace'],lambda *a:None)
        self.assertIn('buildinfo349',v.replay.__code__.co_names)
    def test_reader_inverse_and_only_new_pins(self):
        proof=v.load(HERE/'derivation.json');raw=(HERE/'reader.py').read_bytes()
        for seam in reversed(proof['seams']):
            self.assertEqual(raw.count(seam['after'].encode()),1);raw=raw.replace(seam['after'].encode(),seam['before'].encode())
        self.assertEqual(raw,(HERE.parent/'v6/reader.py').read_bytes())
        self.assertEqual(hashlib.sha256(raw).hexdigest(),proof['parent_reader_sha256'])
        pins=v.load(HERE/'pins.json');old=v.load(HERE.parent/'v6/pins.json');old['base_sha256']=pins['base_sha256']
        old.update({k:pins[k] for k in ('buildinfo_sha256','architecture_profile_sha256')});self.assertEqual(pins,old)
        for name,digest in proof['copied_byte_identical'].items():self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest)
    def test_templates_are_unissued_new_role(self):
        binding=v.load(HERE/'binding.TEMPLATE.json');self.assertEqual(binding['scope'],'ROOT_BOUND_LLVM23_INDEPENDENT_READER_V7')
        self.assertTrue(all(x is None for x in binding['actual'].values()))
        with self.assertRaises(ValueError):r.binding(binding,v.load(HERE/'pins.json'))
        request=v.load(HERE/'request.TEMPLATE.json')
        for key in ('binding','actual_reader_selector','source','original','output','Root_issuer','Root_approved','Root_issued_at','Root_runtime54','Root_resources','Root_storage_profile','required_external_architecture_input'):
            self.assertIsNone(request[key])
        self.assertEqual(request['entry']['sha256'],hashlib.sha256((HERE/'reader.py').read_bytes()).hexdigest())
    def test_operational_primitives_are_fenced(self):
        for event in ('subprocess.Popen','socket.__new__','ctypes.dlopen','fcntl.flock','resource.setrlimit'):
            with self.assertRaises(RuntimeError):fence(event,())


if __name__ == '__main__':unittest.main(verbosity=2)
