# SPDX-License-Identifier: MIT
"""Actor-free bootstrap refusals and explicitly selected genuine reconstruction."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('source205_ci_reconstruction',HERE/'ci_reconstruct.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
CURRENT=HERE.parents[3]
M,R,READER_RAW,OPERANDS,CONSTRUCTION=B.checked_author(CURRENT)


def author_files():
    rows={name:dict(row)for name,row in R.TRANSPORT_CONSTRUCTION.items()}
    rows.update({R.TRANSPORT_OPERANDS[role]:dict(R.whole(row),mode=0o644)for role,row in R.TRANSPORT_REPLACEMENTS.items()})
    return rows


class Controls(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='source205-ci-DATA-')
        self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.author,self.basis=self.root/'author',self.root/'basis'
        self.author.mkdir();self.basis.mkdir()
        self.files={}
        for name,row in author_files().items():
            raw,_=B.read(CURRENT/name,row);self.files[name]=raw;path=self.author/name
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(row['mode'])
        self.output,self.profile=self.root/'output',self.root/'profile.json'
    def tearDown(self):self.assertEqual(B.ACTOR_ATTEMPTS,[])
    def refuse(self,**changes):
        args=dict(author=self.author,basis=self.basis,output=self.output,profile_path=self.profile);args.update(changes)
        with self.assertRaises((ValueError,OSError)):B.reconstruct(**args)
        self.assertFalse(os.path.lexists(self.output));self.assertFalse(os.path.lexists(self.profile))

    def test_fixed_author_tree_and_five_local_operands_join_current_constructor(self):
        self.assertEqual(B.AUTHOR_REVISION,'9e26ce819a258225cac866341e15d7099038ab9e')
        self.assertEqual(B.AUTHOR_TREE,'2e14459be57b26ac7657f302c3d614bea301a13a')
        constructor,reader,raw,operands,construction=B.checked_author(self.author)
        self.assertEqual(set(author_files()),{*R.TRANSPORT_CONSTRUCTION,*R.TRANSPORT_OPERANDS.values()})
        self.assertEqual(len(author_files()),5);self.assertEqual(operands,OPERANDS);self.assertEqual(construction,CONSTRUCTION)
        self.assertEqual(constructor.REPLACEMENTS,reader.TRANSPORT_REPLACEMENTS);self.assertEqual(raw,READER_RAW)

    def test_every_wrong_or_missing_author_operand_refuses_before_publication(self):
        for name,original in self.files.items():
            path=self.author/name
            with self.subTest(name=name,kind='changed'):
                path.write_bytes(original+b'FOREIGN');self.refuse();path.write_bytes(original)
            with self.subTest(name=name,kind='missing'):
                path.unlink();self.refuse();path.write_bytes(original)

    def test_author_symlink_hardlink_and_wrong_mode_refuse(self):
        name=next(iter(R.TRANSPORT_OPERANDS.values()));path=self.author/name;raw=self.files[name]
        target=self.root/'aliased.DATA';target.write_bytes(raw)
        path.unlink();path.symlink_to(target);self.refuse();path.unlink();path.write_bytes(raw)
        alias=self.root/'hardlinked.DATA';os.link(path,alias);self.refuse();alias.unlink()
        path.chmod(0o755);self.refuse();path.chmod(0o644)

    def test_current_constructor_or_readme_drift_refuses(self):
        current=self.root/'current';current.mkdir()
        for name,(raw,mode)in CONSTRUCTION.items():(current/name).write_bytes(raw);(current/name).chmod(mode)
        for name,(raw,mode)in CONSTRUCTION.items():
            (current/name).write_bytes(raw+b'CURRENT_DRIFT')
            with self.subTest(name=name),patch.object(B,'HERE',current):self.refuse()
            (current/name).write_bytes(raw)

    def test_wrong_basis_missing_map_bad_map_and_aliased_root_refuse(self):
        self.refuse()
        for name in('source.lock.json','source-map.json'):(self.basis/name).write_bytes(b'{"foreign":true}\n')
        self.refuse()
        alias=self.root/'basis-alias';alias.symlink_to(self.basis,target_is_directory=True)
        self.refuse(basis=alias)

    def test_existing_output_or_profile_remains_foreign_and_unchanged(self):
        self.output.write_bytes(b'KEEP OUTPUT')
        with self.assertRaises(ValueError):B.reconstruct(self.author,self.basis,self.output,self.profile)
        self.assertEqual(self.output.read_bytes(),b'KEEP OUTPUT');self.assertFalse(self.profile.exists());self.output.unlink()
        self.profile.write_bytes(b'KEEP PROFILE')
        with self.assertRaises(ValueError):B.reconstruct(self.author,self.basis,self.output,self.profile)
        self.assertEqual(self.profile.read_bytes(),b'KEEP PROFILE');self.assertFalse(self.output.exists())

    def test_outputs_inside_inputs_insecure_parent_or_profile_overlap_refuse(self):
        for changes in(dict(output=self.author/'fresh-output'),dict(profile_path=self.basis/'fresh-profile'),
                       dict(profile_path=self.output),dict(output=B.CODE_ROOT/'FOREIGN_BOOTSTRAP_OUTPUT')):
            with self.subTest(changes=changes):self.refuse(**changes)
        insecure=self.root/'foreign-writable';insecure.mkdir();insecure.chmod(0o777)
        try:self.refuse(output=insecure/'fresh-output')
        finally:insecure.chmod(0o700)
        target=self.root/'ordinary-target';target.mkdir();alias=self.root/'output-alias';alias.symlink_to(target,target_is_directory=True)
        self.refuse(output=alias/'fresh-output')

    def test_actor_audit_denies_named_boundaries_without_entering_an_actor(self):
        with patch.object(B,'ACTOR_ATTEMPTS',[])as attempts:
            for event in('subprocess.Popen','socket.connect','ctypes.dlopen','ctypes.call_function','os.exec','os.spawn',
                         'os.fork','os.posix_spawn','os.system','fcntl.flock','resource.setrlimit'):
                with self.subTest(event=event),self.assertRaises(RuntimeError):B.fence(event,())
            self.assertEqual(len(attempts),11)


def genuine_cases(author,basis):
    class GenuineReconstruction(unittest.TestCase):
        def test_exact_source205_reader_profile_and_preserved_input_pins(self):
            constructor,reader,_,_,_=B.checked_author(author)
            before=constructor.load_basis(basis)
            expected_files={name:B.read(author/name,row)for name,row in author_files().items()}
            with tempfile.TemporaryDirectory(prefix='source205-ci-genuine-DATA-')as temporary:
                root=Path(temporary);output,profile=root/'source205',root/'profile.UNISSUED.json'
                result=B.reconstruct(author,basis,output,profile)
                self.assertEqual(result['status'],'PASS_GENUINE_SOURCE205_DATA_RECONSTRUCTION')
                self.assertEqual(result['source'],reader.TRANSPORT_SOURCE)
                self.assertEqual(result['constructor_revision'],B.AUTHOR_REVISION)
                self.assertFalse(result['Git_identity_proved_inside_control'])
                self.assertIsNone(result['Root_acceptance']);self.assertFalse(result['native_acceptance'])
                self.assertEqual(result['actors'],[])
                value=json.loads(profile.read_bytes());self.assertTrue(all(v is None for v in value['actual'].values()))
                self.assertEqual(B.pin(profile.read_bytes()),result['profile'])
                _,_,_,_,C,H=constructor.load_helpers();source,raw=C.source(output,reader.TRANSPORT_SOURCE['source_map']['sha256'])
                rows=dict(source['files']);rows.update({name:dict(reader.TRANSPORT_SOURCE['source_map'],mode=0o644)
                    for name in('source-map.json','source.lock.json')})
                files={name:C.read(output/name,row)for name,row in rows.items()}
                self.assertEqual((len(files),sum(len(v[0])for v in files.values()),H.tree(files)),
                    (reader.TRANSPORT_SOURCE['files'],reader.TRANSPORT_SOURCE['bytes'],reader.TRANSPORT_SOURCE['tree']))
                self.assertEqual(constructor.inverse_v6(files),before)
            self.assertEqual({name:B.read(author/name,row)for name,row in author_files().items()},expected_files)
            self.assertEqual(constructor.load_basis(basis),before);self.assertEqual(B.ACTOR_ATTEMPTS,[])
    return GenuineReconstruction


if __name__=='__main__':
    parser=argparse.ArgumentParser(add_help=False)
    parser.add_argument('--author-data',type=Path);parser.add_argument('--basis',type=Path)
    chosen,remaining=parser.parse_known_args()
    if bool(chosen.author_data)!=bool(chosen.basis):parser.error('--author-data and --basis are required together')
    if chosen.author_data is not None:globals()['GenuineReconstruction']=genuine_cases(chosen.author_data,chosen.basis)
    unittest.main(argv=[sys.argv[0],*remaining],verbosity=2)
