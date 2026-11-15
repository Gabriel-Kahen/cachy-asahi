# SPDX-License-Identifier: MIT
"""Fenced DATA controls; no candidate, acquired binary, daemon or actor runs."""
import ast
import copy
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('rust_entry_data',HERE/'entry.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)


def modeled():
    def descriptor(i):return dict(path='/inputs/proof-'+str(i),local_path='/root/private/proof-'+str(i),bytes=1,sha256='b'*64)
    return dict(candidate_admission=descriptor(0),candidate=dict(qualification=descriptor(1)),stage0_tree_sha256='c'*64,image_root='/qualified/original-root',
        image=dict(id='sha256:'+'d'*64,rootfs_tree_sha256='e'*64,qualified_llvm_tree_sha256='f'*64,qualification_proof=descriptor(7),baseline_inventory=descriptor(8),qualified_inventory=descriptor(9),readonly_volume_subpath_proof=descriptor(10)),
        llvm={name:descriptor(i) for i,name in enumerate(('archive','signature','public_test_key','verification_proof','root_decision'),2)},
        materials=[dict(name=name,bytes=i+1,sha256='a'*64,local_path='/host/'+name,transport='LOCAL_READONLY') for i,name in enumerate(('cargo.tar.xz','llvm.tar.xz','std.tar.xz','rustc.tar.xz','rust-src.tar.xz'))])


class Controls(unittest.TestCase):
    def test_pure_normalization_preserves_original_and_host_paths(self):
        value=modeled();before=copy.deepcopy(value);n=e.normalize(value)
        self.assertEqual(value,before);self.assertEqual(n['root_admission_sha256'],e.pin(e.encode(value))['sha256'])
        self.assertEqual(n['image_id'],value['image']['id']);self.assertEqual(n['candidate_admission'],{k:value['candidate_admission'][k] for k in ('path','sha256')})
        self.assertEqual(n['materials']['cargo.tar.xz']['path'],'/materials/cargo.tar.xz');self.assertNotIn('authority',n)

    def test_actor_proof_projection_is_copy_and_closed(self):
        value=modeled();before=copy.deepcopy(value);projected=e.actor_projection(value)
        self.assertEqual(value,before);self.assertEqual(len(list(e.descriptors(projected))),11)
        self.assertTrue(all(row['local_path']==row['path'] for row in e.descriptors(projected)))
        self.assertTrue(all(row['local_path']=='/materials/'+row['name'] for row in projected['materials']))
        value['llvm']['signature']['path']=value['llvm']['archive']['path']
        with self.assertRaises(ValueError):e.actor_projection(value)

    def test_three_exact_recipe_hooks_and_whole_inverse(self):
        lines=[]
        for action in ('prepare','build','package'):
            suffix=' --destination "$pkgdir"' if action=='package' else ''
            lines.append(f'  python -I "$srcdir/reference.py" {action} --work "$srcdir"{suffix} || return')
        original=('header\n'+'\n'.join(lines)+'\ntail\n').encode();effective=e.project_recipe(original)
        self.assertEqual(effective.count(b'/usr/bin/python -I -B /source/actor/entry.py'),3)
        restored=effective
        for old,action in zip(lines,('prepare','build','package')):restored=restored.replace(f'  /usr/bin/python -I -B /source/actor/entry.py {action} || return'.encode(),old.encode())
        self.assertEqual(restored,original)
        with self.assertRaises(ValueError):e.project_recipe(original+lines[0].encode())

    def test_nested_makepkg_environment_preserves_only_explicit_root_pins(self):
        trust={key:chr(97+i)*64 for i,key in enumerate(e.TRUST)}
        actual=e.command_environment(dict(PATH='/usr/bin',MAKEFLAGS='-j2',ROOT_ADMISSION_SHA256='wrong'),trust)
        self.assertEqual({key:actual[key] for key in e.TRUST},trust);self.assertEqual(actual['MAKEFLAGS'],'-j2')
        self.assertEqual(actual['PYTHONDONTWRITEBYTECODE'],'1');self.assertNotIn('CARGO_MAKEFLAGS',actual)
        with self.assertRaises(ValueError):e.command_environment({},dict(ROOT_ADMISSION_SHA256='a'*64))

    def test_missing_root_gate_stops_before_source_import(self):
        with self.assertRaises(ValueError):e.gate({})
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1.2}'):
            with self.assertRaises(ValueError):e.decode(raw)

    def test_owned_zero_requires_complete_natural_retirement(self):
        row=dict(natural_exit=True,forced_cleanup=False,retirement='REAPED',group_absent=True,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,ownership_lost=False,exit=0)
        self.assertTrue(e.natural(row))
        for key,value in (('forced_cleanup',True),('group_absent',False),('ownership_lost',True),('exit',False),('cleanup_error','lost')):
            with self.subTest(key=key):self.assertFalse(e.natural(dict(row,**{key:value})))

    def test_global_log_aggregate_refuses_even_individually_bounded_streams(self):
        class FakePath:
            def __init__(self,name,size):self.name=name;self.size=size
            def lstat(self):return SimpleNamespace(st_mode=0o100600,st_nlink=1,st_size=self.size)
        paths=[FakePath('one.stdout',32*e.MIB),FakePath('two.stderr',32*e.MIB),FakePath('makepkg.log',1)]
        with patch.object(e,'OUT',SimpleNamespace(iterdir=lambda:iter(paths))):
            with self.assertRaises(ValueError):e.output_watch()

    def test_source_has_no_candidate_import_and_restores_inherited_limit(self):
        tree=ast.parse((HERE/'entry.py').read_text());text=ast.unparse(tree)
        self.assertIn('resource.setrlimit(resource.RLIMIT_FSIZE, old_fsize)',text)
        self.assertIn('admission.external_proofs(mapped)',text);self.assertIn('capture=True',text)
        self.assertNotIn('subprocess.run(',text);self.assertNotIn('reference.py',str([x.names for x in tree.body if isinstance(x,ast.Import)]))


def fence(event,args):
    if event.startswith(('subprocess.','socket.','os.exec','os.spawn','os.posix_spawn')) or event in ('os.system','os.fork','os.forkpty'):
        raise AssertionError('DATA-only actor fence: '+event)


if __name__=='__main__':sys.addaudithook(fence);unittest.main()
