#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure map/archive/guard controls only; never execute native package actors."""
import ast,importlib.util,os,stat,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('orphans3_lifecycle',HERE/'lifecycle.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)

class Lifecycle(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def control(self):
        rows={}
        for name in {M.PRODUCT}|M.FIXTURES:
            version=M.VERSION if name==M.PRODUCT else '1-1';p=self.root/(name+'-'+version+'-any.pkg.tar.zst');p.write_bytes(('inert test bytes '+name).encode());p.with_name(p.name+'.sig').write_bytes(b'inert signature fixture');rows[name]={'archive':p.name,'sha256':M.sha(p)}
        return {'signer':'A'*40,'candidate':rows.pop(M.PRODUCT),'fixtures':rows}
    def test_complete_nine_archive_schema_and_hash_join(self):
        value=self.control();self.assertEqual(set(M.archives(value,self.root)),{M.PRODUCT}|M.FIXTURES)
    def test_archive_hash_extra_version_and_fixture_membership_refuse(self):
        value=self.control();value['candidate']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'archive bytes'):M.archives(value,self.root)
        value=self.control();value['candidate']['archive']='cachy-asahi-orphans-0.1.0-2-any.pkg.tar.zst'
        with self.assertRaisesRegex(ValueError,'basename'):M.archives(value,self.root)
        value=self.control();value['fixtures'].pop(M.PREFIX+'leaf-a')
        with self.assertRaisesRegex(ValueError,'eight'):M.archives(value,self.root)
        value=self.control();(self.root/'arbitrary-1-1-any.pkg.tar.zst').write_bytes(b'never run')
        with self.assertRaisesRegex(ValueError,'additional'):M.archives(value,self.root)
    def test_archive_and_signature_aliases_refuse(self):
        value=self.control();p=self.root/value['candidate']['archive'];p.rename(self.root/'outside');p.symlink_to('outside')
        with self.assertRaisesRegex(ValueError,'archive bytes'):M.archives(value,self.root)
        p.unlink();(self.root/'outside').rename(p);s=p.with_name(p.name+'.sig');os.link(s,self.root/'signature-alias')
        with self.assertRaisesRegex(ValueError,'signature'):M.archives(value,self.root)
    def test_target_map_ignores_atime_but_binds_bytes_identity_links(self):
        d=self.root/'tree';d.mkdir();f=d/'held';f.write_text('inert');before=M.snapshot(d);f.read_bytes();self.assertTrue(M.preservation(before,M.snapshot(d)))
        f.write_text('changed')
        with self.assertRaisesRegex(ValueError,'unselected'):M.preservation(before,M.snapshot(d))
    def test_only_explicit_removal_projection_accepts_absence(self):
        d=self.root/'tree';d.mkdir();(d/'held').write_text('held');(d/'removed').write_text('remove');before=M.snapshot(d);(d/'removed').unlink();after=M.snapshot(d)
        self.assertTrue(M.preservation(before,after,['removed']))
        with self.assertRaisesRegex(ValueError,'undeclared'):M.preservation(before,after)
        (d/'new').write_text('new')
        with self.assertRaisesRegex(ValueError,'appeared'):M.preservation(before,M.snapshot(d),['removed'])
    def test_directory_inode_owner_and_mode_remain_bound(self):
        d=self.root/'tree';d.mkdir();(d/'held').write_text('held');before=M.snapshot(d);d.chmod(0o700)
        with self.assertRaisesRegex(ValueError,'directory'):M.preservation(before,M.snapshot(d))
    def test_mode000_lock_is_recorded_without_read_or_permission_change(self):
        d=self.root/'tree';d.mkdir();p=d/'db.lck';p.write_text('other pid\n');p.chmod(0);rows=M.snapshot(d);self.assertEqual(rows['db.lck']['mode'],0);self.assertNotIn('sha256',rows['db.lck']);self.assertEqual(stat.S_IMODE(p.stat().st_mode),0)
    def test_guard_refuses_before_any_native_actor_on_host(self):
        with patch.object(M.os,'getuid',return_value=1000),patch.object(M.subprocess,'run',side_effect=AssertionError('must not invoke')):
            with self.assertRaisesRegex(ValueError,'dedicated'):M.guard()
    def test_actor_source_uses_installed_actual_backend_and_real_cli(self):
        source=(HERE/'lifecycle.py').read_text();self.assertIn("Path('/usr/lib/cachy-asahi-orphans3/remove.py')",source);self.assertIn('self.holder.begin()',source);self.assertNotIn('ModelTransaction',source);self.assertNotIn('factory=',source)
        trial=next(n for n in ast.parse(source).body if isinstance(n,ast.ClassDef) and n.name=='Trial')
        methods={n.name:n for n in trial.body if isinstance(n,ast.FunctionDef)};run=methods['run']
        pm=next(n.value for n in run.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='pm' for t in n.targets))
        self.assertIsInstance(pm,ast.List);self.assertNotIn('--noscriptlet',[n.value for n in pm.elts if isinstance(n,ast.Constant)])
        operations={};outer_operations=set()
        for call in ast.walk(run):
            if not(isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name) and call.func.value.id=='self' and call.func.attr=='command'):continue
            if not(call.args and isinstance(call.args[0],ast.BinOp) and isinstance(call.args[0].op,ast.Add) and isinstance(call.args[0].left,ast.Name)):continue
            base=call.args[0].left.id
            if base not in ('pm','outer'):continue
            operands=call.args[0].right;self.assertIsInstance(operands,ast.List)
            flags=[n.value for n in operands.elts if isinstance(n,ast.Constant)]
            if base=='pm':
                operation=flags[1] if flags and flags[0]=='--noscriptlet' else flags[0]
                self.assertNotIn(operation,operations);operations[operation]=flags
            else:outer_operations.add(flags[0])
        self.assertEqual(operations,{'-U':['--noscriptlet','-U','--asdeps'],'-D':['-D','--asexplicit']})
        query=next(n for n in ast.walk(methods['inventory']) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='command')
        self.assertEqual(ast.dump(query.args[0]),ast.dump(ast.parse("pacman+['-Q']",mode='eval').body))
        inventories=[n for n in ast.walk(run) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='inventory' and n.args and isinstance(n.args[0],ast.Name) and n.args[0].id=='pm']
        self.assertEqual(len(inventories),2);self.assertEqual(outer_operations,{'-U','-R'})
        outer=next(n.value for n in methods['signed_pacman'].body if isinstance(n,ast.Return));self.assertIsInstance(outer,ast.List)
        self.assertEqual([n.value for n in outer.elts if isinstance(n,ast.Constant)][-2:],['--noconfirm','--noscriptlet'])

if __name__=='__main__':unittest.main()
