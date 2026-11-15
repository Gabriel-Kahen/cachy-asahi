# SPDX-License-Identifier: MIT
"""Source/projection DATA controls only: no candidate import or native actor."""
import ast
import importlib.util
import os
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('rust199_phase_data',HERE/'phase.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


class Controls(unittest.TestCase):
    def test_exact_projection_inverse(self):
        for old,new in ((p.PROBE_VECTOR,p.NATIVE_PROBE),(p.BUILD_VECTOR,p.NATIVE_BUILD)):
            result=p.project(p.WORK,Path('/qualified/root'),old,'/qualified/root')
            self.assertEqual(result,new);self.assertEqual(p.inverse_projection(result),old)
        self.assertNotIn('bwrap',' '.join(p.NATIVE_BUILD));self.assertIn('-B',p.NATIVE_BUILD)
        self.assertEqual(p.NATIVE_BUILD[-2:],['-j','2'])

    def test_alternate_command_path_arguments_refused(self):
        for old in (['/usr/bin/bash'],p.BUILD_VECTOR+['--download'],['python']+p.BUILD_VECTOR[1:],p.PROBE_VECTOR+['x']):
            with self.subTest(old=old),self.assertRaises(ValueError):p.project(p.WORK,Path('/qualified/root'),old,'/qualified/root')
        with self.assertRaises(ValueError):p.project(Path('/other'),Path('/qualified/root'),p.BUILD_VECTOR,'/qualified/root')
        with self.assertRaises(ValueError):p.project(p.WORK,Path('/other'),p.BUILD_VECTOR,'/qualified/root')
        with self.assertRaises(ValueError):p.inverse_projection(p.NATIVE_BUILD+['x'])

    def test_environment_closes_ambient_jobserver_and_cargo_overrides(self):
        previous=dict(os.environ)
        try:
            os.environ.update(MAKEFLAGS='--jobserver-auth=30,31',CARGO_MAKEFLAGS='--jobserver-auth=30,31',RUSTC='/unadmitted/rustc',CARGO_HOME='/host/cargo')
            value=p.environment('a'*64,'b'*64)
            self.assertEqual(value['MAKEFLAGS'],'-j2');self.assertNotIn('CARGO_MAKEFLAGS',value);self.assertNotIn('RUSTC',value)
            self.assertEqual(value['CARGO_HOME'],'/work/build/cargo-home');self.assertEqual(value['CARGO_NET_OFFLINE'],'true')
            self.assertEqual(value['PATH'],'/stage0/bin:/opt/cachy-asahi/llvm23-source-reference/bin:/usr/bin:/bin')
            self.assertEqual(value['DESTDIR'],'/work/build/dest');self.assertTrue(all(type(x) is str for x in value.values()))
            self.assertNotIn('jobserver',' '.join(value.values()))
        finally:os.environ.clear();os.environ.update(previous)

    def test_missing_environment_pins_refused(self):
        for value in (None,'','unqualified','a'*63):
            with self.subTest(value=value),self.assertRaises(ValueError):p.environment(value,'b'*64)

    def test_five_material_projection_and_stage0_destination(self):
        rows={'cargo.tar.xz':{'role':'stage0'},'llvm.tar.xz':{'role':'source'},'std.tar.xz':{'role':'stage0'},'rustc.tar.xz':{'role':'stage0'},'rust-src.tar.xz':{'role':'source'}}
        result=p.extraction_vectors(rows);self.assertEqual(len(result),5)
        for (name,row),argv in zip(rows.items(),result):
            self.assertEqual(argv[:4],['/usr/bin/bsdtar','--no-same-owner','--no-same-permissions','-xf'])
            self.assertEqual(argv[4],'/work/build/verified-materials/'+name)
            self.assertEqual(argv[5:],['-C','/work/build/stage0-unpack' if row['role']=='stage0' else '/work/build'])

    def test_exact_nine_source_probe_children(self):
        self.assertEqual(len(p.PROBE_COMMANDS),9);self.assertEqual(p.PROBE_COMMANDS[:2],[['/stage0/bin/rustc','-vV']]*2)
        self.assertEqual(p.PROBE_COMMANDS[5][0],str(p.LLVM/'bin/llvm-config'))
        self.assertEqual(p.PROBE_COMMANDS[-1],[str(p.LLVM/'bin/ld.lld'),'--version'])
        self.assertTrue(all(argv[0].startswith(('/stage0/bin/','/usr/bin/','/opt/cachy-asahi/llvm23-source-reference/bin/')) for argv in p.PROBE_COMMANDS))

    def test_unadmitted_operation_refuses_before_runtime_or_candidate(self):
        for action,a,call in [('prepare',{'schema':1,'operation':'other'},lambda *a,**k:None),('unknown',{},lambda *a,**k:None),('prepare',{},None)]:
            with self.subTest(action=action),self.assertRaises(ValueError):p.run_phase(action,a,call)

    def test_source_patch_restores_all_three_seams_and_environment(self):
        tree=ast.parse((HERE/'phase.py').read_text());function=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='run_phase')
        cleanup=[x for x in ast.walk(function) if isinstance(x,ast.Try) and x.finalbody][-1].finalbody
        rendered='\n'.join(ast.unparse(x) for x in cleanup)
        for value in ('candidate.subprocess.run = saved_run','candidate.subprocess.check_output = saved_output','candidate.sandbox_command = saved_sandbox','os.environ.update(saved_env)','_ACTIVE = False'):
            self.assertIn(value,rendered)
        self.assertNotIn('preflight(',ast.unparse(function));self.assertIn('candidate.admission(',ast.unparse(function))


if __name__=='__main__':unittest.main()
