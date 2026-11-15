# SPDX-License-Identifier: MIT
"""Fenced explicit-link certificate/packet controls; no compiler or guest run."""
import copy
import importlib.util
from pathlib import Path
import shlex
import sys
import unittest

HERE = Path(__file__).resolve().parent

def load(name):
    s=importlib.util.spec_from_file_location('probe_control_'+name,HERE/(name+'.py'))
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

M=load('test_contracts');K=M.K;A=load('adapter')

def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
        raise RuntimeError('probe DATA control operational fence: '+event)

sys.addaudithook(fence)


class Controls(unittest.TestCase):
    def reject(self, change):
        args=M.modeled();change(args[3])
        with self.assertRaises((ValueError,KeyError)):K.validate(*M.reseal(args))

    def test_headerless_success_without_GCC_development_files(self):
        args=M.modeled();del args[3]['files']['/usr/include/empty-model.h']
        K.validate(*M.reseal(args));binding=K.probe_inputs(args[3])
        self.assertEqual(binding['lib_cxx'],'/usr/lib/libstdc++.so.6.MODEL')
        self.assertEqual(binding['lib_unwind'],'/usr/lib/libgcc_s.so.1')
        self.assertEqual(binding['builtins'],K.BUILTINS)
        self.assertFalse(any('crtbegin' in p or 'crtend' in p or '/include/c++' in p for p in args[3]['files']))

    def test_old_or_implicit_GCC_modes_and_headers_refuse(self):
        for key,value in [('mode','EXPLICIT_COMPILER_RT'),('mode','EXPLICIT_GCC'),('gcc_prefix','/usr'),('headers',['/usr/include/empty-model.h'])]:
            with self.subTest(key=key,value=value):self.reject(lambda r:r['gcc_driver_selection'].__setitem__(key,value))

    def test_startfile_and_unversioned_library_aliases_refuse(self):
        for role,paths in [('startfiles',['/usr/lib/crtbeginS.o']),('libraries',['/usr/lib/libstdc++.so']),('libraries',['/usr/lib/libgcc_s.so'])]:
            with self.subTest(role=role,paths=paths):self.reject(lambda r:r['gcc_driver_selection'].__setitem__(role,paths))

    def test_candidate_builtins_and_required_division_export_are_mandatory(self):
        for kind in ('absent','empty','wrong-path','missing-symbol'):
            def change(r):
                if kind=='absent':del r['candidate_namespace'][K.BUILTINS]
                elif kind=='empty':r['candidate_namespace'][K.BUILTINS]['bytes']=0
                elif kind=='wrong-path':r['gcc_driver_selection']['builtins']='/usr/lib/libgcc.a'
                else:r['gcc_driver_selection']['builtins_symbols']=[]
            with self.subTest(kind=kind):self.reject(change)

    def test_Root39_like_missing_Cxx_physical_ELF_proof_refuses(self):
        self.reject(lambda r:r['gcc_driver_selection']['baseline_elfs'].pop('/usr/lib/libstdc++.so.6'))
        self.reject(lambda r:r['files'].pop('/usr/lib/libstdc++.so.6'))

    def test_required_exception_typeinfo_and_unwind_exports_refuse(self):
        for path,symbol in [('/usr/lib/libstdc++.so.6','__cxa_throw'),('/usr/lib/libstdc++.so.6','_ZTIi'),('/usr/lib/libgcc_s.so.1','_Unwind_Resume')]:
            with self.subTest(symbol=symbol):self.reject(lambda r:r['gcc_driver_selection']['baseline_elfs'][path]['defined_symbols'].remove(symbol))

    def test_exact_baseline_SONAME_pin_and_GNU_version_provider_closure(self):
        for kind in ('hash','soname','provider','version','architecture','4K'):
            def change(r):
                e=r['gcc_driver_selection']['baseline_elfs']['/usr/lib/libstdc++.so.6']
                if kind=='hash':e['sha256']='0'*64
                elif kind=='soname':e['soname']='libstdc++.so'
                elif kind=='provider':e['needed'].append('libUNKNOWN.so.1')
                elif kind=='architecture':e['machine']=62
                elif kind=='4K':e['static_16k_geometry']=False
                else:e['version_needs']['libgcc_s.so.1']=['GCC_UNPROVED']
            with self.subTest(kind=kind):self.reject(change)

    def test_packet_binds_only_certified_resolved_operands(self):
        args=M.modeled();cert=dict(zip(K.EVIDENCE,args[2:]));rows=A.contents(args[0],cert,dict(bytes=1,sha256='c'*64),'a'*32)
        binding=dict(line.split('=',1)for line in rows['probe-link.env'][0].decode().splitlines())
        self.assertEqual(binding,K.probe_inputs(args[3]));self.assertEqual(len(binding),11)
        self.assertEqual(binding['linker'],K.PREFIX+'/bin/ld.lld')
        for role,path in binding.items():
            if role!='link_mode':self.assertEqual(K.guest_path(path),path)
        self.assertIn(args[3]['files']['/usr/lib/libstdc++.so.6']['sha256'].encode(),rows['runtime-paths.sha256'][0])

    def test_guest_link_commands_disable_defaults_and_retain_finite_two_compile_shape(self):
        text=(HERE/'guest/probe.sh').read_text();start=text.index('link_flags=(')+len('link_flags=(');end=text.index(')\n',start)
        flags=shlex.split(text[start:end]);self.assertTrue({'-nostdlib','-nostartfiles','-nostdlib++','-nostdinc','-nostdinc++','-pie','-Wl,--eh-frame-hdr','-Wl,-z,max-page-size=16384'}<=set(flags))
        commands=[shlex.split(line)for line in text.splitlines()if line.startswith('bounded "$compile_seconds"')]
        self.assertEqual(len(commands),2)
        for command in commands:
            self.assertIn('${link_flags[@]}',command);self.assertLess(command.index('$crt_start'),command.index('$crt_init'))
            self.assertLess(command.index('$builtins'),command.index('$crt_fini'));self.assertIn('$loader',command)
            self.assertFalse(any(v.startswith(('-l','-L','-I'))for v in command))
        self.assertIn('$lib_cxx',commands[1]);self.assertIn('$lib_unwind',commands[1])
        for event in ('subprocess.Popen','socket.__new__','ctypes.dlopen'):
            with self.assertRaises(RuntimeError):sys.audit(event)


if __name__=='__main__':unittest.main(verbosity=2)
