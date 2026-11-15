# SPDX-License-Identifier: MIT
"""FENCED synthetic DATA controls. No operational Reader/main/replay invocation."""
import copy
import contextlib,ctypes,fcntl,socket,subprocess
from unittest.mock import patch
import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fenced_independent_reader',HERE/'reader.py')
r = importlib.util.module_from_spec(spec);spec.loader.exec_module(r)


def life():
    return dict(natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,retirement='REAPED',ownership_lost=False,forced_cleanup=False,exit=0)


def elf_bytes(machine=183,alignment=16384,needed=None,rpath=None,soname=None):
    header = bytearray(64);header[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH',header,16,3,machine)
    struct.pack_into('<Q',header,32,64)
    count = 2 if any((needed,rpath,soname)) else 1
    struct.pack_into('<HH',header,54,56,count)
    if count == 1:return bytes(header)+struct.pack('<IIQQQQQQ',1,5,0,0,0,120,120,alignment)
    strings = bytearray(b'\0');pairs = []
    for kind,text in ((1,needed),(29,rpath),(14,soname)):
        if text is not None:
            pairs.append((kind,len(strings)));strings.extend(text.encode()+b'\0')
    dynamic_size = (len(pairs)+3)*16;string_offset = 176+dynamic_size
    pairs = [(5,string_offset),(10,len(strings))]+pairs+[(0,0)]
    total = string_offset+len(strings)
    return bytes(header)+struct.pack('<IIQQQQQQ',1,5,0,0,0,total,total,alignment)+struct.pack('<IIQQQQQQ',2,4,176,176,176,dynamic_size,dynamic_size,8)+b''.join(struct.pack('<qQ',*p) for p in pairs)+strings


def modeled_runtime():
    mounts = '\n'.join([
        '1 0 0:1 / / ro - overlay overlay ro',
        '2 1 0:2 / /inputs ro - ext4 inputs ro',
        '3 1 0:3 / /source ro - ext4 source ro',
        '4 1 0:4 / /work rw - ext4 work rw',
        '5 1 0:5 / /tmp rw,noexec,nosuid,nodev - tmpfs tmpfs rw,size=65536k,uid=1001,gid=1001',
        '6 1 0:6 / /run rw,noexec,nosuid,nodev - tmpfs tmpfs rw,size=8192k,uid=1001,gid=1001'])
    parent = dict(pid=1,ppid=0,starttime=10,uid=1001,euid=1001,gid=1001,egid=1001,architecture='aarch64',page_bytes=4096,groups=[1001],limits={'cpu.max':'200000 100000','memory.max':'8589934592','memory.swap.max':'0','pids.max':'512'},interfaces=['lo'],hostname='llvm23-native',status={**{n:'0000000000000000' for n in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')},'NoNewPrivs':'1','Seccomp':'2','Seccomp_filters':'1'},uid_map=[[0,0,4294967295]],gid_map=[[0,0,4294967295]],namespaces={n:n+':['+str(i)+']' for i,n in enumerate(('user','mnt','net','pid'),10)},mountinfo=mounts,exe='/sbin/docker-init',cmdline=['/sbin/docker-init','--','/usr/bin/bash','--noprofile','--norc','/inputs/actor/entry.sh'],cwd='/work',cgroup='0::/\n')
    entry = copy.deepcopy(parent);entry.update(pid=7,ppid=1,starttime=20,exe='/usr/bin/python3.14',cmdline=['/usr/bin/python3','-I','-B','/inputs/actor/entry.py'],cwd='/work/recipe')
    return {'entry':entry,'parent':parent}


def mini_package(destination,escape=False,cycle=False,rel_tool=False,llvm_soname='libLLVM.so.23.1'):
    import compression.zstd
    prefix = r.PREFIX.lstrip('/')
    files = {'.PKGINFO':b'FENCED_SYNTHETIC_NOT_NATIVE\n','.BUILDINFO':b'FENCED_SYNTHETIC_NOT_NATIVE\n'}
    for tool in ('llvm-config','clang','clang++','ld.lld','llvm-ar','llvm-ranlib'):
        files[prefix+'/bin/'+tool] = elf_bytes(needed='libLLVM.so.23.1',rpath='$ORIGIN/../lib')
    files[prefix+'/lib/libLLVM.so.23.1'] = elf_bytes(soname=llvm_soname)
    if rel_tool:
        body = bytearray(files[prefix+'/bin/clang']);struct.pack_into('<H',body,16,1);files[prefix+'/bin/clang'] = body
    files[prefix+'/lib/libunwind.so.1'] = elf_bytes(soname='libunwind.so.1')
    for name in ('lib/libunwind.a','lib/clang/23/lib/linux/libclang_rt.builtins-aarch64.a','lib/clang/23/lib/linux/libclang_rt.profile-aarch64.a'):
        files[prefix+'/'+name] = b'!<arch>\n'
    with tempfile.TemporaryFile() as raw:
        with tarfile.open(fileobj=raw,mode='w') as archive:
            for name,body in files.items():
                info = tarfile.TarInfo(name);info.mode = 0o755 if '/bin/' in name else 0o644;info.size = len(body);archive.addfile(info,io.BytesIO(body))
            if cycle:
                for name,target in [('loop-a','loop-b'),('loop-b','loop-a')]:
                    info = tarfile.TarInfo(prefix+'/lib/'+name);info.type = tarfile.SYMTYPE;info.linkname = target;archive.addfile(info)
            if escape:
                info = tarfile.TarInfo(prefix+'/lib/escape');info.type = tarfile.SYMTYPE;info.linkname = '/usr/lib/global';archive.addfile(info)
        raw.seek(0)
        with compression.zstd.ZstdFile(destination,'wb') as output:
            while block := raw.read(65536):output.write(block)


class FencedFixtureControls(unittest.TestCase):
    def test_all_actual_selectors_are_null_and_template_refuses(self):
        binding = r.load(HERE/'binding.TEMPLATE.json');pins = r.load(HERE/'pins.json')
        self.assertTrue(all(v is None for v in binding['actual'].values()))
        with self.assertRaisesRegex(ValueError,'selectors remain unbound'):
            r.check_binding(binding,pins)
        self.assertIsNone(binding['original_archive']['sha256'])
        self.assertIsNone(binding['full_original_decode']['map_sha256'])

    def test_json_duplicate_nonfinite_and_path_refusals(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":1e999}'):
            with self.assertRaises(ValueError):r.decode(raw)
        for name in ('../escape','a//b','/absolute','x/./y'):
            with self.assertRaises(ValueError):r.safe_name(name)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);(root/'data').write_text('fixture');(root/'link').symlink_to('data')
            with self.assertRaisesRegex(ValueError,'ordinary absolute'):r.hashed(root/'link')
            os.mkfifo(root/'fifo')
            with self.assertRaisesRegex(ValueError,'single-link DATA'):r.hashed(root/'fifo')

    def test_full_original_zip_fixture_and_wrong_decode_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);archive = root/'FENCED.zip'
            payload = {'a.json':b'{}','logs/b.log':b'fixture\n'}
            with zipfile.ZipFile(archive,'w') as output:
                for name,body in payload.items():output.writestr(name,body)
            rows = {n:{'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()} for n,v in payload.items()}
            expected = {'files':2,'bytes':sum(len(v) for v in payload.values()),'map_sha256':hashlib.sha256(r.canonical(rows)).hexdigest()}
            self.assertEqual(r.full_zip(archive,root/'decoded',expected),rows)
            self.assertEqual((root/'decoded/a.json').stat().st_mode & 0o777,0o400)
            expected['files'] = 1
            with self.assertRaisesRegex(ValueError,'full Original decode'):r.full_zip(archive,root/'wrong',expected)

    def test_source_git_object_known_vectors_and_manifest_rows(self):
        self.assertEqual(r.git_oid('blob',b''),'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391')
        self.assertEqual(r.git_oid('tree',b''),'4b825dc642cb6eb9a060e54bf8d69288fbee4904')
        # The real hosted proof schema is bytes/sha256/int mode/blob, not oid.
        source = (HERE/'reader.py').read_text()
        self.assertIn('found[relative] = dict(row,mode=mode,blob=',source)
        self.assertIn("readback['files'] == blobs",source)

    def test_fenced_full_source_git_tree_and_changed_leaf(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bodies = {'original/data.txt':b'FENCED_FIXTURE_NOT_ACTUAL_SOURCE\n','policy.json':b'{}\n'}
            original = {'actual':{'source':None,'ref':None,'run':None},'files':{'data.txt':dict(bytes=len(bodies['original/data.txt']),sha256=hashlib.sha256(bodies['original/data.txt']).hexdigest(),mode=0o644)}}
            bodies['original/native/source-map.json'] = r.canonical(original)
            manifest = {'schema':1,'actual':{'source':None},'files':{n:dict(bytes=len(v),sha256=hashlib.sha256(v).hexdigest(),mode=0o644) for n,v in bodies.items()}}
            bodies['source-map.json'] = r.canonical(manifest)
            for name,body in bodies.items():
                p = root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(body);p.chmod(0o644)
            # Bottom-up Git tree construction, separate from Reader's top-down walk.
            blobs = {n:r.git_oid('blob',v) for n,v in bodies.items()}
            native = r.git_oid('tree',b'100644 source-map.json\0'+bytes.fromhex(blobs['original/native/source-map.json']))
            original_tree = r.git_oid('tree',b'100644 data.txt\0'+bytes.fromhex(blobs['original/data.txt'])+b'40000 native\0'+bytes.fromhex(native))
            tree = r.git_oid('tree',b'40000 original\0'+bytes.fromhex(original_tree)+b'100644 policy.json\0'+bytes.fromhex(blobs['policy.json'])+b'100644 source-map.json\0'+bytes.fromhex(blobs['source-map.json']))
            commit = ('tree '+tree+'\n\nFENCED_FIXTURE_NOT_ACTUAL_SOURCE\n').encode()
            pins = dict(source_tree=tree,source_map_sha256=hashlib.sha256(bodies['source-map.json']).hexdigest(),source_files=4,source_bytes=sum(map(len,bodies.values())))
            found = r.source_tree(root,pins,commit,r.git_oid('commit',commit))
            self.assertEqual(set(found['policy.json']),{'bytes','sha256','mode','blob'})
            self.assertEqual(found['policy.json']['blob'],blobs['policy.json'])
            (root/'policy.json').write_text('changed fixture')
            with self.assertRaisesRegex(ValueError,'Source byte/mode drift'):
                r.source_tree(root,pins,commit,r.git_oid('commit',commit))

    def test_natural_exclusive_retirement_fixtures(self):
        r.natural(life())
        for key,value in [('forced_cleanup',True),('ownership_lost',True),('natural_exit',False),('exit_observed_via_waitpid',False),('retirement','UNKNOWN')]:
            row = life();row[key] = value
            with self.assertRaisesRegex(ValueError,'retirement unproven/forced'):r.natural(row)

    def test_native4k_runtime_and_domain_tampering_fixtures(self):
        value = modeled_runtime();r.runtime(value)
        for key,value2 in [('page_bytes',16384),('architecture','x86_64'),('uid',0),('uid_map',[[0,1001,1]])]:
            changed = copy.deepcopy(value);changed['entry'][key] = value2
            with self.assertRaises(ValueError):r.runtime(changed)
        changed = copy.deepcopy(value);changed['entry']['status']['CapEff'] = '1'
        with self.assertRaisesRegex(ValueError,'cap0'):r.runtime(changed)
        changed = copy.deepcopy(value);changed['entry']['mountinfo'] = changed['entry']['mountinfo'].replace('/source ro','/source rw')
        with self.assertRaises(ValueError):r.runtime(changed)

    def test_independent_elf_16k_private_rpath_fixtures(self):
        name = r.PREFIX.lstrip('/')+'/bin/clang'
        for body in (elf_bytes(machine=62),elf_bytes(alignment=4096),elf_bytes(needed='libLLVM.so.23.1',rpath='/usr/lib'),elf_bytes(needed='libLLVM.so.23.1',rpath='$ORIGIN')):
            with self.assertRaises(ValueError):r.elf(io.BytesIO(body),len(body),name)
        body = elf_bytes(needed='libLLVM.so.23.1',rpath='$ORIGIN/../lib')
        self.assertEqual(r.elf(io.BytesIO(body),len(body),name)['rpaths'],[r.PREFIX+'/lib'])
        relocatable = bytearray(elf_bytes());struct.pack_into('<H',relocatable,16,1)
        self.assertEqual(r.elf(io.BytesIO(relocatable),len(relocatable),name)['kind'],1)

    def test_package_streaming_elf_ownership_and_escape_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);package = root/'FENCED.pkg.tar.zst'
            mini_package(package)
            rows,elfs,metadata = r.package_data(package,root)
            self.assertEqual(len(elfs),8)
            self.assertIn('.PKGINFO',metadata)
            self.assertIn(r.PREFIX.lstrip('/')+'/bin/clang',rows)
            mini_package(package,escape=True)
            with self.assertRaisesRegex(ValueError,'absolute package symlink'):r.package_data(package,root)
            for options in ({'cycle':True},{'rel_tool':True},{'llvm_soname':'libLLVM.so.99'}):
                mini_package(package,**options)
                with self.assertRaises(ValueError):r.package_data(package,root)

    def test_export_rejects_links_before_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);archive = root/'FENCED.tar'
            with tarfile.open(archive,'w') as output:
                item = tarfile.TarInfo('output/link');item.type = tarfile.SYMTYPE;item.linkname = '/outside';output.addfile(item)
            with self.assertRaisesRegex(ValueError,'flat regular'):r.export_data(archive,root/'out')
            self.assertFalse((root/'out/link').exists())

    def test_exact_null_pins_and_no_source_code_imports_or_network(self):
        pins = r.load(HERE/'pins.json')
        self.assertEqual(pins['source_files'],251)
        self.assertEqual(pins['source_bytes'],40807998)
        self.assertEqual(pins['source_map_sha256'],'809f57839dfd574b7abf0c65535321aeac08c58608d4f9597f936a7af78fb3a2')
        code = (HERE/'reader.py').read_text()
        syntax = ast.parse(code)
        modules = {n.name.split('.')[0] for node in ast.walk(syntax) if isinstance(node,ast.Import) for n in node.names}
        modules |= {node.module.split('.')[0] for node in ast.walk(syntax) if isinstance(node,ast.ImportFrom)}
        self.assertFalse(modules & {'subprocess','urllib','importlib','socket'})
        self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in {'eval','exec','__import__'} for n in ast.walk(syntax)))
        self.assertFalse(hasattr(r,'SourceReader'))


if __name__ == '__main__':
    import compression.zstd  # Preload stdlib before the DATA-only process/dlopen fence.
    def denied(*a,**k):raise AssertionError('operational actor forbidden in DATA controls')
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(r,'main',denied));stack.enter_context(patch.object(r,'replay',denied))
        for module,names in ((fcntl,('flock',)),(ctypes,('CDLL',)),(socket,('socket','create_connection')),(subprocess,('Popen','run','check_output')),(os,('fork','forkpty','system','posix_spawn','posix_spawnp','execv','execve','execvp','execvpe','pidfd_open','unshare','setns'))):
            for name in names:
                if hasattr(module,name):stack.enter_context(patch.object(module,name,denied))
        unittest.main()
