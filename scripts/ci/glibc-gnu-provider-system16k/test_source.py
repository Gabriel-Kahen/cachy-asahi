# SPDX-License-Identifier: MIT
"""Focused inert controls; no candidate/compiler/container/VM/network actor."""
import ast
import base64
import copy
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
import common as c
import run

ROOT=c.SOURCE


def receipt():
    # Synthetic protocol fixture only, never an actual execution receipt.
    symbols={'malloc','pthread_create','iconv_open','snprintf','getaddrinfo','clock_gettime','getrandom','cos'}
    roles={'/'+n for n in c.ROLES.values()};groups=[]
    for process in ('parent','child'):
        objects=set(roles);mapped=set(roles)
        if process=='parent':objects.add('/'+c.FIXTURE+'/plugin.so');mapped|={'/usr/lib/gconv/ISO8859-1.so','/usr/lib/locale/C.utf8/LC_CTYPE'}
        groups.append(dict(kind='identity',process=process,executable='/'+c.FIXTURE+'/'+('smoke-normal' if process=='parent' else 'exec-child'),objects=[dict(path=n) for n in sorted(objects)],mapped_files=[dict(path=n) for n in sorted(mapped)],providers=[dict(symbol=n,path='/'+c.ROLES['libm' if n=='cos' else 'libc']) for n in sorted(symbols)]))
    result=dict(kind='result',status='PASS',cases=8,page_size=16384,glibc_version='2.43')
    records=[dict(kind='test',process='parent',name=n,status='PASS') for n in sorted(c.CASES)]+[dict(kind='test',process='child',name='exec_child',status='PASS'),*groups,result]
    return dict(status='PASS_CONVENTIONAL_GNU_SYSTEM_PATHS_GENERIC16K_RUNTIME',architecture='aarch64',page_size=16384,uid=23001,gid=23001,groups=[],runtime=result,cases=sorted(c.CASES),commands=[dict(argv=['/usr/bin/python3','-I','-B','/enter-system.py',p],exit_code=0,group_absence_verified=True) for p in ('/usr/bin/locale','/usr/bin/iconv','/'+c.FIXTURE+'/smoke-normal')],owned_processes_absent=True,payload_preserved=True,held_preserved=True,normal_parent_and_child=True,runtime_records=records,runtime_files={'/'+n:dict(sha256='1'*64,bytes=1) for n in c.ROLES.values()},scope='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION',hardware='NOT_RUN',release='NOT_ADMITTED',security='NO_CREDIT',kernel='fixture16k')


class Controls(unittest.TestCase):
    def setUp(self):
        self.actor=patch.object(subprocess,'Popen',side_effect=AssertionError('no actor execution'));self.actor.start();self.addCleanup(self.actor.stop)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_unbound_policy_refuses_trial_before_any_output_or_actor(self):
        unbound=dict(schema_version=1,status='UNBOUND_DO_NOT_EXECUTE',binding=None)
        original=c.bindings
        with patch.object(c,'bindings',side_effect=lambda:original(unbound)):
            with self.assertRaisesRegex(ValueError,'UNBOUND'):c.bindings()
            lane=run.namespace(ROOT)
            with self.assertRaisesRegex(ValueError,'UNBOUND'):lane['trial'](NS())
            with self.assertRaisesRegex(ValueError,'UNBOUND'):lane['finalize'](NS())
            self.assertEqual(list(self.root.iterdir()),[])

    def test_frozen_source_closure_is_exact(self):c.check_source(ROOT)

    def test_same_root_elf_closure_cannot_borrow_outer_held_provider(self):
        rows={'system/usr/bin/locale':dict(interpreter='/lib/ld-linux-aarch64.so.1',needed=['libc.so.6'],scope='candidate')}
        files={'system/usr/lib/ld-linux-aarch64.so.1','system/usr/lib/libc.so.6'};c.elf_closure(rows,files)
        with self.assertRaisesRegex(ValueError,'same-root'):c.elf_closure(rows,{'usr/lib/libc.so.6','system/usr/lib/ld-linux-aarch64.so.1'})

    def test_gconv_origin_is_local_to_system_gconv(self):
        rows={'system/usr/lib/gconv/EUC-CN.so':dict(interpreter=None,needed=['libGB.so','libc.so.6'],scope='candidate')}
        c.elf_closure(rows,{'system/usr/lib/gconv/libGB.so','system/usr/lib/libc.so.6'})
        with self.assertRaises(ValueError):c.elf_closure(rows,{'usr/lib/gconv/libGB.so','system/usr/lib/libc.so.6'})

    def test_4k_structural_elf_cannot_pass_16k_gate(self):
        generic=NS(elf=lambda _:('/lib/ld-linux-aarch64.so.1',[],[(0,0,64,4096)]))
        with self.assertRaisesRegex(ValueError,'16K'):c.aligned(b'fixture',generic)
        generic.elf=lambda _:(None,[],[(0,0,64,16384)]);self.assertIsNone(c.aligned(b'fixture',generic)['interpreter'])

    def test_normal_validator_is_original_with_only_page_expectation_changed(self):
        raw=(ROOT/'scripts/ci/glibc-gnu-provider-lifecycle/container.py').read_text();tree=ast.parse(raw)
        original='import os\nfrom pathlib import Path\n\n'+'\n\n'.join(ast.get_source_segment(raw,n) for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('role_identities','validate_runtime'))+'\n'
        self.assertEqual(c.validator_source(ROOT),original.replace("results[0]['page_size']==4096","results[0]['page_size']==16384"));compile(c.validator_source(ROOT),'normal16K-validator','exec')

    def test_adapted_normal_validator_checks_live_inodes_and_provider_hashes(self):
        value=receipt();records=value['runtime_records'];root=self.root/'system';nodes={}
        paths={r['path'] for group in records if group.get('kind')=='identity' for field in ('objects','mapped_files') for r in group[field]}
        for name in paths:
            path=root/name.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(('synthetic data '+name).encode());nodes[name.lstrip('/')]=dict(type='file',sha256=c.sha(path.read_bytes()))
        for group in records:
            if group.get('kind')!='identity':continue
            for field in ('objects','mapped_files'):
                for row in group[field]:
                    info=(root/row['path'].lstrip('/')).stat();row.update(inode=info.st_ino,device_major=os.major(info.st_dev),device_minor=os.minor(info.st_dev))
        api=NS(need=c.need,sha=c.sha,relative=c.relative,read=c.read,ROLES=c.ROLES);space=dict(C=api,FIXTURE=c.FIXTURE);exec(compile(c.validator_source(ROOT),'normal-validator','exec'),space)
        expected=dict(nodes=nodes);roles=space['role_identities'](root,expected);result=space['validate_runtime'](records,root,roles,expected);self.assertTrue(result['normal_parent_and_child'])
        wrong=copy.deepcopy(records);next(r for r in wrong if r.get('kind')=='identity')['objects'][0]['inode']+=1
        with self.assertRaisesRegex(ValueError,'inode'):space['validate_runtime'](wrong,root,roles,expected)
        (root/c.ROLES['libc']).write_bytes(b'provider bytes changed')
        with self.assertRaisesRegex(ValueError,'provider bytes'):space['validate_runtime'](records,root,roles,expected)

    def test_controller_keeps_supervision_and_cleanup_budgets(self):
        raw=run.adapted_source(ROOT);compile(raw,'system-controller','exec')
        for text in ("args.private/'capture.log',240","args.private/'uart.log',900",'signal.ITIMER_REAL,90',"'-smp','1','-m','1024'",'args.kernel_work','shutil.rmtree(work)'):self.assertIn(text,raw)
        self.assertIn('org.cachy-asahi.glibc-system16k.job',raw);self.assertNotIn('glibc16k=1',raw)
        self.assertIn('glibcsystem16k=1',raw);self.assertIn("'system/lib':(stat.S_IFLNK|0o777,b'usr/lib')",raw)

    def test_capture_is_offline_readonly_and_has_no_client_compile(self):
        args=NS(private=self.root,job_token='a'*16,source_root=ROOT,pair_root=self.root/'packet',base_dir=self.root/'base',source_commit='1'*40)
        argv=run.capture_command(args,'sha256:'+'2'*64,'fixture',self.root/'capture',self.root/'stage')
        for flag in ('--network=none','--read-only','--cap-drop=ALL','--memory=2g','--pids-limit=128','--cpus=2'):self.assertIn(flag,argv)
        text=(c.HERE/'capture.py').read_text();self.assertNotIn('compile_suite(',text);self.assertNotIn('makepkg',text);self.assertIn('driver.run_command(argv',text);self.assertIn("'unchanged static page-probe compile'",text)

    def test_launcher_uses_direct_exec_after_chroot_and_privilege_drop(self):
        text=(c.HERE/'enter-system.py').read_text()
        for term in ('os.chroot','os.setgroups([])','os.setgid(23001)','os.setuid(23001)','os.execve'):self.assertIn(term,text)
        self.assertLess(text.index('os.chroot'),text.index('os.execve'));self.assertLess(text.index('os.setuid(23001)'),text.index('os.execve'))
        self.assertNotIn('--library-path',text);self.assertNotIn('--inhibit-cache',text);self.assertIn("'GCONV_PATH','LOCPATH'",text)

    def test_complete_protocol_fixture_requires_all_real_runtime_gates(self):
        good=receipt();c.guest_receipt(good)
        for key in ('page','case','child','held','payload','group','normal','locale','provider','private','argv'):
            bad=copy.deepcopy(good)
            if key=='page':bad['runtime']['page_size']=4096
            elif key=='case':bad['cases'].pop()
            elif key=='child':bad['runtime_records']=[r for r in bad['runtime_records'] if not (r.get('kind')=='test' and r.get('process')=='child')]
            elif key in ('held','payload'):bad[key+'_preserved']=False
            elif key=='group':bad['commands'][0]['group_absence_verified']=False
            elif key=='normal':bad['runtime_records'][9]['executable']='/usr/lib/ld-linux-aarch64.so.1'
            elif key=='locale':bad['runtime_records'][9]['mapped_files']=[r for r in bad['runtime_records'][9]['mapped_files'] if not r['path'].startswith('/usr/lib/locale/')]
            elif key=='provider':bad['runtime_records'][9]['providers'][0]['path']='/libc-foreign.so'
            elif key=='private':bad['scope']='PRIVATE_LOADER'
            else:bad['commands'][2]['argv'][4]='/usr/lib/ld-linux-aarch64.so.1'
            with self.subTest(key=key),self.assertRaises(ValueError):c.guest_receipt(bad)

    def test_nonce_page_and_uncaptured_mapping_refuse(self):
        value=receipt();nonce='a'*32;capture=dict(files={'system/'+n:dict(sha256='1'*64,bytes=1) for n in c.ROLES.values()})
        def uart(v):return b'SMOKE16K: mmap,mprotect,file-offset PASS\n'+('SYSTEM16K BOOT '+nonce+' 16384\nSYSTEM16K REPORT '+nonce+' ').encode()+base64.b64encode(json.dumps(v).encode())+('\nSYSTEM16K PASS '+nonce+'\n').encode()
        self.assertEqual(run.guest_report(uart(value),0,nonce,'fixture16k',capture),value)
        for raw,code in ((uart(value),1),(uart(value).replace(nonce.encode(),b'b'*32,1),0),(uart(value)+('SYSTEM16K PASS '+nonce+'\n').encode(),0)):
            with self.assertRaises(ValueError):run.guest_report(raw,code,nonce,'fixture16k',capture)
        capture['files'].pop(next(iter(capture['files'])))
        with self.assertRaisesRegex(ValueError,'uncaptured'):run.guest_report(uart(value),0,nonce,'fixture16k',capture)

    def test_data_stage_resolves_contained_links_and_omits_development_archives(self):
        files={n:b'private synthetic runtime' for n in (*c.ROLES.values(),'usr/lib/gconv/ISO8859-1.so','usr/lib/locale/C.utf8/LC_CTYPE','usr/bin/iconv','usr/bin/locale','usr/lib/development.a')}
        package=self.root/'fixture.tar.xz'
        with tarfile.open(package,'w:xz') as stream:
            dirs={str(p) for name in files for p in Path(name).parents if str(p)!='.'}
            for name in sorted(dirs):
                m=tarfile.TarInfo(name);m.type=tarfile.DIRTYPE;m.mode=0o755;stream.addfile(m)
            for name,raw in files.items():
                m=tarfile.TarInfo(name);m.mode=0o644;m.size=len(raw);stream.addfile(m,io.BytesIO(raw))
            m=tarfile.TarInfo('usr/lib/libc-alias.so');m.type=tarfile.SYMTYPE;m.linkname='libc.so.6';m.mode=0o777;stream.addfile(m)
        generic=c.load(ROOT,'scripts/virtual/generic16k/fixture.py')
        with patch.object(c,'INDEX',{}),patch.object(c,'PACKAGE_SHA',c.sha(package.read_bytes())):
            stage=self.root/'system';rows=c.stage(package,stage,generic)
        self.assertNotIn('usr/lib/development.a',rows);self.assertFalse((stage/'usr/lib/libc-alias.so').is_symlink());self.assertEqual((stage/'usr/lib/libc-alias.so').read_bytes(),files['usr/lib/libc.so.6'])
        self.assertTrue(set(c.ROLES.values())<=set(rows));self.assertNotIn('opt/',str(rows))

    def test_generated_init_has_actual16k_and_system_proc_dev_mounts(self):
        text=run.namespace(ROOT)['init']('a'*32,'fixture16k').decode()
        self.assertIn('$(/usr/bin/getconf PAGESIZE) == 16384',text);self.assertIn('ro,nosuid,nodev,noexec proc /system/proc',text)
        self.assertIn('devtmpfs /system/dev',text);self.assertIn('/guest.py',text)
        self.assertLess(text.index('/smoke || fail'),text.index('proc /system/proc'))

    def test_cleanup_safe_never_authorizes_producer_before_consumer_absence(self):
        output=self.root/'out';private=self.root/'private';output.mkdir();private.mkdir();args=NS(output=output,private=private,job_token='a'*16)
        fn=run.namespace(ROOT)['cleanup_safe'];self.assertFalse(fn(args))
        c.save(output/'runtime.json',dict(job_token=args.job_token,consumer_cleanup=dict(capture_absent=False,private_removed=True)));self.assertFalse(fn(args))
        c.save(output/'runtime.json',dict(job_token='b'*16,consumer_cleanup=dict(capture_absent=True,private_removed=True)));self.assertFalse(fn(args))
        c.save(output/'runtime.json',dict(job_token=args.job_token,consumer_cleanup=dict(capture_absent=True,private_removed=True)));self.assertTrue(fn(args))

    def test_input_alias_and_byte_substitution_refuse(self):
        p=self.root/'file';p.write_bytes(b'one');row=dict(bytes=3,sha256=c.sha(b'one'));c.checked(self.root,'file',row)
        p.write_bytes(b'two')
        with self.assertRaises(ValueError):c.checked(self.root,'file',row)
        (self.root/'alias').symlink_to(p)
        with self.assertRaises(ValueError):c.checked(self.root,'alias',dict(bytes=3,sha256=c.sha(b'two')))


if __name__=='__main__':unittest.main()
