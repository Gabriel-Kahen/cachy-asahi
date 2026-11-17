#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused TEST crypto/ALPM reads plus an explicit genuine native lifecycle.

Ordinary tests use inert auxiliary fixtures. --actual uses the existing bounded
host TEST profile and real release→apply→ALPM→helper→native/script execution.
"""
import argparse
from contextlib import ExitStack
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import prior_payload_aux_runtime as runtime
import prior_aux_runtime as data_only
import test_prior_aux_runtime as base
import root_link_selection as links
import scale_update as scale
from test_snapshot import encoded,digest

NATIVE='usr/bin/selected-native'
RETIRED='usr/bin/selected-retired'
SCRIPT='usr/bin/selected-script'
PROVIDER='usr/bin/fixture-static-interpreter'
ALIAS='usr/bin/selected-alias'
life=None


def load_lifecycle():
    global life
    if life is not None:return
    logical=HERE/'test_prior_aux_lifecycle.py'
    path=Path(os.environ.get('CACHY_ASAHI_LIFECYCLE_FIXTURE',str(logical)))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        runtime.strict.need(info.st_size==22252,'accepted 3ab6007b lifecycle helper required')
        source=stream.read(22253)
    runtime.strict.need(hashlib.sha256(source).hexdigest()=='8fd402e691ab28f294710e54a2a60fe0456545894be90c5c2477761d094a14b1',
                        'accepted lifecycle helper source changed')
    life=ModuleType('_payload_host_TEST_lifecycle');life.__file__=str(logical)
    # Captured helper code uses this checkout's engine, not external adjacency.
    exec(compile(source,str(path),'exec'),life.__dict__)
    life.source_loaded_from=str(path.resolve())


def build(directory):
    directory.mkdir()
    outputs={}
    sources={
        'old':'#include <stdio.h>\nint main(void){puts("NATIVE-V1");return 0;}\n',
        'new':'#include <stdio.h>\nint main(void){puts("NATIVE-V2");return 0;}\n',
        'interpreter':'#include <stdio.h>\nint main(int n,char**v){char b[256];if(n!=2)return 2;FILE*f=fopen(v[1],"r");if(!f)return 3;if(!fgets(b,256,f)||!fgets(b,256,f))return 4;fclose(f);fputs(b,stdout);return 0;}\n'}
    records=[]
    for name,source in sources.items():
        path=directory/(name+'.c');path.write_text(source);output=directory/name
        command=['/usr/bin/cc','-static','-fno-pie','-no-pie','-Os','-Wl,--build-id=none','-Wl,-s',str(path),'-o',str(output)]
        result=subprocess.run(command,capture_output=True,timeout=30)
        (directory/(name+'.stdout')).write_bytes(result.stdout);(directory/(name+'.stderr')).write_bytes(result.stderr)
        runtime.strict.need(result.returncode==0,'fixed static C fixture compile failed')
        raw=output.read_bytes();runtime.static_elf(raw);outputs[name]=raw
        records.append(dict(command=command,exit=result.returncode,source_sha256=digest(path),binary_sha256=digest(output),bytes=len(raw)))
    (directory/'build.json').write_bytes(encoded(records))
    return outputs


def script(version):return ('#!/'+PROVIDER+'\nSCRIPT-V'+str(version)+'\n').encode()


def archive(path,entries,version,sign,*,pax=None,metadata='',control=None):
    with tarfile.open(path,'w:gz',format=tarfile.PAX_FORMAT) as output:
        info=f'pkgname = selected\npkgver = {version}\narch = any\nlicense = MIT\n{metadata}'.encode()
        for name,data in {'.PKGINFO':info,**entries,**(control or {})}.items():
            node=tarfile.TarInfo(name);node.mode=0o755 if name.startswith('usr/bin/') else 0o644
            if pax and name in pax:node.pax_headers=pax[name]
            if isinstance(data,tuple):node.type,node.mode,node.linkname=tarfile.SYMTYPE,0o777,data[0];output.addfile(node)
            elif data is None:node.type,node.mode=tarfile.DIRTYPE,0o755;output.addfile(node)
            else:node.size=len(data);output.addfile(node,io.BytesIO(data))
    sign(path);return path


class Focused(unittest.TestCase):
    limits=base.Cases.limits;mkdir=base.Cases.mkdir;write=base.Cases.write;keys=base.Cases.keys
    @classmethod
    def setUpClass(cls):
        base.Cases.setUpClass.__func__(cls)
        cls.binaries=build(cls.key_home.parent/'build')

    def setUp(self):
        base.Cases.setUp(self)
        self.alpm.close()
        self.entries.update({NATIVE:self.binaries['old'],RETIRED:self.binaries['old'],SCRIPT:script(1)})
        for name in (NATIVE,RETIRED,SCRIPT):self.write(name,self.entries[name],0o755)
        self.write(PROVIDER,self.binaries['interpreter'],0o755)
        local=self.root/'var/lib/pacman/local'
        (local/'selected-1-1/files').write_text('%FILES%\n'+'\n'.join(self.entries)+'\n\n')
        (local/'held-0-1-1/files').write_text('%FILES%\n'+PROVIDER+'\n\n')
        self.args.payload_interpreters={'/'+PROVIDER:dict(bytes=len(self.binaries['interpreter']),sha256=digest(self.root/PROVIDER))}
        archive(Path(self.args.prior_archive),self.entries,'1-1',self.sign)
        self.reset()

    def archive(self,*args,**kwargs):return base.Cases.archive(self,*args,**kwargs)
    def reset(self):
        self.instance=runtime.Runtime(self.args,self.config,comparator_path=base.fixtures.COMPARATOR)
        self.seed=self.instance.tree(self.root)
        self.alpm=self.instance.Alpm(self.root,self.key_home,self.base/'native-alpm.log',os.uname().machine)
        self.addCleanup(self.alpm.close)
    def select(self):self.instance.selection(self.snapshot,self.before,{'selected':'2-1'})
    def payload(self,entries=None,**kwargs):
        entries={NATIVE:self.binaries['new'],SCRIPT:script(2),'usr/share/selected/data':b'new data',ALIAS:('selected-native',)} if entries is None else entries
        path=archive(self.base/'new.pkg.tar.gz',entries,'2-1',self.sign,**kwargs)
        return self.instance.archive_payload(path,{})

    def test_static_native_script_data_link_projection_and_removal(self):
        self.select();projected=self.instance.projected_paths(self.seed,self.payload())
        self.assertNotIn(RETIRED,projected);self.assertEqual(projected[ALIAS]['target'],'selected-native')
        self.assertIn(PROVIDER,self.instance.providers)
        self.assertEqual(self.instance.tree(self.root),self.seed)
        self.assertFalse(self.instance.providers[PROVIDER]['inspection']['runtime_verified'])

    def test_data_only_default_still_rejects_same_signed_native_prior(self):
        instance=data_only.Runtime(self.args,self.config,comparator_path=base.fixtures.COMPARATOR)
        instance.tree(self.root);instance.alpm=self.alpm
        with self.assertRaisesRegex(ValueError,'native ELF or script'):instance.selection(self.snapshot,self.before,{'selected':'2-1'})

    def test_wrong_machine_and_dynamic_elf_refuse(self):
        self.select();wrong=bytearray(self.binaries['new']);struct.pack_into('<H',wrong,18,183 if os.uname().machine=='x86_64' else 62)
        for raw in (bytes(wrong),Path('/usr/bin/true').read_bytes()):
            with self.subTest(prefix=raw[:20]),self.assertRaises(ValueError):self.payload({NATIVE:raw})

    def test_executable_text_without_format_and_privileged_mode_refuse(self):
        self.select();payload=self.payload({NATIVE:b'plain text\n'})
        with self.assertRaisesRegex(ValueError,'unrecognized executable'):self.instance.projected_paths(self.seed,payload)
        payload=self.payload({NATIVE:self.binaries['new']});payload[NATIVE]['mode']=0o4755
        with self.assertRaisesRegex(ValueError,'privileged'):self.instance.projected_paths(self.seed,payload)

    def test_direct_script_requires_exact_unchanged_foreign_static_provider(self):
        self.args.payload_interpreters={};self.alpm.close();self.reset()
        with self.assertRaisesRegex(ValueError,'explicit reviewed static interpreter'):self.select()

    def test_script_env_and_arguments_refuse(self):
        self.select()
        for raw in (b'#!/usr/bin/env sh\nbody\n',b'#!/usr/bin/fixture-static-interpreter --flag\nbody\n'):
            with self.subTest(raw=raw),self.assertRaisesRegex(ValueError,'direct absolute'):self.payload({SCRIPT:raw})

    def test_dynamic_script_provider_refuses(self):
        self.write(PROVIDER,Path('/usr/bin/true').read_bytes(),0o755)
        self.alpm.close();self.args.payload_interpreters={'/'+PROVIDER:dict(bytes=(self.root/PROVIDER).stat().st_size,sha256=digest(self.root/PROVIDER))};self.reset()
        with self.assertRaisesRegex(ValueError,'only static ET_EXEC'):self.select()

    def test_archive_xattr_or_install_control_refuse(self):
        self.select()
        with self.assertRaisesRegex(ValueError,'xattr/ACL/capability'):
            self.payload(pax={NATIVE:{'SCHILY.xattr.security.capability':'not accepted'}})
        with self.assertRaisesRegex(ValueError,'control member'):self.payload(control={'.INSTALL':b'echo forbidden\n'})

    def test_existing_selected_xattrs_refuse_and_are_preserved(self):
        os.setxattr(self.root/NATIVE,'user.fixture',b'keep')
        with self.assertRaisesRegex(ValueError,'xattr'):self.select()
        self.assertEqual(os.getxattr(self.root/NATIVE,'user.fixture'),b'keep')

    def test_live_provider_edit_and_changed_prior_refuse_before_commit(self):
        self.select();self.instance.projected_paths(self.seed,self.payload())
        self.write(PROVIDER,b'changed interpreter',0o755)
        with self.assertRaises(ValueError):self.instance.tree(self.root)
        path=Path(self.args.prior_archive);path.write_bytes(path.read_bytes()+b'drift')
        with self.assertRaisesRegex(ValueError,'prior input'):self.instance.projected_paths(self.seed,{})

    def test_real_foreign_ownership_refuses_native_update(self):
        held=self.root/'var/lib/pacman/local/held-1-1-1/files';held.write_text('%FILES%\n'+NATIVE+'\n\n')
        self.alpm.close();self.reset()
        with self.assertRaisesRegex(ValueError,'foreign ownership'):self.select()

    def test_selected_native_hardlink_refuses_update(self):
        os.link(self.root/NATIVE,self.base/'outside-native')
        with self.assertRaises(ValueError):self.select()

    def test_alias_escape_and_hook_path_refuse(self):
        self.select()
        with self.assertRaises(ValueError):self.instance.projected_paths(self.seed,self.payload({ALIAS:('../lib/libc.so.6',)}))
        with self.assertRaisesRegex(ValueError,'unsupported hook/service'):
            self.instance.projected_paths(self.seed,self.payload({'usr/share/selected/operation.hook':b'data'}))

    def test_selected_link_endpoint_refuses_update(self):
        alias='usr/share/held-native';(self.root/alias).symlink_to('/'+NATIVE)
        observed=runtime.roots.observe(self.root,limits=self.instance.root_limits,hardlinks=runtime.strict.MODE)
        with ExitStack() as stack:
            for name,value in dict(CHAIN_PATHS=(alias,),LINK_NODES={alias:observed['nodes'][alias]},RESOLVED_ENDPOINTS={alias:NATIVE}).items():
                stack.enter_context(patch.object(links,name,value))
            self.alpm.close();self.reset()
            with self.assertRaisesRegex(ValueError,'closure'):self.select()

    def test_parent_alias_and_auxiliary_helper_write_refuse(self):
        self.mkdir('usr/libexec/selected')
        (self.root/'usr/libexec/selected/alias').symlink_to('../../share/selected')
        self.alpm.close();self.reset();self.select()
        with self.assertRaisesRegex(ValueError,'parent alias'):
            self.instance.projected_paths(self.seed,self.payload({'usr/libexec/selected/alias/code':self.binaries['new']}))
        with self.assertRaises(ValueError):self.payload({'usr/bin/ldconfig':self.binaries['new']})

    def test_xattr_added_after_projection_is_not_hidden_by_node_map(self):
        self.select();self.instance.projected_paths(self.seed,self.payload())
        os.setxattr(self.root/NATIVE,'user.fixture',b'late edit')
        with self.assertRaisesRegex(ValueError,'xattr'):self.instance.tree(self.root)

    def test_same_size_native_edit_after_projection_refuses_at_precommit(self):
        self.select();self.instance.projected_paths(self.seed,self.payload())
        path=self.root/NATIVE;raw=bytearray(path.read_bytes());raw[-1]^=1;path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'observed file content changed'):self.instance.precommit()
        self.assertFalse(getattr(self.instance,'commit_ready',False))

    def test_backup_semantics_remain_refusal(self):
        archive(Path(self.args.prior_archive),self.entries,'1-1',self.sign,metadata='backup = '+NATIVE+'\n')
        with self.assertRaisesRegex(ValueError,'backup semantics'):self.select()

    def test_new_backup_semantics_refuse_before_projection(self):
        self.select()
        with self.assertRaisesRegex(ValueError,'backup semantics'):
            self.payload(metadata='backup = '+NATIVE+'\n')


def actual_worker(request_path):
    load_lifecycle()
    request=json.loads(request_path.read_bytes())
    with life.host_profile(),ExitStack() as selected:
        for name,value in request['selection'].items():
            selected.enter_context(patch.object(links,name,tuple(value) if name=='CHAIN_PATHS' else value))
        result=runtime.apply(argparse.Namespace(**request['args']),comparator_path=life.COMPARATOR)
    Path(request['result']).write_bytes(encoded(result))


def execute(root,command):
    def enter():os.chroot(root);os.chdir('/')
    row=subprocess.run([command],preexec_fn=enter,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},
                       capture_output=True,timeout=5)
    return dict(exit=row.returncode,stdout=row.stdout.decode('ascii'),stderr=row.stderr.decode('ascii'))


def actual_case(sandbox,evidence,binaries,signer,public,sign):
    case=sandbox/'native';case.mkdir(mode=0o700)
    source=case/'source';versions,owned,old=life.source_root(source)
    old.update({NATIVE:binaries['old'],RETIRED:binaries['old'],SCRIPT:script(1)})
    for name in (NATIVE,RETIRED,SCRIPT):life.write(source,name,old[name],0o755)
    life.write(source,PROVIDER,binaries['interpreter'],0o755)
    owned['selected']=list(old);owned['held-000']=[PROVIDER]
    for name in ('selected','held-000'):
        life.write(source,f'var/lib/pacman/local/{name}-1-1/files',('%FILES%\n'+'\n'.join(owned[name])+'\n\n').encode())
    life.helper(source,evidence,'source-initialize')
    with life.host_profile():
        source_before=life.observe(source)
        (evidence/'source-before.json').write_bytes(encoded(source_before))
        with life.aux_copy.copied_root(source,case/'workspace',limits=life.limits(),cleanup_seconds=10) as (root,report):
            life.helper(root,evidence,'copied-initialize')
            original_builder=life.make_bundle;original_info=tarfile.TarInfo
            class PayloadInfo(original_info):
                def __init__(self,name=''):
                    super().__init__(name)
                    if name in (NATIVE,SCRIPT):self.mode=0o755
                    if name==ALIAS:self.type,self.mode,self.linkname=tarfile.SYMTYPE,0o777,'selected-native'
            def builder(*args,**kwargs):
                kwargs['payload']={NATIVE:binaries['new'],SCRIPT:script(2),ALIAS:b'',
                                   'usr/share/selected/data':b'new data\n','usr/share/selected/new':b'new leaf\n'}
                with patch.object(tarfile,'TarInfo',PayloadInfo):return original_builder(*args,**kwargs)
            def previous(path,entries,sign):return archive(path,entries,'1-1',sign)
            with patch.object(life,'make_bundle',builder),patch.object(life,'old_archive',previous):
                args=life.configure(case,root,root.parent,versions,owned,old,signer,public,sign)
            args['payload_interpreters']={'/'+PROVIDER:dict(bytes=len(binaries['interpreter']),sha256=digest(root/PROVIDER))}
            absolute,mask='usr/share/preserved-link','builder-disabled-hooks/test.hook'
            (root/absolute).symlink_to('/usr/lib/libc.so.6');(root/'builder-disabled-hooks').mkdir()
            (root/mask).symlink_to('/dev/null')
            before=life.observe(root);caches={n:(root/n).read_bytes() for n in (life.aux.MAIN_CACHE,life.aux.AUX_CACHE)}
            before_run={p:execute(root,'/'+p) for p in (NATIVE,SCRIPT)}
            life.need(before_run[NATIVE]['stdout']=='NATIVE-V1\n' and before_run[SCRIPT]['stdout']=='SCRIPT-V1\n','old real program/script execution failed')
            inputs=evidence/'inputs';inputs.mkdir();shutil.copytree(case/'bundle',inputs/'bundle')
            for name in ('public.gpg','metadata.json','metadata.json.sig','settings.json','policy.json','scale.json','prior.pkg.tar.gz','prior.pkg.tar.gz.sig'):
                shutil.copy2(case/name,inputs/name)
            selection=dict(CHAIN_PATHS=sorted((absolute,mask)),LINK_NODES={n:before['nodes'][n] for n in (absolute,mask)},
                RESOLVED_ENDPOINTS={absolute:'usr/lib/libc.so.6'},DATA_ONLY_ENDPOINTS={mask:'dev/null'})
            request=evidence/'request.json';request.write_bytes(encoded(dict(args=args,selection=selection,result=str(evidence/'result.json'))))
            trace=evidence/'helper-trace.jsonl';gdb=evidence/'observe.gdb';life.gdb_script(gdb,trace)
            row=life.supervision.run(['/usr/bin/gdb','-nx','-nh','--batch','-x',str(gdb),'--args',
                '/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'--actual-worker',str(request)],
                env={'PATH':'/usr/bin:/bin','HOME':str(case),'TMPDIR':str(sandbox/'tmp'),'LC_ALL':'C',
                     'CACHY_ASAHI_LIFECYCLE_FIXTURE':life.source_loaded_from},cwd=str(case),timeout=45,output_limit=1024**2)
            for name in ('stdout','stderr'):(evidence/('worker.'+name)).write_bytes(row.pop(name))
            (evidence/'supervision.json').write_bytes(encoded(row))
            life.need(row['termination'] is None and row['returncode']==0 and row['direct_child_reaped'],'native apply worker failed')
            result=json.loads((evidence/'result.json').read_bytes())
            life.need(result['status']=='PASS' and result['packages_committed'] is True and result['checkpoint_changed'] is True,'actual native apply failed: '+str(result.get('error')))
            after=life.observe(root)
            after_run={p:execute(root,'/'+p) for p in (NATIVE,SCRIPT,ALIAS)}
            life.need(all(r['exit']==0 for r in after_run.values()) and after_run[NATIVE]['stdout']=='NATIVE-V2\n'
                and after_run[SCRIPT]['stdout']=='SCRIPT-V2\n' and after_run[ALIAS]['stdout']=='NATIVE-V2\n','upgraded real native/script/link execution failed')
            life.need(not (root/RETIRED).exists() and not (root/'usr/share/selected/retired').exists(),'obsolete executable/data remain')
            for name,data in caches.items():
                life.need((root/name).read_bytes()==data,'raw auxiliary/main cache changed')
                (evidence/('before-'+Path(name).name)).write_bytes(data);(evidence/('after-'+Path(name).name)).write_bytes((root/name).read_bytes())
            life.need(all(after['nodes'][n]==before['nodes'][n] for n in (absolute,mask,*life.HOST_FILES,PROVIDER)),'held native/selected-link/provider state changed')
            events=[json.loads(line) for line in trace.read_text().splitlines()]
            exits=[r for r in events if r['event']=='helper-exit'];execs=[r for r in events if r['event']=='helper-exec']
            life.need(len(execs)==len(exits)==1 and exits[0]['exit']==0,'actual helper exit0 not observed')
            alpm=runtime.roots.Alpm(root,case,evidence/'query-alpm.log',os.uname().machine,limits=life.limits())
            try:inventory=alpm.inventory()
            finally:alpm.close()
            life.need(inventory==dict(versions,selected='2-1') and not (root/'var/lib/pacman/db.lck').exists(),'actual inventory/lock differs')
            for name,value in (('before',before),('after',after),('inventory',inventory)):(evidence/(name+'.json')).write_bytes(encoded(value))
            life.need(life.observe(source)['nodes']==source_before['nodes'],'source changed')
            summary=dict(status='PASS actual static native/script TEST upgrade',before_execution=before_run,after_execution=after_run,
                helper_execs=execs,helper_exits=exits,raw_caches='RAW_EQUAL',capacity=life.capacity(root),
                source_correspondence_to_host_helper='NOT VERIFIED',production_ARM_closure='NOT EXERCISED')
        life.need(report['cleanup']=='PASS-owned-workspace-removed','copied root retirement failed')
        summary['copy']=report;(evidence/'actual-summary.json').write_bytes(encoded(summary))
    shutil.rmtree(case)


def actual_main(sandbox,evidence):
    load_lifecycle()
    fence=life.fenced();mapping=Path('/proc/self/uid_map').read_text().split()
    life.need(os.getuid()==0 and len(mapping)==3 and mapping[0]=='0' and int(mapping[1])>0 and mapping[2]=='1','owned mapped user namespace required')
    interfaces={l.split(':',1)[0].strip() for l in Path('/proc/net/dev').read_text().splitlines() if ':' in l}
    life.need(interfaces=={'lo'} and not any(sandbox.iterdir()),'fresh private network/sandbox required')
    subprocess.run(['/usr/bin/mount','-t','tmpfs','-o','size=67108864,nr_inodes=20000,nodev,nosuid,mode=0700','tmpfs',str(sandbox)],check=True,timeout=5)
    status=dict(status='FAIL',fence=fence,profile=life.PROFILE,production_ARM_closure='NOT EXERCISED')
    try:
        (sandbox/'tmp').mkdir(mode=0o700);os.environ['TMPDIR']=str(sandbox/'tmp')
        binaries=build(sandbox/'build');shutil.copytree(sandbox/'build',evidence/'build')
        with life.signing(sandbox/'keys') as (signer,public,sign):actual_case(sandbox,evidence,binaries,signer,public,sign)
        status['status']='PASS actual static native/script TEST lifecycle'
    finally:
        status['peak']={n:(Path(fence['group'])/n).read_text().strip() for n in ('memory.peak','pids.peak')}
        status['key_retirement']=life.retire_agents(sandbox,evidence);os.chdir(HERE)
        unmounted=subprocess.run(['/usr/bin/umount',str(sandbox)],capture_output=True,timeout=5)
        status['unmount']=unmounted.returncode
        if unmounted.returncode:status['status']='FAIL-cleanup'
        (evidence/'lifecycle.json').write_bytes(encoded(status))
        life.need(unmounted.returncode==0,'private native fixture unmount failed')


if __name__=='__main__':
    if '--actual-worker' in sys.argv:actual_worker(Path(sys.argv[sys.argv.index('--actual-worker')+1]))
    elif '--actual' in sys.argv:
        parser=argparse.ArgumentParser();parser.add_argument('--actual',action='store_true')
        parser.add_argument('--sandbox',type=Path,required=True);parser.add_argument('--evidence',type=Path,required=True)
        args=parser.parse_args();actual_main(args.sandbox,args.evidence)
    else:unittest.main()
