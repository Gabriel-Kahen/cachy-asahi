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
from types import ModuleType, SimpleNamespace
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
    path=logical
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        runtime.strict.need(info.st_size==23994,'cleanup-corrected 0cd45dff lifecycle helper required')
        source=stream.read(23995)
    runtime.strict.need(hashlib.sha256(source).hexdigest()=='6c24c1993d29a895f3bab137a2b0af248da3b5dc7728f3e334d2b2fda34b074e',
                        'cleanup-corrected lifecycle helper source changed')
    life=ModuleType('_payload_host_TEST_lifecycle');life.__file__=str(logical)
    # Only this checkout's exact corrected helper can define the actor boundary.
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


class SourceBinding(unittest.TestCase):
    """Source/binding and delegation controls; no compiler, crypto or ALPM."""
    def test_corrected_local_helper_ignores_external_override(self):
        with patch(__name__+'.life',None),patch.dict(os.environ,CACHY_ASAHI_LIFECYCLE_FIXTURE='/unreviewed/external.py'):
            load_lifecycle()
            self.assertEqual(life.source_loaded_from,str(HERE/'test_prior_aux_lifecycle.py'))
            self.assertEqual(life.HERE,HERE)
            self.assertIsNot(life.main,actual_main)

    def test_old_or_changed_helper_refuses_before_module_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for size in (22252,23994):
                (root/'test_prior_aux_lifecycle.py').write_bytes(b'x'*size)
                with self.subTest(size=size),patch(__name__+'.HERE',root),patch(__name__+'.life',None),\
                     patch(__name__+'.ModuleType') as execute_module:
                    with self.assertRaises(ValueError):load_lifecycle()
                    execute_module.assert_not_called()

    def test_actual_entry_delegates_one_case_and_restores_scope(self):
        sandbox,evidence=Path('/MODEL/sandbox'),Path('/MODEL/evidence')
        original_argv=sys.argv;old_case,old_run=object(),object();binaries,expected=object(),object()
        helper=SimpleNamespace(CASES=old_case,run_case=old_run,need=runtime.strict.need)
        def main():
            self.assertEqual(sys.argv[1:],['--sandbox',str(sandbox),'--evidence',str(evidence)])
            self.assertEqual(helper.CASES,('static-native-script',))
            return helper.run_case(sandbox,evidence,helper.CASES[0],'signer',b'public','sign')
        helper.main=main
        with patch(__name__+'.life',helper),patch(__name__+'.load_lifecycle'),\
             patch(__name__+'.build',return_value=binaries) as compile_fixture,\
             patch.object(shutil,'copytree') as copy_build,\
             patch(__name__+'.actual_case',return_value=expected) as run:
            self.assertIs(actual_main(sandbox,evidence),expected)
        compile_fixture.assert_called_once_with(sandbox/'build')
        copy_build.assert_called_once_with(sandbox/'build',evidence/'build')
        run.assert_called_once_with(sandbox,evidence,binaries,'signer',b'public','sign')
        self.assertIs(helper.CASES,old_case);self.assertIs(helper.run_case,old_run);self.assertIs(sys.argv,original_argv)

    def test_delegated_primary_failure_survives_scope_restoration(self):
        error=RuntimeError('MODEL primary');old_case,old_run=object(),object();original_argv=sys.argv
        def main():raise error
        helper=SimpleNamespace(CASES=old_case,run_case=old_run,main=main)
        with patch(__name__+'.life',helper),patch(__name__+'.load_lifecycle'):
            with self.assertRaises(RuntimeError) as raised:actual_main(Path('/MODEL/sandbox'),Path('/MODEL/evidence'))
        self.assertIs(raised.exception,error);self.assertIs(helper.CASES,old_case)
        self.assertIs(helper.run_case,old_run);self.assertIs(sys.argv,original_argv)


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
                env={'PATH':'/usr/bin:/bin','HOME':str(case),'TMPDIR':str(sandbox/'tmp'),'LC_ALL':'C'},
                cwd=str(case),timeout=45,output_limit=1024**2)
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
    return summary


def actual_main(sandbox,evidence):
    load_lifecycle()
    def native_case(sandbox,evidence,mode,signer,public,sign):
        life.need(mode=='static-native-script','one exact native TEST case required')
        binaries=build(sandbox/'build');shutil.copytree(sandbox/'build',evidence/'build')
        return actual_case(sandbox,evidence,binaries,signer,public,sign)
    # Reuse the corrected actor/cleanup boundary instead of duplicating finally.
    argv=[str(Path(__file__).resolve()),'--sandbox',str(sandbox),'--evidence',str(evidence)]
    with patch.object(sys,'argv',argv),patch.object(life,'CASES',('static-native-script',)),\
         patch.object(life,'run_case',native_case):
        return life.main()


if __name__=='__main__':
    if '--actual-worker' in sys.argv:actual_worker(Path(sys.argv[sys.argv.index('--actual-worker')+1]))
    elif '--actual' in sys.argv:
        parser=argparse.ArgumentParser();parser.add_argument('--actual',action='store_true')
        parser.add_argument('--sandbox',type=Path,required=True);parser.add_argument('--evidence',type=Path,required=True)
        args=parser.parse_args();actual_main(args.sandbox,args.evidence)
    else:unittest.main()
