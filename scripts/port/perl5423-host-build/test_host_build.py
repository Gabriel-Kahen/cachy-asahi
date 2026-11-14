#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Candidate-specific input, actor and archive refusal controls; no Docker."""
from contextlib import nullcontext
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

HERE=Path(__file__).resolve().parent


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module


host=load('perl_host_run_test',HERE/'run.py')
reader=load('perl_archive_test',HERE/'inspect_archive.py')
pins=json.loads((HERE/'inputs.json').read_bytes())


def actor():
    return {'Image':'sha256:'+'1'*64,'Config':{'User':'1000:1000','Hostname':'perl5423-host'},'HostConfig':{
        'NanoCpus':2000000000,'Memory':4294967296,'MemorySwap':4294967296,'PidsLimit':256,
        'NetworkMode':'none','ReadonlyRootfs':True,'Init':True,'CapDrop':['ALL'],'CapAdd':[],
        'SecurityOpt':['no-new-privileges'],'Privileged':False,'Devices':[]},'Mounts':[
        {'Destination':'/inputs','Source':'/snapshot','Type':'bind','RW':False},
        {'Destination':'/work','Name':'private-volume','Type':'volume','RW':True}]}


def rows():
    commands=reader.load('perl_names_data',host.ROOT/'packages/port/perl5423-source-candidate/stage_commands.py').COMMANDS
    result={n:dict(type='file',mode=0o644) for n in ['usr/bin/perl','usr/lib/perl5/5.42/core_perl/CORE/libperl.so','usr/share/perl5/core_perl/pod/perldiag.pod']}
    result['usr/bin/perl'].update(mode=0o755,ELF_machine=62)
    result['usr/lib/perl5/5.42/core_perl/CORE/libperl.so']['ELF_machine']=62
    for name,source in [('README','UPSTREAM-README'),('Artistic','UPSTREAM-Artistic'),('Copying','UPSTREAM-Copying'),('LICENSE.packaging','LICENSE.packaging')]:
        result['usr/share/licenses/perl/'+name]=dict(type='file',mode=0o644,sha256=pins['files'][source]['sha256'])
    for command in commands:
        result['usr/bin/'+command]=dict(type='symlink',mode=0o777,target='core_perl/'+command)
        result['usr/bin/core_perl/'+command]=dict(type='file',mode=0o755)
    return result


class Controls(unittest.TestCase):
    def test_exact_actor_contract(self):
        row=actor();host.validate_actor(row,row['Image'],'private-volume',Path('/snapshot'))

    def test_changed_actor_budgets_or_privileges_refuse(self):
        changes={'NanoCpus':1,'Memory':1,'MemorySwap':-1,'PidsLimit':512,'NetworkMode':'host',
            'ReadonlyRootfs':False,'Init':False,'CapDrop':[],'CapAdd':['ALL'],'SecurityOpt':[],
            'Privileged':True,'Devices':[{'PathOnHost':'/dev/sda'}]}
        for key,value in changes.items():
            row=actor();row['HostConfig'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):host.validate_actor(row,row['Image'],'private-volume',Path('/snapshot'))

    def test_foreign_or_writable_input_mounts_refuse(self):
        for changes in ({'RW':True},{'Source':'/home/operator'},{'Type':'volume'}):
            row=actor();row['Mounts'][0].update(changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError):host.validate_actor(row,row['Image'],'private-volume',Path('/snapshot'))
        row=actor();row['Mounts'].append({'Destination':'/home','Type':'bind','RW':False})
        with self.assertRaises(ValueError):host.validate_actor(row,row['Image'],'private-volume',Path('/snapshot'))

    def test_fixed_options_have_no_dependency_or_test_waiver(self):
        text=(HERE/'build.sh').read_text()
        self.assertIn('makepkg --cleanbuild --nosign --noconfirm --log',text)
        for forbidden in ['--nodeps','--nocheck','--skipchecksums','--ignorearch','--syncdeps','sudo ']:self.assertNotIn(forbidden,text)
        command=host.build_options('test','image','private-volume',Path('/snapshot'))
        self.assertIn('--network=none',command);self.assertIn('--read-only',command)

    def test_input_changes_and_extra_namespace_refuse(self):
        with tempfile.TemporaryDirectory(prefix='perl-input-DATA-') as temporary:
            root=Path(temporary);recipe=root/'recipe';recipe.mkdir();source=root/'source'
            (recipe/'PKGBUILD').write_bytes(b'MODELED RECIPE DATA');source.write_bytes(b'MODELED SOURCE DATA')
            contract={'files':{'PKGBUILD':host.identity(recipe/'PKGBUILD')},'source':host.identity(source)}
            (root/'inputs.json').write_text(json.dumps(contract))
            with mock.patch.object(host,'HERE',root):
                host.verify_inputs(recipe,source)
                source.write_bytes(b'CHANGED SOURCE')
                with self.assertRaisesRegex(ValueError,'source archive'):host.verify_inputs(recipe,source)
                contract['source']=host.identity(source);(root/'inputs.json').write_text(json.dumps(contract))
                (recipe/'extra').write_bytes(b'UNREVIEWED DATA')
                with self.assertRaisesRegex(ValueError,'namespace'):host.verify_inputs(recipe,source)

    def test_symlink_file_refuses(self):
        with tempfile.TemporaryDirectory(prefix='perl-input-DATA-') as temporary:
            root=Path(temporary);(root/'source').write_bytes(b'DATA');(root/'link').symlink_to('source')
            with self.assertRaisesRegex(ValueError,'ordinary bounded file'):host.identity(root/'link')

    def test_oversized_export_and_metadata_refuse_without_materializing(self):
        with tempfile.TemporaryDirectory(prefix='perl-export-DATA-') as temporary:
            path=Path(temporary)/'large'
            with path.open('wb') as stream:stream.truncate(64*1024**2+1)
            with self.assertRaisesRegex(ValueError,'bounded file'):host.identity(path)
            with self.assertRaisesRegex(ValueError,'bounded file'):host.log_contains(path,'All tests successful.')
            path.write_bytes(b'ABCDE')
            with self.assertRaisesRegex(ValueError,'bounded file'):host.text(path,4)
            path.write_bytes(b'x'*65530+b'All tests successful.'+b'y'*20)
            self.assertTrue(host.log_contains(path,'All tests successful.'))

    def test_only_exact_missing_cleanup_name_is_benign(self):
        self.assertTrue(host.cleanup_absent(['docker','rm','-f','owned'],'Error response from daemon: No such container: owned\n'))
        self.assertFalse(host.cleanup_absent(['docker','rm','-f','owned'],'permission denied'))
        self.assertFalse(host.cleanup_absent(['docker','rm','-f','owned'],'Error response from daemon: No such container: foreign'))

    def test_final_input_failure_still_saves_cleanup_report(self):
        class FakeRunner:
            def __init__(self,*args):pass
            def run(self,argv,**kwargs):
                if argv[:3]==['docker','image','inspect']:raise ValueError('MODELED image refusal')
                return SimpleNamespace(returncode=0,stdout=b'')
        class Cancelled(BaseException):pass
        runtime=SimpleNamespace(Runner=FakeRunner,cancellation_handlers=nullcontext,defer_signals=nullcontext,Cancelled=Cancelled)
        spec=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module:None))
        with tempfile.TemporaryDirectory(prefix='perl-final-report-DATA-') as temporary:
            root=Path(temporary);source=root/'source';source.write_bytes(b'MODELED source DATA')
            contract=json.loads(json.dumps(pins));contract['source']['name']='source.tar.gz'
            with mock.patch.object(host,'verify_inputs',side_effect=[contract,ValueError('MODELED original input change')]), \
                 mock.patch.object(host,'check_host',return_value=None), \
                 mock.patch.object(host.importlib.util,'spec_from_file_location',return_value=spec), \
                 mock.patch.object(host.importlib.util,'module_from_spec',return_value=runtime), \
                 mock.patch('sys.argv',['run.py','--source',str(source),'--output',str(root/'out'),'--builds','1']):
                with self.assertRaisesRegex(ValueError,'MODELED image refusal'):host.main()
            result=json.loads((root/'out/report.json').read_bytes())
            self.assertEqual(result['status'],'HOLD_ORIGINAL_INPUTS_CHANGED')
            self.assertFalse(result['original_inputs_unchanged']);self.assertTrue(result['cleanup'])

    def test_archive_layout_model_passes(self):
        self.assertEqual(reader.validate(rows(),pins)['command_aliases'],29)

    def test_missing_or_changed_alias_runtime_or_notice_refuses(self):
        for name in ['usr/bin/prove','usr/share/perl5/core_perl/pod/perldiag.pod','usr/share/licenses/perl/Artistic']:
            value=rows();del value[name]
            with self.subTest(name=name),self.assertRaises(ValueError):reader.validate(value,pins)
        value=rows();value['usr/bin/prove']['target']='core_perl/cpan'
        with self.assertRaises(ValueError):reader.validate(value,pins)

    def test_archive_privileged_mode_foreign_ELF_or_service_refuses(self):
        for name,row in [('usr/bin/perl',dict(type='file',mode=0o4755)),
            ('usr/bin/perl',dict(type='file',mode=0o755,ELF_machine=183)),
            ('usr/lib/systemd/system/perl.service',dict(type='file',mode=0o644))]:
            value=rows();value[name]=row
            with self.subTest(name=name,row=row),self.assertRaises(ValueError):reader.validate(value,pins)


if __name__=='__main__':unittest.main()
