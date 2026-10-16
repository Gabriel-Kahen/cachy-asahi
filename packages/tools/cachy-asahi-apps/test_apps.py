#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Readonly planner controls and real isolated signed synthetic release cases."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).absolute().parent
parser=argparse.ArgumentParser();parser.add_argument('--repository-source',type=Path,required=True)
options,rest=parser.parse_known_args();SOURCE=options.repository_source.absolute()
spec=importlib.util.spec_from_file_location('apps',HERE/'apps.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
c,r,PINS=a.helpers(SOURCE)

def pkg(name,version='1',depend=(),provides=(),conflict=(),files=None,**extra):
    row=dict(name=name,version=version,arch='aarch64',depend=list(depend),provides=list(provides),conflict=list(conflict),
                replaces=[],files=files if files is not None else ['usr/share/'+name]);row.update(extra);return row

def context(rows):
    base=pkg('linux-asahi');available=a.indexed(rows,r)
    return dict(available=available,base={base['name']:a.package(base,r)},apps={p['name']:dict(packages=[p['name']]) for p in rows},
        spec=dict(policy=dict(protected_packages=['linux-asahi'])),release=dict(packages=[dict(p,sha256=a.digest(a.encoded(p))) for p in rows]))

def inventory(*rows):
    return dict(schema_version=1,kind='complete-installed-inventory',target_arch='aarch64',snapshot_id='declared-test',packages=[pkg('linux-asahi'),*rows])

class PlannerTests(unittest.TestCase):
    def test_install_dependency_closure_records_signed_hashes_without_mutation(self):
        rows=[pkg('editor',depend=['api>=2']),pkg('runtime','2',provides=['api=2'])];ctx=context(rows);old=inventory();held=copy.deepcopy((ctx,old))
        result=a.plan(ctx,old,'install',['editor'],r)
        self.assertEqual([p['name'] for p in result['additions']],['editor','runtime'])
        self.assertEqual(result['dependencies'],[dict(package='runtime',required_by='editor',dependency='api>=2')])
        self.assertTrue(all(len(p['release_archive_sha256'])==64 for p in result['additions']));self.assertEqual((ctx,old),held)

    def test_removal_is_explicit_and_keeps_unused_dependency(self):
        ctx=context([pkg('editor',depend=['runtime']),pkg('runtime')]);old=inventory(pkg('editor',depend=['runtime']),pkg('runtime'))
        result=a.plan(ctx,old,'remove',['editor'],r)
        self.assertEqual([p['name'] for p in result['removals']],['editor'])
        self.assertNotIn('release_archive_sha256',result['removals'][0]);self.assertEqual(result['additions'],[])

    def test_reverse_dependency_breakage_refuses_including_non_catalog_consumer(self):
        ctx=context([pkg('runtime')]);old=inventory(pkg('runtime'),pkg('other',depend=['runtime>=1']))
        with self.assertRaisesRegex(a.Refusal,'break dependencies') as raised:a.plan(ctx,old,'remove',['runtime'],r)
        self.assertEqual(raised.exception.issues,[dict(kind='unsatisfied-dependency',package='other',dependency='runtime>=1')])

    def test_unresolved_or_ambiguous_dependencies_refuse_without_fallback(self):
        for rows in ([pkg('editor',depend=['missing'])],[pkg('editor',depend=['api>=2']),pkg('a',provides=['api=2']),pkg('b',provides=['api=2'])]):
            with self.subTest(rows=rows),self.assertRaisesRegex(a.Refusal,'unresolved or ambiguous'):a.plan(context(rows),inventory(),'install',['editor'],r)

    def test_explicit_provider_application_resolves_ambiguity_and_cycles_terminate(self):
        rows=[pkg('editor',depend=['api>=2']),pkg('a',provides=['api=2'],depend=['editor']),pkg('b',provides=['api=2'])]
        result=a.plan(context(rows),inventory(),'install',['editor','a'],r)
        self.assertEqual([p['name'] for p in result['additions']],['a','editor'])

    def test_upgrades_use_alpm_epoch_and_pkgrel_and_preserve_reverse_dependencies(self):
        ctx=context([pkg('runtime','2:1-2')]);old=inventory(pkg('runtime','2:1-1'),pkg('consumer',depend=['runtime>=2:1-1']))
        result=a.plan(ctx,old,'install',['runtime'],r);self.assertEqual(result['upgrades'][0]['after']['version'],'2:1-2')
        old['packages'][-1]['depend']=['runtime=2:1-1']
        with self.assertRaisesRegex(a.Refusal,'unresolved or ambiguous'):a.plan(ctx,old,'install',['runtime'],r)

    def test_downgrade_same_version_metadata_drift_and_protected_targets_refuse(self):
        for ctx,old,names in [(context([pkg('editor','1')]),inventory(pkg('editor','2')),['editor']),
                (context([pkg('editor',files=['usr/new'])]),inventory(pkg('editor')),['editor']),
                (context([pkg('editor',provides=['linux-asahi=1'])]),inventory(),['editor'])]:
            with self.subTest(names=names),self.assertRaises(a.Refusal):a.plan(ctx,old,'install',names,r)

    def test_all_base_packages_are_preserved_and_base_drift_refuses(self):
        ctx=context([pkg('editor')]);old=inventory();old['packages'][0]['version']='2'
        with self.assertRaisesRegex(a.Refusal,'base differs'):a.plan(ctx,old,'install',['editor'],r)
        ctx['apps']['unsafe']=dict(packages=['linux-asahi'])
        with self.assertRaisesRegex(a.Refusal,'protected'):a.plan(ctx,inventory(),'remove',['unsafe'],r)

    def test_package_and_file_conflicts_are_reported(self):
        for row in (pkg('editor',conflict=['foreign']),pkg('editor',files=['usr/foreign'])):
            with self.subTest(row=row),self.assertRaisesRegex(a.Refusal,'conflicts') as caught:
                a.plan(context([row]),inventory(pkg('foreign',files=['usr/foreign'])),'install',['editor'],r)
            self.assertTrue(caught.exception.issues)

    def test_regular_file_as_parent_of_another_payload_refuses(self):
        ctx=context([pkg('editor',files=['usr/share/foreign/child'])]);old=inventory(pkg('foreign',files=['usr/share/foreign']))
        with self.assertRaisesRegex(a.Refusal,'conflicts') as caught:a.plan(ctx,old,'install',['editor'],r)
        self.assertEqual(caught.exception.issues[0]['kind'],'file-directory-conflict')

    def test_x86_multilib_aur_and_foreign_catalog_package_refuse(self):
        for row in (pkg('editor',arch='x86_64'),pkg('lib32-editor'),pkg('editor',depend=['lib32-api']),pkg('editor',repository='aur')):
            with self.subTest(row=row),self.assertRaises(a.Refusal):a.package(row,r)
        value=dict(schema_version=1,kind='development-application-catalog',target_arch='aarch64',release_sha256='a'*64,
            repository='aur',applications=[])
        with self.assertRaises(a.Refusal):a.catalog_check(value,{},dict(repo_name='aur'),'a'*64,r)

    def test_noop_unknown_selection_broken_inventory_and_work_cap(self):
        ctx=context([pkg('editor')]);result=a.plan(ctx,inventory(pkg('editor')),'install',['editor'],r)
        self.assertEqual(result['unchanged_selected'],['editor']);self.assertEqual(result['additions'],[])
        with self.assertRaises(a.Refusal):a.plan(ctx,inventory(),'install',['unknown'],r)
        with self.assertRaisesRegex(a.Refusal,'inconsistent'):a.plan(ctx,inventory(pkg('broken',depend=['missing'])),'install',['editor'],r)
        with patch.object(a,'MAX_MATCHES',0),self.assertRaisesRegex(a.Refusal,'bounded work'):
            a.plan(context([pkg('editor',depend=['linux-asahi'])]),inventory(),'install',['editor'],r)

    def test_declared_same_version_byte_mismatch_is_not_silently_reinstalled(self):
        ctx=context([pkg('editor')]);old=inventory(pkg('editor',sha256='0'*64))
        with self.assertRaisesRegex(a.Refusal,'same-version installed archive differs'):a.plan(ctx,old,'install',['editor'],r)
        self.assertEqual(a.plan(ctx,old,'remove',['editor'],r)['removals'][0]['declared_archive_sha256'],'0'*64)

    def test_helper_hash_drift_refuses_before_source_execution(self):
        original=a.ordinary
        def changed(path,*args):
            raw=original(path,*args)
            return raw+b'\nraise RuntimeError("must not execute")' if str(path).endswith('release.py') else raw
        with patch.object(a,'ordinary',side_effect=changed),self.assertRaisesRegex(a.Refusal,'helper differs'):a.helpers(SOURCE)


class SignedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('gpg','gpgconf','bsdtar','vercmp','repo-add'):
            if not __import__('shutil').which(tool):raise RuntimeError('required real signed-fixture tool missing: '+tool)
        path=SOURCE/'scripts/release/test_release.py'
        spec=importlib.util.spec_from_file_location('apps_release_fixture',path);cls.fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.fixture)
        try:cls.fixture.ReleaseTests.setUpClass()
        except BaseException:
            cls.fixture.ReleaseTests.tearDownClass();raise
    @classmethod
    def tearDownClass(cls):cls.fixture.ReleaseTests.tearDownClass()
    def setUp(self):
        self.case=self.fixture.ReleaseTests('test_signed_stage_and_verify');self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.case.stage();self.root=self.case.base;self.bundle=self.case.directory
        self.catalog=self.root/'catalog.json';self.installed=self.root/'installed.json';self.keyring=self.root/'public.gpg'
        self.keyring.write_bytes(self.fixture.r.run(['gpg','--batch','--export',self.case.key],env=self.case.env))
        self.value=dict(schema_version=1,kind='development-application-catalog',target_arch='aarch64',release_sha256=self.fixture.r.sha(self.bundle/'release.json'),
            repository='fixture',applications=[dict(id='fixture',title='Synthetic Fixture',description='Signed planning fixture only',packages=['fixture'])])
        self.write_catalog();base=json.loads((self.bundle/'base.json').read_bytes());base['kind']='complete-installed-inventory';self.installed.write_bytes(a.encoded(base))
        self.args=argparse.Namespace(repository_source=SOURCE,release=str(self.bundle),release_sha256=self.value['release_sha256'],catalog=str(self.catalog),
            catalog_sha256=a.digest(self.catalog.read_bytes()),catalog_signature=str(self.catalog)+'.sig',keyring=str(self.keyring),signer=self.case.key,
            installed=str(self.installed),installed_sha256=a.digest(self.installed.read_bytes()),command='plan',operation='install',applications=['fixture'])
    def write_catalog(self):
        self.catalog.write_bytes(a.encoded(self.value));Path(str(self.catalog)+'.sig').unlink(missing_ok=True);self.fixture.r.sign(self.catalog,self.case.key,self.case.env)
        if hasattr(self,'args'):self.args.catalog_sha256=a.digest(self.catalog.read_bytes())
    def held(self):return {str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file() and not p.is_symlink()}
    def test_actual_signed_install_list_search_show_and_no_source_change(self):
        before=self.held();result=a.execute(self.args)
        self.assertEqual(result['status'],'PLANNED');self.assertEqual(result['applied'],'NOT_APPLIED');self.assertFalse(result['installer_authority'])
        self.assertTrue(result['synthetic']);self.assertEqual(result['plan']['additions'][0]['name'],'fixture')
        self.assertEqual(result['binding']['installed_sha256'],self.args.installed_sha256)
        for command in ('list','search','show'):
            self.args.command=command;self.args.query='sYnThEtIc';self.args.application='fixture'
            self.assertEqual(a.execute(self.args)['applications'][0]['id'],'fixture')
        self.assertEqual(self.held(),before)
    def test_actual_signed_removal_and_already_absent_noop_are_explicit(self):
        row=json.loads((self.bundle/'release.json').read_bytes())['packages'][0]
        state=json.loads(self.installed.read_bytes());state['packages'].append(row)
        self.installed.write_bytes(a.encoded(state));self.args.installed_sha256=a.digest(self.installed.read_bytes());self.args.operation='remove'
        result=a.execute(self.args);self.assertEqual(result['plan']['removals'][0]['name'],'fixture')
        self.assertNotIn('release_archive_sha256',result['plan']['removals'][0])
        state['packages'].pop();self.installed.write_bytes(a.encoded(state));self.args.installed_sha256=a.digest(self.installed.read_bytes())
        self.assertEqual(a.execute(self.args)['plan']['removals'],[])

    def test_nonsynthetic_release_with_synthetic_provenance_is_not_native(self):
        self.case.release_spec.update(synthetic=False,release_id='fixture-native-refusal');self.case.stage()
        self.bundle=self.case.directory;self.args.release=str(self.bundle)
        self.args.release_sha256=self.fixture.r.sha(self.bundle/'release.json');self.value['release_sha256']=self.args.release_sha256;self.write_catalog()
        with self.assertRaisesRegex(a.Refusal,'native aarch64 build provenance'):a.execute(self.args)

    def test_unsigned_catalog_and_tampered_signature_refuse(self):
        Path(self.args.catalog_signature).unlink()
        with self.assertRaises(OSError):a.execute(self.args)
        Path(self.args.catalog_signature).write_bytes(b'not a signature')
        with self.assertRaises(Exception):a.execute(self.args)
    def test_signed_catalog_cannot_select_base_or_foreign_release(self):
        for edit in ('base','foreign'):
            if edit=='base':self.value['applications'][0]['packages']=['linux-asahi']
            else:self.value['release_sha256']='f'*64
            self.write_catalog()
            with self.subTest(edit=edit),self.assertRaises(a.Refusal):a.execute(self.args)
    def test_payload_tamper_wrong_signer_and_inventory_pin_fail(self):
        self.args.installed_sha256='0'*64
        with self.assertRaises(a.Refusal):a.execute(self.args)
        self.args.installed_sha256=a.digest(self.installed.read_bytes());self.args.signer='0'*40
        with self.assertRaises(Exception):a.execute(self.args)
        self.args.signer=self.case.key;archive=next((self.bundle/'repo').glob('*.pkg.tar.gz'));archive.write_bytes(archive.read_bytes()+b'changed')
        with self.assertRaises(Exception):a.execute(self.args)
    def test_cli_plan_and_apply_refusal_use_private_home_and_leave_inputs(self):
        cli=[sys.executable,'-I','-B',str(HERE/'apps.py')]
        for name in ('repository-source','release','release-sha256','catalog','catalog-sha256','catalog-signature','keyring','signer','installed','installed-sha256'):
            cli+=['--'+name,str(getattr(self.args,name.replace('-','_')))]
        home=self.root/'cli-home';home.mkdir();env=dict(PATH='/usr/bin:/bin',HOME=str(home),XDG_RUNTIME_DIR=str(home),LC_ALL='C')
        result=subprocess.run(cli+['plan','install','fixture'],capture_output=True,text=True,timeout=60,env=env)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr);self.assertEqual(json.loads(result.stdout)['applied'],'NOT_APPLIED')
        refused=subprocess.run(cli+['--apply','plan','install','fixture'],capture_output=True,text=True,timeout=30,env=env)
        self.assertNotEqual(refused.returncode,0);self.assertEqual(list(home.iterdir()),[])

if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
