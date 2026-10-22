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
parser.add_argument('--app-recipe-root',type=Path,default=HERE)
parser.add_argument('--runtime-recipe-root',type=Path,default=HERE.parent/'cachy-asahi-repository-runtime')
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

def write_db(path,rows):
    local=path/'local';local.mkdir(parents=True,exist_ok=True);(local/'ALPM_DB_VERSION').write_bytes(b'9\n')
    for row in rows:
        directory=local/(row['name']+'-'+row['version']);directory.mkdir()
        desc=''.join('%'+field+'%\n'+row[key]+'\n\n' for field,key in (('NAME','name'),('VERSION','version'),('ARCH','arch')))
        for field,key in (('DEPENDS','depend'),('PROVIDES','provides'),('CONFLICTS','conflict'),('REPLACES','replaces')):
            if row.get(key):desc+='%'+field+'%\n'+'\n'.join(row[key])+'\n\n'
        (directory/'desc').write_text(desc)
        (directory/'files').write_bytes(('%FILES%\n'+'\n'.join(row['files'])+'\n\n').encode() if row['files'] else b'')
    return local


class PlannerTests(unittest.TestCase):
    def test_install_dependency_closure_records_signed_hashes_without_mutation(self):
        rows=[pkg('editor',depend=['api>=2']),pkg('runtime','2',provides=['api=2'])];ctx=context(rows);old=inventory();held=copy.deepcopy((ctx,old))
        result=a.plan(ctx,old,'install',['editor'],r)
        self.assertEqual([p['name'] for p in result['additions']],['editor','runtime'])
        self.assertEqual(result['dependencies'],[dict(package='runtime',required_by='editor',dependency='api>=2')])
        self.assertTrue(all(len(p['release_archive_sha256'])==64 for p in result['additions']));self.assertEqual((ctx,old),held)

    def test_explicit_reinstall_binds_same_metadata_and_signed_archive(self):
        rows=[pkg('editor',depend=['runtime']),pkg('runtime')];ctx=context(rows);old=inventory(pkg('editor',depend=['runtime'],sha256='f'*64),pkg('runtime'));held=copy.deepcopy((ctx,old))
        result=a.plan(ctx,old,'reinstall',['editor'],r)
        self.assertEqual([v['after']['name'] for v in result['reinstalls']],['editor']);self.assertEqual(result['reinstalls'][0]['before']['declared_archive_sha256'],'f'*64)
        self.assertEqual(result['reinstalls'][0]['after']['release_archive_sha256'],ctx['release']['packages'][0]['sha256'])
        self.assertEqual(result['additions']+result['upgrades']+result['removals']+result['dependencies']+result['unchanged_selected'],[])
        self.assertEqual(result['before_inventory_sha256'],result['after_inventory_sha256']);self.assertEqual((ctx,old),held)
    def test_reinstall_refuses_missing_version_metadata_and_protected_targets(self):
        for old in (inventory(),inventory(pkg('editor','2')),inventory(pkg('editor',files=['usr/other']))):
            with self.subTest(old=old),self.assertRaisesRegex(a.Refusal,'already-installed exact'):a.plan(context([pkg('editor')]),old,'reinstall',['editor'],r)
        ctx=context([pkg('editor')]);ctx['apps']['unsafe']=dict(packages=['linux-asahi'])
        with self.assertRaisesRegex(a.Refusal,'protected'):a.plan(ctx,inventory(),'reinstall',['unsafe'],r)
        ctx=context([pkg('editor',provides=['linux-asahi=1'])]);old=inventory(pkg('editor',provides=['linux-asahi=1']))
        with self.assertRaisesRegex(a.Refusal,'protected'):a.plan(ctx,old,'reinstall',['editor'],r)

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


class CheckInputsTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('check_inputs',HERE/'prepare-check-inputs.py')
        self.prepare=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.prepare)
        self.temp=tempfile.TemporaryDirectory(prefix='apps-check-data-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.archive=HERE/'check-inputs.tar.gz';self.index=HERE/'check-inputs.json'
    def test_exact_closed_check_tree_and_original_source_bytes(self):
        output=self.root/'inputs';value=self.prepare.prepare(self.archive,self.index,output)
        self.assertEqual(value['files'],16);self.assertEqual(value['code_execution'],'NONE')
        self.assertEqual({p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()},self.prepare.MEMBERS)
        for name in PINS:self.assertEqual((output/'repository'/name).read_bytes(),(SOURCE/name).read_bytes())
        self.assertEqual((output/'repository/scripts/release/test_release.py').read_bytes(),(SOURCE/'scripts/release/test_release.py').read_bytes())
    def test_makepkg_local_source_links_stage_private_regular_pinned_inputs(self):
        import hashlib,re,shlex
        recipe=options.app_recipe_root.absolute();text=(recipe/'PKGBUILD').read_text()
        names=shlex.split(re.search(r'^source=\((.*?)\)',text,re.M|re.S)[1])
        pins=shlex.split(re.search(r'^sha256sums=\((.*?)\)',text,re.M|re.S)[1])
        src=self.root/'makepkg-src';src.mkdir()
        for name in names:(src/name).symlink_to(recipe/name)
        with self.assertRaisesRegex(ValueError,'ordinary check input path'):
            self.prepare.prepare(src/'check-inputs.tar.gz',src/'check-inputs.json',self.root/'direct')
        def stage():
            return subprocess.run(['/bin/bash','--noprofile','--norc','-c','set -euo pipefail; source "$1"; _stage_check_sources',
                'stage-check',str(recipe/'PKGBUILD')],env=dict(PATH='/usr/bin:/bin',srcdir=str(src)),text=True,capture_output=True,timeout=30)
        result=stage();self.assertEqual(result.returncode,0,result.stdout+result.stderr);staged=Path(result.stdout.strip())
        self.assertEqual(staged.parent,src);self.assertEqual(staged.stat().st_mode&0o777,0o700)
        self.assertEqual({p.name for p in staged.iterdir()},set(names))
        for name,pin in zip(names,pins):
            path=staged/name;self.assertFalse(path.is_symlink());self.assertEqual(path.stat().st_nlink,1)
            self.assertEqual(path.stat().st_mode&0o777,0o600);self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),pin)
            self.assertTrue((src/name).is_symlink())
        value=self.prepare.prepare(staged/'check-inputs.tar.gz',staged/'check-inputs.json',staged/'check-inputs')
        self.assertEqual(value['files'],16)
        second=stage();self.assertEqual(second.returncode,0,second.stderr);self.assertNotEqual(second.stdout,result.stdout)
        changed=self.root/'changed-index.json';changed.write_bytes(self.index.read_bytes()+b'changed')
        (src/'check-inputs.json').unlink();(src/'check-inputs.json').symlink_to(changed)
        refused=stage();self.assertNotEqual(refused.returncode,0);self.assertEqual(refused.stdout,'')

    def test_bad_archive_hash_existing_output_and_symlink_refuse(self):
        wrong=self.root/'bad.tar.gz';wrong.write_bytes(self.archive.read_bytes()+b'changed')
        with self.assertRaises(ValueError):self.prepare.prepare(wrong,self.index,self.root/'bad')
        existing=self.root/'existing';existing.mkdir()
        with self.assertRaises(ValueError):self.prepare.prepare(self.archive,self.index,existing)
        link=self.root/'alias';link.symlink_to(self.archive)
        with self.assertRaises(ValueError):self.prepare.prepare(link,self.index,self.root/'bad')
        self.assertFalse((self.root/'bad').exists())
    def test_duplicate_link_escape_and_missing_members_refuse_before_writing(self):
        import io,tarfile
        with tarfile.open(self.archive,'r:gz') as archive:
            records=[(copy.deepcopy(m),archive.extractfile(m).read()) for m in archive]
        original=json.loads(self.index.read_bytes())
        for variant in ('duplicate','link','escape','missing'):
            rows=copy.deepcopy(records)
            if variant=='duplicate':rows.append(rows[0])
            elif variant=='link':rows[0][0].type=tarfile.SYMTYPE;rows[0][0].linkname='../../escape';rows[0][0].size=0
            elif variant=='escape':rows[0][0].name='../escape'
            else:rows.pop()
            data=io.BytesIO()
            with tarfile.open(fileobj=data,mode='w:gz',format=tarfile.USTAR_FORMAT) as archive:
                for member,raw in rows:archive.addfile(member,io.BytesIO(raw) if member.type==tarfile.REGTYPE else None)
            path=self.root/(variant+'.tar.gz');path.write_bytes(data.getvalue());index=copy.deepcopy(original)
            index['archive']=self.prepare.digest(data.getvalue());pin=self.root/(variant+'.json');pin.write_bytes(a.encoded(index))
            with self.subTest(variant=variant),self.assertRaises(ValueError):self.prepare.prepare(path,pin,self.root/variant)
            self.assertFalse((self.root/variant).exists())


class InventorySectionSetTests(unittest.TestCase):
    def test_large_ownership_order_and_relation_duplicate_semantics(self):
        reader=a.inventory_reader();files=['usr/share/large/file-'+str(n).zfill(5) for n in range(16384)]
        raw=('%FILES%\n'+'\n'.join(reversed(files))+'\n\n').encode()
        self.assertEqual(reader.sections(raw,{'FILES'})['FILES'],list(reversed(files)))
        for field in ('DEPENDS','PROVIDES','CONFLICTS','REPLACES'):
            data=('%'+field+'%\nz=1\na=2\nz=1\na=2\n\n').encode()
            self.assertEqual(reader.sections(data,{field})[field],['z=1','a=2'])
        for field in ('FILES','BACKUP','NAME','ARCH'):
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'duplicate ALPM value'):
                reader.sections(('%'+field+'%\nx\nx\n\n').encode(),{field})
    def test_empty_malformed_control_and_cross_section_error_order(self):
        reader=a.inventory_reader();self.assertEqual(reader.sections(b'',{'FILES'}),{})
        self.assertEqual(reader.sections(b'%FILES%\n\n',{'FILES'}),{'FILES':[]})
        bad=[(b'%FILES%\nx\nx\n%ALIEN%\n','duplicate ALPM value'),(b'%FILES%\nx\n%FILES%\ny\n','unknown/duplicate/missing-separator'),(b'%FILES%\nx','terminal LF')]
        for raw,error in bad:
            with self.subTest(raw=raw),self.assertRaisesRegex(ValueError,error):reader.sections(raw,{'FILES'})
        for raw in (b'%FILES%\n\x01bad\n\n',b'%FILES%\n\x7f\n\n',b'%FILES%\n%unexpected\n\n',b'%FILES%\n\xff\n\n'):
            with self.subTest(raw=raw),self.assertRaises((ValueError,UnicodeError)):reader.sections(raw,{'FILES'})

class ActualMetadataTests(unittest.TestCase):
    def test_native_compatibility_aliases_are_metadata_not_foreign_selection(self):
        row=pkg('libtool',provides=['libtool-multilib=2.6.0'],conflict=['libtool-multilib'],replaces=['libtool-multilib'])
        self.assertEqual(a.package(row,r)['provides'],row['provides'])
        self.assertEqual(a.package(pkg('libunwind',provides=['libunwind-x86_64.so']),r)['arch'],'aarch64')
        for row in (pkg('libtool-multilib'),pkg('libunwind',arch='x86_64'),pkg('editor',depend=['libtool-multilib']),pkg('editor',provides=['../escape'])):
            with self.subTest(row=row),self.assertRaises((a.Refusal,r.Error)):a.package(row,r)

    def test_identical_alpm_relations_only_normalize_once(self):
        reader=a.inventory_reader()
        for field in ('DEPENDS','PROVIDES','CONFLICTS','REPLACES'):
            self.assertEqual(reader.sections(('%'+field+'%\nlibncursesw.so=6-64\nlibncursesw.so=6-64\n\n').encode(),{field})[field],['libncursesw.so=6-64'])
        for field in ('NAME','ARCH','FILES','BACKUP'):
            with self.subTest(field=field),self.assertRaises(ValueError):reader.sections(('%'+field+'%\nsame\nsame\n\n').encode(),{field})

    def test_literal_systemd_backslash_is_not_decoded_or_a_separator(self):
        reader=a.inventory_reader();name=r'usr/lib/systemd/system/system-systemd\x2dcryptsetup.slice'
        self.assertEqual(reader.relative(name),(name,False))
        self.assertEqual(a.package(pkg('systemd',files=[name]),r)['files'],[name])
        for name in ('../escape','/absolute',r'usr/\x2d/../escape',r'usr/\x2d//escape'):
            with self.subTest(name=name),self.assertRaises(ValueError):reader.relative(name)
        self.assertEqual(a.MAX_INSTALLED_JSON,reader.MAX_INSTALLED_JSON)
        self.assertEqual(c.MAX_JSON,4*1024**2)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='apps-alpm-observation-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.db=self.root/'db';self.local=write_db(self.db,[pkg('linux-asahi'),pkg('fileless',files=[])])
        self.reader=a.inventory_reader();self.output=self.root/'inventory.json';self.normalize=lambda row:a.package(row,r)
    def collect(self):return self.reader.collect(self.db,c,self.normalize)
    def test_fileless_raw_hashes_normalization_and_private_publication_without_commands(self):
        with patch.object(subprocess,'Popen',side_effect=AssertionError('inventory must not run a command')):
            result=self.reader.publish(self.db,self.output,c,self.normalize)
        value=c.decode(self.output.read_bytes());self.assertEqual(self.output.stat().st_mode&0o777,0o600)
        self.assertEqual(result['qualification'],self.reader.QUALIFICATION);self.assertEqual(len(value['packages']),2)
        self.assertEqual(value['packages'][0]['files'],[]);self.assertFalse(value['observation']['payload_verified'])
        self.assertFalse(any('sha256' in row for row in value['packages']))
        self.assertEqual(value['observation']['inputs']['local/fileless-1/files'],dict(bytes=0,sha256=a.digest(b'')))
        self.assertEqual(self.reader.validate(value,self.normalize),self.reader.QUALIFICATION)
    def test_real604_database_with_large_package_keeps_two_exact_reads_and_deadline(self):
        rows=[pkg('large-owned',files=['usr/share/large-owned/file-'+str(n).zfill(5)for n in range(8192)])]+[pkg('finite-'+str(n).zfill(3))for n in range(601)]
        write_db(self.db,rows);original=self.reader.scan;calls=[]
        def scan(*args):calls.append(args[-1]);return original(*args)
        with patch.object(subprocess,'Popen',side_effect=AssertionError('readonly inventory actors forbidden')),patch.object(self.reader,'scan',side_effect=scan):value=self.collect()
        self.assertEqual(len(value['packages']),604);self.assertEqual(len(calls),2);self.assertEqual(calls[0],calls[1])
        self.assertEqual(value['observation']['consistency'],'TWO_MATCHING_READS_NO_LOCK_NO_DETECTED_DRIFT')
        self.assertEqual(len(next(r for r in value['packages']if r['name']=='large-owned')['files']),8192)
        self.assertEqual(self.reader.validate(value,self.normalize),self.reader.QUALIFICATION)

    def test_lock_any_type_uncertainty_and_root_alias_refuse_without_output(self):
        lock=self.db/'db.lck'
        for kind in ('file','directory','symlink'):
            if kind=='file':lock.write_bytes(b'')
            elif kind=='directory':lock.mkdir()
            else:lock.symlink_to(self.root/'absent')
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.reader.publish(self.db,self.output,c,self.normalize)
            if kind=='directory':lock.rmdir()
            else:lock.unlink()
            self.assertFalse(self.output.exists())
        original=self.reader.os.stat
        def uncertain(path,*args,**kw):
            if path=='db.lck':raise PermissionError('uncertain lock')
            return original(path,*args,**kw)
        with patch.object(self.reader.os,'stat',side_effect=uncertain),self.assertRaises(PermissionError):self.collect()
        alias=self.root/'db-alias';alias.symlink_to(self.db,target_is_directory=True)
        with self.assertRaises(OSError):self.reader.collect(alias,c,self.normalize)
    def test_malformed_identity_architecture_ownership_and_exact_fileless_rules(self):
        directory=self.local/'fileless-1';desc=directory/'desc';files=directory/'files';original=desc.read_bytes()
        variants=[original.replace(b'%ARCH%\naarch64\n\n',b''),original.replace(b'aarch64',b'x86_64'),
            original+b'%NAME%\nother\n\n',original+b'%DEPENDS%\n../escape\n\n',b'invalid\n',original+b'\xff']
        for raw in variants:
            desc.write_bytes(raw)
            with self.subTest(raw=raw),self.assertRaises(Exception):self.collect()
        desc.write_bytes(original)
        for raw in (b'\n',b'%BACKUP%\netc/x\t' + b'0'*32+b'\n\n',b'%FILES%\n../escape\n\n',b'%FILES%\nusr/x\nusr/x\n\n'):
            files.write_bytes(raw)
            with self.subTest(raw=raw),self.assertRaises(ValueError):self.collect()
        files.write_bytes(b'%FILES%\n\n');self.assertEqual(self.collect()['packages'][0]['files'],[])
        files.unlink()
        with self.assertRaisesRegex(ValueError,'incomplete'):self.collect()
    def test_hardlinks_symlinks_special_and_unknown_records_refuse(self):
        directory=self.local/'fileless-1';files=directory/'files';files.unlink();target=self.root/'empty';target.write_bytes(b'')
        files.symlink_to(target)
        with self.assertRaises(OSError):self.collect()
        files.unlink();os.link(target,files)
        with self.assertRaises(Exception):self.collect()
        files.unlink();os.mkfifo(files)
        with self.assertRaises(Exception):self.collect()
        files.unlink();files.write_bytes(b'');(directory/'unexpected').write_bytes(b'')
        with self.assertRaises(ValueError):self.collect()
    def test_drift_in_records_membership_or_transient_lock_refuses(self):
        original=self.reader.scan
        for variant in ('record','membership','lock'):
            calls=0;desc=self.local/'fileless-1/desc';old=desc.read_bytes();extra=self.local/'new-1'
            def changed(*args):
                nonlocal calls
                value=original(*args);calls+=1
                if calls==1:
                    if variant=='record':desc.write_bytes(old+b'%DESC%\nchanged\n\n')
                    elif variant=='membership':extra.mkdir()
                    else:(self.db/'db.lck').write_bytes(b'');(self.db/'db.lck').unlink()
                return value
            with self.subTest(variant=variant),patch.object(self.reader,'scan',side_effect=changed),self.assertRaises(Exception):self.collect()
            desc.write_bytes(old)
            if extra.exists():extra.rmdir()
    def test_observed_qualifier_does_not_relax_base_or_claim_payload(self):
        value=self.collect();ctx=context([pkg('editor')]);self.assertEqual(a.plan(ctx,value,'install',['editor'],r)['installed_inventory'],self.reader.QUALIFICATION)
        bad=copy.deepcopy(value);bad['observation']['payload_verified']=True
        with self.assertRaises(ValueError):a.plan(ctx,bad,'install',['editor'],r)
        bad=copy.deepcopy(value);next(p for p in bad['packages'] if p['name']=='linux-asahi')['version']='2'
        bad['observation']['packages_metadata_sha256']=a.digest(a.encoded(bad['packages']))
        with self.assertRaises(Exception):a.plan(ctx,bad,'install',['editor'],r)
        duplicate=self.local/'fileless-2';duplicate.mkdir();(duplicate/'desc').write_text('%NAME%\nfileless\n\n%VERSION%\n2\n\n%ARCH%\naarch64\n\n');(duplicate/'files').write_bytes(b'')
        with self.assertRaises(ValueError):self.collect()
    def test_package_byte_output_and_deadline_bounds_refuse(self):
        for name,value in (('MAX_PACKAGES',1),('MAX_BYTES',1),('MAX_RECORD',1)):
            with self.subTest(name=name),patch.object(self.reader,name,value),self.assertRaises(Exception):self.collect()
        with patch.object(self.reader,'MAX_INSTALLED_JSON',16),self.assertRaises(ValueError):self.collect()
        with patch.object(self.reader.time,'monotonic',side_effect=[0,31]),self.assertRaises(ValueError):self.collect()

    def test_existing_or_alias_output_and_write_failure_preserve_state(self):
        self.output.write_bytes(b'keep')
        with self.assertRaises(ValueError):self.reader.publish(self.db,self.output,c,self.normalize)
        self.assertEqual(self.output.read_bytes(),b'keep');self.output.unlink()
        with self.assertRaises(ValueError):self.reader.publish(self.db,self.db/'snapshot.json',c,self.normalize)
        alias=self.root/'output-alias';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(OSError):self.reader.publish(self.db,alias/'snapshot.json',c,self.normalize)
        with patch.object(self.reader.os,'fsync',side_effect=OSError('injected output failure')),self.assertRaises(OSError):
            self.reader.publish(self.db,self.output,c,self.normalize)
        self.assertFalse(self.output.exists())
    def test_cli_observation_needs_no_release_catalog_or_key_credentials(self):
        command=[sys.executable,'-I','-B',str(HERE/'apps.py'),'--repository-source',str(SOURCE),'inventory','--dbpath',str(self.db),'--output',str(self.output)]
        result=subprocess.run(command,capture_output=True,text=True,timeout=30,env=dict(PATH='/usr/bin:/bin',HOME=str(self.root),LC_ALL='C'))
        self.assertEqual(result.returncode,0,result.stdout+result.stderr);receipt=json.loads(result.stdout)
        self.assertEqual(receipt['qualification'],self.reader.QUALIFICATION);self.assertEqual(receipt['sha256'],a.digest(self.output.read_bytes()))
        self.assertEqual(receipt['applied'],'NOT_APPLIED')


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
    def test_staged_default_lookup_without_checkout_and_companion_failures(self):
        stage=self.root/'installed';stage.mkdir()
        for recipe in (options.app_recipe_root.absolute(),options.runtime_recipe_root.absolute()):
            env=dict(PATH='/usr/bin:/bin',srcdir=str(recipe),pkgdir=str(stage))
            staged=subprocess.run(['/bin/bash','--noprofile','--norc','-c','source "$1"; package','stage',str(recipe/'PKGBUILD')],
                                  env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(staged.returncode,0,staged.stderr)
        target=stage/'usr/bin/cachy-asahi-apps';runtime=stage/'usr/share/cachy-asahi/repository-runtime'
        self.assertEqual({p.relative_to(runtime).as_posix() for p in runtime.rglob('*') if p.is_file()},set(PINS))
        home=self.root/'staged-private-home';home.mkdir();cwd=self.root/'empty-cwd';cwd.mkdir()
        cli=[str(target)]
        for name in ('release','release-sha256','catalog','catalog-sha256','catalog-signature','keyring','signer','installed','installed-sha256'):
            cli+=['--'+name,str(getattr(self.args,name.replace('-','_')))]
        self.assertNotIn('--repository-source',cli)
        env=dict(PATH='/usr/bin:/bin',HOME=str(home),XDG_RUNTIME_DIR=str(home),LC_ALL='C')
        def run(command):return subprocess.run(cli+command,capture_output=True,text=True,timeout=60,env=env,cwd=cwd)
        for command in (['list'],['search','synthetic'],['show','fixture'],['plan','install','fixture'],['plan','remove','fixture']):
            result=run(command);self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            value=json.loads(result.stdout);self.assertEqual(value['applied'],'NOT_APPLIED');self.assertTrue(value['synthetic'])
            if command[:2]==['plan','install']:self.assertEqual(value['plan']['additions'][0]['name'],'fixture')
        helper=runtime/'scripts/client/client.py';raw=helper.read_bytes()
        helper.unlink();missing=run(['list']);self.assertNotEqual(missing.returncode,0)
        helper.write_bytes(raw+b'\nchanged');changed=run(['list']);self.assertNotEqual(changed.returncode,0)
        self.assertIn('helper differs',json.loads(changed.stdout)['error']);helper.write_bytes(raw)
        self.assertEqual(list(home.iterdir()),[]);self.assertFalse((stage/'.git').exists())

    def test_observed_inventory_to_genuine_signed_install_remove_and_base_drift_refusal(self):
        base=json.loads((self.bundle/'base.json').read_bytes());db=self.root/'observed-db';write_db(db,base['packages'])
        reader=a.inventory_reader();self.installed=self.root/'observed.json'
        receipt=reader.publish(db,self.installed,c,lambda row:a.package(row,r))
        self.args.installed=str(self.installed);self.args.installed_sha256=receipt['sha256']
        result=a.execute(self.args);self.assertEqual(result['plan']['additions'][0]['name'],'fixture')
        self.assertEqual(result['plan']['installed_inventory'],reader.QUALIFICATION)
        self.assertNotEqual(json.loads(self.installed.read_bytes())['snapshot_id'],base['snapshot_id'])
        row=json.loads((self.bundle/'release.json').read_bytes())['packages'][0]
        write_db(db,[row]);self.installed=self.root/'observed-after.json'
        receipt=reader.publish(db,self.installed,c,lambda row:a.package(row,r));self.args.installed=str(self.installed);self.args.installed_sha256=receipt['sha256'];self.args.operation='remove'
        result=a.execute(self.args);self.assertEqual(result['plan']['removals'][0]['name'],'fixture')
        self.assertNotIn('release_archive_sha256',result['plan']['removals'][0])
        old=db/'local/runtime-2';(old/'desc').write_bytes((old/'desc').read_bytes().replace(b'%VERSION%\n2\n',b'%VERSION%\n3\n'));old.rename(db/'local/runtime-3')
        changed=self.root/'observed-base-drift.json';receipt=reader.publish(db,changed,c,lambda row:a.package(row,r))
        self.args.installed=str(changed);self.args.installed_sha256=receipt['sha256']
        with self.assertRaisesRegex(a.Refusal,'base differs'):a.execute(self.args)

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

    def test_actual_signed_cli_reinstall_plan_is_explicit_not_applied(self):
        row=json.loads((self.bundle/'release.json').read_bytes())['packages'][0];state=json.loads(self.installed.read_bytes());state['packages'].append(row);self.installed.write_bytes(a.encoded(state));self.args.installed_sha256=a.digest(self.installed.read_bytes());self.args.operation='reinstall';held=self.held()
        result=a.execute(self.args);self.assertEqual(result['applied'],'NOT_APPLIED');self.assertEqual(result['plan']['operation'],'reinstall');self.assertEqual(len(result['plan']['reinstalls']),1);self.assertEqual(result['plan']['additions']+result['plan']['upgrades']+result['plan']['removals'],[])
        cli=[sys.executable,'-I','-B',str(HERE/'apps.py')]
        for name in ('repository-source','release','release-sha256','catalog','catalog-sha256','catalog-signature','keyring','signer','installed','installed-sha256'):cli+=['--'+name,str(getattr(self.args,name.replace('-','_')))]
        home=self.root/'repair-home';home.mkdir();run=subprocess.run(cli+['plan','reinstall','fixture'],capture_output=True,text=True,timeout=60,env=dict(PATH='/usr/bin:/bin',HOME=str(home),XDG_RUNTIME_DIR=str(home),LC_ALL='C'))
        self.assertEqual(run.returncode,0,run.stderr);self.assertEqual(json.loads(run.stdout),result);self.assertEqual(list(home.iterdir()),[]);self.assertEqual(self.held(),held)

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
