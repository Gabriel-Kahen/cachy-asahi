#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Synthetic Cargo data controls. No fixture is native or authenticated evidence."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('audio_vendor_tests',HERE/'audit.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)


def archive(files,links=None):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT)as out:
        for name,body in sorted(files.items()):
            m=tarfile.TarInfo(name);m.size=len(body);out.addfile(m,io.BytesIO(body))
        for name,target in (links or {}).items():
            m=tarfile.TarInfo(name);m.type=tarfile.SYMTYPE;m.linkname=target;out.addfile(m)
    return stream.getvalue()


def crate(name,version,checksum,deps=''):
    files={'Cargo.toml':f'[package]\nname="{name}"\nversion="{version}"\nlicense="MIT"\n{deps}'.encode(),
           'src/lib.rs':b'compile_error!("TEST DATA MUST NEVER EXECUTE");\n','LICENSE':b'MIT synthetic license fixture only\n'}
    files['.cargo-checksum.json']=a.encoded(dict(package=checksum,files={k:a.digest(v)for k,v in files.items()}))
    return {'vendor/'+name+'-'+version+'/'+key:raw for key,raw in files.items()}


class Audit(unittest.TestCase):
    def setUp(self):
        self.files=dict(crate('alpha','1.2.3','a'*64,'[dependencies]\nbeta="^0.2"\n'),**crate('beta','0.2.1','b'*64))
        self.raw=archive(self.files);self.vendor,self.parsed,self.ids=a.vendor_data(self.raw)
        self.lock=('version=3\n[[package]]\nname="root"\nversion="1.0.0"\ndependencies=["alpha"]\n'
            '[[package]]\nname="alpha"\nversion="1.2.3"\nsource="'+a.REGISTRY+'"\nchecksum="'+'a'*64+'"\ndependencies=["beta"]\n'
            '[[package]]\nname="beta"\nversion="0.2.1"\nsource="'+a.REGISTRY+'"\nchecksum="'+'b'*64+'"\n').encode()
        self.source={'root/Cargo.toml':b'[package]\nname="root"\nversion="1.0.0"\nlicense="MIT"\n[dependencies]\nalpha="^1.0"\n',
                     'root/Cargo.lock':self.lock,'root/LICENSE':b'MIT synthetic fixture only\n'}
        self.components=dict(cargo_lock_sha256=a.digest(self.lock),registry_crates=2,
            vendor=dict(**a.desc(self.raw),crates=2,regular_files=8,expanded_bytes=self.vendor['expanded_bytes']),
            locked_components=[dict(file_count=r['files_verified'],license=r['license']['declared_expression'],name=r['name'],
                package_checksum=r['package_checksum'],root=root,version=r['version'])for root,r in self.vendor['crates'].items()])

    def project(self,source=None,vendor=None,parsed=None,ids=None,components=None):
        return a.audit_project(archive(source or self.source),vendor or self.vendor,parsed or self.parsed,ids or self.ids,components or self.components)

    def test_recomputes_all_file_sets_and_checksums(self):
        self.assertEqual(self.vendor['declared_files_verified'],6)
        self.assertEqual(self.vendor['regular_files'],8)
        report,bound=self.project();self.assertEqual(report['errors'],[]);self.assertEqual(len(bound),2)
        self.assertEqual([x['status']for x in report['lock_edges']],['LEXICALLY_JOINED']*2)

    def test_changed_declared_file_refused(self):
        self.files['vendor/alpha-1.2.3/src/lib.rs']=b'changed'
        with self.assertRaisesRegex(a.Refused,'FILE_CHECKSUM_DIFFERS'):a.vendor_data(archive(self.files))

    def test_omitted_declared_file_refused(self):
        del self.files['vendor/alpha-1.2.3/src/lib.rs']
        with self.assertRaisesRegex(a.Refused,'MISSING_OR_EXTRA_FILE'):a.vendor_data(archive(self.files))

    def test_extra_undeclared_file_refused(self):
        self.files['vendor/alpha-1.2.3/extra']=b'unbound'
        with self.assertRaisesRegex(a.Refused,'MISSING_OR_EXTRA_FILE'):a.vendor_data(archive(self.files))

    def test_missing_checksum_manifest_refused(self):
        del self.files['vendor/alpha-1.2.3/.cargo-checksum.json']
        with self.assertRaisesRegex(a.Refused,'MISSING_VENDOR_MANIFEST'):a.vendor_data(archive(self.files))

    def test_unsafe_declared_checksum_path_refused(self):
        key='vendor/alpha-1.2.3/.cargo-checksum.json';value=json.loads(self.files[key]);value['files']['../outside']='0'*64;self.files[key]=a.encoded(value)
        with self.assertRaisesRegex(a.Refused,'UNSAFE_MEMBER_PATH'):a.vendor_data(archive(self.files))

    def test_duplicate_json_keys_refused(self):
        with self.assertRaisesRegex(a.Refused,'DUPLICATE_CHECKSUM_JSON_KEY'):a.json_data(b'{"files":{},"files":{}}')

    def test_duplicate_crate_identity_refused(self):
        other={key.replace('vendor/alpha-1.2.3/','vendor/other/'):raw for key,raw in self.files.items()if key.startswith('vendor/alpha-1.2.3/')}
        with self.assertRaisesRegex(a.Refused,'DUPLICATE_VENDOR_PACKAGE_IDENTITY'):a.vendor_data(archive(dict(self.files,**other)))

    def test_vendor_symlink_and_traversal_refused(self):
        with self.assertRaisesRegex(a.Refused,'LINK_OR_SPECIAL'):a.vendor_data(archive(self.files,{'vendor/alpha-1.2.3/link':'LICENSE'}))
        with self.assertRaisesRegex(a.Refused,'UNSAFE_MEMBER_PATH'):a.tar_data(archive({'../outside':b'x'}))

    def test_source_symlinks_recorded_inertly(self):
        raw=archive(self.source,{'root/link':'LICENSE'});files,root,links=a.source_data(raw)
        self.assertEqual(links,{'root/link':'LICENSE'});self.assertNotIn('root/link',files)
        with self.assertRaisesRegex(a.Refused,'FILE_BELOW_SOURCE_SYMLINK'):
            a.source_data(archive(dict(self.source,**{'root/link/file':b'x'}),{'root/link':'LICENSE'}))

    def test_archive_expansion_and_member_bounds(self):
        with mock.patch.object(a,'MAX_EXPANDED',1),self.assertRaisesRegex(a.Refused,'EXPANDED_BYTE_LIMIT'):a.tar_data(self.raw)
        with mock.patch.object(a,'MAX_MEMBERS',1),self.assertRaisesRegex(a.Refused,'MEMBER_LIMIT'):a.tar_data(self.raw)

    def test_impossible_archive_file_ancestor_refused(self):
        with self.assertRaisesRegex(a.Refused,'FILE_AS_ARCHIVE_ANCESTOR'):a.tar_data(archive({'root/file':b'x','root/file/child':b'y'}))

    def test_numeric_cargo_requirement_subset(self):
        for version,requirement,expected in [('1.2.3','1',True),('2.0.0','^1.2',False),('0.2.1','^0.2',True),
            ('0.3.0','^0.2.1',False),('0.0.3','^0.0.2',False),('0.0.3','0.0',True),('1.2.9','~1.2',True),
            ('1.3.0','~1.2',False),('1.2.3','=1.2',True),('1.3.0','=1.2',False),('0.61.99','>=0.48, <=0.61',True),
            ('0.62.0','>=0.48, <=0.61',False),('2.0.0','>1',True),('1.99.0','>1',False),('1.2.3','1.*',True),
            ('1.2.3','*',True),('1.2.3','01.2',None),('1.2.3','1 || 2',None),('1.2.3-beta','^1',None)]:
            with self.subTest(version=version,requirement=requirement):self.assertIs(a.matches(version,requirement),expected)

    def test_alias_optional_build_dev_target_declarations_retained(self):
        document={'dependencies':{'renamed':{'package':'alpha','version':'1','optional':True}},'dev-dependencies':{'beta':'0.2'},
            'build-dependencies':{'alpha':'^1'},'target':{'cfg(target_os = "linux")':{'dependencies':{'alpha':'1'}}}}
        rows=a.declarations(document,'root/Cargo.toml',self.source,self.vendor['crates'])
        self.assertEqual(len(rows),4);self.assertTrue(all(row['candidates']for row in rows))
        self.assertEqual(next(row for row in rows if row['alias']=='renamed')['package'],'alpha')
        self.assertTrue(all('NOT_EVALUATED'in row['activation']for row in rows))

    def test_missing_inactive_declaration_is_explicit_hold(self):
        rows=a.declarations({'dev-dependencies':{'absent':'1'}},'root/Cargo.toml',self.source,self.vendor['crates'])
        self.assertIn('NO_SUPPLIED_VENDOR_MATCH_FOR_DECLARATION',rows[0]['holds'])

    def test_path_declaration_binds_exact_supplied_manifest(self):
        source=dict(self.source,**{'root/local/Cargo.toml':b'[package]\nname="local"\nversion="0.1.0"\n'})
        rows=a.declarations({'dependencies':{'local':{'path':'local','version':'0.1'}}},'root/Cargo.toml',source,self.vendor['crates'])
        self.assertEqual(rows[0]['candidates'],['root/local/Cargo.toml'])
        self.assertTrue(a.source_relation(rows[0],('local','0.1.0',''),{('local','0.1.0'):['root/local/Cargo.toml']}))
        source_rows=a.declarations({'dependencies':{'local':{'path':'../../outside'}}},'root/Cargo.toml',source,self.vendor['crates'])
        self.assertIn('PATH_DEPENDENCY_NOT_BOUND_TO_SUPPLIED_MANIFEST',source_rows[0]['holds'])

    def test_git_url_commit_and_branch_bind_lexically_without_provenance(self):
        dep={'git':'https://example.invalid/project','rev':'1'*40,'version':'1'}
        row=a.declarations({'dependencies':{'alpha':dep}},'root/Cargo.toml',self.source,self.vendor['crates'])[0]
        self.assertIn('GIT_COMMIT_TO_VENDOR_TREE_PROVENANCE_NOT_ESTABLISHED',row['holds'])
        origin='git+https://example.invalid/project?rev='+('1'*40)+'#'+('1'*40)
        self.assertIs(a.source_relation(row,('alpha','1.2.3',origin),{}),True)
        self.assertIs(a.source_relation(row,('alpha','1.2.3',origin[:-40]+'2'*40),{}),False)
        dep['rev']='short';self.assertIsNone(a.source_relation(row,('alpha','1.2.3',origin),{}))
        dep.pop('rev');dep['branch']='main'
        self.assertIs(a.source_relation(row,('alpha','1.2.3','git+https://example.invalid/project?branch=main#'+'1'*40),{}),True)

    def test_named_registry_workspace_and_unknown_keys_held(self):
        for dep,hold in [({'version':'1','registry':'private'},'NAMED_REGISTRY_CONFIGURATION_NOT_IMPLEMENTED'),
                         ({'workspace':True},'WORKSPACE_INHERITANCE_NOT_IMPLEMENTED'),
                         ({'version':'1','artifact':'bin'},'UNHANDLED_DEPENDENCY_KEYS')]:
            row=a.declarations({'dependencies':{'alpha':dep}},'root/Cargo.toml',self.source,self.vendor['crates'])[0]
            self.assertIn(hold,row['holds']);self.assertIsNone(a.source_relation(row,('alpha','1.2.3',a.REGISTRY),{}))

    def test_unhandled_dependency_field_types_are_held(self):
        row=a.declarations({'dependencies':{'alpha':{'version':'1','optional':'yes','features':'invalid'}}},'root/Cargo.toml',self.source,self.vendor['crates'])[0]
        self.assertIn('UNHANDLED_DEPENDENCY_FIELD_TYPES',row['holds'])
        self.assertIsNone(a.source_relation(row,('alpha','1.2.3',a.REGISTRY),{}))

    def test_unhandled_version_does_not_falsely_join_lock_edge(self):
        self.source['root/Cargo.toml']=self.source['root/Cargo.toml'].replace(b'"^1.0"',b'"1 || 2"')
        report,_=self.project()
        self.assertIn('UNHANDLED_LOCK_EDGE_BINDING',[row['code']for row in report['holds']])
        self.assertIn('HELD_UNHANDLED_FORMAT',[row['status']for row in report['lock_edges']])

    def test_omitted_locked_vendor_crate_flagged(self):
        files={k:v for k,v in self.files.items()if not k.startswith('vendor/beta-')}
        vendor,parsed,ids=a.vendor_data(archive(files));report,_=self.project(vendor=vendor,parsed=parsed,ids=ids)
        self.assertIn('LOCKED_REGISTRY_PACKAGE_MISSING',[row['code']for row in report['errors']])

    def test_lock_checksum_not_equal_vendor_claim_flagged(self):
        source=dict(self.source);source['root/Cargo.lock']=self.lock.replace(('checksum="'+'a'*64).encode(),('checksum="'+'c'*64).encode())
        components=copy.deepcopy(self.components);components['cargo_lock_sha256']=a.digest(source['root/Cargo.lock'])
        report,_=self.project(source=source,components=components)
        self.assertIn('LOCK_VENDOR_PACKAGE_CHECKSUM_DIFFERS',[row['code']for row in report['errors']])

    def test_wrong_declared_requirement_flags_unbound_lock_edge(self):
        self.source['root/Cargo.toml']=self.source['root/Cargo.toml'].replace(b'"^1.0"',b'"^2.0"')
        report,_=self.project();self.assertIn('LOCK_EDGE_WITHOUT_SUPPORTED_MANIFEST_DECLARATION',[row['code']for row in report['errors']])

    def test_lock_reference_missing_ambiguous_and_unknown_format_refused(self):
        _,entries=a.lock_data(self.lock)
        with self.assertRaisesRegex(a.Refused,'MISSING_OR_AMBIGUOUS'):a.lock_reference('absent',entries)
        entries['alpha','2.0.0',a.REGISTRY]={}
        with self.assertRaisesRegex(a.Refused,'MISSING_OR_AMBIGUOUS'):a.lock_reference('alpha',entries)
        self.assertEqual(a.lock_reference('alpha 1.2.3 ('+a.REGISTRY+')',entries),('alpha','1.2.3',a.REGISTRY))
        with self.assertRaisesRegex(a.Refused,'UNHANDLED_CARGO_LOCK_FORMAT'):a.lock_data(b'version=99\npackage=[]\n')

    def test_declared_license_is_distinct_from_actual_text(self):
        doc={'package':{'license':'MIT'}}
        for body,status in [(b'',False),(b'   ',False),(b'\xff',False),(b'MIT test fixture',True)]:
            row=a.license_material(doc,{'root/LICENSE':body},'root');self.assertIs(row['text_presence'],status)
            self.assertEqual(row['declared_expression'],'MIT');self.assertFalse(row['legal_acceptance'])
        row=a.license_material(doc,{},'root');self.assertFalse(row['text_presence']);self.assertTrue(row['holds'])

    def test_declared_license_file_outside_crate_not_invented(self):
        row=a.license_material({'package':{'license':'MIT','license-file':'../LICENSE'}},{'LICENSE':b'MIT'},'root')
        self.assertIsNone(row['bound_declared_file']);self.assertIn('DECLARED_LICENSE_FILE_NOT_BOUND_INSIDE_CRATE',row['holds'])

    def materials(self,raw=None,components=None):
        return {name:dict(**{a.PACKAGES[name]:archive(self.source)},**{'cargo-vendor-117.tar.xz':raw or self.raw,'COMPONENTS.json':a.encoded(components or self.components)})for name in a.PACKAGES}

    def test_union_report_never_claims_raw_crate_or_legal_authentication(self):
        with mock.patch('subprocess.Popen',side_effect=AssertionError('actor forbidden')),mock.patch('socket.socket',side_effect=AssertionError('network forbidden')):
            report=a.audit_materials(self.materials())
        self.assertEqual(report['errors'],[]);self.assertEqual(len(report['union_locked_vendor_roots']),2)
        self.assertEqual(report['raw_crate_authentication'],'NOT_ESTABLISHED_NO_RAW_CRATE_BYTES')
        for key in ('complete_corresponding_source_accepted','legal_acceptance','code_execution','network','native_build'):self.assertIs(report[key],False)

    def test_extra_valid_crate_not_bound_by_any_lock_flagged(self):
        files=dict(self.files,**crate('unbound','1.0.0','c'*64));raw=archive(files);vendor,_,_=a.vendor_data(raw)
        components=copy.deepcopy(self.components);components['vendor']=dict(**a.desc(raw),crates=3,regular_files=12,expanded_bytes=vendor['expanded_bytes'])
        report=a.audit_materials(self.materials(raw,components))
        self.assertEqual(report['unbound_vendor_roots'],['vendor/unbound-1.0.0'])
        self.assertIn('VENDOR_MATERIAL_NOT_BOUND_BY_ANY_DELIVERED_LOCK',[r['code']for r in report['errors']])

    def test_shared_vendor_archive_mismatch_refused(self):
        materials=self.materials();materials['bankstown']['cargo-vendor-117.tar.xz']+=b'changed'
        with self.assertRaisesRegex(a.Refused,'SHARED_VENDOR_BYTES_DIFFER'):a.audit_materials(materials)

    def test_unknown_manifest_identity_is_explicit_format_refusal(self):
        with self.assertRaisesRegex(a.Refused,'UNHANDLED_PACKAGE_IDENTITY'):a.identity({'package':{'name':'alpha','version':{'workspace':True}}})


if __name__=='__main__':unittest.main(verbosity=2)
