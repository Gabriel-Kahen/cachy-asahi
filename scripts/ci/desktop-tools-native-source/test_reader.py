#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Maintained update and archive-custody DATA controls; no native actors."""
import ast
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
SOURCE=Path(os.environ['DESKTOP_NATIVE_SOURCE']).absolute()
NATIVE=SOURCE/'native'
sys.dont_write_bytecode=True
sys.path.insert(0,str(NATIVE))

def deny(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in {'os.system','os.exec','os.posix_spawn','os.fork'}:
        raise AssertionError('reader DATA controls prohibit actors:'+event)
sys.addaudithook(deny)

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
R=module('desktop_update_reader_tested',NATIVE/'desktop_reader_v1.py')
P=module('desktop_update_projection_tested',NATIVE/'desktop_projection_v1.py')
T=module('desktop_update_tools_tested',NATIVE/'desktop_tools_v1.py')

def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

def make_tar(rows,format=tarfile.USTAR_FORMAT):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w',format=format) as archive:
        for original,body in rows:
            member=copy.copy(original);member.size=0 if body is None else len(body)
            archive.addfile(member,None if body is None else io.BytesIO(body))
    return output.getvalue()

class View:
    def __init__(self,rows):self.rows=rows
    def read(self,name):return self.rows[name]
    def load(self,name):return json.loads(self.read(name))

class UpdateReaderControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract=json.loads((NATIVE/'desktop-contract-v1.json').read_bytes())
        bundle=cls.contract['bundle'];raw=(SOURCE/bundle['path']).read_bytes()
        assert R.pin(raw)=={key:bundle[key] for key in ('bytes','sha256')}
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
            members={member.name:archive.extractfile(member).read() for member in archive}
        cls.members=members
        with tarfile.open(fileobj=io.BytesIO(members['recipe/cachy-asahi-desktop-tools-0.1.0.tar.gz']),mode='r:gz') as archive:
            source={member.name:archive.extractfile(member).read() for member in archive if member.isfile()}
        cls.payload={}
        for name,item in cls.contract['recipe']['payload_files'].items():
            body=source['cachy-asahi-desktop-tools-0.1.0/payload/'+name.removeprefix('usr/')]
            assert R.pin(body)=={key:item[key] for key in ('bytes','sha256')};cls.payload[name]=body
        assert len(cls.payload)==6
    def rows(self,label='update'):
        recipe=self.contract['update_recipe'] if label=='update' else self.contract['recipe'];version=recipe['version']
        metadata={'.PKGINFO':('pkgname = cachy-asahi-desktop-tools\npkgbase = cachy-asahi-desktop-tools\npkgver = '+version+'\narch = any\nlicense = MIT\ndepend = python>=3.11\n').encode(),
                  '.BUILDINFO':('format = 2\npkgname = cachy-asahi-desktop-tools\npkgbase = cachy-asahi-desktop-tools\npkgver = '+version+'\npkgarch = any\n'
                      'pkgbuild_sha256sum = '+recipe['source_files']['PKGBUILD']['sha256']+'\nbuildenv = check\n'+
                      ''.join('installed = '+row+'\n' for row in self.contract['buildinfo_installed'])).encode(),
                  '.MTREE':b'INERT UPDATE PROVENANCE MODEL; no native result\n'}
        result=[]
        ancestors={str(parent) for name in self.payload for parent in Path(name).parents if str(parent)!='.'}
        for name in sorted(ancestors):
            member=tarfile.TarInfo(name);member.type=tarfile.DIRTYPE;member.mode=0o755;result.append((member,None))
        for name,body in sorted({**metadata,**self.payload}.items()):
            member=tarfile.TarInfo(name);member.mode=recipe['payload_files'].get(name,{'mode':0o644})['mode'];result.append((member,body))
        return result
    def row(self,raw,label='update',index=0):
        recipe=self.contract['update_recipe'] if label=='update' else self.contract['recipe'];fixed=Path(self.contract['invocation']['source']).parent
        return dict(step='archive-'+label,log='%03d-archive-%s.log'%(index,label),expected=0,
                    argv=['/usr/bin/zstd','-dc',str(fixed/'build-inputs'/label/recipe['archive'])],log_pin=R.pin(raw))
    def checked(self,raw=None,label='update',index=0):
        raw=make_tar(self.rows(label)) if raw is None else raw;row=self.row(raw,label,index)
        a=P.archive_custody(raw,row,self.contract,index);b=R.desktop_archive_custody(raw,row,self.contract,index,P.PRIVATE_MARKER)
        self.assertEqual(a,b);return a
    def refused(self,raw,label='update'):
        row=self.row(raw,label)
        for function,args in ((P.archive_custody,(raw,row,self.contract,0)),(R.desktop_archive_custody,(raw,row,self.contract,0,P.PRIVATE_MARKER))):
            with self.subTest(parser=function.__name__),self.assertRaises(Exception):function(*args)
    def test_exact_update_source_generation_matches_tools_independently(self):
        expected=T.update_generation(self.contract,self.members)
        self.assertEqual(R.desktop_update_source(self.contract),expected)
        self.assertEqual(expected['changed_sources'],['PKGBUILD']);self.assertEqual(expected['scope'],'TEST_LIFECYCLE_UPDATE_FIXTURE_ONLY')
    def test_second_source_change_refused(self):
        contract=copy.deepcopy(self.contract);contract['update_recipe']['source_files']['export_source.py']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'unchanged original'):R.desktop_update_source(contract)
    def test_update_payload_change_refused(self):
        contract=copy.deepcopy(self.contract);name=next(iter(contract['update_recipe']['payload_files']))
        contract['update_recipe']['payload_files'][name]['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'same six'):R.desktop_update_source(contract)
    def test_fixture_cannot_be_promoted_to_release(self):
        contract=copy.deepcopy(self.contract);contract['update_recipe']['provenance']='RELEASE'
        with self.assertRaisesRegex(ValueError,'TEST lifecycle'):R.desktop_update_source(contract)
    def test_all_three_exact_raw_archive_labels(self):
        for label in ('a','b','update'):
            with self.subTest(label=label):self.assertEqual(self.checked(label=label,index=7)['label'],label)
    def test_old_version_metadata_cannot_qualify_update(self):self.refused(make_tar(self.rows('a')))
    def test_update_wrong_recipe_provenance_refused(self):
        rows=self.rows();rows=[(member,body.replace(self.contract['update_recipe']['source_files']['PKGBUILD']['sha256'].encode(),
              self.contract['recipe']['source_files']['PKGBUILD']['sha256'].encode()) if member.name=='.BUILDINFO' else body) for member,body in rows]
        self.refused(make_tar(rows))
    def test_update_wrong349_dependency_arch_refused(self):
        rows=self.rows();rows=[(member,body.replace(b'installed = python-3.14.8-1-aarch64',b'installed = python-3.14.8-1-any') if member.name=='.BUILDINFO' else body) for member,body in rows]
        self.refused(make_tar(rows))
    def test_update_changed_source_body_refused_after_repin(self):
        name=next(iter(self.payload));self.refused(make_tar([(member,body+b'altered' if member.name==name else body) for member,body in self.rows()]))
    def test_metadata_and_header_private_markers_refused(self):
        self.refused(make_tar([(member,body+b'PRIVATE_KEY' if member.name=='.MTREE' else body) for member,body in self.rows()]))
        rows=self.rows();rows[0][0].uname='PRIVATE_KEY';self.refused(make_tar(rows))
    def test_update_padding_and_trailer_are_not_exempt(self):
        raw=make_tar(self.rows())
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:member=next(member for member in archive if member.isfile() and member.size%512)
        altered=bytearray(raw);altered[member.offset_data+member.size]=1;self.refused(bytes(altered))
        self.refused(raw+b'PRIVATE_KEY'+bytes(512-len(b'PRIVATE_KEY')));self.refused(raw+b'\0')
    def test_symlink_duplicate_extra_hidden_headers_refused(self):
        rows=self.rows();index=next(i for i,(member,body) in enumerate(rows) if member.name in self.payload)
        changed=copy.deepcopy(rows);changed[index][0].type=tarfile.SYMTYPE;changed[index][0].linkname='not-followed';changed[index]=(changed[index][0],None);self.refused(make_tar(changed))
        self.refused(make_tar(rows+[rows[-1]]));extra=tarfile.TarInfo('unknown');extra.mode=0o644;self.refused(make_tar(rows+[(extra,b'INERT')]))
        changed=copy.deepcopy(rows);changed[0][0].pax_headers={'comment':'INERT'};self.refused(make_tar(changed,tarfile.PAX_FORMAT))
    def update_model(self):
        recipe=self.contract['update_recipe'];fixed=Path(self.contract['invocation']['source']).parent;slot=fixed/'build-current'
        rawtar=make_tar(self.rows());row=self.row(rawtar,index=2);row['cwd']='/tmp/model'
        buildraw=b'==> Starting check()\nRan 81 tests in 1.000s\n\nOK\n'
        build=dict(step='build-update',log='001-build-update.log',cwd=str(slot),expected=0,
                   argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(slot),'PKGDEST='+str(slot),'SRCDEST='+str(slot),'BUILDDIR='+str(slot),
                         'SOURCE_DATE_EPOCH=1793145600','PACKAGER=cachy-asahi native TEST builder','/usr/bin/makepkg','--cleanbuild','--nodeps','--nosign','--noconfirm',
                         '--config',str(Path(self.contract['invocation']['source'])/self.contract['makepkg_config']['path'])])
        commands=[dict(step='archive-b',log='000-archive-b.log'),build,row]
        prefix='journey/desktop-alpm-v1/';view=View({prefix+row['log']:rawtar,prefix+build['log']:buildraw})
        archive=R.pin(b'OPAQUE SYNTHETIC UPDATE ARCHIVE; no package build')
        payload={name:dict(mode=item['mode'],**{key:item[key] for key in ('bytes','sha256')}) for name,item in recipe['payload_files'].items()}
        bodies={member.name:body for member,body in self.rows() if member.name in ('.PKGINFO','.BUILDINFO','.MTREE')}
        provenance=dict(status='PASS_TEST_LIFECYCLE_UPDATE_ARCHIVE',fixture='TEST_LIFECYCLE_UPDATE_FIXTURE_ONLY',version='0.1.0-2',archive=archive,
                        pkginfo=R.pin(bodies['.PKGINFO']),buildinfo=R.pin(bodies['.BUILDINFO']),mtree=R.pin(bodies['.MTREE']),payload=payload,
                        pkginfo_text=bodies['.PKGINFO'].decode(),buildinfo_text=bodies['.BUILDINFO'].decode(),mtree_base64=base64.b64encode(bodies['.MTREE']).decode(),
                        source_map_sha256='a'*64,pkgbuild_sha256=recipe['source_files']['PKGBUILD']['sha256'],base_inventory_count=349)
        report=dict(update_fixture=R.desktop_update_source(self.contract),update_provenance=provenance,
                    builds=dict(a=dict(build_directory=dict(identity=dict(device=1,inode=1))),b=dict(build_directory=dict(identity=dict(device=1,inode=2))),
                                update=dict(version='0.1.0-2',fixture='TEST_LIFECYCLE_UPDATE_FIXTURE_ONLY',recipe_sha256=recipe['source_files']['PKGBUILD']['sha256'],
                                            check_invoked=True,check_tests=81,check_policy='POSITIVE_CHECK_NO_NOCHECK',build_step='build-update',archive=dict(filename=recipe['archive'],**archive),
                                            build_directory=dict(logical=str(slot),retained=str(fixed/'build-inputs/update'),initial_files=sorted(recipe['source_files']),identity=dict(device=1,inode=3)))))
        def selected(step):
            matches=[(i,row) for i,row in enumerate(commands) if row['step']==step];self.assertEqual(len(matches),1);return matches[0]
        return view,report,selected
    def test_third_clean_build_and_raw_provenance_model(self):
        view,report,selected=self.update_model();index,archive=R.desktop_update_build(view,'journey/desktop-alpm-v1/',report,self.contract,selected,'a'*64)
        self.assertEqual(index,1);self.assertEqual(archive,report['update_provenance']['archive'])
    def test_update_reused_directory_refused(self):
        view,report,selected=self.update_model();report['builds']['update']['build_directory']['identity']=report['builds']['a']['build_directory']['identity']
        with self.assertRaisesRegex(ValueError,'third fresh'):R.desktop_update_build(view,'journey/desktop-alpm-v1/',report,self.contract,selected,'a'*64)
    def test_update_missing81_or_wrong_raw_provenance_refused(self):
        view,report,selected=self.update_model();view.rows['journey/desktop-alpm-v1/001-build-update.log']=b'no check\n'
        with self.assertRaisesRegex(ValueError,'check81'):R.desktop_update_build(view,'journey/desktop-alpm-v1/',report,self.contract,selected,'a'*64)
        view,report,selected=self.update_model();report['update_provenance']['pkgbuild_sha256']=self.contract['recipe']['source_files']['PKGBUILD']['sha256']
        with self.assertRaisesRegex(ValueError,'raw third-build'):R.desktop_update_build(view,'journey/desktop-alpm-v1/',report,self.contract,selected,'a'*64)
    def test_NULL_actual_refuses_before_capsule_read(self):
        with mock.patch.object(R,'open_capsule',side_effect=AssertionError('capsule read')):
            with self.assertRaisesRegex(ValueError,'NULL/unbound'):R.validate(Path('/absent'),dict(source=None,ref=None,run=None,map_sha256='a'*64))

class ProjectionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):UpdateReaderControls.setUpClass.__func__(cls)
    rows=UpdateReaderControls.rows
    row=UpdateReaderControls.row
    def model(self,raw=None,row=None):
        temporary=tempfile.TemporaryDirectory(prefix='desktop-update-projection-data-');self.addCleanup(temporary.cleanup);base=Path(temporary.name)
        source=base/'source';public=base/'public';source.mkdir(mode=0o700);public.mkdir(mode=0o700);producers={}
        for name in P.PRODUCERS:
            body=(SOURCE/name).read_bytes();path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body);producers[name]=R.pin(body)['sha256']
        binding=dict(source='a'*40,ref='refs/heads/codex/desktop-update-model',run='1',attempt=1)
        binding['token']=hashlib.sha256((binding['source']+':'+binding['ref']+':'+binding['run']).encode()).hexdigest()[:24]
        raw=make_tar(self.rows()) if raw is None else raw;row=self.row(raw) if row is None else row
        def put(name,body):
            path=public/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body);path.chmod(0o600)
        prefix='journey/desktop-alpm-v1/'
        put('receipt.json',encoded(dict(binding=binding,source_map_sha256='b'*64)))
        put(prefix+'result.json',encoded(dict(schema_version=1,operation='desktop-alpm-v1',status='FAIL',source_map_sha256='b'*64,commands=[row])))
        put(prefix+'commands.json',encoded([row]));put(prefix+row['log'],raw)
        return source,public,base/'projected',producers,binding
    def project(self,model):
        source,public,dest,producers,binding=model
        with mock.patch.object(P,'PRODUCERS',producers),contextlib.redirect_stdout(io.StringIO()):return P.project(source,public,dest)
    def read_projection(self,model):
        source,public,dest,producers,binding=model
        class FileView:
            def read(self,name):return (dest/name).read_bytes()
            def load(self,name):return json.loads(self.read(name))
        view=FileView();files=view.load('artifacts.json')['files']
        with mock.patch.object(R,'PRODUCERS',producers),mock.patch.object(R,'desktop_contract',return_value=self.contract):
            return R.retained_public_projection(view,files,binding,'b'*64)
    def test_update_archive_custody_projects_without_native_acceptance(self):
        model=self.model();receipt=self.project(model);key='journey/desktop-alpm-v1/000-archive-update.log'
        self.assertEqual(set(receipt['archive_custody']),{key});self.assertEqual(receipt['archive_custody'][key]['payload_files'],6)
        self.assertEqual(self.read_projection(model)['status'],'VALIDATED_FINITE_DESKTOP_PUBLIC_DATA_PROJECTION_ONLY')
        self.assertEqual(json.loads((model[2]/'journey/desktop-alpm-v1/result.json').read_bytes())['status'],'FAIL')
    def test_ordinary_log_privacy_still_refuses(self):
        raw=b'PRIVATE_KEY';row=dict(step='build-update',log='000-build-update.log',expected=0,argv=['/usr/bin/never-executed'],log_pin=R.pin(raw));model=self.model(raw,row)
        with self.assertRaises(Exception):self.project(model)
        self.assertFalse(model[2].exists())
    def test_forged_custody_receipt_rejected_independently(self):
        model=self.model();self.project(model);path=model[2]/'public-projection.json';value=json.loads(path.read_bytes())
        value['archive_custody']['journey/desktop-alpm-v1/000-archive-update.log']['framing']['zero_trailer_bytes']+=512
        path.write_bytes(encoded(value));manifest=model[2]/'artifacts.json';doc=json.loads(manifest.read_bytes());doc['files']['public-projection.json'].update(R.pin(path.read_bytes()));manifest.write_bytes(encoded(doc))
        with self.assertRaisesRegex(ValueError,'independently parsed'):self.read_projection(model)


class UpdatedProbeControls(unittest.TestCase):
    def model(self):
        fixed=Path('/opt/native-desktop-tools-alpm-v1');rows={};selected={};business={};index=1
        for label,home in [('system',fixed/'user-data/system'),('moved',fixed/'user-data/relocated'),('updated',fixed/'user-data/updated')]:
            if label=='updated':index=12
            cli='/usr/bin/cachy-asahi-desktop-tools' if label!='moved' else str(fixed/'user-data/moved-prefix/usr/bin/cachy-asahi-desktop-tools')
            files={'/inert/'+str(number):dict(bytes=1,sha256='a'*64) for number in range(7)}
            report=dict(schema=1,status='PASS_STAGED_CHECKS',scope='STAGED_DESKTOP_INTEGRATION_ONLY',pins=files,environment={'logical':'fixture'})
            canonical=json.dumps(report,sort_keys=True,separators=(',', ':'),ensure_ascii=True,allow_nan=False).encode()
            capture=dict(schema=1,kind='cachy-asahi-desktop-static-inventory-v1',selected=['tool.desktop'],mime=['text/plain'],environment=R.pin(b'INERT ENV'),files=files,audit_sha256=hashlib.sha256(canonical).hexdigest())
            rawcapture=encoded(capture);inventory=R.pin(rawcapture);report.update(inventory_input=inventory,inventory_binding='EXACT_STATIC_INVENTORY',root=str(home/'staged-root'))
            value=dict(status='PASS_ACTUAL_STATIC_CAPTURE_AUDIT_REFUSAL',cli=cli,synthetic=True,version='0.1.0-2' if label=='updated' else '0.1.0-1',payload_cli_version='0.1.0',
                       selected=['tool.desktop'],mime=['text/plain'],baseline_status='PASS_STAGED_CHECKS',moved_root_status='PASS_STAGED_CHECKS',changed_data_status='REFUSED',
                       changed_data_exit=2,zero_payload_execution=True,release='NOT_ADMITTED',steps={},reports={},environment=capture['environment'],inventory=inventory)
            if label=='updated':value['fixture']='TEST_LIFECYCLE_UPDATE_FIXTURE_ONLY'
            for key in ('capture','audit','moved_root','changed_data'):
                stage=home/('staged-root' if key in ('capture','audit') else 'moved-staged-root');step=label+'-'+key.replace('_','-')
                argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(home),cli,'capture' if key=='capture' else 'audit',
                      '--root',str(stage),'--environment',str(home/'environment.json'),'--select','tool.desktop','--mime','text/plain']
                if key!='capture':argv+=['--inventory',str(home/'inventory.json'),'--inventory-sha256',inventory['sha256']]
                raw=rawcapture if key=='capture' else encoded(dict(report,root=str(stage))) if key!='changed_data' else encoded(dict(status='REFUSED',error='staged inventory differs: fixture changed'))
                name='%03d-%s.log'%(index,step);rows['journey/desktop-alpm-v1/'+name]=raw
                selected[step]=(index,dict(argv=argv,cwd=str(home),expected=2 if key=='changed_data' else 0,log=name))
                value['steps'][key]=step;value['reports'][key]=R.pin(raw);index+=1
            business[label]=value
        def choose(step):return selected[step]
        return View(rows),dict(business=business),choose,selected,fixed
    def test_updated_usr_probe_occurs_after_version_update_and_keeps_payload_version(self):
        view,report,selected,_,fixed=self.model();R.desktop_business(view,'journey/desktop-alpm-v1/',report,selected,fixed,0,11,10,17)
    def test_reusing_baseline_version_or_preupdate_order_refused(self):
        view,report,selected,choices,fixed=self.model();report['business']['updated']['version']='0.1.0-1'
        with self.assertRaisesRegex(ValueError,'static-only'):R.desktop_business(view,'journey/desktop-alpm-v1/',report,selected,fixed,0,11,10,17)
        view,report,selected,choices,fixed=self.model();index,row=choices['updated-capture'];choices['updated-capture']=(7,row)
        with self.assertRaisesRegex(ValueError,'occur in order'):R.desktop_business(view,'journey/desktop-alpm-v1/',report,selected,fixed,0,11,10,17)


if __name__=='__main__':unittest.main(verbosity=2)
