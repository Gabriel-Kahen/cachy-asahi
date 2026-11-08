#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic v2 reader helper controls; never open an actual capsule or reader CLI."""
import argparse
import ast
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile
import types
import unittest
import tarfile

HERE = Path(__file__).resolve().parent


def need(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def functions(path, names, **extra):
    tree = ast.parse(path.read_bytes())
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    need({node.name for node in selected} == set(names), 'all named local helper definitions')
    env = dict(Path=Path, re=re, json=json, hashlib=hashlib, need=need, pin=pin, __file__=str(path))
    env.update(extra)
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), 'exec'), env)
    return env


def listed(fixture, info, mirror):
    return dict(schema_version=1, purpose='release-source-mirror-catalog',
        status='VERIFIED_OFFLINE_SOURCE_MIRROR_CATALOG', mirror_sha256=mirror,
        release_sha256=fixture['release_sha256'], release_id='source-tools-two-package-'+fixture['label'],
        head_release_sha256=info['fixtures'][-1]['release_sha256'],
        retained_releases=[dict(release_id='source-tools-two-package-'+row['label'],
                               release_sha256=row['release_sha256']) for row in info['fixtures']],
        packages=[dict(package=row['name'], **{key:row[key] for key in
            ('version','arch','package_sha256','recipe_sha256','srcinfo_sha256')},
            source_profile='REVIEWED_ORIGINAL_RECIPE_PROFILE') for row in fixture['packages']],
        synthetic=True, legal_acceptance=False, corresponding_source_completeness='NOT_ASSERTED',
        native_build_validation='NOT_PERFORMED', hardware_validation='NOT_RUN', release_acceptance='NOT_ADMITTED')


def business_fixture(info, archive_pin):
    """Entire local report/log model is synthetic, not captured native evidence."""
    fixed = Path('/opt/native-source-tools-alpm-v2')
    map_name = 'usr/share/doc/cachy-asahi-source-tools/payload-map.json'
    payload = {map_name: pin(b'synthetic payload map'), 'usr/bin/cachy-asahi-source-tools': pin(b'synthetic launcher')}
    contract = dict(recipe=dict(payload_files=payload, source_files={'fixtures.tar.gz':archive_pin}))
    report = dict(business={}); logs={}; selected={}; counter=10
    prefix='journey/source-tools-alpm-v2/'
    old,current=info['fixtures']; retained=sorted([old['release_sha256'],current['release_sha256']]); mirror_sha='2'*64
    for label, home in (('system',fixed/'user-data/system'),('moved',fixed/'user-data/relocated')):
        work=home/'workflow'; fixtures=home/'fixtures'; mirror=work/'history/mirror.tar'
        cli='/usr/bin/cachy-asahi-source-tools' if label=='system' else str(fixed/'user-data/moved-prefix/usr/bin/cachy-asahi-source-tools')
        records=[]; contexts=[]; reports={}; steps={}; catalogs={}
        def add(key,args,value,expected=0):
            nonlocal counter
            counter+=1; raw=encoded(value); step=label+'-'+key; leaf='%03d-synthetic.log'%counter
            argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(work),
                  'PATH=/usr/bin:/bin','PYTHONDONTWRITEBYTECODE=1',cli,*map(str,args)]
            logs[prefix+leaf]=raw
            selected[step]=(counter,dict(step=step,argv=argv,cwd=str(work),expected=expected,log=leaf,log_pin=pin(raw)))
            records.append(dict(step=key,argv=argv,expected=expected,stdout=pin(raw)));reports[key]=pin(raw);steps[key]=step
            return value
        first=dict(status='EXPORTED_SOURCE_MIRROR',packages=2,release_sha256=old['release_sha256'],mirror_sha256='1'*64,bytes=1000)
        for key,dest in (('export','first'),('repeat','repeat')):
            add(key,['mirror-export','--release-dir',fixtures/old['label'],'--release-sha256',old['release_sha256'],'--output',work/dest],first)
        successor=dict(status='UPDATED_SOURCE_MIRROR',packages=2,retained_releases=retained,stats={'pruned_objects':0},mirror_sha256=mirror_sha,bytes=1200)
        add('successor',['mirror-successor','--previous-bundle',work/'first/mirror.tar','--previous-sha256','1'*64,
            '--previous-release-sha256',old['release_sha256'],'--release-dir',fixtures/current['label'],
            '--release-sha256',current['release_sha256'],'--output',work/'history'],successor)
        def context(fixture,index,package,catalog=None):
            stem=fixture['label']; key=('catalog-' if catalog is not None else '')+stem+'-'+str(index)
            dest=work/(('catalog-' if catalog is not None else '')+stem+'-'+package['name'])
            identity=dict(name=package['name'],version=package['version'],arch=package['arch'],sha256=package['package_sha256'])
            selector=hashlib.sha256((label+key).encode()).hexdigest()
            value=dict(status='MATERIALIZED_MIRROR_BUILDER_CONTEXT',package=identity,mirror_sha256=mirror_sha,
                release_sha256=fixture['release_sha256'],selection_sha256=selector,native_build='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
            add(key+'-context',['build-context','--bundle',mirror,'--mirror-sha256',mirror_sha,'--release-sha256',fixture['release_sha256'],
                '--package',package['name'],'--version',package['version'],'--arch',package['arch'],'--package-sha256',package['package_sha256'],
                '--recipe-sha256',package['recipe_sha256'],'--srcinfo-sha256',package['srcinfo_sha256'],'--output',dest],value)
            checked=dict(status='VERIFIED_MIRROR_BUILDER_CONTEXT',package=identity,selection_sha256=selector,
                         native_build='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
            add(key+'-verify-context',['verify-context','--context',dest.with_name(dest.name+'-moved'),'--selection-sha256',selector],checked)
            sources=package['sources']; row=dict(label=stem,package=package['name'],source_files=len(sources),
                source_map=pin(encoded(sources)),selection_sha256=selector,license_sha256=sources['LICENSE'],notice_sha256=sources['NOTICE'],actual_selectors='ALL_NULL')
            if catalog is not None:row.update(origin='catalog',catalog_step='catalog-'+stem+'-list',input_pins=catalog)
            contexts.append(row)
        for fixture in (old,current):
            stem=fixture['label']; value=dict(status='VERIFIED_OFFLINE_SOURCE_MIRROR_HISTORY',release_sha256=fixture['release_sha256'],
                retained_releases=retained,mirror_sha256=mirror_sha)
            add(stem+'-verify',['mirror-verify','--bundle',mirror,'--sha256',mirror_sha,'--release-sha256',fixture['release_sha256']],value)
            for index,package in enumerate(fixture['packages']):context(fixture,index,package)
        add('tampered',['mirror-verify','--bundle',work/'tampered.tar','--sha256',mirror_sha,'--release-sha256',current['release_sha256']],
            dict(status='REFUSED',reason='mirror checksum/bound mismatch'),1)
        add('incomplete',['mirror-verify','--bundle',work/'incomplete.tar','--sha256','3'*64,'--release-sha256',current['release_sha256']],dict(status='REFUSED',reason='history object set mismatch'),1)
        add('incomplete-successor',['mirror-successor','--previous-bundle',work/'incomplete.tar','--previous-sha256','3'*64,
            '--previous-release-sha256',current['release_sha256'],'--release-dir',fixtures/current['label'],
            '--release-sha256',current['release_sha256'],'--output',work/'must-not-exist'],dict(status='REFUSED',reason='history object set mismatch'),1)
        add('incomplete-release',['mirror-export','--release-dir',work/'incomplete-release','--release-sha256',current['release_sha256'],'--output',work/'must-not-exist'],
            dict(status='REFUSED',reason="No such file or directory: 'cachy-asahi-maintenance-source.tar'"),1)
        for fixture in (old,current):
            key='catalog-'+fixture['label']+'-list'; value=listed(fixture,info,mirror_sha)
            add(key,['mirror-list','--bundle',mirror,'--sha256',mirror_sha,'--release-sha256',fixture['release_sha256']],value)
            catalogs[fixture['label']]=dict(step=key,report=value,stdout=reports[key])
            for index,(package,listed_package) in enumerate(zip(fixture['packages'],value['packages'])):context(fixture,index,package,listed_package)
        refusal=dict(status='REFUSED',reason='mirror checksum/bound mismatch')
        add('catalog-wrong-pin',['mirror-list','--bundle',mirror,'--sha256','0'*64,'--release-sha256',current['release_sha256']],refusal,1)
        report['business'][label]=dict(status='PASS_SOURCE_TOOLS_FINITE_INSTALLED_PROBE',version='0.2.0-1',scope=label,label=label,cli=cli,
            fixture_root=str(fixtures),work_root=str(work),controls=28,packages_per_release=2,retained_release_count=2,exact_contexts=8,
            original_controls=17,catalog_controls=11,catalog_contexts=4,no_pruning=True,actual_selectors='ALL_NULL',
            retained_code_execution='FORBIDDEN',source_execution='FORBIDDEN',native_build='NOT_ESTABLISHED_BY_PROBE',
            alpm_installation='NOT_ESTABLISHED_BY_PROBE',hardware='NOT_RUN',release='NOT_ADMITTED',fixture_info=info,
            fixture=pin(encoded(info)),fixture_data_sha256=pin(encoded(info))['sha256'],source_fixture=archive_pin,retained_releases=retained,
            installed=dict(files=18,payload_map=payload[map_name],launcher=payload['usr/bin/cachy-asahi-source-tools']),
            steps=steps,reports=reports,commands=records,mirror_bytes=1200,mirror_sha256=mirror_sha,mirror=dict(bytes=1200,sha256=mirror_sha),
            contexts=contexts,catalogs=catalogs,catalog_refusal=dict(step='catalog-wrong-pin',report=refusal,stdout=reports['catalog-wrong-pin']))
    view=types.SimpleNamespace(read=lambda name:logs[name])
    return report,view,selected,contract,fixed,counter+1


class ReaderControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw=FIXTURES.read_bytes()
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
            cls.info=json.loads(archive.extractfile('fixtures/fixtures.json').read())
        cls.archive_pin=pin(raw)
        cls.env=functions(READER,('source_tools_catalog','source_tools_business','source_tools_check_output','producer_pins','validate'),
            PRODUCER_NAMES=frozenset('native/'+n for n in ('source_tools_alpm_v2.py','source_tools_tools_v2.py',
              'source_tools_guest_v2.py','source_tools_probe_v2.py','source-tools-contract-v2.json','source-tools-makepkg-v2.conf',
              'source-tools-sources-v2.tar','source_tools_current_check_v2.py','source_tools_current_package_v2.py')))

    def test_synthetic_all28_logs_and_eight_contexts_match_both_locations(self):
        report,view,selected,contract,fixed,remove=business_fixture(self.info,self.archive_pin)
        self.env['source_tools_business'](view,'journey/source-tools-alpm-v2/',report,selected.__getitem__,fixed,10,remove,contract)

    def test_legacy17_report_cannot_qualify_current_route(self):
        report,view,selected,contract,fixed,remove=business_fixture(self.info,self.archive_pin)
        report['business']['system']['controls']=17
        with self.assertRaises(ValueError):self.env['source_tools_business'](view,'journey/source-tools-alpm-v2/',report,selected.__getitem__,fixed,10,remove,contract)

    def test_catalog_report_pin_or_context_pin_substitution_refuses(self):
        for field in ('report','context','argv'):
            report,view,selected,contract,fixed,remove=business_fixture(self.info,self.archive_pin)
            value=report['business']['system']
            if field=='report':value['catalogs']['legacy']['stdout']=pin(b'not actual')
            elif field=='context':value['contexts'][4]['input_pins']['package_sha256']='0'*64
            else:selected['system-catalog-legacy-0-context'][1]['argv'][16]='changed-version'
            with self.subTest(field=field),self.assertRaises(ValueError):
                self.env['source_tools_business'](view,'journey/source-tools-alpm-v2/',report,selected.__getitem__,fixed,10,remove,contract)

    def test_catalog_wrong_pin_must_be_actual_refusal(self):
        report,view,selected,contract,fixed,remove=business_fixture(self.info,self.archive_pin)
        report['business']['moved']['catalog_refusal']['report']['reason']='permission denied'
        with self.assertRaises(ValueError):self.env['source_tools_business'](view,'journey/source-tools-alpm-v2/',report,selected.__getitem__,fixed,10,remove,contract)

    def test_exact_catalog_identity_and_all_evidence_boundaries(self):
        fixture=self.info['fixtures'][0]; value=listed(fixture,self.info,'2'*64)
        self.assertEqual(len(self.env['source_tools_catalog'](value,fixture,self.info,'2'*64)),2)
        for key,bad in (('schema_version',True),('native_build_validation','PASS'),('synthetic',False),
                        ('legal_acceptance',True),('release_sha256','0'*64),('release_acceptance','ADMITTED')):
            changed=copy.deepcopy(value);changed[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):self.env['source_tools_catalog'](changed,fixture,self.info,'2'*64)
        changed=copy.deepcopy(value);changed['packages'][0]['srcinfo_sha256']='0'*64
        with self.assertRaises(ValueError):self.env['source_tools_catalog'](changed,fixture,self.info,'2'*64)

    def test_null_binding_refuses_before_capsule_open(self):
        self.env['open_capsule']=lambda _path:(_ for _ in ()).throw(AssertionError('capsule touched'))
        self.env['bind_local_source']=lambda _pin:(_ for _ in ()).throw(AssertionError('local source touched'))
        with self.assertRaises(ValueError):self.env['validate']('/never-opened',dict(source=None,ref=None,run=None,map_sha256=None))

    def test_valid_selectors_bind_source_before_capsule_ingress(self):
        events=[]
        def refused(_pin):events.append('local-source');raise ValueError('wrong trusted map')
        self.env['bind_local_source']=refused
        self.env['open_capsule']=lambda _path:events.append('capsule')
        with self.assertRaises(ValueError):self.env['validate']('/never-opened',dict(source='1'*40,ref='refs/heads/codex/synthetic',run='1',map_sha256='2'*64))
        self.assertEqual(events,['local-source'])

    def binding_fixture(self,temporary):
        source=Path(temporary);native=source/'native';native.mkdir();producer_rows={}
        for name in self.env['PRODUCER_NAMES']|{'native/source_tools_reader_v2.py','native/source_tools_projection_v2.py'}:
            path=source/name;path.write_bytes(('SYNTHETIC_LOCAL_DATA '+name).encode());path.chmod(0o644)
            if name in self.env['PRODUCER_NAMES']:producer_rows[name]=dict(mode=0o644,**pin(path.read_bytes()))
        mapping=native/'source-tools-producers-v2.json'
        mapping.write_bytes(encoded(dict(schema=1,purpose='source-tools-current-producer-pins',files=producer_rows)));mapping.chmod(0o644)
        rows={name:dict(mode=0o644,**pin((source/name).read_bytes()))for name in self.env['PRODUCER_NAMES']|{'native/source_tools_reader_v2.py','native/source_tools_projection_v2.py','native/source-tools-producers-v2.json'}}
        for index in range(211-len(rows)):rows['retained/synthetic-%03d'%index]=dict(bytes=1,sha256='1'*64,mode=0o644)
        manifest=dict(schema=1,actual=dict(source=None,ref=None,run=None),source_tools_operation='source-tools-alpm-v2',files=rows)
        map_file=native/'source-map.json';map_file.write_bytes(encoded(manifest));map_file.chmod(0o644)
        reader=functions(READER,('producer_pins','bind_local_source'),PRODUCER_NAMES=self.env['PRODUCER_NAMES'],
                         OPERATION='source-tools-alpm-v2',read=lambda path:path.read_bytes())
        reader['__file__']=str(native/'source_tools_reader_v2.py')
        projection=functions(PROJECTION,('producer_pins','bind_local_source'),PRODUCER_NAMES=self.env['PRODUCER_NAMES'],
            C=types.SimpleNamespace(_load=json.loads,need=need,pin=pin),
            _read=lambda source,name:((source/name).read_bytes(),(source/name).stat().st_mode&0o777))
        projection['__file__']=str(native/'source_tools_projection_v2.py')
        return source,producer_rows,manifest,pin(map_file.read_bytes())['sha256'],reader,projection

    def test_trusted_source_map_binds_reader_projection_pinfile_and_nine_bodies(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-local-source-binding-')as temporary:
            source,producer_rows,manifest,checksum,reader,projection=self.binding_fixture(temporary)
            expected={name:row['sha256']for name,row in producer_rows.items()}
            self.assertEqual(reader['bind_local_source'](checksum),expected)
            self.assertEqual(projection['bind_local_source'](source,checksum),expected)
            for call in (lambda:reader['bind_local_source']('0'*64),lambda:projection['bind_local_source'](source,'0'*64)):
                with self.assertRaises(ValueError):call()

    def test_coordinated_producer_and_pinfile_tamper_cannot_reauthorize_itself(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-local-source-binding-')as temporary:
            source,producer_rows,manifest,checksum,reader,projection=self.binding_fixture(temporary)
            name=sorted(producer_rows)[0];path=source/name;path.write_bytes(b'COORDINATED_SYNTHETIC_TAMPER')
            producer_rows[name]=dict(mode=0o644,**pin(path.read_bytes()))
            (source/'native/source-tools-producers-v2.json').write_bytes(encoded(dict(schema=1,purpose='source-tools-current-producer-pins',files=producer_rows)))
            # The old utility is intentionally usable in isolation; the caller's
            # trusted Source map must now reject the mutually agreeing rewrite.
            self.assertEqual(reader['producer_pins']()[name],producer_rows[name]['sha256'])
            with self.assertRaises(ValueError):reader['bind_local_source'](checksum)
            with self.assertRaises(ValueError):projection['bind_local_source'](source,checksum)

    def test_trusted_source_frame_and_reader_body_modes_cannot_be_substituted(self):
        for field in ('operation','rows','reader','projection-mode'):
            with self.subTest(field=field),tempfile.TemporaryDirectory(prefix='synthetic-local-source-binding-')as temporary:
                source,producer_rows,manifest,checksum,reader,projection=self.binding_fixture(temporary)
                if field=='operation':manifest['source_tools_operation']='source-tools-alpm-v1'
                elif field=='rows':manifest['files'].pop(next(name for name in manifest['files']if name.startswith('retained/')))
                elif field=='reader':(source/'native/source_tools_reader_v2.py').write_bytes(b'changed reader')
                else:(source/'native/source_tools_projection_v2.py').chmod(0o600)
                if field in ('operation','rows'):
                    raw=encoded(manifest);(source/'native/source-map.json').write_bytes(raw);checksum=pin(raw)['sha256']
                with self.assertRaises(ValueError):reader['bind_local_source'](checksum)
                with self.assertRaises(ValueError):projection['bind_local_source'](source,checksum)

    def test_current_check_bridge_preserves_full_bound_five_object_result(self):
        contract=dict(checks={'synthetic_count_field':9},recipe=dict(source_files={'synthetic-current-file':{'sha256':'1'*64}}))
        raw=b'SYNTHETIC five check objects';bound=dict(status='BOUND_CURRENT_CHECK_OUTPUT_DATA',check_rows=5,native_acceptance='NOT_GRANTED')
        called=[]
        def check(observed,chosen):
            called.append((observed,chosen));return bound
        env=functions(READER,('source_tools_check_output',),current_module=lambda name:types.SimpleNamespace(check_result=check))
        self.assertIs(env['source_tools_check_output'](raw,contract),bound)
        self.assertEqual(called,[(raw,dict(checks=contract['checks'],recipe=dict(files=contract['recipe']['source_files'])))])

    def test_current_check_bridge_cannot_credit_legacy_or_malformed_output(self):
        def refused(_raw,_chosen):raise ValueError('legacy three-object report')
        env=functions(READER,('source_tools_check_output',),current_module=lambda name:types.SimpleNamespace(check_result=refused))
        self.assertIsNone(env['source_tools_check_output'](b'SYNTHETIC old report',dict(checks={},recipe=dict(source_files={}))));self.assertIsNone(env['source_tools_check_output'](b'incomplete',{}))

    def test_typed_current_producer_map_joins_every_local_body_and_mode(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-reader-source-pins-') as temporary:
            source=Path(temporary);native=source/'native';native.mkdir();rows={}
            for name in self.env['PRODUCER_NAMES']:
                path=source/name;path.write_bytes(('SYNTHETIC_NOT_NATIVE '+name).encode());path.chmod(0o644);rows[name]=dict(mode=0o644,**pin(path.read_bytes()))
            mapping=native/'source-tools-producers-v2.json'
            def write():mapping.write_bytes(encoded(dict(schema=1,purpose='source-tools-current-producer-pins',files=rows)))
            write();env=functions(READER,('producer_pins',),PRODUCER_NAMES=self.env['PRODUCER_NAMES'],read=lambda path:path.read_bytes())
            env['__file__']=str(native/'source_tools_reader_v2.py')
            self.assertEqual(env['producer_pins'](),{n:r['sha256']for n,r in rows.items()})
            projection=functions(PROJECTION,('producer_pins',),PRODUCER_NAMES=self.env['PRODUCER_NAMES'],
                C=types.SimpleNamespace(_load=json.loads,need=need,pin=pin),
                _read=lambda source,name:((source/name).read_bytes(),(source/name).stat().st_mode&0o777))
            self.assertEqual(projection['producer_pins'](source),env['producer_pins']())
            first=source/sorted(rows)[0];first.chmod(0o600)
            with self.assertRaises(ValueError):env['producer_pins']()
            first.chmod(0o644);first.write_bytes(b'changed')
            with self.assertRaises(ValueError):env['producer_pins']()

    def test_projection_and_reader_share_exactnine_producer_names(self):
        def values(path):
            node=next(n for n in ast.parse(path.read_bytes()).body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='PRODUCER_NAMES')
            return eval(compile(ast.Expression(body=node.value),str(path),'eval'),{})
        self.assertEqual(values(READER),values(PROJECTION));self.assertEqual(len(values(READER)),9)

    def test_sensitive_failure_transport_cleanup_functions_remain_ast_identical(self):
        pins=json.loads((HERE/'frozen-v1-sensitive-functions.json').read_bytes())['functions']
        class Normalize(ast.NodeTransformer):
            def visit_Expr(self,node):
                if isinstance(node.value,ast.Call)and isinstance(node.value.func,ast.Name)and node.value.func.id=='bind_local_source':return None
                return self.generic_visit(node)
            def visit_Call(self,node):
                self.generic_visit(node)
                return ast.copy_location(ast.Name(id='PRODUCERS',ctx=ast.Load()),node) if isinstance(node.func,ast.Name)and node.func.id=='producer_pins'and not node.args and not node.keywords else node
        for old,rows in pins.items():
            path=READER if 'reader' in old else PROJECTION
            text=path.read_text().replace('source-tools-alpm-v2','source-tools-alpm-v1').replace('source-tools-contract-v2.json','source-tools-contract-v1.json').replace('_v2','_v1').replace('0.2.0-1','0.1.0-1')
            defs={node.name:Normalize().visit(node)for node in ast.parse(text).body if isinstance(node,ast.FunctionDef)}
            for name,digest in rows.items():
                with self.subTest(function=name):self.assertEqual(hashlib.sha256(ast.dump(defs[name],include_attributes=False).encode()).hexdigest(),digest)

    def test_projection_caps_and_private_scope_preserved(self):
        tree=ast.parse(PROJECTION.read_bytes())
        assignments={n.targets[0].id:n.value for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)}
        self.assertEqual(ast.literal_eval(assignments['REPORTS']),{'source-tools-alpm-v2':{'result.json','commands.json'}})
        self.assertEqual(ast.literal_eval(assignments['PRIVATE']),{'source-tools-alpm-v2':{'home'}})
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='_project')
        constants=[n.value for n in ast.walk(function)if isinstance(n,ast.Constant)and type(n.value)is int]
        self.assertIn(2998,constants);self.assertIn(1000,constants)
        text=ast.unparse(function);self.assertIn('C.LEAF_CAP',text);self.assertIn('C.CAP',text)
        binding=next(n for n in ast.walk(function)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='bind_local_source')
        writes=[n for n in ast.walk(function)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name)and n.func.value.id=='os'and n.func.attr in ('mkdir','open')]
        self.assertTrue(writes and all(binding.lineno<n.lineno for n in writes))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reader',type=Path,default=HERE/'source_tools_reader_v2.py')
    parser.add_argument('--projection',type=Path,default=HERE/'source_tools_projection_v2.py')
    parser.add_argument('--fixtures-archive',type=Path,required=True)
    args=parser.parse_args();READER=args.reader.resolve();PROJECTION=args.projection.resolve();FIXTURES=args.fixtures_archive.resolve()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReaderControls))
    print(json.dumps(dict(status='PASS'if result.wasSuccessful()else'FAIL',tests=result.testsRun,failures=len(result.failures),
        errors=len(result.errors),skipped=len(result.skipped),evidence='SYNTHETIC_READER_HELPER_DATA_NOT_ACTUAL_READER',
        actual_capsules_opened=0,reader_CLI_runs=0,native='NOT_RUN',Source_constructor=0),sort_keys=True))
    raise SystemExit(not result.wasSuccessful()or bool(result.skipped))
