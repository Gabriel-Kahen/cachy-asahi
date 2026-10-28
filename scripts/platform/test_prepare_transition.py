# SPDX-License-Identifier: MIT
"""Actual libalpm inert metadata controls; no synthetic signature is authenticated."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec);spec.loader.exec_module(loaded)
    return loaded

m = module('private_prepare_test', HERE/'prepare_transition.py')
f = module('transition_fixture_producer', HERE/'test_platform_transition.py')


def metadata(name, version='1-1', depends=(), conflicts=(), provides=()):
    return {'NAME':[name], 'VERSION':[version], 'ARCH':['aarch64'], 'LICENSE':['MIT'],
            'DEPENDS':list(depends), 'CONFLICTS':list(conflicts), 'PROVIDES':list(provides),
            'FILENAME':[f'{name}-{version}-aarch64.pkg.tar.xz'], 'CSIZE':['1'], 'ISIZE':['1']}


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name);self.root.chmod(0o700)
        self.before = {'mesa':metadata('mesa'), 'consumer':metadata('consumer',depends=['mesa>=1'])}
        self.after = copy.deepcopy(self.before);self.after['mesa']['VERSION']=['2-1']
        self.after['mesa']['FILENAME']=['mesa-2-1-aarch64.pkg.tar.xz']

    def prepare(self, roots=('mesa',)):
        with tempfile.TemporaryDirectory(prefix='private-platform-prepare-',dir=self.root) as scratch:
            report = m.worker(Path(scratch),self.before,self.after,list(roots))
            self.assertEqual(list((Path(scratch)/'root').iterdir()),[])
            return report

    def test_real_coordinated_upgrade_without_commit(self):
        report=self.prepare()
        self.assertEqual(report['status'],'PASS-private-metadata-prepare')
        self.assertEqual([(r['name'],r['version']) for r in report['add']],[('mesa','2-1')])
        self.assertTrue(report['final_candidate_exact'])
        for name in ('commit_called','hooks_run','host_database_used','package_authentication_performed','production_admitted','hardware_accepted'):
            self.assertFalse(report[name])

    def test_real_downgrade(self):
        self.after['mesa']['VERSION']=['1-0']
        self.after['mesa']['FILENAME']=['mesa-1-0-aarch64.pkg.tar.xz']
        self.assertEqual(self.prepare()['status'],'PASS-private-metadata-prepare')

    def test_real_same_version_reinstall(self):
        self.after=copy.deepcopy(self.before);self.after['mesa']['PROVIDES']=['test-capability']
        report=self.prepare()
        self.assertEqual(report['status'],'PASS-private-metadata-prepare')
        self.assertEqual(report['add'][0]['version'],'1-1')
        self.assertFalse(report['flags'] & (1<<13))

    def test_real_removal(self):
        self.before['unused']=metadata('unused');self.after.pop('mesa');self.after['mesa']=self.before['mesa']
        report=self.prepare(('unused',))
        self.assertEqual(report['status'],'PASS-private-metadata-prepare')
        self.assertEqual([r['name'] for r in report['remove']],['unused'])

    def test_real_dependency_failure_is_retained(self):
        self.after['consumer']['DEPENDS']=['mesa>=3']
        report=self.prepare(('mesa','consumer'))
        self.assertEqual(report['status'],'FAIL-private-metadata-prepare')
        self.assertEqual(report['prepare_errno'],45)
        self.assertTrue(any(r['kind']=='unsatisfied-dependency' for r in report['errors']))

    def test_real_package_conflict_failure_is_retained(self):
        self.after['consumer']['CONFLICTS']=['mesa']
        report=self.prepare(('mesa','consumer'))
        self.assertEqual(report['status'],'FAIL-private-metadata-prepare')
        self.assertNotEqual(report['prepare_exit'],0)
        self.assertTrue(report['errors'] or report['questions'])

    def test_final_inventory_drift_fails(self):
        self.after['new-provider']=metadata('new-provider')
        report=self.prepare()
        self.assertEqual(report['status'],'FAIL-private-metadata-prepare')
        self.assertIn('new-provider',report['final_metadata_mismatches'])

    def test_unapproved_dependency_selection_fails_exact_root_check(self):
        self.after['new-provider']=metadata('new-provider');self.after['mesa']['DEPENDS']=['new-provider']
        report=self.prepare()
        self.assertEqual(report['status'],'FAIL-private-metadata-prepare')
        self.assertIn('new-provider',[r['name'] for r in report['add']])
        self.assertFalse(report['final_candidate_exact'])

    def test_nonempty_workspace_refused(self):
        with tempfile.TemporaryDirectory(prefix='private-platform-prepare-',dir=self.root) as scratch:
            path=Path(scratch);(path/'sentinel').write_text('owned sentinel')
            with self.assertRaisesRegex(ValueError,'fresh empty'):
                m.prepare_metadata(path,self.before,self.after,['mesa'])
            self.assertEqual((path/'sentinel').read_text(),'owned sentinel')

    def test_prepare_timeout_controlled(self):
        with patch.object(m.subprocess,'run',side_effect=subprocess.TimeoutExpired('fixture',0.01)):
            with self.assertRaisesRegex(ValueError,'prepare deadline'):
                m.worker(self.root,{}, {}, [])

    def test_unverified_certificate_never_reaches_ALPM(self):
        fixture=f.TransitionTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        contract=fixture.contract();ref=fixture.save('transition.json',contract)
        report=m.p.run(contract);report['contract_sha256']=ref['sha256']
        report_ref=fixture.save('plan.json',report)
        fake_cert=fixture.save('unverified.gpg',b'not a pinned public certificate')
        pins=fixture.save('runtime-sources.json',{'schema_version':1,'kind':'private-platform-prepare-source-closure',
              'files':{name:m.auth.hash_file(m.p.ROOT/name) for name in m.SOURCE_FILES}})
        request={'schema_version':1,'transition_contract':ref,'transition_report':report_ref,'certificates':{'alarm':fake_cert},'runtime_sources':pins}
        output=fixture.root/'must-not-exist.json'
        with patch.object(m,'worker',side_effect=AssertionError('ALPM must not be reached')):
            with self.assertRaisesRegex(ValueError,'certificate pin'):
                m.run(request,output)
        self.assertFalse(output.exists())
        self.assertEqual(list(fixture.root.glob('private-platform-*')),[])

    def test_relocated_archive_keeps_catalogue_filename(self):
        row=metadata('mesa')
        result=m.catalogue_record('mesa',row,{'path':'/private/opaque-cache-hash','size':1,'sha256':'a'*64})
        self.assertEqual(result['FILENAME'],row['FILENAME'])

    def test_incomplete_source_closure_refused(self):
        path=self.root/'sources.json';data=json.dumps({'schema_version':1,'kind':'private-platform-prepare-source-closure','files':{}}).encode()
        path.write_bytes(data)
        import hashlib
        with self.assertRaisesRegex(ValueError,'whole private preparation source closure'):
            m.runtime_sources({'path':str(path),'size':len(data),'sha256':hashlib.sha256(data).hexdigest()})

    def test_old_bytecode_cannot_replace_bound_source(self):
        import importlib.util, os, py_compile
        stage=self.root/'source-copy'
        for name in m.SOURCE_FILES:
            path=stage/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((m.p.ROOT/name).read_bytes())
        target=stage/'scripts/platform/tuple_audit.py'
        poison=self.root/'poison.py'
        source=b"raise RuntimeError('stale fixture bytecode')\n"
        poison.write_bytes(source+b'#'*(target.stat().st_size-len(source)))
        info=target.stat();os.utime(poison,(info.st_atime,info.st_mtime))
        cache=target.parent/'__pycache__'/('tuple_audit.'+sys.implementation.cache_tag+'.pyc')
        cache.parent.mkdir()
        py_compile.compile(str(poison),cfile=str(cache),doraise=True,invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        env=dict(os.environ);env.pop('PYTHONPYCACHEPREFIX',None)
        original=subprocess.run([sys.executable,'-B',str(stage/'scripts/platform/platform_transition.py'),'--help'],
                                capture_output=True,text=True,timeout=10,env=env)
        self.assertNotEqual(original.returncode,0)
        self.assertIn('stale fixture bytecode',original.stderr)
        fixed=subprocess.run([sys.executable,'-B',str(stage/'scripts/platform/prepare_transition.py'),'--help'],
                             capture_output=True,text=True,timeout=10,env=env)
        self.assertEqual(fixed.returncode,0,fixed.stderr)

    def test_cli_malformed_input_creates_no_report(self):
        path=self.root/'invalid.json';path.write_text('{"schema_version":true}')
        import hashlib
        output=self.root/'output.json'
        result=subprocess.run([sys.executable,'-B',str(HERE/'prepare_transition.py'),'--contract',str(path),
                               '--contract-sha256',hashlib.sha256(path.read_bytes()).hexdigest(),'--output',str(output)],
                              capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,1)
        self.assertIn('refused',result.stderr);self.assertFalse(output.exists())


if __name__=='__main__':
    unittest.main()
