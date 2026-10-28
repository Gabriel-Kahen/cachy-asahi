"""Inert candidate binding, orchestration and scoped cleanup; no Docker or installs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = next(p for p in Path(__file__).resolve().parents if (p/'scripts/checks/package_checks.py').is_file())
sys.path[:0] = [str(REPO/'scripts/ci'),str(REPO/'scripts/checks')]
spec=importlib.util.spec_from_file_location('repository_pair',Path(__file__).with_name('repository-enrollment-native.py'))
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)


class RepositoryNativeTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.base=Path(temporary.name)
        self.source=self.base/'source';self.source.mkdir();self.recipe=self.source/T.RECIPE
        self.recipe.mkdir(parents=True)
        sources=sorted({source for source,_ in T.PAYLOAD.values()})
        for name in sources:(self.recipe/name).write_text('inert fixture '+name+'\n')
        checksums=[hashlib.sha256((self.recipe/name).read_bytes()).hexdigest() for name in sources]
        (self.recipe/'PKGBUILD').write_text("pkgname=cachy-asahi-setup\npkgver=0.1.0\npkgrel=4\narch=('any')\nlicense=('MIT')\n"
            "depends=('python>=3.11' 'gnupg' 'pacman')\nsource=("+' '.join(repr(n) for n in sources)+")\nsha256sums=("+
            ' '.join(repr(n) for n in checksums)+")\n")
        (self.recipe/'.SRCINFO').write_text('pkgname = cachy-asahi-setup\npkgver = 0.1.0\npkgrel = 4\narch = any\nlicense = MIT\n'
            'depends = python>=3.11\ndepends = gnupg\ndepends = pacman\n'+
            ''.join('source = '+n+'\nsha256sums = '+v+'\n' for n,v in zip(sources,checksums)))
        self.gitrows={str(p.relative_to(self.source)):p.read_bytes() for p in self.recipe.rglob('*') if p.is_file()}
        self.args=SimpleNamespace(source_commit='a'*40,cache=self.base/'cache',output=self.base/'output')
        self.args.cache.mkdir();self.addCleanup(patch.stopall)
        patch.object(T,'ROOT',self.source).start()
        patch.object(T.native,'run',side_effect=AssertionError('unexpected real command')).start()
        patch.object(T.subprocess,'run',side_effect=AssertionError('unexpected real subprocess')).start()
        patch.object(T.subprocess,'check_output',side_effect=AssertionError('unexpected real Git')).start()

    def candidate_preflight(self):
        names=sorted(self.gitrows)
        def command(argv,**kwargs):
            return self.args.source_commit if 'rev-parse' in argv else '\n'.join(names)
        with patch.object(T.platform,'system',return_value='Linux'),patch.object(T.platform,'machine',return_value='aarch64'), \
             patch.object(T.os,'getuid',return_value=1000),patch.object(T.os,'geteuid',return_value=1000), \
             patch.object(T.os,'getgid',return_value=1000),patch.object(T.os,'getegid',return_value=1000), \
             patch.dict(T.os.environ,{},clear=True),patch.object(T.native,'run',side_effect=command), \
             patch.object(T.subprocess,'run'),patch.object(T.subprocess,'check_output',side_effect=lambda a,**k:self.gitrows[a[-1].split(':',1)[1]]), \
             patch.object(T.native,'load_pinned',return_value={}):
            return T.preflight(self.args)

    def test_reviewed_candidate_path_and_all_input_bytes_are_fixed(self):
        _,report=self.candidate_preflight()
        self.assertEqual(report['metadata']['pkgrel'],['4'])
        self.assertIn('cachy-asahi-repository',report['input_sha256'])
        (self.recipe/'unreviewed.py').write_text('foreign source')
        with self.assertRaisesRegex(ValueError,'unreviewed recipe path'):self.candidate_preflight()
        (self.recipe/'unreviewed.py').unlink()
        original=(self.recipe/'.SRCINFO').read_text()
        (self.recipe/'.SRCINFO').write_text(original+'# changed inert metadata comment\n')
        with self.assertRaisesRegex(ValueError,'input differs from exact Source'):self.candidate_preflight()
        (self.recipe/'.SRCINFO').write_text(original)
        # Git's selected tree is immutable while working bytes may drift.
        with patch.object(T.native,'run',return_value=self.args.source_commit), \
             patch.object(T.platform,'machine',return_value='aarch64'):
            # A branch label fails before any path or native action.
            self.args.source_commit='main'
            with self.assertRaisesRegex(ValueError,'exact candidate'):T.preflight(self.args)
        self.args.source_commit='a'*40
        # Static recipe rejects the old package before bootstrap or output creation.
        text=(self.recipe/'.SRCINFO').read_text().replace('pkgrel = 4','pkgrel = 3')
        (self.recipe/'.SRCINFO').write_text(text)
        with self.assertRaisesRegex(ValueError,'fixed candidate'):self.candidate_preflight()
        self.assertFalse(self.args.output.exists())

    def test_docker_override_and_non_native_refuse_before_output(self):
        with patch.object(T.platform,'machine',return_value='x86_64'),self.assertRaisesRegex(ValueError,'native ARM'):
            T.preflight(self.args)
        with patch.object(T.platform,'machine',return_value='aarch64'),patch.dict(T.os.environ,{'DOCKER_HOST':'tcp://foreign'}), \
             self.assertRaisesRegex(ValueError,'overrides'):T.preflight(self.args)
        self.assertFalse(self.args.output.exists())

    def owned(self):
        self.args.output.mkdir();(self.args.output/'native').mkdir()
        (self.args.output/'native/image-id').write_text('sha256:'+'b'*64)
        (self.args.output/'build-1').mkdir()
        (self.args.output/'build-1/provenance.json').write_text(json.dumps({'clean_environment_id':'cachy-asahi-'+'c'*16}))

    def test_cleanup_removes_only_recorded_container_and_image_then_checks_absence(self):
        self.owned();calls=[];queries=0
        def command(argv,**kwargs):
            nonlocal queries
            calls.append(argv)
            if argv[1:3]==['container','ls']:
                queries+=1;return 'cachy-asahi-'+'c'*16 if queries==1 else ''
            return ''
        with patch.object(T.native,'run',side_effect=command):result=T.cleanup(self.args.output,['docker'],True,[1])
        self.assertEqual(result['status'],'PASS')
        self.assertIn(['docker','rm','-f','cachy-asahi-'+'c'*16],calls)
        self.assertIn(['docker','image','rm','--no-prune','sha256:'+'b'*64],calls)
        self.assertTrue(result['image']['absence_verified'])
        self.assertEqual(queries,2)

    def test_unknown_bootstrap_or_container_and_failed_query_cannot_claim_cleanup(self):
        self.args.output.mkdir();(self.args.output/'native').mkdir()
        result=T.cleanup(self.args.output,['docker'],True,[])
        self.assertEqual((result['status'],result['image']['status']),('FAIL','UNKNOWN'))
        (self.args.output/'native/image-id').write_text('sha256:'+'b'*64)
        def command(argv,**kwargs):
            if argv[1:3]==['container','ls']:raise ValueError('modeled query failure')
            return ''
        with patch.object(T.native,'run',side_effect=command):
            result=T.cleanup(self.args.output,['docker'],True,[1])
        self.assertEqual(result['status'],'FAIL');self.assertTrue(result['image']['absence_verified'])
        (self.args.output/'build-1').mkdir()
        (self.args.output/'build-1/provenance.json').write_text(json.dumps({'clean_environment_id':'cachy-asahi-'+'c'*16}))
        with patch.object(T.native,'run',side_effect=command):result=T.cleanup(self.args.output,['docker'],True,[1])
        self.assertEqual(result['status'],'FAIL');self.assertTrue(result['image']['absence_verified'])
        (self.args.output/'build-1/provenance.json').write_text(json.dumps({'clean_environment_id':'foreign'}))
        with patch.object(T.native,'run',side_effect=command):result=T.cleanup(self.args.output,['docker'],True,[1])
        self.assertEqual(result['status'],'FAIL')

    def orchestration(self,fail_build=False,cleanup_status='PASS',bad_payload=False,skip_checks=False):
        reviewed=T.recipe(self.recipe/'PKGBUILD');packages=b'fixture-base 1\n';commands=[]
        def build(inputs,cache,out,recipes):
            self.assertEqual(recipes,{})
            (out/'packages.lock').write_bytes(packages);(out/'image-id').write_text('sha256:'+'b'*64)
            return 'sha256:'+'b'*64
        def command(argv,log=None,timeout=None):
            commands.append(argv)
            if 'build.py' not in ' '.join(argv):return ''
            if fail_build:raise ValueError('modeled build failure')
            out=Path(argv[argv.index('--output')+1]);out.mkdir()
            members={name:{'type':'0','mode':mode,'sha256':reviewed['input_sha256'][source]}
                     for name,(source,mode) in T.PAYLOAD.items()}
            (out/'build.log').write_text('==> Starting check()...\n' if not skip_checks else 'skipped checks\n')
            if bad_payload:members['usr/bin/cachy-asahi-repository']['mode']=0o777
            (out/'provenance.json').write_text(json.dumps({'status':'built-package-static-pass'}))
            (out/'validation.json').write_text(json.dumps({'errors':[],'artifacts':[{'members':members}]}))
        with patch.object(T,'preflight',return_value=({'source_date_epoch':1791748800},reviewed)), \
             patch.object(T.native,'probe',return_value={'docker_endpoint':'unix:///run/docker.sock'}), \
             patch.object(T.native,'audit'),patch.object(T.native,'build',side_effect=build), \
             patch.object(T,'PACKAGES_SHA',hashlib.sha256(packages).hexdigest()), \
             patch.object(T.native,'run',side_effect=command),patch.object(T,'cleanup',return_value={'status':cleanup_status}) as cleanup:
            code=T.run(self.args)
        return code,json.loads((self.args.output/'summary/result.json').read_text()),commands,cleanup

    def test_pair_uses_reviewed_inputs_native_offline_and_required_bytes(self):
        code,result,commands,cleanup=self.orchestration()
        self.assertEqual((code,result['status']),(0,'PASS'));cleanup.assert_called_once()
        builds=[c for c in commands if 'build.py' in ' '.join(c)]
        self.assertEqual(len(builds),2)
        for c in builds:
            self.assertEqual(c[c.index('--network')+1],'none');self.assertEqual(c[c.index('--mode')+1],'native')
            self.assertIn('--reviewed-inputs',c);self.assertEqual(c[c.index('--timeout')+1],'300')
        self.assertIn('--require-bytes',commands[-1])
        self.assertEqual((result['hardware_validation'],result['repository_trust'],result['installation']),('NOT RUN',)*3)
        self.assertFalse(result['selected_for_release'])

    def test_skipped_native_recipe_checks_cannot_claim_help_pass(self):
        code,result,commands,cleanup=self.orchestration(skip_checks=True)
        self.assertEqual((code,result['status']),(1,'FAIL'));cleanup.assert_called_once()
        self.assertFalse(any('compare.py' in ' '.join(c) for c in commands))

    def test_payload_drift_refuses_before_comparison(self):
        code,result,commands,cleanup=self.orchestration(bad_payload=True)
        self.assertEqual((code,result['status']),(1,'FAIL'));cleanup.assert_called_once()
        self.assertFalse(any('compare.py' in ' '.join(c) for c in commands))

    def test_remaining_bootstrap_image_is_a_cleanup_failure(self):
        self.owned()
        with patch.object(T.native,'run',side_effect=lambda a,**k:'sha256:'+'b'*64 if a[1:3]==['image','ls'] else ''):
            result=T.cleanup(self.args.output,['docker'],True,[1])
        self.assertEqual((result['status'],result['image']['absence_verified']),('FAIL',False))

    def test_build_and_cleanup_failures_never_promote_candidate(self):
        code,result,commands,cleanup=self.orchestration(fail_build=True)
        self.assertEqual((code,result['status']),(1,'FAIL'));cleanup.assert_called_once()
        self.assertFalse(any('compare.py' in ' '.join(c) for c in commands))
        shutil.rmtree(self.args.output)
        code,result,_,_=self.orchestration(cleanup_status='FAIL')
        self.assertEqual((code,result['status']),(1,'FAIL'))


if __name__=='__main__':unittest.main()
