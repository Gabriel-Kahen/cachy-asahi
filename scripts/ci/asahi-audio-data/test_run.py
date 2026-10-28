"""Fixed data-recipe/payload exception tests; no Docker, make or system actors."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'scripts/checks/package_checks.py').is_file())
sys.path[:0]=[str(ROOT/'scripts/ci'),str(ROOT/'scripts/checks'),str(ROOT/'scripts/build')]
spec=importlib.util.spec_from_file_location('asahi_data_pair',Path(__file__).with_name('run.py'))
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
TREE=Path(__file__).resolve().parents[3]


class DataPairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs=json.loads((T.HERE/'inputs.json').read_text())
        cls.policy=json.loads((T.HERE/'payload.json').read_text())

    def test_exact_recipe_sources_dependencies_and_generic_guards_remain(self):
        for name in T.NAMES:
            path=TREE/'packages/platform'/name/'PKGBUILD'
            report=T.recipe_report(path,self.inputs,self.policy)
            self.assertFalse(report['errors']);self.assertEqual(report['build_only_protected_errors'],['protected platform package name: '+name])
            self.assertEqual(T.checks.recipe(path)['errors'],['protected platform package name: '+name])
            self.assertNotIn('install',report['metadata'])
        self.assertEqual(T.recipe_report(TREE/'packages/platform/asahi-audio/PKGBUILD',self.inputs,self.policy)['metadata']['depends'],
            ['wireplumber>=0.5.2','pipewire>=1.0','bankstown>=1.1.0','lsp-plugins-lv2>=1.2.15','speakersafetyd','triforce-lv2>=0.2.0'])

    def test_original_source_archive_pins_and_exact_upstream_grants(self):
        for name in T.NAMES:
            folder=TREE/'packages/platform'/name;record=json.loads((folder/'source-provenance.json').read_text())
            source=record['source'];archive=folder/source['archive']
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),source['sha256'])
            self.assertFalse(record['selected_for_release']);self.assertTrue(record['development_candidate'])
            root='asahi-audio-4.1' if name=='asahi-audio' else 'alsa-ucm-conf-asahi-10'
            with tarfile.open(archive,'r:gz') as stream:
                grant=stream.extractfile(root+('/LICENSE' if name=='asahi-audio' else '/LICENSE.asahi')).read()
            self.assertEqual(hashlib.sha256(grant).hexdigest(),self.policy[name]['payload']['usr/share/licenses/'+name+'/LICENSE.asahi']['sha256'])

    def test_recipe_drift_or_extra_generic_error_is_not_waived(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary)/'asahi-audio';shutil.copytree(TREE/'packages/platform/asahi-audio',folder)
            path=folder/'PKGBUILD';path.write_text(path.read_text()+'# unexpected input change\n')
            with self.assertRaisesRegex(ValueError,'input bytes differ'):T.recipe_report(path,self.inputs,self.policy)
        original=T.checks.recipe(TREE/'packages/platform/asahi-audio/PKGBUILD')
        original['errors'].append('unrelated dependency or source failure')
        with patch.object(T.checks,'recipe',return_value=original),self.assertRaisesRegex(ValueError,'unexpected recipe error'):
            T.recipe_report('unused',self.inputs,self.policy)

    def report(self,name='asahi-audio'):
        # Inert inspector output exercises the exception boundary, not a package build.
        rows={path:{'type':'0','mode':row['mode'],'uid':0,'gid':0,'sha256':row['sha256']}
              for path,row in self.policy[name]['payload'].items()}
        for path in list(rows):
            for parent in Path(path).parents:
                if str(parent)!='.':rows[str(parent)]={'type':'5','mode':0o755,'uid':0,'gid':0,'sha256':None}
        return {'status':'fail','metadata':{'.PKGINFO':{'pkgname':[name],'pkgver':[self.policy[name]['version']]}},
                'members':rows,'elf':{},'errors':self.policy[name]['package_errors'][:]}

    def test_exact_payload_policy_passes_without_changing_generic_protection(self):
        protected=T.checks.PROTECTED;names=T.checks.PROTECTED_PACKAGES.copy()
        for name in T.NAMES:
            with patch.object(T.checks,'package',return_value=self.report(name)):
                report=T.package_report('unused',self.policy)
            self.assertEqual(report['errors'],[]);self.assertEqual(report['build_only_protected_errors'],self.policy[name]['package_errors'])
        self.assertEqual(T.checks.PROTECTED,protected);self.assertEqual(T.checks.PROTECTED_PACKAGES,names)

    def test_added_or_missing_generic_error_cannot_pass(self):
        for modify in (lambda r:r['errors'].append('arbitrary error'),lambda r:r['errors'].pop()):
            report=self.report();modify(report)
            with patch.object(T.checks,'package',return_value=report),self.assertRaisesRegex(ValueError,'unexpected package error'):
                T.package_report('unused',self.policy)

    def test_payload_tamper_elf_hook_executable_or_extra_path_cannot_pass(self):
        path='usr/share/wireplumber/scripts/device/asahi-lock-volume.lua'
        for modify in (
            lambda r:r['members'][path].update(sha256='0'*64),
            lambda r:r['members'][path].update(mode=0o755),
            lambda r:r['members'][path].update(uid=1000),
            lambda r:r['members'][path].update(type='2'),
            lambda r:r['members'].update({'.INSTALL':{'type':'0','mode':0o644,'uid':0,'gid':0}}),
            lambda r:r['members'].update({'usr/lib/systemd/system/foreign.service':r['members'][path]}),
            lambda r:r['elf'].update({'unexpected':{}}),
            lambda r:r['members'].update({'usr/share/unreviewed':{'type':'5','mode':0o755,'uid':0,'gid':0}}),
            lambda r:r['metadata']['.PKGINFO'].update(pkgver=['4.1-1']),
        ):
            with self.subTest(mutation=modify):
                report=self.report();modify(report)
                with patch.object(T.checks,'package',return_value=report),self.assertRaises(ValueError):T.package_report('unused',self.policy)

    def test_staged_entry_has_only_explicit_nodeps_change(self):
        with tempfile.TemporaryDirectory() as temporary,patch.object(T,'ROOT',ROOT):
            folder=Path(temporary)/'builder';T.build_api(folder,self.inputs,self.policy)
            original=(ROOT/'scripts/build/container-entry.sh').read_text()
            self.assertEqual((folder/'build.py').read_bytes(),(ROOT/'scripts/build/build.py').read_bytes())
            self.assertEqual((folder/'container-entry.sh').read_text(),original.replace(
                'makepkg --cleanbuild --clean --force --log --noconfirm',
                'makepkg --cleanbuild --clean --force --log --noconfirm --nodeps'))


if __name__=='__main__':unittest.main(verbosity=2)
