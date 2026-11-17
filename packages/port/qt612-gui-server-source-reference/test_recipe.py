# SPDX-License-Identifier: MIT
"""Read-only recipe/provider contracts; no package, build, or native actor."""
import sys
sys.dont_write_bytecode = True


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.fork','os.posix_spawn'):
        raise ValueError('SOURCE_CONTRACTS_ONLY')


sys.addaudithook(fence)
import hashlib
import json
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent
BASE = HERE.with_name('qt612-gui-source-reference')
PACKAGE = 'cachy-asahi-qt612-gui-server-source-reference'


def pin(raw): return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def doc(name): return json.loads((HERE/name).read_bytes())


class Recipe(unittest.TestCase):
    def setUp(self):
        self.contract = doc('BUILD-CONTRACT.json'); self.info = {}
        for line in (HERE/'.SRCINFO').read_text().splitlines():
            if line.strip():
                key,value = line.strip().split(' = ',1); self.info.setdefault(key,[]).append(value)

    def test_identity_exclusive_provides_and_reviewed_lifecycle(self):
        for key,value in dict(pkgbase=PACKAGE,pkgname=PACKAGE,pkgver='6.12.0',pkgrel='1',arch='aarch64').items():
            self.assertEqual(self.info[key],[value])
        self.assertEqual(self.info['provides'],self.contract['package']['provides'])
        self.assertEqual(self.info['conflicts'],['qt6-base','cachy-asahi-qt612-base-source-reference','cachy-asahi-qt612-gui-source-reference'])
        for field in ('replaces','install','backup'): self.assertNotIn(field,self.info)
        lifecycle=doc('lifecycle.DATA.json')
        self.assertIsNone(lifecycle['provider_transaction']);self.assertEqual(lifecycle['automatic_replaces'],[])
        self.assertIn('6.12.0-3',lifecycle['version_compatibility'])

    def test_all_source_checksums_and_exact_original_archive(self):
        sources,checks=self.info['source'],self.info['sha256sums'];self.assertEqual(len(sources),14)
        self.assertEqual(len(sources),len(set(sources)));self.assertEqual(len(checks),14)
        archive=doc('SOURCE-INPUTS.lock.json')['archive']
        self.assertEqual(sources[0],archive['url']);self.assertEqual(checks[0],archive['sha256'])
        self.assertEqual(archive['sha256'],'a951bd163c7b80fc6b8c88d7668fb56abf91c152373e13c10666763238131307')
        for name,digest in zip(sources[1:],checks[1:]): self.assertEqual(pin((HERE/name).read_bytes())['sha256'],digest)
        self.assertNotIn('SKIP',checks)

    def test_only_one_feature_changes_and_all18_modules_remain(self):
        old=json.loads((BASE/'BUILD-CONTRACT.json').read_bytes())
        before,after=old['configuration']['settings'],self.contract['configuration']['settings']
        self.assertEqual(len(after),113)
        self.assertEqual({k:(before[k],after[k]) for k in before if before[k]!=after[k]},
                         {'FEATURE_wayland_server':('OFF','ON')})
        for key in ('public_modules','private_modules','plugins_required','tools_required'):
            self.assertEqual(self.contract['expected_stage'][key],old['expected_stage'][key])
        self.assertEqual(len(self.contract['expected_stage']['public_modules'])+len(self.contract['expected_stage']['private_modules']),18)

    def test_preserved_patch_order_notices_and_serial_guard(self):
        old=json.loads((BASE/'BUILD-CONTRACT.json').read_bytes())
        for name in old['patch_order']+['source-notices.json','LICENSE.packaging','LICENSE.third-party','SERIAL-POLICY.DATA.json']:
            self.assertEqual((HERE/name).read_bytes(),(BASE/name).read_bytes())
        policy=doc('source-notices.json');self.assertEqual(len(policy['source_notices']),173)
        recipe=(HERE/'PKGBUILD').read_text();before=(BASE/'PKGBUILD').read_text()
        extract=lambda t: re.search(r'(?ms)^_qt_single_job\(\) \{.*?^\}',t).group()
        self.assertEqual(extract(recipe),extract(before))
        self.assertEqual(self.contract['patch_order'],old['patch_order'])
        self.assertIn('--forward --fuzz=0',recipe)

    def test_normal_server_dependency_and_no_bypass(self):
        self.assertTrue({'wayland>=1.15','libwayland-server.so=0-64','md4c>=0.5.3','md4c<0.6'} <= set(self.info['depends']))
        self.assertEqual(self.info['depends'],self.contract['dependencies']['runtime'])
        self.assertEqual(self.info['makedepends'],self.contract['dependencies']['build'])
        recipe=(HERE/'PKGBUILD').read_text()
        self.assertIn('-DCMAKE_PROJECT_QtBase_INCLUDE="$srcdir/SERVER_DEPENDENCY_GUARD.cmake"',recipe)
        self.assertIn('python "$srcdir/source.py" configuration',recipe)
        self.assertNotRegex(recipe,r'--nodeps|--nocheck|!check|\bpacman\b|\bsudo\b|--skipchecks')
        guard=(HERE/'SERVER_DEPENDENCY_GUARD.cmake').read_text()
        self.assertIn('wayland-server>=1.15',guard);self.assertIn('check_cxx_source_compiles',guard)
        self.assertNotIn('check_cxx_source_runs',guard)

    def test_provider_interface_leaves_compositor_qml_and_svg_separate(self):
        interface=doc('PROVIDER-INTERFACE.DATA.json')
        self.assertEqual(interface['Qtbase_shared_modules'],18)
        self.assertEqual(interface['server_feature_export']['value'],'wayland_server')
        self.assertIn('QT6.12',interface['declarative_provider']);self.assertIn('QT6.12',interface['SVG_provider'])
        self.assertIn('OUTSIDE_QTBASE_VARIANT',interface['QtWaylandCompositor'])
        self.assertIsNone(interface['actual_native_provider']);self.assertIsNone(interface['Root_acceptance'])

    def test_complete_file_and_active_recipe_pins(self):
        closure=doc('recipe-files.lock.json');rows=closure['files']
        found={str(p.relative_to(HERE)) for p in HERE.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
        self.assertEqual(found,set(rows)|{'recipe-files.lock.json'})
        for name,row in rows.items(): self.assertEqual(pin((HERE/name).read_bytes()),{k:row[k] for k in ('bytes','sha256')})
        active=self.contract['native_recipe_files'];self.assertEqual(len(active),15)
        for name,row in active.items(): self.assertEqual(pin((HERE/name).read_bytes()),{k:row[k] for k in ('bytes','sha256')})

    def test_actual_observations_have_no_native_or_hardware_credit(self):
        generated=doc('evidence/generated-targets.DATA.json')
        self.assertEqual(generated['shared_library_target_count'],18)
        self.assertEqual(generated['Qt_build'],'NOT_RUN');self.assertEqual(generated['native_build'],'NOT_RUN')
        self.assertIsNone(generated['Root_acceptance'])
        actual=doc('evidence/wayland-provider.DATA.json')
        self.assertIn('provides = libwayland-server.so=0-64\n',actual['PKGINFO'])
        self.assertEqual(actual['server_ELF']['machine'],183)
        self.assertEqual(actual['server_ELF']['soname'],'libwayland-server.so.0')
        self.assertEqual(actual['GPG'],'NOT_RUN');self.assertIsNone(actual['normal_transaction'])


if __name__ == '__main__': unittest.main()
