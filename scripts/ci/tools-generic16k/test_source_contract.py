# SPDX-License-Identifier: MIT
"""Current source pins stay exact; historical Welcome1 pins do not accept Welcome2."""
import copy,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'scripts/ci/tools-generic16k/support.py').is_file())
sys.path.insert(0,str(ROOT/'scripts/ci/tools-generic16k'))
import support as s

# Historical metadata only. Accepted old source/receipt refs are not rewritten.
HISTORICAL={
 'Makefile':dict(bytes=2134,sha256='ce76cbe478cf4354cb637d738f732515988cac29ea0c7966dffdcb806783a9cf'),
 'PKGBUILD':dict(bytes=2196,sha256='1e02bf118d385edf69321c55b9fba41149bea61499fd784d54df6b5904159f86'),
 'README.md':dict(bytes=3079,sha256='55c0a3a77f40d0dbef7af779ab8ce7ef5270536ea3a33071700b7ebe20812f07'),
 'check_source.py':dict(bytes=3279,sha256='778e025cf5ca7caa7e1bacbb668876ef793d64e7cd3ba0d6d345c1fa9a70e502'),
 'welcome.c':dict(bytes=13447,sha256='891e0fc1f8e17c565e3a8c63dd48e47675fa91fffca169bb6d86d97d3db19f32')}
PREFIX='packages/tools/cachy-asahi-welcome/'

class SourceContract(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.actor=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden'));self.actor.start();self.addCleanup(self.actor.stop)
        self.pins=json.loads((HERE/'dependencies.json').read_bytes())
        for name in self.pins['files']:
            dest=self.root/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,dest)
        self.here=self.root/'scripts/ci/tools-generic16k'
        (self.here/'dependencies.json').write_text(json.dumps(self.pins))
        shutil.copyfile(ROOT/'scripts/ci/tools-generic16k/payload-map.json',self.here/'payload-map.json')
    def check(self):
        with patch.object(s,'HERE',self.here):s.check_source(self.root)
    def test_current_complete_source_contract_and_four_product_map_pass(self):
        self.check()
        with patch.object(s,'HERE',self.here):
            mapping=s.products(self.root)
        self.assertEqual(len(mapping),4);self.assertNotIn('cachy-asahi-welcome',mapping)
        for name,old in HISTORICAL.items():self.assertNotEqual(self.pins['files'][PREFIX+name],old)
    def test_each_current_welcome_file_still_refuses_tampering(self):
        self.check()
        for name in HISTORICAL:
            path=self.root/PREFIX/name;raw=path.read_bytes();path.write_bytes(raw+b'\nchanged\n')
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'source pin differs: '+PREFIX+name):self.check()
            path.write_bytes(raw)
        self.check()
    def test_original_exact_historical_pins_refuse_current_welcome2(self):
        old=copy.deepcopy(self.pins)
        for name,row in HISTORICAL.items():old['files'][PREFIX+name]=row
        with patch.object(s,'pins',return_value=old),self.assertRaisesRegex(ValueError,'source pin differs: '+PREFIX+'Makefile'):self.check()

if __name__=='__main__':unittest.main(verbosity=2)
