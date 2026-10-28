import copy
import json
from pathlib import Path
import shutil
import unittest
import migration as m
import preview
import updater_extension as u

HERE=Path(__file__).resolve().parent


class MigrationBoundaryTests(unittest.TestCase):
    def test_explicit_successor_record_and_signature_pins(self):
        meta=json.loads((HERE/'current-perl-metadata-observation.json').read_text())['perl']
        p=m.item(meta,'core')
        self.assertEqual(p['version'],'5.42.3-1')
        self.assertEqual(p['signature_size'],566)
        self.assertEqual(p['sha256'],'f0e47c42ec91985898af2ce7355ef4eead50457108706add1f8c1650bca19b8f')
        wrong=copy.deepcopy(meta);wrong['ARCH']=['x86_64']
        with self.assertRaises(ValueError):m.item(wrong,'core')
        wrong=copy.deepcopy(meta);wrong['PGPSIG']=['invalid!']
        with self.assertRaises(ValueError):m.item(wrong,'core')
    @unittest.skipUnless(shutil.which('pacman'),'native libalpm required')
    def test_versioned_provider_migration_failure_is_not_accepted(self):
        record={'provider':{'NAME':['provider'],'VERSION':['1-1'],'ARCH':['aarch64'],'PROVIDES':['virtual=1']},
                'app':{'NAME':['app'],'VERSION':['1-1'],'ARCH':['aarch64'],'DEPENDS':['virtual=1']}}
        change={'name':'provider','version':'2-1','arch':'aarch64','depends':[],'provides':['virtual=2'],
                'conflicts':[],'replaces':[],'license':['MIT']}
        result=m.metadata_impact(record,[change])
        self.assertEqual(result['result'],'FAIL-generic-metadata-substitution')
        self.assertEqual(result['unsatisfied'][0]['relation'],'virtual=1')
        with self.assertRaises(ValueError):m.metadata_impact(record,[change|{'name':'absent'}])


class ExtensionBoundaryTests(unittest.TestCase):
    def test_adopted_seed_has_exact_341_and_changed_seed_refused(self):
        receipt=json.loads((HERE/'refreshed-desktop/receipt.json').read_text())
        seed=u.seed(receipt)
        self.assertEqual(len(seed),341);self.assertEqual(seed['perl']['VERSION'],['5.42.3-1'])
        bad=copy.deepcopy(receipt)
        for p in bad['full_candidate_inventory']:
            if p['name']==['perl']:p['version']=['5.42.2-2']
        with self.assertRaises(ValueError):u.seed(bad)
    def test_finite_root_pins_and_baseline_changes_refused(self):
        owner={'direct_roots':list(u.ROOTS),'roots':[{'name':n,'version':'1-1','archive_sha256_metadata':'0'*64} for n in u.ROOTS]}
        packages={n:{'NAME':[n],'VERSION':['1-1'],'ARCH':['aarch64'],'SHA256SUM':['0'*64]} for n in u.ROOTS}
        self.assertEqual(len(u.roots(owner,packages,{})),9)
        with self.assertRaises(ValueError):u.roots(owner,packages,{'glib2':{'VERSION':['0-1']}})
        bad=copy.deepcopy(owner);bad['direct_roots'].append('extra')
        with self.assertRaises(ValueError):u.roots(bad,packages,{})
        bad=copy.deepcopy(owner);bad['roots'][0]['version']='2-1'
        with self.assertRaises(ValueError):u.roots(bad,packages,{})
        bad=copy.deepcopy(owner);bad['roots'][-1]=copy.deepcopy(bad['roots'][0])
        with self.assertRaises(ValueError):u.roots(bad,packages,{})


if __name__=='__main__':unittest.main()
