"""Read-only packet regressions; no native/compiler/GPG/network execution."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
import dependency_audit as audit


class FrozenDependencies(unittest.TestCase):
    def setUp(self):
        self.packet = json.loads(Path(__file__).with_name('dependencies.json').read_text())

    def reject(self, mutate):
        packet = copy.deepcopy(self.packet); mutate(packet)
        with self.assertRaises(ValueError): audit.validate_data(packet)

    def test_exact_inventory_preserves_341(self):
        self.assertEqual(len(audit.validate_data(self.packet)),356)
        self.assertEqual(self.packet['verified_count'],15)
        self.assertEqual(self.packet['deptest_exit'],0)

    def test_baseline_substitution_with_fresh_digest_is_rejected(self):
        def mutate(p):
            p['expected_inventory'] = p['expected_inventory'].replace('gcc 16.1.1+r12+g301eb08fa2c5-1\n','gcc 17.0-1\n')
            p['expected_inventory_sha256'] = hashlib.sha256(p['expected_inventory'].encode()).hexdigest()
        self.reject(mutate)

    def test_missing_root_is_rejected(self):
        self.reject(lambda p:p['root_pins'].pop())

    def test_addition_not_installed_is_rejected(self):
        self.reject(lambda p:p['packages'][0].update(version='9.0-1',filename='bc-9.0-1-aarch64.pkg.tar.xz',
                      url='https://ca.us.mirror.archlinuxarm.org/aarch64/extra/bc-9.0-1-aarch64.pkg.tar.xz'))

    def test_wrong_architecture_is_rejected(self):
        self.reject(lambda p:p['packages'][0].update(arch='x86_64'))

    def test_unofficial_url_is_rejected(self):
        self.reject(lambda p:p['packages'][0].update(url='https://example.org/archive'))

    def test_duplicate_addition_is_rejected(self):
        self.reject(lambda p:p['packages'].__setitem__(1,p['packages'][0]))

    def test_replacement_signer_is_rejected(self):
        self.reject(lambda p:p.update(signer_fingerprint='A'*40))

    def test_oversized_extension_is_rejected(self):
        self.reject(lambda p:p['packages'][0].update(size=audit.MAX_BYTES+1))

    def test_negative_signature_size_is_rejected(self):
        self.reject(lambda p:p['packages'][0].update(signature_size=-1))

    def test_invalid_hash_is_rejected(self):
        self.reject(lambda p:p['packages'][0].update(sha256='Z'*64))

    def test_unsorted_inventory_is_rejected(self):
        def mutate(p):
            lines=p['expected_inventory'].splitlines();lines[0],lines[1]=lines[1],lines[0]
            p['expected_inventory']='\n'.join(lines)+'\n'
            p['expected_inventory_sha256']=hashlib.sha256(p['expected_inventory'].encode()).hexdigest()
        self.reject(mutate)


if __name__ == '__main__': unittest.main()
