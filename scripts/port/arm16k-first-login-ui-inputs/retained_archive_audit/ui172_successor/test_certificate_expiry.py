"""Synthetic declaration controls; no keys, archives or signature actors."""
import hashlib
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('certificate_expiry',Path(__file__).with_name('certificate_expiry.py'))
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)


class ExpiryControls(unittest.TestCase):
    def setUp(self):
        self.created=1000000;self.key=b'\x04'+self.created.to_bytes(4,'big')+b'\x01synthetic-public-data'
        self.primary=hashlib.sha1(b'\x99'+len(self.key).to_bytes(2,'big')+self.key).hexdigest().upper()
        self.fields=[bytes([22,33,4])+bytes.fromhex(self.primary),bytes([5,2])+self.created.to_bytes(4,'big'),bytes([5,9])+(3600).to_bytes(4,'big')]

    def run_declaration(self,now,extra=b''):
        fields=b''.join(self.fields)+extra;sig=b'\x04\x13\x01\x08'+len(fields).to_bytes(2,'big')+fields
        return C.inspect(b'synthetic',lambda _: [(6,self.key,b''),(13,b'user',b''),(2,sig,b'')],self.primary,now)

    def test_current_and_expired_are_distinct_facts_without_approval(self):
        self.assertFalse(self.run_declaration(self.created+3599)['declaration_expired_at_observation'])
        self.assertTrue(self.run_declaration(self.created+3600)['declaration_expired_at_observation'])
        self.assertFalse(self.run_declaration(self.created)['Root_trust_approval'])

    def test_duplicate_expiry_refused(self):
        with self.assertRaisesRegex(ValueError,'one declared key expiry'):
            self.run_declaration(self.created,bytes([5,9])+(1).to_bytes(4,'big'))

    def test_truncated_subpacket_refused(self):
        with self.assertRaisesRegex(ValueError,'complete subpacket'):
            self.run_declaration(self.created,b'\xff\x00\x00\xff\xff')

    def test_foreign_primary_refused(self):
        self.primary='0'*40
        with self.assertRaisesRegex(ValueError,'exact project primary'):
            self.run_declaration(self.created)


if __name__=='__main__':unittest.main()
