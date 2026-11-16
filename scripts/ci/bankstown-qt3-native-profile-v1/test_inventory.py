#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""MODEL477/catalog333 controls over the genuine passive protected349 bytes."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
        raise AssertionError('MODEL inventory controls forbid actors: '+event)
sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('passive_inventory',HERE/'inventory.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
PROTECTED=HERE/'expected349.lock'
def encoded(value):return json.dumps(value,sort_keys=True,allow_nan=False).encode()
def vector(rows):return ''.join(n+' '+v+'\n'for n,v in sorted(rows.items())).encode()

class ModelInventory(unittest.TestCase):
    def setUp(self):
        self.protected=PROTECTED.read_bytes()
        self.assertEqual(P.pin(self.protected),dict(bytes=6800,sha256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'))
        base=P.inventory(self.protected,349)
        added={**{'model-added-%03d'%i:'0.0-MODEL'for i in range(126)},'qt6-base':'6.12.0-3','rust':'1:1.99.0-1'}
        self.assertTrue(set(base).isdisjoint(added))
        self.rows=dict(base,**added);selected=dict(list(sorted(base.items()))[:205],**added)
        self.catalog=dict(MODEL='NOT_ACTUAL_CATALOG_OR_NATIVE_EVIDENCE',actual=None,packages={n:dict(metadata={'/.PKGINFO':dict(pkgname=[n],pkgver=[v])})for n,v in selected.items()})
    def check(self,rows=None,catalog=None,protected=None):
        return P.check(vector(self.rows if rows is None else rows),self.protected if protected is None else protected,encoded(self.catalog if catalog is None else catalog))
    def test_positive_model_joins_return_only_pins_counts_and_no_acceptance(self):
        before=encoded(self.catalog);result=self.check()
        self.assertEqual((result['inventory_count'],result['protected_count'],result['catalog_count'],result['addition_count']),(477,349,333,128))
        self.assertIsNone(result['Root_acceptance']);self.assertFalse(result['native_acceptance'])
        self.assertEqual(result['inventory'],P.pin(vector(self.rows)));self.assertEqual(before,encoded(self.catalog))
    def test_genuine_protected_bytes_are_required_before_other_parsing(self):
        for raw in(self.protected+b'\n',self.protected.replace(b'1',b'2',1),b'MODEL protected349'):
            with self.subTest(raw=raw[:20]),self.assertRaisesRegex(ValueError,'protected349 inventory pin'):self.check(protected=raw)
    def test_inventory_is_exact477_canonical_unique_and_bounded(self):
        raw=vector(self.rows);lines=raw.splitlines(keepends=True)
        invalid=[raw[:-1],raw.replace(b'\n',b'\r\n'),b''.join(reversed(lines)),lines[0]+raw,
                 raw.replace(b' ',b'\t',1),raw.replace(b'model-added-000',b'../MODEL',1),raw+b'\xff']
        for value in invalid:
            with self.subTest(value=value[:30]),self.assertRaises(ValueError):P.check(value,self.protected,encoded(self.catalog))
        with patch.object(P,'INVENTORY_CAP',len(raw)-1),self.assertRaises(ValueError):P.check(raw,self.protected,encoded(self.catalog))
        for delta in(-1,1):
            rows=dict(self.rows)
            if delta<0:rows.pop('model-added-000')
            else:rows['model-unselected']='0.0-MODEL'
            with self.subTest(delta=delta),self.assertRaises(ValueError):self.check(rows=rows)
    def test_protected_and_catalog_versions_cannot_be_replaced(self):
        for name in(next(iter(P.inventory(self.protected,349))),'qt6-base','rust'):
            rows=dict(self.rows);rows[name]='0.0-MODEL-DRIFT'
            with self.subTest(name=name),self.assertRaises(ValueError):self.check(rows=rows)
        catalog=copy.deepcopy(self.catalog);name=next(n for n in catalog['packages']if n.startswith('a'))
        catalog['packages'][name]['metadata']['/.PKGINFO']['pkgver']=['0.0-MODEL-DRIFT']
        with self.assertRaises(ValueError):self.check(catalog=catalog)
    def test_catalog_is_exact333_and_metadata_identity_is_single(self):
        for mutate in(lambda p:p.pop('qt6-base'),lambda p:p.update(model_extra=p['qt6-base']),
            lambda p:p['qt6-base']['metadata']['/.PKGINFO'].update(pkgname=['qt6-base-headless']),
            lambda p:p['qt6-base']['metadata']['/.PKGINFO'].update(pkgver=[]),
            lambda p:p['qt6-base']['metadata']['/.PKGINFO'].update(pkgver=['6.12.0-3','6.12.0-3']),
            lambda p:p['qt6-base']['metadata']['/.PKGINFO'].update(pkgver=[True])):
            c=copy.deepcopy(self.catalog);mutate(c['packages'])
            with self.subTest(mutate=mutate),self.assertRaises((ValueError,KeyError)):self.check(catalog=c)
    def test_qt_and_rust_exact_versions_are_mandatory(self):
        for name,version in(('qt6-base','6.12.0-2'),('qt6-base','6.12.0-5'),('rust','1.99.0-1')):
            c=copy.deepcopy(self.catalog);c['packages'][name]['metadata']['/.PKGINFO']['pkgver']=[version]
            with self.subTest(name=name,version=version),self.assertRaises(ValueError):self.check(catalog=c)
    def test_duplicate_json_keys_and_nonfinite_numbers_refuse(self):
        raw=encoded(self.catalog);packages=encoded(self.catalog['packages'])
        duplicate=b'{"packages":'+packages+b',"packages":'+packages+b'}'
        nested=raw.replace(b'"pkgver": ["6.12.0-3"]',b'"pkgver": ["6.12.0-3"], "pkgver": ["6.12.0-3"]',1)
        self.assertNotEqual(nested,raw)
        for value in(duplicate,nested,b'{"bad":NaN}',b'{"bad":Infinity}',b'{"bad":1e999}'):
            with self.subTest(value=value[:30]),self.assertRaises(ValueError):P.check(vector(self.rows),self.protected,value)
        with patch.object(P,'CATALOG_CAP',len(raw)-1),self.assertRaises(ValueError):P.check(vector(self.rows),self.protected,raw)
    def test_unselected_inventory_extra_is_not_accepted_as_an_addition(self):
        rows=dict(self.rows);rows.pop('model-added-000');rows['model-unselected']='0.0-MODEL'
        with self.assertRaises(ValueError):self.check(rows=rows)
    def test_wrong_raw_types_refuse(self):
        for raw in(None,'MODEL',bytearray(b'MODEL')):
            with self.subTest(raw=raw),self.assertRaises(ValueError):P.check(raw,self.protected,encoded(self.catalog))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--protected',type=Path,default=PROTECTED);a,rest=p.parse_known_args();PROTECTED=a.protected
    unittest.main(argv=[sys.argv[0],*rest])
