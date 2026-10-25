# SPDX-License-Identifier: MIT
"""Closed-source and refusal controls; no positive VM/native fixtures or actors."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import accepted_inputs as A
import guard as G
import native_contract as N
import owner_adapter as O
import transaction_adapter as T

class Source(unittest.TestCase):
    def test_whole_source_native263_and_full_inverses_without_processes(self):
        with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
            result=G.verify()
        self.assertEqual(result['held_native606_files'],263)
        self.assertTrue(all(result[k] is None for k in ('actual_source','actual_ref','actual_run')))
    def test_default_authority_refuses_before_args_or_processes(self):
        with tempfile.TemporaryDirectory(prefix='boot607-null-control-') as temporary:
            base=Path(temporary)
            (base/'input-policy.json').write_bytes((HERE/'default-input-policy.json').read_bytes())
            with patch.object(G,'HERE',base),patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
                with self.assertRaisesRegex(ValueError,'NULL/UNBOUND'):G.authorize()
    def test_complete_actual_public_carrier_input_only(self):
        packet=Path(os.environ['BOOT607_INPUT_PACKET']).absolute()
        checks=G.module('_boot607_controls_held_package_inspector',G.ROOT/'held606/held-tools/scripts/checks/package_checks.py')
        with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
            result=A.inspect(packet,checks)
        self.assertEqual(result['accepted_pair'],A.ARCHIVE)
        self.assertEqual(result['authority'],'ACCEPTED_INPUTS_ONLY_NO_NEW_CURRENT606_OR_NATIVE_ACCEPTANCE')
    def test_native_scope_refuses_local_host_before_processes(self):
        with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
            with self.assertRaises(ValueError):N.native_scope('/','/tmp/expanded604-test/trust','/out/test.log')
    def test_whole_original_signed_step_hash_drift_refuses(self):
        raw=(G.ROOT/T.ORIGINAL).read_text()
        T.derive(raw)
        for changed in (raw+'\n',raw.replace('engine.inventory()==before', 'True',1),raw.replace('deny_exec()', 'pass # removed',1)):
            with self.assertRaises(ValueError):T.derive(changed)
    def test_original606_sequence_and_clock_body_held(self):
        _,_,P,old,_,_=G.original_context()
        raw=(P.HERE/'tools606.py').read_text()
        derived=O.consumer(raw)
        self.assertEqual(derived.replace(O.WITH_BOOT,O.SEQUENCE),raw)
        text=O.owner(old.owner(G.ROOT/'held606'))
        self.assertIn('active.process.wait(timeout=1800)',text)
        self.assertIn('signal.setitimer(signal.ITIMER_REAL,6600)',text)
        self.assertIn("len(owned.rows)==5",text)
        self.assertNotIn('SYS_CHROOT',text)
        self.assertNotIn('SYS_ADMIN',text)
    def test_missing_or_ambiguous_insertions_refuse(self):
        for raw in ('none',O.SEQUENCE+O.SEQUENCE):
            with self.assertRaises(ValueError):O.consumer(raw)
    def test_source_owned_nonce_has_no_root_or_actual_authority(self):
        with tempfile.TemporaryDirectory(prefix='boot607-nonce-control-') as temporary:
            target=Path(temporary)
            owner=O.Integration(None,None,None,None,lambda:None)
            owner.prepare_nonce(target)
            value=A.decode(A.read(target/'boot607-selection.json'))
            self.assertEqual(value['nonce'],owner.nonce)
            self.assertEqual(value['authority'],'SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION')
            self.assertTrue(all(value[k] is None for k in ('actual_source','actual_ref','actual_run')))
            with self.assertRaises(ValueError):owner.prepare_nonce(target)
    def test_no_positive_receipt_fixture_missing_result_refuses(self):
        owner=O.Integration(None,None,HERE,None,lambda:None)
        for value in (None,{},dict(status='PASS_SIGNED604_TO606_PRIVATE_LIFECYCLE')):
            with self.assertRaises((ValueError,KeyError,TypeError)):owner.validate_boot(value)

if __name__=='__main__':unittest.main(verbosity=2)
