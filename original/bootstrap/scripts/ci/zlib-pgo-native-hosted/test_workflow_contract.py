# SPDX-License-Identifier: MIT
"""Passive workflow/refusal controls; never invoke native actors or credentials."""
import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_pgo_workflow_contract',HERE/'workflow_contract.py')
W=importlib.util.module_from_spec(spec);spec.loader.exec_module(W)


class WorkflowControls(unittest.TestCase):
    def setUp(self):
        self.text=(HERE/'workflow.yml.in').read_text();self.reference=W.REFERENCE.read_text()
        self.enterContext(patch.object(socket,'socket',side_effect=AssertionError('network forbidden')))
        for name in('Popen','run','check_output'):self.enterContext(patch.object(subprocess,name,side_effect=AssertionError('actors forbidden')))

    def refuse(self,text):
        with self.assertRaises(ValueError):W.validate(text,self.reference)

    def test_finite_single_source_workflow_and_budget_slack(self):
        report=W.validate(self.text,self.reference)
        self.assertEqual(report['steps'],13);self.assertEqual(report['existing_private_secret_references'],22)
        self.assertEqual(report['job_minutes']-report['sum_step_minutes'],2)
        self.assertIsNone(report['actual']);self.assertEqual(report['native_execution'],'NOT RUN')
        self.assertNotIn('feature_code_sha',self.text)

    def test_existing_transport_rows_pins_and_secret_set_are_held(self):
        _,rows=W.steps(self.text);_,old=W.steps(self.reference)
        name='Seed the six exact retained inputs using existing secrets only'
        self.assertEqual(dict(rows)[name],dict(old)[name])
        for before,after in [
            ('ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad','f'*40),
            ('04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd','f'*40),
            ('a7857658af224984065e575f6ffed8308ea85027d46eace8bda146d9033e93b3','f'*64),
            ('CACHY_OLD_FOUR_SCHEMA: \'1\'','CACHY_OLD_FOUR_SCHEMA: \'2\''),
            ('secrets.CACHY_OLD_FOUR_LIBTIFF_15','secrets.NEW_UNREVIEWED_SECRET')]:
            with self.subTest(before=before):self.refuse(self.text.replace(before,after))
        with self.assertRaises(ValueError):W.validate(self.text,self.reference+'\n')

    def test_presecret_proof_and_new_only_controls_cannot_move_after_transport(self):
        head,rows=W.steps(self.text);changed=list(rows);changed[1],changed[3]=changed[3],changed[1]
        self.refuse(head+''.join(row for _,row in changed))
        self.refuse(self.text.replace('test "$GITHUB_WORKFLOW_SHA" = "$SOURCE_SHA"','true'))
        self.refuse(self.text.replace('discover -s "$SLICE"','discover -s pgo-source'))

    def test_cleanup_retention_order_and_always_guards_are_required(self):
        head,rows=W.steps(self.text);changed=list(rows);changed[10],changed[11]=changed[11],changed[10]
        self.refuse(head+''.join(row for _,row in changed))
        self.refuse(self.text.replace("if: always() && steps.proof.outcome == 'success'","if: success()",1))
        self.refuse(self.text.replace('python3 -I -B "$SLICE/owner.py" cleanup','true # cleanup removed'))
        self.refuse(self.text.replace('    timeout-minutes: 135','    timeout-minutes: 115'))

    def test_synthetic_image_lock_or_extra_checkout_inputs_refuse(self):
        extra='      image:\n        type: string\n        default: sha256:'+'a'*64+'\n'
        self.refuse(self.text.replace('permissions:\n',extra+'permissions:\n',1))
        self.refuse(self.text.replace('owner.py" pairs','owner.py" pairs --image sha256:'+'a'*64))
        self.refuse(self.text.replace('--cache "$RUNNER_TEMP/alarm-cache"','--expected-packages synthetic-three-package.lock --cache "$RUNNER_TEMP/alarm-cache"',1))
        self.refuse(self.text.replace('ref: ${{ inputs.source_sha }}','ref: main',1))

    def test_both_rendered_aliases_are_byte_exact(self):
        rendered=W.render('1'*64,'2'*64,self.text);aliases={name:rendered for name in W.ALIASES}
        self.assertEqual(W.check_aliases(aliases,'1'*64,'2'*64)['bytes'],len(rendered))
        aliases[W.ALIASES[1]]+=b'\n'
        with self.assertRaises(ValueError):W.check_aliases(aliases,'1'*64,'2'*64)
        with self.assertRaises(ValueError):W.check_aliases({W.ALIASES[0]:rendered},'1'*64,'2'*64)
        with self.assertRaises(ValueError):W.render('0'*64,'2'*64,self.text)

    def test_root_dispatch_requires_a_concrete_single_published_source(self):
        report=W.dispatch_contract('3'*40)
        self.assertEqual(report['inputs'],dict(source_sha='3'*40));self.assertIsNone(report['actual'])
        self.assertEqual(report['image'],'FRESH_OWNED_PRODUCER_RUNTIME_RECEIPT_ONLY')
        self.assertEqual(report['packages'],'FULL_FRESH_PRODUCER_PACKAGES_LOCK_ONLY')
        for value in(None,'0'*40,'main','3'*39,'G'*40):
            with self.subTest(value=value),self.assertRaises(ValueError):W.dispatch_contract(value)


if __name__=='__main__':unittest.main()
