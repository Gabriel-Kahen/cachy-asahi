# SPDX-License-Identifier: MIT
"""Controls for emitting the next positive Reader with original rich cleanup rows."""

import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import seal_cleanup_reader as C
from fresh606 import load
from seal_fresh606_reader import files_at


OLD_VERIFY = b'''
def cleanup_order(gui):
 rows=gui['cleanup'];H.need(len(rows)==15,'all original14 plus controller-image cleanup')
 # Preserve the complete original reverse consumer/container and base-alias
 # sequence, with exactly one additional controller image at the image seam.
 baseline=H.load('_current606_original_cleanup_semantics',H.HERE/'baseline/verify.py');copy=dict(gui);image=gui['controller_image'];extra=dict(action='remove-image:'+image,exit=0);H.need(rows.count(extra)==1 and image not in(gui['runtime_image'],gui['base_image']),'one distinct extra owned controller image');copy['cleanup']=[r for r in rows if r!=extra];baseline.cleanup_order(copy)


def verify(gui, root):
    H.need(gui['status'].startswith('PASS_'), 'positive requires success');cleanup_order(gui)
    return 'retained positive caller'
'''

SOURCE = {C.ACTOR: C.ACTOR_PIN}
ACTOR = load('_exact_cleanup_producer', HERE/'failure-cleanup-payload'/C.ACTOR)


class CleanupReceipts(unittest.TestCase):
    def setUp(self):
        runtime, controller, base = ['sha256:'+c*64 for c in 'abc']
        ref = 'cachy-asahi-desktop574-base:'+'d'*32
        containers = ['desktop574-config-'+'1'*32, 'desktop574-fixture-'+'2'*16,
                      'desktop574-vm-'+'3'*16]
        acquire = ACTOR.plan(containers,[runtime,controller],base,ref,True)
        self.gui = dict(status='PASS_CURRENT606_WELCOME8_GENERIC16K_GUI_METADATA', runtime_image=runtime,
                        controller_image=controller, base_image=base, base_reference=ref,
                        base_reference_cleanup=dict(ok=True,base_image_present=True), resource_acquisition=acquire)
        actions = [prefix+name for name in reversed(containers) for prefix in ('remove-container:','check-container:')]
        actions += ['remove-image:'+runtime,'remove-image:'+controller,'remove-fixture','remove-cleaner',None,
                    'check-base-alias','remove-base-alias','check-base-alias-absent','check-base-image-after-alias']
        self.bare = [dict(action=name,exit=0) if name is not None else dict(guest_disk_removed=True) for name in actions]
        self.gui['cleanup'] = [dict(row,**ACTOR.output((base+'\n').encode() if i in (11,14) else b''))
                               if i!=10 else dict(row) for i,row in enumerate(self.bare)]
        def baseline(value):
            self.assertEqual(value,dict(self.gui,cleanup=self.bare[:7]+self.bare[8:]))
        def load(name,path):
            return ACTOR if path==HERE/C.ACTOR else SimpleNamespace(cleanup_order=baseline)
        self.h = SimpleNamespace(need=C.need,load=load,HERE=HERE)

    def method(self, raw):
        namespace = {'H':self.h}
        exec(compile(raw,'<emitted-verify.py>','exec'),namespace)
        return namespace['verify']

    def test_assembled_positive_caller_validates_original_receipts_and_preserves_bare_history(self):
        historical = self.method(OLD_VERIFY)
        self.assertEqual(historical(dict(self.gui,cleanup=self.bare),HERE),'retained positive caller')
        with self.assertRaisesRegex(ValueError,'one distinct extra owned controller image'):
            historical(self.gui,HERE)
        retained = copy.deepcopy(self.gui)
        revised = self.method(C.patch_verify(OLD_VERIFY,SOURCE))
        self.assertEqual(revised(self.gui,HERE),'retained positive caller')
        self.assertEqual(self.gui,retained)

    def test_closed_receipt_stdout_actions_image_reuse_and_absence(self):
        revised = self.method(C.patch_verify(OLD_VERIFY,SOURCE))
        for mutate,reason in (
            (lambda x:x['cleanup'][7].update(stdout_base64='YQ=='),'stdout identity'),
            (lambda x:x['cleanup'][7].update(foreign=True),'command receipt schema'),
            (lambda x:x['cleanup'].__setitem__(slice(6,8),x['cleanup'][6:8][::-1]),'controller image seam'),
            (lambda x:x.update(controller_image=x['runtime_image']),'exact original cleanup acquisitions'),
            (lambda x:x['cleanup'][10].update(guest_disk_removed=1),'all original 15'),
            (lambda x:x['cleanup'][14].update(ACTOR.output((x['base_image']+'\n'+x['runtime_image']+'\n').encode())),
             'both owned images absent'),
        ):
            with self.subTest(reason=reason):
                changed = copy.deepcopy(self.gui)
                mutate(changed)
                with self.assertRaisesRegex(ValueError,reason):
                    revised(changed,HERE)

    def test_failure_remains_a_separate_retirement_path(self):
        failed = dict(self.gui,status='FAIL')
        revised = self.method(C.patch_verify(OLD_VERIFY,SOURCE))
        with self.assertRaisesRegex(ValueError,'positive requires success'):
            revised(failed,HERE)
        self.assertEqual(ACTOR.retired(failed)['status'],'PASS_FAILED_GUI_OWNED_RESOURCE_RETIREMENT_ONLY')
        with self.assertRaisesRegex(ValueError,'failed GUI only'):
            ACTOR.retired(self.gui)

    def test_explicit_emission_preserves_whole_roster_and_all_other_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            reader=root/'reader'
            reader.mkdir()
            known=C.encoded(dict(workflow_id=None,runs=dict.fromkeys(C.CASES)))
            for name,raw in {
                'verify.py':OLD_VERIFY,'known-source.json':known,'binding-template.json':known,
                'reader-profile.json':C.encoded(dict(actual=None,source_path=str(root/'source'),
                                                     original_assets=str(root/'assets'),source_files=SOURCE)),
                'failure_reader.py':b'# separate frozen failure route\n',
            }.items():
                (reader/name).write_bytes(raw)
            before=files_at(reader)
            anchor=C.pin(C.encoded(before))['sha256']
            output=root/'next-reader'
            with self.assertRaisesRegex(ValueError,'map differs'):
                C.emit(reader,'0'*64,output)
            self.assertFalse(output.exists())
            report=C.emit(reader,anchor,output)
            after=files_at(output)
            self.assertEqual(files_at(reader),before)
            self.assertEqual(report['changed'],{'verify.py':after['verify.py']})
            self.assertEqual({n for n in after if before[n]!=after[n]},{'verify.py'})
            self.assertIsNone(report['actual'])
            self.assertIsNone(report['authority'])

    def test_wrong_producer_and_wrong_predecessor_verify_body_refuse(self):
        with self.assertRaisesRegex(ValueError,'exact source-owned'):
            C.patch_verify(OLD_VERIFY,{})
        with self.assertRaisesRegex(ValueError,'exact historical cleanup method'):
            C.patch_verify(OLD_VERIFY.replace(b'original14',b'changed14'),SOURCE)


if __name__ == '__main__':
    unittest.main()
