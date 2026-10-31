# SPDX-License-Identifier: MIT
"""Execute the exact CLI guard AST with capture replaced; no native actors."""
import argparse,ast,contextlib,io,json,re,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'scripts/ci/management-tools-generic16k/contract.py').is_file())
sys.path.insert(1,str(ROOT/'scripts/ci/management-tools-generic16k'))
import contract as C

class CaptureEntry(unittest.TestCase):
    def entry(self,image='sha256:'+'a'*64,commit='b'*40):
        tree=ast.parse(Path(__file__).with_name('capture.py').read_bytes())
        entry=tree.body[-1];self.assertIsInstance(entry,ast.If)
        self.assertEqual(ast.unparse(entry.test),"__name__ == '__main__'")
        capture=Mock(return_value=dict(status='INERT_CAPTURE_NOT_RUN'))
        scope=dict(argparse=argparse,C=C,s=None,re=re,json=json,Path=Path,capture=capture,__doc__='inert CLI guard control')
        with patch.object(sys,'argv',['capture.py','--image-id',image,'--source-commit',commit]),patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')),contextlib.redirect_stdout(io.StringIO()):
            exec(compile(ast.Module(body=entry.body,type_ignores=[]),'capture.py CLI','exec'),scope)
        return capture
    def test_valid_identities_reach_capture_while_original_support_is_uninitialized(self):
        capture=self.entry();capture.assert_called_once_with(Path('/repo'),'sha256:'+'a'*64,'b'*40)
    def test_mutable_short_and_invalid_image_ids_refuse_before_capture(self):
        for image in ('latest','sha256:'+'a'*63,'sha256:'+'g'*64):
            with self.subTest(image=image),self.assertRaisesRegex(ValueError,'immutable image'):self.entry(image=image)
    def test_missing_short_and_nonhex_source_ids_refuse_before_capture(self):
        for commit in ('main','a'*39,'g'*40):
            with self.subTest(commit=commit),self.assertRaisesRegex(ValueError,'exact source commit'):self.entry(commit=commit)

if __name__=='__main__':unittest.main(verbosity=2)
