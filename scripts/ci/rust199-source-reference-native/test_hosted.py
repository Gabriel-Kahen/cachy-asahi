# SPDX-License-Identifier: MIT
"""Synthetic DATA gate controls; no transport, daemon, owned child or candidate."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('rust_hosted_data',HERE/'payload/hosted/entry.py');e=importlib.util.module_from_spec(s);s.loader.exec_module(e)


class HostedControls(unittest.TestCase):
    def packet(self,root):
        body=b'SYNTHETIC DATA ONLY\n';(root/'data').write_bytes(body);(root/'data').chmod(0o644)
        m=dict(schema=1,operation=e.OPERATION,actual=dict.fromkeys(('source','ref','run','job','approval','artifact','image')),files={'data':dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),mode=0o644)})
        raw=e.encode(m);(root/'source-map.json').write_bytes(raw);return hashlib.sha256(raw).hexdigest()
    def test_whole_data_map_membership_mode_and_content(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);sha=self.packet(root);e.source_gate(root,sha)
            (root/'empty').mkdir()
            with self.assertRaises(ValueError):e.source_gate(root,sha)
            (root/'empty').rmdir();(root/'extra').write_text('unmapped')
            with self.assertRaises(ValueError):e.source_gate(root,sha)
            (root/'extra').unlink();(root/'data').chmod(0o755)
            with self.assertRaises(ValueError):e.source_gate(root,sha)
            (root/'data').chmod(0o644);(root/'data').write_text('tampered')
            with self.assertRaises(ValueError):e.source_gate(root,sha)
    def test_alias_and_wrong_external_map_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);sha=self.packet(root)
            with self.assertRaises(ValueError):e.source_gate(root,'0'*64)
            (root/'data').unlink();(root/'data').symlink_to('/dev/null')
            with self.assertRaises(ValueError):e.source_gate(root,sha)
    def test_retirement_requires_full_natural_witness(self):
        good=dict(natural_exit=True,forced_cleanup=False,group_absent=True,retirement='REAPED',ownership_lost=False,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True)
        self.assertTrue(e.natural(good))
        for key in good:
            bad=dict(good);bad.pop(key);self.assertFalse(e.natural(bad))
        self.assertFalse(e.natural(dict(good,forced_cleanup=True)))
    def test_workflow_lane_and_refusal_before_transport(self):
        raw=(HERE/'workflow.yml.in').read_text()
        for literal in ('group: native-arm-build','cancel-in-progress: false','queue: max','timeout-minutes: 360','retention-days: 3','rust199-source-reference-native-v1','root_admission_sha256','approval_sha256'):
            self.assertIn(literal,raw)
        code=(HERE/'payload/hosted/entry.py').read_text()
        self.assertLess(code.index('a=gate.validate(a,check_files=True)'),code.index("(work/'job-metadata.json').write_bytes(actual_job(a))"))
        self.assertNotIn('docker.sock',raw)


if __name__=='__main__':unittest.main()
