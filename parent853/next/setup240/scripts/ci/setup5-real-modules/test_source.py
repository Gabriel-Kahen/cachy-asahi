# SPDX-License-Identifier: MIT
"""Inert pin, extraction, routing, and preservation controls; no shell actors."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
import run

SOURCE=run.safe(Path(os.environ['SETUP5_SOURCE']))
ACCEPTED=run.safe(Path(os.environ['SETUP5_ACCEPTED_INPUTS']))
CONTROL=run.safe(Path(os.environ['SETUP5_CONTROL_ROOT']))


class SourceControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=CONTROL)
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def copied_inputs(self):
        return Path(shutil.copytree(ACCEPTED,self.root/'accepted'))

    def test_dependency_and_driver_pin_closure(self):
        pins=json.loads((run.HERE/'source-manifest.json').read_text())
        self.assertEqual(len(pins['files']),86)
        self.assertEqual(sum(n.startswith('packages/') for n in pins['files']),82)
        for names,base in ((pins['files'],SOURCE),(pins['driver_files'],run.HERE)):
            for name,row in names.items():
                path=run.safe(base/name)
                self.assertEqual(path.stat().st_size,row['bytes'],name)
                self.assertEqual(run.digest(path),row['sha256'],name)

    def test_exact_accepted_cli_extracted_without_other_package_members(self):
        target,provenance=run.accepted_cli(ACCEPTED,self.root)
        self.assertEqual(list(self.root.iterdir()),[target])
        self.assertEqual(run.digest(target),run.CLI_SHA)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o755)
        self.assertEqual(provenance['native_input_run'],38934198468)

    def test_changed_index_refused_without_publishing_cli(self):
        root=self.copied_inputs();(root/'index.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'index identity'):run.accepted_cli(root,self.root)
        self.assertFalse((self.root/'accepted-setup5-cli').exists())

    def test_extra_ordinary_member_refused(self):
        root=self.copied_inputs();(root/'extra').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError,'closure'):run.accepted_cli(root,self.root)
        self.assertFalse((self.root/'accepted-setup5-cli').exists())

    def test_extra_directory_alias_refused(self):
        root=self.copied_inputs();(root/'alias').symlink_to(root/'source',target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'ordinary bounded'):run.accepted_cli(root,self.root)
        self.assertFalse((self.root/'accepted-setup5-cli').exists())

    def test_same_size_payload_mutation_refused(self):
        root=self.copied_inputs();index=json.loads((root/'index.json').read_text())
        name='source/cachy-asahi-setup/cachy-asahi-setup';self.assertIn(name,index['files'])
        path=root/name;raw=path.read_bytes();path.write_bytes(bytes([raw[0]^1])+raw[1:])
        with self.assertRaisesRegex(ValueError,'member bytes'):run.accepted_cli(root,self.root)
        self.assertFalse((self.root/'accepted-setup5-cli').exists())

    def test_safe_rejects_parent_alias_and_parent_traversal(self):
        (self.root/'real').mkdir();(self.root/'alias').symlink_to(self.root/'real',target_is_directory=True)
        for path in (self.root/'alias'/'file',self.root/'real'/'..'/'file'):
            with self.assertRaisesRegex(ValueError,'ordinary absolute'):run.safe(path)

    def test_snapshot_detects_user_bytes_and_modes(self):
        path=self.root/'user';path.write_text('preserve');before=run.snapshot(self.root)
        path.write_text('Preserve');self.assertNotEqual(run.snapshot(self.root),before)
        before=run.snapshot(self.root);path.chmod(0o600);self.assertNotEqual(run.snapshot(self.root),before)

    def test_snapshot_refuses_oversize_regular_file(self):
        (self.root/'too-large').write_bytes(b'x'*(1024**2+1))
        with self.assertRaisesRegex(ValueError,'bounded private'):run.snapshot(self.root)

    def test_reverse_fish_request_routes_complete_generated_config(self):
        homes=run.SetupHomes(self.root/'cli',self.root/'templates',self.root)
        paths=[SOURCE/('packages/tools/cachy-asahi-'+n+'/opt-in.fish') for n in ('fish-done','fish-autopair')]
        paths+=[SOURCE/'packages/shells/cachy-asahi-fish-bang-bang/opt-in.fish']
        target=homes.combined(self.root,'fish-request.fish',paths)
        self.assertEqual(target,self.root/'fish-request/config/fish/config.fish')
        self.assertEqual(homes.pending[self.root/'fish-request'],('fish-done','fish-autopair','fish-bang-bang',*run.MODULES[3:]))
        self.assertFalse(target.exists())

    def test_zsh_alias_only_identifies_selection_and_returns_real_zshrc(self):
        homes=run.SetupHomes(self.root/'cli',self.root/'templates',self.root);home=self.root/'zsh-request';home.mkdir()
        called=[];homes.activate=lambda home,selected:called.append((home,selected))
        target=homes.combined(self.root,'zsh-request.zsh',[self.root/'highlight-runtime/opt-in.zsh'])
        self.assertEqual(target,home/'.zshrc');self.assertEqual(called[0][1][0],'zsh-syntax-highlighting')
        self.assertEqual(set(called[0][1]),set(run.MODULES))

    def test_unknown_module_source_refused(self):
        homes=run.SetupHomes(self.root/'cli',self.root/'templates',self.root)
        with self.assertRaisesRegex(ValueError,'one known module'):homes.combined(self.root,'fish.fish',[self.root/'unknown.fish'])

    def test_reused_preservation_check_detects_post_activation_user_edit(self):
        C=run.load('control_existing_coexistence',SOURCE/'scripts/ci/shell-modules-coexistence/run.py')
        homes=run.SetupHomes(self.root/'cli',self.root/'templates',self.root)
        D,_=run.fixture_modules(C,SOURCE,homes);home=D.prepare(self.root,'preserve-control')
        path=home/'config/fish/config.fish';generated=run.USER_CONFIG+'# captured generated bytes\n';path.write_text(generated);homes.expected[home]=generated
        D.preserved(home)
        path.write_text(generated+'# subsequent user edit\n')
        with self.assertRaisesRegex(ValueError,'config changed'):D.preserved(home)


if __name__=='__main__':unittest.main()
