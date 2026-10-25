# SPDX-License-Identifier: MIT
"""Inert containment/preservation controls; real composition is run.py's PTYs."""
from pathlib import Path
import tempfile
import unittest
import run


class SourceControls(unittest.TestCase):
    def test_new_bindings_allowed_but_any_old_binding_change_refused(self):
        with tempfile.TemporaryDirectory() as root:
            before=Path(root)/'before';after=Path(root)/'after'
            before.write_text('# source before\nbind ctrl-g custom\nbind --preset tab complete\n')
            after.write_text('# source after\nbind ctrl-g custom\nbind --preset tab complete\nbind ! added\n')
            self.assertTrue(run.binding_subset(before,after))
            after.write_text('bind ctrl-g overwritten\nbind --preset tab complete\n')
            self.assertFalse(run.binding_subset(before,after))

    def test_source_snapshot_rejects_symlink_before_runtime_import(self):
        with tempfile.TemporaryDirectory() as root:
            source=Path(root)/'source';out=Path(root)/'out';source.mkdir();out.mkdir()
            directory=sorted({str(Path(p).parent) for p in (*run.FISH.values(),*run.ZSH.values())})[0]
            package=source/directory;package.mkdir(parents=True);(package/'bad').symlink_to('/nonexistent')
            with self.assertRaisesRegex(ValueError,'ordinary'):run.freeze_inputs(source,out)

    def test_source_snapshot_rejects_mismatched_local_hashes(self):
        with tempfile.TemporaryDirectory() as root:
            source=Path(root)/'source';out=Path(root)/'out';source.mkdir();out.mkdir()
            directory=sorted({str(Path(p).parent) for p in (*run.FISH.values(),*run.ZSH.values())})[0]
            package=source/directory;package.mkdir(parents=True);(package/'one').write_text('changed')
            (package/'PKGBUILD').write_text("source=('one')\nsha256sums=('"+'0'*64+"')\n")
            with self.assertRaisesRegex(ValueError,'checksum'):run.freeze_inputs(source,out)


if __name__=='__main__':unittest.main()
