#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy only owned inert data; no package, container, source-root or service actors."""
import os
import functools
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import full_root as roots
import measure_copy as measure


class CopyMeasurement(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.source=self.base/'source';self.source.mkdir()
        self.target=self.base/'copy'
        original=measure.check_capacity
        real_statvfs=os.statvfs
        def inode_fixture(path):
            info=real_statvfs(path)
            if info.f_favail==0 and info.f_files==0:
                values=list(info);values[5]=values[6]=values[7]=1000000
                return os.statvfs_result(values)
            return info
        self.check=patch.object(measure,'check_capacity',functools.partial(original,statvfs=inode_fixture))
        self.check.start();self.addCleanup(self.check.stop)
        self.limits=roots.Limits(deadline=time.monotonic()+10,max_nodes=100,max_bytes=1024**2,max_file_bytes=1024**2)

    def test_actual_data_copy_records_exclusions_and_measures_only_copy(self):
        (self.source/'data').write_bytes(b'payload')
        (self.source/'tmp').mkdir();(self.source/'tmp/private').write_bytes(b'excluded')
        row=measure.copy_data(self.source,self.target,limits=self.limits,excluded={'tmp'})
        self.assertEqual((self.target/'data').read_bytes(),b'payload')
        self.assertEqual(row['excluded'],['tmp']);self.assertFalse(row['copy_complete'])
        self.assertFalse(row['eligible']);self.assertTrue(row['observation_complete'])
        self.assertEqual(row['footprint']['bytes'],7)
        self.assertFalse((self.target/'tmp').exists())

    def test_links_remain_data_and_unsupported_shapes_are_reported(self):
        (self.source/'data').write_bytes(b'payload');os.link(self.source/'data',self.source/'hard')
        (self.source/'absolute').symlink_to('/outside/never-read')
        os.mkfifo(self.source/'fifo')
        row=measure.copy_data(self.source,self.target,limits=self.limits)
        self.assertEqual((self.target/'data').stat().st_ino,(self.target/'hard').stat().st_ino)
        self.assertEqual(os.readlink(self.target/'absolute'),'/outside/never-read')
        self.assertEqual(row['source_hardlink_entries'],2)
        self.assertEqual(row['unsupported_counts'],{'special-node':1})
        examples={(entry['reason'],entry['path']) for entry in row['unsupported_examples']}
        self.assertIn(('absolute-symlink','absolute'),examples)
        self.assertTrue(any(reason=='hardlink' and path in ('data','hard') for reason,path in examples))
        self.assertTrue(all(set(entry)=={'reason','path'} for entry in row['unsupported_examples']))
        self.assertNotIn('nodes',row)
        self.assertFalse(row['eligible']);self.assertFalse((self.target/'fifo').exists())

    def test_capacity_refuses_before_any_copy_allocation(self):
        with patch.object(measure,'check_capacity',side_effect=ValueError('insufficient')):
            with self.assertRaisesRegex(ValueError,'insufficient'):
                measure.copy_data(self.source,self.target,limits=self.limits)
        self.assertFalse(self.target.exists())

    def test_expired_deadline_refuses_before_allocation(self):
        limits=roots.Limits(deadline=time.monotonic()-1)
        with self.assertRaisesRegex(ValueError,'deadline'):
            measure.copy_data(self.source,self.target,limits=limits)
        self.assertFalse(self.target.exists())

    def test_database_observation_does_not_follow_descriptor_symlink(self):
        local=self.source/'var/lib/pacman/local/package-1';local.mkdir(parents=True)
        (local/'desc').symlink_to('/outside/never-read')
        with self.assertRaises(OSError):measure.copied_inventory(self.source)


if __name__=='__main__':unittest.main(verbosity=2)
