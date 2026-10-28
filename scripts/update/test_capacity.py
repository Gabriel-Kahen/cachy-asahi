#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import types
import unittest
from unittest.mock import patch
from capacity import check


class Capacity(unittest.TestCase):
    def rows(self): return [dict(path='/root',bytes=60,inodes=4),dict(path='/work',bytes=50,inodes=4)]

    def test_shared_filesystem_demand_is_combined_not_individually_passed(self):
        with patch('capacity.Path.stat',return_value=types.SimpleNamespace(st_dev=1)), \
             patch('capacity.os.statvfs',return_value=types.SimpleNamespace(f_bavail=100,f_frsize=1,f_favail=9)):
            with self.assertRaisesRegex(ValueError,'insufficient'): check(self.rows())

    def test_different_filesystems_use_independent_capacity(self):
        with patch('capacity.Path.stat',side_effect=[types.SimpleNamespace(st_dev=1),types.SimpleNamespace(st_dev=2)]), \
             patch('capacity.os.statvfs',return_value=types.SimpleNamespace(f_bavail=100,f_frsize=1,f_favail=9)):
            self.assertEqual(len(check(self.rows())),2)

    def test_inode_exhaustion_refuses_even_with_bytes_free(self):
        with patch('capacity.Path.stat',return_value=types.SimpleNamespace(st_dev=1)), \
             patch('capacity.os.statvfs',return_value=types.SimpleNamespace(f_bavail=1000,f_frsize=1,f_favail=7)):
            with self.assertRaisesRegex(ValueError,'insufficient'): check(self.rows())

    def test_invalid_negative_demand_refuses(self):
        with self.assertRaises(ValueError): check([dict(path='/unused',bytes=-1,inodes=0)])


if __name__=='__main__': unittest.main(verbosity=2)
