# SPDX-License-Identifier: MIT
import os
import unittest

from cachy_python_demo import greeting


class DemoTest(unittest.TestCase):
    def test_greeting(self):
        self.assertEqual(greeting(), os.environ['DEMO_EXPECTED'], 'INTENTIONAL_TEST_MISMATCH')


if __name__ == '__main__':
    unittest.main(verbosity=2)
