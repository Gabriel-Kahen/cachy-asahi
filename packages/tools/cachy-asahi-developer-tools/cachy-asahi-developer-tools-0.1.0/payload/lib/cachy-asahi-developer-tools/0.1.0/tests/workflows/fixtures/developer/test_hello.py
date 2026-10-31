# SPDX-License-Identifier: MIT
import unittest
from hello import message

class HelloTest(unittest.TestCase):
    def test_message(self):
        self.assertEqual(message(), 'Hello from cachy-asahi')

if __name__ == '__main__':
    unittest.main()
