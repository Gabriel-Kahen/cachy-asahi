#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded host plumbing fixture, not a distribution performance benchmark."""
import hashlib
import os
import time

assert os.environ['MEASUREMENT_CONTROL'] in ('baseline', 'candidate')
assert hashlib.sha256(b'cachy-asahi fixture').hexdigest() == '9b208d277b7253803c4e665114c44ce375b2e22cf60299459f3b8989ec8c0b7d'
time.sleep(0.24 if os.environ['MEASUREMENT_CONTROL'] == 'baseline' else 0.12)
print('fixed host-only fixture complete')
