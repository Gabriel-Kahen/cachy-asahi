# SPDX-License-Identifier: MIT
"""Finite positive-command diagnostic gate, independent of disposable owner IO."""
import re


def clean_positive(stdout, stderr):
    if re.search(r'^(error\s*:|could not change (?:the root directory|directory))',
                 stdout + '\n' + stderr, re.I | re.M):
        raise ValueError('positive package transaction has ancillary error despite zero exit')
