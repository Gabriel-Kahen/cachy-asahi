# SPDX-License-Identifier: MIT
import sys

def message():
    return 'Hello from cachy-asahi'

if __name__ == '__main__':
    assert sys.prefix != sys.base_prefix, 'execute inside the private venv'
    print(message())
