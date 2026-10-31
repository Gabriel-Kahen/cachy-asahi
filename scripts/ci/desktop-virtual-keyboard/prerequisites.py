# SPDX-License-Identifier: MIT
"""Read-only exact installed QEMU/kernel byte guard for the private fixture."""
import hashlib
import json
from pathlib import Path


def verify(root,lock):
    for row in lock['rows']:
        for name,pin in row['leaves'].items():
            path=Path(root)/name
            if path.is_symlink() or not path.is_file() or path.stat().st_size!=pin['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest()!=pin['sha256']:
                raise ValueError('installed keyboard prerequisite differs: '+name)
    return dict(status='EXACT_KEYBOARD_PREREQUISITES',qemu=lock['qemu_version'],kernel=lock['kernel_release'],
                extra_binary_packages=lock['additional_binary_packages'])


if __name__=='__main__':
    print(json.dumps(verify(Path('/'),json.loads(Path('/runner/prerequisites.json').read_text()))))
