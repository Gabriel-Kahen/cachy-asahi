# SPDX-License-Identifier: MIT
"""Pure primitives for a separately Root-bound native container entry proposal.

No process launch, sandbox selection, source extraction or admission authority.
Passing synthetic DATA is never evidence that a native domain was observed.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FROZEN = HERE.parent


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def contract(root=FROZEN):
    """Verify frozen source bytes before exposing their fixed phase commands."""
    data = json.loads((HERE/'contract.json').read_bytes())
    for name, expected in data['frozen_files_sha256'].items():
        path = root/name
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise ValueError('frozen LLVM source contract changed: '+name)
    return data


def phase_command(phase):
    data = contract()
    if phase not in data['phases']:
        raise ValueError('fixed probe/tools/runtimes/check phase required')
    return list(data['phases'][phase]['argv'])


def inspector():
    """Load only the authenticated pure checks; never call the frozen runner."""
    contract()
    spec = importlib.util.spec_from_file_location('frozen_llvm23_inspector', FROZEN/'reference.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect_stage(root):
    """Inspect an already staged tree as DATA, without executing its binaries."""
    checks = inspector()
    checks.check_stage(Path(root))
    return {'scope':'STATIC_STAGE_ONLY', 'staged_tree_sha256':checks.tree_digest(Path(root)),
            'native_execution':'NOT_ESTABLISHED', 'domain_admission':'NOT_ESTABLISHED'}
