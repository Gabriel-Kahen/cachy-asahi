# SPDX-License-Identifier: MIT
"""Validate emitted ordinary DATA only; never infer a native result or dispatch."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import adapter as A

def inspect(source):
    here = source / 'scripts/ci/client-v3-native'
    manifest = json.loads((here / 'source-manifest.json').read_bytes())
    policy = json.loads((here / 'input-policy.json').read_bytes())
    assert manifest['schema_version'] == 1 and 0 < len(manifest['files']) <= 128
    for name, row in manifest['files'].items():
        path = source / name
        assert not any(p.is_symlink() for p in (path, *path.parents)) and path.stat().st_nlink == 1
        assert dict(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest()) == row
    assert policy['purpose'] == 'CLIENT_V3_RUNTIME_FRESH_COMPONENT_V1' and set(policy['products']) == {'runtime', 'client'}
    assert policy['native_source'] is policy['actual_run'] is policy['native_authority'] is policy['resource_authority'] is None
    if policy['status'] == 'UNBOUND_CLIENT_V3_COMPONENT':
        assert policy['candidate_source'] is None and all(r['source_sha'] is None for r in policy['products'].values())
    elif policy['status'] == 'ROOT_BOUND_FINAL_PRODUCT_SOURCES':
        C = A.module(source, 'contract.py')
        C.verify_source(source)
        for name in C.NAMES:
            C.recipe(source, name)
    else:
        raise ValueError('unknown source calibration status')
    for name in ('contract.py', 'run.py', 'job.py'):
        compile(A.text(source, name), name, 'exec')
    return dict(status='PASS_SOURCE_ONLY_TWO_PRODUCT_COMPONENT', files=len(manifest['files']), native_source=None,
                run=None, native='NOT_RUN', ALPM='NOT_RUN', hardware='NOT_RUN', version_upgrade='NOT_RUN')

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--source', type=Path, required=True)
    print(json.dumps(inspect(p.parse_args().source.absolute()), sort_keys=True))
