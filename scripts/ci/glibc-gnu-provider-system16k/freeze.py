#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only local freeze; does not bind future provider artifacts or actors."""
import argparse
import hashlib
import json
from pathlib import Path


def freeze(root):
    here=root/'scripts/ci/glibc-gnu-provider-system16k'
    assert here==Path(__file__).resolve().parent
    original=root/'scripts/ci/glibc-generic16k';base=json.loads((original/'dependencies.json').read_text())['files'];cache=json.loads((original/'input-policy.json').read_text())['kernel_cache']['files']
    names=set(base)|set(cache)|{'scripts/ci/glibc-generic16k/'+n for n in ('common.py','run.py','input-policy.json','dependencies.json')}|{'scripts/ci/glibc-gnu-provider/'+n for n in ('normal_clients.py','normal-client-policy.json','normal-child-exec.patch','provider_stage.py')}|{'scripts/ci/glibc-gnu-provider-lifecycle/'+n for n in ('container.py','common.py')}|{'scripts/ci/glibc-owned-runtime/source-manifest.json'}
    def rows(names):return {n:dict(bytes=(root/n).stat().st_size,sha256=hashlib.sha256((root/n).read_bytes()).hexdigest()) for n in sorted(names)}
    (here/'dependencies.json').write_text(json.dumps(dict(schema_version=1,files=rows(names)),indent=2)+'\n')
    own={str(p.relative_to(root)) for p in here.iterdir() if p.is_file() and p.name!='source-manifest.json'}
    (here/'source-manifest.json').write_text(json.dumps(dict(schema_version=1,scope='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION',provider_inputs=json.loads((here/'input-policy.json').read_text())['status'],files=rows(names|own)),indent=2)+'\n')
    return dict(status='FROZEN_SOURCE_ONLY_INPUT_BINDING_NOT_GRANTED',dependencies=len(names),manifest_files=len(names|own))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);a=p.parse_args();print(json.dumps(freeze(a.source_root.absolute())))
