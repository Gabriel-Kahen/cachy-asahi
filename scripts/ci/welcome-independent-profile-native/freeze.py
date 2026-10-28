#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root's finite source freeze; never builds, signs or dispatches."""
import argparse
from pathlib import Path
import contract as K


def freeze(source):
    K.policy();K.need(K.HERE==source/K.NAMESPACE,'freeze only the adopted namespace')
    pins=K.read(K.HERE/'source-pins.json')['files'];K.files(source,pins)
    names=set(pins)|{K.NAMESPACE+'/'+p.name for p in K.HERE.iterdir() if p.is_file() and p.name!='source-manifest.json'}
    value=dict(schema_version=1,status='FROZEN_ROOT_INDEPENDENT_PROFILE_SOURCE',files={name:K.pin(source/name) for name in sorted(names)},native='NOT_RUN',hardware='NOT_RUN')
    K.need(len(names)<=512,'independent source closure cap');manifest=K.HERE/'source-manifest.json';manifest.write_bytes(K.encoded(value))
    workflow=source/'.github/workflows/native-arm-welcome-independent-profile.yml';text=workflow.read_text()
    for marker,path in (('@JOB_SHA256@',K.HERE/'job.py'),('@MANIFEST_SHA256@',manifest)):
        K.need(text.count(marker)==1,'explicit workflow freeze marker required');text=text.replace(marker,K.pin(path)['sha256'])
    workflow.write_text(text);return dict(status='SOURCE_ONLY_FROZEN',files=len(names),manifest_sha256=K.pin(manifest)['sha256'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);a=p.parse_args();print(K.encoded(freeze(a.source.absolute())).decode())
