#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Root's adopted-source freeze only; no native/signing/build/daemon actors."""
import argparse,json
from pathlib import Path
import contract as C

def freeze(root):
 binding=C.policy();C.need(root/C.LANE==C.HERE,'freeze only adopted canonical lane after Root binding')
 C.checked(root,binding['adapter']);names=set(C.decode(C.read(C.HERE/'dependency-paths.json'))['files'])
 names|={p.relative_to(root).as_posix() for p in C.HERE.iterdir() if p.is_file() and p.name!='source-manifest.json'}
 names|={'scripts/apps/file_capabilities.py','scripts/apps/test_file_capabilities.py',C.LANE+'/export_extract.py'}
 names.add('.github/workflows/native-arm-apps-full574-transaction.yml');C.need(1<=len(names)<=256,'closed source cap')
 value=dict(schema_version=1,status='FROZEN_NATIVE574_APPS_SOURCE',native='NOT_RUN',hardware='NOT_RUN',files={n:{k:v for k,v in C.ref(root,root/n).items() if k!='path'} for n in sorted(names)})
 C.save(C.HERE/'source-manifest.json',value);C.source(root)
 return dict(status='FROZEN_SOURCE_ONLY',files=len(names),source_manifest_sha256=C.sha(C.read(C.HERE/'source-manifest.json')),native='NOT_RUN',hardware='NOT_RUN')
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True);args=parser.parse_args();print(json.dumps(freeze(C.safe(args.source)),sort_keys=True))
