# SPDX-License-Identifier: MIT
"""Pure fixed94 DATA projection after the separate complete authority gates."""
import json,os
from pathlib import Path
import common as C

def emit(carrier,target):
 carrier,target=map(C.safe,(carrier,target));before=C.rows(carrier);C.need(before==C.profile()['apps16_input_files'],'whole source-bound94 native/recipe DATA');C.need(not os.path.lexists(target)and target.parent.is_dir()and all(target!=r and r not in target.parents and target not in r.parents for r in(carrier,C.ROOT)),'fresh disjoint selected pair DATA output');descriptor=json.loads(C.read(C.HERE/'selected-input.json'));pairs=[]
 for side in('a','b'):
  for tail in('packages/cachy-asahi-apps-'+side+'/cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz','runtime/cachy-asahi-apps-'+side+'/provenance.json','runtime/cachy-asahi-apps-'+side+'/expected-packages.lock'):pairs.append(('native/'+tail,'public/'+tail))
 for n in descriptor['source_files']:pairs.append(('recipe-source/packages/tools/cachy-asahi-apps16/'+n,'public/source/cachy-asahi-apps/'+n))
 values={dest:C.checked(carrier/src,before[src])for src,dest in pairs};C.need(before==C.rows(carrier),'late whole source DATA drift before output');target.mkdir(mode=0o700)
 for n,b in values.items():p=target/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
 (target/'public-build-evidence.json').write_bytes(C.enc(descriptor['build_evidence']));C.need(before==C.rows(carrier),'whole source DATA preserved');return target
