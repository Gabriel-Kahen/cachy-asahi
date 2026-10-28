# SPDX-License-Identifier: MIT
"""Reuse the whole accepted public-pair input builder and exact Apps plan body."""
import copy,types
from pathlib import Path
import coexist_plan as P
APPS_FILES=frozenset(('usr/bin/cachy-asahi-apps','usr/lib/cachy-asahi-apps/apps.py','usr/lib/cachy-asahi-apps/inventory.py','usr/lib/cachy-asahi-apps/helper-pins.json','usr/share/doc/cachy-asahi-apps/README.md','usr/share/doc/cachy-asahi-apps/source-provenance.json','usr/share/licenses/cachy-asahi-apps/LICENSE','usr/share/licenses/cachy-asahi-apps/NOTICE'))
def make(guard,anchor,packet,ready604,output,producer,original_api):
 C,_,I=anchor.builds.apis();C2=types.SimpleNamespace(**dict(vars(C),APPS_FILES=APPS_FILES));plan=guard.module('_whole_accepted_apps350_archive_plan',guard.HERE/'held/apps_plan.py',{'contract':C2})
 # Original complete196 public-pair closure, source/payload/native decisions,
 # old606 restoration operands, signatures and Runtime1 source joins execute.
 with anchor.builds.aliases({'contract':C2,'plan':plan}):
  legacy=I.legacy();value=legacy.make(packet=packet/'payload',ready604=ready604,output=output)
 P.need(value['runtime']['sha256']=='1c8a9149da02e60a4c14598cdf7007d6dbffcd6150757fcf6711977aa00cf8aa'and value['new7']['sha256']=='23fc2fe5707606b0f3bd8c6322b9e7ae0c47a6ff1024cd239f4486679638be39','whole accepted Apps7/Runtime1 archive identities')
 # Retain the accepted archive bytes; use only the already-owned native TEST
 # signer so the existing consumer verification home needs no new trust key.
 original=legacy.original_key(ready604,C.decode(C.ordinary(ready604/'manifest.json',16*1024**2)),value['original6']['signer'])
 candidate=output/'archives'/Path(value['new7']['path']).name
 signing=types.FunctionType(I.sign_candidate.__code__,dict(vars(I),ARCHIVE=dict(bytes=23212,sha256='23fc2fe5707606b0f3bd8c6322b9e7ae0c47a6ff1024cd239f4486679638be39')),'whole_original_sign_candidate')
 signed=signing(path=candidate,output=output,source=guard.ROOT/'held606',producer=producer,original_public=original,signer_fingerprint=value['original6']['signer'],original_api=original_api)
 import shutil
 sig=candidate.with_name(candidate.name+'.sig');shutil.copyfile(signed.with_name(signed.name+'.sig'),sig)
 value['new7']['signature'].update(C.pin(C.ordinary(sig,65536)));value['new7']['signer']=value['original6']['signer'];shutil.rmtree(output/'signing')
 (output/'lifecycle-plan.json').write_bytes(C.encoded(value));return value

def products(plan,prefix,roles):
 out={name:copy.deepcopy(plan[key])for name,key in roles.items()}
 for product in out.values():
  for row in(product,product['signature']):P.need(row['path'].startswith('/runner/inputs/archives/'),'original exact input namespace');row['path']=row['path'].replace('/runner/inputs/archives/',prefix,1)
 return out
