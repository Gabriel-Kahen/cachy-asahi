#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Seal independent local Reader17 template/inverse DATA; never executes Source."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
PROGRAMS=('reader.py','storage.py','bindings.py','evidence.py','archives.py','elf.py')
PREDECESSOR='04345bbe82fd8e0571bb454589d4dd82b271b8a8'
PROFILE_PIN=dict(bytes=1831,sha256='9b6410c6def95e8eb68cee44930ecab1f8a7c281432d71ae04d81b09c695c827')
CONSTRUCTOR='bcbbc44095c301c9ec1a83ad5b0cb460db337603'


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def render():
 old=HERE.parent/'independent_reader_v16'
 previous=json.loads((old/'request.TEMPLATE.json').read_bytes())
 profile_raw=(HERE/'source-profile.DATA.json').read_bytes()
 if pin(profile_raw)!=PROFILE_PIN:raise ValueError('exact stable Source367 constructor profile differs')
 profile=json.loads(profile_raw);contract={k:profile[k]for k in('files','bytes','tree','map_sha256')}
 contract['profile_sha256']=PROFILE_PIN['sha256']
 changes={}
 for name in PROGRAMS:
  before=(old/name).read_bytes();after=(HERE/name).read_bytes()
  if pin(before)!=previous['reader_files'][name]:raise ValueError('held Reader16 body differs')
  changes[name]=dict(before=pin(before),after=pin(after),
                     inverse_body_base64=base64.b64encode(before).decode()if before!=after else None)
 inverse=dict(schema=17,kind='READER17_EXACT_READER16_BYTE_INVERSE_DATA_ONLY',
              predecessor_commit=PREDECESSOR,source_constructor_commit=CONSTRUCTOR,
              source_contract=contract,Root_acceptance=None,files=changes)
 request=dict(previous,schema=17,kind='ROOT_SELECTED_RUST367_RETAINED_EVIDENCE_READER_V17',
              reader_files={n:row['after']for n,row in changes.items()},
              source_contract=contract)
 return {'request.TEMPLATE.json':encoded(request),'inverse.DATA.json':encoded(inverse)}


if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
 for name,raw in render().items():
  if args.write:(HERE/name).write_bytes(raw)
  elif not(HERE/name).exists()or(HERE/name).read_bytes()!=raw:raise ValueError('unsealed local Reader DATA: '+name)
  print(name,len(raw),pin(raw)['sha256'])
