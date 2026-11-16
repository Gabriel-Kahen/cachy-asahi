#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Seal independent local Reader16 template/inverse DATA; never executes Source."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
PROGRAMS=('reader.py','storage.py','bindings.py','evidence.py','archives.py','elf.py')
PREDECESSOR='b26dd9d4680d257de2520f87260eb0c719ff32e6'
PROFILE_PIN=dict(bytes=1831,sha256='b28534a107661ccb790efc9d213eaf975c471d02c14dbd45fc801d3ba2b75e68')
CONSTRUCTOR='56f0a72e01fd7dd76497ffb20003e9c8a5e3a0bc'


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def render():
 old=HERE.parent/'independent_reader_v15'
 previous=json.loads((old/'request.TEMPLATE.json').read_bytes())
 profile_raw=(HERE/'source-profile.DATA.json').read_bytes()
 if pin(profile_raw)!=PROFILE_PIN:raise ValueError('exact stable Source364 constructor profile differs')
 profile=json.loads(profile_raw);contract={k:profile[k]for k in('files','bytes','tree','map_sha256')}
 contract['profile_sha256']=PROFILE_PIN['sha256']
 changes={}
 for name in PROGRAMS:
  before=(old/name).read_bytes();after=(HERE/name).read_bytes()
  if pin(before)!=previous['reader_files'][name]:raise ValueError('held Reader15 body differs')
  changes[name]=dict(before=pin(before),after=pin(after),
                     inverse_body_base64=base64.b64encode(before).decode()if before!=after else None)
 inverse=dict(schema=16,kind='READER16_EXACT_READER15_BYTE_INVERSE_DATA_ONLY',
              predecessor_commit=PREDECESSOR,source_constructor_commit=CONSTRUCTOR,
              source_contract=contract,Root_acceptance=None,files=changes)
 request=dict(previous,schema=16,kind='ROOT_SELECTED_RUST364_RETAINED_EVIDENCE_READER_V16',
              reader_files={n:row['after']for n,row in changes.items()},
              source_contract=contract)
 return {'request.TEMPLATE.json':encoded(request),'inverse.DATA.json':encoded(inverse)}


if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
 for name,raw in render().items():
  if args.write:(HERE/name).write_bytes(raw)
  elif not(HERE/name).exists()or(HERE/name).read_bytes()!=raw:raise ValueError('unsealed local Reader DATA: '+name)
  print(name,len(raw),pin(raw)['sha256'])
