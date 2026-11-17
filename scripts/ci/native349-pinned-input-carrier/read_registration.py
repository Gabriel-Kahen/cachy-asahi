#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Project the frozen bounded registration reader into this one new workflow."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
FROZEN=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-native-canonical-successor-v6-20261117/scripts/ci/llhttp-reference-native-canonical-successor-v6/read_registration.py')
PIN=dict(bytes=10370,sha256='5664e956f20c579a436c87014ff4df7fb5d27f31fdbdd2f8a36eab02af1227fa')
WF='.github/workflows/native-arm-llhttp-pinned-input-source.yml'

def need(value,message):
 if not value:raise ValueError(message)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def render(v):
 need(set(v)=={'Main','source','ref','Source_root','Root_publication','Root_publication_pin','public_store','workflow_id','workflow_body','output','Root_authority'},'exact read-only reader operands')
 for name in('Main','source'):need(type(v[name])is str and re.fullmatch('[0-9a-f]{40}',v[name]),'actual Main/Source CID still unissued')
 need(type(v['ref'])is str and re.fullmatch('refs/heads/codex/[A-Za-z0-9_.-]+',v['ref']) and type(v['workflow_id'])is int and v['workflow_id']>0 and v['workflow_id']!=420972285 and v['Root_authority']is None,'new actual workflow metadata only; no role')
 for name in('Source_root','Root_publication','public_store','output'):
  p=Path(v[name]);need(p.is_absolute() and p==p.resolve() and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary exact metadata operands')
 need(not Path(v['output']).exists(),'fresh read-only metadata output')
 for name in('Root_publication_pin','workflow_body'):
  r=v[name];need(type(r)is dict and set(r)=={'bytes','sha256'}and type(r['bytes'])is int and 0<r['bytes']<=2*1024**2 and re.fullmatch('[0-9a-f]{64}',r['sha256']),'whole explicit metadata pin')
 source=Path(v['Source_root']);raw=(source/WF).read_bytes();need(pin(raw)==v['workflow_body'],'whole new Source workflow')
 names=sorted(set(re.findall(r'\bsecrets\.([A-Z][A-Z0-9_]*)',raw.decode())));need(len(names)==23 and 'CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY'in names,'exact23 literal names only')
 adopted=Path(v['Root_publication']).read_bytes();need(pin(adopted)==v['Root_publication_pin'],'whole actual Root publication')
 a=json.loads(adopted);need(a['issuer']=='Root'and a['source']==v['source']and a['ref']==v['ref']and a['status']=='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY','actual Root publication metadata tuple')
 frozen=FROZEN.read_bytes();need(pin(frozen)==PIN,'whole unchanged bounded reader source')
 text=frozen.decode();tree=ast.parse(text)
 replacements=dict(OUT='Path('+repr(v['output'])+')',HEAD=repr(v['Main']),CID=repr(v['source']),REF=repr(v['ref']),ADOPTED='Path('+repr(v['Root_publication'])+')',ADOPTED_PIN=repr(v['Root_publication_pin']),PUBLIC_STORE='Path('+repr(v['public_store'])+')',WF=repr(WF),WFPIN=repr(v['workflow_body']))
 for node in reversed(tree.body):
  if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in replacements:
   before=ast.get_source_segment(text,node);text=text.replace(before,node.targets[0].id+'='+replacements[node.targets[0].id],1)
 before="Path('/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-native-canonical-successor-v6-20261117/artifacts/development/llhttp95-canonical-v6-20261117-r1/Source95-DATA')"
 need(text.count(before)==1,'one closed Source path seam');text=text.replace(before,'Path('+repr(v['Source_root'])+')')
 text=text.replace('420972285',str(v['workflow_id'])).replace('==22','==23').replace('required_secret_name_count=22','required_secret_name_count=23')
 ast.parse(text);return text


def main():
 a=argparse.ArgumentParser(description=__doc__);a.add_argument('--config',type=Path,required=True);a.add_argument('--sha256',required=True);v=a.parse_args()
 need(sys.flags.isolated and sys.flags.dont_write_bytecode and __debug__,'isolated unoptimized bytecode-free reader')
 raw=v.config.read_bytes();need(len(raw)<=2*1024**2 and pin(raw)['sha256']==v.sha256,'whole explicit read-only configuration')
 config=json.loads(raw);text=render(config)
 Path(config['output']).mkdir(mode=0o700)
 exec(compile(text,str(FROZEN),'exec'),dict(__name__='__main__',__file__=str(FROZEN)))

if __name__=='__main__':main()
