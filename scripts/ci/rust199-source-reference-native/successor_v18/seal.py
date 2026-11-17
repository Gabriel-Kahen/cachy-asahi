#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Seal this held proposal against the exact Source367; issue no Source/profile."""
import argparse
import importlib.util
from pathlib import Path

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('v18_held_proposal',HERE/'prepare.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
SEAL=HERE/'development-seal.DATA.json'

def review(parent):
 before=P.capture(parent);files=P.fs.snapshot(HERE/'payload');P.check_delta(before,files)
 P.fs.need(set(files)==P.REPLACED|{'hosted/build_dependencies.py'},'only held operational delta and dependency helper')
 P.fs.need(b'POLICY_PIN=None #'in files['hosted/build_dependencies.py'][0],'no concrete dependency policy issued')
 P.fs.need(not any((HERE/n).exists()for n in('constructor-profile.json','prospective.DATA.json','payload/hosted/build-dependencies.json')),'no ready constructor profile, Source identity or dependency tuple')
 template=P.fs.decode(P.fs.read(HERE/'dependency-policy.TEMPLATE.json')[0]);P.fs.need(template['status']=='HOLD_SIGNED_CLOSURE_AND_EXACT_RECIPE_PROVENANCE_PENDING'and template['packages']==[],'official source correspondence remains HOLD')
 return dict(schema=18,status='HOLD_PROPOSAL_SEALED_DATA_ONLY',parent=P.PARENT,constructor_files=P.inputs(),source_identity=None,constructor_profile=None,official_recipe_correspondence='HOLD',signed_dependency_policy='HOLD',runtime_library_load='NOT RUN',native='NOT RUN',Root_grants=None,dispatch=None,actual=P.ACTUAL,unadmitted=True)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',type=Path,required=True);p.add_argument('--write',action='store_true');a=p.parse_args();raw=P.encode(review(a.parent))
 if a.write:
  with SEAL.open('xb')as stream:stream.write(raw)
 else:P.fs.need(P.fs.read(SEAL)[0]==raw,'whole proposal seal differs')
 print(P.encode(dict(status='PASS_EXACT_HELD_PROPOSAL_SEAL',seal=P.fs.pin(raw),Source_issued=False,Root_grants=None)).decode(),end='')
