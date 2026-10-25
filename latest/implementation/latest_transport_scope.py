# SPDX-License-Identifier: MIT
"""Whole original durable transport bodies, exact finite nonce/policy successor."""
from pathlib import Path
import latest_plan as P
import latest_selection as S
POLICY={'job':'native','nonce_field':'nonce','nonce_path':'latest607-selection.json','purpose':'SOURCE_OWNED_NATIVE_FRAMED_TRANSPORT_V1','repository':'Gabriel-Kahen/cachy-asahi','step_id':'native_public_retention','step_name':'Retain the separate bounded604 public closure and lifecycle','workflow_name':'native-arm-current607-latest-tools','workflow_path':'.github/workflows/native-arm-build.yml'}
def derive(raw):
 start=raw.index('BOOT607_POLICY=');end=raw.index('def main():',start);before=raw[start:end];after='LATEST607_POLICY='+repr(POLICY)+'''\n# Finite latest-five successor; original complete transport functions byte-held.
_prior_policy=policy
def policy(value):
 need(value==LATEST607_POLICY,'exact complete latest607 transport policy required')
 _prior_policy(dict(value,nonce_path='plan/bridge-selection.json'))
 return value

''';text=raw[:start]+after+raw[end:];P.need(text.replace(after,before,1)==raw,'whole original391 durable transport inverse')
 import failure_retention
 return failure_retention.derive_transport(text)

def verify(root):
 root=Path(root);base=root/'historical/boot391';raw=(base/'boot607/transport.py').read_text();actual=(root/'latest/implementation/latest_transport.py').read_text();P.need(actual==derive(raw),'complete durable capture/ZIP/API/nonce/stream/clock guard bodies unchanged');import json;P.need(json.loads((root/'latest/implementation/transport-policy.json').read_bytes())==POLICY,'full exact latestsource transport role');return dict(status='WHOLE_ORIGINAL391_TRANSPORT_FINITE_POLICY_INVERSE',old_source='203202ec05b428f9a5e9979e6ac30abedda08d3b',actual_source=None,actual_ref=None,actual_run=None)
