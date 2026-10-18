# SPDX-License-Identifier: MIT
"""Deterministic source-only manifests and workflow stamps; never runtime IO."""
import hashlib,json
from pathlib import Path
L='scripts/ci/current606-ksm2-closed-owner';W='scripts/ci/current606-ksm2-copy';BR='scripts/ci/current606-welcome5-source-bridge'
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def rows(root,excluded=()):return {p.relative_to(root).as_posix():pin(p.read_bytes())for p in sorted(root.rglob('*'))if p.is_file()and p.relative_to(root).as_posix()not in excluded}
def refresh(root):
 import contract as C
 from prepare import workflow
 owner=root/L;worker=root/'copyworker'/W
 # Exact API source binding before any child manifest is constructed.
 api=pin((owner/'selection.py').read_bytes());(worker/'owner-api.json').write_bytes(encoded(dict(path='/runner/owner/selection.py',**api)));(root/'bridge'/BR/'owner-api.json').write_bytes(encoded(dict(path='/runner/owner/selection.py',pin=api)))
 # Preserve original manifest schemas while refreshing explicitly changed source rows.
 for home,relative in ((root/'copyworker',W+'/source-manifest.json'),(root/'bridge',BR+'/source-manifest.json')):
  path=home/relative
  value=json.loads(path.read_bytes())if path.exists()else dict(status='SOURCE_ONLY_COPY_WORKER_NOT_NATIVE_ACCEPTANCE')
  value['files']=rows(home,(relative,));path.write_bytes(encoded(value))
 rolepins={}
 for name,(purpose,source)in C.ROLES.items():rolepins[name]=dict(purpose=purpose,source=source,files=rows(root/name))
 (owner/'source-pins.json').write_bytes(encoded(rolepins))
 excluded={L+'/source-manifest.json','.github/workflows/native-arm-current606-ksm2-owned-copy.yml','.github/workflows/native-arm-build.yml'}
 (owner/'source-manifest.json').write_bytes(encoded(dict(schema_version=1,status='CLOSED_SOURCE_ONLY_CURRENT606_KSM2_NOT_NATIVE',files=rows(root,excluded),actual_source=None,actual_ref=None,actual_run=None)))
 policy=json.loads((owner/'input-policy.json').read_bytes());text=workflow((root/'held606/.github/workflows/native-arm-build.yml').read_bytes(),root,policy)
 wf=root/'.github/workflows/native-arm-current606-ksm2-owned-copy.yml';wf.parent.mkdir(parents=True,exist_ok=True);wf.write_text(text);wf.with_name('native-arm-build.yml').write_text(text)
