# SPDX-License-Identifier: MIT
"""Complete274 closure AND readable whole1098/218 ancestry; historical scope only."""
import json
import common as C
from loaders import load
LIBRARY='bd0cf1891083d011b70edab10501c317d3720b78'
def verify():
 original=json.loads(C.read(C.ROOT/'ancestry1098/files.json'));inverse=json.loads(C.read(C.ROOT/'ancestry1098/inverse.json'))
 C.need(len(original)==1098,'entire frozen1098 before namespace')
 for n,w in original.items():C.checked(C.ROOT/('ancestry1098/before/'+n if n in inverse['changed'] else n),w)
 C.need(set(inverse['changed'])<=set(original)and inverse['old218']==218 and inverse['current274']==274 and inverse['held218']==212 and inverse['changed218']==6 and inverse['added274']==56,'finite whole218→274 closure')
 lib=C.ROOT/'installer604';api=load('_fresh607_closed274',lib/'scripts/ci/expanded604-apps6-public-pair-installer/contract.py');api.policy();api.locks();api.COMPOSITION.verify_source(lib)
 mf=api.read(api.HERE/'source-manifest.json');C.need(len(mf['files'])==271,'complete original271 source manifest closure')
 for n,w in mf['files'].items():api.checked(lib,dict(path=n,**w))
 d=json.loads(C.read(C.ROOT/'qualification604/fresh604-root-decision.json'))
 C.need(d['status']=='ROOT_ACCEPTED_SIGNED_PUBLIC_PAIRS_APPS6_CURRENT604_FRESH_INSTALLER'and d['source_sha']==LIBRARY and d['run_id']=='39050697739'and d['package_count']==604 and d['expected604_sha256']==api.TARGET_SHA,'exact historical604 qualified decision only')
 C.need(all(d[k]=='PASS'for k in('ordinary_parent_retired','independent_root_readback','cleanup'))and d['hardware']=='NOT_RUN'and d['release']=='NOT_ADMITTED','old qualification scope held; no fresh607 authority transfer')
 C.need(d['source_manifest_sha256']==C.pin(C.read(api.HERE/'source-manifest.json'))['sha256']and d['input_policy_sha256']==C.pin(C.read(api.HERE/'input-policy.json'))['sha256'],'historical decision exact source policy closure')
 return dict(status='PASS_WHOLE1098_AND_COMPLETE_QUALIFIED274',historical604='SOFTWARE_ONLY',fresh607='NOT_RUN')
