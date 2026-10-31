# SPDX-License-Identifier: MIT
"""New Apps7 authority branch; old Cache/Orphans decisions remain exact."""
import ast,types
from pathlib import Path
VERSIONS={'cachy-asahi-apps':'0.1.0-7','cachy-asahi-repository-runtime':'0.1.0-1','cachy-asahi-cache':'0.2.0-1','cachy-asahi-orphans':'0.1.0-2'}
NATIVE='1dc9ecfee51145ba9cc43a95cc45bee97faed8b9';RUN='39095436036'
DECISION='589498543381db1124fbfbdea85810b7ff1e60261be3dde098ad060cbb2b1b22'
ARCHIVES={'cachy-asahi-apps':(23212,'23fc2fe5707606b0f3bd8c6322b9e7ae0c47a6ff1024cd239f4486679638be39'),'cachy-asahi-repository-runtime':(28888,'1c8a9149da02e60a4c14598cdf7007d6dbffcd6150757fcf6711977aa00cf8aa')}
KIND='APPS7_FOUR_NATIVE_PAIRS_FOR_PROSPECTIVE_FULL574_REPAIR'
ASSEMBLY='NEW_APPS7_RUNTIME_PAIRS_PLUS_HELD65950_CACHE_ORPHANS_NO_REPAIR_CREDIT'

def module(C,root):
 old=C.load('unchanged_apps6_pair_decisions',root/'scripts/ci/apps-full574-repair-native/packet.py')
 original=C.load('unchanged_bounded_packet',root/'scripts/ci/management-tools-generic16k/contract.py')
 def decision(root,row,name,version,comparison):
  if name not in ARCHIVES:return old.decision(C,root,row,name,version,comparison)
  raw=C.checked(root,row['decision']);value=C.decode(raw)
  C.need(C.sha(raw)==DECISION,'exact original Apps7 native Root decision required')
  C.need(value['status']=='ROOT_ACCEPTED_NATIVE_APPS7_CLIENT_RETAINED_SCOPE' and value['source']==row['native_source']==NATIVE and str(value['run'])==row['native_run']==RUN and value['recipe_source']=='134e02ba0c73dab4eb4a22cbfd562599b9e7a411' and value['builds']==6 and value['pairs']==3 and value['original_archive']==dict(bytes=579586,sha256='895e4fe9c9f768cac2d4330ffd50207e113b10a481a67b6380fa448c56738c3a') and value['hardware']=='NOT_RUN' and value['full604']=='NOT_RUN' and value['release']=='NOT_ADMITTED','exact native retained scope; no new repair or604 authority')
  C.need(version==VERSIONS[name] and row['version']==version and row['qualification']=='NATIVE_PAIR_ONLY' and all((row['files'][s]['bytes'],row['files'][s]['sha256'])==ARCHIVES[name] for s in ('a','b')),'exact Apps7/Runtime native pair identity')
 text=C.read(root/'scripts/ci/management-tools-generic16k/contract.py').decode()
 node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='packet');body=ast.get_source_segment(text,node)
 body=old.finite(body,"'ROOT_ACCEPTED_MANAGEMENT16K_NATIVE_INPUTS'",repr(KIND))
 body=old.finite(body,"'FOUR_ROOT_ACCEPTED_NATIVE_PAIRS_FOR_PRIVATE16K_DATA_STAGE'",repr(ASSEMBLY))
 start=body.index("        if decision.get('status')==");end=body.index("        need(set(row['checks'])",start)
 body=body[:start]+"        apps7_decision(root,row,name,version,comparison)\n"+body[end:]
 namespace=dict(vars(original),VERSIONS=VERSIONS,policy=C.policy,C=C,apps7_decision=decision)
 exec(compile(body,str(root/'scripts/ci/management-tools-generic16k/contract.py')+':apps7-native-inputs','exec'),namespace)
 return types.SimpleNamespace(packet=namespace['packet'],package_payload=original.package_payload)
