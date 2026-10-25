"""Whole387 before proof and finite Boot-only transport/workflow inverses."""
import hashlib,json
from pathlib import Path
PRIOR=dict(bytes=145320,sha256='e15d74f97d9ca27b8cf4ea657ec5509c368c7087ec69bb290db1fd76e5f88de4')
POLICY={'job':'native','nonce_field':'nonce','nonce_path':'boot607-selection.json','purpose':'SOURCE_OWNED_NATIVE_FRAMED_TRANSPORT_V1','repository':'Gabriel-Kahen/cachy-asahi','step_id':'native_public_retention','step_name':'Retain the separate bounded604 public closure and lifecycle','workflow_name':'native-arm-current606-boot607-synthetic','workflow_path':'.github/workflows/native-arm-build.yml'}
OVERRIDE='''# Boot607-only admission; all original functions and prior policy remain byte-held.
_prior_policy=policy
def policy(value):
 need(value==BOOT607_POLICY,'exact complete Boot607 transport policy required')
 _prior_policy(dict(value,nonce_path='plan/bridge-selection.json'))
 return value

'''
BOOT_INSERT='BOOT607_POLICY='+repr(POLICY)+'\n'+OVERRIDE
GUARD_INSERT='    import transport_scope\n    transport_scope.verify(ROOT)\n'
OLD_PATH='expanded604-code/scripts/ci/native-evidence-transport/transport.py'
NEW_PATH='expanded604-code/boot607/transport.py'
OLD_TEST='          python3 -I -B expanded604-code/boot607/test_source.py\n'
NEW_TEST=OLD_TEST+'          python3 -I -B expanded604-code/boot607/test_transport.py\n'
WORKFLOW_INSERT="      ("+repr(OLD_PATH)+","+repr(NEW_PATH)+",1),\n      ("+repr(OLD_TEST)+","+repr(NEW_TEST)+",1),\n"
ADDED={'boot607/transport.py','boot607/transport_scope.py','boot607/prior387-authorization.json','boot607/test_transport.py'}
CHANGED={'boot607/guard.py','boot607/workflow.py','boot607/source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current606-boot607.yml'}
ENC=lambda v:(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def inverse(text,insert):
 need(text.count(insert)==1,'one complete finite additive transport seam');return text.replace(insert,'',1)
def verify(root):
 root=Path(root);raw=(root/'boot607/prior387-authorization.json').read_bytes();need(pin(raw)==PRIOR,'whole exact prior387 authority');before=json.loads(raw);need(before['source']=='5beee1c993471669c165ef6adcf7e648371c0d9f','genuine before387 source')
 manifest=json.loads((root/'boot607/source-manifest.json').read_bytes());files=manifest['files'];current={str(p.relative_to(root))for p in root.rglob('*')if p.is_file()and '.git'not in p.relative_to(root).parts[:1]}
 need(len(current)==391 and current==set(files)|{n for n in CHANGED if n.startswith('.github/')}|{'boot607/source-manifest.json'},'closed successor391 source')
 for name,row in files.items():need(pin((root/name).read_bytes())==row,'all full successor source leaves')
 view=next((k for k,rows in before['views'].items()if rows['boot607/input-policy.json']==pin((root/'boot607/input-policy.json').read_bytes())),None);need(view is not None,'exact selected/default before view');old=before['views'][view];need(len(old)==387 and current==set(old)|ADDED,'only four component-owned additions')
 for name,row in old.items():
  if name not in CHANGED:need(pin((root/name).read_bytes())==row,'whole387 held before leaf: '+name)
 for name,insert in(('boot607/guard.py',GUARD_INSERT),('boot607/workflow.py',WORKFLOW_INSERT)):
  need(pin(inverse((root/name).read_text(),insert).encode())==old[name],'whole387 code inverse: '+name)
 shared=root/'scripts/ci/native-evidence-transport/transport.py';derived=(root/'boot607/transport.py').read_text();need(inverse(derived,BOOT_INSERT).encode()==shared.read_bytes(),'whole original transport body inverse')
 need(json.loads((root/'scripts/ci/native-evidence-transport/boot607-policy.json').read_bytes())==POLICY,'full exact original Boot policy held')
 oldmf=dict(manifest,files={n:r for n,r in files.items()if n not in ADDED})
 for name in('boot607/guard.py','boot607/workflow.py'):oldmf['files'][name]=old[name]
 need(pin(ENC(oldmf))==old['boot607/source-manifest.json'],'whole387 manifest inverse')
 newsha=pin((root/'boot607/source-manifest.json').read_bytes())['sha256'];oldsha=old['boot607/source-manifest.json']['sha256']
 for name in CHANGED:
  if not name.startswith('.github/'):continue
  text=(root/name).read_text();need(text.count(NEW_PATH)==1 and text.count(NEW_TEST)==1 and text.count(newsha)==1,'exact workflow scoped path/test/stamp')
  restored=text.replace(NEW_PATH,OLD_PATH).replace(NEW_TEST,OLD_TEST).replace(newsha,oldsha)
  need(pin(restored.encode())==old[name],'whole387 workflow inverse')
 return dict(status='PASS_COMPLETE387_BEFORE_AND391_FINITE_INVERSES',view=view,held_before_files=382,changed_before_files=5,added=sorted(ADDED),source_files=391,old_actual_remains_failure=True)
