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

# BEGIN_BOOT607_FAILURE_RETENTION_SCOPE_V1
import base64 as _failure_base64
PRIOR391={'bytes': 666841, 'sha256': '4ca3a9172e74a051961c566e2fae3d5c1e2b5d7aa489291ba52f724590dc4d48'}
FAILURE_CAPTURE_BEFORE=" step=bytes(step);packets,frames=decode_step(step);index,files=reconstruct(packets);nonce_raw=files.get(p['nonce_path']);"
FAILURE_CAPTURE_AFTER=" step=bytes(step);packets,frames=decode_step(step)\n try:index,files=reconstruct(packets)\n except ValueError as original_error:\n  if type(original_error)is ValueError and str(original_error)=='whole original retained input closure':\n   absent=object();previous=sys.modules.get('transport',absent)\n   try:\n    helper_path=Path(__file__).with_name('failure_retention.py');helper_raw=read(helper_path,M)\n    need(pin(helper_raw)=={'bytes': 6056, 'sha256': 'cfcf9d4b47e612266b51135a4da2c48e9cf20011394ad0123cebfea133061931'},'exact source-owned failure helper')\n    current=types.ModuleType('_boot607_capture_transport');vars(current).update(globals());sys.modules['transport']=current\n    helper=types.ModuleType('_boot607_failure_retention');helper.__file__=str(helper_path)\n    exec(compile(helper_raw,str(helper_path),'exec'),vars(helper))\n    helper.retain(step,original_error,output.with_name(output.name+'-failure'),p,env,started)\n   finally:\n    if previous is absent:sys.modules.pop('transport',None)\n    else:sys.modules['transport']=previous\n    raise original_error\n  raise\n nonce_raw=files.get(p['nonce_path']);"
FAILURE_ENV_BEFORE='          CAA_EVIDENCE_SOURCE_SHA: ${{ inputs.source }}\n          CAA_EVIDENCE_WORKFLOW_SHA: ${{ github.sha }}\n'
FAILURE_ENV_AFTER='          CAA_EVIDENCE_SOURCE_SHA: ${{ inputs.source }}\n          CAA_EVIDENCE_WORKFLOW_SHA: ${{ github.sha }}\n          CAA_BOOT607_COMPOSITION_OUTCOME: ${{ steps.composition604.outcome }}\n'
FAILURE_UPLOAD_BEFORE="      - name: Upload original native framed evidence with source-bound transport receipt\n        if: always() && steps.native_public_retention.outcome == 'success'\n        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9\n        timeout-minutes: 5\n        with:\n          name: native-framed-evidence-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.job }}\n          path: ${{ runner.temp }}/native-framed-evidence/\n          retention-days: 3\n          compression-level: 0\n          include-hidden-files: false\n          if-no-files-found: error\n"
FAILURE_UPLOAD_AFTER="      - name: Upload original native framed evidence with source-bound transport receipt\n        if: always() && steps.native_public_retention.outcome == 'success'\n        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9\n        timeout-minutes: 5\n        with:\n          name: native-framed-evidence-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.job }}\n          path: ${{ runner.temp }}/native-framed-evidence/\n          retention-days: 3\n          compression-level: 0\n          include-hidden-files: false\n          if-no-files-found: error\n      - name: Upload original Boot607 failure DATA with source-bound transport receipt\n        if: always() && steps.composition604.outcome == 'failure' && steps.native_public_retention.outcome == 'failure'\n        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9\n        timeout-minutes: 5\n        with:\n          name: boot607-failure-data-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.job }}\n          path: ${{ runner.temp }}/native-framed-evidence-failure/\n          retention-days: 3\n          compression-level: 0\n          include-hidden-files: false\n          if-no-files-found: error\n"
FAILURE_WORKFLOW_INSERT='      (\'          CAA_EVIDENCE_SOURCE_SHA: ${{ inputs.source }}\\n          CAA_EVIDENCE_WORKFLOW_SHA: ${{ github.sha }}\\n\',\'          CAA_EVIDENCE_SOURCE_SHA: ${{ inputs.source }}\\n          CAA_EVIDENCE_WORKFLOW_SHA: ${{ github.sha }}\\n          CAA_BOOT607_COMPOSITION_OUTCOME: ${{ steps.composition604.outcome }}\\n\',1),\n      ("      - name: Upload original native framed evidence with source-bound transport receipt\\n        if: always() && steps.native_public_retention.outcome == \'success\'\\n        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9\\n        timeout-minutes: 5\\n        with:\\n          name: native-framed-evidence-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.job }}\\n          path: ${{ runner.temp }}/native-framed-evidence/\\n          retention-days: 3\\n          compression-level: 0\\n          include-hidden-files: false\\n          if-no-files-found: error\\n","      - name: Upload original native framed evidence with source-bound transport receipt\\n        if: always() && steps.native_public_retention.outcome == \'success\'\\n        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9\\n        timeout-minutes: 5\\n        with:\\n          name: native-framed-evidence-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.job }}\\n          path: ${{ runner.temp }}/native-framed-evidence/\\n          retention-days: 3\\n          compression-level: 0\\n          include-hidden-files: false\\n          if-no-files-found: error\\n      - name: Upload original Boot607 failure DATA with source-bound transport receipt\\n        if: always() && steps.composition604.outcome == \'failure\' && steps.native_public_retention.outcome == \'failure\'\\n        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9\\n        timeout-minutes: 5\\n        with:\\n          name: boot607-failure-data-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.job }}\\n          path: ${{ runner.temp }}/native-framed-evidence-failure/\\n          retention-days: 3\\n          compression-level: 0\\n          include-hidden-files: false\\n          if-no-files-found: error\\n",1),\n'
FAILURE_TEST_EDITS=[("['source_files'],391)", "['source_files'],393)"), ("['files'],391)", "['files'],393)"), ("S.inverse((HERE/'transport.py').read_text(),S.BOOT_INSERT)", "S.inverse(S.transport_before_failure((HERE/'transport.py').read_text()),S.BOOT_INSERT)"), ("after=ast.parse((HERE/'transport.py').read_text())", "after=ast.parse(S.transport_before_failure((HERE/'transport.py').read_text()))")]
FAILURE_HELPER={'bytes': 6056, 'sha256': 'cfcf9d4b47e612266b51135a4da2c48e9cf20011394ad0123cebfea133061931'}
def transport_before_failure(text):
 need(text.count(FAILURE_CAPTURE_AFTER)==1,'one exact capture failure handoff inverse')
 return text.replace(FAILURE_CAPTURE_AFTER,FAILURE_CAPTURE_BEFORE,1)
def verify(root):
 root=Path(root);raw=(root/'boot607/prior391-authorization.json').read_bytes();need(pin(raw)==PRIOR391,'whole genuine391 authority');before=json.loads(raw)
 need(before['source']=='203202ec05b428f9a5e9979e6ac30abedda08d3b','exact genuine before391 source')
 manifest=json.loads((root/'boot607/source-manifest.json').read_bytes());files=manifest['files'];extra={'.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current606-boot607.yml','boot607/source-manifest.json'}
 current={str(p.relative_to(root))for p in root.rglob('*')if p.is_file()and '.git'not in p.relative_to(root).parts[:1]}
 need(len(current)==393 and current==set(files)|extra,'closed failure-retention393 source')
 for n,v in files.items():need(pin((root/n).read_bytes())==v,'all current393 source pins')
 view=next((k for k,v in before['views'].items()if v['boot607/input-policy.json']==pin((root/'boot607/input-policy.json').read_bytes())),None);need(view is not None,'exact original selected/default view');old=before['views'][view]
 added={'boot607/failure_retention.py','boot607/prior391-authorization.json'}
 changed={'boot607/transport.py','boot607/transport_scope.py','boot607/workflow.py','boot607/test_transport.py','boot607/source-manifest.json'}|{n for n in extra if n.startswith('.github/')}
 need(len(old)==391 and current==set(old)|added,'exact two source-owned failure additions')
 for n,v in old.items():
  if n not in changed:need(pin((root/n).read_bytes())==v,'all original391 held source pins')
 need(pin((root/'boot607/failure_retention.py').read_bytes())==FAILURE_HELPER,'whole byteheld tested failure helper')
 restored=transport_before_failure((root/'boot607/transport.py').read_text());need(pin(restored.encode())==old['boot607/transport.py'],'whole positive transport body inverse')
 marker=bytes.fromhex('2320424547494e5f424f4f543630375f4641494c5552455f524554454e54494f4e5f53434f50455f56310a').decode();scope=(root/'boot607/transport_scope.py').read_text();need(scope.count(marker)==1 and pin(scope.split(marker,1)[0][:-1].encode())==old['boot607/transport_scope.py'],'whole original391 scope body inverse')
 workflow=(root/'boot607/workflow.py').read_text();need(workflow.count(FAILURE_WORKFLOW_INSERT)==1 and pin(workflow.replace(FAILURE_WORKFLOW_INSERT,'',1).encode())==old['boot607/workflow.py'],'whole workflow generator inverse')
 tests=(root/'boot607/test_transport.py').read_text()
 for a,b in reversed(FAILURE_TEST_EDITS):need(tests.count(b)==1,'exact updated transport test inverse');tests=tests.replace(b,a,1)
 need(pin(tests.encode())==old['boot607/test_transport.py'],'whole original source tests inverse')
 restored=dict(manifest,files={n:v for n,v in files.items()if n not in added})
 for n in changed:
  if n in restored['files']:restored['files'][n]=old[n]
 need(pin(ENC(restored))==old['boot607/source-manifest.json'],'whole original391 MF inverse')
 newsha=pin((root/'boot607/source-manifest.json').read_bytes())['sha256'];oldsha=old['boot607/source-manifest.json']['sha256']
 for n in extra:
  if not n.startswith('.github/'):continue
  text=(root/n).read_text()
  for a,b in((FAILURE_UPLOAD_AFTER,FAILURE_UPLOAD_BEFORE),(FAILURE_ENV_AFTER,FAILURE_ENV_BEFORE),(newsha,oldsha)):
   need(text.count(a)==1,'exact failure workflow inverse');text=text.replace(a,b,1)
  need(pin(text.encode())==old[n],'whole original391 workflow bytes')
 return dict(status='PASS_COMPLETE391_BEFORE_AND393_FAILURE_ONLY_INVERSES',view=view,source_files=393,added=sorted(added),original_primary='UNKNOWN_UNEXPORTED',acceptance='NOT_GRANTED')
