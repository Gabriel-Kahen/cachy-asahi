# SPDX-License-Identifier: MIT
"""Finite historical input selection, never default or combined acceptance."""
import hashlib,json,re
from pathlib import Path
import latest_plan as plan
HERE=Path(__file__).resolve().parent
PACKETS={
 'apps':dict(source='02734c705565868b0b964c48399a4f659fc6f271',ref='codex/apps7-test-signature-renewal-v1',files=196,index=dict(bytes=83411,sha256='fb86de7fad44c50d84ae9ebb44e8dd150abbeae84bffc16058bcf7e68da510e2')),
 'doctor':dict(source='628b06a310df6058f154c1bf7a4c6a16cd69c53a',ref='codex/doctor2-current606-native-inputs-v1',files=131,index=dict(bytes=25869,sha256='848ed2fed42236ac166e927bccb86c9957e136f9c9583dce0d650c2edf2bd83b')),
 'ksm':dict(source='fe67aaaae7ef4ea94dfc8a42cd2c806cc5436fc7',ref='codex/ksm-test-signature-renewal-v1',files=32,index=dict(bytes=12513,sha256='4fa63d8a633efc3f337110917d69abf6a932461354e9452ca8632990bf0120ec')),
 'welcome':dict(source='d66af0f75e028db95538f6a572a372e23026a36f',ref='codex/welcome6-current607-native-inputs-v1',files=149,index=dict(bytes=29403,sha256='c92e97dfd3bfdf2f4f577ea6c4c637ed51cf7cb2fb389f5865c96307bb83597f')),
 'boot':dict(source='4decb87f5b15f8828cea31e75cbf9e4381feaeaa',ref='codex/boot-report-current606-native-inputs-v1',files=123,index=dict(bytes=24491,sha256='df27cff377e3c53e209cc07cef55202e859c1002570b9699aaccf39db4d73da3'))}
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def components():
 pins=json.loads((HERE/'accepted-component-pins.json').read_bytes());plan.need(set(pins)=={'apps','doctor','ksm','welcome5','welcome6','boot'},'all six exact historical qualification inputs')
 for role,row in pins.items():
  path=HERE/'accepted'/row['path'];plan.need(path.parent==HERE/'accepted'and not path.is_symlink(),'fixed historical decision DATA path');raw=path.read_bytes();value=json.loads(raw);plan.need(pin(raw)=={k:row[k]for k in('bytes','sha256')}and(value['source'],value.get('run',value.get('run_id')),value['status'],value['release'])==(row['source'],row['run'],row['status'],'NOT_ADMITTED')and row['authority']=='HISTORICAL_FINITE_COMPONENT_INPUT_ONLY_NO_COMBINED_CREDIT','whole exact historical Root decision')
 return pins

def authorize(value,current606):
 plan.need(type(value)is dict and set(value)=={'schema_version','purpose','status','current606','component_inputs','packet_checkouts','actual_source','actual_ref','actual_run','Root_acceptance'},'closed new composition policy')
 plan.need(value['schema_version']==1 and value['purpose']=='CURRENT607_LATEST_FIVE_TOOLS_NATIVE_COMPOSITION'and value['status']=='ROOT_BOUND_HISTORICAL_INPUTS_NO_COMBINED_ACCEPTANCE','NULL/unselected five-tool inputs before actors')
 plan.need(all(value[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')),'all future actual fields NULL in source policy')
 plan.need(value['current606']==current606 and current606['source']=='f3a30f2049f57d9f3cb2433fbd59af51d4cc5720'and current606['run']==39106953257,'genuine original606 provenance, never prior copy acceptance')
 plan.need(value['component_inputs']==components()and value['packet_checkouts']==PACKETS,'all exact historical decisions/carrier commits/indexes before producers')
 return value
