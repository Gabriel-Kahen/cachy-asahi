# SPDX-License-Identifier: MIT
"""Pure finite receipt gate; source/CI/signatures/cleanup remain separate mandatory."""
import math,re
import latest_plan as P

def validate(value,nonce,real_validator):
 P.need(type(value)is dict and value.get('status')=='PASS_NATIVE_FULL606_SETUP6_REAL_MODULES_REQUIRES_REPLAY'and value.get('nonce')==nonce and re.fullmatch('[0-9a-f]{32}',nonce or'')and callable(real_validator),'exact full606 real-module component/nonce')
 P.need(value['base_count']==606 and value['counts']==[606,606,606,606,606,605,606,606]and value['other605_physical_preservation']is True and value['real_modules_suites']==4 and value['selected_inode_restoration']=='NOT_CLAIMED','all phase counts and physical/logical scope')
 events=value['events'];P.need(type(events)is list and[(e['phase'],e['version'])for e in events]==list(P.PHASES)and[e['count']for e in events]==value['counts'][1:],'complete seven signed transactions in fixed order')
 suites=0
 for event in events:
  P.need(event['other605_physical_preservation']['status']=='PROTECTED_KNOWN606_GRAPH_HELD'and event['other605_physical_preservation']['whole_root']is False and event['private_registries_preserved']is event['fixture_graph_unchanged']is True,'full typed native known-graph/private registry predicates')
  result=event['process'];P.need(result['returncode']==0 and result['termination']is None and result['direct_child_reaped']is result['group_retired']is True,'complete source-owned transaction/group retirement')
  transaction=event['transaction'];P.need(transaction['status']=='COMMITTED_NATIVE_SETUP6_REQUIRES_FULL_READBACK'and transaction['signature']=='REQUIRED_TEST_ONLY'and transaction['hooks']==transaction['scriptlets']=='DISABLED','whole original noexec signed transaction')
  if event['version']=='0.1.0-6':real_validator(event['real_modules']);suites+=1
  else:P.need(event['real_modules']is None,'no Setup6 real module result on old or absent helper')
 P.need(suites==4,'four full original240 real suites');graphs=value['graphs'];phases=['baseline5',*(phase for phase,_ in P.PHASES for _ in range(2))];P.need(type(graphs)is list and len(graphs)==15,'fifteen full fresh graphs')
 end=None
 for i,(row,phase)in enumerate(zip(graphs,phases)):
  P.need(row['sequence']==i and row['phase']==phase and row['state']=='COMPLETE'and type(row['nodes'])is int and 0<row['nodes']<=200000 and type(row['bytes_read'])is int and 0<=row['bytes_read']<=6*1024**3 and re.fullmatch('[0-9a-f]{64}',row['graph_sha256']),'each original full graph bounded and complete')
  start,seconds=row['started'],row['seconds'];P.need(type(start)in(int,float)and type(seconds)in(int,float)and math.isfinite(start)and math.isfinite(seconds)and start>=0 and 0<=seconds<=3000 and(end is None or start>=end-.000001),'fresh ordered nonoverlapping graph times');end=start+seconds
 P.need(end-graphs[0]['started']<=3000 and len(value['ldconfig'])==8 and[r['phase']for r in value['ldconfig']]==['baseline5',*[p for p,_ in P.PHASES]],'bounded component and full eight original raw auxiliary observations')
 P.need(value['Apps7_coexistence']=='NOT_RUN_BASELINE_APPS6'and value['notification_delivery']=='NOT_RUN'and value['notification_scope']=='PRIVATE_NOTIFY_SEND_RECORDER_ONLY'and all(value[k]=='NOT_RUN'for k in('audio','GUI','hardware'))and value['release']=='NOT_ADMITTED'and value['performance']=='NOT_CLAIMED','precise real-private-shell scope no delivery/hardware/performance authority')
 return value
