# SPDX-License-Identifier: MIT
"""Finite coexistence DATA gate; whole source/CI/transport/private cleanup also required."""
import hashlib,math,re
import latest_plan as P

def retired(value):P.need(value['returncode']==0 and value['termination']is None and value['direct_child_reaped']is value['group_retired']is True,'owned direct child and complete group retired')
def validate(value,nonce,real_validator,baseline):
 steps=P.transitions(baseline);P.need(type(value)is dict and value.get('status')=='PASS_NATIVE_FULL606_APPS7_SETUP6_COEXISTENCE_REQUIRES_REPLAY'and value.get('nonce')==nonce and re.fullmatch('[0-9a-f]{32}',nonce or'')and callable(real_validator),'exact coexistence component/nonce')
 counts=[606,*[len(s['after'])for s in steps]];P.need(value['base_count']==606 and value['counts']==counts and value['other604_physical_preservation']is True and value['real_modules_suites']==4 and value['selected_inode_restoration']=='NOT_CLAIMED','full other604/phase counts/logical restoration only')
 events=value['events'];P.need(type(events)is list and len(events)==14,'all14 actual signed transactions');suites=0;apps=0
 for event,step in zip(events,steps):
  P.need((event['phase'],event['acted_role'],event['version'],event['count'])==(step['phase'],step['role'],step['version'],len(step['after'])),'one-package fixed phase order')
  proof=event['other604_physical_preservation'];P.need(proof['status']=='PROTECTED_KNOWN606_GRAPH_HELD'and proof['whole_root']is False and event['private_registries_preserved']is event['fixture_graph_unchanged']is True,'full protected graph and private homes');retired(event['process']);tx=event['transaction'];P.need(tx['status']=='COMMITTED_NATIVE_APPS7_SETUP6_REQUIRES_FULL_READBACK'and tx['before_count']==len(step['before'])and tx['after_count']==len(step['after'])and tx['signature']=='REQUIRED_TEST_ONLY'and tx['hooks']==tx['scriptlets']=='DISABLED','typed original signed noexec transaction')
  if step['real_setup']:real_validator(event['real_modules']);suites+=1
  else:P.need(event['real_modules']is None,'no borrowed module result outside four joint phases')
  if step['after'].get('cachy-asahi-apps')=='0.1.0-7':
   apps+=1;r=event['Apps7'];P.need(r['status']=='PASS_ACTUAL_NATIVE_APPS7_BOTH_HOMES'and set(r['homes'])=={'fresh','existing'}and r['zero_capabilities']is True and r['NNP']==1 and r['CapBnd']=='00000000000000db'and r['applied']=='NOT_APPLIED','actual ordinary Apps7 both homes and original capability ceiling');retired(event['Apps7_process']);expected=hashlib.sha256(P.inventory_bytes(step['after'])).hexdigest()
   for home in r['homes'].values():
    c=home['installed_controls'];P.need(home['CLI']==2 and home['inventory_count']==len(step['after'])and home['inventory_versions_sha256']==expected and home['user_config_preserved']is True and c['status']=='PASS_INSTALLED_CONTROLS'and c['mode']=='apps'and c['tests']==15 and c['failures']==c['errors']==c['skipped']==0 and c['installed_source']is True and 0<c['report_bytes']<=65536 and re.fullmatch('[a-f0-9]{64}',c['report_sha256']),'whole actual Apps7 frontend inventory and all15 installed controls')
  else:P.need(event['Apps7']is event['Apps7_process']is None,'no Apps7 fixture claim when old/absent')
 P.need(suites==4 and apps==sum(s['after'].get('cachy-asahi-apps')=='0.1.0-7'for s in steps),'all required actual joint suites and Apps7 boundaries');graphs=value['graphs'];phases=['baseline-original606',*(s['phase']for s in steps for _ in range(2))];P.need(type(graphs)is list and len(graphs)==29,'29 mandatory complete fresh captures');end=None
 for i,(row,phase)in enumerate(zip(graphs,phases)):
  P.need(row['sequence']==i and row['phase']==phase and row['state']=='COMPLETE'and type(row['nodes'])is int and 0<row['nodes']<=200000 and type(row['bytes_read'])is int and 0<=row['bytes_read']<=6*1024**3 and re.fullmatch('[a-f0-9]{64}',row['graph_sha256']),'whole bounded fresh graph');start,seconds=row['started'],row['seconds'];P.need(type(start)in(int,float)and type(seconds)in(int,float)and math.isfinite(start)and math.isfinite(seconds)and start>=0 and 0<=seconds<=7200 and(end is None or start>=end-.000001),'ordered finite source-owned graph clock');end=start+seconds
 P.need(end-graphs[0]['started']<=7200 and len(value['ldconfig'])==15 and[r['phase']for r in value['ldconfig']]==['baseline-original606',*[s['phase']for s in steps]],'component bound and all15 fresh auxiliary observations')
 P.need(value['Apps7_coexistence']=='ACTUAL_INSTALLED_CLI_AND15_CONTROLS_BOTH_HOMES_REQUIRES_REPLAY'and value['notification_delivery']=='NOT_RUN'and value['notification_scope']=='PRIVATE_NOTIFY_SEND_RECORDER_ONLY'and all(value[k]=='NOT_RUN'for k in('audio','GUI','hardware'))and value['release']=='NOT_ADMITTED'and value['performance']=='NOT_CLAIMED','no notification/audio/GUI/hardware/performance admission')
 return value
