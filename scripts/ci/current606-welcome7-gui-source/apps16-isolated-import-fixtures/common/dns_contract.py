# SPDX-License-Identifier: MIT
"""The additional stored-profile view; original management validators stay separate."""
import base64,hashlib,json,re

VIEW='management-dns'
LABEL='List stored DNS profiles'
TITLE='Stored DNS profiles'
UUID='bdb74c1f-1e9e-44b1-820a-705dca6cb760'
NAME='Owned GUI DNS profile'
PROFILE=dict(uuid=UUID,type='802-3-ethernet',name=NAME)
ARGV=['/usr/bin/cachy-asahi-dns','--json','profiles']
RAW_CAP=65536

def need(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True)+'\n').encode()
def report(raw):
    need(type(raw)is bytes and 0<len(raw)<=RAW_CAP,'bounded DNS report required')
    def pairs(rows):
        value={}
        for k,v in rows:need(k not in value,'duplicate DNS report key');value[k]=v
        return value
    value=json.loads(raw,object_pairs_hook=pairs)
    need(value==dict(status='STORED_CONNECTION_PROFILES',profiles=[PROFILE],live_dns='NOT_REAPPLIED_STORED_PROFILE_ONLY'),'exact owned stored-profile discovery required')
    return value,'1 stored connection profile. Read only; live DNS was not reapplied.\n'+UUID+' | 802-3-ethernet | \"'+NAME+'\"'

def process(row,pid):
    need(row.get('argv')==ARGV and row.get('raw_argv',[])[-3:]==ARGV and row.get('uid')==[23001]*4 and
         row.get('welcome_pid')==pid and row.get('original_executable')==ARGV[0] and row.get('stopped')is False and
         type(row.get('pid'))is int and row['pid']>1 and row.get('pgid')==row['pid'] and
         type(row.get('starttime'))is int and type(row.get('supervisor_pid'))is int and row['supervisor_pid']>1 and
         len({row['pid'],row['supervisor_pid'],pid})==3 and row.get('exe','').startswith('/usr/bin/python'),
         'actual Welcome-owned default DNS helper/supervisor required')

def snapshot(C,value,pid,expected):
    need(value.get('pid')==pid,'DNS snapshot PID differs');rows=C.names(value)
    texts=[text for _,row,text in rows if row['showing']and text is not None]
    need(set(expected)=={'text','buttons'} and len(expected['text'])==3 and expected['buttons']=={LABEL:True},'exact DNS view expectation required')
    _,summary=report(expected['text'][2].encode())
    need(expected['text'][1]==summary and expected['text'][0]=='Elapsed:','DNS view summary/complete state differs')
    for text in expected['text']:need(any(text in actual for actual in texts),'actual DNS outcome not showing')
    need(texts.count(expected['text'][2])==1,'entire actual DNS report preview required')
    controls=[row for name,row,_ in rows if name==LABEL and row['role']==43]
    need(len(controls)==1 and controls[0]['enabled']is True and controls[0]['sensitive']is True,'installed DNS discovery button unavailable')
    return dict(node_count=len(rows),showing_text_sha256=[sha(t.encode())for t in texts],expected=expected,body_sha256=sha('\n'.join(texts).encode()))

def fixture(value):
    need(value.get('status')=='PASS_OWNED_STORED_DNS_FIXTURE' and value.get('profile')==PROFILE and
         all(value.get(k)is True for k in ('profile_bytes_preserved','resolver_preserved','network_preserved','no_active_connection','metadata_preserved','daemon_reaped','daemon_group_absent','system_bus_owner_absent','owned_state_removed')),
         'complete readonly fixture and actual retirement required')
    row=value.get('daemon',{})
    need(type(row.get('pid'))is int and row['pid']>1 and row.get('pgid')==row['pid'] and type(row.get('starttime'))is int and
         row.get('uid')==[0]*4 and row.get('exe')=='/usr/bin/NetworkManager' and row.get('NoNewPrivs')=='1' and
         all(row.get(k)=='0000000000000000' for k in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')),'owned capability-free actual NM daemon required')
    for key in ('before','after'):
        need(type(value.get(key))is dict and all(re.fullmatch('[0-9a-f]{64}',v or '')for v in value[key].values()),'bounded readonly fixture identities required')
    need(value['before']==value['after']and set(value['before'])=={'profile','resolver','network','metadata'},'exact before/after readonly identities required')
    return value

def verify(events,lock,C,G):
    need(lock.get('products',{}).get('cachy-asahi-welcome',{}).get('version')=='0.1.0-8' and
         lock.get('products',{}).get('cachy-asahi-dns',{}).get('version')=='0.1.0-2','new installed product identities required')
    selected=lock.get('profile');need(selected in ('minimal','overlay'),'one explicit independent profile required')
    need({e['stage']for e in events if 'stage'in e}=={selected},'foreign or missing DNS profile event')
    results=[]
    for stage in (selected,):
        def one(kind):
            rows=[r for r in events if r.get('stage')==stage and r.get('event')==kind]
            need(len(rows)==1,'one actual DNS continuation receipt required: '+kind);return rows[0]
        result=one('dns_result');frame=next(r for r in events if r.get('stage')==stage and r.get('event')=='frame_ready'and r.get('view')==VIEW)
        need(len([r for r in events if r.get('stage')==stage and r.get('event')=='frame_ready'and r.get('view')==VIEW])==1,'one DNS firstframe required')
        raw=base64.b64decode(result['report_base64'],validate=True);need(sha(raw)==result['report_sha256']and len(raw)==result['report_bytes'],'retained DNS counterpart differs');_,summary=report(raw)
        process(result['gui_process'],frame['welcome_pid'])
        semantic=frame['semantic'];expected=dict(text=['Elapsed:',summary,raw.decode()],buttons={LABEL:True})
        need(semantic['expected']==expected and sha(encoded(semantic['snapshot']))==semantic['snapshot_sha256']and
             snapshot(C,semantic['snapshot'],frame['welcome_pid'],expected)==semantic['summary'],'DNS raw snapshot/report semantics differ')
        need(frame.get('capture_after_ms',0)>=5000 and frame.get('physical_input')==frame.get('hardware')=='NOT_RUN','original firstframe timing/scope required')
        actions=[r for r in events if r.get('stage')==stage and r.get('event')=='dns_action']
        need([(r.get('label'),r.get('scope'),r.get('scroll'))for r in actions]==[(LABEL,None,True),(LABEL,None,False),('View report',TITLE,True),('View report',TITLE,False),('View report',TITLE,True),('View report',TITLE,False)],'actual DNS action sequence differs')
        for i,row in enumerate(actions):
            need(row.get('sequence')==i+1,'DNS action ordinal differs');C.action(row,frame['welcome_pid'],row['label'],row['scope'],row['scroll'])
        fast=result['retirement_observation'];proof=result['retirement_proof'];C.retirement_proof(fast,proof,result['gui_process'],result['inventory'])
        fixture(result['fixture'])
        need(result.get('metadata_readonly')is True and result.get('live_DNS')=='NOT_REAPPLIED_STORED_PROFILE_ONLY'and result.get('hardware')=='NOT_RUN','actual readonly result/scope required')
        G.together(list(frame['windows'].values()),frame['welcome_pid'],frame['doctor_pid'],VIEW)
        need(events.index(actions[2])<events.index(actions[3])<events.index(actions[4])<events.index(frame)<events.index(actions[5])<events.index(result),'DNS report capture/retirement order differs')
        original=next(r for r in events if r.get('stage')==stage and r.get('event')=='management_result')
        need(result['inventory']==original['inventory']and len(result['inventory'])==595,'same complete595 inventory required')
        previous=next(r for r in events if r.get('stage')==stage and r.get('event')=='frame_ready'and r.get('view')=='management-failure')
        closing=next(r for r in events if r.get('stage')==stage and r.get('event')=='frame_ready'and r.get('view')=='management-closing')
        need(events.index(previous)<events.index(actions[0])and events.index(result)<events.index(closing),'DNS fixture must retire between original failure/closing checks')
        need(all(frame[k]==previous[k] for k in ('welcome_pid','doctor_pid','compositor_pid','worker','doctor_proof_sha256','managed_identity','producer_lifecycle')),'original visible managed actors differ')
        results.append(dict(stage=stage,report_sha256=sha(raw),fixture='PASS_OWNED_STORED_ONLY_RETIRED'))
    return dict(status='PASS_WELCOME5_DNS_GUI_METADATA_PIXELS_PENDING_REVIEW',phases=results,GUI_physical='NOT_RUN',M2='NOT_RUN',current606='NOT_RUN')
