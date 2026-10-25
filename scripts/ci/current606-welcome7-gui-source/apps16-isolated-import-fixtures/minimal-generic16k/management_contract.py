INDEPENDENT_PROFILE = 'minimal'
# SPDX-License-Identifier: MIT
"""Finite actual management actions, readonly metadata and original-first-frame joins."""
import base64
import hashlib
import json
from pathlib import Path
import re
import stat

BASE_VIEWS=('home','terminal-action','files-action','system','first-steps','updates','recovery')
MANAGEMENT_VIEWS=tuple('management-'+n for n in ('absent','doctor','orphans','failure','closing'))
VIEWS=BASE_VIEWS+MANAGEMENT_VIEWS
SCOPE='LOCAL_INSTALLED_METADATA_ONLY_NOT_PAYLOAD_RELEASE_REMOVAL_OR_HARDWARE_PROOF'
REPORT_CAP=2*1024**2


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True)+'\n').encode()


def read(path,cap=REPORT_CAP,uid=None):
    path=Path(path);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_nlink==1 and info.st_size<=cap and (uid is None or info.st_uid==uid),'bounded ordinary owned fixture file required')
    raw=path.read_bytes();need(len(raw)==info.st_size,'fixture read changed');return raw


def interface(policy):
    ui=policy.get('ui',{});need(set(ui.get('labels',{}))=={'management','doctor','orphans'} and
        set(ui.get('strings',{}))=={'running','complete','failure','unavailable'} and
        all(type(v) is str and 1<=len(v)<=256 for group in ('labels','strings') for v in ui[group].values()) and
        type(ui.get('raw_preview_suffix')) is str and 0<len(ui['raw_preview_suffix'])<=128 and
        type(ui.get('orphan_preview_bytes')) is int and ui['orphan_preview_bytes']==8192 and ui.get('orphan_preview_suffix')=='\n[Raw preview truncated at 8 KiB.]' and
        type(ui.get('max_output_bytes')) is int and 0<ui['max_output_bytes']<=2*1024**2,'Root final management UI contract remains UNBOUND')
    return ui


def names(snapshot):
    need(snapshot.get('status')=='PASS' and type(snapshot.get('pid')) is int and type(snapshot.get('nodes')) is list and 1<=len(snapshot['nodes'])<=192,'actual owned accessibility snapshot required')
    result=[]
    for row in snapshot['nodes']:
        for key in ('showing','selected','checked','enabled','sensitive'):need(type(row.get(key)) is bool,'typed accessibility state absent')
        name=base64.b64decode(row['name_base64'],validate=True).decode('utf8',errors='replace')
        text=None
        if 'body_base64' in row:
            raw=base64.b64decode(row['body_base64'],validate=True);need(len(raw)<=65664 and sha(raw)==row['text_sha256'] and len(raw)==row['text_bytes'],'retained actual accessible text differs')
            text=raw.decode('utf8')
        result.append((name,row,text))
    return result


def snapshot(value,pid,view,expected=None):
    need(value.get('pid')==pid and view in MANAGEMENT_VIEWS,'management snapshot process/view differs');rows=names(value)
    texts=[text for _,row,text in rows if row['showing'] and text is not None]
    body='\n'.join(texts);expected=expected or {}
    for text in expected.get('text',[]):
        need(any(text in s for s in texts),'actual management outcome/report text not showing')
    if view in ('management-doctor','management-orphans','management-failure') and expected.get('text'):
        need(len(expected['text'])==3 and sum(text==expected['text'][2] for text in texts)==1,
             'entire actual raw preview and truncation notice must match')
    for label,state in expected.get('buttons',{}).items():
        controls=[row for name,row,_ in rows if name==label and row['role']==43]
        need(len(controls)==1 and controls[0]['enabled'] is state and controls[0]['sensitive'] is state,'optional tool button sensitivity differs')
    return dict(node_count=len(rows),showing_text_sha256=[sha(t.encode()) for t in texts],expected=expected,body_sha256=sha(body.encode()))


def report(raw,kind,inventory):
    need(type(raw) is bytes and 0<len(raw)<=REPORT_CAP,'actual helper report byte bound');value=json.loads(raw)
    if kind=='doctor':
        need(value.get('tool')=='cachy-asahi-doctor' and value.get('scope')=='local observations only','actual Doctor report qualifier absent')
        counts={k:0 for k in ('checked','unavailable','unknown')}
        for row in value['checks']:need(row['state'] in counts,'Doctor state differs');counts[row['state']]+=1
        need(value['coverage']==counts,'Doctor actual coverage differs')
        summary='%d observed, %d unavailable, %d unknown.'%tuple(counts[k] for k in ('checked','unavailable','unknown'))
    elif kind=='orphans':
        need(value.get('scope')==SCOPE and value.get('apply_supported') is False and value.get('root')=='/' and value.get('dbpath')=='/var/lib/pacman' and
            {n:r['version'] for n,r in value['packages'].items()}==inventory,'actual target installed metadata differs')
        candidates=value['candidates'];broken=value['broken_dependencies'];need(candidates==sorted(n for n,r in value['packages'].items() if r['candidate']),'actual candidates differ')
        summary='%d possible orphan%s; %d broken dependenc%s. Assessment only; packages remain installed.'%(len(candidates),'' if len(candidates)==1 else 's',len(broken),'y' if len(broken)==1 else 'ies')
    else:
        need(kind=='failure' and value.get('verification')=='REFUSED' and 'ALPM lock' in value.get('reason','') and value.get('apply_supported') is False,'actual held-lock failure differs')
        summary='Assessment refused: '+value['reason']
    return value,summary


def process(row,tool,welcome_pid,stopped=False):
    path='/usr/bin/cachy-asahi-'+tool;need(row.get('argv')==[path,'--json' if tool=='doctor' else 'assess'] and
        row.get('uid')==[23001]*4 and type(row.get('pid')) is int and row['pid']>1 and
        type(row.get('starttime')) is int and type(row.get('supervisor_pid')) is int and row['supervisor_pid']>1 and
        row.get('welcome_pid')==welcome_pid and row.get('original_executable')==path and
        row.get('stopped') is stopped,'actual fixed helper child/supervisor identity differs')
    need(len({row['pid'],row['supervisor_pid'],welcome_pid})==3 and row.get('pgid')==row['pid'] and row.get('raw_argv',[])[-2:]==[path,'--json' if tool=='doctor' else 'assess'] and row.get('exe','').startswith('/usr/bin/python'),'owned helper group differs')


def action_plan(ui):
    labels=ui['labels'];rows=[(labels['management'],None,False),(labels['orphans'],None,True),(labels['management'],None,False)]
    for kind in ('doctor','orphans','failure'):
        tool='doctor' if kind=='doctor' else 'orphans';scope='Doctor' if tool=='doctor' else 'Orphan assessment'
        if kind=='failure':
            rows.extend(((labels[tool],None,True),(labels[tool],None,False),('View report',scope,False),('View report',scope,True),('View report',scope,False)))
        else:
            rows.extend(((labels[tool],None,True),(labels[tool],None,False),('View report',scope,False),('View report',scope,False)))
    return rows+[(labels['orphans'],None,True),(labels['orphans'],None,False)]


def visible_control(proof,pid,label,window,report_scope=None):
    need(report_scope is None or (report_scope in ('Stored DNS profiles','Orphan assessment') and label=='View report'),'exact DNS report visibility scope required')
    need(proof.get('status')=='PASS' and proof.get('pid')==pid and proof.get('interface')=='Component' and
         proof.get('action_name')=='ensure-visible' and proof.get('actions')==0 and proof.get('scroll_called') is True and
         proof.get('coordinate_space')=='ATSPI_SCREEN' and
         all(type(proof.get(k)) is bool for k in ('scroll_returned','focus_called','focused','unclipped_after_scroll')),
         'actual bounded component visibility operation required')
    need(base64.b64decode(proof.get('name_base64',''),validate=True).decode('utf8')==label,'visible action target name differs')
    method=proof.get('method')
    need((method=='COMPONENT_SCROLL' and proof['scroll_returned'] and not proof['focus_called'] and proof['unclipped_after_scroll']) or
         (method=='ALREADY_UNCLIPPED' and not proof['scroll_returned'] and not proof['focus_called'] and proof['unclipped_after_scroll']) or
         (method=='FOCUS_SCROLL' and proof['focus_called'] and proof['focused'] and not proof['unclipped_after_scroll']) or
         (method=='PEER_FOCUS_SCROLL' and not proof['focus_called'] and not proof['focused'] and not proof['unclipped_after_scroll']) or
         (method=='EXPANDED_DNS_REPORT_TEXT_FOCUS_SCROLL' and proof['focus_called'] and not proof['unclipped_after_scroll']),
         'scroll return/focus/visibility evidence differs')
    if method=='PEER_FOCUS_SCROLL':
        need({'peer_focus_reply','peer_focus_error'}<=set(proof),'complete peer focus reply provenance required')
        need((proof.get('peer_focus_reply')=='REPLIED' and proof.get('peer_focus_error') is None) or
             (proof.get('peer_focus_reply')=='TIMEOUT_STATE_CONFIRMED' and proof.get('peer_focus_error')=='timeout from dbind'),
             'exact peer focus reply or timeout-confirmed provenance required')
        expected={'Run Doctor':'Doctor','Assess orphan packages':'Orphan assessment'}
        peer=proof.get('peer_focus');need(type(peer) is dict and type(peer.get('pid')) is int and type(peer.get('role')) is int and
             all(type(peer.get(k)) is bool for k in ('enabled','sensitive','focused','same_panel','target_enabled','target_sensitive')),
             'typed actual peer focus evidence required')
        need(label in expected and peer==dict(pid=pid,role=62,name_base64='VmlldyByZXBvcnQ=',scope=expected[label],
             enabled=True,sensitive=True,focused=True,same_panel=True,target_enabled=False,target_sensitive=False),
             'actual enabled same-tool focus peer required for disabled target')
    else:need(not {'peer_focus','peer_focus_reply','peer_focus_error'}&set(proof),'unexpected peer focus evidence')
    chain=proof.get('chain');need(type(chain) is list and 3<=len(chain)<=13,'complete owned component ancestor chain required')
    def rectangle(row):
        need(type(row) is dict and row.get('pid')==pid and row.get('visible') is True and row.get('showing') is True and
             type(row.get('role')) is int,'visible owned ancestor required')
        rect=row.get('rect');need(type(rect) is list and len(rect)==4 and all(type(v) is int for v in rect) and
             all(-32768<=v<=32768 for v in rect[:2]) and all(0<v<=8192 for v in rect[2:]),'valid actual component rectangle required')
        return rect
    target=rectangle(chain[0]);tx,ty,tw,th=target
    roles=[]
    for row in chain:
        x,y,w,h=rectangle(row);roles.append(row['role'])
        need(x<=tx and y<=ty and tx+tw<=x+w and ty+th<=y+h,'action target clipped by an ancestor')
    need(roles[0]==(62 if report_scope is not None else 43) and roles[-1]==23 and roles.count(23)==1 and 68 in roles and 49 in roles,
         'button, viewport, scroll pane and owned top-level frame required')
    if method=='EXPANDED_DNS_REPORT_TEXT_FOCUS_SCROLL':
        need(report_scope=='Stored DNS profiles' and label=='View report','expanded report exact scope required')
        report=proof.get('report_focus')
        need(type(report) is dict and set(report)=={'scope','pid','role','matches','reply','target_checked','enabled','sensitive','visible','showing','focusable','focused','chain'},'complete typed report focus required')
        need(type(report.get('pid')) is int and type(report.get('role')) is int and type(report.get('matches')) is int and
             report['pid']==pid and report['role']==61 and report['matches']==1 and report['reply']=='REPLIED' and
             report['scope']=='Stored DNS profiles' and all(report.get(k) is True for k in
             ('target_checked','enabled','sensitive','visible','showing','focusable','focused')),'actual expanded owned unique text focus required')
        inner=report['chain'];need(type(inner) is list and 2<=len(inner)<=12 and len(inner)+len(chain)-1<=13 and inner[-1]==chain[0],
             'complete focus ancestry must join exact selected report')
        ix,iy,iw,ih=rectangle(inner[0])
        need(inner[0]['role']==61 and inner[-1]['role']==62,'text descendant to report roles required')
        for row in inner:
            x,y,w,h=rectangle(row)
            need(x<=ix and y<=iy and ix+iw<=x+w and iy+ih<=y+h,'focused report text clipped by ancestor')
    else:need('report_focus' not in proof,'unexpected report text focus evidence')
    # AT-SPI screen origins can differ from Wayland global origins. Join the
    # owned frame's relative target position to the independently checked client.
    need(type(window) is dict and window.get('pid')==pid and
         all(window.get(k) is True for k in ('mapped','visible','floating')) and
         all(window.get(k) is False for k in ('hidden','xwayland')) and window.get('at')==[12,12] and window.get('size')==[1000,550] and
         window.get('title')=='cachy-asahi Welcome' and window.get('class') in
         ('io.github.GabrielKahen.CachyAsahiWelcome','cachy-asahi-welcome') and
         re.fullmatch('0x[0-9a-fA-F]{1,16}',window.get('address','')),
         'actual fixed visible native Welcome action window required')
    fx,fy,_,_=chain[-1]['rect']
    need(0<=tx-fx and 0<=ty-fy and tx-fx+tw<=1000 and ty-fy+th<=550,
         'target outside actual compositor client area')


def action(row,pid,label,scope,scroll):
    proof=row['proof'];need(row.get('pid')==pid and row.get('label')==label and row.get('scope')==scope and row.get('scroll') is scroll and
        row.get('physical_input')=='NOT_RUN' and proof.get('status')=='PASS' and proof.get('pid')==pid,'actual management action identity differs')
    if scroll:visible_control(proof,pid,label,row.get('window'),report_scope=scope)
    else:need('interface' not in proof and proof.get('actions')==1 and proof.get('action_name') in ('click','activate','press','switch'),'actual management GTK action differs')


def preview(raw,ui,kind='doctor'):
    need(kind in ('doctor','orphans','failure'),'fixed preview tool required')
    limit=65536 if kind=='doctor' else ui['orphan_preview_bytes']
    suffix=ui['raw_preview_suffix'] if kind=='doctor' else ui['orphan_preview_suffix']
    return raw[:limit].decode(errors='replace')+(suffix if len(raw)>limit else '')


def retirement_reply(value,closing,operation):
    need(type(value) is dict and value.get('status')=='PASS' and value.get('operation')==operation and
         type(value.get('nonce')) is str and re.fullmatch('[0-9a-f]{32}',value['nonce']) and
         type(value.get('sequence')) is int and 0<=value['sequence']<1024 and value.get('process')==closing,
         'owned current closing reply identity differs')
    keys=('helper_absent','supervisor_absent','group_absent')
    need(all(type(value.get(k)) is bool for k in keys),'typed closing absence required')
    members=value.get('group_members');clipped=value.get('group_members_clipped')
    need(type(members) is list and len(members)<=32 and all(type(p) is int and p>1 for p in members) and
         len(set(members))==len(members) and type(clipped) is bool and
         value['group_absent']==(not members and not clipped),'closing group evidence differs')
    if operation=='retired':need(not {'inventory','nonselected_database'}&set(value),'metadata must follow fast retirement')
    return all(value[k] for k in keys)


def retirement_proof(fast,proof,closing,inventory):
    need(retirement_reply(fast,closing,'retired') and retirement_reply(proof,closing,'retired-proof'),
         'actual helper/supervisor/group absence required')
    need(proof['nonce']==fast['nonce'] and proof['sequence']==fast['sequence']+1,
         'adjacent current closing proof required')
    need(proof.get('inventory')==inventory and proof.get('nonselected_database')=='PRESERVED',
         'GUI fixture mutated nonselected metadata')


def verify_result(events,lock):
    need(lock.get('status')=='VERIFIED_NATIVE_CANDIDATES' and set(lock['products'])=={'cachy-asahi-welcome','cachy-asahi-doctor','cachy-asahi-orphans','cachy-asahi-dns'},'three real bound candidates required')
    ui=interface(lock['policy']);phases=[]
    for stage in ('minimal',):
        frames=[e for e in events if e.get('event')=='frame_ready' and e.get('stage')==stage and e.get('view') in MANAGEMENT_VIEWS]
        need([e['view'] for e in frames]==list(MANAGEMENT_VIEWS),'five original ordered management firstframes required')
        observations=[e for e in events if e.get('event')=='management_result' and e.get('stage')==stage]
        need(len(observations)==1,'one completed management exercise required');result=observations[0]
        need(result.get('metadata_readonly') is True and result.get('nonselected_database')=='PRESERVED' and result.get('welcome_exit')==0 and
            result.get('owned_group_absent') is True and result.get('owned_helper_absent') is True and result.get('owned_supervisor_absent') is True and
            result.get('scope')=='CURRENT606_GENERIC16K_UNPRIVILEGED_ACTUAL_DEFAULT_TOOLS' and result.get('hardware')=='NOT_RUN','actual close/readonly/preservation result absent')
        need(result.get('present_count')==606 and result.get('absent_count')==604 and len(result.get('inventory',{}))==606,'exact GUI profile counts differ')
        actions=[e for e in events if e.get('event')=='management_action' and e.get('stage')==stage]
        plan=action_plan(ui);need(len(actions)==len(plan),'eighteen actual management actions required')
        for i,(row,(label,scope,scroll)) in enumerate(zip(actions,plan)):
            need(row.get('sequence')==i+1,'ordered actual management operation sequence differs')
            action(row,frames[0 if i<2 else 1]['welcome_pid'],label,scope,scroll)
        need(events.index(actions[1])<events.index(frames[0])<events.index(actions[2]) and
             events.index(actions[-1])<events.index(frames[-1])<events.index(result),'actual management action/frame order differs')
        need(all(frame['welcome_pid']==frames[1]['welcome_pid'] for frame in frames[1:]),'one restored actual Welcome actor required')
        for frame in frames:
            semantic=frame['semantic'];raw=semantic['snapshot'];need(sha(encoded(raw))==semantic['snapshot_sha256'] and
                snapshot(raw,frame['welcome_pid'],frame['view'],semantic['expected'])==semantic['summary'],'management raw semantic replay differs')
            need(frame.get('capture_after_ms',0)>=5000 and frame.get('hardware')=='NOT_RUN' and frame.get('physical_input')=='NOT_RUN','firstframe timing/scope differs')
        for frame,text,buttons in ((frames[0],ui['strings']['unavailable'],{ui['labels']['doctor']:False,ui['labels']['orphans']:False}),
                                   (frames[-1],ui['strings']['running'],{ui['labels']['orphans']:False})):
            need(frame['semantic']['expected']==dict(text=[text],buttons=buttons),'absence/running state contract differs')
        for kind in ('doctor','orphans','failure'):
            row=result['reports'][kind];raw=base64.b64decode(row['base64'],validate=True)
            need(sha(raw)==row['sha256'] and len(raw)==row['bytes'],'actual retained helper stdout changed')
            _,summary=report(raw,kind,result['inventory']);frame=next(f for f in frames if f['view']=='management-'+kind)
            if kind=='doctor':
                gui_raw=base64.b64decode(row['gui_report']['base64'],validate=True)
                need(sha(gui_raw)==row['gui_report']['sha256'] and len(gui_raw)==row['gui_report']['bytes'] and len(gui_raw)<=65536,'actual full GUI Doctor report differs')
                _,summary=report(gui_raw,kind,result['inventory'])
                need(gui_raw.decode() in frame['semantic']['expected']['text'],'actual GTK Doctor report must be retained and joined')
            actual=gui_raw if kind=='doctor' else raw;tool='doctor' if kind=='doctor' else 'orphans'
            expected=dict(text=[ui['strings']['failure' if kind=='failure' else 'complete'],summary,preview(actual,ui,kind)],buttons={ui['labels'][tool]:True})
            need(frame['semantic']['expected']==expected and len(raw)<=ui['max_output_bytes'],'actual raw report and GUI conclusion not joined')
            start=3+4*('doctor','orphans','failure').index(kind)
            if kind=='failure':
                need(events.index(actions[start+2])<events.index(actions[start+3])<events.index(frame)<events.index(actions[start+4]),'actual failure report open/scroll/capture/close order differs')
            else:
                need(events.index(actions[start+2])<events.index(frame)<events.index(actions[start+3]),'actual report expander/capture order differs')
            process(row['gui_process'],'doctor' if kind=='doctor' else 'orphans',frame['welcome_pid'])
        process(result['closing_process'],'orphans',frames[-1]['welcome_pid'],True)
        need(events.index(frames[-1])<events.index(result),'close retirement must follow the original closing frame')
        need(result['closing_process']['pgid']!=frames[-1]['welcome_pid'],'cannot retire Welcome group as helper')
        retirement_proof(result.get('retirement_observation'),result.get('retirement_proof'),result['closing_process'],result['inventory'])
        phases.append(dict(stage=stage,reports={k:v['sha256'] for k,v in result['reports'].items()},closing='PASS_ACTUAL_OWNED_GROUP_RETIRED'))
    return dict(status='PASS_MANAGEMENT_NATIVE_METADATA_PIXELS_PENDING_REVIEW',phases=phases,hardware='NOT_RUN',orphan_removal='NOT_IMPLEMENTED')
