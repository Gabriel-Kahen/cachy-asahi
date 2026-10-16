# SPDX-License-Identifier: MIT
"""Bounded managed Welcome UI proofs and native visible-window identities."""
import base64
import importlib.util
import json
from pathlib import Path
import re


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


T=load('welcome_gui_data','terminal_workflow.py')
need,sha,read,publish,snapshot=T.need,T.sha,T.read,T.publish,T.snapshot
VIEWS=('home','terminal-action','files-action','system','first-steps','updates','recovery')
LABELS={'first-steps':'First steps','updates':'Updates','recovery':'Recovery'}
TITLE='cachy-asahi Welcome'
DOCTOR_TITLE='Doctor | installed local report'
DOCTOR_ID='cachy-asahi-doctor-proof'
RECTS={'welcome':([12,12],[1000,550]),'doctor':([12,580],[1000,176]),
       'welcome-action':([12,12],[550,550]),'action':([578,12],[434,550])}


class ViewPending(ValueError):pass


def window(clients,pid,kind,*,positioned=True):
    need(type(clients) is list and all(type(c) is dict for c in clients),'invalid clients')
    rows=[c for c in clients if type(c.get('pid')) is int and c['pid']==pid and c.get('mapped') is True]
    need(len(rows)<=1,'ambiguous app windows')
    if not rows or rows[0].get('visible') is not True:return None
    row=rows[0];need(row.get('hidden') is False and row.get('xwayland') is False and
         re.fullmatch('0x[0-9a-fA-F]{1,16}',row.get('address','')),'native app address required')
    if kind.startswith('welcome'):
        need(row.get('title')==TITLE and row.get('class') in
             ('io.github.GabrielKahen.CachyAsahiWelcome','cachy-asahi-welcome'),'Welcome identity differs')
    elif kind=='doctor':need(row.get('class')==DOCTOR_ID and row.get('title')==DOCTOR_TITLE,'Doctor terminal identity differs')
    elif kind=='terminal':need(row.get('class') in ('Alacritty','alacritty'),'launched terminal class differs')
    elif kind=='files':need(row.get('class') in ('Thunar','thunar','org.xfce.Thunar'),'launched Files class differs')
    else:raise ValueError('unknown app kind')
    if positioned:
        target=kind if kind in RECTS else 'action';at,size=RECTS[target]
        need(row.get('floating') is True and row.get('at')==at and row.get('size')==size,'fixed app layout differs')
    return row


def together(clients,welcome_pid,doctor_pid,view,action_pid=None):
    need(view in VIEWS and welcome_pid!=doctor_pid,'capture identity/view differs')
    primary='welcome-action' if view in ('terminal-action','files-action') else 'welcome'
    a,b=window(clients,welcome_pid,primary),window(clients,doctor_pid,'doctor')
    need(a is not None and b is not None,'Welcome and Doctor must remain visible')
    result=dict(welcome=a,doctor=b)
    if view in ('terminal-action','files-action'):
        kind='terminal' if view=='terminal-action' else 'files'
        child=window(clients,action_pid,kind);need(child is not None,'launched app must remain visible');result['action']=child
    for row in result.values():
        need(type(row.get('monitor')) is int and row['monitor']==a['monitor'] and
             type(row.get('workspace')) is dict and row['workspace'].get('id',0)>0 and
             row['workspace']==a['workspace'],'same compositor workspace/monitor required')
    need(len({r['address'] for r in result.values()})==len(result),'distinct native windows required')
    return result


def layout(command,row,kind):
    need(kind in RECTS and re.fullmatch('0x[0-9a-fA-F]{1,16}',row.get('address','')) and
         type(row.get('floating')) is bool,'safe layout target required')
    at,size=RECTS[kind];target='address:'+row['address']
    expressions=[] if row['floating'] else [f'hl.dsp.window.float({{action="set",window="{target}"}})']
    expressions.extend((
        f'hl.dsp.window.resize({{x={size[0]},y={size[1]},relative=false,window="{target}"}})',
        f'hl.dsp.window.move({{x={at[0]},y={at[1]},relative=false,window="{target}"}})'))
    for expression in expressions:
        need(command(['/usr/bin/hyprctl','dispatch',expression],'layout').strip()=='ok','layout dispatch failed')


def validate_snapshot(value,pid,view,text_sha=None):
    need(value.get('status')=='PASS' and value.get('pid')==pid and type(value.get('nodes')) is list and
         1<=len(value['nodes'])<=192,'owned accessibility snapshot required')
    names=[];texts=[];selected=[];selected_tabs=[]
    for row in value['nodes']:
        encoded=row.get('name_base64','');need(type(encoded) is str and len(encoded)<=216,'accessible name cap')
        name=base64.b64decode(encoded,validate=True).decode('utf-8',errors='replace')
        need(type(row.get('role')) is int and all(type(row.get(k)) is bool for k in ('showing','selected','checked')),
             'typed accessibility node required')
        if row['showing']:
            names.append(name)
            if row['selected'] or row['checked']:selected.append(name)
            if row['role']==37 and row['selected']:selected_tabs.append(name)
            if 'text_sha256' in row:
                need(re.fullmatch('[0-9a-f]{64}',row['text_sha256']) and type(row.get('text_bytes')) is int and
                     0<=row['text_bytes']<=262144,'accessible text hash/bound differs')
                texts.append(row['text_sha256'])
    ready=True
    if view=='home':ready={'Open Terminal','Open Files','First steps','Updates','Recovery'}<=set(names)
    elif view=='system':ready='Refresh system status' in names and text_sha in texts
    elif view in LABELS:ready=LABELS[view] in selected_tabs and text_sha in texts
    else:need(view in ('terminal-action','files-action'),'unknown accessibility view')
    if not ready:raise ViewPending('requested Welcome page/text not showing yet')
    return dict(showing_names=names,selected_names=selected,showing_text_sha256=texts,node_count=len(value['nodes']))



def validate_action(value,pid,label):
    need(value.get('status')=='PASS' and value.get('pid')==pid and type(value.get('actions')) is int and value['actions']==1,
         'one owned accessibility operation required')
    if value.get('action_name')=='select-child':
        guides=('First steps','Updates','Recovery')
        need(label in guides and value.get('interface')=='Selection' and
             type(value.get('target_role')) is int and value['target_role']==37 and
             type(value.get('parent_role')) is int and value['parent_role']==38 and
             type(value.get('child_index')) is int and value['child_index']==guides.index(label) and
             type(value.get('child_count')) is int and value['child_count']==3 and value.get('selected') is True and
             type(value.get('selected_count')) is int and value['selected_count']==1,
             'known guide notebook selection proof differs')
        return 'installed GTK AT-SPI notebook selection'
    need(value.get('action_name') in ('click','activate','press','switch') and 'interface' not in value,
         'real accessibility action required')
    return 'installed GTK AT-SPI action'


def validate_doctor(value,stage,nonce,terminal_pid):
    need(value.get('status')=='PASS_INSTALLED_DOCTOR_REPORT' and value.get('stage')==stage and value.get('nonce')==nonce and
         value.get('terminal_pid')==terminal_pid and type(value.get('worker_pid')) is int and value['worker_pid']>0 and
         value.get('terminal_isatty') is True and type(value.get('pty')) is str and value['pty'].startswith('/dev/pts/'),
         'owned Doctor PTY/result differs')
    report=value['doctor'];need(report.get('tool')=='cachy-asahi-doctor' and report.get('scope')=='local observations only',
                               'Doctor report scope differs')
    checks={r['check']:r for r in report['checks']};platform=checks['platform']['value']
    need(platform['architecture']=='aarch64' and platform['page_size_bytes']==4096,'actual generic ARM platform differs')
    for name in ('cachy-asahi-welcome','cachy-asahi-doctor'):
        need(checks['package/'+name]['state']=='checked' and checks['package/'+name]['value']==
             dict(group='project',presence='present',version='0.1.0-1'),'installed candidate observation differs')
    need(value.get('report_mode')=='0600' and value.get('no_overwrite')=='PASS' and value.get('symlink_refusal')=='PASS' and
         re.fullmatch('[0-9a-f]{64}',value.get('report_sha256','')),'Doctor publication/preservation proof absent')
