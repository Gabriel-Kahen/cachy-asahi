# SPDX-License-Identifier: MIT
"""Fixed Done sources, actual recorder-only PTYs and installed lifecycle."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex

HERE=Path(__file__).resolve().parent
PACKAGE='cachy-asahi-fish-done'
NAMES=(PACKAGE,)
NAME='NO_COMPILED_ADDON'
LABEL='org.cachy-asahi.fish-done-native.job'
UPSTREAM='b86292a52a2b8f646ef8d25daa3cc01ccab60b62'
RECORDER_SHA='4a843e1cd7e9c94d4ec076547b5a3ebff95ca22ae54c1fbc407b8451f87c369c'
SCOPE='local notify-send process shim invocation only; no actual notification manager or visual display'
CASES=('noninteractive','foreground','background','watch-rejection','disown','repeat-preserve','command-data',
       'transport-failure','transport-timeout','disable','existing-function','existing-autoload','existing-variable',
       'existing-wrapper','existing-public','no-bus','notify-send','timeout')
YIELDED=set(CASES[10:])


def need(ok,message):
    if not ok:raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def safe(path):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n') and
         not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute path required');return path


def pinned(source,name):
    pins=json.loads((HERE/'source-pins.json').read_text());raw=safe(source/name).read_bytes()
    need(len(raw)<=16*1024**2 and hashlib.sha256(raw).hexdigest()==pins.get(name),'pinned source differs: '+name);return raw.decode()


def verify_source(source):
    pins=json.loads((HERE/'source-pins.json').read_text())
    need(len([n for n in pins if n.startswith('packages/tools/'+PACKAGE+'/')])==12,'all12 final Done inputs required')
    for name in pins:
        need(not Path(name).is_absolute() and '..' not in Path(name).parts,'safe source pin required');pinned(source,name)


def recipe(source,name=PACKAGE):
    need(name==PACKAGE,'one fixed Done candidate required');root=source/'packages/tools'/name;meta={}
    for match in re.finditer(r'^([a-z_][a-z0-9_]*)=(\([^)]*\)|[^\n]*)',(root/'PKGBUILD').read_text(),re.M):
        key,value=match.groups()
        need(key not in meta and key in {'pkgname','pkgver','pkgrel','pkgdesc','arch','url','license','depends','makedepends','source','sha256sums'} and
             not any(c in value for c in ('$','`',';','\\')),'constant Done recipe metadata required')
        meta[key]=shlex.split(value[1:-1] if value.startswith('(') else value,comments=True)
    expected={'PKGBUILD','.SRCINFO','README.md','check-module.py','usage.md','source-provenance.json','NOTICE',
              'LICENSE.upstream','LICENSE.project','opt-in.fish','done.fish','done.upstream.fish'}
    need({p.name for p in root.iterdir()}==expected,'exact12 Done recipe inputs required');inputs={}
    for path in root.iterdir():
        need(path.is_file() and not path.is_symlink() and path.stat().st_size<=1024**2,'bounded regular input required');inputs[path.name]=digest(path)
    need(meta.get('pkgname')==[PACKAGE] and meta.get('pkgver')==['0.1.0'] and meta.get('pkgrel')==['2'] and
         meta.get('arch')==['any'] and meta.get('license')==['MIT'] and meta.get('depends')==['fish>=4.9.3','libnotify','coreutils'] and
         meta.get('makedepends')==['python'] and len(meta.get('source',[]))==len(meta.get('sha256sums',[]))==9 and
         set(meta['source'])==expected-{'PKGBUILD','.SRCINFO','README.md'},'fixed offline any/MIT/dependency source set required')
    for name,pin in zip(meta['source'],meta['sha256sums']):need(re.fullmatch('[0-9a-f]{64}',pin) and inputs[name]==pin,'local source checksum differs')
    provenance=json.loads((root/'source-provenance.json').read_text());original={r['path']:r for r in provenance['files']}
    need(provenance.get('revision')==UPSTREAM and provenance.get('license')=='MIT' and
         inputs['done.upstream.fish']==original['conf.d/done.fish']['sha256'] and
         inputs['LICENSE.upstream']==original['LICENSE']['sha256'],'original upstream runtime/license join differs')
    return dict(metadata=meta,input_sha256=inputs)


def version(source,name=PACKAGE):recipe(source,name);return '0.1.0-2'


def files(name=PACKAGE):
    need(name==PACKAGE,'unknown Done payload');base='usr/share/cachy-asahi/fish-done/'
    return {**{base+n:(n,0o644) for n in ('done.fish','done.upstream.fish','opt-in.fish','source-provenance.json')},
            base+'README.md':('usage.md',0o644),
            **{'usr/share/licenses/'+PACKAGE+'/'+n:(n,0o644) for n in ('NOTICE','LICENSE.upstream','LICENSE.project')}}


def payload(report,source,name=PACKAGE):
    need(not report['errors'] and not report['elf'],'Done script/data package required')
    expected=files(name);rows={n:r for n,r in report['members'].items() if r['type']!='5' and n not in ('.PKGINFO','.BUILDINFO','.MTREE')}
    need(set(rows)==set(expected),'exact8 Done payload files required')
    parents={str(p) for member in expected for p in Path(member).parents if str(p)!='.'}
    for member,row in report['members'].items():
        if row['type']=='5':need(member in parents,'unexpected empty payload directory')
    for member,(original,mode) in expected.items():
        row=rows[member];need(row['type']=='0' and row['mode']==mode and row['uid']==row['gid']==0 and
            row['sha256']==digest(source/'packages/tools'/PACKAGE/original),'source/license/payload join differs: '+member)
    return rows


def check_log(path,name=PACKAGE):
    need(name==PACKAGE and path.stat().st_size<=16*1024**2,'bounded Done build log required');text=path.read_text(errors='replace')
    need('Starting check()' in text and any(re.search(r'"status"\s*:\s*"PASS"',line) and
         re.search(r'"cases"\s*:\s*18\b',line) for line in text.splitlines()),'actual eighteen-case Done check() result absent')
    return dict(status='PASS_CHECK_EXIT',cases=18,installed_behavior='REQUIRED_SEPARATELY',notification_scope='LOCAL_RECORDER_ONLY')


def invocation(value,failed=False,kind='Foreground command',private=True):
    args=value.get('argv')
    need(type(args) is list and len(args)==8 and all(type(a) is str and len(a)<=4096 for a in args) and
         args[:6]==['--hint=int:transient:1','--urgency='+('critical' if failed else 'normal'),
         '--icon=utilities-terminal','--app-name=fish','--expire-time=3000','--'] and
         args[6].startswith('Failed (' if failed else 'Done in '),'Done recorder argv/status contract differs')
    if private:need(args[7]==kind+' completed.','default Done notification disclosed command/directory')
    return args


def validate_pty(value,wrapper_sha,runtime_sha):
    need(value.get('status')=='PASS' and value.get('machine')=='aarch64' and value.get('fish')=='fish, version 4.9.3' and
         value.get('wrapper_sha256')==wrapper_sha and value.get('runtime_sha256')==runtime_sha and value.get('scope')==SCOPE and
         set(value.get('cases',{}))==set(CASES),'actual installed recorder-only Done identity differs')
    for name,case in value['cases'].items():
        need(type(case.get('exit')) is int and case['exit']==0 and type(case.get('notifications')) is int and
             0<=case['notifications']<=32,'all normal Done exits and bounded recorder counts required')
        if name=='noninteractive' or name in YIELDED:
            need(case['notifications']==0 and (name=='noninteractive' or case.get('activation')=='yielded'),'yielded Done module notified')
        else:need(case.get('activation')=='enabled' and type(case.get('proofs')) is list,'enabled Done behavior missing')
    cases=value['cases'];foreground=cases['foreground']['proofs'];background=cases['background']['proofs']
    need(len(foreground)==2 and len(background)==3,'foreground and actual watched child outcomes required')
    invocation(foreground[0]);need('Failed (7)' in invocation(foreground[1],True)[6],'foreground child status7 absent')
    invocation(background[0],kind='Watched job')
    for row,status in zip(background[1:],(7,143)):
        need('Failed ('+str(status)+')' in invocation(row,True,'Watched job')[6],'actual PROCESS_EXIT outcome absent')
    command=cases['command-data']['proofs'];need(len(command)==1,'escaped optional command proof required')
    args=invocation(command[0],private=False)
    need('&lt;tag&gt; $HOME $(touch PWNED) --leading' in args[7],'Done literal/XML command privacy control absent')
    for name in ('transport-failure','transport-timeout'):
        rows=cases[name]['proofs'];need(len(rows)==1,'bounded transport proof required');row=rows[0]
        elapsed=row.get('elapsed_seconds');need(type(elapsed) in (float,int) and 0<=elapsed<4.5,'Done transport exceeded finite bound')
        if name=='transport-timeout':need(elapsed>=2.5,'three-second TERM/kill recorder control absent')
        invocation(row['invocation'])


def validate_lifecycle(value):
    need(value.get('status')=='PASS_FISH_DONE_INSTALLED_LIFECYCLE' and value.get('base_count')==574 and value.get('installed_count')==575 and
         all(value.get(n) is True for n in ('user_config_preserved','system_config_preserved','user_outputs_preserved')) and
         value.get('hardware')=='NOT_RUN' and value.get('native_architecture')=='aarch64' and value.get('notification_scope')=='LOCAL_RECORDER_ONLY' and
         type(value.get('actual_page_size')) is int and value['actual_page_size']>0,'Done lifecycle acceptance absent')
    pins=json.loads((HERE/'source-pins.json').read_text());base='packages/tools/'+PACKAGE+'/'
    need(value.get('wrapper_sha256')==pins[base+'opt-in.fish'] and value.get('runtime_sha256')==pins[base+'done.fish'],'frozen installed Done digests differ')
    events=value.get('events');need(type(events) is list and len(events)==5,'five Done lifecycle transitions required')
    for event,(phase,count) in zip(events,(('install',575),('same-version-reinstall',575),('remove',574),('reinstall-after-removal',575),('final-remove',574))):
        need(event.get('phase')==phase and event.get('status')=='PASS' and event.get('inventory_count')==count and
             event.get('config_preserved') is True,'Done lifecycle transition differs')
        if count==575:
            rows=event.get('observations');need(type(rows) is list and len(rows)==2 and
                {r.get('home') for r in rows}=={'fish-home-fresh','fish-home-existing'},'both Done user homes required')
            for row in rows:
                need(re.fullmatch('[0-9a-f]{64}',row.get('receipt_sha256','')) and re.fullmatch('[0-9a-f]{64}',row.get('fish_sha256','')),
                     'actual receipt/Fish executable hashes required')
                validate_pty(row['proof'],value['wrapper_sha256'],value['runtime_sha256'])
                need(hashlib.sha256((json.dumps(row['proof'],indent=2)+'\n').encode()).hexdigest()==row['receipt_sha256'],'Done receipt byte/digest join differs')
                validate_recorders(row['recorders'],row['proof'])
        else:need(event.get('guarded_opt_in_absent') is True,'removed Done guarded source check absent')


def validate_recorders(recorders,proof):
    need(type(recorders) is dict and set(recorders)==set(CASES),'all18 local recorder observations required')
    for name,row in recorders.items():
        rows=row.get('rows');need(type(rows) is list and len(rows)<=32,'bounded local recorder rows required')
        need(row.get('transport')==('ABSENT_CONTROL' if name=='notify-send' else 'PRIVATE_NOTIFY_SEND_RECORDER') and
             (name=='notify-send' or row.get('shim_sha256')==RECORDER_SHA),'real notification transport must stay the exact local recorder')
        for event in rows:
            need(set(event)=={'argv','pid'} and type(event['pid']) is int and event['pid']>0 and
                 type(event['argv']) is list and len(event['argv'])==8 and
                 all(type(arg) is str and len(arg)<=4096 for arg in event['argv']),'bounded raw local recorder event required')
        if rows:
            raw=''.join(json.dumps(event)+'\n' for event in rows).encode()
            need(hashlib.sha256(raw).hexdigest()==row.get('transcript_sha256'),'actual local recorder transcript hash differs')
        for expected in proof['cases'][name].get('proofs',[]):
            expected=expected.get('invocation',expected)
            need(any(event['argv']==expected['argv'] for event in rows),'Done proof did not come from its local recorder')
        if name=='noninteractive' or name in YIELDED:need(not rows,'yielded Done recorder received an invocation')
        if name in ('watch-rejection','disown'):
            need(not any(event['argv'][7]=='Watched job completed.' for event in rows),'rejected/disowned job notified')
        if name=='transport-timeout':need(row.get('recorded_pids_absent') is True,'timed-out local recorder survived')
        if name=='repeat-preserve':
            need(all(row.get(key) is True for key in ('hooks_preserved','caller_continued','custom_binding_preserved')),
                 'Done repeat lost user hooks, binding or source caller continuation')
