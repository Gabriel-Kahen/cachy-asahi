# SPDX-License-Identifier: MIT
"""Fixed Fish autopair source, payload and actual native lifecycle contract."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex

HERE=Path(__file__).resolve().parent
PACKAGE='cachy-asahi-fish-autopair'
NAMES=(PACKAGE,)
NAME='NO_COMPILED_ADDON'  # The inherited Welcome ELF branch must stay inactive.
LABEL='org.cachy-asahi.fish-autopair-native.job'
UPSTREAM='4d1752ff5b39819ab58d7337c69220342e9de0e2'
HELPERS=('_autopair_backspace.fish','_autopair_insert_left.fish','_autopair_insert_right.fish','_autopair_insert_same.fish','_autopair_tab.fish')
CASES=('noninteractive','default','vi','hybrid','custom-key','custom-prefix','custom-generic','custom-tab',
       'preset-key','existing-function','existing-autoload','existing-variable','custom-keymap','existing-wrapper')
EDIT_CASES=('round-open','square-open','brace-open','double-open','single-open','nested','closer-skip','quote-skip',
            'pair-backspace','pair-ctrl-h','brace-delete','quote-delete','single-delete','nested-skip','text-delete',
            'escaped-quote','escaped-bracket','quoted-data','tab-basic')


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
    pins=json.loads((HERE/'source-pins.json').read_text());path=safe(source/name);raw=path.read_bytes()
    need(len(raw)<=16*1024**2 and hashlib.sha256(raw).hexdigest()==pins.get(name),'pinned source differs: '+name);return raw.decode()


def verify_source(source):
    pins=json.loads((HERE/'source-pins.json').read_text())
    need(len([n for n in pins if n.startswith('packages/tools/'+PACKAGE+'/')])==15,'all15 final Fish sources required')
    for name in pins:
        need(not Path(name).is_absolute() and '..' not in Path(name).parts,'safe source pin required');pinned(source,name)


def recipe(source,name=PACKAGE):
    need(name==PACKAGE,'one fixed Fish candidate required');root=source/'packages/tools'/name
    meta={}
    for match in re.finditer(r'^([a-z_][a-z0-9_]*)=(\([^)]*\)|[^\n]*)',(root/'PKGBUILD').read_text(),re.M):
        key,value=match.groups()
        need(key not in meta and key in {'pkgname','pkgver','pkgrel','pkgdesc','arch','url','license','depends','makedepends','source','sha256sums'} and
             not any(c in value for c in ('$','`',';','\\')),'constant Fish recipe metadata required')
        meta[key]=shlex.split(value[1:-1] if value.startswith('(') else value,comments=True)
    expected={'PKGBUILD','.SRCINFO','README.md','check-module.py','usage.md','source-provenance.json','NOTICE',
              'LICENSE.upstream','LICENSE.project','opt-in.fish',*HELPERS}
    need({p.name for p in root.iterdir()}==expected and len(expected)==15,'exact15 Fish recipe inputs required')
    inputs={}
    for path in root.iterdir():
        need(path.is_file() and not path.is_symlink() and path.stat().st_size<=1024**2,'regular bounded source required');inputs[path.name]=digest(path)
    need(meta.get('pkgname')==[PACKAGE] and meta.get('pkgver')==['0.1.0'] and meta.get('pkgrel')==['1'] and
         meta.get('arch')==['any'] and meta.get('license')==['MIT'] and meta.get('depends')==['fish>=4.9.3'] and
         meta.get('makedepends')==['python'] and len(meta.get('source',[]))==len(meta.get('sha256sums',[]))==12,
         'fixed any/MIT/Fish4.9.3/Python metadata required')
    need(set(meta['source'])==expected-{'PKGBUILD','.SRCINFO','README.md'},'exact offline source set differs')
    for name,pin in zip(meta['source'],meta['sha256sums']):need(re.fullmatch('[0-9a-f]{64}',pin) and inputs[name]==pin,'local source checksum differs')
    provenance=json.loads((root/'source-provenance.json').read_text())
    need(provenance.get('revision')==UPSTREAM and provenance.get('license')=='MIT','upstream revision/license differs')
    original={r['path']:r for r in provenance['files']}
    for name in HELPERS:need(inputs[name]==original['functions/'+name]['sha256'],'unchanged upstream helper differs')
    need(inputs['LICENSE.upstream']==original['LICENSE.md']['sha256'],'complete upstream license differs')
    return dict(metadata=meta,input_sha256=inputs)


def version(source,name=PACKAGE):recipe(source,name);return '0.1.0-1'


def files(name=PACKAGE):
    need(name==PACKAGE,'unknown Fish payload');base='usr/share/cachy-asahi/fish-autopair/'
    return {**{base+n:(n,0o644) for n in (*HELPERS,'opt-in.fish','source-provenance.json')},
            base+'README.md':('usage.md',0o644),
            **{'usr/share/licenses/'+PACKAGE+'/'+n:(n,0o644) for n in ('NOTICE','LICENSE.upstream','LICENSE.project')}}


def payload(report,source,name=PACKAGE):
    need(not report['errors'] and not report['elf'],'script/data-only Fish package required')
    expected=files(name);rows={n:r for n,r in report['members'].items() if r['type']!='5' and n not in ('.PKGINFO','.BUILDINFO','.MTREE')}
    need(set(rows)==set(expected),'exact11 Fish payload files required')
    parents={str(p) for member in expected for p in Path(member).parents if str(p)!='.'}
    for member,row in report['members'].items():
        if row['type']=='5':need(member in parents,'unexpected empty payload directory')
    for member,(original,mode) in expected.items():
        row=rows[member];need(row['type']=='0' and row['mode']==mode and row['uid']==row['gid']==0 and
            row['sha256']==digest(source/'packages/tools'/PACKAGE/original),'source/license/payload join differs: '+member)
    return rows


def check_log(path,name=PACKAGE):
    need(name==PACKAGE and path.stat().st_size<=16*1024**2,'fixed bounded Fish build log required')
    text=path.read_text(errors='replace');need('Starting check()' in text,'makepkg check() disabled')
    need(any(re.search(r'"status"\s*:\s*"PASS"',line) and re.search(r'"cases"\s*:\s*14\b',line)
             for line in text.splitlines()),'actual Fish check() fourteen-case result absent')
    return dict(status='PASS_CHECK_EXIT',cases=14,installed_behavior='REQUIRED_SEPARATELY')


def validate_pty(value,wrapper_sha):
    need(value.get('status')=='PASS' and value.get('platform')=='aarch64' and value.get('fish')=='fish, version 4.9.3' and
         value.get('wrapper_sha256')==wrapper_sha and set(value.get('cases',{}))==set(CASES),'actual installed Fish/PTY identity differs')
    snapshots=0
    for name,case in value['cases'].items():
        need(type(case.get('exit')) is int and case['exit']==0,'all normal Fish exits required')
        if name=='noninteractive':continue
        enabled=name in ('default','vi','hybrid');rows=case.get('snapshots')
        need(case.get('activation')==('enabled' if enabled else 'yielded') and type(rows) is list and len(rows)==(19 if enabled else 0),
             'enabled/yielded Fish case or snapshot count differs')
        if enabled:
            need([r.get('case') for r in rows]==list(EDIT_CASES) and all(set(r)=={'case','buffer','cursor'} and
                 type(r['buffer']) is str and len(r['buffer'])<=4096 and type(r['cursor']) is int and
                 0<=r['cursor']<=len(r['buffer']) for r in rows),'typed ordered Fish editing snapshots required')
        snapshots+=len(rows)
    need(snapshots==57,'all57 installed editing snapshots required')


def validate_retained_lifecycle(report, actual):
    need(report.get('lifecycle') == actual, 'parent/standalone lifecycle mismatch')
    # The report is sorted JSON; only the original record retains the receipt's
    # serialized field order needed by its exact byte digest.
    validate_lifecycle(actual)


def validate_lifecycle(value):
    need(value.get('status')=='PASS_FISH_AUTOPAIR_INSTALLED_LIFECYCLE' and value.get('base_count')==574 and
         value.get('installed_count')==575 and value.get('user_config_preserved') is True and
         value.get('system_config_preserved') is True and value.get('user_outputs_preserved') is True and
         value.get('hardware')=='NOT_RUN' and value.get('native_architecture')=='aarch64' and
         type(value.get('actual_page_size')) is int and value['actual_page_size']>0,'Fish lifecycle acceptance absent')
    pin=json.loads((HERE/'source-pins.json').read_text())['packages/tools/'+PACKAGE+'/opt-in.fish']
    need(value.get('wrapper_sha256')==pin,'frozen installed Fish wrapper digest differs')
    events=value.get('events');need(type(events) is list and len(events)==5,'five exact Fish lifecycle transitions required')
    for event,(phase,count) in zip(events,(('install',575),('same-version-reinstall',575),('remove',574),('reinstall-after-removal',575),('final-remove',574))):
        need(event.get('phase')==phase and event.get('status')=='PASS' and event.get('inventory_count')==count and
             event.get('config_preserved') is True,'Fish lifecycle transition differs')
        if count==575:
            rows=event.get('observations');need(type(rows) is list and len(rows)==2 and
                {r.get('home') for r in rows}=={'fish-home-fresh','fish-home-existing'},'both Fish user homes required')
            for row in rows:
                need(re.fullmatch('[0-9a-f]{64}',row.get('receipt_sha256','')) and
                     re.fullmatch('[0-9a-f]{64}',row.get('fish_sha256','')),'actual receipt and Fish executable hashes required')
                validate_pty(row['proof'],value['wrapper_sha256'])
                raw=(json.dumps(row['proof'],indent=2)+'\n').encode()
                need(hashlib.sha256(raw).hexdigest()==row['receipt_sha256'],'Fish receipt bytes/digest join differs')
        else:need(event.get('guarded_opt_in_absent') is True,'removed guarded Fish opt-in check absent')
