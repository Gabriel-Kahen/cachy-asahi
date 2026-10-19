# SPDX-License-Identifier: MIT
"""Three fixed opt-in tools; exact sources, licenses, data payload and lifecycle."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex

NAMES=('cachy-asahi-mirrors','cachy-asahi-zsh-syntax-highlighting','cachy-asahi-zsh-history-substring-search')
NAME='NO_COMPILED_TOOL_IN_THIS_LANE'  # The reused Welcome builder's ELF branch is inapplicable.
LABEL='org.cachy-asahi.tools-native.job'
HERE=Path(__file__).resolve().parent


def need(ok,message):
    if not ok:raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def safe(path):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n') and
         not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute path required')
    return path


def verify_source(source):
    final_spec()
    pins=json.loads((HERE/'source-pins.json').read_text())
    need(pins and all(any(n.startswith('packages/tools/'+name+'/') for n in pins) for name in NAMES),
         'all three final product sources must be frozen; no optional skip')
    for name,pin in pins.items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts,'unsafe source pin')
        path=safe(source/name)
        need(path.is_file() and path.stat().st_size<=16*1024**2 and digest(path)==pin,'source dependency differs: '+name)


def recipe(source,name):
    need(name in NAMES,'unknown tool')
    root=source/'packages/tools'/name
    checks=load('tools_recipe_checks',source/'scripts/checks/package_checks.py')
    text=(root/'PKGBUILD').read_text();meta={}
    for match in re.finditer(r'^([a-z_][a-z0-9_]*)=(\([^)]*\)|[^\n]*)',text,re.M):
        key,value=match.groups()
        need(key in checks.FIELDS|{'pkgdesc','url'} and key not in meta and not any(c in value for c in ('$','`',';','\\')),
             'constant single-package metadata required')
        meta[key]=shlex.split(value[1:-1] if value.startswith('(') else value,comments=True)
    inputs={}
    for path in root.iterdir():
        need(path.is_file() and not path.is_symlink() and path.stat().st_size<=1024**2,'bounded flat regular recipe inputs required')
        inputs[path.name]=digest(path)
    need(meta.get('pkgname')==[name] and meta.get('arch')==['any'] and
         not any(meta.get(k) for k in ('install','provides','conflicts','replaces','backup')),
         'small data/script-only recipe required: '+name)
    need(all(len(meta.get(k,[]))==1 for k in ('pkgver','pkgrel')) and not checks.platform_relations(meta),
         'single version/platform-safe recipe required')
    need(len(meta.get('source',[]))==len(meta.get('sha256sums',[])) and meta.get('source') and
         len(set(meta['source']))==len(meta['source']),'bounded unique local source/checksum set required')
    for local,pin in zip(meta['source'],meta['sha256sums']):
        need(local in inputs and re.fullmatch('[0-9a-f]{64}',pin) and inputs[local]==pin,'local source checksum differs: '+local)
    need(meta.get('makedepends',[])==(['python'] if name==NAMES[2] else []),'fixed build dependencies differ')
    expected={'PKGBUILD',*meta['source']}
    if name==NAMES[2]:expected.add('README.md')
    # Provenance is retained source evidence, deliberately not installed by the recipes.
    if name!=NAMES[0]:expected.add('source-provenance.json')
    if (root/'.SRCINFO').exists():expected.add('.SRCINFO')
    need(set(inputs)==expected and all('/' not in n and '://' not in n for n in meta['source']),
         'exact local offline source set required')
    need(set(meta['license'])==({'MIT'} if name==NAMES[0] else {'BSD-3-Clause','MIT'}),'tool license differs')
    need(meta.get('depends')==(['python>=3.11','ca-certificates'] if name==NAMES[0] else
         ['zsh>=4.3.11'] if name==NAMES[1] else ['zsh>=5.9']),'fixed runtime dependencies differ')
    return dict(metadata=meta,input_sha256=inputs)


def version(source,name):
    m=recipe(source,name)['metadata'];return m['pkgver'][0]+'-'+m['pkgrel'][0]


def spec():
    value=json.loads((HERE/'product-spec.json').read_text())
    need(set(value['products'])==set(NAMES),'three product payload maps required')
    return value


def final_spec():
    value=spec();need(value.get('status')=='FINAL_SOURCE_REVIEWED','final tool source/payload binding required')
    activation=value['products'][NAMES[0]].get('activation_cli')
    need(type(activation) is dict and set(activation)=={'activate','restore','refusal_exit'} and
         type(activation['refusal_exit']) is int and 1<=activation['refusal_exit']<=125,'final mirror activation CLI binding required')
    for verb in ('activate','restore'):
        args=activation[verb]
        need(type(args) is list and 2<=len(args)<=16 and args[0]==verb and
             all(type(arg) is str and len(arg)<=128 and (arg in ('{candidate}','{target}','{journal}','{catalog}','{report}') or
                 re.fullmatch('[A-Za-z0-9_-]+',arg)) for arg in args) and '{target}' in args and '{journal}' in args,
             'bounded fixed mirror activation argument vector required')
    return value


def files(name):
    need(name in NAMES,'unknown payload')
    rows=spec()['products'][name]['payload']
    need(type(rows) is dict and 1<=len(rows)<=32,'bounded exact payload map required')
    for target,row in rows.items():
        path=Path(target)
        need(type(target) is str and str(path)==target and not path.is_absolute() and '..' not in path.parts and
             target.startswith(('usr/bin/','usr/share/cachy-asahi/','usr/share/doc/','usr/share/licenses/')) and
             type(row) is list and len(row)==2 and Path(row[0]).name==row[0] and row[1] in (0o644,0o755),
             'reviewed source-to-installed mapping required')
    return rows


def payload(report,source,name):
    need(not report['errors'] and not report['elf'],'script/data payload required')
    expected=files(name);rows={n:r for n,r in report['members'].items() if r['type']!='5' and n not in ('.PKGINFO','.BUILDINFO','.MTREE')}
    need(set(rows)==set(expected),'exact tool payload differs: '+name)
    parents={str(p) for member in expected for p in Path(member).parents if str(p)!='.'}
    for n,row in report['members'].items():
        if row['type']=='5':need(n in parents,'unexpected empty payload directory')
    for n,(original,mode) in expected.items():
        row=rows[n]
        need(row['type']=='0' and row['mode']==mode and row['uid']==row['gid']==0 and
             row['sha256']==digest(source/'packages/tools'/name/original),'source/license/payload join differs: '+n)
    return rows


def check_log(path,name):
    need(path.stat().st_size<=16*1024**2,'build log cap')
    text=path.read_text(errors='replace');need('Starting check()' in text,'native check() disabled')
    for marker in spec()['products'][name]['check_markers']:
        need(type(marker) is str and marker and marker in text,'native product check summary absent')
    return dict(status='PASS_CHECK_EXIT',method='makepkg check() exit0; additional installed behavior required')


def validate_lifecycle(value):
    need(value.get('status')=='PASS_TOOLS_INSTALLED_CLI_PTY_LIFECYCLE' and value.get('base_count')==574 and
         value.get('installed_count')==577 and value.get('user_config_preserved') is True and
         value.get('system_config_preserved') is True and value.get('user_outputs_preserved') is True and
         value.get('hardware')=='NOT_RUN' and value.get('native_architecture')=='aarch64' and type(value.get('actual_page_size')) is int and value['actual_page_size']>0,
         'tools lifecycle acceptance absent')
    events=value.get('events');need(type(events) is list and len(events)==5,'five lifecycle transitions required')
    for event,(phase,count) in zip(events,(('install',577),('same-version-reinstall',577),('remove',574),('reinstall-after-removal',577),('final-remove',574))):
        need(event.get('phase')==phase and event.get('status')=='PASS' and event.get('inventory_count')==count and
             event.get('config_preserved') is True,'lifecycle transition differs')
        if count==577:
            rows=event.get('observations')
            need(type(rows) is list and len(rows)==2 and {r.get('home') for r in rows}=={'tools-home-fresh','tools-home-existing'},
                 'fresh/existing observations required')
            for row in rows:
                need(row.get('mirrors',{}).get('status')=='PASS_OFFLINE_TLS_CLI' and
                     row['mirrors'].get('activate_restore') is True and row['mirrors'].get('restore_conflict_preserved') is True and
                     row['mirrors'].get('repeat_activation_preserved') is True and row['mirrors'].get('repeat_restore_preserved') is True and
                     row.get('highlighting',{}).get('status')=='PASS_INSTALLED_ZLE' and
                     row.get('substring',{}).get('status')=='PASS_HOST_ZSH_PTY_CONTROLS' and
                     row['substring'].get('cases')==6,'real installed per-tool behavior absent')
        else:need(event.get('guarded_opt_in_absent') is True,'removed opt-in behavior untested')
