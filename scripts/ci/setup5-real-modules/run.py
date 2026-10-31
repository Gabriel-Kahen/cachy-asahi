#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real setup5-generated startup files feeding the existing six-module host PTYs."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import types

INDEX_SHA='b1e4208d2f32935f2e5cb1c1e3535cc49f44c7bfe08e7d64692b8ac3781d5a5d'
ARCHIVE_SHA='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc'
CLI_SHA='ea505b6437a416c49e494e9ee0a16a9b160e95fed232ef920ad29aa510e28afd'
MODULES=('fish-bang-bang','fish-autopair','fish-done','zsh-autosuggestions','zsh-syntax-highlighting','zsh-history-substring-search')
USER_CONFIG='# preserved existing user configuration\nprintf \'%s\' user-sourced > "$HOME/setup5-user-sourced"\n'
HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True


def need(ok,why):
    if not ok:raise ValueError(why)


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def safe(path):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute paths required');return path


def accepted_cli(root,out):
    root=safe(root);index=root/'index.json';need(index.stat().st_size==25005 and digest(index)==INDEX_SHA,'accepted setup5 index identity differs')
    value=json.loads(index.read_text());need(value['status']=='ROOT_ACCEPTED_NATIVE_SETUP5_PAIR_AND_LEGACY_LIFECYCLE_INPUTS' and value['native_run']==38934198468 and value['version']=='0.1.0-5' and len(value['files'])==147,'exact accepted setup5 input set required')
    nodes=list(root.rglob('*'));need(len(nodes)<256 and all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in nodes),'ordinary bounded accepted tree required')
    actual={str(p.relative_to(root)) for p in nodes if p.is_file()};need(actual==set(value['files'])|{'index.json','README.md'} and len(actual)==149 and sum((root/n).stat().st_size for n in actual)==1305823,'complete accepted149 file/byte closure required')
    for name,row in value['files'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts,'safe accepted member required');path=safe(root/name)
        need(path.is_file() and path.stat().st_size==row['bytes']<=2*1024**2 and digest(path)==row['sha256'],'accepted member bytes differ: '+name)
    archives=[root/'packages'/('cachy-asahi-setup-'+side)/'cachy-asahi-setup-0.1.0-5-any.pkg.tar.xz' for side in ('a','b')]
    need(all(p.stat().st_size==26872 and digest(p)==ARCHIVE_SHA for p in archives),'accepted exact native archive pair differs')
    with tarfile.open(archives[0],'r:xz') as archive:
        members=[m for m in archive if m.name.removeprefix('./')=='usr/bin/cachy-asahi-setup']
        need(len(members)==1 and members[0].isfile() and members[0].size<=131072 and members[0].mode==0o755,'one ordinary accepted setup CLI required')
        raw=archive.extractfile(members[0]).read()
    need(hashlib.sha256(raw).hexdigest()==CLI_SHA,'accepted setup CLI byte pin differs');target=out/'accepted-setup5-cli';target.write_bytes(raw);target.chmod(0o755)
    return target,dict(index_sha256=INDEX_SHA,archive_sha256=ARCHIVE_SHA,cli_sha256=CLI_SHA,native_input_run=38934198468,input_ref='79d8d2f53510e4f3a04f39c1b1e24c999aa32e44',scope='accepted input provenance only; this execution is host-only')


def snapshot(home):
    rows={};total=0
    for path in sorted(home.rglob('*')):
        need(len(rows)<256,'bounded private home required');info=path.lstat();row=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid)
        if path.is_symlink():row.update(kind='link',target=os.readlink(path))
        elif path.is_file():
            total+=info.st_size;need(info.st_size<=1024**2 and total<=4*1024**2,'bounded private fixture bytes required');row.update(kind='file',bytes=info.st_size,sha256=digest(path),mtime_ns=info.st_mtime_ns)
        else:need(path.is_dir(),'ordinary fixture node required');row['kind']='directory'
        rows[str(path.relative_to(home))]=row
    return rows


class SetupHomes:
    def __init__(self,cli,templates,root):
        self.cli,self.templates,self.root=cli,templates,root;self.expected={};self.pending={};self.records={}

    def paths(self,home):return {'fish':home/'config/fish/config.fish','zsh':home/'.zshrc'}

    def seed(self,home):
        for path in self.paths(home).values():
            path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);path.write_text(USER_CONFIG);path.chmod(0o640)

    def invoke(self,home,operation,components=(),apply=False,expected=0):
        argv=[sys.executable,'-I','-B',str(self.cli),operation,'--home',str(home),'--config-home',str(home/'config'),'--zdotdir',str(home),'--state-dir',str(home/'setup-state'),'--template-root',str(self.templates)]
        if components:argv+=['--components',*components]
        if apply:argv+=['--apply']
        env=dict(PATH='/usr/bin:/bin',HOME=str(home),XDG_CONFIG_HOME=str(home/'config'),XDG_DATA_HOME=str(home/'data'),XDG_STATE_HOME=str(home/'state'),ZDOTDIR=str(home),PYTHONDONTWRITEBYTECODE='1')
        result=subprocess.run(argv,env=env,cwd=home,capture_output=True,timeout=10)
        need(len(result.stdout)+len(result.stderr)<65536 and result.returncode==expected,'setup5 CLI outcome differs: '+operation+' exit '+str(result.returncode)+' '+result.stderr.decode(errors='replace')[:160])
        return json.loads(result.stdout)

    def activate(self,home,selected):
        need(home not in self.records,'one initial activation per private home');before=snapshot(home)
        self.invoke(home,'activate',selected);need(snapshot(home)==before,'setup preview changed private home')
        report=self.invoke(home,'activate',selected,True);state=json.loads((home/'setup-state/state.json').read_text())
        need(set(state['components'])==set(MODULES) and len(report['actions'])==6,'all six explicit module records required')
        for path in self.paths(home).values():need(path.read_text().startswith(USER_CONFIG) and stat.S_IMODE(path.stat().st_mode)==0o640,'existing custom bytes/mode lost')
        for shell,names in [('fish',MODULES[:3]),('zsh',MODULES[3:])]:
            text=self.paths(home)[shell].read_text();positions=[text.index('# >>> cachy-asahi setup '+n+' v1 >>>') for n in names];need(positions==sorted(positions),'generated module source order differs')
        before=snapshot(home);repeat=self.invoke(home,'activate',selected,True);need(snapshot(home)==before and all(a['status']=='unchanged' for a in repeat['actions']),'setup repeat changed home/state')
        self.expected[home]=self.paths(home)['fish'].read_text();self.records[home]=dict(selected=list(selected),effective_order=list(MODULES),preview_readonly=True,repeat_unchanged=True,generated={s:digest(p) for s,p in self.paths(home).items()})

    def combined(self,root,name,paths):
        shell='fish' if name.endswith('.fish') else 'zsh';home=root/name.rsplit('.',1)[0]
        names=[]
        for path in paths:
            text=str(path)
            matches=[m for m in MODULES if '/cachy-asahi-'+m+'/' in text]
            # The inherited highlighting staging alias is used only to identify its requested selection.
            if 'highlight-runtime' in text:matches=['zsh-syntax-highlighting']
            need(len(matches)==1,'one known module source required');names+=matches
        selected=tuple(dict.fromkeys([*names,*MODULES]));self.pending[home]=selected
        if home.exists():self.activate(home,selected)
        return self.paths(home)[shell]

    def remove(self,home):
        before=snapshot(home);paths=self.paths(home);report=self.invoke(home,'remove',apply=True)
        after=snapshot(home);need(set(before)==set(after),'normal removal changed fixture membership')
        managed={str(p.relative_to(home)) for p in paths.values()}|{'setup-state/state.json'}
        need(all(after[n]==row for n,row in before.items() if n not in managed),'removal changed unrelated user files/state metadata')
        for path in paths.values():need(path.read_text()==USER_CONFIG and stat.S_IMODE(path.stat().st_mode)==0o640,'normal removal did not restore exact user bytes/modes')
        state=json.loads((home/'setup-state/state.json').read_text());need(state=={'schema_version':1,'roots':{'config':'config','zsh':'.'},'components':{}},'normal removal left ownership')
        need(len(report['actions'])==6 and all(a['status']=='remove' for a in report['actions']),'six owned removals required')
        return dict(status='PASS',user_bytes_modes_preserved=True,unrelated_user_files_preserved=True,state_components=0)

    def conflicts(self):
        home=self.root/'edited-conflict-user';home.mkdir(mode=0o700);self.seed(home);self.activate(home,MODULES)
        edited=('fish-done','zsh-history-substring-search')
        for component,shell in zip(edited,('fish','zsh')):
            path=self.paths(home)[shell];marker='# >>> cachy-asahi setup '+component+' v1 >>>';path.write_text(path.read_text().replace(marker,marker+'\n# deliberate retained user edit',1))
        before=snapshot(home)
        for operation in ('activate','remove'):
            result=self.invoke(home,operation,edited,True,2);need(snapshot(home)==before and all(a['status']=='preserved-edited' for a in result['actions']),'edited block conflict was not preserved')
        result=self.invoke(home,'remove',apply=True,expected=2);state=json.loads((home/'setup-state/state.json').read_text());need(set(state['components'])==set(edited),'edited ownership was discarded')
        for path in self.paths(home).values():need(path.read_text().startswith(USER_CONFIG) and '# deliberate retained user edit' in path.read_text(),'user edit/prefix lost on partial removal')
        return dict(status='PASS',activate_remove_exit=2,retained_edited_components=list(edited),other_components_removed=4,no_reset=True)


def fixture_modules(C,source,homes):
    raw=(source/'packages/tools/cachy-asahi-fish-done/check-module.py').read_text();anchor="need((home/'bindings-before').read_bytes() == (home/'bindings-after').read_bytes(), 'custom keymap changed')";need(raw.count(anchor)==1,'coexistence binding adapter anchor differs');raw=raw.replace(anchor,"need(binding_subset(home/'bindings-before',home/'bindings-after'), 'preexisting keymap changed')")
    tree=ast.parse(raw);matches=[]
    class UserConfig(ast.NodeTransformer):
        def visit_Constant(self,node):
            if node.value=='touch "$HOME/unexpected-rc"\n':
                matches.append(node)
                if len(matches)==1:return ast.copy_location(ast.Constant(USER_CONFIG),node)
                return ast.copy_location(ast.Call(func=ast.Name(id='expected_fish_config',ctx=ast.Load()),args=[ast.Name(id='home',ctx=ast.Load())],keywords=[]),node)
            return node
    tree=UserConfig().visit(tree);need(len(matches)==2,'exact existing Fish config fixture anchors required')
    D=types.ModuleType('setup5_real_done_fixture');D.__dict__.update(binding_subset=C.binding_subset,expected_fish_config=lambda home:homes.expected.get(home,USER_CONFIG));exec(compile(ast.fix_missing_locations(tree),'<frozen-Done-fixture>','exec'),D.__dict__)
    original=D.prepare
    def prepare(root,name,missing=None):
        home=original(root,name,missing);homes.seed(home)
        if home in homes.pending:homes.activate(home,homes.pending[home])
        return home
    D.prepare=prepare
    Z=C.load('setup5_real_zsh_fixture',source/'packages/tools/cachy-asahi-zsh-history-substring-search/check-module.py');original_home=Z.home
    def zhome(root,name):
        home=original_home(root,name);homes.seed(home);return home
    Z.home=zhome
    return D,Z


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','accepted-inputs','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();source=safe(args.source.absolute());out=safe(args.output.absolute());need(not out.exists(),'fresh private output required');out.mkdir(mode=0o700)
    pins=json.loads((HERE/'source-manifest.json').read_text())
    for name,row in pins['files'].items():
        path=safe(source/name);need(path.stat().st_size==row['bytes'] and digest(path)==row['sha256'],'pinned source differs: '+name)
    for name,row in pins['driver_files'].items():
        path=safe(HERE/name);need(path.stat().st_size==row['bytes'] and digest(path)==row['sha256'],'adapter driver differs: '+name)
    reused=out/'coexistence-driver';reused.mkdir()
    for name,row in pins['files'].items():
        if name.startswith('scripts/ci/shell-modules-coexistence/'):
            raw=safe(source/name).read_bytes();need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'reused driver changed while freezing')
            (reused/Path(name).name).write_bytes(raw)
    original=(reused/'run.py').read_text();anchor='unset ZSH_AUTOSUGGEST_USE_ASYNC';replacement='(( ${+ZSH_AUTOSUGGEST_USE_ASYNC} )) || exit 25'
    need(original.count(anchor)==1,'one exact inherited synchronous-fixture override required')
    adapted=original.replace(anchor,replacement);async_path=reused/'setup5-async-coexistence.py';async_path.write_text(adapted)
    adapter=dict(before=anchor,after=replacement,original_sha256=digest(reused/'run.py'),adapted_sha256=digest(async_path),actual_mode='default asynchronous autosuggestions; variable presence asserted in actual interactive shell')
    C=load('accepted_real_coexistence',async_path);frozen,inputs=C.freeze_inputs(source,out)
    selected={n:r['sha256'] for n,r in pins['files'].items() if n.startswith('packages/')};need(inputs==selected,'real module closure changed while freezing')
    cli,accepted=accepted_cli(args.accepted_inputs.absolute(),out);stage=out/'package-stage';stage.mkdir();package_logs=[]
    for directory in sorted({str(Path(n).parent) for n in (*C.FISH.values(),*C.ZSH.values())}):
        path=frozen/directory;argv=['bash','-e','-c','source "$1"; srcdir="$2"; pkgdir="$3"; package','stage',str(path/'PKGBUILD'),str(path),str(stage)]
        result=subprocess.run(argv,env=dict(PATH='/usr/bin:/bin',HOME=str(out),LANG='C'),capture_output=True,timeout=10);need(result.returncode==0 and not result.stderr,'pure recipe stage failed: '+directory);package_logs.append(directory)
    staged={str(p.relative_to(stage)):dict(bytes=p.stat().st_size,sha256=digest(p),mode=stat.S_IMODE(p.stat().st_mode)) for p in sorted(stage.rglob('*')) if p.is_file()}
    versions={}
    for directory in package_logs:
        fields={line.strip().split(' = ',1)[0]:line.strip().split(' = ',1)[1] for line in (frozen/directory/'.SRCINFO').read_text().splitlines() if ' = ' in line}
        versions[fields['pkgname']]=fields['pkgver']+'-'+fields['pkgrel']
    templates=stage/'usr/share/cachy-asahi';homes=SetupHomes(cli,templates,out);C.combined=homes.combined;D,Z=fixture_modules(C,frozen,homes)
    report=dict(source_manifest_sha256=digest(HERE/'source-manifest.json'),adapter_files=pins['driver_files'],status='FAIL',scope='HOST_SETUP5_GENERATED_STARTUP_WITH_REAL_SIX_MODULE_PRODUCTS',machine=platform.machine(),page_size=os.sysconf('SC_PAGE_SIZE'),uid=os.getuid(),accepted_input=accepted,inputs=inputs,pure_package_stages=package_logs,staged_payload=staged,product_versions=versions,zsh_fixture_adapter=adapter,cases={},lifecycle={},native_runtime='NOT_RUN',M2='NOT_RUN',real_notifications='NOT_RUN',release='NOT_RUN')
    jobs=[('fish-request-forward',lambda:C.fish_case(D,frozen,out,('bang','autopair','done'))),('fish-request-reverse',lambda:C.fish_case(D,frozen,out,('done','autopair','bang'))),('zsh-request-forward',lambda:C.zsh_case(Z,frozen,out,('autosuggest','highlight','substring'))),('zsh-request-reordered',lambda:C.zsh_case(Z,frozen,out,('highlight','substring','autosuggest')))]
    jobs.extend((shell+'-noninteractive',lambda shell=shell:C.noninteractive(D,Z,frozen,out,shell)) for shell in ('fish','zsh'))
    def expired(*_):raise TimeoutError('finite30s setup-generated coexistence case deadline')
    previous=signal.signal(signal.SIGALRM,expired)
    try:
        for name,job in jobs:
            signal.setitimer(signal.ITIMER_REAL,30)
            try:report['cases'][name]=job()
            except Exception as error:report['cases'][name]=dict(status='FAIL',error_type=type(error).__name__,reason=str(error))
            finally:signal.setitimer(signal.ITIMER_REAL,0)
        for home in list(homes.records):
            need((home/'setup5-user-sourced').read_text()=='user-sourced','complete generated user startup file was not sourced')
            report['lifecycle'][home.name]=dict(activation=homes.records[home],removal=homes.remove(home))
        report['conflicts']=homes.conflicts()
        if all(row['status']=='PASS' for row in report['cases'].values()):report['status']='PASS_HOST_SETUP5_GENERATED_REAL_MODULES'
    except Exception as error:report.update(error_type=type(error).__name__,reason=str(error))
    finally:signal.signal(signal.SIGALRM,previous)
    report['versions']={shell:subprocess.check_output([shutil.which(shell),'--version'],env=dict(PATH='/usr/bin:/bin',HOME=str(out)),text=True,timeout=5).strip() for shell in ('fish','zsh')}
    report['interpreters']={shell:digest(Path(shutil.which(shell)).resolve()) for shell in ('fish','zsh')}
    (out/'receipt.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(status=report['status'],cases={n:r['status'] for n,r in report['cases'].items()},receipt=str(out/'receipt.json'))));return int(report['status']!='PASS_HOST_SETUP5_GENERATED_REAL_MODULES')


if __name__=='__main__':raise SystemExit(main())
