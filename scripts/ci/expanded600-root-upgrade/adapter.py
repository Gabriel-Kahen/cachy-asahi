# SPDX-License-Identifier: MIT
"""Make a private, receipted600 selection from an exact accepted587 code closure."""
import ast
import hashlib
from pathlib import Path
import shutil
import contract as C

PREFIX='scripts/ci/expanded600-root-upgrade/'
OLD_BEFORE='2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
OLD_AFTER='dbfe042f77bf61ce8e15a63c53391bcc4f04b94f18e99eeffdfdf85e68aa26ac'
OLD_PACKAGE='c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a'
PACKAGE='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc'
RECIPE='d31e4bdfb5c0c38e0128bbcb5127926414628f2d8d047f9eb0a2da0142848519'
BUILD='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
NUMERIC={'scripts/update/full_root.py':{587:600},'scripts/update/scale_update.py':{587:600},
 'scripts/update/generic_policy.py':{587:600},
 'scripts/ci/full-development-composition/setup4_inputs.py':{587:600},
 'scripts/ci/full-root-upgrade/root_upgrade.py':{587:600},
 'scripts/ci/full-root-upgrade/construct_repository.py':{587:600,341:574},
 'scripts/ci/full-root-upgrade-caller/container.py':{587:600,14:27,10:17},
 'scripts/ci/full-root-upgrade-caller/upgrade_hook.py':{587:600},
 'scripts/ci/full-root-failed-update/run.py':{587:600},'scripts/ci/full-root-failed-update/caller.py':{587:600},
 'scripts/ci/full-root-postcommit-failure/run.py':{587:600,588:601},
 'scripts/ci/full-root-postcommit-failure/caller.py':{587:600}}
STRINGS=set(NUMERIC)|{'scripts/update/aux_runtime.py','scripts/update/linked_runtime.py'}
REPLACEMENTS={OLD_BEFORE:C.BEFORE,OLD_AFTER:C.AFTER,OLD_PACKAGE:PACKAGE,
 '98fecf28a3cde63a9dd7531501c2187825349310':'4cf9884dacb2816532b07c8107982d7157656046',
 'ec816728a154f77723d34e56bcbf04bb39ef436be1d883fb90c1af8d43dae31e':RECIPE,
 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25':BUILD,
 'build-1/artifacts/cachy-asahi-setup-0.1.0-4-any.pkg.tar.xz':'packages/cachy-asahi-setup-a/cachy-asahi-setup-0.1.0-5-any.pkg.tar.xz',
 'build-1/provenance.json':'runtime/cachy-asahi-setup-a/provenance.json',
 'build-2/provenance.json':'runtime/cachy-asahi-setup-b/provenance.json',
 'build-1/inputs/LICENSE':'source/cachy-asahi-setup/LICENSE',
 'build-1/inputs/source-provenance.json':'source/cachy-asahi-setup/source-provenance.json'}
SCRIPTS={'cachy-asahi-'+n for n in ('welcome','doctor','mirrors','zsh-syntax-highlighting','zsh-history-substring-search','fish-autopair','fish-done')}
AUDIO={'asahi-audio','alsa-ucm-conf-asahi','speakersafetyd','bankstown','triforce-lv2','lsp-plugins-lv2'}


def text_value(value):
    for old,new in REPLACEMENTS.items():value=value.replace(old,new)
    return value.replace('0.1.0-4','0.1.0-5').replace('587','600').replace('build341','build574').replace('actual600-persistent-root-setup4-test','actual600-persistent-root-setup5-test')


def literals(raw,name):
    """Replace only typed AST constants; leave calls, guards, limits and control flow intact."""
    text=raw.decode();tree=ast.parse(text);lines=text.splitlines(keepends=True);offsets=[0]
    for line in lines:offsets.append(offsets[-1]+len(line))
    edits=[]
    def replace(node,value):
        edits.append((offsets[node.lineno-1]+node.col_offset,offsets[node.end_lineno-1]+node.end_col_offset,value))
    for node in ast.walk(tree):
        if not isinstance(node,ast.Constant):continue
        value=node.value
        if type(value) is int and value in NUMERIC.get(name,{}):replace(node,str(NUMERIC[name][value]))
        elif type(value) is str and name in STRINGS:
            new=text_value(value)
            if new!=value:replace(node,repr(new))
    if name=='scripts/ci/full-root-upgrade-caller/container.py':
        for node in tree.body:
            if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
                key=node.targets[0].id
                if key in ('PROJECTS','EXTRAS'):
                    additions=SCRIPTS if key=='PROJECTS' else AUDIO
                    replace(node.value,'('+ast.get_source_segment(text,node.value)+') | '+repr(sorted(additions)).replace('[','{',1).removesuffix(']')+'}')
    if name=='scripts/ci/full-root-upgrade/construct_repository.py':
        node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='inspect_package')
        replace(node,"def inspect_package(args, api=None):\n    api = api or apis(ordinary(args.source_root, directory=True))\n    helper = load_module(Path(args.source_root), 'accepted_setup5', '"+PREFIX+"setup5.py')\n    return helper.inspect_package(args, api)\n")
        # Inner literals of this replaced function are intentionally superseded.
        start,end=offsets[node.lineno-1]+node.col_offset,offsets[node.end_lineno-1]+node.end_col_offset
        edits=[e for e in edits if e[0]==start and e[1]==end or not(start<=e[0]<end)]
    for start,end,value in sorted(edits,reverse=True):text=text[:start]+value+text[end:]
    if name=='scripts/ci/full-root-postcommit-failure/run.py':
        text=text.replace('after587_database_verified=', 'after600_database_verified=')
    ast.parse(text);return text.encode()


def prepare(source,target,case,*,git=True):
    C.need(case in C.SOURCES,'closed single-case selection required');source=C.safe(source);target=C.safe(target)
    held=C.read(C.HERE/'held-pins.json')[case]
    C.need(held['source']==C.SOURCES[case] and (not git or C.revision(source)==held['source']),'exact accepted587 code source required')
    C.need(not target.exists(),'fresh private code tree required');C.locks()
    # Verify the whole original closure before making any output.
    for name,row in held['pins'].items():C.checked(source,dict(path=name,**row))
    target.mkdir(mode=0o700);changes={}
    for name,row in held['pins'].items():
        raw=(source/name).read_bytes();derived=literals(raw,name) if name.endswith('.py') else raw
        if name.endswith('/expected-updater-v2.lock'):derived=(C.HERE/'before600.lock').read_bytes()
        if name.endswith('/expected-setup4-v2.lock'):derived=(C.HERE/'after600.lock').read_bytes()
        path=target/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(derived)
        if derived!=raw:changes[name]=dict(before_sha256=row['sha256'],after_sha256=C.sha(path),kind='declared-private-selection')
    helper=target/PREFIX/'setup5.py';helper.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(C.HERE/'setup5.py',helper)
    shutil.copyfile(C.HERE/'accepted_pair.py',helper.with_name('accepted_pair.py'))
    caller=target/'scripts/ci/full-root-upgrade-caller'
    hook=caller/'upgrade_hook.py' if case=='normal' else target/('scripts/ci/'+('full-root-failed-update' if case=='precommit-exit86' else 'full-root-postcommit-failure')+'/caller.py')
    if case!='normal':
        shutil.copyfile(hook,caller/'upgrade_hook.py')
        name='scripts/ci/full-root-upgrade-caller/upgrade_hook.py'
        changes[name]=dict(before_sha256=held['pins'][name]['sha256'],after_sha256=C.sha(caller/'upgrade_hook.py'),
            kind='declared-fault-hook-mount-alias',source=hook.relative_to(target).as_posix())
    config=C.read(source/held['config']);config['purpose']=text_value(config['purpose'])
    config['scale']['before_lock_sha256']=C.BEFORE;config['scale']['after_lock_sha256']=C.AFTER
    config['release']['release_id']='expanded600-setup5-'+case+'-20261016'
    config['release']['namespace']='cachy-asahi-expanded600-'+case
    config['code_pins']={name:C.sha(target/name) for name in config['code_pins']}
    for name in ('run.py','container.py','persistent_scope.py','upgrade_hook.py'):
        relative='scripts/ci/full-root-upgrade-caller/'+name
        config['code_pins'][relative]=C.sha(target/relative)
    # Pin the two additional source-only accepted-pair inspectors through the existing code guard.
    for name in ('setup5.py','accepted_pair.py'):config['code_pins'][PREFIX+name]=C.sha(target/PREFIX/name)
    config['external_pins']['/persistent_scope.py']=C.sha(caller/'persistent_scope.py')
    config_path=target/'upgrade-config.json';config_path.write_bytes(C.encoded(config))
    receipt=dict(schema_version=1,status='PRIVATE_SOURCE_SELECTION_ONLY',case=case,source=held['source'],
        original_pin_count=len(held['pins']),derived_pin_count=len(config['code_pins']),changes=changes,
        config_sha256=C.sha(config_path),before_sha256=C.BEFORE,after_sha256=C.AFTER,
        package_sha256=PACKAGE,hardware='NOT_RUN',actors='NOT_RUN',
        unchanged_policy='original release/client/transaction/aux/ownership/checkpoint/reaping/disposal methods and budgets')
    (target/'adapter.json').write_bytes(C.encoded(receipt));return config_path,caller
