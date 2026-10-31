# SPDX-License-Identifier: MIT
"""Closed604 selection over the unchanged corrected600 private-source adapter."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import contract as C

OLD_BEFORE='d263a3ca9089c204603f2e12b80dc4f209ee6e636f10da940a514040b636db79'
OLD_AFTER='04fabc5702c8389b7b2a53f6ed6168cc45931f6628c158e7e74b073349327c35'
PREFIX='scripts/ci/expanded600-root-upgrade/'  # Held accepted Setup5 inspector API, byte-identical.
MANAGEMENT={'cachy-asahi-'+n for n in ('apps','repository-runtime','cache','orphans')}
HELPERS={
    'adapter.py':(8670,'81f985fbc80e0f2888327245414dd59689c87a5fafeb390c1e840cc3c647026c'),
    'contract.py':(5352,'c8a0fc237a10d1f6830407ab2984636b763283653f63b9d9906abf1d9cc16635'),
    'held-pins.json':(27397,'1d2bb9e3a831f0b7c404bf4971699fc530fa139ed881b513cb62e3b339ed7493'),
    'setup5.py':(4708,'b995936917565114d383e3d0d4076cb24cba368e68f7c7e13b401839064c9167'),
    'accepted_pair.py':(2938,'76938c4aa24dc6d04ed4c0cac4aa1d5ec880af0cda54079725607b908a56ae2a'),
    'before600.lock':(11874,OLD_BEFORE),'after600.lock':(11874,OLD_AFTER)}


def accepted(implementation=None):
    base=C.HERE.parent/'expanded600-root-upgrade' if implementation is None else Path(implementation)/'scripts/ci/expanded600-root-upgrade'
    for name,(size,digest) in HELPERS.items():
        path=C.safe((base/name).absolute());raw=path.read_bytes()
        C.need(len(raw)==size and hashlib.sha256(raw).hexdigest()==digest,'held600 adapter helper differs: '+name)
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
        sys.modules[name]=module;spec.loader.exec_module(module);return module
    missing=object();prior=sys.modules.get('contract',missing)
    try:
        old=load('_root604_held600_contract',base/'contract.py');sys.modules['contract']=old
        value=load('_root604_held600_adapter',base/'adapter.py')
    finally:
        if prior is missing:sys.modules.pop('contract',None)
        else:sys.modules['contract']=prior
    C.need(old.SOURCES==C.SOURCES,'same three original587 private source closures required')
    return value


def rules(name):
    """scope,before,after,count,role. Time budgets are never inventory roles."""
    hashes=[('<module>',OLD_BEFORE,C.BEFORE,1,None),('<module>',OLD_AFTER,C.AFTER,1,None)]
    count=lambda scope,n=1:(scope,600,604,n,'compare')
    caller=[
        count('quiesce'),count('run'),
        ('configuration','explicit initial600 upgrade selection required','explicit initial604 upgrade selection required',1,None),
        ('quiesce','Retain the existing keyring guards, with initial600 selection kept explicit.',
         'Retain the existing keyring guards, with initial604 selection kept explicit.',1,None),
        ('quiesce','initial600 keyring checkpoint required','initial604 keyring checkpoint required',1,None),
        ('quiesce','initial600_keyring_helper','initial604_keyring_helper',1,None),
        ('quiesce','initial600_keyring_reads','initial604_keyring_reads',1,None),
        ('run','exclusive initial600 full-root route required','exclusive initial604 full-root route required',1,None),
        ('run','exact initial signed600/updater-v2 inventory required','exact initial signed604/updater-v2 inventory required',1,None)]
    if name=='scripts/ci/full-root-upgrade-caller/upgrade_hook.py':
        return hashes+caller+[('configuration','actual600-persistent-root-setup5-test','actual604-persistent-root-setup5-test',1,None)]
    if name in ('scripts/ci/full-root-failed-update/caller.py','scripts/ci/full-root-postcommit-failure/caller.py'):
        kind='postcommit' if 'postcommit' in name else 'precommit'
        result=hashes+caller+[('configuration','actual600-'+kind+'-failure-disposal-test','actual604-'+kind+'-failure-disposal-test',1,None),
            ('run','controlled-full600-'+kind+'-failure-disposal','controlled-full604-'+kind+'-failure-disposal',1,None)]
        if kind=='postcommit':result.append(('run','after600_database_verified','after604_database_verified',1,None))
        return result
    table={
        'scripts/update/generic_policy.py':[
            ('protected_names',600,604,1,'keyword:limit'),count('protected_names'),count('authorize')],
        'scripts/update/full_root.py':[('Limits',600,604,1,'annotated:max_packages')],
        'scripts/update/scale_update.py':[
            ('<module>','Opt-in bounded observations/decoder for one update in a copied 600-package root.',
             'Opt-in bounded observations/decoder for one update in a copied 604-package root.',1,None),
            ('__init__',600,604,1,'keyword:max_packages'),count('selection'),count('observed_after'),
            ('selection','actual baseline differs from exact 600-package lock','actual baseline differs from exact 604-package lock',1,None)],
        'scripts/ci/full-development-composition/setup4_inputs.py':[
            ('<module>',OLD_AFTER,C.AFTER,1,None),count('expected_lock',2)],
        'scripts/ci/full-root-upgrade/root_upgrade.py':hashes+[
            count('selection',2),('database',600,604,1,'default:max_packages'),
            ('selection','complete600 lock required','complete604 lock required',1,None),
            ('run','actual root is not initial signed600/updater-v2 checkpoint','actual root is not initial signed604/updater-v2 checkpoint',1,None)],
        'scripts/ci/full-root-upgrade/construct_repository.py':hashes+[
            count('validate_base',2),('locks','exact600 lock pins differ','exact604 lock pins differ',1,None),
            ('validate_base','actual root-derived600 package records required','actual root-derived604 package records required',1,None),
            ('prepare','exact-desired600','exact-desired604',1,None)],
        'scripts/ci/full-root-upgrade-caller/container.py':[
            ('inputs',27,31,1,'compare'),('inputs',17,21,1,'compare'),count('inputs'),
            ('inputs','exact ten projects and four additions required','exact21 projects and10 auxiliary additions required',1,None),
            ('install','installed inventory differs from exact 600-package composition','installed inventory differs from exact 604-package composition',1,None),
            ('main','outer root differs from initial signed600 checkpoint','outer root differs from initial signed604 checkpoint',1,None)],
        'scripts/ci/full-root-failed-update/run.py':[
            ('<module>',OLD_BEFORE,C.BEFORE,1,None),
            ('<module>','actual600-precommit-failure-disposal-test','actual604-precommit-failure-disposal-test',1,None),
            count('arm'),('arm','exact live initial600 inventory required','exact live initial604 inventory required',1,None),
            ('execute_case','controlled-full600-precommit-failure-disposal','controlled-full604-precommit-failure-disposal',1,None)],
        'scripts/ci/full-root-postcommit-failure/run.py':hashes+[
            ('<module>','actual600-postcommit-failure-disposal-test','actual604-postcommit-failure-disposal-test',1,None),
            ('precommit','initial600 differs','initial604 differs',1,None),count('arm'),
            ('arm','live after600 inventory differs','live after604 inventory differs',1,None),
            ('database_after',601,605,1,'compare'),count('database_after'),
            ('database_after','exact600 database shape required','exact604 database shape required',1,None),
            count('prepare_verifier'),count('verify_after'),
            ('verify_after','after600 database differs','after604 database differs',1,None),
            ('execute_case','controlled-full600-postcommit-failure-disposal','controlled-full604-postcommit-failure-disposal',1,None),
            ('execute_case','after600_database_verified','after604_database_verified',1,None)]}
    return table.get(name,[])


def nodes(node,path=(),scope='<module>',parent=None):
    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):scope=node.name
    yield node,path,scope,parent
    for field,value in ast.iter_fields(node):
        if isinstance(value,ast.AST):yield from nodes(value,path+(field,),scope,node)
        elif isinstance(value,list):
            for i,child in enumerate(value):
                if isinstance(child,ast.AST):yield from nodes(child,path+(field,i),scope,node)


def role_matches(role,node,parent,tree,path):
    if role is None:return True
    if role=='compare':return isinstance(parent,ast.Compare)
    if role.startswith('keyword:'):return isinstance(parent,ast.keyword) and parent.arg==role.split(':')[1]
    if role.startswith('annotated:'):return isinstance(parent,ast.AnnAssign) and isinstance(parent.target,ast.Name) and parent.target.id==role.split(':')[1]
    if role.startswith('default:'):
        if not isinstance(parent,ast.arguments):return False
        if path[-2]=='kw_defaults':return parent.kwonlyargs[path[-1]].arg==role.split(':')[1]
        names=[a.arg for a in parent.args[-len(parent.defaults):]]
        return path[-2]=='defaults' and names[path[-1]]==role.split(':')[1]
    C.need(False,'unknown semantic role')


def literals(raw,name):
    tree=ast.parse(raw);expected=copy.deepcopy(tree);declared=rules(name);counts=[0]*len(declared);edits=[]
    lines=raw.splitlines(keepends=True);offsets=[0]
    for line in lines:offsets.append(offsets[-1]+len(line))
    def edit(node,value,code):
        start=offsets[node.lineno-1]+node.col_offset;end=offsets[node.end_lineno-1]+node.end_col_offset
        edits.append((start,end,code));return value
    for node,path,scope,parent in nodes(tree):
        wanted=expected
        for key in path:wanted=wanted[key] if isinstance(key,int) else getattr(wanted,key)
        if isinstance(node,ast.Constant):
            hits=[i for i,(owner,before,after,count,role) in enumerate(declared) if scope==owner and type(node.value)is type(before)
                and node.value==before and role_matches(role,node,parent,tree,path)]
            C.need(len(hits)<=1,'ambiguous604 semantic role')
            if hits:
                i=hits[0];counts[i]+=1;replacement=declared[i][2]
                wanted.value=edit(node,replacement,json.dumps(replacement).encode())
        if name=='scripts/ci/full-root-postcommit-failure/run.py' and isinstance(node,ast.keyword) and node.arg=='after600_database_verified':
            wanted.arg='after604_database_verified'
            start=offsets[node.lineno-1]+node.col_offset;edits.append((start,start+len(node.arg),b'after604_database_verified'))
    C.need(counts==[r[3] for r in declared],'604 semantic role counts differ: '+name)
    keyword_count=sum(isinstance(n,ast.keyword) and n.arg=='after600_database_verified' for n in ast.walk(tree))
    if name=='scripts/ci/full-root-postcommit-failure/run.py':C.need(keyword_count==2,'two exact604 postcommit proof operands required')
    if name=='scripts/ci/full-root-upgrade-caller/container.py':
        assignments=[(n,p) for n,p,s,parent in nodes(tree) if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='PROJECTS']
        C.need(len(assignments)==1,'one bootstrap project selector required');node,path=assignments[0]
        replacement=ast.BinOp(left=copy.deepcopy(node.value),op=ast.BitOr(),right=ast.Set(elts=[ast.Constant(n) for n in sorted(MANAGEMENT)]))
        wanted=expected
        for key in path:wanted=wanted[key] if isinstance(key,int) else getattr(wanted,key)
        wanted.value=replacement
        explicit='{'+', '.join(repr(n) for n in sorted(MANAGEMENT))+'}'
        edit(node.value,None,('('+ast.get_source_segment(raw.decode(),node.value)+') | '+explicit).encode())
    output=raw
    for start,end,replacement in sorted(edits,reverse=True):output=output[:start]+replacement+output[end:]
    C.need(ast.dump(expected,include_attributes=False)==ast.dump(ast.parse(output),include_attributes=False),'undeclared604 AST mutation refused: '+name)
    compile(output,'<root604-'+name+'>','exec')
    return output,dict(edits=len(edits),semantic_rules=declared,before_sha256=hashlib.sha256(raw).hexdigest(),after_sha256=hashlib.sha256(output).hexdigest())


def prepare(source,target,case,*,git=True,implementation=None):
    C.need(case in C.SOURCES,'closed single-case604 selection required');C.locks()
    old=accepted(implementation);config_path,caller=old.prepare(source,target,case,git=git)
    prior=C.read(target/'adapter.json');config=C.read(config_path);held=old.C.read(old.C.HERE/'held-pins.json')[case];changes={}
    # Every original source remains held; only the already-private600 selection is extended.
    for name in held['pins']:
        path=target/name;raw=path.read_bytes()
        if name.endswith('.py'):
            effective=prior['changes'].get(name,{}).get('source',name)
            output,receipt=literals(raw,effective)
            if output!=raw:path.write_bytes(output);changes[name]=receipt
        elif name.endswith('/expected-updater-v2.lock'):path.write_bytes((C.HERE/'before604.lock').read_bytes())
        elif name.endswith('/expected-setup4-v2.lock'):path.write_bytes((C.HERE/'after604.lock').read_bytes())
    purposes={'normal':'actual604-persistent-root-setup5-test','precommit-exit86':'actual604-precommit-failure-disposal-test',
              'postcommit-exit87':'actual604-postcommit-failure-disposal-test'}
    config['purpose']=purposes[case];config['scale']['before_lock_sha256']=C.BEFORE;config['scale']['after_lock_sha256']=C.AFTER
    config['release']['release_id']='expanded604-setup5-'+case+'-20261016';config['release']['namespace']='cachy-asahi-expanded604-'+case
    diagnostic=None
    if case=='normal':
        location=Path(__file__).with_name('driver_progress.py')
        progress=C.load('_root604_normal_progress',location)
        diagnostic=progress.prepare(target)
        config['code_pins'][progress.SELF]=C.sha(target/progress.SELF)
    config['code_pins']={name:C.sha(target/name) for name in config['code_pins']}
    config['external_pins']['/persistent_scope.py']=C.sha(caller/'persistent_scope.py')
    config_path.write_bytes(C.encoded(config))
    receipt=dict(schema_version=1,status='PRIVATE604_SOURCE_SELECTION_ONLY',case=case,source=held['source'],accepted600=prior,
        original_pin_count=len(held['pins']),derived_pin_count=len(config['code_pins']),changes=changes,config_sha256=C.sha(config_path),
        before_sha256=C.BEFORE,after_sha256=C.AFTER,package_count=604,protected_package_count=603,project_count=21,bootstrap_additions=31,
        setup5_inspectors='UNCHANGED_PRIVATE600_API_PATH',actors='NOT_RUN',hardware='NOT_RUN')
    if diagnostic is not None:receipt['normal_driver_diagnostic']=diagnostic
    (target/'adapter.json').write_bytes(C.encoded(receipt));return config_path,caller
