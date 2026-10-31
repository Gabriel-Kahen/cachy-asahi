# SPDX-License-Identifier: MIT
"""Narrow604 successor over the byte-held accepted600 installer adapter."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import contract as C

NAMES=('profile.py','run.py','prepare.py','guest.py','installer.py','numeric_vm.py')
HELPERS={
    'contract.py':(6642,'f636c614ae42fbc32ed8396441351872cc20db19bab4d6ac40b04dabd9cb9fd8'),
    'adapter.py':(5094,'df60573ea722d4ccd9312b0be132bdc302ded9fd3fc8e2473e0077920731a100'),
    'adapter-rules.json':(3895,'384a41d4db2159686736208fd2e0707a0c579816ac3190007c38a8c1dd63d7e1'),
    'call-rules.json':(98,'36784cbefc735e62ad51f75501983e2e2fc90753d1e058913a51c6a02ff079d1'),
    'legacy-pins.json':(12884,'67416a3d292d3938c0a2d747d6bea08cd750b585fdd67473e62fac55e14a66c1'),
    'observer600.py':(2784,'c3d804e7f2927c7889835ad187a39a3d7c618a4651700f57b0c5413c46612607')}
OLD='d263a3ca9089c204603f2e12b80dc4f209ee6e636f10da940a514040b636db79'
TARGET='76c37db5eb097662f4a9ca0465680de285466b0443916a50255ea5b8f6d6c946'


def accepted(source=None):
    base=C.HERE.parent/'expanded600-installer-vm' if source is None else Path(source)/'scripts/ci/expanded600-installer-vm'
    for name,(size,digest) in HELPERS.items():
        path=base/name;raw=path.read_bytes()
        C.need(not path.is_symlink() and len(raw)==size and hashlib.sha256(raw).hexdigest()==digest,
               'accepted600 adapter helper differs: '+name)
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
        sys.modules[name]=module;spec.loader.exec_module(module);return module
    missing=object();prior=sys.modules.get('contract',missing)
    try:
        old=load('_installer604_accepted_contract',base/'contract.py');sys.modules['contract']=old
        return load('_installer604_accepted_adapter',base/'adapter.py')
    finally:
        if prior is missing:sys.modules.pop('contract',None)
        else:sys.modules['contract']=prior


def rules(name):
    # scope, typed before/after, exact count, optional keyword role. No600 deadline is selected.
    lane=('expanded600-installer-vm','expanded604-installer-vm')
    ready=('READY_SIGNED_EXPANDED600','READY_SIGNED_EXPANDED604')
    passed=('PASS_EXPANDED600_INSTALLER','PASS_EXPANDED604_INSTALLER')
    return {
        'profile.py':[
            ('<module>','Source-only signed expanded600 profile; never install, extract, mount or fetch.',
             'Source-only signed expanded604 profile; never install, extract, mount or fetch.',1,None),
            ('<module>',OLD,TARGET,1,None),('manifest',*ready,1,None),
            ('manifest','held expanded600 lock differs','held expanded604 lock differs',1,None),
            ('manifest',600,604,3,None),('manifest','0.1.0-3','0.1.0-5',1,None),
            ('<module>','full-installer-expanded600-ldconfig-sonames-v1','full-installer-expanded604-ldconfig-sonames-v1',1,None),
            ('build',*lane,1,None),('build',600,604,1,'packages'),
            ('build','fresh signed expanded600 transaction plus declared user fixtures in generic4K VM',
             'fresh signed expanded604 transaction plus declared user fixtures in generic4K VM',1,None)],
        'run.py':[
            ('<module>','Owned, offline generic ARM VM route for the declared expanded600 installer.',
             'Owned, offline generic ARM VM route for the declared expanded604 installer.',1,None),
            ('<module>',OLD,TARGET,1,None),('input_files',*ready,1,None),('input_files',600,604,2,None),
            ('input_files','actual signed full600 export required','actual signed full604 export required',1,None),
            ('validate_completion',*passed,1,None),('validate_completion',600,604,1,None),
            ('vm','generic4K-full600-installer-software-only','generic4K-full604-installer-software-only',1,None),
            ('container_args','cachy-asahi.expanded600-installer=','cachy-asahi.expanded604-installer=',1,None),
            ('host',*lane,3,None),('host','cachy-asahi-expanded600-installer:','cachy-asahi-expanded604-installer:',1,None),
            ('host','cachy-expanded600-installer-','cachy-expanded604-installer-',1,None),
            ('host','cachy-asahi.expanded600-installer','cachy-asahi.expanded604-installer',1,None)],
        'prepare.py':[('verify_contract',*lane,1,None)],
        'guest.py':[('<module>',*passed,1,None)],
        'installer.py':[
            ('<module>','Generic-VM-only fresh expanded600 transaction through the held installer barrier.',
             'Generic-VM-only fresh expanded604 transaction through the held installer barrier.',1,None),
            ('<module>',*passed,1,None),('checked_inputs',*lane,1,None),
            ('checked_inputs',600,604,1,'packages'),('engine',600,604,1,'package_count'),
            ('engine',600,604,2,'max_packages'),('execute',600,604,2,'max_packages')],
        'numeric_vm.py':[('verify_export',600,604,2,'max_packages')]}[name]


def nodes(node,path=(),scope='<module>',parent=None):
    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):scope=node.name
    yield node,path,scope,parent
    for field,value in ast.iter_fields(node):
        if isinstance(value,ast.AST):yield from nodes(value,path+(field,),scope,node)
        elif isinstance(value,list):
            for i,child in enumerate(value):
                if isinstance(child,ast.AST):yield from nodes(child,path+(field,i),scope,node)


def transform(raw,name,*,source=None):
    C.need(name in NAMES,'unknown604 runner')
    base,prior=accepted(source).transform(raw,name)  # Exact83 held legacy bytes and original closed600 transformation.
    tree=ast.parse(base);expected=copy.deepcopy(tree);declared=rules(name);counts=[0]*len(declared);edits=[]
    lines=base.splitlines(keepends=True);offsets=[0]
    for line in lines:offsets.append(offsets[-1]+len(line))
    for node,path,scope,parent in nodes(tree):
        if not isinstance(node,ast.Constant):continue
        hits=[i for i,(owner,before,after,count,keyword) in enumerate(declared)
              if owner==scope and type(node.value) is type(before) and node.value==before and
              (keyword is None or isinstance(parent,ast.keyword) and parent.arg==keyword)]
        C.need(len(hits)<=1,'ambiguous604 semantic adapter role')
        if not hits:continue
        i=hits[0];counts[i]+=1;replacement=declared[i][2]
        target=expected
        for key in path:target=target[key] if isinstance(key,int) else getattr(target,key)
        target.value=replacement
        start=offsets[node.lineno-1]+node.col_offset;end=offsets[node.end_lineno-1]+node.end_col_offset
        edits.append((start,end,json.dumps(replacement).encode()))
    C.need(counts==[row[3] for row in declared],'exact604 semantic adapter role counts differ: '+name)
    output=base
    for start,end,replacement in sorted(edits,reverse=True):output=output[:start]+replacement+output[end:]
    C.need(ast.dump(expected,include_attributes=False)==ast.dump(ast.parse(output),include_attributes=False),
           'undeclared604 AST mutation refused')
    compile(output,'<expanded604-held-'+name+'>','exec')
    return output,dict(file=name,accepted600=prior,semantic_edits=len(edits),rules=declared,
        accepted600_sha256=hashlib.sha256(base).hexdigest(),after_sha256=hashlib.sha256(output).hexdigest())


def materialize(legacy,out,*,source=None):
    C.legacy(legacy);C.need(not out.exists(),'fresh604 adapter output required');out.mkdir(mode=0o700);result={}
    for name in NAMES:
        raw=(legacy/'scripts/ci/full-composition-installer-vm'/name).read_bytes()
        output,receipt=transform(raw,name,source=source);(out/name).write_bytes(output)
        result[name]=dict(receipt,before_sha256=hashlib.sha256(raw).hexdigest(),bytes=len(output))
    (out/'adapter.json').write_bytes(C.encoded(dict(status='PASS_CLOSED604_SEMANTIC_SOURCE_ADAPTER',legacy_source=C.LEGACY,
        files=result,package_count=604,expected604_sha256=TARGET,independent_readback_seconds=600,native='NOT_RUN',hardware='NOT_RUN')))
    return result
