#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create only a private, byte-pinned full26 engine; canonical sources stay intact."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
PASS='PASS_GENERIC_ARM_FULL26'
PURPOSE='installer-full26-generic-vm'
VIRTUAL=('controller.py','common.py','guest.py','prepare.py','run.py','gbm_probe.c',
         'image_decode_probe.c','image_decode_report.py','audit_tooling.py','tooling.lock.json','tooling-audit.json')


def need(ok,why):
    if not ok:raise ValueError(why)


def digest(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def read(path,cap=8*1024**2):
    need(not any(p.is_symlink() for p in (path,*path.parents)), 'ordinary source path')
    st=path.stat();need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<=cap,'bounded source file')
    raw=path.read_bytes();need(len(raw)==st.st_size,'source length changed');return raw


def selection():
    value=json.loads(read(HERE/'selection.json'))
    need(value['methods']==26 and value['transaction_calls']==22 and
         [len(v) for v in value['classes'].values()]==[17,7,1,1], 'original full26 selection')
    return value['classes']


def replace_function(raw,name,replacement):
    tree=ast.parse(raw);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name]
    need(len(nodes)==1,'one anchored function required: '+name);node=nodes[0]
    lines=raw.splitlines(keepends=True)
    return b''.join(lines[:node.lineno-1])+replacement+b'\n'+b''.join(lines[node.end_lineno:])


def constants(raw,changes):
    tree=ast.parse(raw);lines=raw.splitlines(keepends=True);offsets=[0]
    for line in lines:offsets.append(offsets[-1]+len(line))
    edits=[];counts={k:0 for k in changes}
    for node in ast.walk(tree):
        if isinstance(node,ast.Constant) and type(node.value) is str and node.value in changes:
            counts[node.value]+=1;edits.append((offsets[node.lineno-1]+node.col_offset,
                offsets[node.end_lineno-1]+node.end_col_offset,repr(changes[node.value]).encode()))
    for start,end,data in sorted(edits,reverse=True):raw=raw[:start]+data+raw[end:]
    return raw,counts


def assignment(raw,name,value):
    tree=ast.parse(raw);nodes=[n for n in tree.body if isinstance(n,ast.Assign) and any(getattr(t,'id',None)==name for t in n.targets)]
    need(len(nodes)==1,'one held assignment: '+name);node=nodes[0];lines=raw.splitlines(keepends=True)
    return b''.join(lines[:node.lineno-1])+(name+' = '+repr(value)+'\n').encode()+b''.join(lines[node.end_lineno:])


def prepare(source,output):
    source=source.absolute();output=output.absolute()
    need(not output.exists() and not output.is_symlink() and output.parent.is_dir(),'fresh private engine required')
    pins=json.loads(read(HERE/'held-files.json'))['files'];blobs={}
    for name,row in pins.items():
        blobs[name]=read(source/name);need(digest(blobs[name])==row,'held source changed: '+name)
    selected=selection()
    tree=ast.parse(blobs['scripts/install/native_arm_trial.py'])
    original=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(getattr(t,'id',None)=='SELECTED' for t in n.targets))
    need(selected=={k:list(v) for k,v in original.items()} and list(selected)==list(original),'native original26 selection drift')
    tests=ast.parse(blobs['scripts/install/test_local_transaction.py'])
    for cls,names in selected.items():
        node=next(n for n in tests.body if isinstance(n,ast.ClassDef) and n.name==cls)
        need(set(names)<={n.name for n in node.body if isinstance(n,ast.FunctionDef)},'original method absent')
    transformed={};receipts={}
    for name in (*('scripts/virtual/'+n for n in VIRTUAL),'scripts/install/local_transaction.py',
                 'scripts/install/test_local_transaction.py','scripts/port/kernel-native-job/runtime.py'):
        raw=blobs[name];new=raw
        if name.endswith('guest.py'):
            replacement=read(HERE/'matrix.py')
            new=replace_function(new,'transaction_test',replacement)
        if name.endswith('virtual/common.py'):
            new=replace_function(new,'transaction_event',read(HERE/'protocol.py'))
        if name.endswith(('guest.py','virtual/common.py')):
            new=('FULL26_SELECTED = '+repr(selected)+'\n').encode()+new
        if name.endswith('.py') and name not in ('scripts/install/test_local_transaction.py','scripts/port/kernel-native-job/runtime.py'):
            new,counts=constants(new,{'installer-transaction-only':PURPOSE,'PASS_TRANSACTION_ONLY':PASS})
        else:counts={}
        if name.endswith('guest.py'):
            # Early bootstrap failures must use the same closed full26 protocol.
            old=b'first_failure=failure,class_cleanups_returned=True,cancelled='
            need(new.count(old)==1,'early failure event anchor')
            new=new.replace(old,b"duties=[],scope='GENERIC_ARM_FULL26_ORIGINAL_METHODS_SOFTWARE_ONLY',barrier_report=None,"+old)
        transformed[name]=new;receipts[name]=dict(before=digest(raw),literal_edits=counts)
    worker='scripts/install/local_transaction.py';test='scripts/install/test_local_transaction.py';runtime='scripts/port/kernel-native-job/runtime.py'
    sources={n:digest(transformed[n]) for n in (worker,test,runtime)}
    common='scripts/virtual/common.py'
    transformed[common]=assignment(transformed[common],'TRANSACTION_FILES',sources)
    tree=ast.parse(transformed[common]);frames=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(getattr(t,'id',None)=='TRANSACTION_FRAME_LINES' for t in n.targets))
    frames.update(SELECTED_WORKER=len(transformed[worker].splitlines()),SELECTED_TEST=len(transformed[test].splitlines()),GUEST=len(transformed['scripts/virtual/guest.py'].splitlines()))
    transformed[common]=assignment(transformed[common],'TRANSACTION_FRAME_LINES',frames)
    core={n:digest(transformed['scripts/virtual/'+n])['sha256'] for n in ('common.py','guest.py','prepare.py','run.py','gbm_probe.c','image_decode_probe.c','image_decode_report.py')}
    controller='scripts/virtual/controller.py';transformed[controller]=assignment(transformed[controller],'CORE',core)
    need(transformed[test]==blobs[test] and transformed[runtime]==blobs[runtime],'original tests/runtime must stay byte-identical')
    # Runtime/unit/VM/per-worker bounds and the136-file tool/profile bytes are
    # untouched. All generated source files compile only as Python syntax here.
    for name,raw in transformed.items():
        if name.endswith('.py'):compile(raw,name,'exec')
        receipts[name]['after']=digest(raw)
    output.mkdir(mode=0o700)
    for name,raw in transformed.items():
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(0o644)
    receipt=dict(status='SOURCE_ONLY_PRIVATE_FULL26_ENGINE',purpose=PURPOSE,files=receipts,selected=selected,
        original_tests_sha256=pins[test]['sha256'],native_P0='UNCHANGED_FAILED',hardware='NOT_RUN',
        bounds=dict(child_seconds=900,unit_seconds=950,VM_seconds=1200,worker_seconds=90,supervision_seconds=1))
    (output/'adapter.json').write_bytes(encoded(receipt));return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path);args=parser.parse_args();print(json.dumps(prepare(args.source,args.output),sort_keys=True))
