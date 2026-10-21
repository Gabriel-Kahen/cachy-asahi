# SPDX-License-Identifier: MIT
"""Closed adapter: selection literals and three explicit600 package-inventory bounds."""
import ast
import json
from pathlib import Path
import contract as C

NAMES=('profile.py','run.py','prepare.py','guest.py','installer.py','numeric_vm.py')


def transform(raw,name):
    pin=C.read(C.HERE/'legacy-pins.json')['scripts/ci/full-composition-installer-vm/'+name]
    C.need(len(raw)==pin['bytes'] and __import__('hashlib').sha256(raw).hexdigest()==pin['sha256'],
           'held adapter source bytes differ: '+name)
    rules=C.read(C.HERE/'adapter-rules.json')[name];tree=ast.parse(raw)
    lines=raw.splitlines(keepends=True);offsets=[0]
    for line in lines:offsets.append(offsets[-1]+len(line))
    edits=[];counts=[0]*len(rules)
    calls=C.read(C.HERE/'call-rules.json').get(name,{});call_counts={key:0 for key in calls}
    for node in ast.walk(tree):
        if not isinstance(node,ast.Constant):continue
        matches=[i for i,row in enumerate(rules) if type(node.value) is type(row['before']) and node.value==row['before']]
        C.need(len(matches)<=1,'ambiguous literal adapter rule')
        if matches:
            index=matches[0];row=rules[index];counts[index]+=1
            start=offsets[node.lineno-1]+node.col_offset;end=offsets[node.end_lineno-1]+node.end_col_offset
            edits.append((start,end,json.dumps(row['after']).encode()))
    for node in ast.walk(tree):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name):
            label=node.func.value.id+'.'+node.func.attr
            if label in calls:
                C.need(not node.args and {k.arg for k in node.keywords}==
                       {'deadline','max_nodes','max_bytes','max_file_bytes','max_package_files'},'held Limits call shape changed')
                end=offsets[node.end_lineno-1]+node.end_col_offset
                C.need(raw[end-1:end]==b')','held Limits close delimiter changed')
                edits.append((end-1,end-1,b',max_packages=600'));call_counts[label]+=1
    C.need(call_counts==calls,'held inventory-bound call counts changed: '+name)
    C.need(counts==[r['count'] for r in rules],'held literal anchor counts changed: '+name)
    output=raw
    for start,end,replacement in sorted(edits,reverse=True):output=output[:start]+replacement+output[end:]
    compile(output,'<expanded600-held-'+name+'>','exec')
    # Verify the entire AST differs only by the declared typed constants.
    class Expected(ast.NodeTransformer):
        def visit_Call(self,node):
            self.generic_visit(node)
            if isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id+'.'+node.func.attr in calls:
                node.keywords.append(ast.keyword(arg='max_packages',value=ast.Constant(value=600)))
            return node
        def visit_Constant(self,node):
            for row in rules:
                if type(node.value) is type(row['before']) and node.value==row['before']:
                    node.value=row['after'];break
            return node
    C.need(ast.dump(Expected().visit(tree),include_attributes=False)==ast.dump(ast.parse(output),include_attributes=False),
           'undeclared adapter mutation refused')
    backend_receipt=None
    if name=='numeric_vm.py':
        backend=(Path(__file__).resolve().parent/'observer600.py').read_bytes()
        C.need(len(backend)==2784 and __import__('hashlib').sha256(backend).hexdigest()=='c3d804e7f2927c7889835ad187a39a3d7c618a4651700f57b0c5413c46612607',
               'dedicated600 observer backend bytes differ')
        anchor=b"    observation=roots.observe(target,limits=limits,hardlinks='generic-development-internal')\n"
        C.need(output.count(anchor)==1,'dedicated600 observer call anchor differs')
        output=output.replace(anchor,anchor.replace(b'roots.observe(',b'_observer600(roots,'))+b'\n'+backend
        compile(output,'<expanded600-numeric-mount-id>','exec')
        backend_receipt=dict(bytes=len(backend),sha256=__import__('hashlib').sha256(backend).hexdigest(),
            scope='INDEPENDENT600_ROOT_READBACK_MOUNT_QUERY_ONLY',deadline_seconds=600,
            fallback='ORIGINAL_FDINFO_NO_BUDGET_OR_CHECK_WAIVER')
    return output,dict(file=name,edits=len(edits),rules=rules,inventory_calls=call_counts,mount_query_backend=backend_receipt)


def materialize(legacy,out):
    C.legacy(legacy);C.need(not out.exists(),'fresh adapter output required');out.mkdir(mode=0o700)
    result={}
    for name in NAMES:
        path=legacy/'scripts/ci/full-composition-installer-vm'/name
        raw=path.read_bytes();output,receipt=transform(raw,name);target=out/name;target.write_bytes(output)
        result[name]=dict(receipt,before_sha256=C.sha(path),after_sha256=C.sha(target),bytes=len(output))
    (out/'adapter.json').write_bytes(C.encoded(dict(status='PASS_CLOSED_LITERAL_SOURCE_ADAPTER',legacy_source=C.LEGACY,files=result,
        package_count=600,expected600_sha256=C.AFTER,hardware='NOT_RUN',native='NOT_RUN')))
    return result
