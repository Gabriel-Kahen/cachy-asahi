# SPDX-License-Identifier: MIT
"""Reproduce exact1203 retained dependency-cache source from its pinned parent."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 725463, 'sha256': '739939ed5b732fc6fa1046cb090ee19f6d6ca47c5ce0d0ce4f92f0d8e8b61ac8'}

def need(ok, message):
    if not ok:
        raise ValueError(message)

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def ordinary(value):
    raw = os.fspath(value)
    need(type(raw) is str and os.path.isabs(raw) and raw == os.path.normpath(raw),
         'absolute normalized path required')
    path = Path(raw)
    need(path == path.resolve(), 'canonical resolved path required')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary nonalias ancestry')
    return path

def identity(info):
    # Reading a file/directory may update atime; it is never identity evidence.
    return tuple(getattr(info, key) for key in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def read_state(value):
    path = ordinary(value)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= 8 * 1024**2, 'bounded ordinary single-link source file')
        parts, size = [], 0
        while part := os.read(fd, 1024**2):
            parts.append(part)
            size += len(part)
            need(size <= before.st_size, 'source file grew during read')
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(path.lstat()), 'whole stable descriptor and path identity')
        return b''.join(parts), identity(before)
    finally:
        os.close(fd)

def read(path):
    return read_state(path)[0]

def scan(value):
    root = ordinary(value)
    need(root.is_dir(), 'ordinary source root required')
    files, state, directories = {}, {}, {}
    for path in (root, *sorted(root.rglob('*'))):
        info = path.lstat()
        need(not path.is_symlink(), 'source alias refused')
        name = path.relative_to(root).as_posix() if path != root else ''
        if stat.S_ISDIR(info.st_mode):
            directories[name] = (identity(info), tuple(sorted(p.name for p in path.iterdir())))
        else:
            raw, record = read_state(path)
            files[name], state[name] = raw, record
    required = {''}
    for name in files:
        required.update('' if str(p) == '.' else p.as_posix() for p in Path(name).parents)
    need(set(directories) == required, 'closed source directory membership, no foreign empty dirs')
    for name, (record, names) in directories.items():
        path = root / name
        need(identity(path.lstat()) == record and
             tuple(sorted(p.name for p in path.iterdir())) == names, 'stable whole source namespace')
    return files, dict(files=state, directories=directories)

def tree(root):
    return scan(root)[0]

def paths(source, output):
    source, output = ordinary(source), ordinary(output)
    need(output.parent.is_dir() and not os.path.lexists(output), 'fresh output required')
    need(not any('native-actual' in p.name for p in (output, *output.parents)),
         'native actual roots are not source-factory destinations')
    for protected in (source, HERE):
        need(not output.is_relative_to(protected) and not protected.is_relative_to(output),
             'disjoint supplied source/factory/output paths')
    return source, output

def apply(raw,rows,reverse=False):
    for a,b in(reversed(rows)if reverse else rows):
        old,new=(b.encode(),a.encode())if reverse else(a.encode(),b.encode())
        need(old and raw.count(old)==1,'one exact readable source seam')
        raw=raw.replace(old,new,1)
    return raw


def compose(source):
 source=ordinary(source);entry=read_state(HERE/'prepare.py');raw,pstate=read_state(HERE/'profile.json');need(pin(raw)==PROFILE,'entry-pinned factory profile');p=json.loads(raw)
 need(p['counts']==dict(before=1203,after=1203,held=1195,changed=8,added=0)and all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance'))and p['acceptance_authority']is False,'closed source-only scope')
 before,bstate=scan(source);need({n:pin(b)for n,b in before.items()}==p['parent']['files'],'whole exact parent1203');states={};operands={}
 for n,w in p['operands'].items():
  b,s=read_state(HERE/n);need(pin(b)==w,'fixed readable operand '+n);operands[n]=b;states[n]=(b,s)
 c=json.loads(operands['cache-context.json']);c['helper_append']=operands['dependency_append.py.in'].decode();c['files']=p['parent']['files'];c['git']['files']=p['parent']['files'];c['before_bodies']={n:before[n].decode()for n in p['changed']if n!='implementation/page-parent.json'}
 need(c['source']==p['parent']['source']and c['actual_source']is c['actual_ref']is c['actual_run']is None,'fixed parent SOURCE identity')
 helper=apply(before['implementation/compiler6.py'],c['helper_edits']);anchor=b"if __name__=='__main__':";need(helper.count(anchor)==1,'one original CLI boundary');helper=helper.replace(anchor,operands['dependency_append.py.in']+b'\n'+anchor,1)
 workflow=before['implementation/workflow-template.yml'];step=c['preparation_step'].encode();need(workflow.count(step)==1,'one held preparation checkout');workflow=workflow.replace(step,b'',1);anchor=b'      - name: Checkout exact retained compiler6 archive and signature inputs\n';need(workflow.count(anchor)==1,'one compiler checkout boundary');workflow=workflow.replace(anchor,step+c['incoming_step'].encode()+anchor,1);workflow=apply(workflow,c['workflow_edits'])
 parent=json.loads(before['implementation/page-parent.json']);oldsha=pin(before['implementation/page-parent.json'])['sha256'];guard=before['implementation/page_source.py'];need(guard.count(oldsha.encode())==1,'one old parent seal');template=apply(guard.replace(oldsha.encode(),b'@PARENT_SHA@',1),p['guard_edits'])
 for path,names in c['parent_seam']['added_before_bodies'].items():
  target=parent
  for key in path.split('.'):target=target[key]
  for name in names:need(name not in target,'only missing declared inverse operand');target[name]=before[name].decode()
 parent['dependency_cache_parent']=c;parent['guard_template']=pin(template);praw=encoded(parent);need(len(praw)<16*1024**2 and template.count(b'@PARENT_SHA@')==1,'held16MiB parent and one seal')
 values=dict(before);values.update({'implementation/compiler6.py':helper,'implementation/compiler6-profile.json':encoded(c['profile']),'implementation/page_source.py':template.replace(b'@PARENT_SHA@',pin(praw)['sha256'].encode(),1),'implementation/page-parent.json':praw,'implementation/workflow-template.yml':workflow})
 aliases=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml');manifest=json.loads(before['source-manifest.json']);manifest['files']={n:pin(b)for n,b in values.items()if n not in('source-manifest.json',*aliases)};values['source-manifest.json']=encoded(manifest)
 for n in aliases:need(workflow.count(b'@FRESH607_MANIFEST@')==1,'one workflow manifest seal');values[n]=workflow.replace(b'@FRESH607_MANIFEST@',pin(values['source-manifest.json'])['sha256'].encode(),1)
 need({n:pin(b)for n,b in values.items()}==p['result']['files'],'all exact published1203 bytes')
 restored=dict(values)
 for n in p['changed']:restored[n]=before[n]
 need(restored==before and {n for n in before if values[n]!=before[n]}==set(p['changed'])and all(values[n]==before[n]for n in p['held']),'whole before inverse and1195 held')
 need(apply(template,p['guard_edits'],reverse=True).replace(b'@PARENT_SHA@',oldsha.encode(),1)==before['implementation/page_source.py'],'whole guard inverse')
 need(apply(helper.replace(operands['dependency_append.py.in']+b'\n'+b"if __name__=='__main__':",b"if __name__=='__main__':",1),c['helper_edits'],reverse=True)==before['implementation/compiler6.py'],'whole original compiler helper inverse')
 states.update({'profile.json':(raw,pstate),'prepare.py':entry});need(scan(source)==(before,bstate)and all(read_state(HERE/n)==v for n,v in states.items()),'late complete source/operand identity')
 return values,p,(before,bstate),states

def emit(source,output,context):
 need(context in('known','null'),'known/NULL receipt only');source,output=paths(source,output);values,p,before,states=compose(source);paths(source,output)
 need(scan(source)==before and all(read_state(HERE/n)==v for n,v in states.items()),'late inputs before writes');output.mkdir(mode=0o700)
 for n,b in sorted(values.items()):
  q=output/n;q.parent.mkdir(parents=True,exist_ok=True);fd=os.open(q,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb')as f:f.write(b);os.fchmod(f.fileno(),0o644)
 need(tree(output)==values and all(stat.S_IMODE((output/n).stat().st_mode)==0o644 for n in values),'exact production1203 bytes/modes')
 return dict(status='SOURCE_ONLY_RETAINED_DEPENDENCY_CACHE_NOT_ACCEPTANCE',context=context,files=p['result']['files'],source=p['result']['source']if context=='known'else None,ref=p['result']['ref']if context=='known'else None,actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None,hardware='NOT_RUN',performance='NOT_MEASURED')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('source','output','context'):p.add_argument('--'+n,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source,a.output,a.context),sort_keys=True,indent=2))
