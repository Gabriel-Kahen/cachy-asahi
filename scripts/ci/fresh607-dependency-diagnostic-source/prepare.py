# SPDX-License-Identifier: MIT
"""Pure exact public1203→1203 dependency failure DATA source factory; no actors."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE = {'bytes': 724058, 'sha256': 'c9ef1df5abea6d1fbc0101a777b9ba5675e53e2bcf71e5a384895364bd5ef5ce'}

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
    source=ordinary(source);entry=read_state(HERE/'prepare.py')
    raw,profile_state=read_state(HERE/'profile.json');need(pin(raw)==PROFILE,'fixed entry-point-pinned profile')
    p=json.loads(raw);need(p['counts']==dict(before=1203,after=1203,held=1197,changed=6,added=0)and
        all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance'))and
        p['acceptance_authority']is False,'closed source-only1203 scope')
    before,bstate=scan(source);need({n:pin(b)for n,b in before.items()}==p['parent']['files'],'whole exact public1203 parent')
    states={};operands={}
    for n,w in p['operands'].items():
        b,s=read_state(HERE/n);need(pin(b)==w,'fixed readable operand '+n);operands[n]=json.loads(b);states[n]=(b,s)
    changes=operands['helper-edits.json'];helper=apply(before['implementation/producer_diagnostic.py'],changes['edits'])+changes['append'].encode()
    parent=json.loads(before['implementation/page-parent.json']);oldsha=pin(before['implementation/page-parent.json'])['sha256']
    guard=before['implementation/page_source.py'];need(guard.count(oldsha.encode())==1,'one exact parent seal')
    template=apply(guard.replace(oldsha.encode(),b'@PARENT_SHA@',1),p['guard_edits'])
    d=operands['dependency-context.json'];need(d['source']==p['parent']['source']and d['actual_source']is d['actual_ref']is d['actual_run']is None,'fixed historical source DATA')
    d.update(files=p['parent']['files'],before_bodies={n:before[n].decode()for n in p['changed']},helper_edits=changes);d['git']['files']=p['parent']['files']
    parent['before_bodies']['implementation/producer_diagnostic.py']=before['implementation/producer_diagnostic.py'].decode()
    parent['scope_parent']['before_bodies']['implementation/producer_diagnostic.py']=before['implementation/producer_diagnostic.py'].decode()
    parent['dependency_parent']=d;parent['guard_template']=pin(template);praw=encoded(parent)
    need(template.count(b'@PARENT_SHA@')==1,'one final current source parent seal');guard=template.replace(b'@PARENT_SHA@',pin(praw)['sha256'].encode(),1)
    values=dict(before);values.update({'implementation/producer_diagnostic.py':helper,'implementation/page_source.py':guard,'implementation/page-parent.json':praw})
    aliases=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml')
    manifest=json.loads(before['source-manifest.json']);manifest['files']={n:pin(b)for n,b in values.items()if n not in('source-manifest.json',*aliases)};values['source-manifest.json']=encoded(manifest)
    for n in aliases:
        workflow=values['implementation/workflow-template.yml'];need(workflow.count(b'@FRESH607_MANIFEST@')==1,'one unchanged workflow manifest seal')
        values[n]=workflow.replace(b'@FRESH607_MANIFEST@',pin(values['source-manifest.json'])['sha256'].encode(),1)
    need({n:pin(b)for n,b in values.items()}==p['result']['files'],'all1203 exact current published bytes')
    restored=dict(values)
    for n in p['changed']:restored[n]=d['before_bodies'][n].encode()
    need(restored==before and set(values)==set(before)and{n for n in before if values[n]!=before[n]}==set(p['changed'])and
        all(values[n]==before[n]for n in p['held']),'whole1203 inverse and all1197 held')
    need(apply(helper[:-len(changes['append'].encode())],changes['edits'],reverse=True)==before['implementation/producer_diagnostic.py'],'whole original helper inverse')
    need(apply(template,p['guard_edits'],reverse=True).replace(b'@PARENT_SHA@',oldsha.encode(),1)==before['implementation/page_source.py'],'whole original page guard inverse')
    states.update({'profile.json':(raw,profile_state),'prepare.py':entry})
    need(scan(source)==(before,bstate)and all(read_state(HERE/n)==row for n,row in states.items()),'late source/operand content identity drift')
    return values,p,(before,bstate),states


def emit(source,output,context):
    need(context in('known','null'),'known/NULL publication receipt only');source,output=paths(source,output)
    values,p,before,states=compose(source);paths(source,output)
    need(scan(source)==before and all(read_state(HERE/n)==row for n,row in states.items()),'late complete inputs before any write')
    output.mkdir(mode=0o700)
    for n,b in sorted(values.items()):
        target=output/n;target.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as stream:stream.write(b);os.fchmod(stream.fileno(),0o644)
    need(tree(output)==values and all(stat.S_IMODE((output/n).stat().st_mode)==0o644 for n in values),'all1203 production bytes and0644 modes')
    return dict(status='SOURCE_ONLY_EXACT1203_DEPENDENCY_FAILURE_DATA_NOT_ACCEPTANCE',context=context,files={n:pin(b)for n,b in values.items()},held=1197,changed=6,
        source=p['result']['source']if context=='known'else None,ref=p['result']['ref']if context=='known'else None,
        actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None,native='NOT_RUN',hardware='NOT_RUN',performance='NOT_RUN',fit='NOT_ESTABLISHED',inner_dependency_cause='UNKNOWN')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True);parser.add_argument('--output',required=True);parser.add_argument('--context',choices=('known','null'),required=True)
    args=parser.parse_args();print(json.dumps(emit(args.source,args.output,args.context),sort_keys=True,indent=2))
