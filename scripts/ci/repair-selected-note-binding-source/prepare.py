# SPDX-License-Identifier: MIT
"""Portable exact compressed failure NOTE245 factory from its operative public parent."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE_SHA='5f531db2b6eb6bcc4bf942e0320e2a01dcee0e08cbf40a30adb54b41938e6ce6'
def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def canonical(value):
    raw = os.fspath(value)
    need(type(raw) is str and os.path.isabs(raw) and raw == os.path.normpath(raw) and not raw.startswith('//'),
         'absolute normalized path required')
    path = Path(raw)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary nonalias ancestry')
    return path


def identity(info):
    # Reading a file/directory may update atime; it is never identity evidence.
    return tuple(getattr(info, key) for key in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read_state(value):
    path = canonical(value)
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
    root = canonical(value)
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

A='scripts/ci/apps7-full574-repair16k/adapter.py';H='apps16-repair/inspect_validation.py';G='apps16-repair/relative_source.py';Q='apps16-repair/relative-profile.json';SUCCESSOR='apps16-repair/successor.json'
MANIFESTS=('scripts/ci/apps7-full574-repair-native/source-manifest.json','scripts/ci/apps7-full574-repair16k/source-manifest.json','scripts/ci/apps7-full574-repair16k-ci/source-manifest.json')
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-apps7-full574-repair16k.yml')
def one(raw,before,after):
    need(raw.count(before)==1,'one exact counted binding operand')
    result=raw.replace(before,after,1)
    need(result.count(after)==1 and result.replace(after,before,1)==raw,'whole counted binding inverse')
    return result

def literal(raw):
    import ast
    matches=[n for n in ast.parse(raw).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='_INSPECT_VALIDATION_SOURCE'for t in n.targets)]
    need(len(matches)==1,'one operative inline helper literal')
    node=matches[0].value
    return ast.get_source_segment(raw.decode(),node).encode(),ast.literal_eval(node)

def transform(before,p,operands):
    old_literal,old_body=literal(before[A]);need(old_body.encode()==before[H],'exact operative parent required')
    helper=before[H]
    for a,b in operands['helper_edits']['edits']:helper=one(helper,a.encode(),b.encode())
    helper+=operands['helper_edits']['append'].encode()
    old_sha=pin(before[Q])['sha256'];guard=before[G]
    for a,b in operands['guard_edits']:guard=one(guard,a.encode(),b.encode())
    guard+=operands['guard_append']
    profile=json.loads(before[Q]);capture=dict(p['stderr_capture'],before=p['parent']['files'],git=dict(p['parent']['git_header'],files=p['parent']['files']),literal_before=old_literal.decode(),before_guard_template=profile['guard_template'],helper_edits=operands['helper_edits']['edits'],helper_append=operands['helper_edits']['append'],guard_edits=operands['guard_edits'],guard_append=operands['guard_append'].decode())
    profile['stderr_capture']=capture
    need(guard.count(old_sha.encode())==1,'one original guard seal')
    profile['guard_template']=pin(guard.replace(old_sha.encode(),b'PROFILE_SHA_PLACEHOLDER',1))
    raw_profile=encoded(profile);need(len(raw_profile)<8*1024**2,'original8MiB profile cap')
    guard=one(guard,old_sha.encode(),pin(raw_profile)['sha256'].encode())
    values=dict(before);values[H]=helper;values[A]=one(before[A],old_literal,repr(helper.decode()).encode());values[G]=guard;values[Q]=raw_profile
    v=json.loads(before[SUCCESSOR]);v['after']={n:pin(b)for n,b in sorted(values.items())if n not in v['excluded_seals']};values[SUCCESSOR]=encoded(v)
    for n in MANIFESTS:
        v=json.loads(before[n]);v['files']={k:pin(values[k])for k in sorted(v['files'])};values[n]=encoded(v)
    for n in WORKFLOWS:values[n]=one(before[n],pin(before[MANIFESTS[-1]])['sha256'].encode(),pin(values[MANIFESTS[-1]])['sha256'].encode())
    need(literal(values[A])[1].encode()==values[H],'whole operative and external helper equality')
    return values

def inverse(values,p):
    capture=json.loads(values[Q])['stderr_capture'];before=p['parent']['files'];restored={}
    for n in before:
        raw=values[n]
        if n==H:
            tail=capture['helper_append'].encode();need(tail and raw.endswith(tail),'one whole helper footer inverse');raw=raw[:-len(tail)]
            for a,b in reversed(capture['helper_edits']):raw=one(raw,b.encode(),a.encode())
        elif n==A:raw=one(raw,repr(values[H].decode()).encode(),capture['literal_before'].encode())
        elif n==Q:
            v=json.loads(raw);v.pop('stderr_capture');v['guard_template']=capture['before_guard_template'];raw=encoded(v)
        elif n==G:
            raw=one(raw,pin(values[Q])['sha256'].encode(),before[Q]['sha256'].encode());tail=capture['guard_append'].encode();need(tail and raw.endswith(tail),'one whole guard footer inverse');raw=raw[:-len(tail)]
            for a,b in reversed(capture['guard_edits']):raw=one(raw,b.encode(),a.encode())
        elif n==SUCCESSOR:
            v=json.loads(raw);v['after']={k:before[k]for k in v['after']};raw=encoded(v)
        elif n in MANIFESTS:
            v=json.loads(raw);v['files']={k:before[k]for k in v['files']};raw=encoded(v)
        elif n in WORKFLOWS:raw=one(raw,pin(values[MANIFESTS[-1]])['sha256'].encode(),before[MANIFESTS[-1]]['sha256'].encode())
        need(pin(raw)==before[n],'entire operative parent before byte '+n);restored[n]=raw
    return restored

def compose(source):
    source=canonical(source);profile_raw,profile_state=read_state(HERE/'profile.json')
    need(pin(profile_raw)['sha256']==PROFILE_SHA,'fixed portable source profile')
    p=json.loads(profile_raw);operands={};states={}
    for file,key in(('guard-edits.json','guard_edits'),('helper-edits.json','helper_edits'),('guard-append.py.txt','guard_append')):
        raw,state=read_state(HERE/file);need(pin(raw)==p[key],'readable counted '+key+' operands');states[file]=(raw,state);operands[key]=raw if key=='guard_append'else json.loads(raw)
    before,state=scan(source);need({n:pin(b)for n,b in before.items()}==p['parent']['files'],'entire exact exported operative245 input')
    values=transform(before,p,operands);need({n:pin(b)for n,b in values.items()}==p['result']['files'],'entire exact compressed NOTE public245 output')
    need(inverse(values,p)==before and {n for n in before if values[n]!=before[n]}==set(p['changed'])and all(values[n]==before[n]for n in p['held']),'whole245 inverse,10changed235held')
    for n,b in values.items():
        if n.endswith('.py'):compile(b,n,'exec')
    need(scan(source)==(before,state)and read_state(HERE/'profile.json')==(profile_raw,profile_state)and all(read_state(HERE/file)==record for file,record in states.items()),'late byte/inode/namespace/profile/operand drift before writes')
    return values,p

def destinations(source,output,receipt):
    source,output=map(canonical,(source,output));receipt=canonical(receipt)if receipt is not None else None
    for value in(output,receipt):
        if value is None:continue
        need(value.parent.is_dir()and not os.path.lexists(value),'fresh output/receipt with existing parent')
        need(not any('native-actual'in x.name for x in(value,*value.parents)),'actual namespace protected')
        for root in(source,HERE):need(not value.is_relative_to(root)and not root.is_relative_to(value),'disjoint input/factory/output/receipt')
    if receipt is not None:need(not output.is_relative_to(receipt)and not receipt.is_relative_to(output),'disjoint output and receipt')
    return source,output,receipt

def emit(source,output,context,receipt=None):
    need(context in('known','null'),'explicit source-only known/NULL context')
    source,output,receipt=destinations(source,output,receipt);values,p=compose(source);destinations(source,output,receipt)
    output.mkdir(mode=0o700)
    for n,b in values.items():
        path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'wb')as stream:stream.write(b);os.fchmod(stream.fileno(),0o644)
    need(scan(output)[0]==values,'entire emitted245 bytes')
    row=dict(status='SOURCE_ONLY_EXACT_COMPRESSED_NOTE_PUBLIC245_NOT_NATIVE_ACCEPTANCE',source=p['result']['source']if context=='known'else None,ref=p['result']['ref']if context=='known'else None,files=245,actual=None,Root_acceptance=None,native='NOT_RUN',deadline_fit='NOT_ESTABLISHED',inner_hotspot='UNKNOWN',M2='NOT_RUN')
    if receipt is not None:
        with receipt.open('xb')as stream:stream.write(encoded(dict(row,file_map=p['result']['files'])))
    return row

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for n in('source','output'):parser.add_argument('--'+n,required=True)
    parser.add_argument('--context',choices=('known','null'),required=True);parser.add_argument('--receipt');args=parser.parse_args()
    print(json.dumps(emit(args.source,args.output,args.context,args.receipt),sort_keys=True))
