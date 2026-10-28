# SPDX-License-Identifier: MIT
"""Pure exact bound357→cache360 source factory; no actors."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE = {'bytes': 403524, 'sha256': 'e02f5dad83809448f6f7afe5d69aacdbd34d171d7ba437629b13bc107eb281ad'}

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
             0 <= before.st_size <= 16 * 1024**2, 'bounded ordinary single-link source file')
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

def paths(source, helper, output):
    source, helper, output = map(ordinary, (source, helper, output))
    need(not source.is_relative_to(helper) and not helper.is_relative_to(source),
         'distinct disjoint ordinary parent and helper DATA roots')
    need(output.parent.is_dir() and not os.path.lexists(output), 'fresh output required')
    need(not any('native-actual' in p.name for p in (output, *output.parents)),
         'native actual roots are not source-factory destinations')
    for protected in (source, helper, HERE):
        need(not output.is_relative_to(protected) and not protected.is_relative_to(output),
             'disjoint supplied DATA/factory/output paths')
    return source, helper, output


def apply(raw, rows, reverse=False):
    for before, after in (reversed(rows) if reverse else rows):
        a, b = (after.encode(), before.encode()) if reverse else (before.encode(), after.encode())
        need(a and raw.count(a) == 1, 'one exact readable source seam')
        raw = raw.replace(a, b, 1)
    return raw


def compose(source, helper):
    source, helper = map(ordinary, (source, helper))
    entry = read_state(HERE/'prepare.py')
    raw, state = read_state(HERE/'profile.json')
    need(pin(raw) == PROFILE, 'entry-point-pinned closed profile')
    p = json.loads(raw)
    need(p['counts'] == dict(before=357, after=360, held=345, changed=12, added=3, removed=0)
         and all(p[k] is None for k in ('actual_source','actual_ref','actual_run','Root_acceptance'))
         and p['acceptance_authority'] is False, 'fixed source-only cache layer')
    before, before_state = scan(source)
    helpers, helper_state = scan(helper)
    need({n:pin(b) for n,b in before.items()} == p['parent']['files'], 'entire exact public357 parent')
    need({n:pin(b) for n,b in helpers.items()} == p['helper']['files'], 'entire exact public1203 helper SOURCE DATA')
    operands, states = {}, {'prepare.py':entry, 'profile.json':(raw,state)}
    for n,w in p['operands'].items():
        b,s = read_state(HERE/n)
        need(pin(b) == w, 'fixed readable operand '+n)
        operands[n], states[n] = b, (b,s)
    edits = json.loads(operands['edits.json'])
    values = dict(before)
    for n, rows in edits.items():
        values[n] = apply(before[n], rows)
        need(apply(values[n], rows, reverse=True) == before[n], 'whole original body inverse '+n)
    for name, operand in (('implementation/cache.py','cache_append.py.txt'),
                          ('implementation/namespace_context.py','context_append.py.txt'),
                          ('README.md','readme_append.md')):
        values[name] = before[name] + operands[operand]
        need(values[name][:-len(operands[operand])] == before[name], 'complete held prefix '+name)
    profile = json.loads(before['implementation/profile.json'])
    profile['dependency_cache'] = p['dependency_cache']
    profile['input_sources']['dependency_incoming'] = p['dependency_cache']['incoming_source']
    previous_profile = json.loads(encoded(profile))
    previous_profile.pop('dependency_cache')
    previous_profile['input_sources'].pop('dependency_incoming')
    need(encoded(previous_profile) == before['implementation/profile.json'], 'entire original profile inverse')
    values['implementation/profile.json'] = encoded(profile)
    for name,w in p['helper']['selected'].items():
        path = 'implementation/'+name
        need(pin(helpers[path]) == w, 'exact selected readable helper '+name)
        values[path] = helpers[path]
    marker = b"\nif __name__=='__main__':\n"
    need(before['test_source.py'].count(marker) == 1, 'one explicit original source suite')
    test = before['test_source.py'].replace(marker, operands['test_append.py.txt']+marker, 1)
    test = apply(test, [("suite.countTestCases()==11", "suite.countTestCases()==16"),
                        ('nonzero exact11 source groups', 'nonzero exact16 source groups')])
    values['test_source.py'] = test
    aliases = ('.github/workflows/native-arm-build.yml',
               '.github/workflows/native-arm-latest607-updater4k.yml')
    need(before[aliases[0]] == before[aliases[1]], 'whole original workflow alias')
    workflow = json.loads(before[aliases[0]])
    steps = workflow['jobs']['native']['steps']
    need(len(steps) == 62, 'whole original62 source steps')
    matches = [i for i,r in enumerate(steps) if r['name'] ==
               'Required separate native ARM4K full interruption/recovery case']
    need(len(matches) == 1, 'one unchanged native case stage')
    index = matches[0]
    steps.insert(index, dict(name='Checkout exact retained five dependency input source',
        uses=steps[0]['uses'], **{'with':dict(ref=p['dependency_cache']['incoming_source'],
            path='latest607-dependency-incoming', **{'persist-credentials':False})}))
    run = steps[index+1]['run']
    a = '  --latest-installer '
    b = '  --dependency-incoming "$GITHUB_WORKSPACE/latest607-dependency-incoming" \\\n  --latest-installer '
    need(run.count(a) == 1, 'one native runtime incoming argument seam')
    steps[index+1]['run'] = run.replace(a,b,1)
    controls = [r for r in steps if r['name'] == 'Run closed607 source and focused nonzero source controls']
    need(len(controls) == 1, 'one explicit source control step')
    a = 'python3 -I -B native4k-source/test_source.py'
    b = 'LATEST607_HELD_SOURCE="$GITHUB_WORKSPACE/expanded604-upgrade" '+a
    need(controls[0]['run'].count(a) == 1, 'one original test invocation')
    controls[0]['run'] = controls[0]['run'].replace(a,b,1)
    need(len(steps) == 63, 'one added exact checkout only')
    restored_workflow = json.loads(encoded(workflow))
    restored_steps = restored_workflow['jobs']['native']['steps']
    checkout = restored_steps.pop(index)
    need(checkout['with']['ref'] == p['dependency_cache']['incoming_source'], 'exact checkout inverse')
    current_run = restored_steps[index]['run']
    extra = '  --dependency-incoming "$GITHUB_WORKSPACE/latest607-dependency-incoming" \\\n'
    need(current_run.count(extra) == 1, 'one runtime argument inverse')
    restored_steps[index]['run'] = current_run.replace(extra, '', 1)
    restored_control = next(r for r in restored_steps if r['name'] ==
                           'Run closed607 source and focused nonzero source controls')
    need(restored_control['run'].count(b) == 1, 'one test environment inverse')
    restored_control['run'] = restored_control['run'].replace(b, a, 1)
    need(encoded(restored_workflow) == before[aliases[0]], 'entire original workflow inverse')
    values.update({n:encoded(workflow) for n in aliases})
    parent = json.loads(before['implementation/parent355.json'])
    parent['dependency_cache_context'] = dict(source=p['parent']['source'],ref=p['parent']['ref'],
        files=p['parent']['files'],before_bodies={n:before[n].decode() for n in p['before_body_names']},
        operands=p['helper']['selected'],reused_source=p['helper']['source'],reused_ref=p['helper']['ref'],
        actual_source=None,actual_ref=None,actual_run=None,acceptance=False)
    values['implementation/parent355.json'] = encoded(parent)
    manifest = json.loads(before['source-manifest.json'])
    manifest['files'] = {n:pin(b) for n,b in values.items() if n != 'source-manifest.json'}
    values['source-manifest.json'] = encoded(manifest)
    need({n:pin(b) for n,b in values.items()} == p['result']['files'], 'all360 exact published cache-layer bytes')
    need(set(values)-set(before) == set(p['added']) and all(values[n] == before[n] for n in p['held'])
         and {n for n in before if values[n] != before[n]} == set(p['changed']), 'closed345held/12changed/3added')
    context = parent['dependency_cache_context']
    prior = dict(parent)
    prior.pop('dependency_cache_context')
    restored = {}
    for n,w in p['parent']['files'].items():
        if n == 'implementation/parent355.json':
            b = encoded(prior)
        elif n in context['before_bodies']:
            b = context['before_bodies'][n].encode()
        elif n == 'source-manifest.json':
            m = dict(manifest)
            m['files'] = {k:v for k,v in p['parent']['files'].items() if k != 'source-manifest.json'}
            b = encoded(m)
        else:
            b = values[n]
        need(pin(b) == w, 'whole original357 inverse '+n)
        restored[n] = b
    need(restored == before, 'entire original357 byte equality')
    need(scan(source) == (before,before_state) and scan(helper) == (helpers,helper_state)
         and all(read_state(HERE/n) == row for n,row in states.items()), 'late whole source/helper/operand drift')
    return values,p,(before,before_state),(helpers,helper_state),states


def emit(source,helper,output,context):
    need(context in ('known','null'), 'known/NULL source receipt only')
    source,helper,output = paths(source,helper,output)
    values,p,before,helpers,states = compose(source,helper)
    paths(source,helper,output)
    need(scan(source) == before and scan(helper) == helpers and
         all(read_state(HERE/n) == row for n,row in states.items()), 'late complete inputs before any write')
    output.mkdir(mode=0o700)
    for n,b in sorted(values.items()):
        target=output/n
        target.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(b)
            os.fchmod(stream.fileno(),0o644)
    need(tree(output) == values and all(stat.S_IMODE((output/n).stat().st_mode)==0o644 for n in values),
         'all360 production bytes and0644 modes')
    return dict(status='SOURCE_ONLY_EXACT_UPDATER_CACHE360_NOT_NATIVE_ACCEPTANCE',context=context,
        files={n:pin(b) for n,b in values.items()},source=p['result']['source'] if context=='known' else None,
        ref=p['result']['ref'] if context=='known' else None,actual_source=None,actual_ref=None,actual_run=None,
        Root_acceptance=None,native='NOT_RUN',hardware='NOT_RUN',performance='NOT_RUN',fit='NOT_ESTABLISHED',
        old_dependency_cause='UNKNOWN',runtime_argument_fix='SEPARATE_ED981_FACTORY_REQUIRED')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True)
    parser.add_argument('--helper-source',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--context',choices=('known','null'),required=True)
    args=parser.parse_args()
    print(json.dumps(emit(args.source,args.helper_source,args.output,args.context),sort_keys=True,indent=2))
