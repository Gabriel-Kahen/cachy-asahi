"""Emit the exact Setup606 source from two complete immutable source inputs."""
import argparse, hashlib, json, shutil, stat
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORDERED = {'real-modules': {'bytes': 230031, 'sha256': 'c364be8520067eef013bd9f385f5798e4237ffd5e6a2ee897cec53bb67e6325c'}, 'coexistence': {'bytes': 242232, 'sha256': '5c110eaaa5b7f4784230720d9baacbbdb35f07aaaa1b86d6b1c95a7cd7b579da'}}
COEXISTENCE = {'bytes': 241622, 'sha256': '606b1f545159cd347da14452dad3476b2c9c0a6a8e1b73ae026db2b94f10e871'}
PROFILE = {'bytes': 354144, 'sha256': '6455817a90e9046e0d6ebd2d416b8b3a8e385e9d2625e72c53b39a9ed88f6f92'}  # Filled by the reviewed profile builder.
pin = lambda b: dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
encoded = lambda v: (json.dumps(v, sort_keys=True, indent=2) + '\n').encode()

def need(ok, why):
    if not ok:
        raise ValueError(why)

def ordinary(path):
    p = Path(path).absolute()
    need('..' not in p.parts and not any(q.is_symlink() for q in (p, *p.parents)),
         'ordinary absolute source/output ancestry')
    return p

def read(path):
    p = ordinary(path)
    before = p.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 16 * 1024**2,
         'bounded singlelink source leaf')
    body = p.read_bytes()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
                          s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(len(body) == before.st_size and identity(before) == identity(p.lstat()), 'stable whole source read')
    return body

def files(root):
    root = ordinary(root)
    need(root.is_dir(), 'complete explicit source directory')
    result = {}
    for p in root.rglob('*'):
        rel = p.relative_to(root)
        if rel.parts[0] == '.git':
            continue
        need(not p.is_symlink() and (p.is_file() or p.is_dir()), 'ordinary closed source namespace')
        if p.is_file():
            result[rel.as_posix()] = pin(read(p))
    return result

def emit(original, setup, output, mode='copied-root', ordered_nonce=False):
    raw = read(HERE / 'profile.json')
    need(pin(raw) == PROFILE, 'whole fixed Setup606 source profile')
    p = json.loads(raw)
    original, setup, output = map(ordinary, (original, setup, output))
    need(files(original) == p['original']['files'] and files(setup) == p['setup']['files'],
         'whole immutable353 and240 inputs before output')
    need(mode in ('copied-root', 'real-modules', 'coexistence'), 'explicit finite Setup source profile')
    coexist = None
    addition = {}
    if mode == 'coexistence':
        body = read(HERE / 'coexistence-profile.json')
        need(pin(body) == COEXISTENCE, 'whole fixed coexistence profile before output')
        coexist = json.loads(body)
        need(set(coexist) == {'schema_version', 'parent_source', 'parent_files', 'source', 'ref', 'files', 'payload', 'actual', 'native'}
             and coexist['schema_version'] == 1 and coexist['parent_source'] == p['real_modules']['source']
             and coexist['parent_files'] == p['real_modules']['files'] and len(coexist['parent_files']) == 636
             and coexist['source'] == '5a45919d81890c3196cb712b0b67272d4469f570'
             and coexist['ref'] == 'codex/setup6-apps7-current606-v1'
             and coexist['actual'] is None and coexist['native'] == 'NOT_RUN_BY_FACTORY'
             and len(coexist['files']) == 676 and len(coexist['payload']) == 42, 'typed whole636 to676 profile')
        need(files(HERE / 'coexistence') == coexist['payload'], 'whole coexistence payload before output')
        addition = {n: read(HERE / 'coexistence' / n) for n in coexist['payload']}
        need(all(pin(addition[n]) == row for n, row in coexist['payload'].items())
             and dict(coexist['parent_files'], **coexist['payload']) == coexist['files'],
             'complete coexistence parent/output maps before output')
    expected = coexist['files'] if coexist is not None else p['output'] if mode == 'copied-root' else p['real_modules']['files']
    ordered = None
    ordered_addition = {}
    need(type(ordered_nonce) is bool and (not ordered_nonce or mode in ORDERED),
         'ordered nonce revision only for the two normal-Docker profiles')
    if ordered_nonce:
        name = 'ordered-' + mode
        body = read(HERE / (name + '-profile.json'))
        need(pin(body) == ORDERED[mode], 'whole fixed ordered source profile before output')
        ordered = json.loads(body)
        parent = coexist if coexist is not None else p['real_modules']
        need(ordered['schema_version'] == 1 and ordered['mode'] == mode
             and ordered['parent_source'] == parent['source'] and ordered['parent_files'] == expected
             and ordered['actual'] is None and ordered['native'] == 'NOT_RUN_BY_FACTORY'
             and len(ordered['files']) == len(expected)
             and len(ordered['payload']) == (5 if mode == 'real-modules' else 6),
             'typed complete original/ordered source maps')
        need(files(HERE / name) == ordered['payload'], 'whole ordered readable payload before output')
        ordered_addition = {n: read(HERE / name / n) for n in ordered['payload']}
        need(all(pin(ordered_addition[n]) == row for n, row in ordered['payload'].items())
             and dict(expected, **ordered['payload']) == ordered['files'],
             'all ordered source/payload pins before output')
    payload = {n: read(HERE / 'payload' / n) for n in p['payload']}
    overlay = {} if mode == 'copied-root' else {n: read(HERE / 'real-modules' / n) for n in p['real_modules']['payload']}
    need(mode == 'copied-root' or all(pin(overlay[n]) == row for n, row in p['real_modules']['payload'].items()), 'whole real-module payload before output')
    need(all(pin(payload[n]) == row for n, row in p['payload'].items()), 'whole readable payload before output')
    need(not output.exists() and output.parent.is_dir() and not output.is_relative_to(original)
         and not original.is_relative_to(output) and not output.is_relative_to(setup)
         and not setup.is_relative_to(output), 'fresh disjoint output before copying')
    shutil.copytree(original, output, ignore=shutil.ignore_patterns('.git'))
    shutil.copytree(setup, output / 'setup240', ignore=shutil.ignore_patterns('.git'))
    sources = dict(original=original, setup=setup)
    for n, row in p['copies'].items():
        body = read(sources[row['role']] / row['path'])
        need(pin(body) == row['pin'], 'whole selected source helper')
        dest = output / n
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(body)
    for n, body in dict(payload, **overlay).items():
        dest = output / n
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(body)
    if coexist is not None:
        need(files(output) == coexist['parent_files'], 'entire unchanged636 parent before finite overlay')
        for n, body in addition.items():
            dest = output / n
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
    need(files(output) == expected, 'whole exact selected608/636/676 source output')
    if ordered is not None:
        for n, body in ordered_addition.items():
            dest = output / n
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
        need(files(output) == ordered['files'], 'entire exact ordered source output')
        return dict(status='SOURCE_ONLY_EXACT_ORDERED_SETUP_PROFILE_NATIVE_UNQUALIFIED',
                    files=ordered['files'], source_mode=mode, source_revision='ordered-nonce',
                    expected_source=ordered['source'], actual=None, hardware='NOT_RUN', release='NOT_ADMITTED',
                    full606_real_shell='NOT_RUN_BY_FACTORY_REAL_DOCKER_PROFILE',
                    Apps7='NOT_RUN_BY_FACTORY_REQUIRES_FULL676_NATIVE_REPLAY' if mode == 'coexistence' else 'NOT_RUN_BASELINE_APPS6')
    if coexist is not None:
        return dict(status='SOURCE_ONLY_EXACT676_APPS7_SETUP6_COEXISTENCE_NATIVE_UNQUALIFIED',
                    files=expected, source_mode=mode, expected_source=coexist['source'],
                    actual=None, hardware='NOT_RUN', release='NOT_ADMITTED',
                    full606_real_shell='NOT_RUN_BY_FACTORY_REAL_DOCKER_PROFILE',
                    Apps7='NOT_RUN_BY_FACTORY_REQUIRES_FULL676_NATIVE_REPLAY')
    return dict(status='SOURCE_ONLY_EXACT608_SETUP6_CURRENT606_NATIVE_UNQUALIFIED' if mode == 'copied-root' else 'SOURCE_ONLY_EXACT636_SETUP6_REAL_MODULES_NATIVE_UNQUALIFIED',
                files=expected, source_mode=mode, expected_source=p['expected_source'] if mode == 'copied-root' else p['real_modules']['source'], actual=None, hardware='NOT_RUN', release='NOT_ADMITTED',
                full606_real_shell='NOT_RUN_DEVICE_FREE_COPY' if mode == 'copied-root' else 'NOT_RUN_BY_FACTORY_REAL_DOCKER_PROFILE', Apps7='NOT_RUN_BASELINE_APPS6')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original-source', type=Path, required=True)
    parser.add_argument('--setup-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mode', choices=('copied-root', 'real-modules', 'coexistence'), default='copied-root')
    parser.add_argument('--ordered-nonce', action='store_true', help='Use the fixed corrected source revision; original source modes remain reproducible')
    parser.add_argument('--authorization', type=Path, required=True)
    args = parser.parse_args()
    auth = ordinary(args.authorization)
    need(not auth.exists() and auth.parent.is_dir(), 'fresh authorization output')
    value = emit(args.original_source, args.setup_source, args.output, args.mode, args.ordered_nonce)
    with auth.open('xb') as stream:
        stream.write(encoded(value))
