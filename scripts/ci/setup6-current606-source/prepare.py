"""Emit the exact Setup606 source from two complete immutable source inputs."""
import argparse, hashlib, json, shutil, stat
from pathlib import Path

HERE = Path(__file__).resolve().parent
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

def emit(original, setup, output, mode='copied-root'):
    raw = read(HERE / 'profile.json')
    need(pin(raw) == PROFILE, 'whole fixed Setup606 source profile')
    p = json.loads(raw)
    original, setup, output = map(ordinary, (original, setup, output))
    need(files(original) == p['original']['files'] and files(setup) == p['setup']['files'],
         'whole immutable353 and240 inputs before output')
    need(mode in ('copied-root', 'real-modules'), 'explicit finite Setup source profile')
    expected = p['output'] if mode == 'copied-root' else p['real_modules']['files']
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
    need(files(output) == expected, 'whole exact608 source output')
    return dict(status='SOURCE_ONLY_EXACT608_SETUP6_CURRENT606_NATIVE_UNQUALIFIED' if mode == 'copied-root' else 'SOURCE_ONLY_EXACT636_SETUP6_REAL_MODULES_NATIVE_UNQUALIFIED',
                files=expected, source_mode=mode, expected_source=p['expected_source'] if mode == 'copied-root' else p['real_modules']['source'], actual=None, hardware='NOT_RUN', release='NOT_ADMITTED',
                full606_real_shell='NOT_RUN_DEVICE_FREE_COPY' if mode == 'copied-root' else 'NOT_RUN_BY_FACTORY_REAL_DOCKER_PROFILE', Apps7='NOT_RUN_BASELINE_APPS6')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original-source', type=Path, required=True)
    parser.add_argument('--setup-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mode', choices=('copied-root', 'real-modules'), default='copied-root')
    parser.add_argument('--authorization', type=Path, required=True)
    args = parser.parse_args()
    auth = ordinary(args.authorization)
    need(not auth.exists() and auth.parent.is_dir(), 'fresh authorization output')
    value = emit(args.original_source, args.setup_source, args.output, args.mode)
    with auth.open('xb') as stream:
        stream.write(encoded(value))
