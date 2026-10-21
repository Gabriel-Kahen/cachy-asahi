"""Emit the exact Setup606 source from two complete immutable source inputs."""
import argparse, hashlib, json, shutil, stat
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE = {'bytes': 229139, 'sha256': '6142a4f48c3d23eb700ef0d39b9e8aea8b656d9103038553ae0864e518f08bdb'}  # Filled by the reviewed profile builder.
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

def emit(original, setup, output):
    raw = read(HERE / 'profile.json')
    need(pin(raw) == PROFILE, 'whole fixed Setup606 source profile')
    p = json.loads(raw)
    original, setup, output = map(ordinary, (original, setup, output))
    need(files(original) == p['original']['files'] and files(setup) == p['setup']['files'],
         'whole immutable353 and240 inputs before output')
    payload = {n: read(HERE / 'payload' / n) for n in p['payload']}
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
    for n, body in payload.items():
        dest = output / n
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(body)
    need(files(output) == p['output'], 'whole exact608 source output')
    return dict(status='SOURCE_ONLY_EXACT608_SETUP6_CURRENT606_NATIVE_UNQUALIFIED',
                files=p['output'], actual=None, hardware='NOT_RUN', release='NOT_ADMITTED',
                full606_real_shell='NOT_RUN_DEVICE_FREE_COPY', Apps7='NOT_RUN_BASELINE_APPS6')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original-source', type=Path, required=True)
    parser.add_argument('--setup-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--authorization', type=Path, required=True)
    args = parser.parse_args()
    auth = ordinary(args.authorization)
    need(not auth.exists() and auth.parent.is_dir(), 'fresh authorization output')
    value = emit(args.original_source, args.setup_source, args.output)
    with auth.open('xb') as stream:
        stream.write(encoded(value))
