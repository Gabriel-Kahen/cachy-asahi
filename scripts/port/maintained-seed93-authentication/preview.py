"""Pinned read-only preparation CLI. Actual Source execution is unassigned."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

BASE = Path(__file__).absolute().parent
SOURCE_FILES = {'source/common.py','source/seed93.py','source/operations.py',
                'source/helper_policy.py','source/composition.py','preview.py'}


def read(path, maximum=32*1024**2):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in [path,*path.parents]):
        raise ValueError('SYMLINK_INPUT')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    original = None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size > maximum:
            raise ValueError('INPUT_NODE_MODE_SIZE')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum+1)
        if before != os.fstat(fd) or before != os.lstat(path) or len(raw) != before.st_size:
            raise ValueError('INPUT_DRIFT')
        return raw, {'bytes':len(raw),'mode':stat.S_IMODE(before.st_mode),
                     'sha256':hashlib.sha256(raw).hexdigest()}
    except BaseException as error:
        original = error
        raise
    finally:
        try:
            os.close(fd)
        except BaseException as error:
            if original is None:
                raise
            try:
                BaseException.add_note(original, 'SECONDARY_FD_CLOSE_FAILURE:' + type.__dict__['__name__'].__get__(type(error)))
            except BaseException:
                pass


def document(raw):
    def unique(rows):
        result = {}
        for key,value in rows:
            if key in result:
                raise ValueError('JSON_DUPLICATE_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('JSON_NONFINITE')))


def prepare(profile_path, expected_profile_sha256):
    profile_raw, descriptor = read(profile_path)
    if descriptor['sha256'] != expected_profile_sha256:
        raise ValueError('PROFILE_RAW_PIN')
    profile = document(profile_raw)
    manifest_raw, descriptor = read(BASE/'source-manifest.json')
    if descriptor['sha256'] != profile['source_manifest_sha256']:
        raise ValueError('SOURCE_MANIFEST_RAW_PIN')
    manifest = document(manifest_raw)
    if set(manifest) != {'schema','files'} or manifest['schema'] != 'seed93-source-manifest-v1' or set(manifest['files']) != SOURCE_FILES:
        raise ValueError('SOURCE_MANIFEST_SCHEMA')
    sources = {}
    for relative, expected in manifest['files'].items():
        raw, actual = read(BASE/relative)
        if actual != expected:
            raise ValueError('SOURCE_BYTE_MODE_PIN')
        sources[relative] = raw
    modules = {}
    for name,relative in [('common','source/common.py'),('helper_policy','source/helper_policy.py'),
                          ('seed93','source/seed93.py'),('composition','source/composition.py')]:
        if name in sys.modules:
            raise ValueError('PREEXISTING_SOURCE_MODULE')
        module = types.ModuleType(name)
        module.__file__ = str(BASE/relative)
        sys.modules[name] = module
        exec(compile(sources[relative], module.__file__, 'exec'), module.__dict__)
        modules[name] = module
    bundle = {role:read(BASE/item['filename'])[0] for role,item in modules['common'].FIXED_INPUT_ROLES.items()}
    bundle.update(profile=profile_raw, source_manifest=manifest_raw, contract=read(BASE/'contract.json')[0])
    bound = modules['common'].bind(profile_raw, bundle, manifest_raw, expected_profile_sha256)
    return {'preparation':modules['seed93'].preview(bound),
            'retained_composition':modules['composition'].compose(bundle)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, default=BASE/'profile.json')
    parser.add_argument('--profile-sha256', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.profile,args.profile_sha256),sort_keys=True,indent=2))
        return 0
    except (ValueError,OSError,KeyError,TypeError,RecursionError) as error:
        print(json.dumps({'status':'REFUSED_PREPARATION_ONLY','reason':type.__dict__['__name__'].__get__(type(error)),
                          'actual_authentication':'NOT_RUN','actor_grant':False},sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
