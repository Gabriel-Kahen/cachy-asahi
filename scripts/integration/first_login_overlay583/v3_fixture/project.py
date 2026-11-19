#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt in to the executable isolation fixture on an already pinned v3 worker."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

HERE = Path(__file__).resolve().parent
ADDON = 'scripts/integration/first_login_overlay583/'
BEFORE = 'OVERLAY583_NATIVE_FIRST_LOGIN_V3_ROOT_OPERANDS_ONLY_R1'
AFTER = 'OVERLAY583_NATIVE_FIRST_LOGIN_V3_ROOT_OPERANDS_ONLY_R2'
FIXED = {ADDON + leaf for leaf in ('isolation.py', 'guest.py', 'target.py', 'stage.py')}
LIMIT = 128 * 1024


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read(path):
    require(path.is_absolute() and path.resolve(strict=True) == path, 'ordinary absolute source path required')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= LIMIT,
                'bounded ordinary source file required')
        raw = stream.read(before.st_size + 1)
        require(len(raw) == before.st_size, 'source size changed during read')
    return raw


def digest(value):
    if re.fullmatch('[a-f0-9]{64}', value) is None:
        raise argparse.ArgumentTypeError('whole SHA-256 required')
    return value


def once(code, before, after):
    require(code.count(before) == 1, 'exact v3 fixture source seam required: ' + before.splitlines()[0])
    return code.replace(before, after, 1)


def target_source(code):
    code = once(code, 'isolation_home=WORK/isolation.TEST_HOME', 'isolation_home=isolation.fixture_home(nonce)')
    return once(code, "        result=getattr(error,'first_login_result',dict(status='FAIL',error=type(error).__name__))",
                "        result=getattr(error,'first_login_result',dict(status='FAIL',error=type(error).__name__))\n"
                "        if isinstance(error,isolation.IsolationRefusal):\n"
                "            result['isolation_boundary']=error.args[0]")


def guest_source(code):
    code = once(code, 'import re\n', 'import re\nimport shutil\n')
    code = once(code, '        isolated_home=target_work/isolation.TEST_HOME', '''        selected_home=isolation.fixture_home(nonce)
        isolated_home=target/selected_home.relative_to('/')
        fixture=isolated_home.parent
        need(fixture.parent==fixture.parent.resolve() and fixture.parent.is_dir(),
             'exact ordinary private guest var/tmp parent')
        fixture.mkdir(mode=0o755)
        stack.callback(shutil.rmtree,fixture)
        fixture.chmod(0o755)''')
    code = once(code, "        isolation.verify(TARGET_WORK/isolation.TEST_HOME,seed['initial'],journey['isolation'],isolation_after_removal)",
                "        isolation.verify(selected_home,seed['initial'],journey['isolation'],isolation_after_removal)")
    return once(code, '    return dict(status=PASS, before=initial, installed=installed,',
                "    need(not os.path.lexists(fixture),'owned executable fixture retired with the guest')\n"
                '    return dict(status=PASS, before=initial, installed=installed, isolation_fixture_retired=True,')


def reader_source(code):
    code = once(code, BEFORE, AFTER)
    code = once(code, 'CLOSED_LOCAL_OVERLAY583_NATIVE_FIRST_LOGIN_V3_R1_', 'CLOSED_LOCAL_OVERLAY583_NATIVE_FIRST_LOGIN_V3_R2_')
    code = once(code, "    isolation.verify(Path(journey['home']).parent/isolation.TEST_HOME,seed['initial'],",
                "    need(addon['isolation_fixture_retired'] is True,'owned executable fixture must be retired')\n"
                "    isolation.verify(isolation.fixture_home(nonce),seed['initial'],")
    return once(code, '                  isolation_after_removal=addon["isolation_after_removal"])',
                '                  isolation_after_removal=addon["isolation_after_removal"],isolation_fixture_retired=True)')


def project(sources, reader):
    require(FIXED <= set(sources), 'complete v3 worker fixture leaves required')
    result = dict(sources)
    isolation = (HERE / 'isolation.py').read_bytes()
    old = pin(sources[ADDON + 'isolation.py'])['sha256']
    require(pin(isolation)['sha256'] != old, 'unprojected isolation fixture required')
    result[ADDON + 'isolation.py'] = isolation
    result[ADDON + 'target.py'] = target_source(sources[ADDON + 'target.py'].decode()).encode()
    result[ADDON + 'guest.py'] = guest_source(sources[ADDON + 'guest.py'].decode()).encode()
    result[ADDON + 'stage.py'] = once(sources[ADDON + 'stage.py'].decode(), old, pin(isolation)['sha256']).encode()
    reader = reader_source(reader.decode()).encode()
    for name, raw in {**{name: result[name] for name in FIXED}, 'readback.py': reader}.items():
        require(len(raw) <= LIMIT, 'projected source exceeds worker bound')
        compile(raw, name, 'exec')
    return result, reader


def stage(source, handoff, handoff_sha, reader, reader_sha, output):
    raw = read(handoff)
    require(pin(raw)['sha256'] == handoff_sha, 'exact external v3 handoff pin required')
    selection = json.loads(raw)
    require(selection['kind'] == BEFORE, 'explicit prior v3 worker required')
    expected = selection['source']
    require(type(expected) is dict and FIXED <= set(expected) and len(expected) <= 64,
            'bounded whole v3 worker map required')
    require(source.is_absolute() and source.is_dir() and source.resolve() == source and
            output.is_absolute() and output.resolve() == output and not os.path.lexists(output) and
            not output.is_relative_to(source), 'ordinary source tree and fresh separate output required')
    actual = {p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_symlink() or not p.is_dir()}
    require(actual == set(expected), 'exact source file roster required')
    bodies = {}
    for name, descriptor in expected.items():
        path = PurePosixPath(name)
        require(path.as_posix() == name and not path.is_absolute() and '..' not in path.parts,
                'contained source member required')
        data = read(source / name)
        require(pin(data) == descriptor, 'exact v3 worker source changed: ' + name)
        bodies[name] = data
    review = read(reader)
    require(pin(review)['sha256'] == reader_sha, 'exact independent v3 reader pin required')
    projected, readback = project(bodies, review)
    result = dict(status='V3_EXECUTABLE_FIXTURE_SOURCE_ONLY', handoff_kind=AFTER, input_handoff=pin(raw),
                  input_reader=pin(review), source={name: pin(data) for name, data in projected.items()},
                  readback=pin(readback), changed=sorted(FIXED | {'readback.py'}), actual_installation=None)
    output.mkdir(mode=0o700)
    for name, data in {**{'source/' + name: data for name, data in projected.items()}, 'readback.py': readback}.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
    with (output / 'projection.json').open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'handoff', 'reader', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('handoff-sha256', 'reader-sha256'):
        parser.add_argument('--' + name, required=True, type=digest)
    args = parser.parse_args()
    try:
        result = stage(args.source, args.handoff, args.handoff_sha256, args.reader, args.reader_sha256, args.output)
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, f'v3 fixture source refused: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
