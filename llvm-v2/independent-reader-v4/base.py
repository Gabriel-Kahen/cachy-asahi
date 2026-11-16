# SPDX-License-Identifier: MIT
"""Pinned passive Reader closure and proved DATA projections; no role entry."""
import ast
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import stat
from types import FunctionType, SimpleNamespace

HERE = Path(__file__).resolve().parent
V3, V2 = HERE.parent / 'v3', HERE.parent / 'v2'
PINS = {
    'v3/reader.py': '1edb14485c8df4b880750e0d783fe4f732e88ed9d17119ef491fb7cfe65cd8c6',
    'v3/base.py': '6d6d6c00d686ea97e6cd9702b61c545d630418be1f18ac3fe9b1ff7da82cd610',
    'v3/pins.json': '3adab3af82327142762aa4d366993aa9695e9d25a012f0b72c07cb611f926439',
    'v2/reader.py': 'e3fed71e01be989b5c84cd0e33124ca096e452eda380f4840b45786cb385335c',
    'v2/pins.json': 'c9a1013cac557e992ab2ad824821ad868c87d73c2b9da60e860d05a70742a328',
}


def raw(name):
    path = HERE.parent / name
    if name not in PINS or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('ordinary pinned passive Reader path')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= 128 * 1024:
            raise ValueError('bounded single-link passive Reader input')
        body = stream.read(128 * 1024 + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if len(body) != before.st_size or identity(before) != identity(after) or identity(after) != identity(path.lstat()):
        raise ValueError('passive Reader input changed while read')
    if hashlib.sha256(body).hexdigest() != PINS[name]:
        raise ValueError('whole frozen passive Reader pin: ' + name)
    return body


def compiled_module(name, path, body, additions=None):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    if additions:
        module.__dict__.update(additions)
    exec(compile(body, str(path), 'exec'), module.__dict__)
    return module


def projected(original, seams, label):
    result = original
    for before, after in seams:
        if before == after or result.count(before) != 1 or after in result:
            raise ValueError('one exact ' + label + ' seam')
        result = result.replace(before, after)
    inverse = result
    for before, after in reversed(seams):
        if inverse.count(after) != 1:
            raise ValueError('unambiguous ' + label + ' inverse')
        inverse = inverse.replace(after, before)
    if inverse != original:
        raise ValueError('whole ' + label + ' byte inverse')
    return result, dict(before_sha256=hashlib.sha256(original).hexdigest(),
                        after_sha256=hashlib.sha256(result).hexdigest(), seams=len(seams),
                        inverse='EXACT_FUNCTION_BYTES' if label != 'trusted base wiring' else 'EXACT_MODULE_BYTES')


def function_bytes(body, name):
    nodes = [n for n in ast.parse(body).body if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(nodes) != 1:
        raise ValueError('one frozen passive function: ' + name)
    return ast.get_source_segment(body.decode(), nodes[0]).encode()


# Every compiled byte comes from pinned trusted Reader code, never a Source input.
_closure = {name: raw(name) for name in PINS}
_base3 = compiled_module('llvm_v4_held_v3_base', V3 / 'base.py', _closure['v3/base.py'])
frozen = _base3.v
_loader = b"spec=importlib.util.spec_from_file_location('llvm_v3_base',HERE/'base.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B);v=B.v"
_reader3, _wiring_proof = projected(_closure['v3/reader.py'], [(_loader, b'B=__held_base;v=B.v')], 'trusted base wiring')
v3 = compiled_module('llvm_v4_held_v3_reader', V3 / 'reader.py', _reader3, {'__held_base': _base3})
old_pins = frozen.decode(_closure['v3/pins.json'])
_expected_pins253 = frozen.decode(_closure['v3/pins.json'])

# A distinct complete v2 namespace is necessary: replay's global initializer lookup
# must resolve to this one updated predicate while all other functions stay intact.
v = compiled_module('llvm_v4_cloned_v2_reader', V2 / 'reader.py', _closure['v2/reader.py'])
_init_before = function_bytes(_closure['v2/reader.py'], 'initializer')
_init_after, initializer_proof = projected(_init_before,
    [(b"h['CapAdd'] == ['CHOWN']", b"h['CapAdd'] in (['CHOWN'], ['CAP_CHOWN'])")], 'initializer predicate')
initializer_proof.update(module_sha256=PINS['v2/reader.py'], changed_function='initializer',
                         cloned_namespace=True, actual_Source_ref_run_job_map_changes=False)
exec(compile(_init_after, '<frozen-v2-initializer-capability-spelling>', 'exec'), v.__dict__)
if v.replay.__globals__ is not v.__dict__ or v.volume_initialization.__globals__ is not v.__dict__:
    raise ValueError('cloned replay must use cloned initializer globals')
for _name, _value in vars(frozen).items():
    if callable(_value) and hasattr(_value, '__code__') and _name != 'initializer':
        _clone = getattr(v, _name)
        if _clone.__code__ != _value.__code__:
            raise ValueError('unmodified frozen v2 function changed: ' + _name)

_historical_before = function_bytes(_closure['v3/reader.py'], 'inverse251')
_historical_after, _historical_proof = projected(_historical_before, [
    (b"v.load(source/'successor-v3.json')", b"v.decode(source['successor-v3.json'][0])"),
    (b"v.read(source/'hosted/common.py')", b"source['hosted/common.py'][0]"),
    (b'v.read(source/n,64*MIB)', b'source[n][0]'),
    (b"v.read(source/'previous-v2/source-map.json')", b"source['previous-v2/source-map.json'][0]"),
], 'historical253 Source read')
_historical248_original, _historical248_proof = _base3.historical_successor()
_historical248 = FunctionType(_historical248_original.__code__, v.__dict__,
                             _historical248_original.__name__, _historical248_original.__defaults__,
                             _historical248_original.__closure__)
_historical_bridge = SimpleNamespace(old_pins=_base3.old_pins,
    historical_successor=lambda: (_historical248, dict(_historical248_proof)))
_historical_namespace = dict(vars(v3), v=v, B=_historical_bridge)
exec(compile(_historical_after, '<frozen-v3-in-memory253-inverse>', 'exec'), _historical_namespace)
_historical_inverse = _historical_namespace['inverse251']
projection_proof = dict(closure_sha256=PINS, trusted_base_wiring=_wiring_proof,
                        historical253=_historical_proof, historical251=_historical248_proof,
                        initializer=initializer_proof, actual_Source_ref_run_job_map_changes=False)


def _tuple_namespace(rows, pins):
    """Closed historical253 tuples, independently joined to the frozen whole pins."""
    v.need(type(rows) is dict and len(rows) == pins['source_files'], 'exact historical253 tuple count')
    found = {}
    for name, row in rows.items():
        v.safe_name(name)
        v.need(type(row) is tuple and len(row) == 2 and type(row[0]) is bytes and
               type(row[1]) is int and row[1] in (0o644, 0o755), 'historical253 ordinary bytes/mode')
        body, mode = row
        found[name] = dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest(), mode=mode, blob=v.git_oid('blob', body))
    v.need(sum(r['bytes'] for r in found.values()) == pins['source_bytes'], 'exact historical253 byte total')
    raw_map = rows['source-map.json'][0]
    v.need(rows['source-map.json'][1] == 0o644 and hashlib.sha256(raw_map).hexdigest() == pins['source_map_sha256'],
           'exact historical253 map')
    manifest = v.decode(raw_map)
    describe = lambda r: {k: r[k] for k in ('bytes', 'sha256', 'mode')}
    v.need(manifest['actual'] == dict.fromkeys(('source', 'ref', 'run', 'job', 'reader', 'authority', 'approval', 'artifact', 'image')) and
           manifest['files'] == {n: describe(r) for n, r in found.items() if n != 'source-map.json'}, 'closed historical253 map/NULL membership')
    def tree(prefix=''):
        children = {}
        for name, row in found.items():
            if name.startswith(prefix):
                part = name[len(prefix):].split('/', 1)[0]
                children[part] = row if prefix + part == name else None
        body = bytearray()
        for name, row in sorted(children.items(), key=lambda item: (item[0] + ('/' if item[1] is None else '')).encode()):
            mode, oid = ('40000', tree(prefix + name + '/')) if row is None else ('100755' if row['mode'] == 0o755 else '100644', row['blob'])
            body.extend(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid))
        return v.git_oid('tree', body)
    v.need(tree() == pins['source_tree'], 'independent historical253 Git tree')
    return found


def historical253(rows253, parent251, pins253, ancestor248):
    """Return251 descriptor rows; exact v3 guards also verify the explicit248 chain."""
    v.need(pins253 == _expected_pins253, 'whole frozen253 pins; no actual selectors projected')
    found = _tuple_namespace(rows253, pins253)
    selected = dict(pins253, _ancestor_path=str(ancestor248))
    return _historical_inverse(rows253, selected, found, Path(parent251))


def initializer_projection_proof():
    return dict(initializer_proof)
