"""Literal graph inputs and hash-held helpers; importing starts no actors."""
import functools
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = next((p for p in HERE.parents if (p / 'scripts/ci/asahi-lsp-offline/run.py').is_file()), HERE)
HELD_PINS = {
    'run': '07d0a0fb495c422dc392a28b516b63c6fd5cac617c7ede5e32f7e80b4464d8d1',
    'job': '8f3bef5193ec54cacb0f4165f2535baaefc700599c7955de227ac385c23deead',
    'container': 'b1af113aaadcc9ca828e501b963e666cdd2dc79f421cf59c7915f63a82f35542',
}
RUST_RUN = '94143717f44a9a2311bfd2ca0d910badb9b80c6b7e03146742b3db9c1a35d625'
LOCK = 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
PUBLIC = {'result.json', 'runtime.json'}
CONTROLS = ('malformed', 'duplicate', 'trailing', 'missingURI', 'invalidport',
            'allFIRabsent', '48konlyabsent', 'unknowncontrol')


def need(value, code):
    if not value: raise ValueError(code)


def sha(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def load(name, path, pin=None):
    path = Path(path)
    need(path.is_file() and not path.is_symlink() and (pin is None or sha(path) == pin), 'held-module-differs')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


@functools.lru_cache(maxsize=None)
def held(name, directory=None):
    return load('graph_held_' + name, (Path(directory) if directory is not None else
                ROOT / 'scripts/ci/asahi-lsp-offline') / (name + '.py'), HELD_PINS[name])


def inputs():
    path = HERE / 'inputs.json'
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 256 * 1024, 'fixed-inputs-invalid')
    value = json.loads(path.read_text())
    need(value['schema_version'] == 1 and [x['name'] for x in value['packages']] ==
         ['asahi-audio', 'bankstown', 'triforce-lv2', 'lsp-plugins-lv2'], 'fixed-inputs-invalid')
    return value


def graphs():
    value = json.loads((HERE / 'graphs.json').read_text())
    need(value['schema_version'] == 1 and len(value['cases']) == 4 and len(value['firs']) == 16, 'fixed-graphs-invalid')
    return value


def cases():
    return {row['id']: row for row in graphs()['cases']}
