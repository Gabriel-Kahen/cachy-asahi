"""Fixed paths/pins and import-only reuse; no actors at import time."""
import functools
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
HELD_PINS = {
    'run': '07d0a0fb495c422dc392a28b516b63c6fd5cac617c7ede5e32f7e80b4464d8d1',
    'job': '8f3bef5193ec54cacb0f4165f2535baaefc700599c7955de227ac385c23deead',
    'container': 'b1af113aaadcc9ca828e501b963e666cdd2dc79f421cf59c7915f63a82f35542',
}
LOCK = 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
BANK = 'https://chadmed.au/bankstown'
TRI = 'https://chadmed.au/triforce'
FEATURE = 'http://lv2plug.in/ns/lv2core#inPlaceBroken'
URIS = (BANK, TRI)
PROFILES = {
    BANK: {'j413': {'bypass': 0, 'amt': 1.2, 'sat_second': 1.05, 'sat_third': 1.3,
                    'blend': 1, 'ceil': 220, 'floor': 140},
           'j415': {'bypass': 0, 'amt': 1.65, 'sat_second': 1.75, 'sat_third': 1.85,
                    'blend': 1, 'ceil': 200, 'floor': 20, 'final_hp': 200}},
    TRI: {'asahi-microphone': {'h_angle': 80, 'v_angle': 0, 'opt_freq': 1100, 't_win': 500,
                         'mic2_x': .02, 'mic2_y': 0, 'mic3_x': .01, 'mic3_y': .0173}},
}
BANK_FIXTURES = ('zero', 'bypass', 'amount-zero', 'configured', 'channel-exchange',
                 'sign-reversal', 'wet-amount-scaling')
TRI_FIXTURES = ('zero', 'common-mode-dc', 'common-mode-quarter-wave', 'unequal')
RATES = {BANK: (44100, 48000, 88200, 96000), TRI: (48000,)}
PUBLIC = {'result.json', 'runtime.json'}


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def load(name, path, pin=None):
    path = Path(path)
    need(path.is_file() and not path.is_symlink() and (pin is None or sha(path) == pin),
         'held-module-differs')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@functools.lru_cache(maxsize=None)
def held(name, directory=None):
    directory = Path(directory) if directory is not None else HERE.parent / 'asahi-lsp-offline'
    return load('rust_held_' + name, directory / (name + '.py'), HELD_PINS[name])


def inputs():
    path = HERE / 'inputs.json'
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 128 * 1024,
         'fixed-inputs-invalid')
    value = json.loads(path.read_text())
    need(value['schema_version'] == 1 and len(value['packages']) == 2 and
         [x['name'] for x in value['packages']] == ['bankstown', 'triforce-lv2'], 'fixed-inputs-invalid')
    return value


def grid():
    return {(uri, profile, rate, fixture) for uri in URIS for profile in PROFILES[uri]
            for rate in RATES[uri] for fixture in (BANK_FIXTURES if uri == BANK else TRI_FIXTURES)}
