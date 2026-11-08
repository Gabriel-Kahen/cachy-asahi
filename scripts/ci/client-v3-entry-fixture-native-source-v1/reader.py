# SPDX-License-Identifier: MIT
"""Root-only exact third fixture override; outer actor/network/write fence is mandatory."""
import ast
import importlib.util
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BASE=HERE.parent/'client-v3-makepkg-native-source-v1'

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

ADDITION="""def _trusted_producer_body(path):
    if path.name == 'test_entry_failures.py':
        raw = (_ENTRY_FIXTURE_HERE / 'producer' / path.name).read_bytes()
        C.need(C.pin(raw) == _ENTRY_FIXTURE_PIN, 'trusted entry fixture differs')
        return raw
    if path.name in _PRODUCER_OVERRIDES:
        raw = (_FACTORY_HERE / 'producer' / path.name).read_bytes()
        C.need(C.pin(raw) == _PRODUCER_OVERRIDES[path.name], 'trusted two-file producer override differs')
        return raw
    return path.read_bytes()

"""
def derive(raw,root=ROOT):
    # Pure trusted Reader text derivation; never invokes a Reader.
    F=load('_entry_fixture_factory',HERE/'prepare.py');F.trusted(root)
    M=load('_held_makepkg_reader',root/'scripts/ci/client-v3-makepkg-native-source-v1/reader.py');raw=M.derive(raw)
    F.need(raw.decode().count(M.ADDITION)==1,'one exact trusted helper seam')
    text=raw.decode().replace(M.ADDITION,ADDITION,1);F.need(text.replace(ADDITION,M.ADDITION,1).encode()==raw,'full third override inverse');ast.parse(text)
    return text.encode()

def main():
    # Root must install its outer actor/network/write fence BEFORE import.
    F=load('_entry_fixture_factory',HERE/'prepare.py');p=F.trusted(ROOT)
    raw=derive(F.ordinary(ROOT/'scripts/ci/client-v3-native-intake-v1/reader.py'))
    old=load('_held_makepkg_factory',BASE/'prepare.py').profile();overrides=dict(old['producer_overrides'])
    namespace=dict(__name__='__main__',__file__=str(ROOT/'scripts/ci/client-v3-native-intake-v1/reader.py'),_FACTORY_HERE=BASE,_PRODUCER_OVERRIDES=overrides,_ENTRY_FIXTURE_HERE=HERE,_ENTRY_FIXTURE_PIN=p['fixture_after'])
    exec(compile(raw,'<ROOT-qualified-client-entry-fixture-matching-reader-v1>','exec'),namespace)

if __name__=='__main__':main()
