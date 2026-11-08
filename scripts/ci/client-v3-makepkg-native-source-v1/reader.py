# SPDX-License-Identifier: MIT
"""Root-only strict matching reader; only trusted maintained code is executed."""
import ast
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
BASE=HERE.parent/'client-v3-native-intake-v1'
PRODUCER=HERE.parent/'client-v3-native'
OLD="self.policy.get('candidate_source') == '2dbe7fe5623fae9ed5940a26385400958c3ffb42'"
NEW="self.policy.get('candidate_source') == '438acd83fa3bcb79abe29a007ae9e8d0f784d03f'"
BODY="self.read(LANE + '/' + path.name) == path.read_bytes()"
REPLACEMENT="self.read(LANE + '/' + path.name) == _trusted_producer_body(path)"
ADDITION='''def _trusted_producer_body(path):
    # Exactly two qualified maintained overrides; Source/capsule code stays DATA.
    if path.name in _PRODUCER_OVERRIDES:
        raw = (_FACTORY_HERE / 'producer' / path.name).read_bytes()
        C.need(C.pin(raw) == _PRODUCER_OVERRIDES[path.name], 'trusted two-file producer override differs')
        return raw
    return path.read_bytes()

'''

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def need(ok,why):
    if not ok:raise ValueError(why)

def derive(raw):
    """Pure exact text transformation; no Reader/Source imports or execution."""
    profile=json.loads((HERE/'profile.json').read_bytes());need(pin(raw)==profile['base_reader']['reader.py'],'exact frozen Source82 reader body')
    text=raw.decode();need(text.count(OLD)==text.count(BODY)==text.count('class SourceData:\n')==1,'exact bounded matching-reader seams')
    out=text.replace(OLD,NEW,1).replace(BODY,REPLACEMENT,1).replace('class SourceData:\n',ADDITION+'class SourceData:\n',1)
    inverse=out.replace(NEW,OLD,1).replace(REPLACEMENT,BODY,1).replace(ADDITION,'',1)
    need(inverse.encode()==raw,'full old-reader inverse');ast.parse(out)
    return out.encode()

def main():
    # Root installs its outer actor/network/write fence BEFORE importing this file.
    import importlib.util
    spec=importlib.util.spec_from_file_location('_trusted_makepkg_factory',HERE/'prepare.py');factory=importlib.util.module_from_spec(spec);spec.loader.exec_module(factory)
    profile=factory.profile();need(set(profile['producer_overrides'])=={'prepare.py','test_source.py'},'exact two trusted overrides')
    for n,want in profile['base_reader'].items():need(pin(factory.ordinary(BASE/n))==want,'all ten frozen trusted reader inputs '+n)
    for n,want in profile['base_producer'].items():need(pin(factory.ordinary(PRODUCER/n))==want,'all twenty-two frozen producer inputs '+n)
    for n,want in profile['producer_overrides'].items():need(pin(factory.ordinary(HERE/'producer'/n))==want,'explicit producer override '+n)
    raw=derive(factory.ordinary(BASE/'reader.py'))
    namespace=dict(__name__='__main__',__file__=str(BASE/'reader.py'),_FACTORY_HERE=HERE,_PRODUCER_OVERRIDES=profile['producer_overrides'])
    exec(compile(raw,'<ROOT-qualified-client-makepkg-matching-reader-v1>','exec'),namespace)

if __name__=='__main__':main()
