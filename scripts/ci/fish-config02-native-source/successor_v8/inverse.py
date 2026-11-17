# SPDX-License-Identifier: MIT
"""Inert exact Source60 inverse shared by constructor and emitted validator."""
SOURCE60 = dict(source='1b4186b8e069abd39725a0b054e59999e8f40f0f',
                tree='8e7d42d9a25eeef1bd80389d198fedf84a5902ac',files=60,bytes=1130628,
                map=dict(bytes=12826,sha256='c604399d2472fb5dd0a5e97a299b1017a697426ebd47454c5a43c72ce05892d5'))


def inverse_source60(bodies):
    # need/decode/pin/git_tree/PREFIX are the already held validator primitives.
    proof=decode(bodies[PREFIX+'source60-inverse.json'])
    need(set(proof)=={'kind','origin','before_utf8','after','added','actual'} and
         proof['kind']=='FISH_COMPLETE_SOURCE60_INVERSE_V8' and proof['origin']==SOURCE60 and proof['actual'] is None,
         'exact Source60 inverse domain')
    before=proof['before_utf8']
    need(type(before)is dict and all(type(v)is str for v in before.values()) and
         'source-map.json'in before and pin(before['source-map.json'].encode())==SOURCE60['map'],
         'whole immutable Source60 root map')
    manifest=decode(before['source-map.json'].encode())
    original=dict(manifest['files'],**{'source-map.json':dict(SOURCE60['map'],mode=0o644)})
    need(len(original)==60 and manifest['kind']=='FISH02_FIXED_FILESYSTEM_DIAGNOSTIC_SOURCE_V7' and
         all(v is None for v in manifest['actual'].values()),'original complete60 schema')
    changed={n for n,row in original.items()if n not in bodies or dict(pin(bodies[n]),mode=0o644)!=row}
    added=set(bodies)-set(original)
    need(set(before)==changed and type(proof['added'])is list and len(set(proof['added']))==len(proof['added']) and
         set(proof['added'])==added,'complete60 changed/new inverse namespace')
    excluded={'source-map.json',PREFIX+'owner-program.json',PREFIX+'source60-inverse.json'}
    after={n:dict(pin(raw),mode=0o644)for n,raw in bodies.items()if n not in excluded and(n in added or n in changed)}
    need(proof['after']==after,'whole nonrecursive successor inverse bindings')
    restored={n:before[n].encode()if n in before else bodies[n]for n in original}
    for name,row in original.items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts and
             dict(pin(restored[name]),mode=0o644)==row,'whole restored Source60 body/mode')
    need(sum(map(len,restored.values()))==SOURCE60['bytes']and git_tree(restored)==SOURCE60['tree'],
         'complete original60 bytes and physical Git tree')
    return restored
