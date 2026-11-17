# SPDX-License-Identifier: MIT
"""Inert exact Source50 inverse shared by constructor and emitted validator."""
SOURCE50 = dict(source='c5db06eb66e9df7bf33f5be1695e28fb012be953',
                tree='dff997f10bd4e917709f2b76d4c32f07ed379a03',files=50,bytes=892625,
                map=dict(bytes=10661,sha256='93bd88bf41da2a067cc7f04ebaa70374963bfda350cb821a7e6cf9278235c021'))


def inverse_source50(bodies):
    # need/decode/pin/git_tree/PREFIX are the already held validator primitives.
    proof=decode(bodies[PREFIX+'source50-inverse.json'])
    need(set(proof)=={'kind','origin','before_utf8','after','added','actual'} and
         proof['kind']=='FISH_COMPLETE_SOURCE50_INVERSE_V5' and proof['origin']==SOURCE50 and proof['actual'] is None,
         'exact Source50 inverse domain')
    before=proof['before_utf8']
    need(type(before)is dict and all(type(v)is str for v in before.values()) and
         'source-map.json'in before and pin(before['source-map.json'].encode())==SOURCE50['map'],
         'whole immutable Source50 root map')
    manifest=decode(before['source-map.json'].encode())
    original=dict(manifest['files'],**{'source-map.json':dict(SOURCE50['map'],mode=0o644)})
    need(len(original)==50 and manifest['kind']=='FISH02_NO_HOST_APT_SOURCE_V4' and
         all(v is None for v in manifest['actual'].values()),'original complete50 schema')
    changed={n for n,row in original.items()if n not in bodies or dict(pin(bodies[n]),mode=0o644)!=row}
    added=set(bodies)-set(original)
    need(set(before)==changed and type(proof['added'])is list and len(set(proof['added']))==len(proof['added']) and
         set(proof['added'])==added,'complete50 changed/new inverse namespace')
    excluded={'source-map.json',PREFIX+'owner-program.json',PREFIX+'source50-inverse.json'}
    after={n:dict(pin(raw),mode=0o644)for n,raw in bodies.items()if n not in excluded and(n in added or n in changed)}
    need(proof['after']==after,'whole nonrecursive successor inverse bindings')
    restored={n:before[n].encode()if n in before else bodies[n]for n in original}
    for name,row in original.items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts and
             dict(pin(restored[name]),mode=0o644)==row,'whole restored Source50 body/mode')
    need(sum(map(len,restored.values()))==SOURCE50['bytes']and git_tree(restored)==SOURCE50['tree'],
         'complete original50 bytes and physical Git tree')
    return restored
