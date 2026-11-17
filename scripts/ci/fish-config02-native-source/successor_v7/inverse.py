# SPDX-License-Identifier: MIT
"""Inert exact Source57 inverse shared by constructor and emitted validator."""
SOURCE57 = dict(source='198db17eb3a16714f2530334c24be8512feaa03f',
                tree='4e06d52d001a504916fab131104b39014fd2338c',files=57,bytes=1066965,
                map=dict(bytes=12161,sha256='f98da639c80ae35423f7c33a66df12bd5f70ea9fc15ecbaabb93c6569f3a6150'))


def inverse_source57(bodies):
    # need/decode/pin/git_tree/PREFIX are the already held validator primitives.
    proof=decode(bodies[PREFIX+'source57-inverse.json'])
    need(set(proof)=={'kind','origin','before_utf8','after','added','actual'} and
         proof['kind']=='FISH_COMPLETE_SOURCE57_INVERSE_V7' and proof['origin']==SOURCE57 and proof['actual'] is None,
         'exact Source57 inverse domain')
    before=proof['before_utf8']
    need(type(before)is dict and all(type(v)is str for v in before.values()) and
         'source-map.json'in before and pin(before['source-map.json'].encode())==SOURCE57['map'],
         'whole immutable Source57 root map')
    manifest=decode(before['source-map.json'].encode())
    original=dict(manifest['files'],**{'source-map.json':dict(SOURCE57['map'],mode=0o644)})
    need(len(original)==57 and manifest['kind']=='FISH02_PAYLOAD_RETIREMENT_SOURCE_V6' and
         all(v is None for v in manifest['actual'].values()),'original complete57 schema')
    changed={n for n,row in original.items()if n not in bodies or dict(pin(bodies[n]),mode=0o644)!=row}
    added=set(bodies)-set(original)
    need(set(before)==changed and type(proof['added'])is list and len(set(proof['added']))==len(proof['added']) and
         set(proof['added'])==added,'complete57 changed/new inverse namespace')
    excluded={'source-map.json',PREFIX+'owner-program.json',PREFIX+'source57-inverse.json'}
    after={n:dict(pin(raw),mode=0o644)for n,raw in bodies.items()if n not in excluded and(n in added or n in changed)}
    need(proof['after']==after,'whole nonrecursive successor inverse bindings')
    restored={n:before[n].encode()if n in before else bodies[n]for n in original}
    for name,row in original.items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts and
             dict(pin(restored[name]),mode=0o644)==row,'whole restored Source57 body/mode')
    need(sum(map(len,restored.values()))==SOURCE57['bytes']and git_tree(restored)==SOURCE57['tree'],
         'complete original57 bytes and physical Git tree')
    return restored
