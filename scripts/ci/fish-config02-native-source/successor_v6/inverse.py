# SPDX-License-Identifier: MIT
"""Inert exact Source53 inverse shared by constructor and emitted validator."""
SOURCE53 = dict(source='7ac1c330d2a2c19d4f353cf6f271730f20aa2771',
                tree='4f10cc1cdb48d946b6a0af8bd4051b54308c34f5',files=53,bytes=967199,
                map=dict(bytes=11296,sha256='ef50c6185a228cefcc4b241863221eb3bf9d44959b4b312b422887bdf6dc3db5'))


def inverse_source53(bodies):
    # need/decode/pin/git_tree/PREFIX are the already held validator primitives.
    proof=decode(bodies[PREFIX+'source53-inverse.json'])
    need(set(proof)=={'kind','origin','before_utf8','after','added','actual'} and
         proof['kind']=='FISH_COMPLETE_SOURCE53_INVERSE_V6' and proof['origin']==SOURCE53 and proof['actual'] is None,
         'exact Source53 inverse domain')
    before=proof['before_utf8']
    need(type(before)is dict and all(type(v)is str for v in before.values()) and
         'source-map.json'in before and pin(before['source-map.json'].encode())==SOURCE53['map'],
         'whole immutable Source53 root map')
    manifest=decode(before['source-map.json'].encode())
    original=dict(manifest['files'],**{'source-map.json':dict(SOURCE53['map'],mode=0o644)})
    need(len(original)==53 and manifest['kind']=='FISH02_FINITE_DOCKER_VA_SOURCE_V5' and
         all(v is None for v in manifest['actual'].values()),'original complete53 schema')
    changed={n for n,row in original.items()if n not in bodies or dict(pin(bodies[n]),mode=0o644)!=row}
    added=set(bodies)-set(original)
    need(set(before)==changed and type(proof['added'])is list and len(set(proof['added']))==len(proof['added']) and
         set(proof['added'])==added,'complete53 changed/new inverse namespace')
    excluded={'source-map.json',PREFIX+'owner-program.json',PREFIX+'source53-inverse.json'}
    after={n:dict(pin(raw),mode=0o644)for n,raw in bodies.items()if n not in excluded and(n in added or n in changed)}
    need(proof['after']==after,'whole nonrecursive successor inverse bindings')
    restored={n:before[n].encode()if n in before else bodies[n]for n in original}
    for name,row in original.items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts and
             dict(pin(restored[name]),mode=0o644)==row,'whole restored Source53 body/mode')
    need(sum(map(len,restored.values()))==SOURCE53['bytes']and git_tree(restored)==SOURCE53['tree'],
         'complete original53 bytes and physical Git tree')
    return restored
