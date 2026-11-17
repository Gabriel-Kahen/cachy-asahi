# SPDX-License-Identifier: MIT
"""Inert complete frozen Fish carrier62 inverse."""
SOURCE_CARRIER62=dict(files=62,bytes=1431202,tree='9db85398af8cd52b43adcf5925568b7bcf54cbc7',map=dict(bytes=13276,sha256='44a5c63ae729a9eb0fb83280659e987fc29dee0b105e5125ab12975a6a1d2507'))


def inverse_carrier_source62(bodies):
    proof=decode(bodies[PREFIX+'source-ro-binding.json'])
    need(set(proof)=={'kind','origin','before_utf8','after','added','actual'}and proof['kind']=='FISH02_COMPLETE_CARRIER62_BOUND512_HOLD_INVERSE_V2'and proof['origin']==SOURCE_CARRIER62 and proof['actual']is None,'complete carrier62 inverse declaration')
    before=proof['before_utf8'];raw=before['source-map.json'].encode();need(pin(raw)==SOURCE_CARRIER62['map'],'whole fixed carrier62 map')
    value=decode(raw);rows=dict(value['files'],**{'source-map.json':dict(SOURCE_CARRIER62['map'],mode=0o644)})
    need(len(rows)==62 and value['kind']=='FISH02_EXACT_PINNED_INPUT_CARRIER_SOURCE_V1'and all(v is None for v in value['actual'].values()),'complete frozen carrier62 frame')
    changed={n for n,r in rows.items()if n not in bodies or dict(pin(bodies[n]),mode=0o644)!=r};added=set(bodies)-set(rows)
    need(set(before)==changed and set(proof['added'])==added and len(proof['added'])==len(added),'whole carrier62 inverse namespace')
    excluded={'source-map.json',PREFIX+'owner-program.json',PREFIX+'source-ro-binding.json'}
    need(proof['after']=={n:dict(pin(raw),mode=0o644)for n,raw in bodies.items()if n not in excluded and(n in changed or n in added)},'complete literal after-bindings')
    restored={n:before[n].encode()if n in before else bodies[n]for n in rows}
    need(all(dict(pin(restored[n]),mode=0o644)==r for n,r in rows.items())and sum(map(len,restored.values()))==SOURCE_CARRIER62['bytes']and git_tree(restored)==SOURCE_CARRIER62['tree'],'whole frozen carrier62 body/mode/tree inverse')
    return restored
