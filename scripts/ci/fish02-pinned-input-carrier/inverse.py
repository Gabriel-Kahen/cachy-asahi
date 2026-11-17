# SPDX-License-Identifier: MIT
"""Inert complete frozen Source62 inverse; appended to the admitted validator."""
SOURCE62=dict(files=62,bytes=1220725,tree='3c8a238723718c6c6534f6adc5cf020e2275ecc4',map=dict(bytes=13251,sha256='399d833c468d1d932d1e689cc634ca0be50cd0b32dd674fce3e9b0ce17dd66b3'))


def inverse_source62(bodies):
    proof=decode(bodies[PREFIX+'source-ro-binding.json'])
    need(set(proof)=={'kind','origin','before_utf8','after','added','actual'} and proof['kind']=='FISH02_COMPLETE_SOURCE62_CARRIER_INVERSE_V1'and proof['origin']==SOURCE62 and proof['actual']is None,'complete original62 inverse declaration')
    before=proof['before_utf8'];need(type(before)is dict and all(type(r)is str for r in before.values())and 'source-map.json'in before,'whole62 original bodies')
    raw=before['source-map.json'].encode();need(pin(raw)==SOURCE62['map'],'whole immutable62 map')
    old=decode(raw);rows=dict(old['files'],**{'source-map.json':dict(SOURCE62['map'],mode=0o644)})
    need(len(rows)==62 and old['kind']=='FISH02_EXPLICIT_SOURCE_READONLY_SOURCE_V8'and all(v is None for v in old['actual'].values()),'complete original62 schema')
    changed={n for n,r in rows.items()if n not in bodies or dict(pin(bodies[n]),mode=0o644)!=r};added=set(bodies)-set(rows)
    need(set(before)==changed and set(proof['added'])==added and len(proof['added'])==len(added),'complete original62 changed/new namespace')
    excluded={'source-map.json',PREFIX+'owner-program.json',PREFIX+'source-ro-binding.json'}
    need(proof['after']=={n:dict(pin(raw),mode=0o644)for n,raw in bodies.items()if n not in excluded and(n in changed or n in added)},'whole finite after-bindings')
    restored={n:before[n].encode()if n in before else bodies[n]for n in rows}
    need(all(dict(pin(restored[n]),mode=0o644)==r for n,r in rows.items())and sum(map(len,restored.values()))==SOURCE62['bytes']and git_tree(restored)==SOURCE62['tree'],'whole complete original62 body/mode/tree inverse')
    return restored
