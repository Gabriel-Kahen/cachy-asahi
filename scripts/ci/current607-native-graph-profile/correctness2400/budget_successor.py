"""Separate correctness budget; the complete original 1800s profile still verifies."""
import base64, importlib.util, json, sys, tempfile
from pathlib import Path
import lifecycle_cost_successor as original

pin, enc, rows, need = original.pin, original.enc, original.rows, original.need

def verify(root, name, want):
    root = Path(root)
    raw = (root / name).read_bytes()
    need(pin(raw) == want and not sys.flags.optimize, 'whole correctness2400 source proof')
    p = json.loads(raw)
    before, actual = p['before'], rows(root)
    changed, added = set(p['before_bodies']), set(p['added'])
    need(len(before) == 566 and len(actual) == 568 and set(actual) == set(before) | added,
         'exact full568 source membership')
    need({n for n in before if actual[n] != before[n]} == changed,
         'only recorded source/budget/test derivations changed')
    need(all(actual[n] == row for n, row in p['helpers'].items()), 'whole budget helper')
    bodies = {n: base64.b64decode(p['before_bodies'][n], validate=True)
              if n in changed else (root / n).read_bytes() for n in before}
    need(all(pin(bodies[n]) == row for n, row in before.items()), 'whole original566 inverse')
    for n, edits in p['edits'].items():
        text = (root / n).read_text()
        for old, new in reversed(edits):
            need(text.count(new) == 1, 'one explicit correctness budget seam')
            text = text.replace(new, old, 1)
        need(text.encode() == bodies[n], 'complete original body outside budget seams')
    marker = '\n# BEGIN_CORRECTNESS2400_PROFILE\n'
    parts = (root / p['guard']).read_text().split(marker)
    footer = ('def verify():\n import budget_successor\n return budget_successor.verify(ROOT, '
              + repr(name) + ', ' + repr(want) + ')\n')
    need(len(parts) == 2 and parts[0].encode() == bodies[p['guard']] and parts[1] == footer,
         'mandatory complete original guard plus exact profile appendix')
    mf = json.loads((root / p['manifest']).read_bytes())
    need(mf['files'] == {n: row for n, row in actual.items()
                        if n not in {p['manifest'], *p['workflows']}}, 'whole new manifest')
    restored = dict(mf, files={n: row for n, row in mf['files'].items() if n not in added})
    for n in changed - {p['manifest'], *p['workflows']}:
        restored['files'][n] = before[n]
    need(enc(restored) == bodies[p['manifest']], 'whole original manifest inverse')
    for n in p['workflows']:
        need((root / n).read_bytes().replace(actual[p['manifest']]['sha256'].encode(),
             before[p['manifest']]['sha256'].encode()) == bodies[n], 'all outer workflow clocks held')
    pub = p['publication']
    need(pub == dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',
         source='1c5d0fa3ffd55f323225782958f8199eccb80ebc', ref='codex/current607-ancestry-cost-v1',
         files=566, git_joins=566, actual='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED'),
         'genuine full566 parent publication')
    need(p['source_authorization'] == before and p['git_authorization'] == dict(
         status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN', source=pub['source'], ref=pub['ref'], files=before),
         'whole genuine parent source/Git authority')
    saved, paths = dict(sys.modules), sys.path[:]
    try:
        with tempfile.TemporaryDirectory(prefix='current607-original1800-') as tmp:
            old = Path(tmp) / 'source'
            old.mkdir()
            for n, body in bodies.items():
                q = old / n
                q.parent.mkdir(parents=True, exist_ok=True)
                q.write_bytes(body)
            need(rows(old) == before, 'all566 original leaves before original full guard')
            for q in old.rglob('*.py'):
                sys.modules.pop(q.stem, None)
            sys.path.insert(0, str((old / p['guard']).parent))
            spec = importlib.util.spec_from_file_location('_full_original566_budget_parent', old / p['guard'])
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            fact = module.verify()
    finally:
        sys.path[:] = paths
        for n in set(sys.modules) - set(saved):
            sys.modules.pop(n, None)
        sys.modules.update(saved)
    need(fact['files'] == 566, 'entire original566 guard completed')
    return dict(fact, files=568, profile='NATIVE607_CORRECTNESS2400',
                original1800_fit='FAILED_NOT_RECLASSIFIED',
                bounds=dict(consumer=2400, owner=6600, transaction=90, fixture=100, cleanup=60),
                performance='NOT_CLAIMED', actual=None, hardware='NOT_RUN', release='NOT_ADMITTED')
