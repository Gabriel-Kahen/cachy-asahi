# SPDX-License-Identifier: MIT
"""Exact finite runtime inverse followed by the entire original source guard."""
import base64, hashlib, importlib.util, json, shutil, stat, sys, tempfile
from pathlib import Path

def need(ok, text):
    if not ok:
        raise ValueError(text)

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def enc(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def files(root):
    need(not sys.flags.optimize and not any(p.is_symlink() for p in (root, *root.parents)), 'ordinary source ancestry and unoptimized guards')
    result = {}
    for path in sorted(root.rglob('*')):
        if path.relative_to(root).parts[0] == '.git':
            continue
        before = path.lstat()
        need(stat.S_ISREG(before.st_mode) or stat.S_ISDIR(before.st_mode), 'ordinary source directories and leaves')
        if stat.S_ISREG(before.st_mode):
            need(before.st_nlink == 1 and 0 <= before.st_size <= 16*1024**2, 'bounded single-link source leaf')
            raw = path.read_bytes()
            need(path.lstat() == before and len(raw) == before.st_size, 'whole stable source read')
            result[path.relative_to(root).as_posix()] = pin(raw)
    return result

def verify(root, proof_name, proof_pin):
    root = Path(root)
    raw = (root / proof_name).read_bytes()
    need(pin(raw) == proof_pin, 'hard-pinned complete runtime successor authority')
    proof = json.loads(raw)
    before = proof['before']
    actual = files(root)
    changed = set(proof['before_bodies'])
    added = set(proof['added'])
    need(set(actual) == set(before) | added and set(before) & added == set(), 'complete source held and added partition')
    need({n for n in before if actual[n] != before[n]} == changed, 'exact six changed source leaves')
    need(len(changed) == 6 and len(added) == 2 and all(actual[n] == before[n] for n in set(before) - changed), 'whole held source context')
    bodies = {n: base64.b64decode(proof['before_bodies'][n], validate=True) if n in changed else (root/n).read_bytes() for n in before}
    need(all(pin(bodies[n]) == row for n, row in before.items()), 'entire original source reconstruction')
    pub, git, auth = (proof[k] for k in ('publication', 'git_authorization', 'source_authorization'))
    need(pub['status'] == 'COMMITTED_EXACT_CLOSED_TRIAL_SOURCE' and pub['files'] == pub['git_joins'] == len(auth) == len(before) and pub['actual'] == pub['hardware'] == 'NOT_RUN' and pub['release'] == 'NOT_ADMITTED', 'genuine complete original source-only publication')
    need(git == dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN', source=pub['source'], ref=pub['ref'], files=auth), 'whole original Git/source authority')
    need(proof['view'] in ('selected', 'default') and set(before) == set(auth), 'entire original selected/default membership')
    need(before == auth if proof['view'] == 'selected' else all(before[n] == auth[n] for n in before if n not in proof['view_changes']), 'only original recorded default decision differs')
    runtime = proof['runtime']
    text = (root/runtime).read_text()
    for old, new in reversed(proof['edits']):
        need(text.count(new) == 1, 'exact finite runtime inverse seam')
        text = text.replace(new, old, 1)
    need(text.encode() == bodies[runtime], 'whole original runtime outside narrow corrections')
    test = proof['test']
    text = (root/test).read_text()
    for old, new in reversed(proof['test_edits']):
        need(text.count(new) == 1, 'exact source-control update inverse seam')
        text = text.replace(new, old, 1)
    need(text.encode() == bodies[test], 'entire original test outside current guard entrypoint/count')
    guard = proof['guard']
    marker = '\n# BEGIN_EXACT_RUNTIME_SUCCESSOR\n'
    text = (root/guard).read_text()
    need(text.count(marker) == 1 and text.split(marker)[0].encode() == bodies[guard], 'complete original guard prefix byteheld')
    helper = proof['helper']
    need(actual[helper] == proof['helper_pin'] and added == {helper, proof_name}, 'exact tested helper only')
    manifest = proof['manifest']
    value = json.loads((root/manifest).read_bytes())
    workflows = proof['workflows']
    need(value['files'] == {n: p for n, p in actual.items() if n not in {manifest, *workflows}}, 'complete current manifest')
    restored = dict(value, files={n: p for n, p in value['files'].items() if n not in added})
    for n in changed - {manifest, *workflows}:
        restored['files'][n] = before[n]
    need(enc(restored) == bodies[manifest], 'entire original manifest inverse')
    for name in workflows:
        need((root/name).read_bytes().replace(actual[manifest]['sha256'].encode(), before[manifest]['sha256'].encode()) == bodies[name], 'entire original workflow outside source stamp')
    saved, paths = dict(sys.modules), sys.path[:]
    try:
        with tempfile.TemporaryDirectory(prefix='runtime-before-') as temporary:
            prior = Path(temporary)/'source'
            prior.mkdir()
            for name, body in bodies.items():
                path = prior/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
            need(files(prior) == before, 'whole original source before guard')
            directory = (prior/guard).parent
            stems = {p.stem for p in prior.rglob('*.py')}
            for name in stems:
                sys.modules.pop(name, None)
            sys.path.insert(0, str(directory))
            spec = importlib.util.spec_from_file_location('_entire_runtime_predecessor_guard', prior/guard)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            original = module.verify()
    finally:
        sys.path[:] = paths
        for name in set(sys.modules)-set(saved):
            sys.modules.pop(name, None)
        sys.modules.update(saved)
    return dict(original, status='SOURCE_ONLY_EXACT_RUNTIME_SUCCESSOR_NOT_ACCEPTED', files=len(actual), original_source=pub['source'], original_files=len(before), changed=6, added=2, held=len(before)-6, actual_source=None, actual_ref=None, actual_run=None, hardware='NOT_RUN', release='NOT_ADMITTED')
