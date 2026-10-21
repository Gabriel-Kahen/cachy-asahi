# SPDX-License-Identifier: MIT
"""Exact complete native-base cache workflow inverse and entire original source guard."""
import base64, hashlib, importlib.util, json, shutil, stat, sys, tempfile
from pathlib import Path

def need(ok, text):
    if not ok:
        raise ValueError(text)

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def enc(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def stable_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

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
            need(stable_identity(path.lstat()) == stable_identity(before) and len(raw) == before.st_size, 'whole stable source read')
            result[path.relative_to(root).as_posix()] = pin(raw)
    return result

def verify(root, proof_name, proof_pin):
    root = Path(root)
    raw = (root / proof_name).read_bytes()
    need(pin(raw) == proof_pin, 'hard-pinned complete native-base successor authority')
    proof = json.loads(raw)
    before, changed, added = proof['before'], set(proof['before_bodies']), set(proof['added'])
    actual = files(root)
    need(set(actual) == set(before) | added and not set(before) & added, 'complete source partition')
    need(len(changed) == 5 and len(added) == 2 and {n for n in before if actual[n] != before[n]} == changed,
         'exact five workflow/guard/manifest/test changes and two finite proof additions')
    bodies = {n: base64.b64decode(proof['before_bodies'][n], validate=True) if n in changed else (root/n).read_bytes() for n in before}
    need(all(pin(bodies[n]) == row for n,row in before.items()), 'entire original source reconstruction')
    auth, pub, git = (proof[k] for k in ('source_authorization', 'publication', 'git_authorization'))
    need(pub == dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE', source=proof['original_source'],
                    ref=proof['original_ref'], files=len(auth), git_joins=len(auth), actual='NOT_RUN',
                    hardware='NOT_RUN', release='NOT_ADMITTED') and len(auth) == len(before), 'genuine whole predecessor source publication')
    need(git == dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN', source=pub['source'], ref=pub['ref'], files=auth), 'whole original Git/source authority')
    need(proof['view'] in ('selected','default') and set(before) == set(auth), 'whole selected/default membership')
    need(before == auth if proof['view'] == 'selected' else all(before[n] == auth[n] for n in before if n not in proof['view_changes']), 'only recorded original default decisions differ')
    carrier = proof['carrier_context']
    carrier_auth, carrier_pub, carrier_git = (carrier[k] for k in ('authorization','publication','git_authorization'))
    need(carrier_pub == proof['carrier_publication'] and len(carrier_auth) == 501 and
         carrier_pub == dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE', source=carrier_pub['source'],
                             ref=carrier_pub['ref'], files=501, git_joins=501, actual='NOT_RUN',
                             hardware='NOT_RUN', release='NOT_ADMITTED') and
         carrier_git == dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN', source=carrier_pub['source'],
                             ref=carrier_pub['ref'], files=carrier_auth), 'complete original carrier501 publication/Git context')
    guard, helper, test, manifest, workflows = (proof[k] for k in ('guard', 'helper', 'test', 'manifest', 'workflows'))
    suffix = '\n# BEGIN_COMPLETE_NATIVE_BASE_SUCCESSOR\ndef verify():\n import native_base_successor\n return native_base_successor.verify(ROOT, '+repr(proof_name)+', '+repr(proof_pin)+')\n'
    need((root/guard).read_bytes() == bodies[guard] + suffix.encode(), 'entire original guard prefix and exact new guard slot')
    need(added == {helper, proof_name} and actual[helper] == proof['helper_pin'], 'exact tested helper only')
    text = (root/test).read_text()
    for old,new,count in reversed(proof['test_edits']):
        need(text.count(new) == count, 'exact honest source-count control inverse')
        text = text.replace(new,old)
    need(text.encode() == bodies[test], 'every original control outside honest source count held')
    value = json.loads((root/manifest).read_bytes())
    need(value['files'] == {n:p for n,p in actual.items() if n not in {manifest,*workflows}}, 'complete current source manifest')
    restored = dict(value, files={n:p for n,p in value['files'].items() if n not in added})
    for n in changed - {manifest,*workflows}:
        restored['files'][n] = before[n]
    need(enc(restored) == bodies[manifest], 'entire original source manifest inverse')
    for name in workflows:
        text = (root/name).read_text().replace(actual[manifest]['sha256'], before[manifest]['sha256'])
        for old,new in reversed(proof['workflow_edits']):
            need(text.count(new) == 1, 'exact full native-base workflow inverse seam')
            text = text.replace(new,old,1)
        need(text.encode() == bodies[name], 'whole original workflow outside exact cache hook/stamp')
    saved, paths = dict(sys.modules), sys.path[:]
    try:
        with tempfile.TemporaryDirectory(prefix='native-base-before-') as temporary:
            prior = Path(temporary)/'source';prior.mkdir()
            for name,body in bodies.items():
                path=prior/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)
            need(files(prior) == before, 'complete original source before original guard')
            for name in {p.stem for p in prior.rglob('*.py')}:
                sys.modules.pop(name,None)
            sys.path.insert(0,str((prior/guard).parent))
            spec=importlib.util.spec_from_file_location('_whole_native_base_predecessor_guard',prior/guard)
            module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
            original=module.verify()
    finally:
        sys.path[:]=paths
        for name in set(sys.modules)-set(saved):sys.modules.pop(name,None)
        sys.modules.update(saved)
    return dict(original,status='SOURCE_ONLY_COMPLETE496_CACHE_HOOK_NOT_ACCEPTED',files=len(actual),
                native_base_original_source=pub['source'],native_base_original_files=len(before),
                native_base_changed=5,native_base_added=2,native_base_held=len(before)-5,
                actual_source=None,actual_ref=None,actual_run=None,hardware='NOT_RUN',release='NOT_ADMITTED')
