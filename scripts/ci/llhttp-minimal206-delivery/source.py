# SPDX-License-Identifier: MIT
"""Bind the exact authenticated Root adoption to the fixed512 minimal206 Source."""

import hashlib
import importlib.util
import os
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


PREPARER = HERE.parent / 'llhttp-minimal-builder-command512/prepare.py'
if hashlib.sha256(PREPARER.read_bytes()).hexdigest() != '0f687972c90cd8d89b3a650a5ae25b1f7135d1202b2cd83447b35843ad88926f':
    raise ValueError('exact command512 predecessor constructor')
P = module(PREPARER, 'minimal206_fixed512')
E = module(HERE / 'public_evidence.py', 'minimal206_public_evidence')
need, pin, encode, decode = P.need, P.pin, P.encode, P.decode
NB, NO = P.NB, P.NO
REPOSITORY = 'Gabriel-Kahen/cachy-asahi'
BRANCH = 'codex/llhttp-minimal206-authenticated-source-20261117-r2'
REF = 'refs/heads/' + BRANCH
PRIVATE_REF = 'refs/heads/codex/llhttp-minimal206-authenticated-source-20261117-r1'
PRIVATE_TREE = '0ce20196636943c4fb9d30b5d2907dcbcf6f2bf8'
WORKFLOW = '.github/workflows/native-arm-llhttp-minimal-builder-source.yml'
AUTH = dict(bytes=735, sha256='34eea4d446b4e595b1f6e08455d4b1090a7cd57e3e70bebdf8a73f7bad35ebc7')
TRANSCRIPT = dict(bytes=219316, sha256='731c31033d7a53a86b2831ecf857fe2a72ff5e49640b453e37db61e0c64e794f')
PARENT_MAP = dict(bytes=20332, sha256='53ae0f0beed7f222cf34ee25eee168128a1767087e32d08c71a61d48a98f3144')
PARENT_TREE = '8a8f0baa349399a5546883acd67f43d4fe0f15f1'


def physical(root, *, checkout=False):
    root = P.P.ordinary(root)
    bodies = {}
    directories = set()
    need(root.is_dir(), 'ordinary Source directory')
    for directory, children, leaves in os.walk(root):
        relative = Path(directory).relative_to(root)
        if checkout and relative == Path('.') and '.git' in children:
            need(not (root / '.git').is_symlink(), 'ordinary local Git metadata')
            children.remove('.git')
        for child in children:
            path = Path(directory) / child
            need(stat.S_ISDIR(path.lstat().st_mode), 'ordinary Source directory')
            directories.add(path.relative_to(root).as_posix())
            need(len(directories) < 416, 'bounded Source directories')
        for leaf in leaves:
            path = Path(directory) / leaf
            need(len(bodies) < 96 and stat.S_IMODE(path.lstat().st_mode) == 0o644, 'finite mode0644 Source leaves')
            bodies[path.relative_to(root).as_posix()] = P.read(path)
    expected = {parent.as_posix() for name in bodies for parent in Path(name).parents if parent != Path('.')}
    need(directories == expected and len(bodies) == 96 and sum(map(len, bodies.values())) < 2 * 1024**2,
         'complete 96-file Source under 2MiB')
    return bodies


def parent_bodies(root):
    bodies = physical(root)
    need(pin(bodies['source-map.json']) == PARENT_MAP and P.tree(bodies) == PARENT_TREE,
         'whole command512 Source map and tree')
    P.inverse(bodies)
    return bodies


def adoption(path, transcript):
    raw, proof = P.read(path), P.read(transcript)
    need(pin(raw) == AUTH and pin(proof) == TRANSCRIPT, 'whole exact Root r2 adoption and 207-signature transcript')
    value = decode(raw)
    need(encode(value) == raw and len(decode(proof)) == 207, 'exact canonical adoption and complete transcript')
    return value


def replace(raw, before, after):
    text = raw.decode()
    need(text.count(before) == 1 and after not in text, 'one exact authenticated delivery seam')
    return text.replace(before, after).encode()


def rows(bodies):
    return {name: dict(pin(raw), mode=0o644) for name, raw in sorted(bodies.items())}


def authenticated_source(parent, *, public=True):
    bodies = dict(parent)
    ref = REF if public else PRIVATE_REF
    contract = NB + 'contract.py'
    before = "    return value\n\ndef admitted("
    after = (
        "    need(pin((json.dumps(value, indent=2, sort_keys=True) + '\\n').encode())\n"
        f"         == {AUTH!r}, 'exact Root-adopted minimal206 input authentication r2')\n"
        + before
    )
    bodies[contract] = replace(parent[contract], before, after)

    owner = NO + 'data.py'
    raw = replace(
        parent[owner],
        'def admission(root, map_sha, admission_raw, runtime_raw, admission_sha, runtime_sha, env, now):',
        'def source_documents(root, map_sha, admission_raw, runtime_raw, admission_sha, runtime_sha, source_sha, source_ref, now):',
    )
    raw = replace(raw, "value['source'] == env.get('GITHUB_SHA')", "value['source'] == source_sha")
    raw = replace(raw, "value['ref'] == env.get('GITHUB_REF') and value['ref'].startswith('refs/heads/codex/')",
                  f"value['ref'] == source_ref == {ref!r}")
    start = raw.index(b"    need(a['nonce'] == r['nonce'] and")
    end = raw.index(b"    need(r['external_supervision']", start)
    raw = raw[:start] + b"    need(a['nonce'] == r['nonce'], 'same Root admission/runtime nonce')\n" + raw[end:]
    actor_check = f"""def admission(root, map_sha, admission_raw, runtime_raw, admission_sha, runtime_sha, env, now):
    need(env.get('GITHUB_REPOSITORY') == {REPOSITORY!r}
         and env.get('GITHUB_WORKFLOW_REF') == {f'{REPOSITORY}/{WORKFLOW}@{ref}'!r}
         and env.get('GITHUB_JOB') == 'pair' and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
         and env.get('GITHUB_RUN_ATTEMPT') == '1' and re.fullmatch('[1-9][0-9]{{1,19}}', env.get('GITHUB_RUN_ID', '')),
         'exact minimal206 hosted workflow/job and first dispatch attempt')
    return source_documents(root, map_sha, admission_raw, runtime_raw, admission_sha, runtime_sha,
                            env.get('GITHUB_SHA'), env.get('GITHUB_REF'), now)


"""
    bodies[owner] = replace(raw, 'def projected_entry(body):', actor_check + 'def projected_entry(body):')
    bodies[WORKFLOW] = replace(
        parent[WORKFLOW],
        "github.repository == 'Gabriel-Kahen/cachy-asahi' && github.event.repository.private == false",
        f"github.repository == '{REPOSITORY}' && github.event.repository.private == false && github.ref == '{ref}'",
    )
    bodies[WORKFLOW] = replace(bodies[WORKFLOW], 'GITHUB_RUN_ID,GITHUB_JOB,ImageOS',
                              'GITHUB_RUN_ID,GITHUB_JOB,GITHUB_WORKFLOW_REF,ImageOS')

    if public:
        E.project(bodies, NB, NO, P.MARKER, pin, encode, decode)

    # Rebind inside-out. The parent constructor and all other source bodies stay byte-exact.
    base_map = NB + 'source-map.json'
    program, outer_map = bodies.pop(NO + 'owner-program.json'), bodies.pop('source-map.json')
    previous_base = decode(bodies.pop(base_map))
    held = {name.removeprefix('held-source/'): raw for name, raw in bodies.items() if name.startswith('held-source/')}
    bodies[base_map] = encode(dict(previous_base, files=rows(held)))
    base_pin = pin(bodies[base_map])
    bodies[NO + 'base-binding.json'] = encode(dict(map=base_pin, files=len(held) + 1,
                                                  bytes=sum(map(len, held.values())) + base_pin['bytes']))
    owners = {name: raw for name, raw in bodies.items() if not name.startswith('held-source/')}
    bodies[NO + 'owner-program.json'] = encode(dict(decode(program), base_source_map_sha256=base_pin['sha256'],
                                                  files=rows(owners)))
    bodies['source-map.json'] = encode(dict(decode(outer_map), files=rows(bodies)))
    need(set(bodies) == set(parent) and sum(map(len, bodies.values())) < 2 * 1024**2, 'same96 Source namespace and cap')
    if public:
        need(not E.private_findings(bodies), 'public Source and all nested evidence are clear of private paths and markers')
    else:
        need(P.tree(bodies) == PRIVATE_TREE, 'whole original private authenticated Source')
    return bodies


def source_tuple(bodies):
    return dict(tree=P.tree(bodies), files=len(bodies), bytes=sum(map(len, bodies.values())),
                source_map=pin(bodies['source-map.json']), workflow=pin(bodies[WORKFLOW]),
                policy=pin(bodies[NO + 'policy.json']), program=pin(bodies[NO + 'owner-program.json']),
                builder_input_authentication=AUTH)
