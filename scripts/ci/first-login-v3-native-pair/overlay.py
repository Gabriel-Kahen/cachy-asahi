#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Join the closed thin First Login role and the exact immutable Fish r12 role."""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent
THIN = 'scripts/ci/first-login-v3-native-pair/'
FULL = 'scripts/ci/fish-config02-native-source/successor_v2/'
HELD = 'held-source32/scripts/ci/fish-config02-native-source/'
WORKFLOW = '.github/workflows/native-arm-first-login-v3-native-pair.yml'
RECIPE = 'packages/tools/cachy-asahi-first-login-v3/'
MAP = 'source-map.json'
MAX = 2 * 1024**2
R12 = {'commit': '19dea1cca35659ad7ab307dfea09c30a77362640',
       'tree': 'de61a2e7351a09d1dcf0471d50c80e3a1a6ee479',
       'map_sha256': '14a3f9d1f12f224bf43a71a7bb4ef9ba3bfe03b5918b25aabc33ce1fdb71a3b2',
       'bytes': 2093900}
NEW_REF = 'refs/heads/codex/first-login-v3-native-source-20261118-r1'


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


P = module(HERE / 'pair.py', 'first_login_pair')


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def row(raw):
    return {'bytes': len(raw), 'sha256': P.digest(raw), 'mode': 0o644}


def files(root):
    seen = set()
    for current, dirs, leaves in os.walk(root):
        current = Path(current)
        if current == root and '.git' in dirs:
            dirs.remove('.git')
        if current == root and '.git' in leaves:
            leaves.remove('.git')
        for name in dirs:
            P.need(not (current / name).is_symlink(), 'ordinary Source directory')
        for name in leaves:
            path = current / name
            P.need(stat.S_IMODE(path.lstat().st_mode) == 0o644, 'exact Source mode 0644')
            seen.add(path.relative_to(root).as_posix())
        P.need(len(seen) <= 160 and len(dirs) <= 24, 'bounded Source namespace')
    return seen


def verify(root, sha, kind):
    P.need(root.is_absolute() and root == root.resolve() and re.fullmatch('[0-9a-f]{64}', sha),
           'exact absolute Source root and map SHA')
    raw = P.read(root / MAP, 64 * 1024)
    frame = json.loads(raw)
    P.need(P.digest(raw) == sha and set(frame) == {'kind', 'roles', 'files'}
           and frame['kind'] == kind and frame['roles']['fish_r12'] == R12,
           'externally pinned Source map and exact r12 role')
    rows = frame['files']
    names = files(root)
    P.need(names == set(rows) | {MAP} and sum(value['bytes'] for value in rows.values()) + len(raw) < MAX,
           'whole exact Source namespace and 2 MiB budget')
    bodies = {name: P.read(root / name, MAX) for name in rows}
    P.need(all(row(body) == rows[name] for name, body in bodies.items()), 'whole Source body and mode pins')
    if kind == 'FIRST_LOGIN_V3_PROJECTED_RUNTIME_V1':
        program_name = FULL + 'owner-program.json'
        program = json.loads(bodies[program_name])
        P.need(program['files'] == {name: value for name, value in rows.items()
               if name != program_name and not name.startswith(HELD)}, 'complete projected owner-program join')
    return frame, bodies


def write(root, kind, roles, bodies):
    P.need(root.is_absolute() and root == root.resolve() and not root.exists(), 'fresh Source root required')
    raw = encode({'kind': kind, 'roles': roles, 'files': {name: row(body) for name, body in bodies.items()}})
    P.need(len(raw) + sum(map(len, bodies.values())) < MAX, 'whole 2 MiB Source guard')
    root.mkdir(mode=0o755)
    for name, content in {**bodies, MAP: raw}.items():
        path = root / name
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(content)
        path.chmod(0o644)
    sha = P.digest(raw)
    verify(root, sha, kind)
    return {'map_sha256': sha, 'files': len(bodies) + 1, 'bytes': len(raw) + sum(map(len, bodies.values()))}


def thin(root, output):
    bodies = {name: P.read(root / name, 128 * 1024) for name in (
        WORKFLOW, THIN+'overlay.py', THIN+'pair.py', THIN+'bootstrap.py', THIN+'inputs.json')}
    recipe = {name: P.read(root / RECIPE / name, 64 * 1024) for name in P.PINS['recipe']}
    P.review_recipe(recipe)
    bodies.update({RECIPE + name: body for name, body in recipe.items()})
    return write(output, 'FIRST_LOGIN_V3_THIN_PUBLIC_SOURCE_V1', {'fish_r12': R12}, bodies)


def verified_parent(parent):
    raw = P.read(parent / MAP, 64 * 1024)
    P.need(P.digest(raw) == R12['map_sha256'], 'exact external Fish r12 map')
    manifest = json.loads(raw)
    P.need(files(parent) == set(manifest['files']) | {MAP}, 'closed original r12 Source namespace')
    bodies = {name: P.read(parent / name, MAX) for name in manifest['files']}
    P.need(all(row(body) == manifest['files'][name] for name, body in bodies.items())
           and len(raw) + sum(map(len, bodies.values())) == R12['bytes'] < MAX,
           'exact mode, body and complete original r12 budget')
    data = module(parent / FULL / 'data.py', 'genuine_original_r12')
    data.source(parent, R12['map_sha256'])
    P.need(data.git_tree({**bodies, MAP: raw}) == R12['tree'], 'exact original parent Git tree')
    return bodies


def replace(body, before, after):
    P.need(body.count(before) == 1 and after not in body, 'unique reviewed projection anchor')
    result = body.replace(before, after, 1)
    P.need(result.replace(after, before, 1) == body, 'complete reversible projection')
    return result


def selected_setup(encoded):
    P.need(type(encoded) is str and len(encoded) == 45708, 'exact finite Setup8 operand encoding')
    raw = base64.b64decode(encoded, validate=True)
    bodies = {}
    for role, name in (('archive', P.SETUP), ('signature', P.SETUP + '.sig'), ('certificate', 'public.gpg')):
        pin = P.PINS['setup8'][role]
        body, raw = raw[:pin['bytes']], raw[pin['bytes']:]
        P.need({'bytes': len(body), 'sha256': P.digest(body)} == pin, 'exact Setup8 ' + role)
        bodies[THIN + 'dependency/' + name] = body
    P.need(not raw, 'exact Setup8 packet exhaustion')
    return bodies


def runtime_material(confirmed, thin_bodies, setup, supplemental_pins=None):
    # Historical inverses stay in the verified external role. They are not opened by the runtime.
    briefs = {'source-ro-binding.json', 'libffi-recovery-inverse.json',
              'carrier-admission-inverse.json', 'base-read-delta.json'}
    files = {name: body for name, body in confirmed.items()
             if not name.startswith('.github/') and not (
                 name.startswith(FULL) and ('-inverse.' in name or name.rsplit('/', 1)[-1] in briefs))}
    files.update({name: body for name, body in thin_bodies.items() if name != WORKFLOW})
    files.update(setup)
    files[THIN+'expected342.lock'] = P.builder_lock(confirmed[FULL+'expected341.lock'])
    files[THIN+'reviewed-inputs.json'] = encode(P.PINS['recipe'])
    base_tools = ('scripts/build/build_v2.py', 'scripts/build/source_materials.py',
                  'scripts/build/container-entry-v2.sh', 'scripts/checks/package_checks.py',
                  'scripts/maintenance/source_cache.py', 'scripts/release/source_delivery.py')
    prefix = HELD + 'runtime/'
    tool_root = THIN + 'runtime/'
    for name in base_tools:
        files[tool_root+name] = confirmed[prefix+name]
    for name in P.FISH_TOOL_PINS:
        rel = 'scripts/build/' + name
        files[tool_root+rel] = P.project_tool(name, confirmed[prefix+rel])

    data_name = FULL + 'data.py'
    data = files[data_name]
    begin, end = data.index(b'def source(root, expected):'), data.index(b'def admission(')
    data = data[:begin] + b'''def source(root, expected):
    import importlib.util
    spec = importlib.util.spec_from_file_location('first_login_closed_runtime', Path(root)/'scripts/ci/first-login-v3-native-pair/overlay.py')
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    return runtime.verify(Path(root), expected, 'FIRST_LOGIN_V3_PROJECTED_RUNTIME_V1')[0]


''' + data[end:]
    files[data_name] = replace(data,
        b"    policy=decode(read(root/PREFIX/'policy.json'))\n    need(policy.get('managed_containerd')==MANAGED_CONTAINERD,",
        b"    need(a['ref'] == 'refs/heads/codex/first-login-v3-native-source-20261118-r1' and\n"
        b"         a.get('operation') == r.get('operation') == 'FIRST_LOGIN_V3_PACKAGE_PAIR', 'fixed First Login operation/ref')\n"
        b"    runtime_source = source(root,map_sha)\n"
        b"    need(r.get('thin_map_sha256') == runtime_source['roles']['first_login_map_sha256'], 'exact admitted thin role')\n"
        b"    policy=decode(read(root/PREFIX/'policy.json'))\n    need(policy.get('managed_containerd')==MANAGED_CONTAINERD,")

    context = FULL + 'host_context.py'
    files[context] = replace(files[context],
        b"refs/heads/codex/fish02-no-host-apt-v4-source-[A-Za-z0-9._-]{1,80}",
        NEW_REF.encode())
    payload = FULL + 'payload.py'
    files[payload] = replace(files[payload],
        b"    exec(compile(I.project_entry(Q.project_entry(N.project_entry(projected))),str(entry_path),'exec'),namespace)",
        b"    lane=D.module_first_login(root)\n"
        b"    namespace['FIRST_LOGIN_PAIR']=lane\n"
        b"    projected=I.project_entry(Q.project_entry(N.project_entry(projected)))\n"
        b"    exec(compile(lane.project_entry(projected),str(entry_path),'exec'),namespace)")
    files[data_name] += b'''

def module_first_login(root):
    import importlib.util
    spec = importlib.util.spec_from_file_location('first_login_owned_lane', Path(root)/'scripts/ci/first-login-v3-native-pair/overlay.py')
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded
'''
    export_name, policy_name = FULL+'public_evidence.py', FULL+'policy.json'
    renames = ((b'cachy-asahi-fish-config-0.1.0-2-any', (P.FIRST_LOGIN+'-any').encode()),
               (b'cachy-asahi-fish-config-0.1.0-2-aarch64-check.log', P.CHECK_LOG.encode()))
    export, policy = files[export_name], files[policy_name]
    for before, after in renames:
        export = replace(export, before, after)
        P.need(policy.count(before) >= 2, 'exact retained package allowlist rewrite')
        policy = policy.replace(before, after)
    export = replace(export, b"else PACKAGE+'-'+phase+'.log'", b"else CHECK_LOG.removesuffix('check.log')+phase+'.log'")
    for phase in ('prepare', 'pkgver', 'build', 'package'):
        before = (P.FIRST_LOGIN+'-any-'+phase+'.log').encode()
        after = (P.FIRST_LOGIN+'-aarch64-'+phase+'.log').encode()
        P.need(policy.count(before) == 2 and after not in policy, 'exact retained host-named phase log')
        policy = policy.replace(before, after)
    files[export_name], files[policy_name] = export, policy

    for name in ('hosted_owner.py', 'public_evidence.py', 'payload.py', 'retain.py'):
        rel = FULL + name
        files[rel] = files[rel].replace(b'PASS_CURRENT_FISH02_NATIVE_PAIR',
                                        b'PASS_CURRENT_FIRST_LOGIN_V3_NATIVE_PAIR')
        files[rel] = files[rel].replace(b'cachy-fish02-controller-', b'cachy-first-login-v3-controller-')
    program = FULL + 'owner-program.json'
    old_program = json.loads(confirmed[program])
    program_rows = {name: row(raw) for name, raw in files.items() if name != program and not name.startswith(HELD)}
    program_rows.update(supplemental_pins or {})
    files[program] = encode({'schema': 1, 'base_source_map_sha256': old_program['base_source_map_sha256'],
                             'files': program_rows})
    return files


def project_entry(body):
    edits = (
        (b"        image=native.build",
         b"        FIRST_LOGIN_PAIR.bind_bootstrap(native, HERE)\n        image=native.build"),
        (b"        expected_inventory=FISH_INVENTORY.inventory(inputs)",
         b"        FISH_INVENTORY.inventory(inputs)\n        expected_inventory=FIRST_LOGIN_PAIR.HERE/'expected342.lock'"),
        (b"        cache_handoff.retire_context()",
         b"        cache_handoff.retire_context()\n        FIRST_LOGIN_PAIR.retire_setup(output/'bootstrap/context/setup8')"),
        (b"        builds,compare=FISH_INVENTORY.plans(C,HERE,output,image,expected_inventory)",
         b"        builds,compare=FIRST_LOGIN_PAIR.plans(C,HERE,output,image,expected_inventory)"),
        (b"        finisher=FISH_INVENTORY.finisher(HERE,expected_inventory);pair=finisher.finish(output/'build-1',output/'build-2',output/'comparison.json',image);",
         b"        pair=FIRST_LOGIN_PAIR.P.finish(output/'build-1',output/'build-2',output/'comparison.json',image,expected_inventory);"),
    )
    for old, new in edits:
        body = replace(body, old, new)
    return body.replace(b'PASS_CURRENT_FISH02_NATIVE_PAIR', b'PASS_CURRENT_FIRST_LOGIN_V3_NATIVE_PAIR')


def bind_bootstrap(native, held):
    bootstrap = module(HERE/'bootstrap.py', 'first_login_signed_dependency')
    return bootstrap.bind(native, P.read(held/'runtime/scripts/ci/native_arm.py', 64*1024),
                          HERE/'dependency', HERE/'dependency/public.gpg', P)


def retire_setup(target):
    expected = {P.SETUP: 'archive', P.SETUP + '.sig': 'signature', 'public.gpg': 'certificate'}
    P.need(target == target.resolve() and {path.name for path in target.iterdir()} == set(expected),
           'exact owned Setup8 Docker context before retirement')
    for name, role in expected.items():
        body = P.read(target / name, P.PINS['setup8'][role]['bytes'])
        P.need(row(body) == {**P.PINS['setup8'][role], 'mode': 0o644}, 'same Setup8 context bytes before retirement')
    for name in expected:
        (target / name).unlink()
    target.rmdir()


def plans(contract, held, output, image, inventory):
    builds, compare = contract.plans(held, output, image)
    for args in builds:
        P.need(args[3].endswith('/build_fish02.py') and args[4] == str(held/'recipe'), 'exact inherited owned build plan')
        args[3:5] = [str(HERE/'runtime/scripts/build/build_fish02.py'), str(HERE.parents[2]/RECIPE)]
        for flag, path in (('--expected-packages', inventory), ('--reviewed-inputs', HERE/'reviewed-inputs.json')):
            args[args.index(flag)+1] = str(path)
    P.need(compare[3].endswith('/compare_fish_xz.py'), 'exact inherited strict comparison plan')
    compare[3] = str(HERE/'runtime/scripts/build/compare_fish_xz.py')
    return builds, compare


def joined_source(parent, overlay, thin_sha):
    _, thin_bodies = verify(overlay, thin_sha, 'FIRST_LOGIN_V3_THIN_PUBLIC_SOURCE_V1')
    P.need(set(thin_bodies) == {WORKFLOW, *(THIN+name for name in ('overlay.py','pair.py','bootstrap.py','inputs.json')),
                              *(RECIPE+name for name in P.PINS['recipe'])}, 'complete thin First Login roles')
    P.review_recipe({name: thin_bodies[RECIPE+name] for name in P.PINS['recipe']})
    return verified_parent(parent), thin_bodies, {'fish_r12': R12, 'first_login_map_sha256': thin_sha}


def plan(parent, overlay, thin_sha):
    """Forecast the exact projected seal using only the three retained public pins."""
    prior, thin_bodies, roles = joined_source(parent, overlay, thin_sha)
    pins = {THIN+'dependency/'+name: {**P.PINS['setup8'][role], 'mode': 0o644}
            for role, name in (('archive', P.SETUP), ('signature', P.SETUP+'.sig'), ('certificate', 'public.gpg'))}
    bodies = runtime_material(prior, thin_bodies, {}, pins)
    rows = {**{name: row(raw) for name, raw in bodies.items()}, **pins}
    raw = encode({'kind': 'FIRST_LOGIN_V3_PROJECTED_RUNTIME_V1', 'roles': roles, 'files': rows})
    size = len(raw) + sum(pin['bytes'] for pin in rows.values())
    P.need(size < MAX, 'whole projected runtime size')
    return {'map_sha256': P.digest(raw), 'files': len(rows) + 1, 'bytes': size,
            'owner_program': row(bodies[FULL+'owner-program.json']), 'policy': row(bodies[FULL+'policy.json']),
            'Setup8_packet_base64_bytes': 45708, 'authority': None}


def compose(parent, overlay, thin_sha, output, ordered_setup):
    prior, thin_bodies, roles = joined_source(parent, overlay, thin_sha)
    bodies = runtime_material(prior, thin_bodies, selected_setup(ordered_setup))
    return write(output, 'FIRST_LOGIN_V3_PROJECTED_RUNTIME_V1', roles, bodies)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    emit = sub.add_parser('thin')
    emit.add_argument('--root', required=True, type=Path)
    stage = sub.add_parser('compose')
    review = sub.add_parser('plan')
    for mode in (stage, review):
        for name in ('parent', 'overlay'):
            mode.add_argument('--'+name, required=True, type=Path)
        mode.add_argument('--thin-map-sha256', required=True)
    stage.add_argument('--expected-map-sha256', required=True)
    stage.add_argument('--event', required=True, type=Path)
    for mode in (emit, stage):
        mode.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.action == 'thin':
        result = thin(args.root, args.output)
    elif args.action == 'plan':
        result = plan(args.parent, args.overlay, args.thin_map_sha256)
    else:
        event = json.loads(P.read(args.event, 256 * 1024))
        result = compose(args.parent, args.overlay, args.thin_map_sha256, args.output,
                         event['inputs']['setup8_packet_b64'])
        P.need(result['map_sha256'] == args.expected_map_sha256, 'exact independent Root expected runtime-map pin')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
