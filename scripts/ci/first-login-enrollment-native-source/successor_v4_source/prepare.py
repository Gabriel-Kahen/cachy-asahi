#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Closed delegated Source DATA over an exactly pinned, invertible v3 basis.

No actor, workflow dispatch, acquisition, trust verification or Root issuance.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
FAMILY = 'scripts/ci/first-login-enrollment-native-source'
PREFIX = FAMILY+'/successor_v4_source'
OP = 'first-login-enrollment-ui-current-v2'
OWNER_API = 'CURRENT_ONBOARDING_DELEGATED_OWNER_V3'
RETENTION_API = 'CURRENT_ONBOARDING_DELEGATED_RETENTION_V4'
ROLES = ('v3_basis_owner', 'v3_basis_route', 'context', 'image', 'image_executor',
         'delegated_owner', 'route', 'retention', 'public_reader', 'policy', 'workflow', 'encoder', 'owned_process',
         'hosted_launcher', 'inputs_assembler')
ENTRYPOINTS = ('image_executor', 'public_reader', 'hosted_launcher', 'inputs_assembler')
ACTUAL = ('source', 'ref', 'run', 'job', 'Root_delegation', 'Root_trust',
          'Root_resources', 'Root_runtime', 'actual_images', 'publication')
V3 = {
    'prepare.py': (19990, '85af9d4ddd3df614f417b849566f166e6f063bbf16c93ead531e5e5fdb2c577f'),
    'common.py': (6699, '72cb64a9fc62340147ef5a203f6b6dd9f82efe0231ad2b6f76a1248c8a022930'),
    'dispatch.py': (5361, '816ae26ae2475c6b650d865b8be48b3c30813c02bc7d29511480ccc7b1d934ea'),
    'README.md': (5488, 'dbc1a75868fa889961cba0739366a74eea952cb64f57ccdbcf38e30189c1ca88'),
    'owner-closure.TEMPLATE.json': (257, '7cd3a6b501fab8095c07979054565c6477a059aee9f87040f28cb47baf6f7189')}
BASIS = {
    'v3_basis_owner': (FAMILY+'/payload/native/owner_current_v2.py', 46298,
                       'f1a91dee080f76eff88409dd1fe893dc45a2084338017f367ec9874a462a612d'),
    'v3_basis_route': (FAMILY+'/successor_v2/owned_route.py', 26320,
                       '43db41de72822cb8f4d875b6c1d17ffd5062770616ed303f63e299c13478dd86')}
OWNED = ('scripts/virtual/owned_process.py', 25140,
         '83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f')
RETENTION_DEPENDENCIES = {
    FAMILY+'/payload/native/retention_current_v3.py': (44006, '738360745901f1938be1e6a893ce45131c3f1f825421991522cfee3c66ed8c6a'),
    'scripts/ci/log_evidence.py': (1708, 'a25f0089759c12afae3eea23bab8b22fa05cf5bbaa9eddc1611ce78b0405f8f5')}
BUILD_VALIDATOR = (FAMILY+'/successor_v4/validate_build.py', 7798,
                   'dd2fd5a390b7764b753817044e60b8ea088cb6b704e80503f53d4b6335559d84')
PROGRAM_ROLES = dict(context='context', owner='delegated_owner', image='image', image_executor='image_executor',
    route='route', retention='retention', public_reader='public_reader', owned_process='owned_process',
    hosted_launcher='hosted_launcher', inputs_assembler='inputs_assembler', encoder='encoder',
    local_callbacks='v3_basis_owner')
PREREQUISITE_FILES = {
    'host_prerequisites': (FAMILY+'/payload/native/host_prerequisites_current_v3.py', 13750, '521163f6f9504edaa573fa079751d7714065bea2ceef69428e8bc7585e361daa'),
    'host_prerequisite_plan': ('scripts/ci/fish-config02-native-source/successor_v2/host_prerequisites.py', 13845, '4bef653f0e999876e8dd1e74e7d61b808182f7528f4f50ce6444e14f6ff33d64'),
    'host_prerequisite_tools': ('scripts/ci/fish-config02-native-source/successor_v2/host_tools.py', 5273, '5f980d2df87cebdf264167e7be7220485a6fcc555667782d31316da0d08aef72'),
    'host_prerequisite_runner_basis': ('scripts/ci/fish-config02-native-source/successor_v2/hosted_owner.py', 31464, '7f4d2a68f13a2439a4363cfb154553dc9e721a88dc985080dd290d44583ad634')}
PREREQUISITE_POLICY = dict(kind='CURRENT_ONBOARDING_HOST_PREREQUISITES_V3', scope_seconds=495,
    work_seconds=450, observation_seconds=15, cleanup_seconds=30, controller_AS_bytes=536870912,
    controller_CPU_seconds=500, core_bytes=0,
    scope_limits={'memory.max':'536870912', 'memory.swap.max':'0', 'cpu.max':'100000 100000', 'pids.max':'64'},
    output_bytes=16777216, output_nodes=64, minimum_free_bytes=822083584, minimum_free_nodes=4288,
    prerequisite_plan_sha256=PREREQUISITE_FILES['host_prerequisite_plan'][2], Root_acceptance=None)
PREREQUISITE_TIMING = dict(kind='CURRENT_HOSTED_SHARED_7560_PREREQUISITE_TIMING_V3', whole_budget_seconds=7560,
    charge_preflight_and_prerequisites=True, allow_clipped_stage_window=True, metadata_queries=2,
    controller_retirement_reserve_seconds=15, Root_acceptance=None)
PREREQUISITE_CALLBACKS = {'prerequisite_selected', 'prerequisite_program', 'make_timing', 'validate_timing',
                          'controller_seconds', 'available_stage_seconds', 'prerequisite_controller'}
OFFICIAL = ('fuse-common', 'fuse3', 'gobject-introspection-runtime', 'graphene', 'gssdp',
            'gst-plugins-bad-libs', 'gst-plugins-base-libs', 'gstreamer', 'gtk4', 'gupnp',
            'gupnp-igd', 'libgirepository', 'libnice', 'liburing', 'libva', 'libxv', 'numactl',
            'orc', 'python-gobject', 'vmaf', 'vulkan-icd-loader', 'xdg-desktop-portal', 'xdg-desktop-portal-gtk')
ALIASES = {'official/'+name+'/'+kind: 'official_'+name.replace('-', '_')+'_'+kind
           for name in OFFICIAL for kind in ('archive', 'signature')}
ALIASES.update({
    'Setup8/archive': 'setup8_archive', 'Setup8/current_signature': 'setup8_current_signature',
    'Setup8/current_public_key': 'setup8_current_public_key', 'Setup8/current_verification': 'setup8_current_verification',
    'Setup8/current_decision': 'setup8_current_decision', 'expected/backend': 'expected_backend',
    'expected/ui': 'expected_ui', 'expected/lifecycle': 'expected_lifecycle',
    'official/exact_closure': 'official_exact_closure', 'official/archive_signature_inputs': 'official_archive_signature_inputs',
    'prospective/inputs': 'prospective_inputs', 'expected/stage_vectors': 'expected_stage_vectors',
    'prospective/signed_lifecycle': 'prospective_signed_lifecycle'})


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def load_v3():
    """Verify the entire finite local v3 construction closure before loading it."""
    root = HERE.parent/'successor_v3'
    for name, (size, digest) in V3.items():
        path = root/name
        need(path == path.resolve() and not path.is_symlink() and path.stat().st_nlink == 1,
             'ordinary pinned v3 constructor member')
        raw = path.read_bytes()
        need(pin(raw) == dict(bytes=size, sha256=digest), 'immutable v3 constructor member: '+name)
    spec = importlib.util.spec_from_file_location('delegated_v4_pinned_v3', root/'prepare.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def closure_template(*, with_host_prerequisites=False):
    need(type(with_host_prerequisites) is bool, 'explicit optional prerequisite descriptor roster')
    return dict(schema=4, kind='COMMITTED_DELEGATED_CURRENT_PIPELINE_CLOSURE_V4', operation=OP,
                commit=None, roles=dict.fromkeys((*ROLES, *(PREREQUISITE_FILES if with_host_prerequisites else ()))), files=None,
                entrypoints=dict.fromkeys(ENTRYPOINTS), actual=dict.fromkeys(ACTUAL))


def prerequisite_policy_candidate(base):
    """Return separate unissued policy DATA; preserve the actual main ceilings."""
    result = json.loads(encode(base))
    limits = result['executor_current_v3']
    need(all(type(limits.get(k)) is int and limits[k] == v for k, v in
         dict(controller_seconds=7560, stage_seconds=7200, setup_seconds=180, cleanup_seconds=180).items()),
         'existing exact7560 main policy required before optional prerequisite composition')
    for key in ('Root_issuance', 'Root_final_acceptance', 'actual_binding', 'actual_images', 'runtime'):
        need(result.get(key) is None, 'policy candidate issues no authority or runtime observation')
    for key, expected in (('host_prerequisites_current_v3', PREREQUISITE_POLICY),
                          ('host_prerequisite_timing_v3', PREREQUISITE_TIMING)):
        need(key not in result or result[key] == expected, 'refuse conflicting optional policy:'+key)
        result[key] = json.loads(encode(expected))
    return result


def committed_closure(P, repo, raw):
    C = P.C
    value = C.decode(raw)
    need(set(value) == set(closure_template()) and value['schema'] == 4
         and value['kind'] == 'COMMITTED_DELEGATED_CURRENT_PIPELINE_CLOSURE_V4'
         and value['operation'] == OP, 'explicit complete delegated closure')
    need(type(value['actual']) is dict and set(value['actual']) == set(ACTUAL)
         and all(v is None for v in value['actual'].values()), 'future authority selectors must be NULL')
    need(type(value['commit']) is str and re.fullmatch('[0-9a-f]{40}', value['commit']),
         'single full actual committed closure required')
    need(type(value['roles']) is dict and set(value['roles']) in (set(ROLES), set(ROLES) | set(PREREQUISITE_FILES))
         and all(type(v) is str for v in value['roles'].values())
         and len(set(value['roles'].values())) == len(value['roles']), 'all distinct actual pipeline role members required')
    need(type(value['files']) is dict and len(ROLES) <= len(value['files']) <= 96
         and set(value['roles'].values()) <= set(value['files']), 'complete finite committed file closure')
    for name, row in value['files'].items():
        C.relative(name)
        need(not name.startswith((PREFIX+'/', C.PREFIX+'/', 'carrier/', 'inputs/', 'provenance/'))
             and name not in ('source-map.json', 'source.lock.json'), 'closure cannot occupy generated Source slots')
        need(type(row) is dict and set(row) == {'bytes', 'sha256', 'mode'}
             and type(row['mode']) is int and row['mode'] in (0o644, 0o755), 'whole committed file/mode row')
    P.commit(repo, value['commit'])
    files = {name: P.blob(repo, value['commit'], name, row) for name, row in value['files'].items()}
    for name, (size, digest) in RETENTION_DEPENDENCIES.items():
        need(name in files and files[name][1] == 0o644 and
             pin(files[name][0]) == dict(bytes=size, sha256=digest), 'immutable closed retention dependency: '+name)
    name, size, digest = BUILD_VALIDATOR
    need(name in files and files[name][1] == 0o644 and pin(files[name][0]) == dict(bytes=size, sha256=digest),
         'exact committed owned static validator dependency')
    role = lambda name: value['roles'][name]
    prerequisites = set(PREREQUISITE_FILES) <= set(value['roles'])
    if prerequisites:
        for name, (member, size, digest) in PREREQUISITE_FILES.items():
            need(role(name) == member and member in files and files[member][1] == 0o644 and
                 pin(files[member][0]) == dict(bytes=size, sha256=digest), 'exact optional prerequisite dependency: '+name)
    for name, (path, size, digest) in BASIS.items():
        need(role(name) == path and files[path] == (files[path][0], 0o644)
             and pin(files[path][0]) == dict(bytes=size, sha256=digest), 'unchanged DATA-only v3 callback basis')
    path, size, digest = OWNED
    need(role('owned_process') == path and files[path][1] == 0o755
         and pin(files[path][0]) == dict(bytes=size, sha256=digest), 'exact committed held supervisor required')
    def functions(name):
        return {n.name for n in ast.parse(files[role(name)][0]).body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    wanted = dict(context={'validate_delegation', 'validate_context', 'capture_context', 'adopt_pair', 'adopt_selected_pair'},
                  image={'build_stage'}, delegated_owner={'run_owned_current_v3', 'open_delegated_session', 'launch_delegated_lifecycle'},
                  route={'run_registered'}, retention={'retain_delegated_stage'}, encoder={'bundle'},
                  inputs_assembler={'validate_owner_inputs_v3', 'validate_hosted_inputs_v3', 'stage_inputs'},
                  image_executor={'context_contract', 'owner_main', 'controller_main'},
                  hosted_launcher={'checked_inputs', 'preflight'})
    for name, entries in wanted.items():
        need(entries <= functions(name), 'actual committed role callbacks missing: '+name)
    if prerequisites:
        need('prepare_host_prerequisites' in functions('host_prerequisites'), 'actual prerequisite API')
        need(PREREQUISITE_CALLBACKS <= functions('hosted_launcher'), 'actual committed prerequisite/time launcher callbacks')
    owner = ast.parse(files[role('delegated_owner')][0])
    need(any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'API' for t in n.targets)
             and isinstance(n.value, ast.Constant) and n.value.value == OWNER_API for n in owner.body),
         'actual delegated owner API, never old owner relabelling')
    retention = ast.parse(files[role('retention')][0])
    need(any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'API' for t in n.targets)
             and isinstance(n.value, ast.Constant) and n.value.value == RETENTION_API for n in retention.body),
         'explicit delegated retention API, never old Root-schema wrappers')
    need(role('encoder') == 'scripts/ci/log_evidence.py', 'actual immutable evidence encoder role')
    context_pin = pin(files[role('context')][0])
    for consumer in ('image', 'image_executor'):
        pins = context_program_pins(files[role(consumer)][0])
        need(pins.get(4) == context_pin, 'actual selected v4 context whole pin differs from '+consumer)
    entries = value['entrypoints']
    need(type(entries) is dict and set(entries) == set(ENTRYPOINTS), 'explicit actual executor/Reader/launcher/assembler entries')
    for name, entry in entries.items():
        need(type(entry) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,95}', entry)
             and entry in functions(name), 'declared committed callback missing: '+name)
    policy = C.decode(files[role('policy')][0])
    if prerequisites:
        need(policy.get('host_prerequisites_current_v3') == PREREQUISITE_POLICY and
             policy.get('host_prerequisite_timing_v3') == PREREQUISITE_TIMING and
             literal_assignment(files[role('hosted_launcher')][0], 'TIMING') == PREREQUISITE_TIMING,
             'exact helper policy and committed launcher shared7560 contract')
        limits = policy['executor_current_v3']
        need(all(type(limits.get(k)) is int and limits[k] == v for k, v in
             dict(controller_seconds=7560, stage_seconds=7200, setup_seconds=180, cleanup_seconds=180).items()),
             'unchanged main ceiling with prerequisite charged inside7560')
    else:
        need(not {'host_prerequisites_current_v3', 'host_prerequisite_timing_v3'} & set(policy),
             'prerequisite policy requires complete optional descriptor roster')
    need(role('workflow').startswith('.github/workflows/') and role('workflow').endswith('.yml')
         and b'workflow_dispatch:' in files[role('workflow')][0], 'committed distinct dispatch workflow required')
    return value, files


def literal_assignment(raw, name):
    """Read only a named finite literal table, without importing consumer code."""
    need(name in ('CONTEXT_PROGRAM_PINS', 'TIMING'), 'finite reviewed literal selection')
    tree = ast.parse(raw)
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    need(len(rows) == 1, 'one explicit existing consumer literal table:'+name)
    class LiteralDict(ast.NodeTransformer):
        def visit_Call(self, node):
            need(isinstance(node.func, ast.Name) and node.func.id == 'dict' and not node.args and
                 all(row.arg is not None for row in node.keywords), 'literal context pin dict only')
            return ast.Dict(keys=[ast.Constant(row.arg) for row in node.keywords],
                            values=[self.visit(row.value) for row in node.keywords])
    return ast.literal_eval(LiteralDict().visit(rows[0]))


def context_program_pins(raw):
    value = literal_assignment(raw, 'CONTEXT_PROGRAM_PINS')
    need(type(value) is dict and set(value) <= {3, 4}, 'finite explicit context versions')
    return value


def delegation_programs(roles, files):
    """Canonical descriptor selection only; never an issued Root delegation."""
    programs = {name: roles[role] for name, role in PROGRAM_ROLES.items()}
    programs.update({name:roles[name] for name in PREREQUISITE_FILES if name in roles})
    name, size, digest = BUILD_VALIDATOR
    need(files[name][1] == 0o644 and pin(files[name][0]) == dict(bytes=size, sha256=digest),
         'actual validator body before canonical descriptor selection')
    programs['build_validator'] = dict(member=name, **pin(files[name][0]))
    return programs


def project_materials(material_map, files):
    """Exact59 original roles -> fixed lowercase aliases; path -> member only.

    files is the already verified Source dictionary {member: (bytes, mode)}.
    Nothing rewrites carrier bytes, historical Root proof bodies or their pins.
    """
    need(type(material_map) is dict and set(material_map) == set(ALIASES) and len(ALIASES) == 59
         and len(set(ALIASES.values())) == 59, 'exact original role set and collision-free fixed aliases')
    projected, members = {}, set()
    for original, alias in sorted(ALIASES.items()):
        need(re.fullmatch('[a-z][a-z0-9_]{0,63}', alias), 'bounded lowercase delegation alias')
        row = material_map[original]
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'} and type(row['path']) is str
             and row['path'].startswith('carrier/') and '..' not in Path(row['path']).parts
             and row['path'] in files and row['path'] not in members
             and type(row['bytes']) is int and 0 < row['bytes'] <= 16*1024**2
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
             'unique closed original Source-relative carrier member/whole pin')
        members.add(row['path'])
        path = Path(row['path'])
        need(not path.is_absolute() and path.as_posix() == row['path'] and len(path.parts) <= 16
             and all(re.fullmatch('[A-Za-z0-9._+-]+', part) and part not in ('.', '..') for part in path.parts),
             'canonical safe original carrier member')
        body, mode = files[row['path']]
        need(type(body) is bytes and mode == 0o644 and pin(body) == {k: row[k] for k in ('bytes', 'sha256')},
             'unchanged actual carrier body/mode/whole pin')
        projected[alias] = dict(member=row['path'], **pin(body))
    return dict(schema=4, kind='DELEGATED_SOURCE_RELATIVE_MATERIALS_V4', aliases=dict(ALIASES), materials=projected)


def extend_v3(P, files, closure, closure_raw):
    """Add the explicit v4 program; retain the v3 registry strictly as DATA basis."""
    C = P.C
    files = dict(files)
    basis_files = dict(files)
    original_map = files['source-map.json']
    need(original_map == files['source.lock.json'], 'exact separate v3 map/lock aliases')
    original = C.decode(original_map[0])
    need(original['files'] == C.descriptors({n: v for n, v in files.items() if n not in ('source-map.json', 'source.lock.json')}),
         'complete v3 construction namespace before extension')
    old_program = C.decode(files[C.PREFIX+'/owner-program.json'][0])
    materials = project_materials(old_program['materials'], files)
    roles = {name: dict(member=path, **pin(files[path][0])) for name, path in closure['roles'].items()}
    added = {
        'provenance/v4/v3-source-map.json': original_map,
        'provenance/v4/delegated-closure.json': (closure_raw, 0o644),
        'inputs/delegated-materials-v4.json': (encode(materials), 0o644)}
    registry = dict(schema=4, kind='DELEGATED_CURRENT_PROGRAM_REGISTRY_V4', operation=OP,
                    api=OWNER_API, owner=roles['delegated_owner'], route=roles['route'],
                    owner_callbacks=dict(build='open_delegated_session', lifecycle='launch_delegated_lifecycle'),
                    route_callback='run_registered', roles=roles, entrypoints=closure['entrypoints'],
                    delegation_programs=delegation_programs(roles, files),
                    retention_callback='retain_delegated_stage',
                    closure_commit=closure['commit'], v3_registry_scope='PRESERVED_DATA_ONLY_NEVER_DELEGATED_EXECUTION',
                    actual=dict.fromkeys(ACTUAL))
    added[PREFIX+'/program.json'] = (encode(registry), 0o644)
    for name in ('prepare.py', 'README.md'):
        # Even this constructor/document must be committed in the same full revision.
        body, mode = P.blob(closure['_repo'], closure['commit'], PREFIX+'/'+name)
        current, current_mode = C.read(HERE/name)
        need((body, mode) == (current, current_mode), 'exact executing committed v4 construction member')
        added[PREFIX+'/'+name] = (body, mode)
    inverse_name = PREFIX+'/inverse.json'
    inverse = dict(schema=4, kind='DELEGATED_SOURCE_V4_TO_V3_INVERSE_DATA_ONLY',
                   original_map=pin(original_map[0]), original_files=len(files), original_bytes=sum(len(v[0]) for v in files.values()),
                   remove=sorted([*added, inverse_name]), actual_acceptance=None)
    added[inverse_name] = (encode(inverse), 0o644)
    need(not set(added) & set(files), 'no v3 body replacement')
    files.update(added)
    body = C.decode(original_map[0])
    body['files'] = C.descriptors({n: v for n, v in files.items() if n not in ('source-map.json', 'source.lock.json')})
    raw = encode(body)
    files['source-map.json'] = files['source.lock.json'] = (raw, 0o644)
    restored = inverse_v3(files)
    need(restored == basis_files, 'whole v3 inverse namespace/body/mode')
    need(len(files) <= C.MAX_FILES and sum(len(v[0]) for v in files.values()) <= C.MAX_TOTAL
         and all(len(v[0]) <= C.MAX_FILE for v in files.values()), 'unchanged complete Source caps')
    return files


def inverse_v3(files):
    P = load_v3()
    C = P.C
    value = C.decode(files[PREFIX+'/inverse.json'][0])
    original = files['provenance/v4/v3-source-map.json']
    need(pin(original[0]) == value['original_map'], 'whole retained original v3 map')
    result = {n: v for n, v in files.items() if n not in value['remove'] and n not in ('source-map.json', 'source.lock.json')}
    old = C.decode(original[0])
    need(C.descriptors(result) == old['files'], 'exact inverse original namespace/body/mode')
    result['source-map.json'] = result['source.lock.json'] = original
    need(len(result) == value['original_files'] and sum(len(v[0]) for v in result.values()) == value['original_bytes'], 'whole inverse file/byte count')
    return result


def assemble(repo, closure_raw, carrier_raw, manifest_raw):
    P = load_v3()
    closure, code = committed_closure(P, repo, closure_raw)
    v3_closure = dict(schema=1, kind='CURRENT_ONBOARDING_COMMITTED_OWNER_ROUTE_CLOSURE_V3',
                      api=P.C.API, operation=OP, commit=closure['commit'], files=closure['files'],
                      owner=closure['roles']['v3_basis_owner'], route=closure['roles']['v3_basis_route'])
    files, basis = P.assemble(repo, encode(v3_closure), carrier_raw, manifest_raw)
    need(all(files[name] == value for name, value in code.items()), 'same single committed closure throughout v3 basis')
    selected = dict(closure, _repo=repo)
    files = extend_v3(P, files, selected, closure_raw)
    return files, dict(status='CLOSED_DELEGATED_SOURCE_V4_DATA_RUNTIME_UNQUALIFIED', files=len(files),
                        bytes=sum(len(v[0]) for v in files.values()), source_map=pin(files['source-map.json'][0]),
                        delegated_program=pin(files[PREFIX+'/program.json'][0]), v3_basis=basis, actual=dict.fromkeys(ACTUAL))


def main():
    need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, 'isolated unoptimized DATA constructor')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'closure', 'carrier', 'carrier-manifest', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    for name in ('closure-sha256', 'carrier-sha256', 'carrier-manifest-sha256'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    P = load_v3()
    read = lambda p, sha, cap: P.C.read(p, dict(bytes=p.stat().st_size, sha256=sha), cap=cap)[0]
    files, result = assemble(args.repo, read(args.closure, args.closure_sha256, 1024**2),
                             read(args.carrier, args.carrier_sha256, 32*1024**2),
                             read(args.carrier_manifest, args.carrier_manifest_sha256, 1024**2))
    P.publish(files, args.output)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
