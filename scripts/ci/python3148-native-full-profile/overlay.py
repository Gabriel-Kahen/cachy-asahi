#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compose code-only Python Source with the exact immutable Fish r12 owner."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE = Path(__file__).resolve().parent
THIN = 'scripts/ci/python3148-native-full-profile/'
FULL = 'scripts/ci/fish-config02-native-source/successor_v2/'
HELD = 'held-source32/scripts/ci/fish-config02-native-source/'
WORKFLOW = '.github/workflows/native-arm-python3148-native-full-profile.yml'
RECIPE = 'packages/port/python3148-source-candidate/'
MAP = 'source-map.json'
MAX = 2 * 1024**2
R12 = {'commit': '19dea1cca35659ad7ab307dfea09c30a77362640',
       'tree': 'de61a2e7351a09d1dcf0471d50c80e3a1a6ee479',
       'map_sha256': '14a3f9d1f12f224bf43a71a7bb4ef9ba3bfe03b5918b25aabc33ce1fdb71a3b2',
       'bytes': 2093900}
NEW_REF = 'refs/heads/codex/python3148-native-full-profile-source-20261118-r3'


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


sys.path.insert(0,str(HERE))
import preflight as P
import lane
import input_roles
import controller_policy


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def row(raw):
    return {'bytes': len(raw), 'sha256': P.pin(raw)['sha256'], 'mode': 0o644}


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
    P.need(P.pin(raw)['sha256'] == sha and set(frame) == {'kind', 'roles', 'files'}
           and frame['kind'] == kind and frame['roles']['fish_r12'] == R12,
           'externally pinned Source map and exact r12 role')
    rows = frame['files']
    names = files(root)
    P.need(names == set(rows) | {MAP} and sum(value['bytes'] for value in rows.values()) + len(raw) < MAX,
           'whole exact Source namespace and 2 MiB budget')
    bodies = {name: P.read(root / name, MAX) for name in rows}
    P.need(all(row(body) == rows[name] for name, body in bodies.items()), 'whole Source body and mode pins')
    if kind == 'PYTHON3148_PROJECTED_RUNTIME_V1':
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
    sha = P.pin(raw)['sha256']
    verify(root, sha, kind)
    return {'map_sha256': sha, 'files': len(bodies) + 1, 'bytes': len(raw) + sum(map(len, bodies.values()))}


def verified_parent(parent):
    raw = P.read(parent / MAP, 64 * 1024)
    P.need(P.pin(raw)['sha256'] == R12['map_sha256'], 'exact external Fish r12 map')
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
    P.need(body.count(before) == 1 and after not in body, 'unique reviewed projection anchor: '+repr(before[:165]))
    result = body.replace(before, after, 1)
    P.need(result.replace(after, before, 1) == body, 'complete reversible projection')
    return result


THIN_KIND='PYTHON3148_THIN_CODE_SOURCE_V1'
RUNTIME_KIND='PYTHON3148_PROJECTED_RUNTIME_V1'
FILE_NAMES={'overlay.py','lane.py','preflight.py','native_bootstrap.py','material-pins.json','input_roles.py','artifact.py',
            'startup.py','controller_policy.py','expected345.lock','source-plan.json','source-cache-inputs.json','reviewed-inputs.json',
            'cache-FORMAT.data','cache-receipt.json',
            *('notices/python-'+str(i)+'.txt' for i in range(6)),
            'runtime/scripts/build/build_python3148.py','runtime/scripts/build/container-entry-v2.sh'}
BASE_TOOLS=('scripts/build/source_materials.py','scripts/checks/package_checks.py',
            'scripts/maintenance/source_cache.py','scripts/release/source_delivery.py')
INNER_PASS='PASS_CURRENT_PYTHON3148_FULL_PROFILE_ONLY'


def review(thin):
    recipe={name.removeprefix(RECIPE):P.pin(body)['sha256'] for name,body in thin.items() if name.startswith(RECIPE)}
    P.need(set(thin)=={WORKFLOW,*(THIN+n for n in FILE_NAMES),*(RECIPE+n for n in recipe)}
           and len(recipe)==12 and json.loads(thin[THIN+'reviewed-inputs.json'])==recipe
           and P.pin(thin[THIN+'expected345.lock'])['sha256']==lane.LOCK_SHA
           and P.pin(thin[THIN+'source-plan.json'])['sha256']==lane.SOURCE_PLAN_SHA
           and P.pin(thin[THIN+'material-pins.json'])['sha256']==input_roles.PIN_SHA,
           'closed reviewed Python recipe, code and public input descriptor')
    for name,raw in thin.items():
        P.need(not name.endswith(('.tar.xz','.tar.xz.sig','.pkg.tar.zst','.gpg')) and b'\x00' not in raw,
               'no source archive or raw package input in public Git role')


def project_entry(raw):
    edits=(
        (b"                resource.setrlimit(resource.RLIMIT_FSIZE,(16*1024**2,16*1024**2))",
         b"                file_cap=PYTHON_LANE.driver_file_cap(argv)\n"
         b"                resource.setrlimit(resource.RLIMIT_FSIZE,(file_cap,file_cap))"),
        (b"genuine exact freshly provisioned341 inventory",b"genuine exact freshly provisioned345 inventory"),
        (b"profile=C.load(HERE/'profile.json');C.verify_source",
         b"profile=PYTHON_LANE.profile(C.load(HERE/'profile.json'));C.verify_source"),
        (b"('bind',str(HERE/'runtime/scripts/build/container-entry-v2.sh'),'/builder-entry.sh',False)",
         b"('bind',str(PYTHON_LANE.HERE/'runtime/scripts/build/container-entry-v2.sh'),'/builder-entry.sh',False),('bind',str(out/'source-material/srcdest'),'/offline-sources',False)"),
        (b'        image=native.build',
         b'        PYTHON_LANE.bind_bootstrap(native,HERE,PYTHON_INPUTS)\n        image=native.build'),
        (b'        expected_inventory=FISH_INVENTORY.inventory(inputs)',
         b"        FISH_INVENTORY.inventory(inputs)\n        expected_inventory=PYTHON_LANE.HERE/'expected345.lock'"),
        (b'        cache_handoff.retire_context()',
         b"        cache_handoff.retire_context()\n        PYTHON_LANE.bootstrap.retire(output/'bootstrap/context')"),
        (b'        builds,compare=FISH_INVENTORY.plans(C,HERE,output,image,expected_inventory)',
         b'        builds=[PYTHON_LANE.build_argv(output,image,PYTHON_INPUTS)]'),
        (b"runner(argv,360,env={'CACHY_FISH02_NONCE':nonce",
         b"runner(argv,PYTHON_LANE.ACTOR,env={'CACHY_FISH02_NONCE':nonce"),
        (b"        result=runner(compare,120);(output/'comparison.json').write_bytes(result.stdout)\n"
         b"        finisher=FISH_INVENTORY.finisher(HERE,expected_inventory);pair=finisher.finish(output/'build-1',output/'build-2',output/'comparison.json',image);(output/'pair.json').write_text(json.dumps(pair,indent=2)+'\\n')",
         b"        pair=PYTHON_LANE.finish(output/'build-1',image)\n"
         b"        (output/'build-result.json').write_bytes(PYTHON_LANE.P.encode(pair))"),
        (b'try:retain(output)',b'try:C.need((output/\'report.json\').is_file(),\'outer literal snapshot owns retention\')'),
    )
    for before,after in edits:
        raw=replace(raw,before,after)
    return raw.replace(b'PASS_CURRENT_FISH02_NATIVE_PAIR',lane.NATIVE_PASS.encode())


def runtime_material(confirmed, thin):
    reviews={'source-ro-binding.json','libffi-recovery-inverse.json','carrier-admission-inverse.json','base-read-delta.json'}
    files={name:body for name,body in confirmed.items()
           if not name.startswith('.github/') and not (
             name.startswith(FULL) and ('-inverse.' in name or name.rsplit('/',1)[-1] in reviews))}
    files.update({name:body for name,body in thin.items() if name!=WORKFLOW})
    for name in BASE_TOOLS:
        body=confirmed[HELD+'runtime/'+name]
        P.need(P.pin(body)['sha256']==P.TOOLS[name],'exact accepted builder helper')
        files[THIN+'runtime/'+name]=body
    data_name=FULL+'data.py'
    data=files[data_name]
    first,last=data.index(b'def source(root, expected):'),data.index(b'def admission(')
    new=b'''def python_module(root, leaf):
    import importlib.util
    path=Path(root)/'scripts/ci/python3148-native-full-profile'/leaf
    spec=importlib.util.spec_from_file_location('sealed_python_'+path.stem,path)
    M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M);return M


def source(root, expected):
    M=python_module(root,'overlay.py')
    return M.verify(Path(root),expected,'PYTHON3148_PROJECTED_RUNTIME_V1')[0]


'''
    data=data[:first]+new+data[last:]
    data=replace(data,b"    source(root,map_sha); a,r = decode(admission_raw),decode(runtime_raw)\n"
                     b"    profile = decode(read(root/'held-source32'/BASE_PREFIX/'profile.json'))",
      b"    projected=source(root,map_sha); a,r = decode(admission_raw),decode(runtime_raw)\n"
      b"    L=python_module(root,'lane.py')\n"
      b"    profile=L.profile(decode(read(root/'held-source32'/BASE_PREFIX/'profile.json')))\n"
      b"    need(a.get('operation')==r.get('operation')==L.OPERATION and a['ref']==L.REF\n"
      b"         and r.get('thin_map_sha256')==projected['roles']['python_thin_map_sha256']\n"
      b"         and r.get('python_input_pin_sha256')==python_module(root,'input_roles.py').PIN_SHA,\n"
      b"         'separate exact Python operation, code role and raw input descriptor authority')")
    data=replace(data,b"'--property=RuntimeMaxSec=1290s'",f"'--property=RuntimeMaxSec={lane.SERVICES}s'".encode())
    files[data_name]=data
    host=FULL+'host_context.py'
    files[host]=replace(files[host],b'refs/heads/codex/fish02-no-host-apt-v4-source-[A-Za-z0-9._-]{1,80}',lane.REF.encode())
    payload=FULL+'payload.py'
    files[payload]=replace(files[payload],
        b"    exec(compile(I.project_entry(Q.project_entry(N.project_entry(projected))),str(entry_path),'exec'),namespace)",
        b"    L=D.python_module(root,'overlay.py')\n"
        b"    namespace.update(PYTHON_LANE=L.lane,PYTHON_INPUTS=Path(config['python_inputs']))\n"
        b"    projected=I.project_entry(Q.project_entry(N.project_entry(projected)))\n"
        b"    exec(compile(L.project_entry(projected),str(entry_path),'exec'),namespace)")
    owner=FULL+'hosted_owner.py'
    raw=files[owner]
    key=b"for name in ('root','output','carrier-root'):"
    raw=replace(raw,key,b"for name in ('root','output','carrier-root','python-inputs'):")
    key=b"        report['pinned_input_carrier']=N.stage(a.carrier_root,work/'native349-pinned-inputs',a.runner_uid,a.runner_gid)"
    raw=replace(raw,key,key+b"\n        STARTUP.phase('native349-inputs-staged',a.output)\n"
         b"        D.python_module(a.root,'input_roles.py').stage(a.python_inputs,work/'python-inputs',a.runner_uid,a.runner_gid)\n"
         b"        STARTUP.phase('python-inputs-staged',a.output)")
    raw=replace(raw,b"pinned_inputs=str(work/'native349-pinned-inputs'))",
                    b"pinned_inputs=str(work/'native349-pinned-inputs'),python_inputs=str(work/'python-inputs'))")
    raw=replace(raw,b"evidence=work/'fish02-native/evidence'",b"evidence=work/'fish02-native'")
    begin=b"s=importlib.util.spec_from_file_location('fish02_exact_carrier'"
    start=(b"ps=importlib.util.spec_from_file_location('python_startup',HERE.parents[1]/'python3148-native-full-profile/startup.py')\n"
           b"STARTUP=importlib.util.module_from_spec(ps);ps.loader.exec_module(STARTUP)\n"
           b"STARTUP.phase('owner-python-entry')\n")
    raw=replace(raw,begin,start+begin)
    raw=replace(raw,b"LIMIT_FILES=(",b"STARTUP.phase('imports-complete')\nLIMIT_FILES=(")
    for anchor,label in (
        (b"    policy=D.decode(D.read(HERE/'policy.json'))","admission-verified"),
        (b"    os.umask(0o077);a.output.mkdir","controller-domain-verified"),
    ):
        raw=replace(raw,anchor,b'    STARTUP.phase('+repr(label).encode()+b')\n'+anchor)
    for anchor,label,indent,out in (
        (b"    owner=Controller(","output-created",4,b'a.output'),
        (b"        self.capacity()","host-context",8,b'self.out'),
        (b"        self.preflight() # Existing required tools only; no host package manager.","host-tools-probe",8,b'self.out'),
        (b"        p=self.policy;available=self.capacity()","host-tools-ready",8,b'self.out'),
        (b"        image=self.out/'storage.img';fd=","storage-reservation",8,b'self.out'),
        (b"        self.run([self.tool('mkfs.ext4')","loop-attached",8,b'self.out'),
        (b"        daemon=self.start('daemon',argv)","daemon-starting",8,b'self.out'),
        (b"        report['pinned_input_carrier']=N.stage","raw-input-staging",8,b'a.output'),
        (b"        payload=owner.start('owner'","ordinary-owner-starting",8,b'a.output'),
        (b"        evidence=work/'fish02-native'","payload-terminal",8,b'a.output'),
        (b"        E.preserve(report,","owner-finalizing",8,b'a.output'),
        (b"        write(a.output/'owner-report.json',report)","retirement-writing",8,b'a.output'),
    ):
        raw=replace(raw,anchor,b' '*indent+b'STARTUP.phase('+repr(label).encode()+b','+out+b')\n'+anchor)
    raw=replace(raw,b"        D.need(available>=p['minimum_available_bytes']and",
        b"""        D.need(p['minimum_available_bytes']==sum(p[role]['memory_bytes'] for role in
               ('controller','owner','daemon'))+p['host_reserve_bytes'],'complete node memory budget')
        D.need(available>=p['minimum_available_bytes']and""")
    raw=replace(raw,
        b"""        D.need(p['minimum_available_bytes']>=p['owner']['memory_bytes']+p['daemon']['memory_bytes']+p['host_reserve_bytes']
               and p['minimum_disk_bytes']>=p['storage_bytes']+p['host_reserve_bytes'],'aggregate policy inequality')""",
        b"""        D.need(p['minimum_disk_bytes']>=p['storage_bytes']+p['host_reserve_bytes'],'aggregate disk policy inequality')""")
    files[owner]=raw
    for leaf in ('hosted_owner.py','payload.py','public_evidence.py'):
        rel=FULL+leaf
        files[rel]=files[rel].replace(b'PASS_CURRENT_FISH02_NATIVE_PAIR',lane.NATIVE_PASS.encode())
        files[rel]=files[rel].replace(b'cachy-fish02-controller-',b'cachy-python3148-controller-')
    pub=FULL+'public_evidence.py'
    raw=files[pub]
    raw=replace(raw,b"'cachy-asahi-fish-config-0.1.0-2-any'",b"'python-3.14.8-1.1-aarch64'")
    raw=replace(raw,b"'cachy-asahi-fish-config-0.1.0-2-aarch64-check.log'",repr(lane.CHECK_LOG).encode())
    raw=replace(raw,b"('report.json', 'cleanup.json', 'comparison.json', 'pair.json')",
                       b"('report.json', 'cleanup.json', 'build-result.json')")
    raw=replace(raw,b"for build in (1, 2) for n in",b"for build in (1,) for n in")
    raw=replace(raw,b"for build in (1, 2) for name in",b"for build in (1,) for name in")
    raw=replace(raw,b'MAX_BYTES = 16*1024**2',b'MAX_BYTES = 64*1024**2')
    raw=replace(raw,b"0 <= before.st_size <= min(MAX_BYTES, remaining)",
                    b"0 <= before.st_size <= min(40*1024**2 if name.endswith('.pkg.tar.xz') else 8*1024**2, remaining)")
    files[pub]=raw
    names={}
    exec(compile(raw,pub,'exec'),names)
    policy=controller_policy.physical_policy(json.loads(files[FULL+'policy.json']),thin[WORKFLOW],
                                              json.loads(confirmed[HELD+'profile.json'])['resources'])
    policy.update(pair_seconds=lane.OWNER,controller_work_seconds=lane.CONTROLLER,controller_scope_seconds=lane.SCOPE,
                  inner_public_retention=names['DECLARATION'])
    policy['finite_command_case'].update(CPU_RSS_PID_swap_and_deadlines_unchanged=False,
        kind='PYTHON3148_ONE_BUILD_INHERITED_FISH_COMMAND_COUNT_REVIEW',
        ledger=dict(previous_authority=R12['map_sha256'],one_build_driver=True,inner_limit=512,outer_limit=512,
            outer_running_queries_upper=331,startup_commands_upper=66,review_required=True))
    policy['python_native_build']=dict(archive_cap=lane.ARCHIVE_CAP,retained_cap=lane.BYTE_CAP,
        build_seconds=P.BUILD_SECONDS,driver_seconds=lane.ACTOR,driver_file_bytes=lane.DRIVER_FILE_CAP,bootstrap_seconds=lane.BOOTSTRAP,
        inner_seconds=lane.INNER,cleanup_seconds=lane.CLEANUP,owned_service_seconds=lane.SERVICES,
        original_host_package_mutations=0,ordinary_user_build=True,
        startup_observation=dict(seconds=24,observer_ordinary_user=True,only_exact_controller=True,
                                 cgroup_resource_limits_unchanged=True,observes_memory_max=True))
    files[FULL+'policy.json']=encode(policy)
    program=FULL+'owner-program.json'
    held=json.loads(confirmed[program])
    files[program]=encode({'schema':1,'base_source_map_sha256':held['base_source_map_sha256'],
        'files':{name:row(body) for name,body in files.items() if name!=program and not name.startswith(HELD)}})
    return files


def compose(parent, thin_root, thin_sha, new):
    _,thin=verify(thin_root,thin_sha,THIN_KIND)
    review(thin)
    files=runtime_material(verified_parent(parent),thin)
    result=write(new,RUNTIME_KIND,{'fish_r12':R12,'python_thin_map_sha256':thin_sha},files)
    return dict(result,owner_program=row(files[FULL+'owner-program.json']),policy=row(files[FULL+'policy.json']),authority=None)


def fetch(root,sha,output):
    spec=importlib.util.spec_from_file_location('sealed_host_admission',root/FULL/'data.py')
    D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)
    D.admission(root,sha,os.environ['ROOT_FISH02_ADMISSION_JSON'].encode(),os.environ['ROOT_FISH02_RUNTIME_JSON'].encode(),
                os.environ['ADMISSION_SHA256'],os.environ['RUNTIME_SHA256'],os.environ,int(__import__('time').time()))
    input_roles.fetch(output)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('compose','fetch'))
    parser.add_argument('--parent',type=Path)
    parser.add_argument('--thin',type=Path)
    parser.add_argument('--thin-map-sha256')
    parser.add_argument('--expected-runtime-sha256',required=True)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    a=parser.parse_args()
    if a.action=='compose':
        result=compose(a.parent,a.thin,a.thin_map_sha256,a.runtime)
        P.need(result['map_sha256']==a.expected_runtime_sha256,'exact independent projected runtime pin')
        print(json.dumps(result,sort_keys=True))
    else:
        verify(a.runtime,a.expected_runtime_sha256,RUNTIME_KIND)
        fetch(a.runtime,a.expected_runtime_sha256,a.output)
