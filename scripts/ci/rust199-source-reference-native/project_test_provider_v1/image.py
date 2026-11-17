# SPDX-License-Identifier: MIT
"""Dedicated TEST image/observation component, not the full Rust qualifier.

No entry runs on import. Callers must first authenticate the explicit Root
admission and complete provider context. No official-v18 actor is rewired here.
Qualification envelopes below are DATA; the caller still authenticates/replays
the full Root/source/kernel/mount/volume/grant evidence with existing predicates.
"""
import ast
import hashlib
import math
import os
from pathlib import Path
import re
import shlex
import types

HERE = Path(__file__).resolve().parent
PREDECESSOR = HERE.parent / 'successor_v18/payload'
QUALIFICATION = dict(cap0_phases=['data', 'probe'], cli_probes=9,
                     resources_changed=False, makepkg_dependency_checks=True)
CGROUP = {'cpu.max': '200000 100000', 'memory.max': '8589934592',
          'memory.swap.max': '0', 'pids.max': '512'}
CAPS = {'CapPrm', 'CapEff', 'CapBnd', 'CapInh', 'CapAmb'}
KIND = 'RUST_PROJECT_TEST_PROVIDER_OBSERVATION_V1'


def pinned(path, size, digest):
    raw = path.read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('immutable Rust18 helper changed')
    return raw


def official():
    path = PREDECESSOR / 'hosted/build_dependencies.py'
    raw = pinned(path, 20374, 'ba8aaf5b89c5fa318ce1595bbb486edec270b8e0f4ea71975c42a0f70046e882')
    module = types.ModuleType('project_image_frozen_v18'); module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def qualification_predicates():
    path = PREDECESSOR / 'actor/qualify.py'
    raw = pinned(path, 14490, '12094e033881ed3daf3eb33a224b363e274b6d769bd24528b35ff280178a0b73')
    nodes = [node for node in ast.parse(raw).body if
             isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in {'LLVM', 'PROBES'} for t in node.targets)
             or isinstance(node, ast.FunctionDef) and node.name == 'natural']
    namespace = {'Path': Path}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace['PROBES'], namespace['natural']


def contract(p, D):
    trust = p['trust']
    D.need(type(trust) is dict and set(trust) == {'scope', 'public_key', 'primary_fingerprint', 'signing_fingerprint', 'ALARM_authentication'}
           and trust['scope'] == 'PROJECT_TEST_ONLY' and trust['ALARM_authentication'] is False, 'separate project TEST trust only')
    for key in ('primary_fingerprint', 'signing_fingerprint'):
        D.need(type(trust[key]) is str and re.fullmatch('[0-9A-F]{40}', trust[key]) and trust[key] != D.SIGNER,
               'explicit full project TEST fingerprint, never ALARM')
    key = trust['public_key']; D.need(type(key) is dict and set(key) == {'path', 'bytes', 'sha256'}, 'whole selected public TEST key')
    D.relative(key['path']); D.descriptor({k: key[k] for k in ('bytes', 'sha256')}, 65536)
    D.need(D.encode(p['qualification']) == D.encode(QUALIFICATION), 'unchanged two cap0 phases, nine probes and dependencies')
    return trust


def extend_dockerfile(original, p, D):
    trust = contract(p, D)
    D.need(type(original) is bytes and original.endswith(b'USER alarm\nWORKDIR /tmp\n'), 'exact existing normal-image Dockerfile ending')
    packages = p['packages']; D.need(type(packages) is list and len(packages) == 2, 'two explicit project TEST providers')
    names, requirements = [], {'bash', 'curl', 'gcc', 'glibc', 'libgcc', 'libstdc++', 'libgit2', 'libssh2',
        'openssl', 'sqlite', 'zlib', 'cachy-asahi-llvm23-source-reference=23.1.1', 'python>=3.12', 'bubblewrap', 'libarchive'}
    for row in packages:
        D.need(re.fullmatch(r'[A-Za-z0-9._+-]+-aarch64\.pkg\.tar\.xz', row['filename'])
               and D.literal(row['name']) and not row['name'].startswith('-')
               and D.literal(row['version']) and not row['version'].startswith('-'), 'finite exact project package operands')
        names.append('/tmp/rust-project-test-dependencies/' + row['filename'])
        D.need(all(D.literal(v) and not v.startswith('-') for v in row['metadata']['depend']), 'literal non-option project dependencies')
        requirements.update(row['metadata']['depend']); requirements.add(row['name'] + '=' + row['version'])
    D.need(len(set(names)) == 2, 'distinct project archives')
    home, config, context = '/tmp/rust-project-test-gpg', '/tmp/rust-project-test-pacman.conf', '/tmp/rust-project-test-dependencies'
    gpg = '/usr/bin/gpg --no-options --no-auto-key-retrieve --batch --homedir ' + home
    commands = ['test ! -e ' + home, 'test ! -L ' + home, 'test ! -e ' + config, 'test ! -L ' + config, 'mkdir -m 700 ' + home,
        "printf '[options]\\nArchitecture = aarch64\\nSigLevel = Required\\nLocalFileSigLevel = Required\\nHookDir = /builder-disabled-hooks\\n' > " + config,
        gpg + ' --import ' + context + '/public-test.gpg',
        gpg + ' --with-colons --fingerprint --fingerprint --list-keys > ' + home + '/public-list.txt',
        "test \"$(awk -F: '$1==\"pub\" {n++} $1==\"fpr\" && !first {first=$10} END {print n \":\" first}' " + home + "/public-list.txt)\" = '1:" + trust['primary_fingerprint'] + "'",
        "awk -F: '$1==\"fpr\" {print $10}' " + home + '/public-list.txt | grep -Fx ' + shlex.quote(trust['signing_fingerprint']),
        "printf '%s:6:\\n' " + shlex.quote(trust['primary_fingerprint']) + ' | ' + gpg + ' --import-ownertrust',
        '/usr/bin/pacman --gpgdir ' + home + ' --config ' + config + ' -U --noconfirm --noscriptlet ' + ' '.join(map(shlex.quote, names)),
        '/usr/bin/pacman --config ' + config + ' -T ' + ' '.join(map(shlex.quote, sorted(requirements))),
        'ldconfig', 'pacman -Q | LC_ALL=C sort > /builder-qualified.lock',
        'cmp -s /builder-qualified.lock ' + context + '/expected-qualified.lock',
        '/usr/bin/gpgconf --homedir ' + home + ' --kill gpg-agent']
    for suffix in ('', '.browser', '.extra', '.ssh'):
        path = home + '/S.gpg-agent' + suffix; commands += ['test ! -e ' + path, 'test ! -L ' + path]
    commands += ['rm -rf ' + home + ' ' + context + ' ' + config]
    return original + ('USER root\nCOPY project-test-dependencies/ ' + context + '/\nRUN ' + ' && '.join(commands) + '\nUSER alarm\nWORKDIR /tmp\n').encode()


def _old(value, D):
    return dict(schema=18, status='OBSERVED_EXACT_SIGNED_BUILD_DEPENDENCIES_DATA_ONLY', policy=D.POLICY_PIN,
        **{k: value[k] for k in ('inventory', 'providers', 'native_uid_gid_checked', 'runtime_loads', 'native_acceptance', 'Root_acceptance')})


def observe(image_root, source_root, p, *, image_id, tick=lambda: None, native=False, D=None):
    D = official() if D is None else D; contract(p, D)
    D.need(type(native) is bool and type(image_id) is str and re.fullmatch('sha256:[0-9a-f]{64}', image_id), 'exact immutable project image observation')
    old = D.observe(image_root, source_root, p, tick, native=native)
    return dict(schema=1, kind=KIND, trust_scope='PROJECT_TEST_ONLY', ALARM_authentication=False,
        policy=D.pin(D.encode(p)), image_id=image_id,
        **{k: old[k] for k in ('inventory', 'providers', 'native_uid_gid_checked', 'runtime_loads', 'native_acceptance', 'Root_acceptance')})


def validate_observation(value, source_root, p, *, image_id, expected=None, native=True, D=None):
    D = official() if D is None else D; contract(p, D)
    keys = {'schema', 'kind', 'trust_scope', 'ALARM_authentication', 'policy', 'image_id', 'inventory', 'providers',
            'native_uid_gid_checked', 'runtime_loads', 'native_acceptance', 'Root_acceptance'}
    D.need(type(value) is dict and set(value) == keys and type(value['schema']) is int and value['schema'] == 1
           and value['kind'] == KIND and value['trust_scope'] == 'PROJECT_TEST_ONLY'
           and value['ALARM_authentication'] is False and value['image_id'] == image_id
           and re.fullmatch('sha256:[0-9a-f]{64}', image_id)
           and D.encode(value['policy']) == D.encode(D.pin(D.encode(p))), 'exact project TEST observation scope and image')
    D.validate_observation(_old(value, D), source_root, p, _old(expected, D) if expected is not None else None, native=native)
    if expected is not None:
        D.need(all(D.encode(value[k]) == D.encode(expected[k]) for k in ('image_id', 'policy', 'inventory', 'providers')), 'same host-qualified TEST dependency state')
    return value


def validate_qualification(host, phases, probes, source_root, p, *, image_id, D=None):
    """Component evidence only; caller retains all full Rust admission predicates.

    phases is exactly data/probe, each {observation,kernel,lifecycle}. kernel has
    phase,image_id,policy,architecture,uid[4],gid[4],capabilities,NoNewPrivs,cgroup,
    offline,readonly_root,readonly_inputs,mount_proof_sha256,elapsed_seconds.
    The raw mount/provenance authority is checked by the full existing qualifier.
    """
    D = official() if D is None else D; contract(p, D); expected, natural = qualification_predicates()
    validate_observation(host, source_root, p, image_id=image_id, native=False, D=D)
    D.need(type(phases) is dict and set(phases) == {'data', 'probe'}, 'both fixed project cap0 phases')
    for phase, envelope in phases.items():
        D.need(type(envelope) is dict and set(envelope) == {'observation', 'kernel', 'lifecycle'}
               and type(envelope['lifecycle'].get('exit')) is int and natural(envelope['lifecycle']), 'naturally retired project qualifier phase')
        validate_observation(envelope['observation'], source_root, p, image_id=image_id, expected=host, native=True, D=D)
        k = envelope['kernel']; fields = {'phase', 'image_id', 'policy', 'architecture', 'uid', 'gid', 'capabilities', 'NoNewPrivs', 'cgroup',
                                         'offline', 'readonly_root', 'readonly_inputs', 'mount_proof_sha256', 'elapsed_seconds'}
        D.need(type(k) is dict and set(k) == fields and k['phase'] == phase and k['image_id'] == image_id
               and D.encode(k['policy']) == D.encode(host['policy']) and k['architecture'] == 'aarch64'
               and k['uid'] == k['gid'] == [1001] * 4 and all(type(v) is int for key in ('uid', 'gid') for v in k[key])
               and type(k['capabilities']) is dict and set(k['capabilities']) == CAPS
               and all(type(v) is int and v == 0 for v in k['capabilities'].values())
               and type(k['NoNewPrivs']) is int and k['NoNewPrivs'] == 1 and k['cgroup'] == CGROUP
               and all(k[key] is True for key in ('offline', 'readonly_root', 'readonly_inputs'))
               and D.sha(k['mount_proof_sha256']) and type(k['elapsed_seconds']) in (int, float)
               and math.isfinite(k['elapsed_seconds']) and 0 <= k['elapsed_seconds'] <= {'data': 900, 'probe': 180}[phase], 'same native1001 cap0 NNP resource/kernel component')
    D.need(type(probes) is list and len(probes) == len(expected) == 9, 'nine frozen Rust CLI probes')
    seconds = 0
    for row, argv in zip(probes, expected):
        life = row['lifecycle']; elapsed = life.get('elapsed_seconds')
        D.need(row['argv'] == argv and type(row['returncode']) is int and row['returncode'] == 0 and natural(life)
               and type(life.get('exit')) is int and row['kernel_mount_proof_sha256'] == phases['probe']['kernel']['mount_proof_sha256']
               and type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 30, 'exact naturally retired bounded CLI probe')
        seconds += elapsed
    D.need(seconds <= 60, 'unchanged aggregate sixty-second native probe budget')
    return dict(schema=1, kind='RUST_PROJECT_TEST_PROVIDER_QUALIFICATION_COMPONENT_V1',
                status='PASS_PROJECT_TEST_DEPENDENCY_COMPONENT_DATA_ONLY', image_id=image_id, policy=host['policy'],
                inventory=host['inventory'], providers=host['providers'], cap0_phases=['data', 'probe'], cli_probes=9,
                full_Rust_qualification=False, ALARM_authentication=False, native_acceptance=False, Root_acceptance=None)
