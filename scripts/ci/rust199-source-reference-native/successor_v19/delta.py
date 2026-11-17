# SPDX-License-Identifier: MIT
"""Finite Source367 -> frozen v18 runtime -> separate project TEST bridge.

No Source program or role runs. Only the three dependency-admission call sites
change; every original authority/kernel/mount/volume/resource predicate remains.
"""
import ast
import hashlib
from pathlib import Path
import stat
import types

HERE = Path(__file__).resolve().parent
V18 = HERE.parent / 'successor_v18'
V18_DELTA = dict(bytes=4545, sha256='f032c22aeb05beeac8749289be39db4032d7da66c49c02e7df0d4ea5e1170b4f')
V18_PINS = {
    'hosted/bootstrap.py': dict(bytes=32404, sha256='ebaa47429768dc619b5d0424a358316a77586b978638c04fa245df25f98d044c'),
    'hosted/qualification.py': dict(bytes=24731, sha256='118eaa9ef06397c69bf36d6f515423c4f4d16b0cde969a38c6ec7ee00c998744'),
    'actor/qualify.py': dict(bytes=14490, sha256='12094e033881ed3daf3eb33a224b363e274b6d769bd24528b35ff280178a0b73'),
}
PATCHES = {
    'hosted/bootstrap.py': [
        ("dependencies=load('rust_bootstrap_build_dependencies',root/'hosted/build_dependencies.py');dependency_policy=dependencies.policy(root)",
         "dependencies=load('rust_bootstrap_project_test_providers',root/'hosted/project_provider.py');dependency_policy=None"),
        ("    try:\n        report['base_intent']=True;",
         "    try:\n        dependency_policy=dependencies.policy(root,tick=tick)\n        report['base_intent']=True;"),
        ("dependencies.prepare_context(root,context,out,Path(os.environ['RUNNER_TEMP'])/'alarm-cache',dependency_policy,call,tick)",
         "dependencies.prepare_context(root,context,out,dependency_policy,call,tick)"),
        ("dependencies.extend_dockerfile(normal_dockerfile(own['base_tag'],fingerprint_expected),dependency_policy)",
         "dependencies.extend_dockerfile(normal_dockerfile(own['base_tag'],fingerprint_expected),dependency_policy,dependency_audit)"),
        ("dependencies.observe(rootfs,root,dependency_policy,tick)",
         "dependencies.observe(rootfs,root,dependency_policy,tick,image_id=image)"),
        ("dependencies.validate_observation(dependency_observation,root,dependency_policy,native=False)",
         "dependencies.validate_observation(dependency_observation,root,dependency_policy,image_id=image,native=False,tick=tick)"),
        ("dict(policy=dependencies.POLICY_PIN,audit=",
         "dict(policy=dependencies.pin(encode(dependency_policy['policy'])),audit="),
    ],
    'hosted/qualification.py': [
        ("def validate_result(value,provider,boot,directory=None):",
         "def validate_result(value,provider,boot,directory=None,*,tick=lambda:None):"),
        ("dependencies=load('qualification_build_dependency_checks',Path(__file__).with_name('build_dependencies.py'))",
         "dependencies=load('qualification_project_test_provider_checks',Path(__file__).with_name('project_provider.py'))"),
        ("dependency_policy=dependencies.policy(source_root)",
         "dependency_policy=dependencies.policy(source_root,tick=tick)"),
        ("dependencies.validate_observation(value['build_dependencies'],source_root,dependency_policy,boot['build_dependencies']['observation'])",
         "dependencies.validate_observation(value['build_dependencies'],source_root,dependency_policy,boot['build_dependencies']['observation'],image_id=boot['image'],tick=tick)"),
        ("raw=dependencies.read(path,1024**2)",
         "raw=dependencies.read(path,1024**2,tick=tick)"),
        ("dependencies.validate_observation(dependencies.decode(raw),source_root,dependency_policy,boot['build_dependencies']['observation'])",
         "dependencies.validate_observation(dependencies.decode(raw),source_root,dependency_policy,boot['build_dependencies']['observation'],image_id=boot['image'],tick=tick)"),
        ("validate_result(value,provider,boot,data);need(value['source_audit']==audit",
         "validate_result(value,provider,boot,data,tick=tick);need(value['source_audit']==audit"),
    ],
    'actor/qualify.py': [
        ("dependencies=load('native_qualification_build_dependencies',ROOT/'hosted/build_dependencies.py');dependency_policy=dependencies.policy(ROOT)",
         "dependencies=load('native_qualification_project_test_providers',ROOT/'hosted/project_provider.py');dependency_policy=dependencies.policy(ROOT,tick=tick)"),
        ("dependencies.observe(Path('/'),ROOT,dependency_policy,tick,native=True)",
         "dependencies.observe(Path('/'),ROOT,dependency_policy,tick,image_id=p['image_id'],native=True)"),
        ("dependencies.validate_observation(dependency_observation,ROOT,dependency_policy,p['build_dependencies'])",
         "dependencies.validate_observation(dependency_observation,ROOT,dependency_policy,p['build_dependencies'],image_id=p['image_id'],tick=tick)"),
    ],
}


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def pinned(path, expected):
    need(path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents)), 'unaliased frozen v18 runtime')
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o644
         and info.st_size == expected['bytes'], 'ordinary exact frozen v18 runtime')
    raw = path.read_bytes(); need(pin(raw) == expected, 'whole frozen v18 runtime pin')
    return raw, 0o644


def predecessor():
    raw, _ = pinned(V18 / 'delta.py', V18_DELTA)
    module = types.ModuleType('project19_frozen_v18_delta'); module.__file__ = str(V18 / 'delta.py')
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def v18_leaves():
    return {name: pinned(V18 / 'payload' / name, wanted) for name, wanted in V18_PINS.items()}


def project(before):
    need(type(before) is dict and set(before) == set(PATCHES), 'only three exact project-provider runtime leaves')
    result = {}
    for name, changes in PATCHES.items():
        raw, mode = before[name]
        need(type(raw) is bytes and type(mode) is int and mode == 0o644
             and pin(raw) == V18_PINS[name], 'exact rendered v18 runtime predecessor')
        original = raw
        for old, new in changes:
            old, new = old.encode(), new.encode()
            need(raw.count(old) == 1 and new not in raw, 'one exact v19 project bridge insertion site: ' + name)
            raw = raw.replace(old, new)
        ast.parse(raw)
        inverse = raw
        for old, new in reversed(changes):
            need(inverse.count(new.encode()) == 1, 'exact v19 runtime inverse site')
            inverse = inverse.replace(new.encode(), old.encode())
        need(inverse == original, 'complete v19-to-v18 runtime byte inverse')
        result[name] = raw, mode
    return result


def payload_leaves():
    return project(v18_leaves())


def render_leaves(before):
    """Source367 operational inputs only; constructor checks full Source tuple."""
    need(type(before) is dict and all(name in before and type(before[name]) is tuple and len(before[name]) == 2
         and type(before[name][0]) is bytes and type(before[name][1]) is int for name in PATCHES), 'complete Source367 runtime rows')
    rendered = predecessor().render_leaves(before)
    need(rendered == v18_leaves(), 'Source367 delta must reproduce whole pinned v18 runtime')
    return project(rendered)
