# SPDX-License-Identifier: MIT
"""Counted two-product derivatives; no original factory or native source is edited."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import types

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OLD = 'scripts/ci/apps-cache-native/'

def read(source, name):
    row = json.loads((HERE / 'original-pins.json').read_bytes())[name]
    path = source / name
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('original source alias')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != row['bytes']:
            raise ValueError('original source type/size')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(row['bytes'] + 1)
        key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if key(before) != key(os.fstat(fd)):
            raise ValueError('original source drift')
    finally:
        os.close(fd)
    if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
        raise ValueError('original source hash: ' + name)
    return raw.decode()

def replace(raw, old, new):
    if raw.count(old) != 1:
        raise ValueError('one exact derivative seam required: ' + old[:100])
    return raw.replace(old, new)

def function(raw, name, body):
    nodes = [n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(nodes) != 1:
        raise ValueError('one exact function required')
    node = nodes[0]
    lines = raw.splitlines(keepends=True)
    lines[node.lineno - 1:node.end_lineno] = [body]
    return ''.join(lines)

def text(source, name):
    raw = read(source, OLD + name)
    if name == 'contract.py':
        raw = replace(raw, "ROLES={'runtime':'cachy-asahi-repository-runtime','apps':'cachy-asahi-apps','cache':'cachy-asahi-cache'}",
                      "ROLES={'runtime':'cachy-asahi-repository-runtime','client':'cachy-asahi-repository-client-v3'}")
        raw = raw.replace('Root final runtime/apps/cache sources, versions and payloads remain UNBOUND', 'Root final Runtime/client-v3 sources, versions and payloads remain UNBOUND').replace('final ctypes Cache requires no extra dependency input', 'closed component has no extra dependency input')
        raw = replace(raw, "LABEL='org.cachy-asahi.apps-cache-native.job'", "LABEL='org.cachy-asahi.client-v3-native.job'")
        raw = replace(raw, "    if name==ROLES['apps']:need(ROLES['runtime']+'='+row(ROLES['runtime'])['version'] in meta.get('depends',[]),'exact runtime dependency required')\n", '')
        raw = replace(raw, "if name==ROLES['cache']:need(meta.get('depends')==['python>=3.11','pacman'],'final ctypes Cache dependency set differs')",
                      "if name==ROLES['client']:need(meta.get('depends')==['python>=3.11','cachy-asahi-repository-runtime=0.1.0-1'],'exact unchanged Runtime1 dependency required')")
        raw = replace(raw, "    return value\n\n\ndef verify_source", "    need(value.get('purpose')=='CLIENT_V3_RUNTIME_FRESH_COMPONENT_V1' and {k:r['version'] for k,r in value['products'].items()}=={'runtime':'0.1.0-1','client':'0.1.0-1'} and value.get('retained_input_carrier')=='3856733787d10820ab73f842e9f2bbf4fdb84181','exact two product identities and Root-qualified carrier required')\n    return value\n\n\ndef verify_source")
        raw = function(raw, 'validate_lifecycle', "def validate_lifecycle(value):\n from rules import validate\n from types import SimpleNamespace\n return validate(SimpleNamespace(need=need,re=re,ROLES=ROLES),value)\n")
    elif name == 'run.py':
        raw = replace(raw, 'import contract as C\n', 'import contract as C\nimport adapter as A\n')
        raw = function(raw, 'execute', _run_body(raw))
    elif name == 'job.py':
        raw = replace(raw, 'import contract as C\n', 'import contract as C\nimport adapter as A\n')
        raw = replace(raw, "    old.manifest_files(source,C.read(C.HERE/'source-manifest.json'))\n", "    old.manifest_files(source,C.read(C.HERE/'source-manifest.json'))\n    A.cleanup_parent(runtime)\n")
        raw = replace(raw, "for name in ('base-inventory.log','lifecycle.log','catalog-fixture.log','runtime-dependency-image-install.log','runtime-dependency-image-commit.log'):",
                      "for name in ('base-inventory.log','lifecycle.log','runtime-dependency-image-install.log','runtime-dependency-image-commit.log'):")
        start = raw.index("    fixture=runtime/'catalog-fixture'\n")
        end = raw.index('    try:\n        C.verify_source(source);report=', start)
        raw = raw[:start] + raw[end:]
        raw = replace(raw, "[('base-consumers',8),('apps-consumers',2)]", "[('base-consumers',5),('apps-consumers',2)]")
        if raw.count('PASS_NATIVE_APPS_RUNTIME_CACHE_PAIRS_AND_INSTALLED_LIFECYCLE') != 1:
            raise ValueError('one parent result join required')
        raw = raw.replace('PASS_NATIVE_APPS_RUNTIME_CACHE_PAIRS_AND_INSTALLED_LIFECYCLE', 'PASS_NATIVE_RUNTIME_CLIENT_V3_PAIRS_AND_FRESH_LIFECYCLE')
        raw = replace(raw, "result.update(status='PASS_NATIVE_UNSELECTED_APPS_RUNTIME_CACHE_CANDIDATES',cache_cleanup='APPLIED_DISPOSABLE_FIXTURES_ONLY',cache_apply='PASS_REAL_ALPM16_EMPTY_TRANSACTION')",
                      "result.update(status='PASS_NATIVE_RUNTIME_CLIENT_V3_FRESH_COMPONENT',cache_cleanup='NOT_RUN',client_v3='PASS_REAL_SIGNED_CHECKPOINT_COMPONENT_ONLY',version_upgrade='NOT_RUN')")
        raw = replace(raw, "'PASS_NATIVE_UNSELECTED_APPS_RUNTIME_CACHE_CANDIDATES'", "'PASS_NATIVE_RUNTIME_CLIENT_V3_FRESH_COMPONENT'")
        raw = raw.replace('six clean native build bindings required', 'four clean native build bindings required')
        marker = "    try:\n        C.verify_source(source);report=C.read(runtime/'report.json');C.validate_lifecycle(report['lifecycle'])\n"
        extra = "    A.forward_runners(C, runtime, copy, result)\n"

        raw = replace(raw, marker, extra + marker)
    else:
        raise ValueError('finite native derivative name required')
    return raw

def _run_body(raw):
    node = next(n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == 'execute')
    body = ''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
    start = body.index('    def runner_context(context):\n')
    end = body.index('    def dependency_image(', start)
    body = body[:start] + '    def runner_context(context):return A.runner(source,context)\n' + body[end:]
    body = replace(body, "for name in (C.ROLES['runtime'],C.ROLES['cache'])", "for name in (C.ROLES['runtime'],)")
    body = replace(body, "C.recipe(source,C.ROLES['apps'])", "C.recipe(source,C.ROLES['client'])")
    body = replace(body, "        products[C.ROLES['apps']]=build_pair(C.ROLES['apps'],runtime_image,runtime_base,runtime_lock,apps_actors)\n        products[C.ROLES['cache']]=build_pair(C.ROLES['cache'],image,base,lock,base_actors)",
                   "        products[C.ROLES['client']]=build_pair(C.ROLES['client'],runtime_image,runtime_base,runtime_lock,apps_actors)")
    start = body.index("        fixture_source=out/'fixture-source'\n")
    end = body.index("        actor='cachy-asahi-product-lifecycle-'", start)
    body = body[:start] + '        public_tree(life)\n' + body[end:]
    body = replace(body, "scope='THREE_UNSELECTED_APPS_RUNTIME_CACHE_CANDIDATES'", "scope='TWO_UNSELECTED_RUNTIME_CLIENT_V3_FRESH_COMPONENT'")
    body = replace(body, "report.update(status='PASS_NATIVE_APPS_RUNTIME_CACHE_PAIRS_AND_INSTALLED_LIFECYCLE',lifecycle=lifecycle,cache_cleanup='APPLIED_DISPOSABLE_FIXTURES_ONLY'",
                   "report.update(status='PASS_NATIVE_RUNTIME_CLIENT_V3_PAIRS_AND_FRESH_LIFECYCLE',lifecycle=lifecycle,cache_cleanup='NOT_RUN'")
    return body

def module(source, name):
    result = types.ModuleType('client_v3_native_' + name.replace('.', '_'))
    result.__file__ = str(HERE / name)
    sys.modules[result.__name__] = result
    exec(compile(text(source, name), result.__file__, 'exec'), result.__dict__)
    return result

def runner(source, context):
    runner = context / 'runner'
    runner.mkdir()
    accepted = runner / 'accepted'
    accepted.mkdir()
    (runner / 'contract.py').write_text(text(source, 'contract.py'))
    for name in ('lifecycle.py', 'installed.py', 'runtime_image.py', 'rules.py', 'installed_v3.py', 'rename_after_real_verification.py', 'input-policy.json'):
        shutil.copyfile(HERE / name, runner / name)
    for name, original in [('lifecycle.py', 'scripts/ci/welcome-native/lifecycle.py'), ('root_upgrade.py', 'scripts/ci/full-root-upgrade/root_upgrade.py')]:
        shutil.copyfile(source / original, accepted / name)
    fixture = runner / 'fixture-client'
    fixture.mkdir()
    for name in ('test_client_v2.py', 'client_v2.py'):
        shutil.copyfile(source / 'scripts/client' / name, fixture / name)
    rows = {}
    for path in sorted(runner.rglob('*')):
        if path.is_file():
            path.chmod(0o644)
            raw = path.read_bytes()
            rows[path.relative_to(runner).as_posix()] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), mode=0o644)
    if len(rows) != 12:
        raise ValueError('exact complete twelve-file runtime runner required')
    (context / 'runner-derivations.json').write_text(json.dumps(dict(schema=1, status='SOURCE_CLOSED_ACTUAL_RUNTIME_RUNNER_DATA', files=rows), sort_keys=True, indent=2) + '\n')
    return runner


RUNNER_NAMES = frozenset(('contract.py','lifecycle.py','installed.py','runtime_image.py','rules.py',
    'installed_v3.py','rename_after_real_verification.py','input-policy.json','accepted/lifecycle.py',
    'accepted/root_upgrade.py','fixture-client/test_client_v2.py','fixture-client/client_v2.py'))

def cleanup_parent(runtime):
    """Create only this owned report parent; forwarding is never a cleanup prerequisite."""
    runtime = Path(runtime)
    if not runtime.is_absolute() or any(p.is_symlink() for p in (runtime,*runtime.parents)):
        raise ValueError('ordinary owned cleanup report parent required')
    if not runtime.exists(): runtime.mkdir(mode=0o700)
    info = runtime.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('private owned cleanup report parent required')

def forward_runners(C, runtime, copy, result):
    """Only retained actual bytes may satisfy positive forwarding; preserve failures as DATA."""
    for role,context in [('runtime-dependency',runtime/'runtime-context'),('lifecycle',runtime/'lifecycle-inputs')]:
        try:
            proof = C.read(context/'runner-derivations.json')
            C.need(type(proof) is dict and set(proof)=={'schema','status','files'} and type(proof['schema']) is int and proof['schema']==1
                and proof['status']=='SOURCE_CLOSED_ACTUAL_RUNTIME_RUNNER_DATA' and type(proof['files']) is dict
                and set(proof['files'])==RUNNER_NAMES,'complete actual runner forwarding required')
            copy(context/'runner-derivations.json','emitted/'+role+'/runner-derivations.json',65536)
            for name,row in proof['files'].items():
                C.need(type(row) is dict and set(row)=={'bytes','sha256','mode'} and type(row['bytes']) is int and 0<row['bytes']<=2*1024**2
                    and type(row['mode']) is int and row['mode']==0o644,'bounded actual runner row required')
                path=context/'runner'/name
                C.need(not path.is_symlink() and all(not p.is_symlink() for p in path.parents) and stat.S_ISREG(path.lstat().st_mode)
                    and path.stat().st_nlink==1 and stat.S_IMODE(path.stat().st_mode)==row['mode'] and path.stat().st_size==row['bytes']
                    and C.digest(path)==row['sha256'],'actual runner bytes differ')
                copy(path,'emitted/'+role+'/runner/'+name,2*1024**2)
        except Exception as error:
            # Negative artifacts remain complete/honest; success still requires errors==[].
            result['errors'].append('emitted/'+role+'/runner: '+type(error).__name__)
