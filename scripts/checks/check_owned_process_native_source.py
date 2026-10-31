#!/usr/bin/env python3
"""Join the manual workflow's literal runtime guard to real Git and checkout DATA.

Never execute or import the workflow's inline Python or the native Source code.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

WORKFLOW = '.github/workflows/native-arm-owned-process-control.yml'
CHECKOUT = 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
REPOSITORY = 'Gabriel-Kahen/cachy-asahi'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def dump(node):
    return ast.dump(node, include_attributes=False)


def checkout_materialization(workflow):
    job = workflow['jobs']['adopted-zero-control']
    inherited = dict(workflow.get('env', {}), **job.get('env', {}))
    require(inherited.get('GIT_NO_LAZY_FETCH') == '1', 'post-checkout global lazy-fetch denial must remain')
    checkouts = [s for s in job['steps'] if s.get('uses', '').startswith('actions/checkout@')]
    require(len(checkouts) == 2 and all(s['uses'] == CHECKOUT for s in checkouts), 'two pinned production checkouts required')
    effective = [dict(inherited, **s.get('env', {})).get('GIT_NO_LAZY_FETCH') for s in checkouts]
    require(effective == ['0', '0'], 'both checkout steps must permit lazy blob materialization')
    return effective


def contract(body):
    workflow = json.loads(body)
    checkout_environment = checkout_materialization(workflow)
    steps = workflow['jobs']['adopted-zero-control']['steps']
    guards = [s for s in steps if s.get('id') == 'source_guard']
    require(len(guards) == 1, 'exactly one production source_guard required')
    match = re.fullmatch(r"set -euo pipefail\npython -I -B - <<'PYGUARD'\n(.*)\nPYGUARD", guards[0]['run'], re.S)
    require(match is not None, 'unrecognized guard envelope; update passive parser')
    tree = ast.parse(match[1])
    git_functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'git']
    require(len(git_functions) == 1, 'one passive production Git helper required')
    readers = [n for n in ast.walk(git_functions[0]) if isinstance(n, ast.Call)
               and dump(n.func) == dump(ast.parse('subprocess.check_output', mode='eval').body)]
    require(len(readers) == 1, 'one explicit passive Git invocation required')
    environments = [k.value for k in readers[0].keywords if k.arg == 'env']
    require(len(environments) == 1 and isinstance(environments[0], ast.Call)
            and isinstance(environments[0].func, ast.Name) and environments[0].func.id == 'dict'
            and [ast.literal_eval(k.value) for k in environments[0].keywords if k.arg == 'GIT_NO_LAZY_FETCH'] == ['1'],
            'passive guard Git reads must explicitly disable lazy fetch')
    calls = [n.value for n in ast.walk(tree) if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Subscript) and isinstance(n.targets[0].value, ast.Name)
             and n.targets[0].value.id == 'value' and isinstance(n.targets[0].slice, ast.Constant)
             and n.targets[0].slice.value == 'runtime']
    require(len(calls) == 1, 'exactly one runtime file guard required')
    call = calls[0]
    require(isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
            and call.func.id == 'file' and len(call.args) == 3 and not call.keywords, 'literal file guard required')
    name, expected, mode = call.args
    require(isinstance(expected, ast.Call) and isinstance(expected.func, ast.Name)
            and expected.func.id == 'dict' and not expected.args, 'literal pin dictionary required')
    pin = {k.arg: ast.literal_eval(k.value) for k in expected.keywords}
    require(len(expected.keywords) == 2 and set(pin) == {'bytes', 'sha256'}, 'exact body pin fields required')
    name, mode = ast.literal_eval(name), ast.literal_eval(mode)
    require(type(name) is str and type(mode) is int and mode in (0o644, 0o755), 'ordinary file mode required')
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and len(path.parts) >= 2, 'unsafe runtime path')
    require(type(pin['bytes']) is int and 0 < pin['bytes'] <= 1024**2
            and re.fullmatch('[0-9a-f]{64}', pin['sha256']), 'bounded literal body pin required')
    data_path = path.parts[0]
    checkouts = [s for s in steps if s.get('with', {}).get('path') == data_path]
    require(len(checkouts) == 1, 'runtime guard must identify one actual DATA checkout')
    checkout = checkouts[0]
    source = checkout['with']['ref']
    require(checkout.get('uses') == CHECKOUT and checkout['with'].get('repository') == REPOSITORY
            and checkout['with'].get('persist-credentials') is False
            and re.fullmatch('[0-9a-f]{40}', source), 'exact pinned Source checkout required')
    relative = str(PurePosixPath(*path.parts[1:]))
    require(checkout['with'].get('sparse-checkout') == relative, 'checkout/runtime path disagreement')
    values = [n.value for n in tree.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == 'value' for t in n.targets)]
    require(len(values) == 1 and isinstance(values[0], ast.Call) and dump(values[0].func) == dump(ast.Name(id='dict', ctx=ast.Load())), 'provenance dictionary required')
    sources = [ast.literal_eval(k.value) for k in values[0].keywords if k.arg == 'runtime_source']
    require(sources == [source], 'checkout and provenance Source disagree')
    require(any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'data' for t in n.targets)
                and dump(n.value) == dump(ast.parse('workspace/' + repr(data_path), mode='eval').body)
                for n in ast.walk(tree)), 'guard DATA root disagrees with checkout')
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'file']
    require(len(functions) == 1, 'one ordinary file predicate required')
    for target, expression in (('p', 'workspace/name'), ('s', 'p.lstat()')):
        require(any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == target for t in n.targets)
                    and dump(n.value) == dump(ast.parse(expression, mode='eval').body)
                    for n in ast.walk(functions[0])), 'file predicate must inspect the actual named path')
    predicates = {dump(n) for a in ast.walk(functions[0]) if isinstance(a, ast.Assert) for n in ast.walk(a.test)}
    for expression in ('p==p.resolve()', 'stat.S_ISREG(s.st_mode)', 's.st_nlink==1',
                       'stat.S_IMODE(s.st_mode)==mode', "s.st_size==expected['bytes']", 'pin(b)==expected'):
        require(dump(ast.parse(expression, mode='eval').body) in predicates, 'missing physical file predicate: ' + expression)
    require(any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'b' for t in n.targets)
                and dump(n.value) == dump(ast.parse('p.read_bytes()', mode='eval').body)
                for n in ast.walk(functions[0])), 'file predicate must hash actual file bytes')
    pins = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'pin']
    expected_pin = ast.parse('def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())').body[0]
    require(len(pins) == 1 and dump(pins[0]) == dump(expected_pin), 'unrecognized body pin predicate')
    head_check = ast.parse("git(data,'rev-parse','HEAD')==value['runtime_source']", mode='eval').body
    require(any(isinstance(n, ast.Assert) and dump(n.test) == dump(head_check) for n in ast.walk(tree)), 'production Source HEAD guard missing')
    return dict(source=source, checkout=data_path, path=relative, mode=mode,
                checkout_lazy_fetch=checkout_environment, **pin)


def git(root, *args):
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1', GIT_OPTIONAL_LOCKS='0',
               GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
    return subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
                                    '-C', str(root), *args], env=env, timeout=15)


def git_source(root, guard):
    source = guard['source']
    require(git(root, 'cat-file', '-t', source) == b'commit\n', 'Source is not an actual commit')
    require(int(git(root, 'cat-file', '-s', source)) <= 1024**2, 'bounded raw commit required')
    raw = git(root, 'cat-file', 'commit', source)
    require(hashlib.sha1(b'commit ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == source, 'raw Source commit identity')
    row = git(root, 'ls-tree', '-z', source, '--', guard['path'])
    fields, name = row.rstrip(b'\0').split(b'\t')
    mode, kind, oid = fields.decode().split()
    require(name.decode() == guard['path'] and row.count(b'\0') == 1 and kind == 'blob', 'exact ordinary Git leaf required')
    require(mode in ('100644', '100755') and int(mode, 8) & 0o777 == guard['mode'], 'workflow mode differs from real Source Git mode')
    require(int(git(root, 'cat-file', '-s', oid)) == guard['bytes'], 'real Git blob size differs')
    body = git(root, 'cat-file', 'blob', oid)
    require(len(body) == guard['bytes'] and hashlib.sha256(body).hexdigest() == guard['sha256'], 'workflow body pin differs from Source blob')
    require(hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest() == oid, 'raw blob identity')
    return dict(source=source, tree=git(root, 'rev-parse', source + '^{tree}').decode().strip(),
                raw_commit_sha256=hashlib.sha256(raw).hexdigest(), git_mode=mode, blob=oid, **{k: guard[k] for k in ('bytes', 'sha256')})


def physical_file(root, guard):
    root = root.resolve()
    path = root / guard['path']
    info = path.lstat()
    require(path == path.resolve() and stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'ordinary unaliased physical checkout leaf required')
    require(stat.S_IMODE(info.st_mode) == guard['mode'] and info.st_size == guard['bytes'], 'physical checkout metadata differs')
    require(hashlib.sha256(path.read_bytes()).hexdigest() == guard['sha256'], 'physical checkout body differs')


def check(workspace, workflow_sha):
    require(re.fullmatch('[0-9a-f]{40}', workflow_sha), 'exact workflow checkout SHA required')
    require(git(workspace, 'rev-parse', 'HEAD').decode().strip() == workflow_sha, 'workflow checkout HEAD differs')
    allowed = ('https://github.com/' + REPOSITORY, 'git@github.com:' + REPOSITORY)
    for folder in (workspace,):
        require(git(folder, 'remote', 'get-url', 'origin').decode().strip().removesuffix('.git') in allowed, 'workflow repository provenance')
    workflow_path = workspace / WORKFLOW
    info = workflow_path.lstat()
    require(workflow_path == workflow_path.resolve() and stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1 and info.st_size <= 1024**2, 'ordinary bounded production workflow required')
    body = workflow_path.read_bytes()
    require(body == git(workspace, 'show', workflow_sha + ':' + WORKFLOW), 'production workflow differs from actual HEAD')
    guard = contract(body)
    source_root = workspace / guard['checkout']
    require(source_root == source_root.resolve(), 'Source checkout root aliases another path')
    require(git(source_root, 'rev-parse', 'HEAD').decode().strip() == guard['source'], 'actual Source checkout HEAD differs')
    require(git(source_root, 'rev-parse', '--show-toplevel').decode().strip() == str(source_root), 'Source must have its own checkout')
    require(git(source_root, 'remote', 'get-url', 'origin').decode().strip().removesuffix('.git') in allowed, 'Source repository provenance')
    proof = git_source(source_root, guard)
    physical_file(source_root, guard)
    return dict(status='PASS_REAL_SOURCE_GIT_AND_CHECKOUT_DATA_JOIN', workflow_source=workflow_sha,
                workflow_sha256=hashlib.sha256(body).hexdigest(), derived_guard=guard, source=proof,
                native_runtime_executed=False, native_acceptance=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--workflow-sha', required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.workspace.resolve(), args.workflow_sha), sort_keys=True, indent=2))
