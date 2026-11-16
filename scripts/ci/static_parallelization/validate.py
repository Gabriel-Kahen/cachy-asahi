#!/usr/bin/env python3
"""Offline preservation/routing proof; runs syntax checks, never suite commands.

Needs PyYAML or fy-tool for real YAML parsing. The baseline must be the
pre-sharding commit, not the current parent after subsequent integrations.
"""
import argparse
import ast
from collections import Counter
from copy import deepcopy
import itertools
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = '.github/workflows/static.yml'
SHARDS = ['foundation', 'source-data', 'desktop', 'composition']
BASE = 'fd374f605cc51381a8c787549b9e15c424c9f48e'


def yaml_load(raw):
    try:
        import yaml
    except ImportError:
        return json.loads(subprocess.check_output(
            ['fy-tool', '--yaml-1.2', '-m', 'json'], input=raw))
    return yaml.load(raw, Loader=yaml.BaseLoader)


def expression(raw, context):
    """Evaluate the actual bounded workflow predicates, rejecting other syntax."""
    code = raw.removeprefix('${{').removesuffix('}}').strip()
    for key in sorted(set(context) - {'cancelled'}, key=len, reverse=True):
        code = code.replace(key, repr(context[key]))
    code = code.replace('&&', ' and ').replace('||', ' or ')
    code = re.sub(r'!(?!=)', ' not ', code).strip()
    functions = {'fromJSON': json.loads, 'always': lambda: True,
                 'cancelled': lambda: context['cancelled']}
    tree = ast.parse(code, mode='eval')
    permitted = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare,
                 ast.Eq, ast.NotEq, ast.Constant, ast.Call, ast.Name, ast.Load,
                 ast.UnaryOp, ast.Not)
    for node in ast.walk(tree):
        assert isinstance(node, permitted), ast.dump(node)
        if isinstance(node, ast.Name):
            assert node.id in functions, node.id
        if isinstance(node, ast.Call):
            assert isinstance(node.func, ast.Name) and not node.keywords
    return eval(compile(tree, '<workflow predicate>', 'eval'),
                {'__builtins__': {}}, functions)


def context(event='pull_request', measure=False, phase='normal',
            seed='skipped', result='success', cancelled=False, shard='all'):
    return {'github.event_name': event, 'inputs.measure-cache': measure,
            'inputs.setup-phase': phase, 'needs.cache-seed.result': seed,
            'needs.checks.result': result, 'matrix.shard': shard,
            'cancelled': cancelled}


def selected(step, shard, **kwargs):
    return expression(step.get('if', '${{ always() }}'),
                      context(shard=shard, **kwargs))


def encoded(step):
    return json.dumps(step, sort_keys=True)


def validate(baseline, current):
    old, new = baseline['jobs']['checks'], current['jobs']['checks']
    original, routed = old['steps'], deepcopy(new['steps'])
    assert len(original) == len(routed)
    # Compare the entire step, including env, working-directory, timeouts,
    # action pins and all with arguments, allowing only new routing predicates.
    for before, after in zip(original, routed):
        if 'if' not in before:
            after.pop('if', None)
        assert before == after, before.get('name', before.get('uses'))
    for key in ('needs', 'if', 'runs-on'):
        assert old[key] == new[key]
    for key in baseline:
        if key != 'jobs':
            assert baseline[key] == current[key], key
    assert set(current['jobs']) == set(baseline['jobs']) | {'static-result'}
    for key in baseline['jobs']:
        if key != 'checks':
            assert baseline['jobs'][key] == current['jobs'][key], key
    assert new['strategy']['fail-fast'] in (False, 'false')
    matrix = new['strategy']['matrix']['shard']
    for event, measure, phase in itertools.product(
            ('push', 'pull_request', 'workflow_dispatch'), (False, True),
            ('normal', 'warm')):
        measured = (event == 'workflow_dispatch' and measure) or phase == 'warm'
        assert expression(matrix, context(event, measure, phase)) == (
            ['all'] if measured else SHARDS)
        assert expression(new['if'], context(event, measure, phase)) == (
            not (event == 'workflow_dispatch' and measure))
        assert expression(new['if'], context(event, measure, phase, seed='success')) == (
            event == 'workflow_dispatch' and measure)
        for bad in ('failure', 'cancelled'):
            assert not expression(new['if'], context(event, measure, phase, seed=bad))
        assert not expression(new['if'], context(event, measure, phase, cancelled=True))

    steps = new['steps']
    membership = [{s for s in SHARDS if selected(step, s)} for step in steps]
    for index, step in enumerate(steps):
        assert selected(step, 'all', event='workflow_dispatch', measure=True)
        assert selected(step, 'all', event='workflow_dispatch', phase='warm')
        if index < 2:
            assert membership[index] == set(SHARDS)
        elif index == len(steps) - 1:
            assert not membership[index]  # original measurement-only report
        elif 'run' in step:
            assert len(membership[index]) == 1, step['name']
        else:
            assert membership[index], step['name']

    # Every normal suite command runs once; only bounded setup/checkouts repeat.
    expected = Counter(encoded(s) for s in original[2:-1] if 'run' in s)
    actual = Counter(encoded(routed[i]) for i in range(2, len(steps)-1)
                     if 'run' in routed[i] for _ in membership[i])
    assert actual == expected
    checkout_copies = {s['with']['path']: len(membership[i])
                       for i, s in enumerate(steps)
                       if 'path' in s.get('with', {}) and len(membership[i]) > 1}
    assert checkout_copies == {'.ci-inputs/historical604-runtime': 2,
                              '.ci-inputs/historical-inventory-input-basis': 3}

    # Checkout and stable temporary-tree producers must precede every consumer
    # on the same shard. These are real paths extracted from the parsed steps.
    paths = {s['with']['path'] for s in steps if 'path' in s.get('with', {})}
    for step in steps:
        paths.update(re.findall(r'(?:\$RUNNER_TEMP/|\$\{\{ runner.temp \}\}/)([\w-]+)',
                                encoded(step)))
    edges = 0
    for path in paths:
        references = [i for i, step in enumerate(routed) if path in encoded(step)]
        producer = references[0]
        for consumer in references[1:]:
            assert membership[consumer] <= membership[producer], (path, producer, consumer)
            edges += 1
    # Git objects and staged Setup5 DATA are also prerequisites of passive replay.
    def index(prefix):
        matches = [i for i, step in enumerate(steps)
                   if step.get('name', '').startswith(prefix)]
        assert len(matches) == 1, prefix
        return matches[0]
    replay = index('Check Apps transactions')
    for prefix in ('Fetch exact updater sources', 'Checkout exact accepted Setup5',
                   'Stage the149', 'Fetch three exact passive',
                   'Stage exact accepted Setup5 data'):
        producer = index(prefix)
        assert producer < replay and membership[replay] <= membership[producer]

    aggregate = current['jobs']['static-result']
    assert aggregate['name'] == 'checks'
    assert aggregate['needs'] == ['cache-seed', 'checks']
    assert aggregate['if'] == '${{ always() }}'
    assert new['name'] == 'Static ${{ matrix.shard }}'
    gate = aggregate['steps'][0]
    cases = 0
    for measure, cancelled, seed, result in itertools.product(
            (False, True), (False, True),
            ('success', 'failure', 'skipped', 'cancelled'),
            ('success', 'failure', 'skipped', 'cancelled')):
        ctx = context(event='workflow_dispatch', measure=measure, seed=seed,
                      result=result, cancelled=cancelled)
        env = {k: str(expression(v, ctx)).lower() for k, v in gate['env'].items()}
        code = subprocess.run(['bash', '-e', '-c', gate['run']],
                              env=dict(os.environ, **env), capture_output=True).returncode
        assert (code == 0) == (not cancelled and result == 'success' and
                              seed == ('success' if measure else 'skipped')), env
        cases += 1

    blocks = 0
    for job in current['jobs'].values():
        for step in job.get('steps', []):
            if 'run' in step:
                shell = re.sub(r'\$\{\{.*?\}\}', 'workflow_value', step['run'])
                subprocess.run(['bash', '-n'], input=shell.encode(), check=True)
                blocks += 1
    print(json.dumps(dict(status='PASS_OFFLINE_PRESERVATION_AND_ROUTING',
          original_steps=len(original), suite_run_blocks=sum(expected.values()),
          preserved_step_sequence_sha256=hashlib.sha256(encoded(original).encode()).hexdigest(),
          shell_blocks_checked=blocks, dependency_edges=edges, aggregate_cases=cases,
          active_steps={s: sum(s in row for row in membership) for s in SHARDS},
          repeated_historical_checkouts=checkout_copies), sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-ref', default=BASE)
    args = parser.parse_args()
    raw = subprocess.check_output(['git', 'show', args.baseline_ref + ':' + WORKFLOW], cwd=ROOT)
    validate(yaml_load(raw), yaml_load((ROOT / WORKFLOW).read_bytes()))
