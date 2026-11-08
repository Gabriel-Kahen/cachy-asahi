#!/usr/bin/env python3
"""New synthetic DATA controls. Execute only explicitly extracted new pure helpers."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
LABEL = 'org.cachy-asahi.native-developer'
OPERATION = 'source-tools-alpm-v1'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def pin(body):
    return dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def encoded(value):
    return json.dumps(value, sort_keys=True, allow_nan=False).encode()


def helpers(name, names):
    source = (ROOT / ('overlay' if name == 'owner.py' else 'producer-overlay') / 'native' / name).read_text()
    nodes = [node for node in ast.parse(source).body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    need({node.name for node in nodes} == set(names), 'exact new helper closure')
    namespace = dict(need=need, pin=pin, json=json, re=re, hashlib=hashlib,
                     LABEL=LABEL, OPERATION=OPERATION)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<new-pure-data-helpers>', 'exec'), namespace)
    return namespace


A = helpers('source_tools_alpm_v1.py', ['unknown_image_build_context', 'image_build_context'])
O = helpers('owner.py', ['build_policy_declared', '_image_build_policy_identity',
                        'unknown_image_build_policy', 'image_build_policy_receipt'])
R = helpers('source_tools_reader_v1.py', ['build_policy_declared', 'source_tools_build_policy_data'])
MAP = 'a' * 64
BINDING = dict(source='b' * 40, ref='refs/heads/codex/policy-data', run='123', attempt=1)
BINDING['token'] = hashlib.sha256((':'.join(BINDING[k] for k in ('source', 'ref', 'run'))).encode()).hexdigest()[:24]
ARGV = ['/usr/bin/docker', '--host=unix:///var/run/docker.sock', 'build', '--network=none',
        '--pull=false', '--no-cache', '--platform=linux/arm64', '--tag',
        'native-developer-tools:' + BINDING['token'], '--label', LABEL + '=' + BINDING['token'],
        '--label', LABEL + '.source=' + BINDING['source'], '--iidfile', '/owned/id', '/owned/context']
VALUES = {key: None for key in ('uid', 'euid', 'gid', 'egid', 'cwd', 'groups', 'group_count',
          'groups_truncated', 'status_fields', 'status_state', 'namespaces', 'maps', 'policy', 'lsm', 'mounts', 'bwrap')}
VALUES.update(uid=1001, euid=1001, gid=1001, egid=1001, cwd='/owned/build', groups=[998, 1001],
              group_count=2, groups_truncated=False, status_fields={'Seccomp': '2'},
              policy={'effective_rules': 'UNKNOWN'}, lsm={'current': 'docker-default (enforce)'})
OBSERVED = dict(schema=1, status='NAMESPACE_PREREQUISITE_DATA_ONLY', mode='context',
                source_map_sha256=MAP, before=VALUES, after=copy.deepcopy(VALUES), syscall=None,
                scope='OWN_BUILD_ACTOR_SELF_ONLY_NO_CHILD_OR_GLOBAL_MUTATION',
                namespace_acceptance='NOT_ESTABLISHED', native_acceptance='NOT_ADMITTED')
CONTEXT_LOG = '004-namespace-a-context.log'
CONTEXT_PIN = pin(encoded(OBSERVED))


class View:
    def __init__(self, bodies):
        self.bodies = bodies

    def read(self, name):
        return self.bodies[name]

    def load(self, name):
        return json.loads(self.read(name))


def fixture(context_kind='observed'):
    context = (A['image_build_context'](OBSERVED, MAP, 4, CONTEXT_LOG, CONTEXT_PIN)
               if context_kind == 'observed' else A['unknown_image_build_context'](MAP))
    row = dict(argv=list(ARGV), public_log='actor-logs/0035.log', log_pin=pin(b'original build log\n'))
    actors = [dict(argv=['earlier-actor'])] * 3 + [row]
    operations = [dict(role='tools', terminal=True, actor=row)]
    policy = O['image_build_policy_receipt'](BINDING, MAP, actors, operations, context)
    receipt = dict(binding=copy.deepcopy(BINDING), source_map_sha256=MAP, actors=actors, image_build_policy=policy)
    commands = [{} for _ in range(4)] + [dict(log=CONTEXT_LOG, log_pin=CONTEXT_PIN)]
    report = dict(operation=OPERATION, source_map_sha256=MAP, image_build_context=context,
                  commands=commands, namespace_observations={'a': dict(observations=[
                      dict(mode='context', command_index=4, output=CONTEXT_PIN)])})
    bodies = {'receipt.json': encoded(receipt), 'cleanup.json': encoded(dict(build_operations=operations)),
              row['public_log']: b'original build log\n',
              'journey/source-tools-alpm-v1/result.json': encoded(report),
              'journey/source-tools-alpm-v1/' + CONTEXT_LOG: encoded(OBSERVED)}
    return receipt, bodies


def read_policy(receipt, bodies, corrupt=None):
    files = {name: dict(kind='file', **pin(body)) for name, body in bodies.items()}
    selected = {name: pin(body) for name, body in bodies.items()}
    if corrupt:
        corrupt(files, selected, bodies)
    bodies = dict(bodies, **{'public-projection.json': encoded(dict(selected=selected))})
    return R['source_tools_build_policy_data'](View(bodies), files, receipt, BINDING, MAP)


RESULTS = []


def check(name, function, refuses=False):
    try:
        function()
    except (ValueError, KeyError, TypeError) as error:
        if not refuses:
            raise
        RESULTS.append(dict(name=name, result='PASS_REFUSED', error_type=type(error).__name__))
    else:
        need(not refuses, name + ': failed to refuse')
        RESULTS.append(dict(name=name, result='PASS'))


def changed_context(**changes):
    value = copy.deepcopy(OBSERVED); value.update(changes)
    return A['image_build_context'](value, MAP, 4, CONTEXT_LOG, CONTEXT_PIN)


def changed_fixture(change):
    receipt, bodies = fixture()
    change(receipt, bodies)
    bodies['receipt.json'] = encoded(receipt)
    return read_policy(receipt, bodies)


def report_change(key, value):
    def mutate(receipt, bodies):
        name = 'journey/source-tools-alpm-v1/result.json'
        report = json.loads(bodies[name]); report[key] = value; bodies[name] = encoded(report)
    return mutate


def unknown_receipt():
    return dict(binding=copy.deepcopy(BINDING), source_map_sha256=MAP,
                image_build_policy=O['unknown_image_build_policy'](BINDING, MAP))


check('context copies without resampling', lambda: need(changed_context()['values'] == VALUES, 'copy'))
check('context wrong domain mode refused', lambda: changed_context(mode='user'), True)
check('context wrong map refused', lambda: changed_context(source_map_sha256='c'*64), True)
check('context changed after refused', lambda: changed_context(after={}), True)
check('context syscall attribution refused', lambda: changed_context(syscall={'errno': 1}), True)
check('context typed UNKNOWN', lambda: need(A['unknown_image_build_context'](MAP)['values'] is None, 'unknown'))
check('owner uses actual public log differing from index', lambda: need(fixture()[0]['image_build_policy']['build_actor']['public_log'] == 'actor-logs/0035.log', 'actual log'))
check('owner no tools is UNKNOWN', lambda: need(O['image_build_policy_receipt'](BINDING, MAP, [], [], None)['reason'] == 'NO_RETAINED_BUILD_ACTOR', 'unknown'))


def owner_without_log():
    row = dict(argv=ARGV)
    return O['image_build_policy_receipt'](BINDING, MAP, [row], [dict(role='tools', terminal=True, actor=row)], None)


check('owner missing log is UNKNOWN', lambda: need(owner_without_log()['reason'] == 'NO_RETAINED_BUILD_LOG', 'unknown'))
check('parser declared values', lambda: need(O['build_policy_declared'](ARGV) == R['build_policy_declared'](ARGV), 'identical parser'))
check('parser future security option DATA', lambda: need(R['build_policy_declared'](ARGV + ['--security-opt', 'seccomp=unconfined'])['security_options'] == ['seccomp=unconfined'], 'declared only'))
check('parser duplicate singleton refused', lambda: R['build_policy_declared'](ARGV + ['--network=host']), True)
check('parser empty option refused', lambda: R['build_policy_declared'](ARGV + ['--security-opt=']), True)
check('complete original DATA join', lambda: need(read_policy(*fixture())['native'] == 'NOT_ADMITTED', 'no uplift'))
check('typed UNKNOWN context joins', lambda: read_policy(*fixture('unknown')))
check('unknown receipt joins', lambda: read_policy(unknown_receipt(), {'receipt.json': encoded(unknown_receipt())}))
check('binding substitution refused', lambda: changed_fixture(lambda r, b: r['image_build_policy']['binding'].update(run='124')), True)
check('map substitution refused', lambda: changed_fixture(lambda r, b: r['image_build_policy'].update(source_map_sha256='c'*64)), True)
check('actor selector substitution refused', lambda: changed_fixture(lambda r, b: r['image_build_policy']['build_actor'].update(index=0)), True)
check('guessed log filename refused', lambda: changed_fixture(lambda r, b: r['image_build_policy']['build_actor'].update(public_log='actor-logs/0003.log')), True)
check('effective policy claim refused', lambda: changed_fixture(lambda r, b: r['image_build_policy']['policy_provenance'].update(effective_seccomp_rules='KNOWN')), True)
check('later consumer context refused', lambda: changed_fixture(report_change('image_build_context', dict(domain='LATER_CONSUMER'))), True)
check('missing seeded result context refused', lambda: changed_fixture(report_change('image_build_context', None)), True)
check('stale observation output pin refused', lambda: changed_fixture(report_change('namespace_observations', {'a': dict(observations=[dict(mode='context', command_index=4, output=pin(b'stale'))])})), True)
check('manifest projection pin mismatch refused', lambda: read_policy(*fixture(), corrupt=lambda f, s, b: s['actor-logs/0035.log'].update(sha256='0'*64)), True)
check('actual build log body mismatch refused', lambda: read_policy(*fixture(), corrupt=lambda f, s, b: b.update({'actor-logs/0035.log': b'substitute'})), True)
check('unknown standalone receipt forgery refused', lambda: read_policy(unknown_receipt(), {'receipt.json': encoded({})}), True)
print(json.dumps(dict(schema=1, status='PASS_NEW_PORTABLE_DATA_CONTROLS', controls=RESULTS,
                     count=len(RESULTS), full_module_imports=0, actual_reader_calls=0,
                     native_actors=0, old_controls=0, native='NOT_ADMITTED'), sort_keys=True, indent=2))
