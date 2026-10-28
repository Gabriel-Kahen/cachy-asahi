#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Durable offline maintenance receipts; never execute builds, sign or publish."""
import argparse
from contextlib import contextmanager, ExitStack
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'scripts/maintenance/update_plan.py').is_file())
MAX_JSON = 32 * 1024**2
MAX_EVENTS = 256
INPUTS = ('inventory', 'advisories', 'provenance', 'advisory_report', 'graph')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    need(len(raw) <= MAX_JSON, 'campaign JSON byte bound')
    return raw


def decode(raw):
    need(len(raw) <= MAX_JSON, 'campaign JSON byte bound')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('JSON floats/nonfinite numbers forbidden')
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(type(value) is dict, 'JSON object required')
    return value


def regular(path):
    path = Path(os.path.abspath(path))
    need(path == path.resolve() and path.is_file(), 'regular nonsymlink file required: ' + str(path))
    return path


def read(path):
    with regular(path).open('rb') as stream:
        raw = stream.read(MAX_JSON + 1)
    need(len(raw) <= MAX_JSON, 'campaign input byte bound')
    return raw


def digest(path):
    h = hashlib.sha256()
    with regular(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            h.update(block)
    return h.hexdigest()


def fields(value, keys):
    need(type(value) is dict and set(value) == set(keys.split()), 'unexpected/missing fields: ' + keys)


def selected(ref):
    fields(ref, 'path sha256')
    raw = read(ref['path'])
    need(type(ref['sha256']) is str and re.fullmatch('[0-9a-f]{64}', ref['sha256']) and
         sha(raw) == ref['sha256'], 'selected input checksum mismatch: ' + str(ref['path']))
    return raw


def implementation():
    # Conservative transitive source closure, including dynamically loaded siblings.
    result = {}
    for directory in ('build', 'checks', 'maintenance', 'release'):
        for path in sorted((ROOT / 'scripts' / directory).rglob('*')):
            if path.suffix in ('.py', '.sh'):
                result[str(path.relative_to(ROOT))] = digest(path)
    result['scripts/maintenance/campaign.py'] = digest(__file__)
    return result


def runtime():
    paths = [Path(sys.executable).resolve()]
    for name in ('bsdtar', 'vercmp'):
        path = shutil.which(name)
        need(path is not None, 'required existing tool unavailable: ' + name)
        paths.append(Path(path).resolve())
    return {str(p): digest(p) for p in paths}


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def synced(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(path, raw):
    """Publish immutable bytes without replacement, then persist the directory entry."""
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.pending-', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                need(read(path) == raw, 'immutable campaign record collision')
            synced(path.parent)
        finally:
            temporary.unlink()


class Store:
    def __init__(self, path):
        self.path = Path(os.path.abspath(path))

    def object(self, raw):
        checksum = sha(raw)
        create(self.path / 'objects' / (checksum + '.json'), raw)
        return checksum

    def bytes(self, checksum):
        need(type(checksum) is str and re.fullmatch('[0-9a-f]{64}', checksum), 'object hash required')
        raw = read(self.object_path(checksum))
        need(sha(raw) == checksum, 'campaign object drift')
        return raw

    def object_path(self, checksum):
        return self.path / 'objects' / (checksum + '.json')

    def value(self, checksum):
        return decode(self.bytes(checksum))

    @contextmanager
    def lock(self, fresh=False):
        need(self.path == self.path.resolve(), 'campaign directory aliases forbidden')
        if fresh:
            self.path.mkdir(mode=0o700)
            for name in ('objects', 'events'):
                (self.path / name).mkdir(mode=0o700)
            (self.path / '.lock').touch(mode=0o600)
            synced(self.path)
            synced(self.path.parent)
        need(self.path.is_dir(), 'campaign directory required')
        for name in ('objects', 'events'):
            path = self.path / name
            need(path.is_dir() and not path.is_symlink(), 'campaign directory layout changed')
        with regular(self.path / '.lock').open('rb') as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('campaign is owned by another command') from None
            yield

    def history(self):
        paths = sorted((self.path / 'events').iterdir())
        need(len(paths) <= MAX_EVENTS, 'campaign event bound')
        previous = None
        rows = []
        for index, path in enumerate(paths, 1):
            # A killed atomic publisher may leave an uncommitted temporary.
            if path.name.startswith('.pending-'):
                continue
            need(path.name == f'{len(rows)+1:06d}.json', 'campaign journal gap/unknown entry')
            raw = read(path)
            row = decode(raw)
            fields(row, 'schema_version sequence previous state')
            need(row['schema_version'] == 1 and type(row['schema_version']) is int and
                 row['sequence'] == len(rows)+1 and row['previous'] == previous, 'campaign journal chain mismatch')
            previous = sha(raw)
            rows.append(row)
        return rows

    def state(self):
        rows = self.history()
        need(rows, 'campaign prepare did not commit; use a fresh directory')
        return rows[-1]['state']

    def commit(self, state):
        rows = self.history()
        need(len(rows) < MAX_EVENTS, 'campaign event bound')
        previous = sha(read(self.path / 'events' / f'{len(rows):06d}.json')) if rows else None
        event = dict(schema_version=1, sequence=len(rows)+1, previous=previous, state=state)
        create(self.path / 'events' / f'{len(rows)+1:06d}.json', encoded(event))

    def checked(self):
        state = self.state()
        need(state['implementation'] == implementation(), 'campaign implementation drift; start a reviewed successor')
        need(state['runtime'] == runtime(), 'campaign runtime tool drift; start a reviewed successor')
        # Verify every retained object referenced by current state before using it.
        for checksum in state['inputs'].values():
            self.bytes(checksum)
        for key in ('selection', 'build_graph', 'update_plan', 'build_plan', 'binding', 'candidate', 'handoff'):
            if state.get(key):
                self.bytes(state[key])
        return state


def prepare(store, ref):
    before, tools = implementation(), runtime()
    raw = selected(ref)
    selection = decode(raw)
    fields(selection, 'schema_version campaign_id as_of max_age_hours inputs build_graph')
    need(type(selection['schema_version']) is int and selection['schema_version'] == 1, 'campaign selection schema')
    need(type(selection['campaign_id']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}', selection['campaign_id']), 'campaign ID required')
    fields(selection['inputs'], ' '.join(INPUTS))
    raws = {key: selected(selection['inputs'][key]) for key in INPUTS}
    graph_raw = selected(selection['build_graph'])
    update = module('campaign_update', 'scripts/maintenance/update_plan.py')
    report = update.plan(raws, selection['as_of'], selection['max_age_hours'])
    graph = decode(graph_raw)
    build_plan = update.b.plan(graph)
    old = update.a.decode(raws['graph'])
    need({p['name'] for p in old['packages']} == {p['name'] for p in graph['packages']},
         'campaign supports a fixed package-name set; additions/removals need a reviewed successor input')
    # Existing planners trust declared changes; retain that interface while
    # refusing candidate revisions omitted from the declared rebuild work.
    planned = {p['name'] for p in build_plan['packages']}
    def projections(value):
        builds = {p['package']: p for p in value['build_dependencies']}
        sources = {p['id']: p for p in value['sources']}
        return {p['name']: [p, builds.get(p['name']),
                sources.get(builds.get(p['name'], {}).get('source_id'))] for p in value['packages']}
    old_rows, new_rows = projections(old), projections(graph)
    need(all(old_rows[name] == row or name in planned for name, row in new_rows.items()),
         'candidate graph metadata changed outside declared rebuild coverage')
    required = sorted({p['name'] for p in report['rebuild']['packages']} |
                      {p['name'] for p in build_plan['packages']})
    holds = list(build_plan['global_holds'])
    holds.extend('HELD_GROUP:' + group['id'] for group in build_plan['groups'] if group['held'])
    runnable = {p['name'] for p in build_plan['packages'] if p['disposition'] == 'build'}
    holds.extend('MISSING_BUILD_COVERAGE:' + name for name in required if name not in runnable)
    if not required:
        holds.append('NO_DECLARED_REBUILD_WORK')
    need(before == implementation() and tools == runtime(), 'campaign implementation changed during planning')
    with store.lock(fresh=True):
        state = dict(schema_version=1, campaign_id=selection['campaign_id'], implementation=before, runtime=tools,
            selection=store.object(raw), inputs={key: store.object(value) for key, value in raws.items()},
            build_graph=store.object(graph_raw), update_plan=store.object(encoded(report)),
            build_plan=store.object(encoded(build_plan)), required_packages=required, build_holds=holds,
            phases=dict(planning='COMPLETE', build_receipts='NOT_RUN', outputs='NOT_RUN', handoff='NOT_RUN',
                        security_review='BLOCKED' if report['maintenance_review_held'] else 'NOT_ESTABLISHED',
                        staging='NOT_RUN', publication='NOT_RUN', installed='NOT_RUN', hardware='NOT_RUN'),
            binding=None, candidate=None, handoff=None, attempts=0, error=None)
        store.commit(state)
        return state


def bind(store, ref):
    state = store.checked()
    raw = selected(ref)
    spec = decode(raw)
    fields(spec, 'schema_version purpose synthetic input batches pairs')
    need(selected(spec['input']) == store.bytes(state['build_graph']), 'batch input differs from campaign build graph')
    need(type(spec['pairs']) is list and 0 < len(spec['pairs']) <= 256, 'finite pair list required')
    names = [p['package'] for p in spec['pairs']]
    need(len(names) == len(set(names)) and sorted(names) == state['required_packages'], 'campaign requires exact full rebuild pair coverage')
    need(type(spec['batches']) is list and 2 <= len(spec['batches']) <= 512, 'finite batch list required')
    for row in spec['batches']:
        path = Path(os.path.abspath(row['path']))
        need(path == path.resolve() and path.is_dir(), 'batch directory aliases forbidden')
        row['path'] = str(path)
    # Retain the caller's original selection and use the campaign-owned graph copy.
    origin = store.object(raw)
    spec['input'] = dict(path=str(store.object_path(state['build_graph'])), sha256=state['build_graph'])
    effective = store.object(encoded(spec))
    binding = store.object(encoded(dict(original=origin, effective=effective)))
    if state['binding'] and store.value(state['binding'])['effective'] == effective:
        return state
    state.update(binding=binding, candidate=None, handoff=None, attempts=0, error=None)
    state['phases'].update(build_receipts='BOUND_NOT_VERIFIED', outputs='NOT_RUN', handoff='NOT_RUN')
    store.commit(state)
    return state


def candidate(store, state):
    need(not state['build_holds'], 'campaign build plan blocked: ' + ', '.join(state['build_holds']))
    need(state['binding'], 'bind explicit batch receipts first')
    binding = store.value(state['binding'])
    store.bytes(binding['original'])
    store.bytes(binding['effective'])
    outputs = module('campaign_outputs', 'scripts/maintenance/build_outputs_v2.py')
    result = outputs.candidate(store.object_path(binding['effective']), binding['effective'])
    need(sorted(p['name'] for p in result['packages']) == state['required_packages'], 'admitted output set differs from campaign')
    need(state['implementation'] == implementation() and state['runtime'] == runtime(), 'campaign code/tool drift during output admission')
    return result


def verify(store, retry=False):
    state = store.checked()
    prior = state['phases']['outputs']
    need(prior not in ('FAILED', 'RUNNING') or retry, 'failed/interrupted verification requires explicit --retry or new binding')
    need(not retry or prior in ('FAILED', 'RUNNING'), '--retry requires a failed/interrupted verification')
    if prior == 'COMPLETE':
        try:
            need(encoded(candidate(store, state)) == store.bytes(state['candidate']), 'candidate changed since verification')
            return state
        except Exception as error:
            state.update(candidate=None, handoff=None, error=str(error)[:2000])
            state['phases'].update(outputs='FAILED', handoff='NOT_RUN')
            store.commit(state)
            raise
    need(state['attempts'] < 3, 'three verification attempts exhausted; bind new reviewed receipts')
    state['attempts'] += 1
    state.update(candidate=None, handoff=None, error=None)
    state['phases'].update(outputs='RUNNING', handoff='NOT_RUN')
    store.commit(state)
    try:
        result = candidate(store, state)
        state['candidate'] = store.object(encoded(result))
        state['phases'].update(build_receipts='COMPLETE', outputs='COMPLETE')
    except Exception as error:
        state['error'] = str(error)[:2000]
        state['phases']['outputs'] = 'BLOCKED' if state['build_holds'] else 'FAILED'
        store.commit(state)
        raise
    store.commit(state)
    return state


def release_preflight(path, checksum, result, required, graph):
    """Invoke existing read-only release checks, preserving their optional source policy."""
    spec_raw = selected(dict(path=str(path), sha256=checksum))
    spec = decode(spec_raw)
    r = module('campaign_release', 'scripts/release/release.py')
    r.require(spec.get('schema_version') == 1 and type(spec['schema_version']) is int and
              spec.get('target_arch') == 'aarch64', 'invalid release schema/architecture')
    r.valid_name(spec['release_id']); r.valid_name(spec['repo_name'])
    r.require(re.fullmatch('[0-9a-f]{40}', spec.get('source_commit', '')), 'full project source commit required')
    models = spec['policy'].get('supported_models', [])
    r.require(models and len(set(models)) == len(models) and set(models) <= r.MODELS, 'explicit exact supported M2 Air sizes required')
    need(type(spec.get('synthetic', False)) is bool and spec.get('synthetic', False) == result['synthetic'],
         'release/candidate synthetic labels differ')
    need(sorted(spec['policy']['selected_packages']) == required, 'release selection differs from complete campaign output set')
    base_dir = regular(path).parent
    closure = {str(regular(path)): checksum}
    def reference(ref):
        selected_path = r.file_ref(base_dir, ref)
        # Keep the selected hash if a file changes after file_ref() validated it.
        closure[str(selected_path)] = ref['sha256']
        return selected_path
    base = decode(read(reference(spec['base'])))
    need(spec['base']['snapshot_id'] == graph['snapshot_id'], 'release target snapshot differs from campaign graph')
    expected = {p['name']: p for p in result['packages']}
    packages, records = [], {}
    for item in spec['packages']:
        archive = reference(item['artifact'])
        need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+:-]*\.pkg\.tar\.(?:gz|xz|zst)', archive.name), 'invalid package filename')
        p = r.pkginfo(archive)
        name = p['name']
        need(name in expected and name not in records, 'unexpected/duplicate release package')
        output = expected[name]
        need(item['artifact']['sha256'] == output['sha256'] and
             all(p[k] == output[k] for k in ('version', 'arch')), 'release archive differs from admitted output')
        record = decode(read(reference(item['provenance'])))
        r.provenance_check(p, record, output['sha256'], spec)
        need(record['recipe_sha256'] == output['recipe_inputs']['PKGBUILD'] and
             record['sources'] == output['source']['sources'], 'release source projection differs from admitted build')
        need(record['licenses'] == p['license'], 'release license projection differs from admitted archive')
        need(record['build']['execution'] == ('synthetic' if result['synthetic'] else 'native'), 'release execution label differs')
        need(record['build']['architecture'] in ('aarch64', 'arm64'), 'release build architecture differs from admitted native ARM label')
        records[name] = record
        p.update(filename=archive.name, sha256=output['sha256'])
        packages.append(p)
    need(set(records) == set(required), 'release package set incomplete')
    need(len({p['filename'] for p in packages}) == len(packages), 'duplicate package filename')
    r.dependency_check(spec, packages, base)
    effective = {p['name']: p for p in base['packages'] if p['name'] not in required}
    effective.update({p['name']: p for p in packages})
    planned = {p['name']: p for p in graph['packages']}
    need(set(effective) == set(planned), 'release target package set differs from campaign graph')
    for name, p in effective.items():
        row = planned[name]
        need(all(p[k] == row[k] for k in ('version', 'arch')) and
             sorted(p['depend']) == sorted(row['depend']) and sorted(p['provides']) == sorted(row['provides']),
             'release target metadata differs from campaign graph: ' + name)
    evidence = {}
    for row in spec.get('evidence', []):
        eid = r.valid_name(row['id'])
        need(eid not in evidence, 'duplicate release evidence ID')
        reference(row)
        evidence[eid] = row
    if spec.get('project_license'):
        r.text_field(spec['project_license'], 'spdx')
        reference(spec['project_license'])
    if 'source_delivery' in spec:
        fields(spec['source_delivery'], 'schema_version index')
        need(type(spec['source_delivery']['schema_version']) is int and spec['source_delivery']['schema_version'] == 1, 'source delivery schema')
        helper = r.source_delivery_module()
        assembled = helper.assemble(base_dir, spec['source_delivery']['index'], packages,
            spec['policy']['selected_packages'], spec.get('synthetic'), lambda p: records[p['name']])
        for row in assembled:
            need(row['id'] not in evidence or evidence[row['id']] == row, 'source delivery evidence collision')
            reference(row)
            evidence[row['id']] = row
        projected = copy.deepcopy(spec)
        projected['evidence'] = list(evidence.values())
        helper.verify_associations(projected, packages,
            lambda eid, limit: helper.read_file(reference(evidence[eid]), limit), lambda p: records[p['name']])
    need(all(digest(p) == value for p, value in closure.items()), 'release input changed during preflight')
    return dict(spec=dict(path=str(regular(path)), sha256=checksum), closure=closure,
                source_delivery='CHECKED_DECLARED_ASSOCIATIONS' if 'source_delivery' in spec else 'NOT_DECLARED',
                release_id=spec['release_id'])


def handoff(store, ref):
    state = store.checked()
    need(state['phases']['outputs'] == 'COMPLETE', 'complete verified outputs required before handoff')
    state['phases']['handoff'] = 'RUNNING'
    state.update(handoff=None, error=None)
    store.commit(state)
    try:
        # Existing shared batch locks cover admission, release preflight and the
        # final commit, excluding cooperating runners throughout the handoff.
        with ExitStack() as locks:
            binding = store.value(state['binding'])
            spec = store.value(binding['effective'])
            outputs = module('campaign_handoff_outputs', 'scripts/maintenance/build_outputs_v2.py')
            for row in spec['batches']:
                outputs.batch_open(row, locks, state['build_graph'])
            result = candidate(store, state)
            need(encoded(result) == store.bytes(state['candidate']), 'candidate changed since verification')
            receipt = release_preflight(Path(ref['path']), ref['sha256'], result, state['required_packages'],
                                        store.value(state['build_graph']))
            receipt['spec_object'] = store.object(selected(ref))
            receipt.update(schema_version=1, campaign_id=state['campaign_id'], candidate_sha256=state['candidate'],
                status='SYNTHETIC_HANDOFF_NOT_STAGEABLE' if result['synthetic'] else 'STAGING_INPUTS_READY',
                authenticated=False, security_review=state['phases']['security_review'],
                release_acceptance='NOT_ESTABLISHED', staging='NOT_RUN', signing='NOT_RUN', publication='NOT_RUN',
                command=None if result['synthetic'] else [sys.executable, '-B', str(ROOT/'scripts/release/release.py'),
                    '--root', '<explicit-local-storage>', '--gpg-home', '<existing-external-keyring>',
                    '--key', '<existing-full-fingerprint>', 'stage', '--spec', str(regular(ref['path']))])
            need(state['implementation'] == implementation() and state['runtime'] == runtime(), 'campaign code/tool drift during handoff')
            need(all(digest(p) == value for p, value in receipt['closure'].items()), 'release input drift before handoff commit')
            state['handoff'] = store.object(encoded(receipt))
            state['phases']['handoff'] = receipt['status']
            store.commit(state)
    except Exception as error:
        state['error'] = str(error)[:2000]
        state['phases']['handoff'] = 'FAILED'
        store.commit(state)
        raise
    return state


def summary(store, state):
    return dict(campaign=str(store.path), campaign_id=state['campaign_id'], phases=state['phases'],
                required_packages=state['required_packages'], build_holds=state['build_holds'],
                attempts=state['attempts'], error=state['error'],
                status_scope='RECORDED_ONLY_REVERIFY_BEFORE_USE',
                candidate=str(store.object_path(state['candidate'])) if state['candidate'] else None,
                handoff=str(store.object_path(state['handoff'])) if state['handoff'] else None,
                journal_events=len(store.history()), authenticated=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'bind', 'verify', 'handoff', 'status'))
    parser.add_argument('--campaign', required=True, type=Path)
    parser.add_argument('--selection', type=Path)
    parser.add_argument('--selection-sha256')
    parser.add_argument('--retry', action='store_true')
    args = parser.parse_args(argv)
    store = Store(args.campaign)
    try:
        if args.action in ('prepare', 'bind', 'handoff'):
            need(args.selection is not None and args.selection_sha256 is not None, 'selected input path and SHA-256 required')
            ref = dict(path=str(args.selection), sha256=args.selection_sha256)
        else:
            need(args.selection is None and args.selection_sha256 is None, 'selection only applies to prepare/bind/handoff')
        need(not args.retry or args.action == 'verify', '--retry only applies to verify')
        if args.action == 'prepare':
            state = prepare(store, ref)
        else:
            with store.lock():
                if args.action == 'bind':
                    state = bind(store, ref)
                elif args.action == 'verify':
                    state = verify(store, args.retry)
                elif args.action == 'handoff':
                    state = handoff(store, ref)
                else:
                    state = store.checked()
        sys.stdout.buffer.write(encoded(summary(store, state)))
        return 0
    except Exception as error:
        print('maintenance campaign: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
