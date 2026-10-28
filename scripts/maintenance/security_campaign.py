#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compose retained advisory DATA into the existing offline rebuild campaign."""
import argparse
import importlib.util
from pathlib import Path
import re
import sys
import tempfile

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'scripts/maintenance/campaign.py').is_file())


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


c = module('security_existing_campaign', 'scripts/maintenance/campaign.py')
u = module('security_existing_update', 'scripts/maintenance/update_plan.py')
a, b = u.a, u.b
need, encoded = c.need, c.encoded
INPUTS = ('inventory', 'advisories', 'provenance', 'graph', 'candidate_graph')


class PreparingStore(c.Store):
    """Bind the original adapter intent in campaign.prepare's first event."""
    def __init__(self, path, selection, adapter):
        super().__init__(path)
        self.selection, self.adapter = selection, adapter

    def commit(self, state):
        state['security_intent'] = dict(selection=self.object(self.selection), adapter_sha256=self.adapter)
        super().commit(state)


def select(ref):
    c.fields(ref, 'path sha256')
    raw = a.read(Path(ref['path']))
    need(type(ref['sha256']) is str and re.fullmatch('[0-9a-f]{64}', ref['sha256'])
         and c.sha(raw) == ref['sha256'], 'selected input checksum mismatch: ' + str(ref['path']))
    return raw


def compose(selection, raws, imported=None):
    """Reuse advisory replay and graph planners; keep original and candidate apart."""
    items = a.inventory(a.decode(raws['inventory']))
    groups = a.decode(raws['advisories'])
    cache = a.provenance(a.decode(raws['provenance']), raws['advisories'],
                         a.utc(selection['as_of']), selection['max_age_hours'])
    # Apply the update planner's expansion bound before producing the report.
    index = a.advisories(groups)
    need(len(items) <= b.MAX_PACKAGES and
         sum(len(index.get(p['name'], [])) for p in items) <= b.MAX_PACKAGES,
         'finite inventory/advisory root bound')
    sizes = {g['name']: len(a.encoded(g)) + 4096 for g in groups}
    need(sum(sizes[g['name']] for p in items for g in index.get(p['name'], []))
         + len(raws['inventory']) * 4 <= b.pins.MAX_OUTPUT // 2, 'advisory expansion bound')
    report = a.report(items, groups, cache, selection['as_of'])
    report['inputs'] = {key + '.json': a.pin(raws[key])
                        for key in ('inventory', 'advisories', 'provenance')}
    originals = {key: raws[key] for key in ('inventory', 'advisories', 'provenance', 'graph')}
    originals['advisory_report'] = a.encoded(report)
    review = u.plan(originals, selection['as_of'], selection['max_age_hours'])
    old, candidate = a.decode(raws['graph']), a.decode(raws['candidate_graph'])
    for row in old['packages']:
        need(type(row.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
             'exact pre-change release archive identity required: ' + row['name'])
    need(old['snapshot_id'] == candidate['snapshot_id'], 'candidate target snapshot differs')
    import_holds = None
    if imported is not None:
        bundle = a.decode(imported)
        need(bundle.get('schema_version') == 1 and type(bundle['schema_version']) is int and
             bundle.get('status') == 'RETAINED_INPUT_GRAPH_IMPORT_REQUIRES_REVIEW',
             'current retained import bundle required')
        need(a.encoded(bundle['graph']) == a.encoded(old) and
             a.encoded(bundle['inventory']) == a.encoded(items),
             'import bundle differs from exact inventory/pre-change graph')
        import_holds = dict(global_holds=bundle['global_holds'],
                            packages=[dict(name=p['name'], holds=p['holds']) for p in bundle['packages']],
                            origin='SELECTED_IMPORT_BUNDLE_DATA_NOT_REAUTHENTICATED')
    # Old edges must remain actionable even when a candidate removes an offer.
    # Seed the complete old impact set as review roots, then let the same planner
    # compute candidate closure/order. These references never assert a fix.
    roots = {(r['package'], r['reference']) for r in candidate['changed']['advisories']}
    roots.update((r['package'], r['reference']) for r in review['derived_advisory_roots'])
    prior = 'security-campaign:pre-change-impact:' + c.sha(raws['graph'])
    roots.update((p['name'], prior) for p in review['rebuild']['packages'])
    candidate['changed']['advisories'] = [dict(package=p, reference=r) for p, r in sorted(roots)]
    b.plan(candidate)
    return originals, a.encoded(candidate), review, import_holds


def checked(store):
    state = store.checked()
    intent = state['security_intent']
    store.bytes(intent['selection'])
    need(intent['adapter_sha256'] == c.digest(__file__), 'security adapter drift; use a reviewed successor operation')
    need(state.get('security_operation'), 'security preparation interrupted; prepare --retry with the original selection')
    op = store.value(state['security_operation'])
    need(op['selection'] == intent['selection'], 'security selection differs from initial intent')
    need(op['adapter_sha256'] == c.digest(__file__), 'security adapter drift; use a reviewed successor operation')
    for key in ('selection', 'candidate_original', 'import_bundle'):
        if op[key]:
            store.bytes(op[key])
    if state.get('security_batches'):
        batch = store.value(state['security_batches'])
        store.bytes(batch['selection'])
        for row in batch['batches']:
            for key in ('config', 'sources', 'admission'):
                store.bytes(row[key])
    return state


def prepare(store, ref, retry=False):
    raw = select(ref)
    selection = a.decode(raw)
    c.fields(selection, 'schema_version operation_id as_of max_age_hours inputs import_bundle')
    need(type(selection['schema_version']) is int and selection['schema_version'] == 1, 'security selection schema')
    need(type(selection['max_age_hours']) is int and 1 <= selection['max_age_hours'] <= 8760, 'bounded advisory age')
    c.fields(selection['inputs'], ' '.join(INPUTS))
    before, runtime, adapter = c.implementation(), c.runtime(), c.digest(__file__)
    raws = {key: select(selection['inputs'][key]) for key in INPUTS}
    need(sum(map(len, raws.values())) <= u.MAX_TOTAL, 'total security input bound')
    imported = select(selection['import_bundle']) if selection['import_bundle'] is not None else None
    originals, graph, review, import_holds = compose(selection, raws, imported)
    # campaign.prepare already retains generated bytes as immutable objects;
    # these temporary paths are provenance only after its first commit.
    with tempfile.TemporaryDirectory(prefix='security-compose-') as td:
        directory = Path(td)
        def retain(name, body):
            path = directory / (name + '.json')
            path.write_bytes(body)
            return dict(path=str(path), sha256=c.sha(body))
        existing = dict(schema_version=1, campaign_id=selection['operation_id'],
                        as_of=selection['as_of'], max_age_hours=selection['max_age_hours'],
                        inputs={key: retain(key, body) for key, body in originals.items()},
                        build_graph=retain('candidate', graph))
        if retry:
            with store.lock():
                state = store.checked()
                need(not state.get('security_operation') and len(store.history()) == 1,
                     'prepare --retry only recovers an interrupted initial preparation')
                need(state.get('security_intent') == dict(selection=c.sha(raw), adapter_sha256=adapter) and
                     store.bytes(state['security_intent']['selection']) == raw,
                     'interrupted preparation original selection/adapter differs')
                need(state['campaign_id'] == selection['operation_id'] and
                     state['inputs'] == {key: c.sha(body) for key, body in originals.items()} and
                     state['build_graph'] == c.sha(graph), 'interrupted preparation inputs differ')
        else:
            state = c.prepare(PreparingStore(store.path, raw, adapter), retain('campaign-selection', encoded(existing)))
    with store.lock():
        state = store.checked()
        need(not state.get('security_operation') and len(store.history()) == 1,
             'initial preparation changed before security commit')
        need(state['implementation'] == before and state['runtime'] == runtime and
             c.digest(__file__) == adapter, 'implementation/runtime changed during security preparation')
        for key in INPUTS:
            need(select(selection['inputs'][key]) == raws[key], 'security input changed during preparation')
        need(select(ref) == raw, 'security selection changed during preparation')
        if imported is not None:
            need(select(selection['import_bundle']) == imported, 'import bundle changed during preparation')
        op = dict(schema_version=1, adapter_sha256=adapter, selection=store.object(raw),
                  candidate_original=store.object(raws['candidate_graph']),
                  import_bundle=store.object(imported) if imported is not None else None,
                  imported_holds=import_holds,
                  status='REBUILD_REVIEW_REQUIRED' if state['required_packages'] else 'NO_REBUILD_FROM_SUPPLIED_ROOTS',
                  graph_unaffected=review['rebuild']['unaffected_by_declared_graph'],
                  unknown_advisory_packages=[p['name'] for p in review['package_reviews'] if not p['findings']],
                  gates=dict(platform='NOT_ESTABLISHED', recovery='NOT_ESTABLISHED',
                             provider='RETAINED_PLANNER_AND_IMAGE_BINDINGS_REQUIRED',
                             arm_affectedness='UNKNOWN', remediation='NOT_ESTABLISHED'))
        state.update(security_operation=store.object(encoded(op)), security_batches=None, security_attempts=0)
        state['phases']['batch_planning'] = 'NOT_RUN'
        store.commit(state)
        return state


def plan_builds(store, ref, retry=False):
    """Ask existing offline-build-v2 admission for an independent pair; emit argv."""
    state = checked(store)
    need(state['required_packages'], 'no declared rebuild work; no batch commands')
    need(not state['build_holds'], 'campaign build plan held: ' + ', '.join(state['build_holds']))
    prior = state['phases']['batch_planning']
    need((prior in ('FAILED', 'RUNNING')) == retry, 'failed/interrupted batch planning requires --retry; otherwise omit it')
    need(state['security_attempts'] < 3, 'three planning attempts exhausted; use a successor operation')
    state.update(security_batches=None, error=None, security_attempts=state['security_attempts'] + 1)
    state['phases']['batch_planning'] = 'RUNNING'
    store.commit(state)
    try:
        raw = select(ref)
        spec = a.decode(raw)
        c.fields(spec, 'schema_version batches')
        need(type(spec['schema_version']) is int and spec['schema_version'] == 1, 'batch selection schema')
        need(type(spec['batches']) is list and len(spec['batches']) == 2, 'exact independent rebuild pair required')
        batch = module('security_existing_batch', 'scripts/maintenance/build_batch_v2.py')
        planner = ROOT / 'scripts/maintenance/rebuild_plan.py'
        graph_path, graph_sha = store.object_path(state['build_graph']), state['build_graph']
        rows, outputs = [], set()
        for index, row in enumerate(spec['batches'], 1):
            c.fields(row, 'config sources output')
            config, sources = select(row['config']), select(row['sources'])
            output = Path(row['output']).absolute()
            need(output == output.resolve() and not output.exists() and output.parent.is_dir(), 'fresh batch output beneath existing ordinary parent required')
            need(not (output == store.path or output.is_relative_to(store.path) or store.path.is_relative_to(output)), 'batch output overlaps operation')
            need(all(not (output == p or output.is_relative_to(p) or p.is_relative_to(output)) for p in outputs), 'independent batch outputs overlap')
            outputs.add(output)
            config_sha, sources_sha = store.object(config), store.object(sources)
            config_path, sources_path = store.object_path(config_sha), store.object_path(sources_sha)
            admission = batch.admission(graph_path, graph_sha, config_path, config_sha,
                                        planner, c.digest(planner), sources_path, sources_sha,
                                        builder_interface=batch.INTERFACE)
            need(sorted(admission['tasks']) == state['required_packages'], 'batch must cover exact full campaign rebuild set')
            need(not admission['global_holds'] and all(not g['held'] for g in admission['groups']), 'batch admission held')
            for task in admission['tasks'].values():
                cache = Path(task['offline_sources']['source_cache'])
                need(not (output == cache or output.is_relative_to(cache) or cache.is_relative_to(output)), 'batch output overlaps source cache')
            admit_sha = store.object(encoded(admission))
            common = [sys.executable, '-B', str(ROOT / 'scripts/maintenance/build_batch_v2.py'),
                      '--builder-interface', batch.INTERFACE, '--input', str(graph_path), '--input-sha256', graph_sha,
                      '--config', str(config_path), '--config-sha256', config_sha,
                      '--planner', str(planner), '--planner-sha256', c.digest(planner),
                      '--sources', str(sources_path), '--sources-sha256', sources_sha]
            rows.append(dict(pair_member=index, config=config_sha, sources=sources_sha, admission=admit_sha,
                             output=str(output), plan_command=common[:3] + ['plan'] + common[3:],
                             execute_command=common[:3] + ['execute'] + common[3:] +
                             ['--admission-sha256', admit_sha, '--output', str(output)],
                             execution='NOT_RUN'))
            need(select(row['config']) == config and select(row['sources']) == sources, 'batch input changed during planning')
        need(select(ref) == raw, 'batch selection changed during planning')
        for row in rows:
            admission = store.value(row['admission'])
            need(all(c.digest(path) == checksum for path, checksum in admission['implementation'].items()),
                 'admitted build/source input changed before command commit')
        checked(store)
        state['security_batches'] = store.object(encoded(dict(selection=store.object(raw), batches=rows,
            status='CONDITIONAL_EXISTING_BATCH_COMMANDS_NOT_EXECUTED',
            recovery='Use existing execute --resume --retry PACKAGE only after recording actual batch failure; then bind receipts through campaign.py.')))
        state['phases']['batch_planning'] = 'COMPLETE'
    except Exception as error:
        state['error'] = str(error)[:2000]
        state['phases']['batch_planning'] = 'FAILED'
        store.commit(state)
        raise
    store.commit(state)
    return state


def summary(store, state):
    value = c.summary(store, state)
    op = store.value(state['security_operation'])
    value.update(operation=op, batch_planning_attempts=state['security_attempts'],
                 bindings=dict(inputs=state['inputs'], effective_candidate_graph=state['build_graph'],
                               update_plan=state['update_plan'], build_plan=state['build_plan']),
                 commands=store.value(state['security_batches']) if state['security_batches'] else None,
                 security_status='UNKNOWN_PLANNING_IS_NOT_REMEDIATION')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'plan-builds', 'status'))
    parser.add_argument('--operation', required=True, type=Path)
    parser.add_argument('--selection', type=Path)
    parser.add_argument('--selection-sha256')
    parser.add_argument('--retry', action='store_true')
    args = parser.parse_args(argv)
    store = c.Store(args.operation)
    try:
        if args.action == 'status':
            need(args.selection is None and args.selection_sha256 is None and not args.retry, 'status takes no selection/retry')
        else:
            need(args.selection is not None and args.selection_sha256 is not None, 'explicit selection path and digest required')
            ref = dict(path=str(args.selection), sha256=args.selection_sha256)
        if args.action == 'prepare':
            state = prepare(store, ref, args.retry)
        else:
            with store.lock():
                state = checked(store) if args.action == 'status' else plan_builds(store, ref, args.retry)
        sys.stdout.buffer.write(encoded(summary(store, state)))
        return 0
    except Exception as error:
        print('security campaign: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
