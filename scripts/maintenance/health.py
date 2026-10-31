#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Review finite authenticated release and retained maintenance observations offline."""
import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys
import tempfile

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'scripts/release/check_source_pins.py').is_file())


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pins = load('health_pins', 'scripts/release/check_source_pins.py')
comparison = load('health_comparison', 'scripts/release/compare_releases.py')
expiry = load('health_expiry', 'scripts/maintenance/signing_expiry.py')
update = load('health_update', 'scripts/maintenance/update_plan.py')
a, r, s = update.a, pins.r, pins.s
KINDS = ('signing', 'maintenance', 'sources', 'comparison', 'operations')
ROLES = ('platform', 'release', 'support', 'signing', 'security', 'incident')
MAX_TOTAL = 32 * 1024**2
ERRORS = (r.Error, s.Error, comparison.r.Error, update.b.r.Error, update.b.s.Error,
          OSError, ValueError, KeyError, TypeError, RecursionError)


def same(left, right, reason):
    r.require(a.encoded(left) == a.encoded(right), reason)


def identities(rows):
    a.inventory(rows)
    return sorted(({k: row[k] for k in ('name', 'version', 'arch')} for row in rows),
                  key=lambda row: row['name'])


@contextmanager
def verification_env(home, release):
    """Copy public keyring bytes into a private, fixed-option verifier home."""
    r.gpg_env(home, release)  # Preserve the existing outside-checkout contract.
    home = Path(home).absolute()
    r.require(not any(p.is_symlink() for p in (home, *home.parents)), 'verifier home aliases refused')
    keyring = next((home / name for name in ('pubring.kbx', 'pubring.gpg') if (home / name).exists()), None)
    r.require(keyring is not None, 'supplied offline public keyring unavailable')
    raw = a.read(keyring)
    with tempfile.TemporaryDirectory(prefix='maintenance-health-verify-') as temporary:
        target = Path(temporary)
        (target / keyring.name).write_bytes(raw)
        (target / 'gpg.conf').write_text('no-auto-key-retrieve\nno-auto-key-import\nauto-key-locate clear\n'
                                       'no-autostart\nno-auto-check-trustdb\nno-sig-cache\n')
        yield dict(PATH='/usr/bin:/bin', HOME=temporary, GNUPGHOME=temporary, LANG='C', LC_ALL='C')
    r.require(a.read(keyring) == raw, 'supplied public keyring changed during verification')


def context(release, checksum, key, env):
    """Return only data bound to the authenticated manifest's signed file map."""
    directory = comparison.directory(release)
    manifest, spec, base, digest = comparison.verified(directory, key, env)
    r.require(digest == checksum, 'selected release checksum mismatch')
    r.require(spec.get('target_arch') == 'aarch64', 'ARM release required')
    base_rows = comparison.indexed(base['packages'], 'base package')
    base_rows.update(comparison.indexed(manifest['packages'], 'release package'))
    packages = list(base_rows.values())
    rows = []
    for package in manifest['packages']:
        raw = s.local_read(directory, package['provenance'], pins.MAX_JSON)
        r.require(pins.digest(raw) == manifest['files'][package['provenance']],
                  'release provenance changed')
        record = pins.decode(raw)
        r.provenance_check(package, record, package['sha256'], spec)
        rows.append(pins.project(record))
    sources = pins.indexed(rows)
    binding = dict(release_id=manifest['release_id'], release_sha256=digest,
                   source_commit=spec['source_commit'], snapshot_id=base['snapshot_id'],
                   synthetic=spec.get('synthetic', False),
                   package_inventory_sha256=pins.digest(a.encoded(identities(packages))),
                   project_sources_sha256=pins.digest(a.encoded(sources)))
    return dict(binding=binding, packages=packages, sources=sources,
                created_utc=manifest['created_utc'])


class Reader:
    def __init__(self, root):
        self.root, self.retained, self.total = Path(root).absolute(), {}, 0

    def read(self, ref):
        pins.fields(ref, ('path', 'sha256'))
        r.require(type(ref['path']) is str and 0 < len(ref['path']) <= 4096,
                  'bounded explicit input path required')
        r.require(type(ref['sha256']) is str and r.HEX.fullmatch(ref['sha256']),
                  'explicit input SHA-256 required')
        path = self.root / ref['path']
        r.require('..' not in path.parts, 'input path traversal refused')
        raw = a.read(path)
        r.require(pins.digest(raw) == ref['sha256'], 'observation input checksum mismatch: ' + str(path))
        self.total += len(raw)
        r.require(self.total <= MAX_TOTAL, 'total observation byte bound')
        if path in self.retained:
            r.require(raw == self.retained[path], 'observation input changed')
        self.retained[path] = raw
        return raw

    def finish(self):
        for path, raw in self.retained.items():
            r.require(a.read(path) == raw, 'input changed during health review: ' + str(path))


def assess(ctx, observations, reader, key, env, as_of, max_age_hours=24):
    now = expiry.timestamp(as_of)
    r.require(type(max_age_hours) is int and 1 <= max_age_hours <= 8760, 'bounded evidence age required')
    pins.fields(observations, ('schema_version', 'observations'))
    r.require(type(observations['schema_version']) is int and observations['schema_version'] == 1,
              'observation schema required')
    entries = observations['observations']
    r.require(type(entries) is dict and not (entries.keys() - set(KINDS)), 'unknown observation kind')
    created = datetime.fromisoformat(ctx['created_utc'])
    r.require(created.tzinfo == timezone.utc and created.timestamp() <= now,
              'release created time invalid or in the future')
    findings, checks = [], {}

    def issue(kind, code, action, **details):
        findings.append(dict(kind=kind, code=code, action=action, **details))

    def age(kind, epoch, label):
        r.require(type(epoch) is int and 0 <= epoch <= now, label + ' time invalid or in the future')
        seconds = now - epoch
        if seconds > max_age_hours * 3600:
            issue(kind, 'STALE_' + label.upper(), 'Retain prior evidence and obtain a fresh ' + label + ' observation.',
                  age_seconds=seconds, max_age_hours=max_age_hours)
        return seconds

    for kind in KINDS:
        entry = entries.get(kind)
        if entry is None:
            issue(kind, 'EVIDENCE_UNAVAILABLE', 'Supply the exact-release ' + kind + ' observation and original digest-selected inputs.')
            checks[kind] = dict(status='UNAVAILABLE')
            continue
        pins.fields(entry, ('binding', 'observed_at', 'inputs'))
        same(entry['binding'], ctx['binding'], kind + ' generation/package/source binding mismatch')
        observed = expiry.timestamp(entry['observed_at'])
        r.require(observed >= created.timestamp(), 'observation binding predates release generation')
        start = len(findings)
        elapsed = age(kind, observed, 'observation')
        raw_inputs = entry['inputs']
        r.require(type(raw_inputs) is dict, 'observation inputs object required')
        try:
            if kind == 'signing':
                pins.fields(raw_inputs, ('certificate', 'report'))
                raw = reader.read(raw_inputs['certificate'])
                retained = a.decode(reader.read(raw_inputs['report']))
                when, days = retained['as_of_epoch'], retained['warning_days']
                r.require(type(when) is int and when <= observed, 'signing report postdates observation')
                original = expiry.report(expiry.inspect(raw, when), key, when, days)
                if 'certificate' in retained:
                    original['certificate'] = a.pin(raw)
                same(retained, original, 'signing report does not replay')
                report_age = age(kind, when, 'signing_report')
                current = expiry.report(expiry.inspect(raw, now), key, now, days)
                for item in current['keys']:
                    if item['status'] not in ('WITHIN_EXPORTED_TIME_WINDOW', 'NO_EXPIRY_IN_EXPORT'):
                        issue(kind, item['status'], item['action'], fingerprint=item['fingerprint'])
                if current['signing_time_window'] != 'AVAILABLE_IN_EXPORT':
                    issue(kind, 'NO_SIGNING_WINDOW', 'Resolve the exported signing-key validity window before signing another release.')
                issue(kind, 'REVOCATION_UNAVAILABLE_OFFLINE',
                      'Review independently obtained current revocation and custody evidence before signing; this cached certificate cannot establish them.')
                checks[kind] = dict(report_age_seconds=report_age, certificate=a.pin(raw), report=current)
            elif kind == 'maintenance':
                pins.fields(raw_inputs, (*update.INPUTS, 'report'))
                raws = {name: reader.read(raw_inputs[name]) for name in update.INPUTS}
                retained = a.decode(reader.read(raw_inputs['report']))
                when = expiry.timestamp(retained['as_of'])
                r.require(when <= observed, 'maintenance report postdates observation')
                expected = update.plan(raws, retained['as_of'], retained['freshness']['cache']['max_age_hours'])
                # The producer CLI adds code receipts after computing its plan.
                payload = {k: v for k, v in retained.items() if k != 'implementation_dependencies'}
                same(payload, expected, 'maintenance report does not replay')
                report_age = age(kind, when, 'maintenance_report')
                current = update.plan(raws, as_of, max_age_hours)
                graph = a.decode(raws['graph'])
                r.require(graph['release_id'] == ctx['binding']['release_id'] and
                          graph['snapshot_id'] == ctx['binding']['snapshot_id'], 'maintenance graph generation mismatch')
                same(identities(a.decode(raws['inventory'])), identities(ctx['packages']),
                     'advisory inventory differs from exact effective release/base inventory')
                actual = {p['name']: p for p in ctx['packages']}
                for package in graph['packages']:
                    for field in ('depend', 'provides'):
                        if field in package:
                            same(sorted(package[field]), sorted(actual[package['name']][field]),
                                 'graph differs from signed runtime metadata: ' + package['name'])
                        else:
                            issue(kind, 'UNKNOWN_RUNTIME_METADATA', 'Retain the signed runtime ' + field + ' metadata in the pre-change graph.',
                                  package=package['name'], field=field)
                builds = {row['package']: row for row in graph['build_dependencies']}
                sources = {row['id']: row for row in graph['sources']}
                for name, source in ctx['sources'].items():
                    selected = sources.get(builds.get(name, {}).get('source_id'))
                    if selected is None:
                        issue(kind, 'SIGNED_SOURCE_MAPPING_UNAVAILABLE', 'Map the build unit to the signed recipe/source provenance.', package=name)
                    else:
                        same({k: selected[k] for k in ('recipe_sha256', 'sources')},
                             {k: source[k] for k in ('recipe_sha256', 'sources')},
                             'maintenance graph differs from signed recipe/source pins: ' + name)
                for hold in current['global_holds']:
                    issue(kind, hold['code'], hold['action'])
                for package in current['package_reviews']:
                    for hold in package['holds']:
                        issue(kind, hold['code'], hold['action'], package=package['name'])
                held = [group for group in current['maintenance_groups'] if group['held']]
                for group in held:
                    issue(kind, 'REBUILD_HELD', 'Resolve the retained rebuild and prerequisite holds before scheduling this group.',
                          group=group['id'], packages=group['packages'], holds=group['holds'],
                          rebuild_actions=group['rebuild_actions'], held_prerequisites=group['held_prerequisites'])
                checks[kind] = dict(report_age_seconds=report_age, freshness=current['freshness'],
                                   coverage_packages=len(current['package_reviews']), held_rebuild_groups=len(held),
                                   advisory_summary=dict(Counter(p['advisory_status'] for p in current['package_reviews'])),
                                   arm_security_status='UNKNOWN', build_status='NOT_RUN')
            elif kind == 'sources':
                pins.fields(raw_inputs, ('candidate', 'report'))
                candidate = reader.read(raw_inputs['candidate'])
                retained = a.decode(reader.read(raw_inputs['report']))
                pins.candidate(candidate, raw_inputs['candidate']['sha256'])
                # check_source_pins authenticates and binds the release again.
                expected = pins.check_source_pins(ctx['path'], reader.root / raw_inputs['candidate']['path'],
                                                  pins.digest(candidate), key, env)
                same(retained, expected, 'source observation does not replay')
                if expected['changes'] or not expected['coverage']['exact_package_set']:
                    issue(kind, 'SOURCE_DRIFT', 'Review the exact added/removed package and recipe/source changes; build and validate an explicit successor.',
                          changes=expected['changes'], coverage=expected['coverage'])
                issue(kind, 'UPSTREAM_FRESHNESS_UNAVAILABLE_OFFLINE',
                      'Obtain and review timestamped upstream/base source observations separately; this comparison covers only the supplied candidate.')
                checks[kind] = dict(candidate_sha256=pins.digest(candidate), coverage=expected['coverage'],
                                   changed_packages=len(expected['changes']), candidate_authenticated=False,
                                   upstream_freshness='UNKNOWN_OFFLINE', base_source_pins_checked=False)
            elif kind == 'comparison':
                pins.fields(raw_inputs, ('predecessor', 'report'))
                predecessor = raw_inputs['predecessor']
                pins.fields(predecessor, ('path', 'sha256'))
                path = comparison.directory(reader.root / predecessor['path'])
                prior = context(path, predecessor['sha256'], key, env)
                r.require(prior['binding']['release_sha256'] != ctx['binding']['release_sha256'],
                          'predecessor must be a different release generation')
                r.require(datetime.fromisoformat(prior['created_utc']) <= created,
                          'predecessor is newer than selected release')
                retained = a.decode(reader.read(raw_inputs['report']))
                expected = comparison.compare_releases(path, ctx['path'], key, env)
                same(retained, expected, 'release comparison does not replay')
                for change in expected['packages']:
                    if change['change'] in ('downgraded', 'same-version-byte-change', 'removed', 'equivalent-version'):
                        issue(kind, 'PACKAGE_TRANSITION_REVIEW', 'Review the selected package transition and retain explicit compatibility and recovery evidence.',
                              package=change['name'], change=change['change'], before=change['before'], after=change['after'])
                checks[kind] = dict(before=expected['before'], after=expected['after'],
                                   package_changes=expected['packages'], dependency_impact=expected['dependency_impact'])
                impact = expected['dependency_impact']['unchanged_dependents']
                if impact:
                    issue(kind, 'DEPENDENCY_IMPACT_REVIEW', 'Review unchanged runtime consumers of changed providers; retain build and compatibility evidence.',
                          packages=[p['name'] for p in impact])
                if expected['policy'] or expected['coordinated_sets']:
                    issue(kind, 'COORDINATED_POLICY_REVIEW', 'Review the changed coordinated versions and support/protection policy against target compatibility evidence.')
            else:
                pins.fields(raw_inputs, ('record',))
                value = a.decode(reader.read(raw_inputs['record']))
                pins.fields(value, ('roles', 'package_owners', 'capacity'))
                pins.fields(value['roles'], ROLES)
                r.require(type(value['package_owners']) is dict and
                          set(value['package_owners']) == {p['name'] for p in ctx['packages']},
                          'operations package owner coverage must equal exact effective inventory')
                capacity = value['capacity']
                pins.fields(capacity, ('native_aarch64_slots', 'builder_owner', 'builder_reference',
                                      'repository_owner', 'repository_reference'))
                slots = capacity['native_aarch64_slots']
                r.require(slots is None or type(slots) is int and 0 <= slots <= 1024, 'bounded native capacity or null')
                for scope, values in (('role', value['roles']), ('package', value['package_owners']),
                                      ('capacity', {k: v for k, v in capacity.items() if k != 'native_aarch64_slots'})):
                    for name, owner in values.items():
                        r.require(owner is None or type(owner) is str and 0 < len(owner) <= 512 and owner.isprintable(),
                                  'bounded owner/reference text or null required')
                        if owner is None:
                            issue(kind, 'MAINTENANCE_' + scope.upper() + '_MISSING',
                                  'Assign and record an accountable ' + scope + ' owner/reference for ' + name + '.', name=name)
                if not slots:
                    issue(kind, 'NATIVE_CAPACITY_UNAVAILABLE', 'Reserve accountable native aarch64 build capacity and record a reviewed availability reference.')
                checks[kind] = dict(record=value, verification='OPERATOR_RECORD_NOT_STAFFING_OR_CAPACITY_ACCEPTANCE')
        except FileNotFoundError as error:
            issue(kind, 'EVIDENCE_UNAVAILABLE', 'Restore the missing retained ' + kind + ' input and rerun.', path=str(error.filename))
            checks[kind] = dict(status='UNAVAILABLE')
        checks[kind].update(observation_age_seconds=elapsed,
                            status=checks[kind].get('status', 'REVIEW_REQUIRED' if len(findings) > start else 'REPLAYED_FINITE'))
    return dict(schema_version=1, status='OFFLINE_HEALTH_REVIEW_REQUIRED' if findings else 'FINITE_OBSERVATIONS_REPLAYED',
                as_of=as_of, max_age_hours=max_age_hours, binding=ctx['binding'], checks=checks, findings=findings,
                summary=dict(Counter(row['code'] for row in findings)),
                release_authenticated_to_supplied_fingerprint=True, observations_authenticated=False,
                release_verification_time='CURRENT_GPG_TIME_NOT_HISTORICAL_AS_OF',
                arm_security_status='UNKNOWN', maintenance_acceptance='NOT_ESTABLISHED',
                publication_selection_or_withdrawal='NOT_CHECKED',
                native_build='NOT_RUN', installed_lifecycle='NOT_RUN', physical_m2='NOT_RUN',
                limitations=['Only the supplied signed release bundle is authenticated to the independently selected fingerprint.',
                             'Observation timestamps/bindings, candidate sources, build graphs, owners and capacity are operator records; digests do not authenticate them.',
                             'Offline certificate exports cannot establish current revocation or custody. No caller trust state is changed.',
                             'Arch references never establish ARM applicability or mitigation; missing matches remain unknown.',
                             'Finite package scope is the signed release plus signed base inventory, with release packages taking precedence.',
                             'Source comparison does not discover current upstream revisions or base source pins.',
                             'No network, scheduler, build, installation, signing, publication or hardware operation is performed.'])


def text_report(value):
    lines = [value['status'], 'Release ' + value['binding']['release_id'] + ' ' + value['binding']['release_sha256'],
             'As of ' + value['as_of'] + '; ARM security UNKNOWN; maintenance acceptance NOT_ESTABLISHED']
    for kind, check in value['checks'].items():
        lines.append(kind + ': ' + check['status'])
        if kind == 'signing' and 'report' in check:
            for key in check['report']['keys']:
                lines.append(f"  {key['role']} {key['fingerprint']}: {key['status']}; expiry epoch={key['expires_epoch']}; seconds remaining={key['seconds_until_expiry']}")
        if kind == 'maintenance' and 'coverage_packages' in check:
            lines.append(f"  Packages reviewed={check['coverage_packages']}; held rebuild groups={check['held_rebuild_groups']}; advisory coverage={check['advisory_summary']}")
        if kind == 'comparison' and 'package_changes' in check:
            for change in check['package_changes']:
                before, after = change['before'] or {}, change['after'] or {}
                lines.append(f"  {change['name']}: {change['change']}; {before.get('version')} -> {after.get('version')}; artifact {before.get('sha256')} -> {after.get('sha256')}")
        if kind == 'sources' and 'coverage' in check:
            lines.append(f"  Changed packages={check['changed_packages']}; coverage={check['coverage']}; upstream freshness UNKNOWN_OFFLINE")
    for row in value['findings']:
        detail = ' [' + row.get('package', row.get('name', row.get('group', ''))) + ']'
        lines.append(row['kind'] + ' ' + row['code'] + detail + ': ' + row['action'])
        if row['code'] == 'PACKAGE_TRANSITION_REVIEW':
            lines.append('  ' + row['change'] + ': ' + str(row['before']) + ' -> ' + str(row['after']))
        if row['code'] == 'SOURCE_DRIFT':
            for change in row['changes']:
                lines.append('  ' + change['name'] + ': ' + ', '.join(change['fields']))
            lines.append('  Missing: ' + ', '.join(row['coverage']['missing']) + '; extra: ' + ', '.join(row['coverage']['extra']))
    return '\n'.join([*lines, '', *value['limitations']]) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('release', 'release-sha256', 'key', 'gpg-home', 'as-of'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--observations', type=Path)
    parser.add_argument('--observations-sha256')
    parser.add_argument('--context-only', action='store_true', help='print authenticated binding for observation preparation')
    parser.add_argument('--max-age-hours', type=int, default=24)
    parser.add_argument('--format', choices=('json', 'text'), default='json')
    args = parser.parse_args(argv)
    try:
        expiry.timestamp(args.as_of)
        r.require(type(args.release_sha256) is str and r.HEX.fullmatch(args.release_sha256), 'release SHA-256 required')
        key = r.fingerprint(args.key)
        release = comparison.directory(args.release)
        dependencies = {Path(__file__).resolve(), ROOT / 'scripts/release/check_source_pins.py',
                        ROOT / 'scripts/release/compare_releases.py', ROOT / 'scripts/maintenance/signing_expiry.py',
                        ROOT / 'scripts/maintenance/update_plan.py', update.REBUILD, update.ADVISORY,
                        ROOT / 'scripts/release/release.py', ROOT / 'scripts/release/source_delivery.py'}
        dependencies_before = {str(path.relative_to(ROOT)): a.pin(a.read(path)) for path in sorted(dependencies)}
        with verification_env(args.gpg_home, release) as env:
            ctx = context(release, args.release_sha256, key, env)
            created = datetime.fromisoformat(ctx['created_utc'])
            r.require(created.tzinfo == timezone.utc and created.timestamp() <= expiry.timestamp(args.as_of),
                      'release created time invalid or in the future')
            if args.context_only:
                output = a.encoded(ctx['binding'])
            else:
                ctx['path'] = release
                reader = Reader(args.observations.parent if args.observations else Path.cwd())
                observations = dict(schema_version=1, observations={})
                if args.observations:
                    observations = a.decode(reader.read(dict(path=str(args.observations.absolute()), sha256=args.observations_sha256)))
                else:
                    r.require(args.observations_sha256 is None, 'observations path required for its checksum')
                value = assess(ctx, observations, reader, key, env, args.as_of, args.max_age_hours)
                final = context(release, args.release_sha256, key, env)
                same({k: v for k, v in ctx.items() if k != 'path'}, final, 'release changed during health review')
                value['implementation_dependencies'] = dependencies_before
                reader.finish()
                output = pins.encoded(value) if args.format == 'json' else text_report(value).encode()
                r.require(len(output) <= pins.MAX_OUTPUT, 'health report output byte bound')
        same(dependencies_before, {str(path.relative_to(ROOT)): a.pin(a.read(path)) for path in sorted(dependencies)},
             'implementation changed during health review')
        sys.stdout.write(output.decode())
        return 0
    except ERRORS as error:
        print('maintenance health: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
