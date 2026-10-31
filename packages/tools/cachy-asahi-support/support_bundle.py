#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create or verify a finite offline support bundle from explicitly reviewed JSON."""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import types
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

MAX_INPUT = 1024 * 1024
MAX_ARCHIVE = 2 * 1024 * 1024
KINDS = ('signing', 'maintenance', 'sources', 'comparison', 'operations')
STATES = ('checked', 'unknown', 'unavailable')
ACTIVE = ('active', 'reloading', 'inactive', 'failed', 'activating', 'deactivating', 'maintenance', 'refreshing')
LOAD = ('loaded', 'not-found', 'error', 'masked', 'bad-setting', 'merged', 'stub')
REASONS = ('observed', 'total-deadline', 'local-endpoint-unavailable', 'local-endpoint-changed',
           'command-absent', 'query-denied', 'query-failed', 'query-warning', 'timeout', 'output-limit',
           'launch-failed', 'read-failed', 'malformed-or-unsupported-output', 'interface-unavailable',
           'not-exposed-by-selected-interface', 'reaping-policy-incompatible', 'reaping-policy-unverified',
           'child-reservation-lost', 'child-reservation-unverified', 'cleanup-incomplete')
MEMBERS = {'summary.txt', 'reports/session.json', 'reports/doctor.json', 'reports/doctor-before.json',
           'reports/doctor-after.json', 'reports/doctor-comparison.json', 'reports/health.json'}
LIMITATION = ('Supplied observations and release identity are operator records. Hashes bind bytes, not truth. '
              'No collection, authentication replay, repair, upload, native build, installed lifecycle, '
              'physical M2, recovery, performance or release acceptance is established.\n')


def require(ok):
    if not ok:
        raise ValueError('unsupported, changed or malformed input')


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return dict(bytes=len(raw), sha256=digest(raw))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value)
            value[key] = item
        return value
    def invalid(_):
        raise ValueError('invalid JSON constant')
    def floating(value):
        result = float(value)
        require(math.isfinite(result))
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid, parse_float=floating)


def hex_value(value, lengths=(64,)):
    require(type(value) is str and len(value) in lengths and re.fullmatch('[0-9a-f]+', value))
    return value


def count(value, maximum=1000000):
    require(type(value) is int and 0 <= value <= maximum)
    return value


def timestamp(value):
    require(type(value) is str and len(value) <= 40)
    parsed = datetime.fromisoformat(value)
    require(parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0)
    # Normalize instead of retaining arbitrary original strings.
    return parsed.isoformat()


def text(value, maximum=4096):
    require(type(value) is str and len(value) <= maximum)


def directory_fd(path):
    path = Path(os.path.abspath(path))
    require('..' not in Path(path).parts)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(path, maximum=MAX_INPUT):
    """Open through directory descriptors; no symlink, FIFO, device or hardlink."""
    require('..' not in Path(path).parts)
    path = Path(os.path.abspath(path))
    parent = directory_fd(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        stable = lambda info: tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        require(stable(before) == stable(after) and len(raw) == before.st_size)
        return raw
    finally:
        os.close(fd)


def load_current(relative, name):
    """Only current repository APIs; verification needs no repository imports."""
    root = next(p for p in Path(__file__).resolve().parents if (p / 'scripts/hardware/session_probe.py').is_file())
    path = root / relative
    raw = read_file(path)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module, dict(path=relative, **pin(raw))


def service(value):
    fields(value, 'LoadState ActiveState SubState')
    require(value['LoadState'] in LOAD and value['ActiveState'] in ACTIVE)
    require(type(value['SubState']) is str and re.fullmatch('[a-z-]{1,64}', value['SubState']))
    # SubState is free text in the producer; retain only two finite enums.
    return {key: value[key] for key in ('LoadState', 'ActiveState')}


def doctor_projection(validated):
    result = {}
    for name, row in validated['rows'].items():
        value = row['value']
        safe = None
        if name.startswith('package/'):
            safe = dict(presence=value['presence'])
        elif name.startswith(('user/', 'system/')) and row['state'] == 'checked':
            safe = service(value)
        elif name == 'platform':
            safe = dict(page_size_bytes=value['page_size_bytes'])
        elif name == 'apple-model':
            safe = dict(identifier=value['identifier'])
        elif name == 'session':
            safe = value
        elif name == 'tools' or name == 'audio/default-output':
            safe = value
        result[name] = dict(state=row['state'], value=safe)
    return dict(version=validated['version'], collected_utc=timestamp(validated['collected_utc']),
                checks=result, coverage=dict(Counter(row['state'] for row in result.values())))


def session_projection(report, producer, identity):
    fields(report, 'schema_version record_type collected_at tool_sha256 identity session_hints limits tools_available checks coverage physical_checks limitations')
    require(type(report['schema_version']) is int and report['schema_version'] == 1 and report['record_type'] == 'session-observations')
    hex_value(report['tool_sha256'])
    original = report['identity']
    fields(original, 'declared_model_id source_revision baseline_sha256 execution_context architecture kernel page_size_bytes observed_model_id declared_model_matches_observation')
    for name in ('declared_model_id', 'observed_model_id'):
        require(original[name] is None or original[name] in producer.MODELS)
    for name, lengths in (('source_revision', (40, 64)), ('baseline_sha256', (64,))):
        if original[name] is not None:
            hex_value(original[name], lengths)
    require(original['source_revision'] in (None, identity['source_commit']))
    require(original['execution_context'] in ('physical', 'virtual', 'emulated', 'unknown'))
    for name in ('kernel', 'architecture'):
        text(original[name], 256)
    size = count(original['page_size_bytes'], 1048576)
    require(size >= 1024 and size & (size - 1) == 0)
    declared, observed = original['declared_model_id'], original['observed_model_id']
    require(observed is None or original['architecture'] == 'aarch64')
    expected_match = declared == observed if declared and observed else None
    require(original['declared_model_matches_observation'] is expected_match)
    fields(report['session_hints'], 'session_type wayland_environment_present hyprland_environment_present')
    require(report['session_hints']['session_type'] in (None, 'wayland', 'x11', 'tty'))
    require(all(type(v) is bool for k, v in report['session_hints'].items() if k != 'session_type'))
    require(report['limits'] == dict(command_seconds=2, total_query_seconds=20,
                                    combined_output_bytes_per_command=524288, cleanup_seconds_per_command=1))
    require(all(type(v) is int for v in report['limits'].values()))
    fields(report['tools_available'], 'hyprctl eglinfo systemctl loginctl pw-dump busctl')
    require(all(type(v) is bool for v in report['tools_available'].values()))
    require(report['physical_checks'] == dict.fromkeys(producer.PHYSICAL_CHECKS, 'NOT RUN'))
    require(type(report['limitations']) is list and len(report['limitations']) <= 16)
    for item in report['limitations']:
        text(item)
    names = {'hyprland/version', 'hyprland/displays', 'hyprland/compositor-renderer',
             'renderer/wayland-gles-client', 'session/logind', 'audio/graph', 'suspend/logind-capability',
             'suspend/kernel-state', 'suspend/kernel-mem_sleep'}
    names.update('user/' + unit for unit in producer.USER_UNITS)
    names.update('system/' + unit for unit in producer.SYSTEM_UNITS)
    require(type(report['checks']) is list and len(report['checks']) == len(names))
    rows = {}
    for row in report['checks']:
        require(type(row) is dict and {'check', 'state', 'reason', 'value', 'note'} <= row.keys()
                and not row.keys() - {'check', 'state', 'reason', 'value', 'note', 'argv', 'returncode'})
        name, state, value = row['check'], row['state'], row['value']
        require(type(name) is str and name in names and name not in rows and state in STATES and row['reason'] in REASONS)
        text(row['note'])
        if 'argv' in row:
            require(type(row['argv']) is list and len(row['argv']) <= 32)
            for argument in row['argv']:
                text(argument)
        if 'returncode' in row:
            require(row['returncode'] is None or type(row['returncode']) is int and -255 <= row['returncode'] <= 255)
        safe = None
        if state != 'checked':
            require(value is None and row['reason'] != 'observed')
        else:
            require(row['reason'] == 'observed')
            if name.startswith(('user/', 'system/')):
                safe = service(value)
            elif name == 'suspend/logind-capability':
                fields(value, 'logind_can_suspend')
                require(value['logind_can_suspend'] in ('yes', 'no', 'challenge', 'na'))
                safe = value
            elif name.startswith('suspend/kernel-'):
                require(type(value) is list and all(type(v) is str for v in value))
                allowed = {'freeze', 'standby', 'mem', 'disk'} if name.endswith('state') else {'s2idle', 'shallow', 'deep'}
                safe = producer.power_tokens(' '.join(value).encode(), allowed)
            elif name == 'hyprland/version':
                fields(value, 'version commit')
                text(value['version'], 100)
                hex_value(value['commit'], (40, 64))
            elif name == 'hyprland/displays':
                require(type(value) is list and len(value) <= 32)
                for index, display in enumerate(value):
                    require(type(display) is dict and not display.keys() - {'index', 'width', 'height', 'refresh_hz', 'scale', 'transform', 'dpmsStatus', 'disabled', 'focused'})
                    require(type(display['index']) is int and display['index'] == index)
                    for key, low, high in (('width', 1, 32768), ('height', 1, 32768), ('refresh_hz', 1, 2000), ('scale', .1, 10), ('transform', 0, 7)):
                        producer.number(display[key], low, high)
                    require(all(type(v) is bool for k, v in display.items() if k in ('dpmsStatus', 'disabled', 'focused')))
                safe = value
            elif name == 'renderer/wayland-gles-client':
                fields(value, 'vendor renderer version software_renderer_hint')
                for key in ('vendor', 'renderer', 'version'):
                    text(value[key], 240)
                require(type(value['software_renderer_hint']) is bool)
                safe = dict(software_renderer_hint=value['software_renderer_hint'])
            elif name == 'session/logind':
                fields(value, 'Type Class State Active Remote LockedHint')
                # Unknown future scalar values remain unknown in the projection.
                enums = dict(Type=('wayland', 'x11', 'tty', 'unspecified'), Class=('user', 'greeter', 'lock-screen', 'background', 'manager'),
                             State=('opening', 'active', 'online', 'closing'), Active=('yes', 'no'), Remote=('yes', 'no'), LockedHint=('yes', 'no'))
                for item in value.values():
                    require(type(item) is str and re.fullmatch('[a-z-]{1,64}', item))
                safe = {k: v if v in enums[k] else 'unknown' for k, v in value.items()}
            elif name == 'audio/graph':
                fields(value, 'media_class_counts node_state_counts link_state_counts known_asahi_graph_nodes speaker_protection')
                require(value['speaker_protection'] == 'NOT TESTED')
                for key, allowed in (('media_class_counts', ('Audio/Sink', 'Audio/Source', 'Audio/Source/Virtual', 'Audio/Sink/Virtual')),
                                     ('node_state_counts', ('creating', 'suspended', 'idle', 'running', 'error')),
                                     ('link_state_counts', ('error', 'unlinked', 'init', 'negotiating', 'allocating', 'paused', 'active'))):
                    require(type(value[key]) is dict and not value[key].keys() - set(allowed))
                    for number in value[key].values():
                        count(number, 4096)
                nodes = value['known_asahi_graph_nodes']
                require(type(nodes) is list and len(nodes) <= 8 and all(type(v) is str and re.fullmatch(r'(audio_effect|effect_output)\.j(413|415)-(convolver|mic)', v) for v in nodes))
                safe = value
            else:
                require(False)  # Selected compositor interface never reports a renderer.
        rows[name] = dict(state=state, reason=row['reason'], value=safe)
    require(report['coverage'] == dict(Counter(row['state'] for row in rows.values())))
    require(all(type(v) is int for v in report['coverage'].values()))
    return dict(collected_at=timestamp(report['collected_at']), tool_sha256=report['tool_sha256'],
                identity={k: original[k] for k in ('source_revision', 'baseline_sha256', 'execution_context',
                                                 'declared_model_id', 'observed_model_id', 'page_size_bytes')},
                session_hints=report['session_hints'], tools_available=report['tools_available'],
                checks=rows, coverage=report['coverage'], physical_checks=report['physical_checks'])


def health_projection(report, identity):
    fields(report, 'schema_version status as_of max_age_hours binding checks findings summary release_authenticated_to_supplied_fingerprint observations_authenticated release_verification_time arm_security_status maintenance_acceptance publication_selection_or_withdrawal native_build installed_lifecycle physical_m2 limitations implementation_dependencies')
    require(type(report['schema_version']) is int and report['schema_version'] == 1)
    require(report['status'] in ('OFFLINE_HEALTH_REVIEW_REQUIRED', 'FINITE_OBSERVATIONS_REPLAYED'))
    binding = report['binding']
    fields(binding, 'release_id release_sha256 source_commit snapshot_id synthetic package_inventory_sha256 project_sources_sha256')
    require(all(binding[k] == identity[k] for k in identity))
    text(binding['snapshot_id'])
    require(type(binding['synthetic']) is bool)
    for key in ('package_inventory_sha256', 'project_sources_sha256'):
        hex_value(binding[key])
    require(type(report['max_age_hours']) is int and 1 <= report['max_age_hours'] <= 8760)
    require(report['release_authenticated_to_supplied_fingerprint'] is True and report['observations_authenticated'] is False)
    for key, value in dict(release_verification_time='CURRENT_GPG_TIME_NOT_HISTORICAL_AS_OF', arm_security_status='UNKNOWN',
                           maintenance_acceptance='NOT_ESTABLISHED', publication_selection_or_withdrawal='NOT_CHECKED',
                           native_build='NOT_RUN', installed_lifecycle='NOT_RUN', physical_m2='NOT_RUN').items():
        require(report[key] == value)
    require(type(report['checks']) is dict and set(report['checks']) == set(KINDS))
    checks = {}
    check_fields = dict(signing='report_age_seconds certificate report',
        maintenance='report_age_seconds freshness coverage_packages held_rebuild_groups advisory_summary arm_security_status build_status',
        sources='candidate_sha256 coverage changed_packages candidate_authenticated upstream_freshness base_source_pins_checked',
        comparison='before after package_changes dependency_impact', operations='record verification')
    for kind, row in report['checks'].items():
        require(type(row) is dict and row.get('status') in ('UNAVAILABLE', 'REVIEW_REQUIRED', 'REPLAYED_FINITE'))
        if row['status'] == 'UNAVAILABLE':
            require(not row.keys() - {'status', 'observation_age_seconds'})
        else:
            fields(row, 'status observation_age_seconds ' + check_fields[kind])
        checks[kind] = dict(status=row['status'])
        for key in ('coverage_packages', 'held_rebuild_groups', 'changed_packages', 'report_age_seconds', 'observation_age_seconds'):
            if key in row:
                checks[kind][key] = count(row[key], 2**53)
    require(type(report['findings']) is list and len(report['findings']) <= 10000)
    codes, categories = Counter(), Counter()
    for finding in report['findings']:
        require(type(finding) is dict and finding.get('kind') in KINDS)
        code = finding.get('code')
        require(type(code) is str and re.fullmatch('[A-Z][A-Z0-9_]{0,127}', code))
        text(finding.get('action'))
        codes[code] += 1
        categories[finding['kind']] += 1
    require(report['summary'] == dict(codes) and all(type(v) is int for v in report['summary'].values()))
    require(bool(report['findings']) == (report['status'] == 'OFFLINE_HEALTH_REVIEW_REQUIRED'))
    for kind, row in checks.items():
        require((row['status'] == 'REPLAYED_FINITE') == (categories[kind] == 0))
    require(type(report['limitations']) is list and len(report['limitations']) <= 32)
    for item in report['limitations']:
        text(item)
    require(type(report['implementation_dependencies']) is dict and len(report['implementation_dependencies']) <= 32)
    for path, receipt in report['implementation_dependencies'].items():
        text(path)
        fields(receipt, 'bytes sha256')
        count(receipt['bytes'], 2**53)
        hex_value(receipt['sha256'])
    # Deliberately omit findings text/codes, owners, references, key identities and paths.
    return dict(status=report['status'], as_of=timestamp(report['as_of']), max_age_hours=report['max_age_hours'],
                synthetic=binding['synthetic'], checks=checks, finding_count=len(report['findings']),
                findings_by_kind=dict(categories), arm_security_status='UNKNOWN', maintenance_acceptance='NOT_ESTABLISHED',
                authentication='SUPPLIED_REPORT_CLAIM_NOT_REVERIFIED')


def archive_bytes(members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(raw), 0o600, 0
            archive.addfile(info, io.BytesIO(raw))
    raw = stream.getvalue()
    require(len(raw) <= MAX_ARCHIVE)
    return raw


def publish(directory, members):
    """New private directory, anchored descriptors, rollback on incomplete publication."""
    require('..' not in Path(directory).parts)
    path = Path(os.path.abspath(directory))
    parent = directory_fd(path.parent)
    created = []
    fd = None
    made_directory = False
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent)
        made_directory = True
        fd = os.open(path.name, os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        for name, raw in sorted(members.items()):
            # Fixed one-level report paths only.
            target = fd
            if '/' in name:
                require(name.startswith('reports/') and name.count('/') == 1)
                if 'reports/' not in created:
                    os.mkdir('reports', 0o700, dir_fd=fd)
                    created.append('reports/')
                target = os.open('reports', os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                out = os.open(name.rsplit('/', 1)[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target)
                created.append(name)
                with os.fdopen(out, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                if target != fd:
                    os.close(target)
    except BaseException:
        if fd is not None:
            for name in reversed(created):
                if name.endswith('/'):
                    os.rmdir(name.rstrip('/'), dir_fd=fd)
                else:
                    os.unlink(name, dir_fd=fd)
            os.close(fd)
            fd = None
            os.rmdir(path.name, dir_fd=parent)
        elif made_directory:
            os.rmdir(path.name, dir_fd=parent)
        raise
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def create(args):
    identity = dict(release_id=args.release_id, release_sha256=hex_value(args.release_sha256),
                    source_commit=hex_value(args.source_commit, (40, 64)))
    require(type(identity['release_id']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+-]{0,95}', identity['release_id']))
    require(bool(args.doctor_before) == bool(args.doctor_after))
    require(not args.doctor_comparison or args.doctor_before)
    require(any((args.session, args.doctor, args.doctor_before, args.health)))
    retained, inputs, members = {}, {}, {}
    dependencies = dict(support_bundle=dict(path='scripts/support/support_bundle.py', **pin(read_file(__file__))))
    def selected(name, ref):
        path, checksum = ref
        hex_value(checksum)
        raw = read_file(path)
        require(digest(raw) == checksum)
        retained[path] = raw
        inputs[name] = pin(raw)
        return decode(raw)
    doctor = None
    if args.doctor or args.doctor_before:
        doctor, receipt = load_current('packages/tools/cachy-asahi-doctor2/cachy-asahi-doctor', 'support_doctor')
        dependencies['doctor'] = receipt
    if args.doctor:
        members['reports/doctor.json'] = encoded(doctor_projection(doctor.validate_report(selected('doctor', args.doctor))))
    if args.doctor_before:
        before = doctor.validate_report(selected('doctor-before', args.doctor_before))
        after = doctor.validate_report(selected('doctor-after', args.doctor_after))
        comparison = doctor.compare_reports(before, after)
        if args.doctor_comparison:
            require(selected('doctor-comparison', args.doctor_comparison) == comparison)
        for name, report in (('before', before), ('after', after)):
            members['reports/doctor-' + name + '.json'] = encoded(doctor_projection(report))
        # Preserve exact change names/kinds and counts; no arbitrary version/kernel text.
        changes = [{k: row[k] for k in ('check', 'kind')} for row in comparison['changes']]
        members['reports/doctor-comparison.json'] = encoded(dict(changed=comparison['changed'],
            change_count=comparison['change_count'], unchanged_count=comparison['unchanged_count'],
            coverage=comparison['coverage'], changes=changes))
    if args.session:
        producer, receipt = load_current('scripts/hardware/session_probe.py', 'support_session')
        dependencies['session'] = receipt
        members['reports/session.json'] = encoded(session_projection(selected('session', args.session), producer, identity))
    if args.health:
        members['reports/health.json'] = encoded(health_projection(selected('health', args.health), identity))
    lines = ['Offline support bundle', 'Release: ' + identity['release_id'], 'Release SHA256: ' + identity['release_sha256'],
             'Source commit: ' + identity['source_commit'], 'Release identity is operator supplied. Doctor observations are not release-bound.']
    for name, raw in sorted(members.items()):
        value = decode(raw)
        lines.append(name + ': ' + (value.get('status') or json.dumps(value.get('coverage', {}), sort_keys=True)))
        if 'change_count' in value:
            lines.append('  Changed observations: ' + str(value['change_count']))
        for check, row in value.get('checks', {}).items():
            lines.append('  ' + check + ': ' + row.get('state', row.get('status', 'unknown')) +
                         (' ' + json.dumps(row['value'], sort_keys=True) if row.get('value') is not None else ''))
    members['summary.txt'] = ('\n'.join(lines) + '\n\n' + LIMITATION).encode()
    manifest = dict(schema_version=1, tool='cachy-asahi-support-bundle', release=identity, inputs=inputs,
                    implementation_dependencies=dependencies, members={k: pin(v) for k, v in sorted(members.items())},
                    scope='FINITE_SANITIZED_SUPPLIED_OBSERVATIONS', limitations=LIMITATION.strip())
    members['inventory.json'] = encoded(manifest)
    archive = archive_bytes(members)
    for path, raw in retained.items():
        require(read_file(path) == raw)
    for receipt in dependencies.values():
        root = next(p for p in Path(__file__).resolve().parents if (p / 'scripts/hardware/session_probe.py').is_file())
        path = Path(__file__) if receipt['path'] == 'scripts/support/support_bundle.py' else root / receipt['path']
        require(pin(read_file(path)) == {k: receipt[k] for k in ('bytes', 'sha256')})
    publish(args.output_dir, {'support-bundle.tar': archive, 'SHA256SUMS': (digest(archive) + '  support-bundle.tar\n').encode()})
    return pin(archive)


def verify(args):
    raw = read_file(args.archive, MAX_ARCHIVE)
    require(digest(raw) == hex_value(args.sha256))
    members = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for info in archive:
            require(info.name in MEMBERS | {'inventory.json'} and info.name not in members and info.isfile()
                    and 0 < info.size <= MAX_INPUT and info.mode == 0o600 and info.uid == info.gid == info.mtime == 0
                    and not info.uname and not info.gname and not info.pax_headers)
            members[info.name] = archive.extractfile(info).read(MAX_INPUT + 1)
    require('inventory.json' in members and 'summary.txt' in members and archive_bytes(members) == raw)
    inventory = decode(members['inventory.json'])
    fields(inventory, 'schema_version tool release inputs implementation_dependencies members scope limitations')
    require(type(inventory['schema_version']) is int and inventory['schema_version'] == 1
            and inventory['tool'] == 'cachy-asahi-support-bundle' and inventory['scope'] == 'FINITE_SANITIZED_SUPPLIED_OBSERVATIONS'
            and inventory['limitations'] == LIMITATION.strip())
    require(inventory['members'] == {k: pin(v) for k, v in members.items() if k != 'inventory.json'})
    if args.extract_to:
        publish(args.extract_to, members)
    return pin(raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    new = commands.add_parser('create', help='read reviewed, digest-pinned reports; collect nothing')
    for flag in ('release-id', 'release-sha256', 'source-commit', 'output-dir'):
        new.add_argument('--' + flag, required=True)
    for flag in ('session', 'doctor', 'doctor-before', 'doctor-after', 'doctor-comparison', 'health'):
        new.add_argument('--reviewed-' + flag, dest=flag.replace('-', '_'), nargs=2, metavar=('JSON', 'SHA256'))
    check = commands.add_parser('verify', help='verify exact archive hash/inventory; optionally extract privately')
    check.add_argument('--archive', required=True)
    check.add_argument('--sha256', required=True, help='independently retained expected archive SHA-256')
    check.add_argument('--extract-to')
    args = parser.parse_args(argv)
    try:
        result = create(args) if args.command == 'create' else verify(args)
        print(json.dumps(dict(status='CREATED' if args.command == 'create' else 'VERIFIED', **result), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, StopIteration, RecursionError, OverflowError, tarfile.TarError):
        print('support bundle: refused invalid input or output; no report contents echoed', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
