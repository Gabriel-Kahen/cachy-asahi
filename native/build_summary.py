# SPDX-License-Identifier: MIT
"""Whitelist build status DATA before admission; never emit raw result values."""
import json
from pathlib import Path
import re
from capsule import _ordinary
from common import need, pin, save

TOOLS = ('cmake', 'ctest', 'meson', 'ninja', 'cc', 'c++')
PROJECTS = ('cmake', 'meson')
AGGREGATE = {'PASS_AVAILABLE_LOCAL_WORKFLOWS', 'NOT_RUN_NO_BUILD_SYSTEM', 'FAIL', 'UNKNOWN', 'ABSENT'}
PROJECT_STATUS = {'PASS_REAL_PROJECT_WORKFLOW', 'NOT_RUN', 'FAIL', 'RUNNING', 'UNKNOWN', 'ABSENT'}
TOOL_STATUS = {'PRESENT', 'MISSING', 'UNKNOWN', 'ABSENT'}
LOG = re.compile(r'[0-9]{3}-[A-Za-z0-9][A-Za-z0-9_+.-]{0,127}\.log')
CAP = 512 * 1024


def _status(value, allowed, present=True):
    return value if type(value) is str and value in allowed else 'UNKNOWN' if present else 'ABSENT'


def _pin(value, cap):
    need(type(value) is dict and set(value) == {'bytes', 'sha256'} and type(value['bytes']) is int
         and 0 <= value['bytes'] <= cap and type(value['sha256']) is str
         and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'bounded diagnostic pin required')


def validate_summary(value, map_hash):
    need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
         and value.get('source_map_sha256') == map_hash and re.fullmatch('[0-9a-f]{64}', map_hash or ''), 'summary map binding')
    if value.get('status') == 'REFUSED_BUILD_SYSTEM_SUMMARY_DATA':
        need(set(value) == {'schema', 'status', 'source_map_sha256', 'reason'}
             and value['reason'] == 'BOUNDED_BUILD_STATUS_DATA_UNAVAILABLE', 'fixed build diagnostic refusal')
        return True
    need(set(value) == {'schema', 'status', 'source_map_sha256', 'aggregate', 'projects', 'tools',
         'observed_projects', 'unexpected_project_keys', 'original_result_pin', 'command_logs'}
         and value['status'] == 'BUILD_SYSTEM_SUMMARY_DATA_ONLY' and type(value['aggregate']) is str
         and value['aggregate'] in AGGREGATE,
         'fixed build summary schema')
    need(type(value['projects']) is dict and set(value['projects']) == set(PROJECTS)
         and type(value['tools']) is dict and set(value['tools']) == set(TOOLS)
         and all(type(s) is str and s in TOOL_STATUS for s in value['tools'].values()), 'fixed project/tool scalars')
    need(type(value['observed_projects']) is dict and set(value['observed_projects']) == set(PROJECTS)
         and all(type(b) is bool for b in value['observed_projects'].values())
         and type(value['unexpected_project_keys']) is bool, 'fixed project presence flags')
    for row in value['projects'].values():
        need(type(row) is dict and set(row) == {'status', 'missing', 'missing_unknown'}
             and type(row['status']) is str and row['status'] in PROJECT_STATUS
             and type(row['missing']) is dict and set(row['missing']) == set(TOOLS)
             and all(type(b) is bool for b in row['missing'].values()) and type(row['missing_unknown']) is bool,
             'fixed project status and missing-tool booleans')
    _pin(value['original_result_pin'], 16*1024**2)
    need(type(value['command_logs']) is list and len(value['command_logs']) <= 1000, 'finite log pin list')
    names = set()
    for row in value['command_logs']:
        need(type(row) is dict and set(row) == {'log', 'pin'} and type(row['log']) is str
             and LOG.fullmatch(row['log']) and row['log'] not in names, 'fixed bounded source log name')
        names.add(row['log']); _pin(row['pin'], 256*1024)
    from consumer_diagnostics import safe_text
    safe_text(json.dumps(value, sort_keys=True, allow_nan=False).encode())
    need(len(json.dumps(value).encode()) <= CAP, 'summary byte cap')
    return True


def capture(output, report, map_hash):
    output = Path(output)
    raw = _ordinary(output / 'result.json', 16*1024**2)
    need(json.loads(raw) == report and type(report) is dict, 'actual raw build result differs')
    projects = report.get('project_workflows', {}); tools = report.get('tools', {})
    need(type(projects) is dict and type(tools) is dict, 'source report maps')
    project_rows = {}
    for name in PROJECTS:
        row = projects.get(name, {}); row = row if type(row) is dict else {}
        missing = row.get('missing', []); valid = type(missing) is list and all(type(v) is str for v in missing)
        project_rows[name] = dict(status=_status(row.get('status'), PROJECT_STATUS, name in projects),
            missing={tool: bool(valid and tool in missing) for tool in TOOLS},
            missing_unknown=not valid or any(v not in TOOLS for v in missing))
    logs = []; commands = report.get('commands', [])
    need(type(commands) is list and len(commands) <= 1000, 'source command records')
    for row in commands:
        need(type(row) is dict and type(row.get('log')) is str and LOG.fullmatch(row['log']), 'source command log')
        expected = row.get('log_pin'); _pin(expected, 256*1024)
        need(pin(_ordinary(output / row['log'], 256*1024)) == expected, 'actual raw command log pin differs')
        logs.append(dict(log=row['log'], pin=expected))
    value = dict(schema=1, status='BUILD_SYSTEM_SUMMARY_DATA_ONLY', source_map_sha256=map_hash,
        aggregate=_status(report.get('status'), AGGREGATE, 'status' in report), projects=project_rows,
        tools={name: _status(tools[name].get('status') if type(tools.get(name)) is dict else None,
                           TOOL_STATUS, name in tools) for name in TOOLS},
        observed_projects={name: name in projects for name in PROJECTS},
        unexpected_project_keys=any(name not in PROJECTS for name in projects),
        original_result_pin=pin(raw), command_logs=logs)
    validate_summary(value, map_hash)
    return value


def emit(output, report, map_hash, write_root, emit_line=print):
    try:
        value = capture(output, report, map_hash)
    except Exception:
        value = dict(schema=1, status='REFUSED_BUILD_SYSTEM_SUMMARY_DATA', source_map_sha256=map_hash,
                     reason='BOUNDED_BUILD_STATUS_DATA_UNAVAILABLE')
    try:
        save(Path(write_root) / 'build-summary.json', value)
        emit_line('NATIVE_BUILD_SUMMARY ' + json.dumps(value, sort_keys=True, allow_nan=False), flush=True)
    except Exception:
        pass  # Preserve the following original aggregate guard and its error.
    return value


def validate_bound(value, own, map_hash):
    need(type(value) is dict and set(value) == {'schema', 'status', 'binding', 'source_map_sha256',
         'guest_summary_pin', 'guest_summary'} and type(value['schema']) is int and value['schema'] == 1
         and value['status'] == 'BOUND_BUILD_SUMMARY_DATA_ONLY' and value['binding'] == own
         and value['source_map_sha256'] == map_hash, 'bound build summary schema')
    _pin(value['guest_summary_pin'], CAP)
    validate_summary(value['guest_summary'], map_hash)
    return True


def bind(output, own, map_hash):
    """Source/run envelope around unchanged original guest scalar DATA."""
    output = Path(output)
    try:
        raw = _ordinary(output / 'journey/build-summary.json', CAP)
    except FileNotFoundError:
        return None
    summary = json.loads(raw); validate_summary(summary, map_hash)
    value = dict(schema=1, status='BOUND_BUILD_SUMMARY_DATA_ONLY', binding=own,
        source_map_sha256=map_hash, guest_summary_pin=pin(raw), guest_summary=summary)
    validate_bound(value, own, map_hash); save(output / 'build-summary.json', value)
    return value
