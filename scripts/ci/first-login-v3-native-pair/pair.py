#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage and check the fixed First Login 0.1.0-3 hosted native pair."""

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / 'inputs.json').read_bytes())
SETUP = 'cachy-asahi-setup-0.3.0-1-any.pkg.tar.xz'
FIRST_LOGIN = 'cachy-asahi-first-login-0.1.0-3'
ARCHIVE = FIRST_LOGIN + '-any.pkg.tar.xz'
CHECK_LOG = FIRST_LOGIN + '-aarch64-check.log'
LOCK_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
BOOTSTRAP_SHA = '8e71ba83e7d5037c6f7772401ec3b872684ccfa8472d855d8d6d3052cb1f41ba'
FISH_TOOL_PINS = {
    'build_fish02.py': ('0fb88871886dfbc1ede2e2c1fe0ec6408475c0a48acf0c98da74fb8fed61409b', 1),
    'compare_fish_xz.py': ('83f5b90abe76462e912419205aa937084b0d94e600e11f9be5be7d4fb29020ec', 2),
}
CASES = {
    'test_first_login.py': frozenset((
        'test_helper_context_excludes_ambient_python_and_current_directory',
        'test_real_helper_ignores_poisoned_python_path_home_and_interpreter_path',
        'test_emitted_inspect_command_is_isolated_and_preserves_frozen_roots',
        'test_inspect_and_preview_have_no_writes_and_explicit_selection',
        'test_apply_repeat_and_real_helper_deactivation_preserve_existing_bytes',
        'test_unavailable_program_or_template_blocks_entire_selection',
        'test_config_conflict_blocks_other_selected_components_before_apply',
        'test_interruption_is_routed_to_explicit_preview_then_recovery',
        'test_recovery_preserves_custom_path_options_and_edits',
        'test_migration_journal_is_redirected_to_its_owner_without_replay',
        'test_environment_roots_are_frozen_for_recovery_from_another_shell',
        'test_unknown_state_and_symlinked_targets_fail_without_apply',
        'test_incompatible_helper_status_refuses_operation',
        'test_cli_returns_json_and_root_refusal',
    )),
    'test_delivery.py': frozenset((
        'test_installed_inspect_isolated_through_actual_setup_helper',
        'test_installed_printed_preview_and_apply_followups_keep_isolation_and_roots',
        'test_candidate_payload_uninstall_preserves_user_configuration',
        'test_actual_package_function_installs_only_six_opt_in_files',
        'test_relocated_launcher_runs_without_checkout_or_cwd_python_imports',
        'test_relocated_inspect_and_preview_preserve_fresh_home',
    )),
}
VERBOSE_CASE = re.compile(rb'^(test_\w+) \([^\r\n]*\) \.\.\. ok$', re.M)


def need(value, why):
    if not value:
        raise ValueError(why)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, limit):
    path = Path(path)
    info = path.lstat()
    need(path.absolute() == path.resolve() and stat.S_ISREG(info.st_mode)
         and info.st_nlink == 1 and 0 < info.st_size <= limit, 'ordinary bounded file required: ' + path.name)
    with path.open('rb') as stream:
        body = stream.read(limit + 1)
    current = path.lstat()
    need(len(body) == info.st_size and (info.st_dev, info.st_ino, info.st_ctime_ns) ==
         (current.st_dev, current.st_ino, current.st_ctime_ns), 'file changed: ' + path.name)
    return body


def json_data(path, limit=4 * 1024**2):
    return json.loads(read(path, limit))


def builder_lock(original):
    need(digest(original) == LOCK_SHA, 'exact proven Fish 341-package inventory required')
    lines = original.decode('ascii').splitlines()
    need(len(lines) == 341 and not any(row.startswith('cachy-asahi-setup ') for row in lines),
         'one new Setup8 operand required')
    return ('\n'.join(sorted([*lines, 'cachy-asahi-setup 0.3.0-1'])) + '\n').encode()


def project_tool(name, body):
    """Keep Fish r12's proven owned argv and exact XZ gates for this archive."""
    expected, count = FISH_TOOL_PINS[name]
    before, after = b'cachy-asahi-fish-config-0.1.0-2-any.pkg.tar.xz', ARCHIVE.encode()
    need(digest(body) == expected and body.count(before) == count and after not in body,
         'exact proven Fish builder/comparator required')
    result = body.replace(before, after)
    need(result.replace(after, before) == body, 'whole original native builder or comparator inverse')
    compile(result, name, 'exec')
    return result


def review_recipe(sources):
    need({name: digest(body) for name, body in sources.items()} == PINS['recipe'],
         'exact First Login recipe snapshot required')
    for name, cases in CASES.items():
        actual = {node.name for node in ast.walk(ast.parse(sources[name]))
                  if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')}
        need(actual == cases, 'exact normal check() case identities required')


def prepare(recipe, original_lock, overlay, output, fish_tools):
    """Write only public source and exact operand pins for a later admitted build."""
    need(output.is_absolute() and output == output.resolve() and not output.exists()
         and not output.is_relative_to(recipe.resolve()) and not output.is_relative_to(overlay.resolve()),
         'fresh disjoint output directory required')
    sources = {name: read(recipe / name, 64 * 1024) for name in PINS['recipe']}
    review_recipe(sources)
    lock = builder_lock(read(original_lock, 32 * 1024))
    tools = {name: project_tool(name, read(fish_tools / name, 32 * 1024)) for name in FISH_TOOL_PINS}
    # The old TEST certificate remains an external reviewed input to the future carrier.
    # Its pin is recorded here without opening a key or invoking a verifier.
    dependency = {}
    for role, name in (('archive', SETUP), ('signature', SETUP + '.sig')):
        expected = PINS['setup8'][role]
        body = read(overlay / 'release/repo' / name, expected['bytes'])
        need({'bytes': len(body), 'sha256': digest(body)} == expected, 'exact Setup8 ' + role + ' required')
        dependency[name] = body
    output.mkdir(mode=0o700)
    (output / 'recipe').mkdir()
    (output / 'dependency').mkdir()
    (output / 'tool-projections').mkdir()
    for name, body in sources.items():
        (output / 'recipe' / name).write_bytes(body)
    for name, body in dependency.items():
        (output / 'dependency' / name).write_bytes(body)
    for name, body in tools.items():
        (output / 'tool-projections' / name).write_bytes(body)
    (output / 'expected342.lock').write_bytes(lock)
    (output / 'reviewed-inputs.json').write_text(json.dumps(PINS['recipe'], indent=2, sort_keys=True) + '\n')
    (output / 'plan.DATA.json').write_text(json.dumps({
        'status': 'PREPARED_FIRST_LOGIN_PAIR_INPUTS_ONLY',
        'recipe': 'cachy-asahi-first-login 0.1.0-3',
        'archive': ARCHIVE,
        'check_log': CHECK_LOG,
        'expected_builder': {'count': 342, 'sha256': digest(lock)},
        'tool_projections': {name: digest(body) for name, body in tools.items()},
        'setup8': PINS['setup8'],
        'required_checks': {name: sorted(cases) for name, cases in CASES.items()},
        'actual': {'source': None, 'run': None, 'job': None, 'image': None, 'Root_acceptance': None},
    }, indent=2, sort_keys=True) + '\n')


def check_log(raw):
    rows = VERBOSE_CASE.findall(raw)
    expected = set().union(*CASES.values())
    need(len(rows) == len(expected) and {row.decode('ascii') for row in rows} == expected,
         'all named normal makepkg checks must pass once')
    need(re.findall(rb'^Ran (\d+) tests? in .*\r?$', raw, re.M) == [str(len(cases)).encode() for cases in CASES.values()]
         and len(re.findall(rb'^OK\r?$', raw, re.M)) == 2, 'both test groups must finish normally')


def finish(first, second, comparison, image, lock):
    """Require strict comparator result, exact environments and original raw checks."""
    need(first.resolve() != second.resolve() and re.fullmatch(r'sha256:[0-9a-f]{64}', image),
         'distinct native build trees and immutable image required')
    expected = read(lock, 32 * 1024)
    base = [line for line in expected.splitlines(keepends=True)
            if line != b'cachy-asahi-setup 0.3.0-1\n']
    need(builder_lock(b''.join(base)) == expected, 'exact sorted 342-package lock required')
    compared = json_data(comparison)
    need(compared.get('status') == 'contents-reproduced' and compared.get('errors') == []
         and len(compared['packages']) == 1, 'successful strict comparator required')
    package, equal = next(iter(compared['packages'].items()))
    need(package == ARCHIVE and all(equal.get(name) is True for name in
         ('installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal', 'bytes_equal')),
         'exact any archive, installed tree, package metadata and bytes must compare equal')
    builds = []
    for root in (first, second):
        record = json_data(root / 'provenance.json')
        need(record.get('status') == 'built-package-static-pass' and record.get('exit_code') == 0
             and record.get('mode') == 'native' and record.get('builder_host_arch') == 'aarch64'
             and record.get('image_id') == image and record.get('recipe_inputs') == PINS['recipe']
             and record.get('expected_packages_sha256') == digest(expected)
             and record.get('clean_environment_id'), 'successful exact native build required')
        artifacts = root / 'artifacts'
        need(read(artifacts / 'packages.lock', 32 * 1024) == expected, 'actual complete 342-package inventory required')
        archive = read(artifacts / package, 128 * 1024)
        log = read(artifacts / CHECK_LOG, 1024 * 1024)
        check_log(log)
        need(archive.startswith(b'\xfd7zXZ\0')
             and record.get('artifacts') == {package: digest(archive)}
             and record['files'].get('artifacts/' + CHECK_LOG) == digest(log),
             'recorded original host-named check log and actual archive required')
        builds.append({'container': record['clean_environment_id'], 'archive_sha256': digest(archive),
                       'archive_bytes': len(archive), 'check_log': CHECK_LOG, 'check_log_sha256': digest(log)})
    need(builds[0]['container'] != builds[1]['container']
         and builds[0]['archive_sha256'] == builds[1]['archive_sha256'],
         'separate clean builds must yield identical whole archives')
    return {'status': 'FIRST_LOGIN_NATIVE_PAIR_POSTCONDITIONS_PASSED', 'image': image,
            'archive': package, 'builds': builds, 'Root_acceptance': None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest='operation', required=True)
    stage = subcommands.add_parser('prepare')
    for name in ('recipe', 'original-lock', 'overlay', 'output', 'fish-tools'):
        stage.add_argument('--' + name, required=True, type=Path)
    review = subcommands.add_parser('finish')
    for name in ('first', 'second', 'comparison', 'lock'):
        review.add_argument('--' + name, required=True, type=Path)
    review.add_argument('--image', required=True)
    args = parser.parse_args()
    try:
        if args.operation == 'prepare':
            prepare(args.recipe, args.original_lock, args.overlay, args.output, args.fish_tools)
        else:
            print(json.dumps(finish(args.first, args.second, args.comparison, args.image, args.lock), indent=2))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
