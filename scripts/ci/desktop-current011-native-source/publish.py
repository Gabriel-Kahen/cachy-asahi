#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-only once Source publication proposal; no actor on import."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


def load_sibling_prepare():
    path = Path(__file__).resolve().with_name('prepare.py')
    spec = importlib.util.spec_from_file_location('_desktop_current011_prepare', path)
    if spec is None or spec.loader is None:
        raise ImportError('cannot load sibling prepare module: ' + str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load_sibling_prepare()

REF = 'refs/heads/codex/native-desktop-current011-owned-v2-v1'
EMAIL = '93809974+Gabriel-Kahen@users.noreply.github.com'
HOOK = dict(bytes=748, sha256='d57aae5ee57a5b23ecfbf12ca14c7633b3446059e94bcc0c302ffd50ee742d68')
PREFIX = 'scripts/ci/desktop-current011-native-source/'
PRODUCT_MERGE = '2561dcebee3ba70b924c9c4b42e4316b2994d832'


def evidence_pin(value):
    P.need(type(value) is dict and set(value) == {'path', 'bytes', 'sha256'}
           and type(value['bytes']) is int and 0 < value['bytes'] <= 1024**2
           and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']),
           'pinned finite genuine Root evidence required')
    P.relative(value['path'])


def expected_ci(value):
    P.need(type(value) is dict and set(value) == {'checks', 'workflows', 'workflow_ids'},
           'closed exact factory CI expectation required')
    for key in ('checks', 'workflows'):
        row = value[key]
        keys = {'total', 'success', 'skipped', 'failure', 'cancelled', 'pending'}
        P.need(type(row) is dict and set(row) == keys and all(type(v) is int and 0 <= v <= 10000 for v in row.values())
               and row['total'] > 0 and row['success'] > 0 and row['failure'] == row['cancelled'] == row['pending'] == 0
               and row['total'] == row['success'] + row['skipped']
               and row['skipped'] == (1 if key == 'checks' else 0), 'finite terminal green factory CI counts required')
    names = value['workflow_ids']
    P.need(type(names) is list and len(names) == value['workflows']['total'] == value['workflows']['success']
           and value['workflows']['skipped'] == 0 and all(type(n) is int and n > 0 for n in names)
           and len(set(names)) == len(names), 'exact successful factory workflow names required')


def evidence_data(authority, ci, proof, raw):
    factory = authority['factory']; wanted = factory['expected_CI']
    P.need(type(ci) is dict and set(ci) == {'schema', 'role', 'head', 'attempt', 'reruns', 'status', 'checks', 'workflows', 'runs'}
           and type(ci['schema']) is int and ci['schema'] == 1 and ci['role'] == 'ROOT_FACTORY_CI_TERMINAL'
           and ci['head'] == factory['head'] and type(ci['attempt']) is int and ci['attempt'] == 1
           and type(ci['reruns']) is int and ci['reruns'] == 0 and ci['status'] == 'EXACT_HEAD_COMPLETE_CI_GREEN'
           and ci['checks'] == wanted['checks'] and ci['workflows'] == wanted['workflows'],
           'genuine exact-head attempt1 complete factory CI receipt required')
    # Reject bool-as-int and malformed terminal counts inside the actual receipt too.
    expected_ci(dict(checks=ci['checks'], workflows=ci['workflows'], workflow_ids=wanted['workflow_ids']))
    runs = ci['runs']
    P.need(type(runs) is list and len(runs) == len(wanted['workflow_ids']), 'one genuine run per expected workflow required')
    names = []
    for run in runs:
        P.need(type(run) is dict and set(run) == {'workflow_id', 'head', 'attempt', 'status', 'conclusion', 'run_id'}
               and run['head'] == factory['head'] and type(run['attempt']) is int and run['attempt'] == 1
               and run['status'] == 'completed' and run['conclusion'] == 'success'
               and type(run['run_id']) is int and run['run_id'] > 0
               and type(run['workflow_id']) is int and run['workflow_id'] > 0, 'genuine successful first-attempt workflow run required')
        names.append(run['workflow_id'])
    P.need(sorted(names) == sorted(wanted['workflow_ids']) and len({r['run_id'] for r in runs}) == len(runs),
           'exact unique expected factory workflow runs required')
    P.need(type(proof) is dict and set(proof) == {'schema', 'role', 'head', 'merge', 'tree', 'parents', 'raw_commit'}
           and type(proof['schema']) is int and proof['schema'] == 1 and proof['role'] == 'ROOT_FACTORY_MERGE_PROOF'
           and proof['head'] == factory['head'] and proof['merge'] == factory['merge']
           and type(proof['tree']) is str and re.fullmatch('[0-9a-f]{40}', proof['tree'])
           and type(proof['parents']) is list and len(proof['parents']) == 2
           and all(type(x) is str and re.fullmatch('[0-9a-f]{40}', x) for x in proof['parents'])
           and proof['parents'][0] != proof['parents'][1] == factory['head']
           and proof['raw_commit'] == factory['raw_commit'], 'genuine exact two-parent factory Root merge proof required')
    headers = raw.split(b'\n\n', 1)[0].splitlines()
    P.need(P.pin(raw) == {k: factory['raw_commit'][k] for k in ('bytes', 'sha256')}
           and P.oid(b'commit', raw).hex() == factory['merge']
           and [x[5:].decode() for x in headers if x.startswith(b'tree ')] == [proof['tree']]
           and [x[7:].decode() for x in headers if x.startswith(b'parent ')] == proof['parents'],
           'whole genuine raw factory merge SHA/tree/parents differs')
    return dict(ci=ci, proof=proof, raw=raw)


def factory_evidence(authority, directory):
    def operand(key):
        expected = authority['factory'][key]
        raw, mode = P.read(directory / expected['path'], 1024**2)
        P.need(mode == 0o644 and P.pin(raw) == {k: expected[k] for k in ('bytes', 'sha256')},
               'whole externally pinned genuine factory evidence differs: ' + key)
        return raw
    return evidence_data(authority, P.document(operand('CI_receipt')),
                         P.document(operand('Root_merge_proof')), operand('raw_commit'))


def main_join(git, remote, expected=None):
    local = git('rev-parse', 'refs/heads/main').stdout.decode().strip()
    P.need(type(local) is str and re.fullmatch('[0-9a-f]{40}', local)
           and git('rev-parse', 'HEAD').stdout.decode().strip() == local
           and git('rev-parse', 'refs/remotes/origin/main').stdout.decode().strip() == local
           and git('ls-remote', '--heads', remote, 'refs/heads/main').stdout.decode().split() == [local, 'refs/heads/main']
           and not git('status', '--porcelain', '--untracked-files=no').stdout
           and (expected is None or local == expected), 'known local/tracking/remote clean Main join differs')
    return local


def git_factory(git, commit, expected):
    raw = git('ls-tree', '-rz', '--full-tree', commit, PREFIX.rstrip('/')).stdout
    rows = {}
    for record in raw.split(b'\0'):
        if not record:
            continue
        header, path = record.split(b'\t', 1); mode, kind, blob = header.decode().split(); path = path.decode()
        P.need(path.startswith(PREFIX) and kind == 'blob' and mode in ('100644', '100755'), 'ordinary canonical factory Git leaf required')
        name = path.removeprefix(PREFIX); P.relative(name)
        P.need(name not in rows, 'unique canonical factory Git leaf required')
        rows[name] = dict(mode=int(mode, 8) & 0o777, blob=blob)
    P.need(rows == {n: dict(mode=r['mode'], blob=r['blob']) for n, r in expected.items()},
           'complete canonical factory namespace/modes/blobs differs')
    for name, row in rows.items():
        body = git('cat-file', 'blob', row['blob']).stdout
        P.need(P.row(body, row['mode']) == expected[name], 'whole canonical factory Git bytes differs')


def factory_gate(authority, evidence, git, remote, main):
    P.need(P.body_rows(P.snapshot(P.HERE, authority['maintained_namespace'])) == authority['maintained_namespace'],
           'whole physical HERE/profile no longer matches reviewed merged factory')
    P.need(main_join(git, remote, main) == main, 'Main join changed')
    for ancestor in (authority['factory']['merge'], PRODUCT_MERGE):
        P.need(git('merge-base', '--is-ancestor', ancestor, main, okay=(0, 1)).returncode == 0,
               'actual factory/product merge must be ancestor of current Main')
    P.need(git('cat-file', 'commit', authority['factory']['merge']).stdout == evidence['raw'],
           'actual Git factory merge differs from pinned genuine Root raw merge')
    for commit in (authority['factory']['merge'], main):
        git_factory(git, commit, authority['maintained_namespace'])


def disjoint_receipts(stage, repository, output):
    for operand in (stage, P.HERE, repository / PREFIX.rstrip('/'), repository / '.git'):
        P.need(not output.is_relative_to(operand) and not operand.is_relative_to(output),
               'publication receipt output must be disjoint from stage/factory/Git operands')
    P.need(not repository.is_relative_to(output), 'receipt output cannot contain repository')


def publication_authority(value, profile_sha256):
    P.need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
           and value.get('role') == 'ROOT_CURRENT011_SOURCE_PUBLICATION'
           and value.get('ref') == REF and value.get('parent') == P.PARENT
           and value.get('product_merge') == '2561dcebee3ba70b924c9c4b42e4316b2994d832'
           and value.get('package_source_commit') == '446f657723c2e4443f8a3fe8ccbe592ebbaf282b'
           and value.get('profile_sha256') == profile_sha256, 'Root exact current product/factory authority required')
    factory = value.get('factory')
    P.need(type(factory) is dict and set(factory) == {'head', 'merge', 'CI_receipt', 'Root_merge_proof', 'raw_commit', 'expected_CI'}
           and all(type(factory.get(key)) is str and re.fullmatch('[0-9a-f]{40}', factory[key])
                   for key in ('head', 'merge')), 'future genuine factory merge/CI must be bound')
    for key in ('CI_receipt', 'Root_merge_proof', 'raw_commit'):
        evidence_pin(factory[key])
    expected_ci(factory['expected_CI'])
    rows = value.get('maintained_namespace')
    P.need(type(rows) is dict and 1 <= len(rows) <= 128, 'finite complete maintained factory namespace required')
    P.check_rows(rows, len(rows))
    P.need({'prepare.py', 'publish.py', 'profile.json', 'test_current011_data.py'} <= set(rows), 'actual reviewed factory modules required')
    P.need(rows['profile.json']['sha256'] == profile_sha256, 'reviewed profile must belong to whole factory namespace')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--receipts', type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True)
    parser.add_argument('--authority-file', type=Path, required=True)
    parser.add_argument('--authority-sha256', required=True)
    parser.add_argument('--root-source-publish-authorized', action='store_true', required=True)
    args = parser.parse_args()
    authority_raw, authority_mode = P.read(P.absolute(args.authority_file), 1024**2)
    P.need(authority_mode == 0o644 and P.pin(authority_raw)['sha256'] == args.authority_sha256,
           'whole external Root authority pin required')
    authority = publication_authority(P.document(authority_raw), args.profile_sha256)
    P.need(P.body_rows(P.snapshot(P.HERE, authority['maintained_namespace'])) == authority['maintained_namespace'],
           'complete Root-reviewed factory namespace/body/modes differs')
    evidence = factory_evidence(authority, P.absolute(args.authority_file).parent)
    stage, repository, output = P.absolute(args.stage), P.absolute(args.repository), P.absolute(args.receipts)
    disjoint_receipts(stage, repository, output)
    P.owned_directory(output.parent)
    P.need(not os.path.lexists(output), 'fresh once-only Source publication receipts required')
    value = P.profile(args.profile_sha256)
    P.verify_output(stage, args.profile_sha256)
    source = P.snapshot(stage / 'source', value['after200'])
    output.mkdir(mode=0o700)
    env = {key: val for key, val in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1', GIT_OPTIONAL_LOCKS='0')
    def git(*argv, data=None, private=False, okay=(0,)):
        selected = dict(env)
        if private: selected['GIT_INDEX_FILE'] = str(output / 'private-index')
        result = subprocess.run(['git', '-C', str(repository), *argv], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=selected, timeout=120)
        P.need(result.returncode in okay, 'Git refused; reconcile rather than retry: ' + repr(argv))
        return result
    def save(name, raw):
        with (output / name).open('xb') as stream: stream.write(raw)
    def record(name, row): save(name, P.encoded(row))
    def primary():
        head = git('rev-parse', 'HEAD').stdout.strip()
        P.need(head == git('rev-parse', 'refs/heads/main').stdout.strip()
               and not git('status', '--porcelain', '--untracked-files=no').stdout, 'clean primary Main required')
        index = Path(git('rev-parse', '--path-format=absolute', '--git-path', 'index').stdout.decode().strip())
        P.need(index != output / 'private-index', 'private Git index must differ from primary index')
        return dict(head=head.decode(), index=P.pin(P.read(index)[0]))
    prior = primary()
    try:
        fetch = git('remote', 'get-url', '--all', 'origin').stdout.decode().splitlines()
        push = git('remote', 'get-url', '--push', '--all', 'origin').stdout.decode().splitlines()
        P.need(fetch == push and len(fetch) == 1 and fetch[0] in
               ('https://github.com/Gabriel-Kahen/cachy-asahi.git', 'git@github.com:Gabriel-Kahen/cachy-asahi.git'),
               'one known identical source endpoint required')
        remote = fetch[0]
        hook = Path(git('rev-parse', '--path-format=absolute', '--git-path', 'hooks/pre-push').stdout.decode().strip())
        P.need(os.access(hook, os.X_OK) and P.pin(P.read(hook)[0]) == HOOK, 'installed real attribution hook required')
        for role in ('GIT_AUTHOR_IDENT', 'GIT_COMMITTER_IDENT'):
            P.need(git('var', role).stdout.decode().startswith('Gabriel Kahen <' + EMAIL + '> '), 'current noreply identity required')
        P.need(git('show-ref', '--verify', '--quiet', REF, okay=(0, 1)).returncode == 1
               and not git('ls-remote', '--heads', remote, REF).stdout, 'fresh Source ref required')
        parent = git('cat-file', 'commit', P.PARENT).stdout
        P.need(parent == P.raw_parent(value), 'actual Root parent commit differs')
        listed = git('ls-tree', '-rz', '--full-tree', P.PARENT).stdout
        expected = b''.join((format(0o100000 | row['mode'], 'o') + ' blob ' + row['blob'] + '\t' + name).encode() + b'\0'
                            for name, row in sorted(value['before200'].items()))
        # ls-tree traverses directories in Git order; compare all parsed leaf records.
        P.need(set(listed.split(b'\0')) == set(expected.split(b'\0')), 'complete actual parent leaf map differs')
        factory_gate(authority, evidence, git, remote, prior['head'])
        record('COMMIT-ONCE.intent.json', dict(parent=P.PARENT, tree=value['output']['tree'], ref=REF,
            profile_sha256=args.profile_sha256, primary=prior, Source_files=200))
        git('read-tree', P.PARENT, private=True)
        for name, (raw, mode) in source.items():
            P.need(git('hash-object', '-w', '--stdin', data=raw).stdout.decode().strip() == value['after200'][name]['blob'], 'written Source blob differs')
        entries = b''.join((format(0o100000 | row['mode'], 'o') + ' ' + row['blob'] + '\t' + name).encode() + b'\0'
                           for name, row in sorted(value['after200'].items()))
        git('update-index', '-z', '--index-info', data=entries, private=True)
        tree = git('write-tree', private=True).stdout.decode().strip()
        P.need(tree == value['output']['tree'], 'complete private Source tree differs')
        head = git('commit-tree', tree, '-p', P.PARENT,
                   data=b'ci: qualify exact desktop-tools 0.1.1 with owned-v2\n').stdout.decode().strip()
        raw = git('cat-file', 'commit', head).stdout
        headers = raw.split(b'\n\n', 1)[0].splitlines()
        P.need(P.oid(b'commit', raw).hex() == head
               and [x[7:].decode() for x in headers if x.startswith(b'parent ')] == [P.PARENT]
               and headers[0] == ('tree ' + tree).encode(), 'actual raw Source identity differs')
        for role in (b'author ', b'committer '):
            P.need(len([x for x in headers if x.startswith(role)]) == 1
                   and next(x for x in headers if x.startswith(role)).startswith(role + b'Gabriel Kahen <' + EMAIL.encode() + b'> '), 'actual Source attribution differs')
        save('Source-commit.raw', raw)
        git('update-ref', REF, head, '0' * 40)
        P.need(not git('ls-remote', '--heads', remote, REF).stdout, 'remote Source ref appeared; no push')
        factory_gate(authority, evidence, git, remote, prior['head'])
        record('PUSH-ONCE.intent.json', dict(source=head, parent=P.PARENT, tree=tree, ref=REF, nonforce=True))
        result = git('push', '--no-follow-tags', '--no-mirror', '--no-force', remote, head + ':' + REF)
        save('push.stdout', result.stdout); save('push.stderr', result.stderr)
        P.need(git('ls-remote', '--heads', remote, REF).stdout.decode().split() == [head, REF], 'remote Source readback differs; never repush')
        for name, (body, _) in source.items():
            P.need(git('show', head + ':' + name).stdout == body, 'whole committed Source body differs')
        record('publication.json', dict(source=head, parent=P.PARENT, tree=tree, ref=REF,
            source_files=200, map_sha256=value['output']['map_sha256'], pushes=1, retries=0,
            Source_constructed_by='ROOT_ONLY', native='NOT_RUN', Original_GETs=0, actual_readers=0, primary_held=True))
        print(json.dumps(dict(source=head, parent=P.PARENT, tree=tree, ref=REF)))
    finally:
        P.need(primary() == prior, 'primary Main/index/tracked state changed')


if __name__ == '__main__':
    main()
