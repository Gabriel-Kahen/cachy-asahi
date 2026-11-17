#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Prepare the exact local publication commit or validate canonical five-input dispatch DATA."""

import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('minimal206_authenticated_source', HERE / 'source.py')
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

PUBLICATION_KIND = 'ROOT_LLHTTP_MINIMAL206_SOURCE_PUBLICATION_V1'
REGISTRATION_KIND = 'ROOT_LLHTTP_MINIMAL206_WORKFLOW_REGISTRATION_V1'
ACTOR = 'Gabriel Kahen'
EMAIL = '93809974+Gabriel-Kahen@users.noreply.github.com'
DATE = '1794931049 +0000'
MESSAGE = b'Bind exact Root-authenticated minimal206 llhttp Source\n'


def git(root, *args, body=None):
    env = dict(PATH='/usr/bin:/bin', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
               GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1',
               GIT_AUTHOR_NAME=ACTOR, GIT_AUTHOR_EMAIL=EMAIL, GIT_AUTHOR_DATE=DATE,
               GIT_COMMITTER_NAME=ACTOR, GIT_COMMITTER_EMAIL=EMAIL, GIT_COMMITTER_DATE=DATE)
    argv = ['/usr/bin/git', '-C', str(root), '-c', 'core.autocrlf=false', '-c', 'core.hooksPath=/dev/null']
    return subprocess.run([*argv, *args], input=body, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env=env, check=True, timeout=45).stdout.decode().strip()


def check_checkout(checkout, expected):
    S.need(S.physical(checkout, checkout=True) == expected, 'whole physical published Source bytes and modes')
    source = git(checkout, 'rev-parse', 'HEAD')
    target = S.source_tuple(expected)
    author = f'{ACTOR} <{EMAIL}> {DATE}'
    commit = (f"tree {target['tree']}\nauthor {author}\ncommitter {author}\n\n").encode() + MESSAGE
    expected_source = hashlib.sha1(b'commit ' + str(len(commit)).encode() + b'\0' + commit).hexdigest()
    S.need(source == expected_source and git(checkout, 'rev-parse', 'HEAD^{tree}') == target['tree']
           and git(checkout, 'rev-parse', '--show-toplevel') == str(checkout),
           'exact parentless Git Source commit and tree')
    return dict(target, source=source, ref=S.REF, repository=S.REPOSITORY)


def selection(parent, adoption, transcript):
    auth = S.adoption(adoption, transcript)
    bodies = S.authenticated_source(S.parent_bodies(parent))
    S.need(S.P.read(HERE.parents[2] / S.WORKFLOW) == bodies[S.WORKFLOW],
           'Main registration workflow must match the authenticated Source')
    return auth, bodies


def private_assurance(before, after, output):
    """Retain the whole preimage outside the candidate Git object store."""
    output.mkdir(mode=0o700)
    try:
        for name, raw in before.items():
            leaf = output / 'original-source' / name
            leaf.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            leaf.write_bytes(raw)
            leaf.chmod(0o600)
        receipt = dict(original=S.source_tuple(before), public=S.source_tuple(after),
                       original_CID='7a55473d017e5c95c86088027ecb44df06ad2cf9',
                       originals=S.rows(before), public_changes=sorted(n for n in before if before[n] != after[n]))
        path = output / 'assurance.json'
        path.write_bytes(S.encode(receipt))
        path.chmod(0o600)
    except BaseException:
        shutil.rmtree(output)
        raise


def prepare(parent, adoption, transcript, output, assurance):
    _, bodies = selection(parent, adoption, transcript)
    output, assurance = map(S.P.P.ordinary, (output, assurance))
    S.need(not output.exists() and not assurance.exists() and not output.is_relative_to(assurance)
           and not assurance.is_relative_to(output)
           and not any(p.is_relative_to(parent) or parent.is_relative_to(p) for p in (output, assurance)),
           'fresh disjoint local publication and private assurance outputs')
    private = S.authenticated_source(S.parent_bodies(parent), public=False)
    output.mkdir(mode=0o700)
    try:
        for name, raw in bodies.items():
            leaf = output / name
            leaf.parent.mkdir(parents=True, exist_ok=True)
            leaf.write_bytes(raw)
            leaf.chmod(0o644)
        git(output, 'init', '--quiet', '--object-format=sha1', '--initial-branch=' + S.BRANCH, '--template=')
        git(output, 'add', '--force', '--all', '--', '.')
        tree = git(output, 'write-tree')
        S.need(tree == S.P.tree(bodies), 'Git staging preserved whole Source tree')
        commit = git(output, 'commit-tree', tree, body=MESSAGE)
        git(output, 'update-ref', S.REF, commit, '0' * 40)
        result = check_checkout(output, bodies)
        private_assurance(private, bodies, assurance)
    except BaseException:
        shutil.rmtree(output)
        raise
    return dict(result, status='LOCAL_AUTHENTICATED_SOURCE_PREPARED', publication=None, Root_native_authority=None)


def read_document(path, expected, limit=16384):
    raw = S.P.read(path, limit)
    S.need(S.pin(raw)['sha256'] == expected, 'whole externally pinned Root document')
    return raw


def canonical(parent, adoption, transcript, checkout, publication, registration, admission, runtime, now):
    auth, expected = selection(parent, adoption, transcript)
    identity = check_checkout(checkout, expected)
    published = S.decode(publication)
    publication_fields = dict(identity, kind=PUBLICATION_KIND, issuer='Root', public_clone_complete=True,
                              public_blob_tree_join=True, Root_native_authority=None)
    S.need(published == publication_fields
           and published['public_clone_complete'] is True and published['public_blob_tree_join'] is True,
           'independently Root-adopted whole public Source readback required')

    registered = S.decode(registration)
    S.need(registered.get('kind') == REGISTRATION_KIND and registered.get('issuer') == 'Root'
           and registered.get('repository') == S.REPOSITORY and registered.get('state') == 'active'
           and type(registered.get('workflow_id')) is int and registered['workflow_id'] > 0
           and registered.get('registered_on_default_branch') is True
           and registered.get('workflow_path') == S.WORKFLOW and registered.get('workflow') == identity['workflow']
           and re.fullmatch('[0-9a-f]{40}', registered.get('registration_commit') or '')
           and registered.get('public_ref') == S.REF and registered.get('public_source') == identity['source']
           and type(registered.get('observed_utc')) is int and 0 <= now - registered['observed_utc'] < 600
           and registered.get('Root_native_authority', False) is None,
           'fresh Root Main workflow registration and public Source ref readback required')

    actor = S.module(checkout / S.NO / 'data.py', 'minimal206_authenticated_actor_data')
    source_map = identity['source_map']['sha256']
    admit_sha, runtime_sha = S.pin(admission)['sha256'], S.pin(runtime)['sha256']
    admitted, reviewed = actor.source_documents(checkout, source_map, admission, runtime, admit_sha, runtime_sha,
                                                identity['source'], S.REF, now)
    S.need(admitted['builder_input_authentication'] == reviewed['builder_input_authentication'] == auth,
           'both independently issued actor documents carry the exact authentication adoption')
    inputs = dict(source_map_sha256=source_map, admission_sha256=admit_sha, admission_json=admission.decode(),
                  runtime_sha256=runtime_sha, runtime_json=runtime.decode())
    return dict(workflow_id=registered['workflow_id'], workflow_path=S.WORKFLOW,
                body=dict(ref=S.BRANCH, inputs=inputs))


def main():
    S.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, 'run with python3 -I -B')
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare_cli = commands.add_parser('prepare')
    canonical_cli = commands.add_parser('canonical')
    for sub in (prepare_cli, canonical_cli):
        sub.add_argument('--parent', type=Path, required=True)
        sub.add_argument('--adoption', type=Path, required=True)
        sub.add_argument('--transcript', type=Path, required=True)
    prepare_cli.add_argument('--output', type=Path, required=True)
    prepare_cli.add_argument('--assurance-output', type=Path, required=True)
    canonical_cli.add_argument('--checkout', type=Path, required=True)
    for name in ('publication', 'registration', 'admission', 'runtime'):
        canonical_cli.add_argument('--' + name, type=Path, required=True)
        canonical_cli.add_argument('--' + name + '-sha256', required=True)
    args = parser.parse_args()
    operands = args.parent, args.adoption, args.transcript
    if args.command == 'prepare':
        result = prepare(*operands, args.output, args.assurance_output)
    else:
        documents = [read_document(getattr(args, n), getattr(args, n + '_sha256'))
                     for n in ('publication', 'registration', 'admission', 'runtime')]
        result = canonical(*operands, args.checkout, *documents, int(time.time()))
    sys.stdout.buffer.write(S.encode(result))


if __name__ == '__main__':
    main()
