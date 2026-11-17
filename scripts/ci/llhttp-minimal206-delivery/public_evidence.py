# SPDX-License-Identifier: MIT
"""Project historical evidence to public paths and audit retained nested bytes."""

import base64
import io
import json
import re
import tarfile
import zlib

HOST_PATH = re.compile(rb'/(?:home/[^/"\s]+/(?:Documents/|work/)|dev/shm/|run/user/)[A-Za-z0-9_.+@/-]*')
CREDENTIAL = re.compile(
    rb'-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----|'
    rb'github_pat_[A-Za-z0-9_]{15,}|gh[pousr]_[A-Za-z0-9]{20,}|\bAKIA[A-Z0-9]{16}\b'
)
EVIDENCE_OWNER = ('successor-v4-evidence.DATA.json', 'successor-v5-evidence.DATA.json')
EVIDENCE_RECIPE = ('commands.json', 'llhttp-0.log', 'llhttp-2.log', 'package-function-stage.log')


def relative_path(match):
    path = match.group()
    if b'/Documents/ChatGPT/' in path:
        workspace, _, relative = path.split(b'/Documents/ChatGPT/', 1)[1].partition(b'/')
        if b'/orchestrator-resume-' in relative:
            retained = relative.split(b'/orchestrator-resume-', 1)[1].partition(b'/')[2]
            return b'retained-review/' + retained
        if workspace.endswith(b'-source-recipes-20261117'):
            return b'recipe-audit/recipes/' + relative
        return b'recipe-audit/work/' + relative
    if b'/work/' in path:
        return b'hosted-runner/work/' + path.split(b'/work/', 1)[1]
    raise ValueError('unclassified host-local evidence path')


def private_findings(bodies):
    """Identify suspect leaves without returning matched path or credential content."""
    findings = []

    def inspect(name, raw, depth=0):
        if depth > 4 or len(raw) > 2 * 1024**2:
            raise ValueError('bounded nested Source evidence')
        if HOST_PATH.search(raw) or CREDENTIAL.search(raw):
            findings.append(name)
        if not raw.startswith(b'{'):
            return
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            if name.endswith('.json'):
                raise
            return
        stack = [value]
        while stack:
            item = stack.pop()
            if type(item) is list:
                stack.extend(item)
            if type(item) is not dict:
                continue
            for key, entry in item.items():
                if key not in ('body_base64', 'zlib_base64'):
                    stack.append(entry)
                    continue
                decoded = base64.b64decode(entry, validate=True)
                if key == 'zlib_base64':
                    stream = zlib.decompressobj()
                    decoded = stream.decompress(decoded, 2 * 1024**2)
                    if not stream.eof or stream.unused_data or stream.unconsumed_tail:
                        raise ValueError('bounded complete compressed Source evidence')
                inspect(name + ' (' + key + ' preimage)', decoded, depth + 1)

    for name, raw in bodies.items():
        inspect(name, raw)
        if name.endswith('.tar.gz'):
            total = 0
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
                for count, member in enumerate(archive, 1):
                    total += member.size
                    if count > 128 or total > 2 * 1024**2:
                        raise ValueError('bounded public upstream recipe archive')
                    if member.isfile():
                        with archive.extractfile(member) as stream:
                            inspect(name + ' (upstream archive member)', stream.read(), 1)
    return findings


def project(bodies, base, owner, marker, pin, encode, decode):
    """Change only the six audited evidence bodies and their current references."""
    paths = [owner + n for n in EVIDENCE_OWNER] + [base + 'recipe/evidence/' + n for n in EVIDENCE_RECIPE]
    pins = {}
    for path, count in zip(paths, (12, 23, 16, 1, 7, 7), strict=True):
        old = bodies[path]
        new, replacements = HOST_PATH.subn(relative_path, old)
        if replacements != count:
            raise ValueError('exact reviewed host-path occurrence count')
        bodies[path] = new
        pins[path] = dict(original=pin(old), public=pin(new))

    recipe_prefix = base + 'recipe/'
    reviewed_path = base + 'reviewed-inputs.json'
    reviewed = decode(bodies[reviewed_path])
    for name in EVIDENCE_RECIPE:
        relative = 'evidence/' + name
        row = pins[recipe_prefix + relative]
        if reviewed[relative] != row['original']['sha256']:
            raise ValueError('exact original reviewed recipe evidence')
        reviewed[relative] = row['public']['sha256']

    result_path = recipe_prefix + 'evidence/host-result.json'
    original_result = bodies[result_path]
    result = decode(original_result)
    result['original_log_pins'] = dict(result['logs'])
    for log in ('llhttp-0.log', 'llhttp-2.log'):
        row = pins[recipe_prefix + 'evidence/' + log]
        if result['logs'][log] != row['original']:
            raise ValueError('exact historical recipe log')
        result['logs'][log] = row['public']
    bodies[result_path] = encode(result)
    reviewed_relative = result_path.removeprefix(recipe_prefix)
    if reviewed[reviewed_relative] != pin(original_result)['sha256']:
        raise ValueError('exact original host compilation result')
    reviewed[reviewed_relative] = pin(bodies[result_path])['sha256']
    pins[result_path] = dict(original=pin(original_result), public=pin(bodies[result_path]))
    bodies[reviewed_path] = encode(reviewed)

    projection = decode(bodies[marker])
    held = {}
    historical_owner = 'scripts/ci/llhttp-reference-native-source/owner/'
    for name in EVIDENCE_OWNER:
        path = historical_owner + name
        row = projection['changed'].pop(path)
        raw = zlib.decompress(base64.b64decode(row.pop('zlib_base64'), validate=True))
        if not HOST_PATH.search(raw) or pin(raw) != row['pin']:
            raise ValueError('exact private historical evidence preimage')
        held[path] = row
    projection['public_evidence_projection'] = dict(
        evidence=pins, private_inverse_rows=held, historical_inverse='requires private original Source assurance packet')
    bodies[marker] = encode(projection)
