# SPDX-License-Identifier: MIT
"""Finite passive projection of already qualified original component DATA."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import client_v3_common as C
from reader import inspect_inputs

PRIVATE = re.compile(br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|BEGIN PGP PRIVATE|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)', re.I)

def project_files(summary, files, retention, selected):
    result, omitted = {}, {}
    for n, raw in files.items():
        # Complete raw original ZIP pins were checked first. Code and verbose logs are not a shareable input substitute.
        drop = n.startswith(('harness/', 'source/')) or (n.startswith('emitted/') and '/runner/' in n) or n.endswith('.log')
        if drop:
            omitted[n] = C.pin(raw)
            continue
        C.need(not PRIVATE.search(raw), 'private material marker in selected projection DATA refused')
        result[n] = dict(**C.pin(raw), base64=base64.b64encode(raw).decode())
    C.need(len(result) <= C.LEAF_CAP and sum(row['bytes'] for row in result.values()) <= 48 * 1024**2, 'finite component projection caps')
    return dict(schema=1, status='PASSIVE_CLIENT_V3_COMPONENT_DATA_PROJECTION_NOT_NATIVE_ADMISSION', binding=selected,
        original_zip=dict(bytes=selected['artifact_bytes'], sha256=selected['artifact_sha256']), original_retention=C.pin(files['retention.json']),
        selected=result, omitted_originals=omitted, summary=summary, original_unchanged=True, original_required_for_requalification=True,
        Root_acceptance=None, native_admission=False, Doc315_qualification=False, actors=0, collected_code_imports=0)

def project_component(**kwargs):
    summary, files, retention, selected = inspect_inputs(**kwargs)
    with C.passive():
        return project_files(summary, files, retention, selected)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for n in ('binding-path', 'authorization-path', 'source-root', 'run-path', 'jobs-path', 'artifact-metadata-path', 'archive-path', 'output'):
        parser.add_argument('--' + n, type=Path, required=True)
    parser.add_argument('--binding-sha256', required=True)
    args = vars(parser.parse_args())
    output = args.pop('output').absolute()
    C.need(output == output.resolve() and output.parent.is_dir() and not any(p.is_symlink() for p in (output, *output.parents)), 'fresh canonical output path required')
    value = project_component(**args)
    raw = C.encoded(value)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(dict(status=value['status'], output=C.pin(raw), native_admission=False), sort_keys=True))
