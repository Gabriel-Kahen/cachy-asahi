#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Explicit retained-archive controls. DATA only; never run archive contents."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('actual_archive', HERE / 'inspect_archive.py')
review = importlib.util.module_from_spec(spec); spec.loader.exec_module(review)


def controls(archive):
    rows = review.read_rows(archive)
    pins = json.loads((HERE / 'inputs.json').read_text())
    positive = review.validate_rows(rows, pins)
    results = ['actual complete payload accepted']

    def refused(label, action):
        try:
            action()
        except ValueError:
            results.append(label)
        else:
            raise AssertionError('control accepted: ' + label)

    with tempfile.TemporaryDirectory(prefix='python314-archive-controls-') as private:
        for name, suffix in (('truncated', None), ('trailing', b'x')):
            path = Path(private) / (name + '.pkg.tar.zst')
            shutil.copyfile(archive, path)
            with path.open('r+b') as stream:
                if suffix is None:
                    stream.truncate(path.stat().st_size - 1)
                else:
                    stream.seek(0, 2); stream.write(suffix)
            refused('actual ' + name + ' compressed archive refused', lambda: review.read_rows(path))
    missing = copy.deepcopy(rows)
    del missing['usr/lib/python3.14/lib-dynload/_tkinter.cpython-314-x86_64-linux-gnu.so']
    refused('actual payload with omitted Tk refused', lambda: review.validate_rows(missing, pins))
    changed = copy.deepcopy(rows)
    changed['usr/share/licenses/python/CPython-LICENSE']['sha256'] = '0' * 64
    refused('actual payload with changed notice refused', lambda: review.validate_rows(changed, pins))
    extra = copy.deepcopy(rows)
    extra['usr/lib/systemd/system/unbound.service'] = {'type': 'file', 'mode': 0o644}
    refused('actual payload with extra service refused', lambda: review.validate_rows(extra, pins))
    extra = copy.deepcopy(rows)
    extra['etc/unbound'] = {'type': 'file', 'mode': 0o644}
    refused('actual payload with outside-/usr material refused', lambda: review.validate_rows(extra, pins))
    return {'status': 'PASS seven actual DATA controls', 'controls': results,
            'archive': review.host.identity(archive), 'positive': positive, 'holds': review.host.HOLDS}


if __name__ == '__main__':
    if not sys.flags.isolated:
        raise ValueError('run with python3 -I')
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('archive', type=Path)
    print(json.dumps(controls(parser.parse_args().archive), indent=2, sort_keys=True))
