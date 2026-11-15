#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Refusal checks against a genuine retained archive and its decoded DATA map."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import tempfile

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('perl_actual_reader',HERE/'inspect_archive.py')
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('archive',type=Path);args=parser.parse_args()
    pins=json.loads((HERE/'inputs.json').read_bytes());rows=reader.read_rows(args.archive)
    results={'genuine_archive':reader.validate(rows,pins)['status']}
    with tempfile.TemporaryDirectory(prefix='perl-archive-controls-') as temporary:
        body=args.archive.read_bytes()
        for name,data in [('truncated',body[:-2]),('trailing-compressed-data',body+b'UNACCEPTED')]:
            target=Path(temporary)/name;target.write_bytes(data)
            try:reader.read_rows(target)
            except ValueError:results[name]='REFUSED'
            else:raise AssertionError('corrupt archive accepted: '+name)
    for name,change in [
        ('missing-command',lambda value:value.pop('usr/bin/prove')),
        ('changed-alias',lambda value:value['usr/bin/prove'].update(target='core_perl/cpan')),
        ('missing-diagnostic-data',lambda value:value.pop('usr/share/perl5/core_perl/pod/perldiag.pod')),
        ('changed-notice',lambda value:value['usr/share/licenses/perl/Artistic'].update(sha256='0'*64)),
        ('foreign-ELF',lambda value:value['usr/bin/perl'].update(ELF_machine=183)),
        ('missing-ELF',lambda value:value['usr/bin/perl'].pop('ELF_machine')),
        ('extra-service',lambda value:value.update({'usr/lib/systemd/system/perl.service':dict(type='file',mode=0o644)}))]:
        value=copy.deepcopy(rows);change(value)
        try:reader.validate(value,pins)
        except ValueError:results[name]='REFUSED'
        else:raise AssertionError('mutated DATA accepted: '+name)
    print(json.dumps(dict(status='PASS_GENUINE_ARCHIVE_AND_NINE_REFUSAL_CONTROLS',checks=results),sort_keys=True,indent=2))


if __name__=='__main__':main()
