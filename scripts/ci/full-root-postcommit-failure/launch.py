#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Select this separate hook through the held composition owner's existing API."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile

HERE=Path(__file__).resolve().parent
PREFIX='scripts/ci/full-root-postcommit-failure/'


def need(ok,reason):
    if not ok:raise ValueError(reason)


def main():
    parser=argparse.ArgumentParser(add_help=False)
    parser.add_argument('--upgrade-code',required=True,type=Path)
    parser.add_argument('--upgrade-config',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args,_=parser.parse_known_args()
    code=args.upgrade_code.resolve(strict=True)
    config=json.loads(args.upgrade_config.read_bytes())
    need(config['purpose']=='actual587-postcommit-failure-disposal-test' and
         config['failure']==dict(case='postcommit-exit87',exit_code=87,worker_seconds=1200,verify_seconds=600),
         'explicit separate failed-update composition selection required')
    source='scripts/ci/full-root-upgrade-caller/run.py'
    selected={source:'run.py','scripts/ci/full-root-upgrade-caller/container.py':'container.py',
              'scripts/ci/full-root-upgrade-caller/persistent_scope.py':'persistent_scope.py',
              PREFIX+'caller.py':'upgrade_hook.py',PREFIX+'launch.py':'launch.py',PREFIX+'run.py':'failed-run.py'}
    for name in selected:
        path=code/name
        need(path.is_file() and not any(p.is_symlink() for p in (path,*path.parents)) and
             hashlib.sha256(path.read_bytes()).hexdigest()==config['code_pins'][name],'selected caller source differs: '+name)
    need((code/(PREFIX+'launch.py')).read_bytes()==Path(__file__).read_bytes(),'launcher source selection differs')
    spec=importlib.util.spec_from_file_location('failed_update_composition_owner',code/source)
    api=importlib.util.module_from_spec(spec);sys.modules[spec.name]=api;spec.loader.exec_module(api)
    # Only a private module's explicit source-directory setting changes. Its
    # normal constructor, actors, capabilities, volume ownership and cleanup stay.
    private=Path(tempfile.mkdtemp(prefix='postcommit-failure-caller-',dir='/tmp'))
    try:
        for name,target in selected.items():
            if target in ('container.py','persistent_scope.py','upgrade_hook.py'):
                shutil.copyfile(code/name,private/target)
        api.CALLER=private
        return api.main()
    finally:
        retired=False
        receipt=args.output/'public/coordinator.json'
        try:
            if receipt.is_file() and not receipt.is_symlink() and receipt.stat().st_size<=1024**2:
                terminal=json.loads(receipt.read_bytes())
                retired=terminal.get('cleanup',{}).get('status')=='PASS' and terminal.get('upgrade_volume_cleanup')=='PASS-absence-verified'
        except (OSError,ValueError):pass
        if retired:shutil.rmtree(private)
        else:print(json.dumps(dict(failure_caller_sources=str(private),cleanup='RETAINED-owner-retirement-unverified')),file=sys.stderr)


if __name__=='__main__':main()
