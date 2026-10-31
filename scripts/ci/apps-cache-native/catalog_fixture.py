#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real signed synthetic catalog through unchanged release fixture APIs; never install it."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    need=lambda ok,why:None if ok else (_ for _ in ()).throw(ValueError(why))
    need(os.uname().machine=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_ASAHI_CATALOG_FIXTURE')=='1','dedicated native fixture actor required')
    need(all(shutil.which(tool) for tool in ('gpg','gpgconf','repo-add','bsdtar','vercmp')),'all real signing fixture tools required; no skips')
    control=json.loads(Path('/fixture-control.json').read_bytes());target=Path('/out/catalog-fixture')
    need(not target.exists(),'fresh signed-fixture export required');target.mkdir(mode=0o755)
    path=Path('/fixture-source/scripts/release/test_release.py');spec=importlib.util.spec_from_file_location('apps_cache_original_signed_fixture',path)
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    cls=fixture.ReleaseTests;cls.home=Path('/authority');cls.key=control['signer']
    case=cls('test_signed_stage_and_verify');case.setUp()
    try:
        case.stage();fixture.r.verify_release(case.directory,case.key,case.env)
        shutil.copytree(case.directory,target/'bundle',symlinks=True)
        base=json.loads((case.directory/'base.json').read_bytes());base['kind']='complete-installed-inventory'
        (target/'installed-before.json').write_bytes((json.dumps(base,sort_keys=True,indent=2)+'\n').encode())
        release=json.loads((case.directory/'release.json').read_bytes());base['packages']+=release['packages']
        (target/'installed-selected.json').write_bytes((json.dumps(base,sort_keys=True,indent=2)+'\n').encode())
        catalog=dict(schema_version=1,kind='development-application-catalog',target_arch='aarch64',
            release_sha256=fixture.r.sha(target/'bundle/release.json'),repository='fixture',applications=[dict(
                id='fixture',title='Synthetic Fixture',description='Real signed planning fixture only; never installed',packages=['fixture'])])
        path=target/'catalog.json';path.write_text(json.dumps(catalog,sort_keys=True,indent=2)+'\n');fixture.r.sign(path,case.key,case.env)
        (target/'public.gpg').write_bytes(fixture.r.run(['gpg','--batch','--export',case.key],env=case.env))
        (target/'control.json').write_text(json.dumps(dict(signer=case.key,release_sha256=catalog['release_sha256'],
            catalog_sha256=fixture.r.sha(path),installed_before_sha256=fixture.r.sha(target/'installed-before.json'),
            installed_selected_sha256=fixture.r.sha(target/'installed-selected.json'),synthetic=True,
            applied='NOT_APPLIED',production_trust='NOT_ESTABLISHED'),sort_keys=True)+'\n')
        # This public fixture has no private keys and must be readable by the ordinary lifecycle account.
        for path in (target,*target.rglob('*')):
            if path.is_symlink():continue
            path.chmod(0o755 if path.is_dir() else 0o644)
    finally:
        case.doCleanups();subprocess.run(['gpgconf','--homedir','/authority','--kill','all'],check=True,capture_output=True,timeout=20)


if __name__=='__main__':main()
