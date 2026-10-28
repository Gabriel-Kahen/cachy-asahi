# SPDX-License-Identifier: MIT
"""Bind the genuine accepted Setup5 pair to the unchanged release constructor."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace

NAME='cachy-asahi-setup'
PACKAGE='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc'
RECIPE='d31e4bdfb5c0c38e0128bbcb5127926414628f2d8d047f9eb0a2da0142848519'
BUILD='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def inspect_package(args,api):
    """Data-only checks. No package rebuild, replacement, signing or CLI execution."""
    pair=Path(args.setup4_pair)
    path=Path(__file__).with_name('accepted_pair.py')
    spec=importlib.util.spec_from_file_location('expanded600_accepted_pair',path)
    accepted=importlib.util.module_from_spec(spec);spec.loader.exec_module(accepted)
    with tempfile.TemporaryDirectory(prefix='accepted-setup5-inspect-') as temporary:
        accepted.accepted_cli(pair,Path(temporary))
    source=pair/'source/cachy-asahi-setup';reports=[];records=[]
    for side in ('a','b'):
        native=pair/('runtime/cachy-asahi-setup-'+side);record=json.loads((native/'provenance.json').read_bytes())
        archive=pair/('packages/cachy-asahi-setup-'+side)/'cachy-asahi-setup-0.1.0-5-any.pkg.tar.xz'
        need(record['status']=='built-package-static-pass' and record['mode']=='native' and
             record['expected_packages_sha256']==BUILD and sha(native/'expected-packages.lock')==BUILD and
             len((native/'expected-packages.lock').read_text().splitlines())==574 and
             record['artifacts']=={archive.name:PACKAGE} and record['recipe_inputs']['PKGBUILD']==RECIPE,
             'actual native pair/build574 provenance differs')
        environment=(native/'artifacts/environment.txt').read_text().splitlines()
        need(len(environment)>2 and ' aarch64 GNU/Linux' in environment[0] and environment[1]=='4096',
             'retained actual native aarch64/4K environment differs')
        argv=record['command'];need('--platform=linux/arm64' in argv and '--network=none' in argv and
             '--read-only' in argv and record['image']==record['image_id'] and
             '--env=SOURCE_DATE_EPOCH=1791748800' in argv,'actual offline native builder binding differs')
        for name,digest in record['recipe_inputs'].items():
            need('/' not in name and name not in ('.','..') and sha(source/name)==digest,'retained source input differs')
        report=api.checks.package(archive);need(not report['errors'] and report['sha256']==PACKAGE,'genuine Setup5 package check failed')
        metadata=api.checks.metadata((source/'.SRCINFO').read_text())
        need(not api.build.bind_artifact(metadata,report,RECIPE),'actual Setup5 recipe/archive binding differs')
        pkg=report['metadata']['.PKGINFO'];need(pkg['pkgname']==[NAME] and pkg['pkgver']==['0.1.0-5'] and
             pkg['license']==['MIT'] and sorted(pkg['depend'])==['gnupg','pacman','python>=3.11'] and
             not pkg.get('provides') and not pkg.get('conflict'),'genuine Setup5 package identity/dependencies differ')
        payload=api.composition.payload(report)
        wanted={'/usr/bin/'+n:(record['recipe_inputs'][n],0o755) for n in ('cachy-asahi-setup','cachy-asahi-repository')}
        wanted.update({'/usr/share/doc/'+NAME+'/'+n:(record['recipe_inputs'][n],0o644) for n in ('README.md','repository-enrollment.md')})
        wanted.update({'/usr/share/licenses/'+NAME+'/'+n:(record['recipe_inputs'][n],0o644) for n in ('LICENSE','NOTICE')})
        need(len(payload)==6 and {p['path'] for p in payload}==set(wanted),'exact six owned Setup paths required')
        for item in payload:need(item['type']=='file' and (item['sha256'],item['mode'])==wanted[item['path']],'actual Setup5 payload/source binding differs')
        reports.append((archive,report,payload));records.append(record)
    need(records[0]['clean_environment_id']!=records[1]['clean_environment_id'],'two distinct actual native build environments required')
    package,native=Path(args.package),Path(args.provenance)
    need(package==reports[0][0] and sha(package)==PACKAGE and
         native==pair/'runtime/cachy-asahi-setup-a/provenance.json','explicit first native archive/provenance selection required')
    return SimpleNamespace(pair=pair,retained=reports[0][0],report=reports[0][1],payload=reports[0][2],
        package=package,native=native,native_record=records[0],build_lock=pair/'runtime/cachy-asahi-setup-a/expected-packages.lock')
