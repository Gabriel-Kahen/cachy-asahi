#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-only new candidate source binding; this does not accept a native result."""
import argparse,copy,json,re
from pathlib import Path
import adapter as A
import contract as C
import rules

def bind(source,candidate):
 C.need(C.HERE==source/'scripts/ci/apps6-native-reinstall' and re.fullmatch('[0-9a-f]{40}',candidate),'explicit adopted source/candidate basis required')
 value=copy.deepcopy(C.read(source/'scripts/ci/apps-cache-native/input-policy.json'))
 C.need(value['status']=='ROOT_BOUND_FINAL_PRODUCT_SOURCES' and {r:p['version'] for r,p in value['products'].items()}==dict(runtime='0.1.0-1',apps='0.1.0-5',cache='0.2.0-1'),'only exact held Apps5 policy may supply Runtime1/Cache2 mappings')
 checks=C.load('apps6_binding_recipe_checks',source/'scripts/checks/package_checks.py');recipe=checks.recipe(source/'packages/tools/cachy-asahi-apps/PKGBUILD');C.need(not recipe['errors'] and recipe['metadata']['pkgver']==['0.1.0'] and recipe['metadata']['pkgrel']==['6'],'exact checked Apps6 candidate required')
 product=value['products']['apps'];product.update(version='0.1.0-6',recipe_sha256=C.digest(source/'packages/tools/cachy-asahi-apps/PKGBUILD'),source_files={name:dict(bytes=(source/'packages/tools/cachy-asahi-apps'/name).stat().st_size,sha256=pin) for name,pin in recipe['input_sha256'].items()},check_markers=['Ran 42 tests','OK'])
 value.update(purpose=rules.PURPOSE,candidate_source=candidate);path=C.HERE/'input-policy.json';path.write_bytes(C.encoded(value));C.policy();C.verify_source(source)
 return dict(status='BOUND_NEW_APPS6_SOURCES_ONLY',candidate_source=candidate,native='NOT_RUN',package_version='0.1.0-6')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--candidate-source',required=True);a=p.parse_args();print(json.dumps(bind(a.source.absolute(),a.candidate_source),sort_keys=True))
