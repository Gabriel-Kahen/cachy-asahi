# SPDX-License-Identifier: MIT
"""A separate fully source/Git-bound accepted Apps10 input, never an Apps7 alias."""
import importlib.util,json,sys
from pathlib import Path
import admission as A
import apps10_common as C

def prepare(root,carrier,deadline):
 selection=A.obj(root/'apps10-selection.json');A.need(selection['status']=='ROOT_BOUND_ACCEPTED_APPS10_INPUTS_ONLY_NO_GUI_AUTHORITY'and selection['actual_source']is selection['actual_ref']is selection['actual_run']is None,'finite explicit input-only Apps10 binding');profile=selection['selection'];A.need(profile is not None and profile['actual']is None,'genuine Apps10 binding before actors')
 path=root/'factory/retained-helpers/legacy_prefill.py';spec=importlib.util.spec_from_file_location('_apps10_full_external_source_git',path);L=importlib.util.module_from_spec(spec);spec.loader.exec_module(L);proof=L.prove(carrier,carrier/'.git',profile,deadline)
 index=A.obj(carrier/'index.json');A.need(A.pin(A.read(carrier/'index.json'))==profile['index'],'exact public Apps10 DATA index');acceptance=A.obj(carrier/C.member(index['acceptance']));A.need(A.pin(A.read(carrier/index['acceptance']))==profile['acceptance'],'exact original Root acceptance');row=C.index_check(index,profile['files'],A.obj(root/'apps10-recipe-map.json'),acceptance);A.need(row==profile['package'],'exact accepted Apps10 archive row');archive=carrier/index['archives'][0]['path'];A.need(A.pin(A.read(archive))==dict(bytes=row['size'],sha256=row['sha256']),'exact selected Apps10 native body')
 return dict(row=row,archive=archive,proof=dict(status='WHOLE_ACCEPTED_APPS10_INPUT_CUSTODY_NOT_GUI_ACCEPTANCE',carrier=proof,index=profile['index'],acceptance=profile['acceptance'],pair_source=C.PAIR,pair_run=C.RUN,recipe_source=C.RECIPE,archive=A.pin(A.read(archive))))

def payload(report,root):
 profile=A.obj(root/'factory/apps10-installed-profile.json');metadata=report['metadata']['.PKGINFO'];A.need(all(metadata.get(k,[])==v for k,v in profile['metadata'].items()),'exact Apps10 source name/version/any/license/dependencies/provides/conflicts/replaces');members={n:r for n,r in report['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')};A.need(set(members)==set(profile['payload'])and not report['errors'],'exact eight-file Apps10 project package policy')
 for n,w in profile['payload'].items():
  r=members[n];A.need(r['type']=='0'and r['size']==w['bytes']and r['sha256']==w['sha256']and r['mode']==profile['modes'][n],'whole accepted Apps10 payload '+n)
 A.need(report['metadata']['.BUILDINFO']['pkgbuild_sha256sum']==[A.obj(root/'apps10-recipe-map.json')['packages/tools/cachy-asahi-apps10/PKGBUILD']['sha256']],'Apps10 original recipe-to-BUILDINFO join')
