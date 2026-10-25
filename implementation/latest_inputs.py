# SPDX-License-Identifier: MIT
"""Exact issued Six record and eight full archive identities; historical DATA only."""
import json
from pathlib import Path
import latest_common as C
import accepted_inputs

def verify(record,public,checks):
 decision,post=accepted_inputs.public(record,public);p=C.profile();metadata=json.loads(C.read(C.HERE/'archive-metadata.json'));C.need(metadata['record_source']==p['accepted_record_source']and set(metadata['rows'])==set(p['incoming']),'whole exact eight archive metadata projection');result={}
 for name,row in p['incoming'].items():
  path=Path(public)/row['path'];r=checks.package(path);m=r['metadata']['.PKGINFO'];payload={n:v for n,v in r['members'].items()if n not in('.PKGINFO','.BUILDINFO','.MTREE')and v['type']!='5'}
  C.need(not r['errors']and r['sha256']==row['sha256']and m['pkgname']==[name]and m['pkgver']==[row['version']]and m['arch'][0]in('any','aarch64')and not m.get('install'),'exact accepted archive/name/version/architecture/no scriptlets')
  C.need(payload==row['payload']and r['metadata']==metadata['rows'][name]['metadata']and not any(n.startswith(('usr/share/libalpm/hooks/','etc/pacman.d/hooks/'))for n in payload),'whole metadata/payload and no added hooks')
  result[name]=dict(archive=Path(row['path']).name,name=name,version=row['version'],size=row['bytes'],sha256=row['sha256'])
 C.need(len(result)==8 and p['actual_source']is p['actual_ref']is p['actual_run']is None,'fixed eight historical inputs never current acceptance')
 return dict(rows=result,decision=C.pin(C.read(Path(record)/'qualification/Root-acceptance.json')),record_source=p['accepted_record_source'],record_ref=p['accepted_record_ref'],native_source=p['native_source'],native_run=p['native_run'],scope='HISTORICAL_ACCEPTED_INPUT_DATA_ONLY_NOT_GUI_OR_FRESH_AUTHORITY',current_actual=None)

def apply(required,fact):
 before=dict(required);p=C.profile();C.need(len(before)==33 and 'cachy-asahi-boot-report'not in before and before['cachy-asahi-setup']['version']=='0.1.0-5','whole original33 and sole Setup5/Boot absence seams');rows=fact['rows']
 for n,row in rows.items():
  if n not in('cachy-asahi-setup','cachy-asahi-boot-report'):
   C.need((before[n]['version'],before[n]['size'],before[n]['sha256'])==(row['version'],row['size'],row['sha256']),'no same-version archive substitution '+n)
 result=dict(before);result.update(rows);C.need(len(result)==34 and result['cachy-asahi-setup']['version']=='0.1.0-6'and result['cachy-asahi-boot-report']['version']=='0.1.0-1','exact34 incoming after two finite changes');return result
