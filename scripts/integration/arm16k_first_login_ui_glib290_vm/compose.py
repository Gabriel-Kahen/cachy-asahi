# SPDX-License-Identifier: MIT
"""Finite manifest proposal DATA, never Root admission or materialization."""
import copy,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
def propose(original):
 assert original['kind']=='ARM16K_FIRST_LOGIN_UI_ADDITIONS_V1'and len(original['archives'])==172 and 'glib2'not in original['archives']
 facts=json.loads((HERE/'data/glib-materials.json').read_text());anchor=json.loads((HERE/'data/additions172-anchor.json').read_text())
 assert {n:{k:r[k]for k in ['filename','version','archive','metadata']}for n,r in original['archives'].items()}==anchor
 result=copy.deepcopy(original);new=facts['new'];old=facts['old']
 def row(value,role):return {'version':value['metadata']['pkgver'][0],'filename':'glib2-'+value['metadata']['pkgver'][0]+'-aarch64.pkg.tar.xz','archive':value['archive'],'signature':facts['signature_pins'][role],'metadata':value['metadata'],'official_repository':True,'signer_role':'official','expected_signer':facts['official_primary'],'source_provenance':{'kind':'PINNED_PUBLIC_GPGV_AND_ELF_DATA','contract':'data/glib-materials.json'}}
 result['archives']['glib2']=row(new,'new');result['rollback']=row(old,'old');result.update(kind='ARM16K_FIRST_LOGIN_UI_GLIB290_ADDITIONS_V1',status='PROPOSAL_NOT_ROOT_ADMITTED',issued_by=None,issued_at=None,Root_review=None,runtime_authority=None,trust=None,metadata_prepare=facts['metadata_evidence'],glib_material_contract=None)
 for name in ['usr/lib/girepository-1.0/GLib-2.0.typelib','usr/lib/girepository-1.0/Gio-2.0.typelib']:result['required_namespace'][name]={'owner':'glib2','payload':new['payload'][name]}
 return result
