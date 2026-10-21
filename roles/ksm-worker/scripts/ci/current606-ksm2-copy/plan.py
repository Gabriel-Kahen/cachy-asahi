# SPDX-License-Identifier: MIT
"""Archive-derived complete KSM DB fields; original1 is never a fresh substitute."""
import copy,hashlib,json,sys
import contract as C
FIELDS={'pkgname':'NAME','pkgver':'VERSION','pkgbase':'BASE','pkgdesc':'DESC','url':'URL','arch':'ARCH','builddate':'BUILDDATE','packager':'PACKAGER','size':'SIZE','license':'LICENSE','group':'GROUPS','replaces':'REPLACES','depend':'DEPENDS','optdepend':'OPTDEPENDS','conflict':'CONFLICTS','provides':'PROVIDES','xdata':'XDATA'}
BUILD_ONLY=frozenset(('makedepend','checkdepend','buildtool','buildtoolver'))
LOCAL_ONLY=frozenset(('INSTALLDATE','REASON','VALIDATION','INSTALLED_DB'))
KEYS={'original1','new2','original606_manifest','verification_keys'}

def schema_need(source_fields,condition,message):
 """Failure-only redacted DATA; reporting cannot replace the original refusal."""
 if not condition:
  try:
   raw=C.encoded(source_fields);allowed=set(FIELDS.values())|LOCAL_ONLY
   keys=set(source_fields)if type(source_fields)is dict else set()
   unknown=sorted(keys-allowed);reason=source_fields.get('REASON')if type(source_fields)is dict else None
   validation=source_fields.get('VALIDATION')if type(source_fields)is dict else None
   row=dict(event='selected_db_schema_failure',schema_version=1,status='DIAGNOSTIC_ONLY',
    source_fields=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),
    known_present=sorted(keys&allowed),missing_required=sorted({'INSTALLDATE','VALIDATION'}-keys),
    unknown_count=len(unknown),unknown_labels_sha256=hashlib.sha256(C.encoded(unknown)).hexdigest(),
    reason='ABSENT_EXPLICIT_DEFAULT'if 'REASON'not in keys else'EXPLICIT_ZERO'if reason==['0']else'DEPENDENCY_ONE'if reason==['1']else'OTHER',
    validation='PGP'if validation==['pgp']else'NONE'if validation==['none']else'OTHER'if 'VALIDATION'in keys else'MISSING')
   line=json.dumps(row,sort_keys=True,separators=(',',':'))
   if len(line.encode())<=2048:sys.stderr.write(line+'\n');sys.stderr.flush()
  except Exception:pass
 C.need(condition,message)


def fields(pkginfo,source_fields):
 C.need(type(pkginfo)is dict and set(pkginfo)<=FIELDS.keys()|BUILD_ONLY and all(type(v)is list and v and all(type(s)is str and s and '\0'not in s for s in v)for v in pkginfo.values()),'closed KSM PKGINFO')
 C.need(all(k in pkginfo and len(pkginfo[k])==1 for k in('pkgname','pkgver','arch','size','builddate','packager'))and pkginfo['pkgname']==['cachy-asahi-ksmctl']and pkginfo['arch']==['any']and pkginfo['pkgver'][0]in('0.1.0-1','0.1.0-2'),'exact KSM1/2 same-name archive identity')
 schema_need(source_fields,type(source_fields)is dict and {'INSTALLDATE','VALIDATION'}<=source_fields.keys()and set(source_fields)<=set(FIELDS.values())|LOCAL_ONLY and source_fields.get('REASON',['0'])==['0']and source_fields['VALIDATION']==['pgp'],'complete explicit signed initial KSM DB')
 result={FIELDS[k]:list(v)for k,v in pkginfo.items()if k in FIELDS};result.update({k:list(v)for k,v in source_fields.items()if k in LOCAL_ONLY});return result

def complete(value,source_fields):
 C.need(type(value)is dict and set(value)==KEYS,'closed Apps copy plan');p=copy.deepcopy(value)
 C.need(fields(p['original1']['pkginfo'],source_fields)==source_fields,'all original Apps6 archive/source DB fields calibrate')
 for key in('original1','new2'):p[key]['database_fields']=fields(p[key]['pkginfo'],source_fields)
 return p

def archive_fields(report,product,*,name):
 C.need(report.get('errors')==[] and report['metadata']['.PKGINFO']['pkgname']==[name]and report['metadata']['.PKGINFO']['pkgver']==[product['version']],'complete actual archive report identity')
 rows={n:r for n,r in report['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')};C.need(rows==product['payload'],'whole actual package payload')
 if name=='cachy-asahi-ksmctl':C.need(set(rows)==(C.OLD_FILES if product['version']=='0.1.0-1'else C.KSM_FILES),'exact KSM owned leaves')
 mtree=report['members']['.MTREE'];C.need(mtree['type']=='0'and 0<mtree['size']<=16*1024**2,'bounded raw archive mtree')
 return dict(pkginfo=copy.deepcopy(report['metadata']['.PKGINFO']),mtree=dict(bytes=mtree['size'],sha256=mtree['sha256']))

def make(*,original1,new2,original606_manifest,original1_report,new2_report,verification_keys):
 old,new=map(copy.deepcopy,(original1,new2))
 for product,report in((old,original1_report),(new,new2_report)):product.update(archive_fields(report,product,name='cachy-asahi-ksmctl'))
 C.need(old.get('source_record')==original606_manifest.get('cachy-asahi-ksmctl'),'exact original606 KSM1 archive/payload/provenance')
 return dict(original1=old,new2=new,original606_manifest=copy.deepcopy(original606_manifest),verification_keys=copy.deepcopy(verification_keys))
