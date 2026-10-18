# SPDX-License-Identifier: MIT
"""Closed Welcome archive→selected local DB expectations, calibrated on source4.

No private source DB is exported or guessed by the ordinary host. The worker
reads its authenticated readonly seed, checks this complete translation against
all source4 fields, and only then uses the same mapping for candidate5.
"""
import copy
import contract as C
FIELDS={'pkgname':'NAME','pkgver':'VERSION','pkgbase':'BASE','pkgdesc':'DESC','url':'URL','arch':'ARCH','builddate':'BUILDDATE','packager':'PACKAGER','size':'SIZE','license':'LICENSE','group':'GROUPS','replaces':'REPLACES','depend':'DEPENDS','optdepend':'OPTDEPENDS','conflict':'CONFLICTS','provides':'PROVIDES','xdata':'XDATA'}
BUILD_ONLY=frozenset(('makedepend','checkdepend','buildtool','buildtoolver'))
LOCAL_ONLY=frozenset(('INSTALLDATE','REASON','VALIDATION','INSTALLED_DB'))

def fields(pkginfo,source_fields):
 C.need(type(pkginfo)is dict and set(pkginfo)<=FIELDS.keys()|BUILD_ONLY and all(type(v)is list and 0<len(v)<=100000 and all(type(s)is str and s and '\0'not in s for s in v)for v in pkginfo.values()),'closed original Welcome PKGINFO metadata')
 C.need(all(k in pkginfo and len(pkginfo[k])==1 for k in('pkgname','pkgver','arch','size','builddate','packager'))and pkginfo['pkgname']==['cachy-asahi-welcome']and pkginfo['arch']==['aarch64']and pkginfo['pkgver'][0]in('0.1.0-4','0.1.0-5'),'exact archive same-name compiled identity')
 C.need(type(source_fields)is dict and {'INSTALLDATE','REASON','VALIDATION'}<=source_fields.keys()and set(source_fields)<=set(FIELDS.values())|LOCAL_ONLY,'complete supported source selected DB fields')
 C.need(source_fields['REASON']==['0']and source_fields['VALIDATION']==['pgp'],'explicit originally signed selected install')
 result={FIELDS[k]:list(v)for k,v in pkginfo.items()if k in FIELDS}
 result.update({k:list(v)for k,v in source_fields.items()if k in LOCAL_ONLY})
 return result

def complete(value,source_fields):
 C.need(type(value)is dict and set(value)=={'original4','new5','original604_manifest','fixture_policy','fixture_products','verification_keys'},'closed lifecycle plan')
 p=copy.deepcopy(value)
 C.need(fields(p['original4']['pkginfo'],source_fields)==source_fields,'ALL original archive→source4 DB fields must calibrate exactly')
 for key in('original4','new5'):p[key]['database_fields']=fields(p[key]['pkginfo'],source_fields)
 C.need(value['fixture_products']['cachy-asahi-welcome']==value['original4']and value['fixture_products']['cachy-asahi-welcome5']==value['new5'],'exact source4/candidate5 fixture product operands')
 p['fixture_products']={'cachy-asahi-welcome':p['original4'],'cachy-asahi-welcome5':p['new5']}
 return p

def archive_fields(report,product):
 """Use the original trusted package_checks DATA report after its archive join."""
 C.need(type(report)is dict and report.get('errors')==[] and set(product['payload'])==C.WELCOME_FILES,'complete reviewed Welcome archive report')
 metadata=report['metadata']['.PKGINFO'];C.need(metadata['pkgver']==[product['version']],'actual archive version joins operand')
 rows={n:r for n,r in report['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')};C.need(rows==product['payload'],'full actual archive payload joins operand')
 mtree=report['members']['.MTREE'];C.need(mtree['type']=='0'and type(mtree['size'])is int and 0<mtree['size']<=16*1024**2,'bounded raw .MTREE archive member')
 return dict(pkginfo=copy.deepcopy(metadata),mtree=dict(bytes=mtree['size'],sha256=mtree['sha256']))

def make(*,original4,new5,original604_manifest,original4_report,new5_report,fixture_policy,verification_keys):
 """Host constructor: no private DB reads, actors or false current606 decision."""
 old=copy.deepcopy(original4);new=copy.deepcopy(new5)
 old.update(archive_fields(original4_report,old));new.update(archive_fields(new5_report,new))
 C.need(old.get('source_record')==original604_manifest.get('cachy-asahi-welcome'),'immutable original4 provenance/restore row')
 return dict(original4=old,new5=new,original604_manifest=copy.deepcopy(original604_manifest),fixture_policy=copy.deepcopy(fixture_policy),fixture_products={'cachy-asahi-welcome':old,'cachy-asahi-welcome5':new},verification_keys=copy.deepcopy(verification_keys))
