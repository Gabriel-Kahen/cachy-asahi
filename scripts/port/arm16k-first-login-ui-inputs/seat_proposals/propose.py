#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Three explicit DATA proposals on frozen ARM111, using held graph/libalpm."""
import argparse,gc,hashlib,importlib.util,json,resource,sys,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('held_ARM111_plan',HERE.parent/'plan.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
MINIMAL=['python','python-gobject','polkit','networkmanager']
POLICY_SHA='6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446'
def current_row(path):
    doc=json.loads(path.read_text());assert doc['status']=='PASS_CURRENT_ARCHIVE_SIGNATURE_IDENTITY_DATA_ONLY';a,s=doc['objects'];assert Path(a['path']).stat().st_size==a['bytes']and P.sha(Path(a['path']))==a['sha256'];assert P.sha(Path(s['path']))==s['sha256'];meta,pin=P.package_metadata(Path(a['path']));assert meta==doc['metadata']and meta['arch']==['aarch64']and meta['pkgname']==['xorg-server-xvfb'];assert doc['signature']['signer_primary']=='68B3537F39A313B3E574D06777193F152BDBE6A6'
    verifier=P.load('current_Xvfb_reverify',HERE.parent/'six_pair_intake/intake.py');key=Path('/tmp/cachy-asahi-arm16k-project-lifecycle-inputs-20261114/archlinuxarm.gpg.binary');assert key.stat().st_size==2228 and P.sha(key)=='9403f923eed777ba0896a0b225e1522d3a7625234694c753ae26b27c29672aae'
    with tempfile.TemporaryDirectory(prefix='current-Xvfb-proposal-gpg-')as home:verifier.verify(Path(a['path']),Path(s['path']),key,Path(home),verifier.Budget())
    return {'name':'xorg-server-xvfb','version':meta['pkgver'][0],'repo':'extra','arch':'aarch64','depends':meta.get('depend',[]),'provides':meta.get('provides',[]),'conflicts':meta.get('conflict',[]),'replaces':meta.get('replaces',[]),'files':None,'hooks':None,'review':None,'licenses_declared':meta.get('license',[]),'archive':{'filename':Path(a['path']).name,'bytes':a['bytes'],'sha256':a['sha256'],'signature_bytes':s['bytes'],'signature_sha256':s['sha256']},'separate_current_acquisition':{'path':str(path),'sha256':P.sha(path)}}
def run(mode,current=None,provider=None):
    c=json.loads((HERE.parent/'inputs.json').read_text());base=json.loads(P.bound({**c['baseline'],'path':str(HERE.parent/c['baseline']['filename'])}));anchors=P.anchor_rows(base);protected={r['name']:r['version']for r in anchors};assert {r['name']:r['version']for r in json.loads(P.bound(c['reference_prepared']))['base_packages']}==protected;R=P.load('seat_existing_resolver',P.ROOT/'scripts/port/platform-residual-closure/resolve.py');parser=P.load('seat_existing_srcinfo',P.ROOT/'scripts/port/supported-composition/compose.py')
    for name,pin in c['engine_sources'].items():assert P.sha(P.ROOT/name)==pin['sha256'],'engine drift'
    catalog=[]
    for ref in c['catalogs']:
        grouped,_=R.read_catalog(P.bound(ref),ref['repo'],time.monotonic()+30);rows=R.catalog_packages(grouped,ref['repo'],ref);catalog.extend(rows);del grouped,rows;gc.collect()
    project=[]
    if mode!='minimal-seat':
        for ref in c['project']:
            row,evidence=P.candidate(ref,parser);catalog.append(row);project.append(evidence)
    names=list(MINIMAL) if mode=='minimal-seat'else c['root_names']+(['networkmanager']if mode=='ui-with-NM'else[])
    if provider is not None:
        assert mode in ['minimal-seat','ui-with-NM']and provider in ['iptables','iptables-legacy'];names.append(provider)
    replacement=None
    if mode=='current-Xvfb':
        assert current is not None;replacement=current_row(current);catalog=[r for r in catalog if r['name']!='xorg-server-xvfb'];catalog.append(replacement)
    roots=[]
    for name in names:
        rows=[r for r in catalog if r['name']==name];assert len(rows)==1;roots.append(R.identity(rows[0]))
    graph=R.resolve(anchors,catalog,roots,protected,limits=R.Limits(max_packages=512,max_seconds=30));additions=[r for r in graph['selected']if r['name']not in protected];assert {r['name']:r['version']for r in graph['selected']if r['name']in protected}==protected
    del catalog;gc.collect()
    caches=c['cache_directories']+['/tmp/cachy-asahi-arm16k-ui-six-pair-intake-20261115/archives']+([str(current.parent/'archives')]if current else[])
    materials=[]
    original=json.loads((HERE.parent/'actual-facts.json').read_text());original_names={r['name']for r in json.loads(P.bound(original['report']))['materials']}
    for row in additions:
        observed=P.retained(row,caches,1024**2)if row['repo']!='project'else[next(p for p in project if p['name']==row['name'])]
        materials.append({k:row[k]for k in ['name','version','repo','arch','depends','provides','conflicts','replaces','archive','licenses_declared']}|{'incremental_to_old145':row['name']not in original_names,'observations':observed,'availability':'MISSING'if not observed else'RETAINED_PENDING_FULL_AUTHENTICATION','source_license_ELF16K_ABI_runtime':'HOLD'})
    prepared=P.prepare_proposal(anchors,additions)
    return {'schema_version':1,'status':'HOLD_SEPARATE_METADATA_PROPOSAL','proposal':mode,'roots':roots,'root_count':len(roots),'explicit_libxtables_provider':provider,'baseline_count':111,'preserved_baseline':111,'additions':len(additions),'total':111+len(additions),'metadata_prepare':prepared,'graph_status':graph['metadata_graph_status'],'graph_blockers':[b for b in graph['blockers']if b.get('scope')not in ['custody','ownership','hooks','review']],'materials':materials,'incremental_to_old145':[m for m in materials if m['incremental_to_old145']],'missing_archives':[m['archive']for m in materials if m['availability']=='MISSING'],'declared_archive_bytes':sum(m['archive']['bytes']for m in materials),'separate_current_replacement':replacement,'required_real_policy':{'package':'networkmanager','path':'usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy','action':'org.freedesktop.NetworkManager.settings.modify.own','x86_source_hash_comparison':POLICY_SHA,'actual_ARM_policy_byte_comparison':'PENDING_ARCHIVE_AUDIT; never infer from name'},'holds':['all111versions remain protected','no original145proposal/pin/failure changed','metadata only, no install/daemon/VM/native/M2/release','retained metadata/signature-byte observations are not full new authentication','actual ELF16K/dynamicABI/fileconflict/hooks/source/license/trust/freshness held']}
def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--proposal',choices=['minimal-seat','ui-with-NM','current-Xvfb'],required=True);a.add_argument('--current-acquisition',type=Path);a.add_argument('--libxtables-provider',choices=['iptables','iptables-legacy']);a.add_argument('--output',type=Path,required=True);v=a.parse_args();
    if not __debug__:a.error('assertions must remain enabled')
    resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2));resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_CPU,(90,90));v.output.mkdir(mode=0o700,exist_ok=False)
    try:r=run(v.proposal,v.current_acquisition,v.libxtables_provider)
    except Exception as error:r={'status':'HOLD_INPUT_OR_RESOURCE_REFUSAL','category':type(error).__name__,'reason':str(error)[:512]}
    (v.output/'proposal.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');print(json.dumps({k:r.get(k)for k in ['status','proposal','preserved_baseline','additions','total','category','reason']}));return 2
if __name__=='__main__':raise SystemExit(main())
