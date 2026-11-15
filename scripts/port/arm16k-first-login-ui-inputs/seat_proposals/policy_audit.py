#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One exact retained ARM NM policy/signature DATA audit; no daemon/policy install."""
import argparse,hashlib,importlib.util,json,resource,tarfile,tempfile,xml.etree.ElementTree as ET
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('seat_policy_intake',HERE.parent/'six_pair_intake/intake.py');I=importlib.util.module_from_spec(spec);spec.loader.exec_module(I);P=I.P
EXPECTED='6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446'
def run(proposal,output):
    output.mkdir(mode=0o700,exist_ok=False);d=json.loads(proposal.read_text());r=next(v for v in d['materials']if v['name']=='networkmanager');assert r['version']=='1.58.1-2'and r['arch']=='aarch64';a=r['archive'];o=next(v for v in r['observations']if v.get('PKGINFO_identity_and_dependencies')=='PASS');archive=Path(o['path']);assert archive.stat().st_size==a['bytes']and P.sha(archive)==a['sha256'];sig=archive.with_name(archive.name+'.sig');assert sig.stat().st_size==a['signature_bytes']and P.sha(sig)==a['signature_sha256'];meta,_=P.package_metadata(archive);assert meta['pkgname']==[r['name']]and meta['pkgver']==[r['version']]and meta['arch']==['aarch64']and sorted(meta.get('depend',[]))==sorted(r['depends'])
    key=Path('/tmp/cachy-asahi-arm16k-project-lifecycle-inputs-20261114/archlinuxarm.gpg.binary');assert key.stat().st_size==2228 and P.sha(key)=='9403f923eed777ba0896a0b225e1522d3a7625234694c753ae26b27c29672aae'
    with tempfile.TemporaryDirectory(prefix='NM-policy-public-gpg-',dir=output)as home:signature=I.verify(archive,sig,key,Path(home),I.Budget())
    wanted='usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy';data=None;decoded=0
    with tarfile.open(archive,'r|xz')as t:
        for index,m in enumerate(t):
            assert index<50000;decoded+=m.size;assert decoded<128*1024**2
            if m.name.removeprefix('./')==wanted:assert m.isfile()and m.size<512*1024;data=t.extractfile(m).read();break
    assert data is not None;sha=hashlib.sha256(data).hexdigest();policy=ET.fromstring(data);actions={v.attrib['id']:v for v in policy.findall('action')};own=actions['org.freedesktop.NetworkManager.settings.modify.own'];defaults={v.tag:v.text for v in own.find('defaults')};file=output/'org.freedesktop.NetworkManager.policy.DATA';file.write_bytes(data);file.chmod(0o600)
    return {'status':'PASS_EXACT_ARM_POLICY_SIGNATURE_DATA_ONLY','archive':{'path':str(archive),**a},'signature':signature,'policy':{'path':wanted,'bytes':len(data),'sha256':sha,'x86_source_expected_sha256':EXPECTED,'exact_x86_source_bytes_match':sha==EXPECTED,'action':own.attrib['id'],'defaults':defaults,'actions':len(actions)},'actual_guest_policy_install_session_authentication':'NOT RUN','other43minimal_archives_authentication':'NOT RUN','source_license_trustfreshness_native_M2_release':'HOLD'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--proposal',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();
    if not __debug__:p.error('assertions must remain enabled')
    resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2));resource.setrlimit(resource.RLIMIT_CORE,(0,0));assert __debug__
    try:r=run(a.proposal,a.output)
    except Exception as error:r={'status':'HOLD_POLICY_DATA_REFUSAL','category':type(error).__name__,'reason':str(error)[:512]}
    (a.output/'policy-audit.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');print(json.dumps(r,sort_keys=True))
