#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finish the same180s/12-request window from recorded official mirror metadata."""
import argparse,hashlib,importlib.util,json,signal,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('bounded_Xvfb_recovery',HERE/'recover.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
def finish(root):
    first=root/'receipt.json';original=json.loads(first.read_text());earlier=root/'metadata-followup-receipt-2.json';previous=json.loads(earlier.read_text());budget=R.I.Budget();budget.started-=time.time()-(first.stat().st_mtime-original['seconds']);budget.gets=previous['initial_requests'];budget.body=previous['response_body_bytes']
    report={'status':'HOLD_EXACT_XVFB_UNAVAILABLE','first_receipt_sha256':R.P.sha(first),'metadata_receipt_sha256':R.P.sha(earlier),'requests':[]}
    contract=json.loads((HERE.parent/'six_pair_intake/inputs.json').read_text());item=next(p for p in contract['pairs']if p['name']=='xorg-server-xvfb');key=contract['binary_public_key'];mirrorlist=(root/'retained-official-mirrorlist.txt').read_text()
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(TimeoutError('original180s window expired')));signal.alarm(max(1,int(budget.remaining())))
    try:
        for host in ['dk.mirror.archlinuxarm.org','fr.mirror.archlinuxarm.org','de.mirror.archlinuxarm.org']:
            if budget.gets>=11:break
            assert 'http://'+host+'/$arch/$repo'in mirrorlist;R.I.HOSTS.add(host);url='https://'+host+'/aarch64/extra/'+R.NAME;entry={'kind':'exact-archive','official_mirror_source':'retained pacman-mirrorlist20260411-2'};report['requests'].append(entry)
            try:
                archive=root/'archives'/R.NAME;sig=archive.with_name(R.NAME+'.sig')
                R.I.fetch(url,{'bytes':705376,'sha256':R.SHA},archive,budget,entry)
                s={'kind':'exact-signature'};report['requests'].append(s);R.I.fetch(url+'.sig',{'bytes':566,'sha256':R.SIG},sig,budget,s)
                with tempfile.TemporaryDirectory(prefix='xvfb-gpg-public-',dir=root)as home:
                    R.P.bound(key);report['signature']=R.I.verify(archive,sig,Path(key['path']),Path(home),budget)
                report['metadata']=R.I.metadata(archive,item);report['status']='PASS_EXACT_XVFB_ARCHIVE_SIGNATURE_METADATA_DATA_ONLY';break
            except Exception as error:entry.update(category=type(error).__name__,reason=str(error)[:256])
    except Exception as error:report.update(category=type(error).__name__,reason=str(error)[:256])
    finally:
        signal.alarm(0);report.update(initial_requests=budget.gets,response_body_bytes=budget.body,seconds=time.monotonic()-budget.started,five_pairs_and_original_receipt_unchanged=all(R.P.sha(Path(p))==h for p,h in original['preserved_input_hashes'].items()));(root/'final-recovery-receipt.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(report,sort_keys=True));return 0 if report['status'].startswith('PASS')else 2
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--recovery-root',type=Path,required=True);a=p.parse_args();raise SystemExit(finish(a.recovery_root))
