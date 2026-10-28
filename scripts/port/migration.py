#!/usr/bin/env python3
"""Authenticate two explicit snapshot migration candidates; data-only proposal."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import authenticate as auth
import preview

CACHE=Path('/tmp/cachy-asahi-port-migration-cache')
KEYS=Path('/home/gabe/.local/share/cachy-asahi/private-inputs/cachy-asahi-native-arm-audit')
FIELDS={'name':'NAME','version':'VERSION','arch':'ARCH','depends':'DEPENDS','provides':'PROVIDES',
        'conflicts':'CONFLICTS','replaces':'REPLACES','license':'LICENSE'}


def item(meta, repo):
    preview.check(meta)
    sig=base64.b64decode(meta['PGPSIG'][0],validate=True)
    result={k:meta.get(field,[]) if k in ('depends','provides','conflicts','replaces','license') else meta[field][0]
            for k,field in FIELDS.items()}
    result.update({'filename':meta['FILENAME'][0],'sha256':meta['SHA256SUM'][0],'size':int(meta['CSIZE'][0]),
                   'signature_sha256':hashlib.sha256(sig).hexdigest(),'signature_size':len(sig),
                   'url':'https://ca.us.mirror.archlinuxarm.org/aarch64/'+repo+'/'+meta['FILENAME'][0],
                   'repo':repo,'source_url':meta.get('URL',[])})
    preview.need(result['name'] in ('perl','libfdk-aac') and result['arch']=='aarch64' and
                 result['filename']==f'{result["name"]}-{result["version"]}-aarch64.pkg.tar.xz' and
                 0<result['size']<=20*1024**2, 'candidate scope refused')
    return result


def baseline(receipt, complete):
    records={}
    for p in receipt['full_candidate_inventory']:
        if complete or p['repository']=='retained-generic-builder':
            records[p['name'][0]]={field:p[k] for k,field in {'name':'NAME','version':'VERSION','arch':'ARCH',
                'depends':'DEPENDS','provides':'PROVIDES','conflicts':'CONFLICTS','replaces':'REPLACES',
                'license_metadata':'LICENSE','upstream_url':'URL'}.items()}
    preview.need(len(records)==(574 if complete else 341),'baseline identity/count refused')
    return records


def metadata_impact(records, candidates):
    changed={n:p.copy() for n,p in records.items()}
    for c in candidates:
        preview.need(c['name'] in changed,'unexpected migration package')
        changed[c['name']]={field:(c[k] if isinstance(c[k],list) else [c[k]]) for k,field in FIELDS.items()}
    with tempfile.TemporaryDirectory(prefix='cachy-port-',dir='/tmp') as tmp:
        work=Path(tmp);(work/'root').mkdir();preview.write_local(work/'db/local',changed)
        relationships,conflicts=preview.alpm_audit(work,changed)
    return {'count':len(changed),'changes':[{'name':c['name'],'old_version':records[c['name']]['VERSION'][0],
                        'proposed_version':c['version']} for c in candidates],
            'dependency_relationships':relationships,'unsatisfied':[r for r in relationships if not r['provider']],
            'conflicts':conflicts,'removals':[],
            'result':'PASS-generic-metadata-substitution-only' if not conflicts and all(r['provider'] for r in relationships) else 'FAIL-generic-metadata-substitution',
            'installation':'NOT RUN','runtime_ABI':'NOT RUN','transaction_commit':'NOT RUN'}


def authenticate_candidate(candidate,keyring,out):
    auth.fetch(candidate,CACHE);auth.fetch(auth.native.signature_item(candidate),CACHE)
    with tempfile.TemporaryDirectory(prefix='cachy-port-public-gpg-',dir='/tmp') as tmp:
        home=Path(tmp);gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(home),
                          '--no-auto-key-retrieve','--no-autostart']
        imported=subprocess.run(gpg+['--import',str(keyring)],capture_output=True,text=True,timeout=60)
        preview.need(imported.returncode==0,'public key import failed')
        verified=subprocess.run(gpg+['--status-fd','1','--verify',str(CACHE/(candidate['filename']+'.sig')),
                                    str(CACHE/candidate['filename'])],capture_output=True,text=True,timeout=60)
        status={'exit':verified.returncode,'status':verified.stdout,'diagnostic':verified.stderr.replace(str(CACHE),'<private-candidate-cache>').replace(str(home),'<public-only-gpg-home>')}
        # Record failed GPG evidence before refusing it.
        auth.native.save(out/(candidate['name']+'-signature.json'),status)
        auth.status(verified)
        observations=auth.observe(CACHE/candidate['filename'],candidate)
        auth.native.save(out/(candidate['name']+'-observations.json'),observations)
    return {'status':'PASS-authenticated-candidate-data','candidate':candidate,'gpg':status,
            'observations_sha256':auth.native.sha(out/(candidate['name']+'-observations.json')),
            'public_only_gpg_home_removed':True,'installation':'NOT RUN'}


def migrate(core,extra,old_builder,old_desktop,receipt,out):
    preview.need(core['sha256']=='5f184763bad034ac02662ee37d87edad8124244c8609f4a441947da1855b0b08' and
                 extra['sha256']=='66cfbeae024c325e19ba7334afcb0ff2ab892ba4f0789216b358648f7647b480','current snapshot identity refused')
    perl=item(core['perl'],'core');fdk=item(extra['libfdk-aac'],'extra')
    preview.need(perl['version']=='5.42.3-1' and fdk['version']=='3.0.0-1','explicit successor versions refused')
    old_perl=next(p for p in old_builder['packages'] if p['name']=='perl')
    old_fdk=next(p for p in old_desktop['packages'] if p['name']=='libfdk-aac')
    preview.need(auth.native.sha(KEYS/old_perl['filename'])==old_perl['sha256'],'old Perl archive changed')
    old_observations=auth.observe(KEYS/old_perl['filename'],old_perl)
    preview.need(not out.exists() and not out.is_symlink(),'new output required')
    out.mkdir(parents=True)
    CACHE.mkdir(mode=0o700,exist_ok=True)
    preview.need(not CACHE.is_symlink() and CACHE.stat().st_uid==os.getuid() and CACHE.stat().st_mode&0o077==0,'private candidate cache refused')
    for k in old_builder['keyring_files']:
        p=KEYS/k['filename'];preview.need(p.is_file() and not p.is_symlink() and auth.native.sha(p)==k['sha256'] and p.stat().st_size==k['size'],'official key pin mismatch')
    record={'scope':'explicit coordinated generic snapshot migration proposal','schema':1,'status':'FAIL',
            'source_sha256':auth.native.sha(Path(__file__)),'authenticate_helper_sha256':auth.native.sha(Path(auth.__file__)),
            'native_helper_sha256':auth.native.sha(Path(auth.native.__file__)),
            'signer_fingerprint':auth.SIGNER,'observed_utc':datetime.now(timezone.utc).isoformat(),
            'old_builder_lock_sha256':'7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41',
            'old_desktop_lock_sha256':'119f420629a8b594e8fc46ddf6d5f0cbcc2a3176867cda75f3c5d0ccf73b1a86',
            'old_preview_receipt_sha256':'2b20ab5d0baa7ccafd0287e4c86419dc914745d02600e0ca3b3318d611dc042f',
            'new_unsigned_snapshots':[{'name':n,'sha256':d['sha256'],'bytes':d['bytes'],'url':d['url']} for n,d in [('core',core),('extra',extra)]],
            'source_inputs':{'core_observation_sha256':hashlib.sha256((json.dumps(core,indent=2,sort_keys=True)+'\n').encode()).hexdigest(),
                             'extra_observation_sha256':hashlib.sha256((json.dumps(extra,indent=2,sort_keys=True)+'\n').encode()).hexdigest()},
            'packages':[],'failures':[],'old_inputs_preserved':True,'shared_locks_changed':False,
            'native_build':'NOT RUN','target_Asahi_transaction':'NOT RUN','hardware':'NOT RUN','binary_publication':False}
    auth.native.save(out/'old-perl-observations.json',old_observations)
    for old,new in [(old_perl,perl),(old_fdk,fdk)]:
        try:
            authenticated=authenticate_candidate(new,KEYS/'archlinuxarm.gpg',out)
            authenticated['old_candidate']=old
            authenticated['metadata_relation_diff']={k:{'old':old[k],'new':new[k]} for k in FIELDS if old[k]!=new[k]}
            authenticated['old_archive_authentication']='old Perl pinned bytes rehashed; prior authentication evidence; old FDK bytes were unavailable'
            record['packages'].append(authenticated)
        except Exception as e:
            record['failures'].append({'name':new['name'],'kind':type(e).__name__,'diagnostic':str(e).replace(str(CACHE),'<private-candidate-cache>').replace(str(KEYS),'<private-original-cache>')[:1000]})
        auth.native.save(out/'migration-proposal.json',record)
    if not record['failures'] and len(record['packages'])==2:
        record['builder_metadata_impact']=metadata_impact(baseline(receipt,False),[perl])
        record['desktop_metadata_impact']=metadata_impact(baseline(receipt,True),[perl,fdk])
        record['status']='PASS-authenticated-data-migration-proposal' if all(record[k]['result'].startswith('PASS') for k in ['builder_metadata_impact','desktop_metadata_impact']) else 'FAIL-candidate-metadata-incompatible'
        record['acceptance']='proposal only; coordinator must refreeze sources/full transaction/environment and repeat native checks'
    auth.native.save(out/'migration-proposal.json',record)
    return record


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    here=Path(__file__).resolve().parent
    try:
        core=preview.load(here/'current-perl-metadata-observation.json','4c0a5cc9176ab531ca407f66ec2ee61b3f8170d5543f1088c0565528aecf579e');extra=preview.load(here/'current-fdk-metadata-observation.json','e5e6c4ed07dd0dd9a6f285727342b8ae7a75905cdde95191725603b4ecb24a8b')
        old_builder=preview.load(here.parents[1]/'docs/validation/input-snapshots/7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41.json','7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41')
        old_desktop=preview.load(here/'desktop-archives-proposal.json','119f420629a8b594e8fc46ddf6d5f0cbcc2a3176867cda75f3c5d0ccf73b1a86')
        receipt=preview.load(here/'generic-desktop-receipt.json','2b20ab5d0baa7ccafd0287e4c86419dc914745d02600e0ca3b3318d611dc042f')
        r=migrate(core,extra,old_builder,old_desktop,receipt,a.output)
        print(r['status']);return 0 if r['status'].startswith('PASS') else 1
    except (ValueError,OSError,KeyError,subprocess.SubprocessError):
        print('REFUSED migration input/hash/prerequisite');return 2


if __name__=='__main__':raise SystemExit(main())
