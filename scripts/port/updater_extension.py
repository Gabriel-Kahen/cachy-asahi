#!/usr/bin/env python3
"""Resolve and authenticate one finite updater builder extension; never install."""
import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import authenticate as auth
import preview
import re_resolution as desktop

ROOTS=('rust','scdoc','git','glib2','gettext','pkgconf','bats','python','make')
OWNER_PROPOSAL='38a26d91d5b153951b64991c1c018a907835ffa89525e90b91a54d59ad5a2fe4'
BASE_RECEIPT='b7f53cc24eb8e12119050c76554f78f7daa215d6fa048c2c4336037f824b2deb'
BASE_INVENTORY='89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f'
CACHE=Path('/tmp/cachy-asahi-updater-extension-cache')
KEYS=Path('/home/gabe/.local/share/cachy-asahi/private-inputs/cachy-asahi-native-arm-audit')


def seed(receipt):
    records={}
    for p in receipt['full_candidate_inventory']:
        if p['repository']=='declared-new-builder-metadata':
            records[p['name'][0]]={field:p[k] for k,field in {'name':'NAME','version':'VERSION','arch':'ARCH',
                'depends':'DEPENDS','provides':'PROVIDES','conflicts':'CONFLICTS','replaces':'REPLACES',
                'license_metadata':'LICENSE','upstream_url':'URL','archive_filename':'FILENAME','archive_sha256':'SHA256SUM'}.items()}
    text=''.join(n+' '+p['VERSION'][0]+'\n' for n,p in sorted(records.items()))
    preview.need(len(records)==341 and hashlib.sha256(text.encode()).hexdigest()==BASE_INVENTORY,'adopted baseline identity refused')
    return records


def package_record(p):
    sig=base64.b64decode(p['PGPSIG'][0],validate=True)
    return {'name':p['NAME'][0],'version':p['VERSION'][0],'arch':p['ARCH'][0],'filename':p['FILENAME'][0],
        'sha256':p['SHA256SUM'][0],'size':int(p['CSIZE'][0]),'source_url':p.get('URL',[]),
        'url':'https://ca.us.mirror.archlinuxarm.org/aarch64/'+p['repo']+'/'+p['FILENAME'][0],
        'signature_sha256':hashlib.sha256(sig).hexdigest(),'signature_size':len(sig),
        **{k:p.get(k.upper(),[]) for k in ('depends','provides','conflicts','replaces','license')}}


def roots(owner,packages,initial):
    preview.need(tuple(owner['direct_roots'])==ROOTS and len(owner['roots'])==9,'finite updater roots refused')
    selected=[]
    for r in owner['roots']:
        p=packages[r['name']]
        preview.need(p['VERSION']==[r['version']] and p['SHA256SUM']==[r['archive_sha256_metadata']], 'owner root pin mismatch')
        preview.need(r['name'] not in initial or initial[r['name']]['VERSION']==[r['version']], 'baseline root version change requires explicit review')
        selected.append(r['name']+'='+r['version'])
    preview.need(len(set(selected))==9,'duplicate root refused')
    return selected


def run(builder,owner,receipt,dbdir,out):
    preview.need(not out.exists() and not out.is_symlink(),'new output required')
    initial=seed(receipt);packages=preview.databases(dbdir,desktop.SNAPSHOTS)
    targets=roots(owner,packages,initial)
    record={'schema_version':1,'scope':'separate compiled updater native builder extension; data only',
        'status':'FAIL','source_sha256':auth.native.sha(Path(__file__)),
        'base_inputs_lock_sha256':desktop.NEW_BUILDER,'base_inventory_sha256':BASE_INVENTORY,
        'owner_proposal_sha256':OWNER_PROPOSAL,'base_receipt_sha256':BASE_RECEIPT,
        'snapshots':desktop.SNAPSHOTS,'initial_count':341,'roots':owner['roots'],
        'packages':[],'failures':[],'installation':'NOT RUN','native_compiler_execution':'NOT RUN',
        'native_updater_build':'NOT RUN','16K_runtime':'NOT RUN','hardware':'NOT RUN','shared_inputs_lock_changed':False}
    out.mkdir(parents=True);(out/'observations').mkdir()
    def save():auth.native.save(out/'extension-receipt.json',record)
    save()
    with tempfile.TemporaryDirectory(prefix='cachy-port-',dir='/tmp') as tmp:
        work=Path(tmp);preview.setup(work,dbdir,desktop.SNAPSHOTS,initial)
        printed=preview.run(work,'preview',targets);final=dict(initial);additions=[]
        record['pacman']={'exit':printed.returncode,'diagnostic':printed.stderr.replace(str(work),'<temporary-context>')}
        preview.need(printed.returncode==0,'print resolution failed')
        for line in printed.stdout.splitlines():
            parts=line.split('\t')
            if len(parts)!=6:continue
            n,version,repo,arch,size,hash_=parts
            preview.need(n in packages and packages[n]['VERSION']==[version] and packages[n]['repo']==repo and
                         packages[n]['ARCH']==[arch] and packages[n]['SHA256SUM']==[hash_],'print package not snapshot-bound')
            preview.need(n not in initial,'baseline package change refused; proposal review required')
            final[n]=packages[n];additions.append(package_record(packages[n]))
        preview.need(1<=len(additions)<=30 and len({a['name'] for a in additions})==len(additions) and
                     sum(a['size']+a['signature_size'] for a in additions)<=150*1024**2,'finite extension bound refused')
        for target in owner['roots']:
            preview.need(final.get(target['name'],{}).get('VERSION')==[target['version']],'required root absent')
        shutil.rmtree(work/'db/local');preview.write_local(work/'db/local',final)
        relations,conflicts=preview.alpm_audit(work,final)
        deptest=preview.run(work,'deps',sorted({r['relation'] for r in relations}))
        record.update({'final_count':len(final),'add_count':len(additions),'baseline_changes':[],
            'download_bytes':sum(a['size'] for a in additions),'dependency_relationships':relations,
            'unsatisfied':[r for r in relations if not r['provider']],'conflicts':conflicts,'removals':[],
            'deptest_exit':deptest.returncode,'deptest_missing':deptest.stdout.splitlines()})
        save()
        preview.need(not record['unsatisfied'] and not conflicts and deptest.returncode==0,'extension dependency/conflict failure')
    inventory=''.join(n+' '+p['VERSION'][0]+'\n' for n,p in sorted(final.items()))
    (out/'expected-packages.lock').write_text(inventory)
    record['expected_inventory_sha256']=hashlib.sha256(inventory.encode()).hexdigest()
    lock={'schema_version':1,'purpose':'separate-cachy-update-builder-extension','base_inputs_lock_sha256':desktop.NEW_BUILDER,
        'base_inventory_sha256':BASE_INVENTORY,'expected_inventory_sha256':record['expected_inventory_sha256'],
        'snapshots':desktop.SNAPSHOTS,'root_pins':[{'name':r['name'],'version':r['version']} for r in owner['roots']],
        'signer_fingerprint':auth.SIGNER,'keyring_files':builder['keyring_files'],'packages':sorted(additions,key=lambda a:a['name']),
        'source_license_closure':'not established; private authenticated toolchain inputs only','native_installation':'NOT RUN'}
    auth.native.save(out/'builder-extension.lock.json',lock)
    record['extension_lock_sha256']=auth.native.sha(out/'builder-extension.lock.json')
    CACHE.mkdir(mode=0o700,exist_ok=True)
    preview.need(not CACHE.is_symlink() and CACHE.stat().st_uid==os.getuid() and CACHE.stat().st_mode&0o077==0,'private cache refused')
    for k in builder['keyring_files']:
        p=KEYS/k['filename'];preview.need(p.is_file() and not p.is_symlink() and p.stat().st_size==k['size'] and auth.native.sha(p)==k['sha256'],'public key pin mismatch')
    def download(p):
        try:
            auth.fetch(p,CACHE);auth.fetch(auth.native.signature_item(p),CACHE);return p['name'],None
        except Exception as e:return p['name'],{'phase':'download','kind':type(e).__name__,'diagnostic':str(e).replace(str(CACHE),'<private-extension-cache>')[:1000]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=dict(pool.map(download,additions))
    with tempfile.TemporaryDirectory(prefix='cachy-port-public-gpg-',dir='/tmp') as tmp:
        home=Path(tmp);gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve','--no-autostart']
        imported=subprocess.run(gpg+['--import',str(KEYS/'archlinuxarm.gpg')],capture_output=True,text=True,timeout=60)
        preview.need(imported.returncode==0,'public key import failed')
        for package in additions:
            entry={'name':package['name'],'version':package['version'],'archive_sha256':package['sha256'],
                   'signature_sha256':package['signature_sha256'],'status':'FAIL'}
            try:
                preview.need(results[package['name']] is None,'download failure')
                verified=subprocess.run(gpg+['--status-fd','1','--verify',str(CACHE/(package['filename']+'.sig')),
                                              str(CACHE/package['filename'])],capture_output=True,text=True,timeout=60)
                entry['gpg']={'exit':verified.returncode,'status':verified.stdout,'diagnostic':verified.stderr.replace(str(CACHE),'<private-extension-cache>').replace(str(home),'<public-only-gpg-home>')}
                auth.status(verified);obs=auth.observe(CACHE/package['filename'],package)
                f=out/'observations'/(package['name']+'.json');auth.native.save(f,obs)
                entry['observation']={'file':'observations/'+f.name,'sha256':auth.native.sha(f),'ELF_count':len(obs['ELF']),
                    'hook_scriptlet_count':len(obs['hooks_and_scriptlets']),'path_count':obs['path_count']}
                entry['status']='PASS-authenticated-toolchain-data'
            except Exception as e:
                entry['failure']=results[package['name']] or {'phase':'signature-or-inspection','kind':type(e).__name__,
                    'diagnostic':str(e).replace(str(CACHE),'<private-extension-cache>').replace(str(home),'<public-only-gpg-home>')[:1000]}
                record['failures'].append({'name':package['name'],'failure':entry['failure']})
            record['packages'].append(entry);save()
    record['public_only_gpg_home_removed']=True
    record['verified_count']=sum(p['status']=='PASS-authenticated-toolchain-data' for p in record['packages'])
    record['status']='PASS-authenticated-updater-builder-extension-proposal' if not record['failures'] and record['verified_count']==len(additions) else 'FAIL-incomplete-extension-authentication'
    record['rust_runtime']={'compiler':'1:1.99.0-1','cargo_and_rustfmt':'provided by rust archive',
        'compiler_rt':'23.1.1-1','lld':'23.1.1-1','llvm_libs':'23.1.1-1 retained baseline',
        'compiled_ARM_package_bytes':'authenticated; ELF observations retained','native_execution':'NOT RUN'}
    save();return record


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    here=Path(__file__).resolve().parent
    try:
        builder=preview.load(here.parent/'ci/inputs.lock.json',desktop.NEW_BUILDER)
        owner=preview.load(here.parents[1]/'packages/tools/cachy-asahi-update/builder-extension-proposal.json',OWNER_PROPOSAL)
        receipt=preview.load(here/'refreshed-desktop/receipt.json',BASE_RECEIPT)
        r=run(builder,owner,receipt,Path('/tmp/cachy-port-migration-snapshots'),a.output)
        print(r['status']);return 0 if r['status'].startswith('PASS') else 1
    except (ValueError,OSError,KeyError,subprocess.SubprocessError):
        print('REFUSED finite extension source/hash/prerequisite');return 2


if __name__=='__main__':raise SystemExit(main())
