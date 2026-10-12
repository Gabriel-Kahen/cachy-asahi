#!/usr/bin/env python3
"""Re-resolve the generic desktop proposal against the adopted Perl builder pins."""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import authenticate as auth
import migration
import preview

NEW_BUILDER='3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650'
OLD_RECEIPT='2b20ab5d0baa7ccafd0287e4c86419dc914745d02600e0ca3b3318d611dc042f'
OLD_PROPOSAL='d39a04fb680b57b9b45eb5ec8cfdee4e7f834976564fc90c69e23e267ad0722a'
SNAPSHOTS=[{'name':'core','sha256':'5f184763bad034ac02662ee37d87edad8124244c8609f4a441947da1855b0b08','size':256696,'signed':False,
            'url':'https://ca.us.mirror.archlinuxarm.org/aarch64/core/core.db'},
           {'name':'extra','sha256':'66cfbeae024c325e19ba7334afcb0ff2ab892ba4f0789216b358648f7647b480','size':10613897,'signed':False,
            'url':'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/extra.db'}]


def resolve(builder, old_receipt, old_proposal, dbdir, out):
    preview.need(not out.exists() and not out.is_symlink(),'new output required')
    initial=migration.baseline(old_receipt,False)
    for p in old_receipt['full_candidate_inventory']:
        if p['name'][0] in initial:
            initial[p['name'][0]].update({'FILENAME':p['archive_filename'],'SHA256SUM':p['archive_sha256'],
                                         'repo':'declared-new-builder-metadata'})
    new_perl=next(p for p in builder['packages'] if p['name']=='perl')
    preview.need(new_perl['version']=='5.42.3-1' and new_perl['sha256']=='f0e47c42ec91985898af2ce7355ef4eead50457108706add1f8c1650bca19b8f','adopted Perl identity refused')
    initial['perl']={field:(new_perl[k] if isinstance(new_perl[k],list) else [new_perl[k]]) for k,field in migration.FIELDS.items()}
    initial['perl'].update({'FILENAME':[new_perl['filename']],'SHA256SUM':[new_perl['sha256']],
                            'URL':new_perl['source_url'],'repo':'declared-new-builder-metadata'})
    inventory=''.join(n+' '+p['VERSION'][0]+'\n' for n,p in sorted(initial.items()))
    inventory_hash=hashlib.sha256(inventory.encode()).hexdigest()
    proposal=copy.deepcopy(old_proposal)
    proposal.update({'builder_lock_sha256':NEW_BUILDER,'builder_inventory_sha256':inventory_hash,'snapshots':SNAPSHOTS})
    proposal['provider_constraints'].append({'name':'perl','version':'5.42.3-1'})
    proposal['limitations']=['Declared new 341 builder inventory, not yet a native installed builder',
        'GENERIC stock Mesa only; Asahi boot/kernel/firmware/Mesa/audio transaction NOT RUN',
        'FDK 3.0.0 candidate authenticated but license/source clearance still pending',
        '45 roots; Neovim optional; current complete candidate archive set must be separately authenticated',
        'Named package/platform/release custodians unassigned']
    packages=preview.databases(dbdir,SNAPSHOTS)
    targets=preview.proposal_check(proposal,packages)
    receipt={'schema':1,'scope':'GENERIC desktop re-resolution from explicitly adopted builder metadata',
        'source_sha256':auth.native.sha(Path(__file__)),'preview_helper_sha256':auth.native.sha(Path(preview.__file__)),
        'builder_lock_sha256':NEW_BUILDER,'initial_declared_count':341,'initial_inventory_sha256':inventory_hash,
        'old_preview_receipt_sha256':OLD_RECEIPT,'roots':proposal['roots'],'provider_constraints':proposal['provider_constraints'],
        'snapshots':SNAPSHOTS,'status':'FAIL','native_builder_installation':'NOT RUN','host_package_installation':'NOT RUN',
        'target_Asahi_transaction':'NOT RUN','hardware':'NOT RUN','signature_authentication':'separate candidate/archive receipts; not performed by print resolution'}
    with tempfile.TemporaryDirectory(prefix='cachy-port-',dir='/tmp') as tmp:
        work=Path(tmp);preview.setup(work,dbdir,SNAPSHOTS,initial)
        result=preview.run(work,'preview',targets)
        final=dict(initial);changes=[]
        for line in result.stdout.splitlines():
            v=line.split('\t')
            if len(v)!=6:continue
            n,version,repo,arch,size,hash_=v
            preview.need(n in packages and packages[n]['VERSION']==[version] and packages[n]['repo']==repo and
                         packages[n]['ARCH']==[arch] and packages[n]['SHA256SUM']==[hash_],'print identity not snapshot-bound')
            changes.append({'name':n,'old_version':initial.get(n,{}).get('VERSION',[None])[0],
                            'version':version,'download_bytes':int(size),'kind':'change' if n in initial else 'add'})
            final[n]=packages[n]
        preview.need(len({c['name'] for c in changes})==len(changes),'duplicate print result')
        for r in proposal['roots']+proposal['provider_constraints']:
            preview.need(final.get(r['name'],{}).get('VERSION')==[r['version']],'selected pinned root/provider missing')
        import shutil
        shutil.rmtree(work/'db/local');preview.write_local(work/'db/local',final)
        relationships,conflicts=preview.alpm_audit(work,final)
        deptest=preview.run(work,'deps',sorted({r['relation'] for r in relationships}))
        receipt.update({'pacman_exit':result.returncode,'diagnostic':result.stderr.replace(str(work),'<temporary-context>'),
            'changes':sorted(changes,key=lambda c:c['name']),'final_count':len(final),
            'download_bytes':sum(c['download_bytes'] for c in changes),'dependency_relationships':relationships,
            'unsatisfied':[r for r in relationships if not r['provider']],'conflicts':conflicts,'removals':[],
            'deptest_exit':deptest.returncode,'deptest_missing':deptest.stdout.splitlines(),
            'full_candidate_inventory':[preview.public_record(p) for _,p in sorted(final.items())]})
        receipt['status']='PASS-generic-metadata-preview' if not (result.returncode or deptest.returncode or conflicts or receipt['unsatisfied']) else 'FAIL'
        preview.need(receipt['final_count']==574 and len(changes)==233 and all(c['kind']=='add' for c in changes),'expected unchanged 341 +233 expansion refused')
    archive_items=[]
    for change in receipt['changes']:
        m=packages[change['name']];sig=base64.b64decode(m['PGPSIG'][0],validate=True)
        item={key:(m.get(field,[]) if key in ('license','depends','provides','conflicts','replaces') else m[field][0])
              for key,field in migration.FIELDS.items()}
        item.update({'filename':m['FILENAME'][0],'sha256':m['SHA256SUM'][0],'size':int(m['CSIZE'][0]),'isize':int(m['ISIZE'][0]),
            'url':'https://ca.us.mirror.archlinuxarm.org/aarch64/'+m['repo']+'/'+m['FILENAME'][0],
            'signature_sha256':hashlib.sha256(sig).hexdigest(),'signature_size':len(sig),'repo':m['repo'],'source_url':m.get('URL',[])})
        archive_items.append(item)
    out.mkdir(parents=True)
    auth.native.save(out/'desktop-proposal.json',proposal);auth.native.save(out/'receipt.json',receipt)
    (out/'proposed-builder-inventory.lock').write_text(inventory)
    lock={'schema':1,'scope':'GENERIC-desktop-data-authentication','signer_fingerprint':auth.SIGNER,'keyring_files':builder['keyring_files'],
        'proposal_sha256':auth.native.sha(out/'desktop-proposal.json'),'preview_receipt_sha256':auth.native.sha(out/'receipt.json'),
        'builder_lock_sha256':NEW_BUILDER,'repository_databases':SNAPSHOTS,'packages':archive_items}
    auth.validate(lock);auth.bind(lock,proposal,receipt,builder)
    auth.native.save(out/'desktop-archives-proposal.json',lock)
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);a=parser.parse_args()
    here=Path(__file__).resolve().parent
    try:
        builder=preview.load(here.parent/'ci/inputs.lock.json',NEW_BUILDER)
        old_receipt=preview.load(here/'generic-desktop-receipt.json',OLD_RECEIPT)
        old_proposal=preview.load(here/'desktop-proposal.json',OLD_PROPOSAL)
        r=resolve(builder,old_receipt,old_proposal,Path('/tmp/cachy-port-migration-snapshots'),a.output)
        print(r['status']);return 0 if r['status'].startswith('PASS') else 1
    except (ValueError,OSError,KeyError,subprocess.SubprocessError):
        print('REFUSED re-resolution input/hash/prerequisite');return 2


if __name__=='__main__':raise SystemExit(main())
