#!/usr/bin/env python3
"""Finite kernel toolchain data audit. No package installation or native execution."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
BASE = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
INVENTORY = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
ROOTS = ('rust', 'rust-src', 'rust-bindgen', 'pahole', 'bc', 'dtc', 'xmlto', 'clang', 'llvm')
MAX_BYTES = 800 * 1024**2
HELPERS = {
    'scripts/port/preview.py': 'd737c51474e05cc2c4db2e87fc021f50328eea7744983dd4076d44751fce7383',
    'scripts/port/authenticate.py': '241cd67370eb593bdf948a25788f006ecf470c645ba5d198bc9c318119ebfe10',
    'scripts/ci/native_arm.py': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898',
    'scripts/port/updater_extension.py': '55d1fa6976e2a25c6d5f7ade8ef9e3581e0fee4e0f03313332ce8db4a106704f',
    'scripts/port/re_resolution.py': '1553c5d01fbe074372db584b6216c03e683a7a69c6fcf165b354238dfb3c6b8f',
}

def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024**2), b''): h.update(b)
    return h.hexdigest()


def need(ok, message):
    if not ok: raise ValueError(message)


def helpers():
    for path, pin in HELPERS.items(): need(sha(ROOT/path) == pin, 'helper source pin mismatch')
    sys.path.insert(0, str(ROOT/'scripts/port'))
    import preview, authenticate, updater_extension, re_resolution
    return preview, authenticate, updater_extension, re_resolution


def inventory(records):
    return ''.join(n+' '+p['VERSION'][0]+'\n' for n, p in sorted(records.items()))


def check_preserved(base, final):
    need(len(base) == 341 and hashlib.sha256(inventory(base).encode()).hexdigest() == INVENTORY,
         'accepted baseline identity refused')
    need(all(n in final and final[n]['VERSION'] == p['VERSION'] for n,p in base.items()),
         'baseline replacement/removal refused')


def finite_packages(items):
    need(1 <= len(items) <= 30 and len({p['name'] for p in items}) == len(items), 'finite package count refused')
    total = 0
    for p in items:
        need(p['arch'] in ('aarch64','any') and p['filename'] == f"{p['name']}-{p['version']}-{p['arch']}.pkg.tar.xz",
             'package architecture/filename refused')
        need(p['url'] == 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/'+p['filename'], 'package URL refused')
        need(all(isinstance(p[k],int) and 0 < p[k] <= MAX_BYTES for k in ('size','signature_size')) and
             p['signature_size'] <= 65536, 'package size refused')
        need(all(isinstance(p[k],str) and len(p[k]) == 64 and all(c in '0123456789abcdef' for c in p[k])
                 for k in ('sha256','signature_sha256')), 'package digest refused')
        total += p['size'] + p['signature_size']
    need(total <= MAX_BYTES, 'finite byte budget refused')
    return total


def resolve(dbdir, output):
    p,a,u,r = helpers()
    builder = p.load(ROOT/'scripts/ci/inputs.lock.json',BASE)
    receipt = p.load(ROOT/'scripts/port/refreshed-desktop/receipt.json',u.BASE_RECEIPT)
    base = u.seed(receipt); packages = p.databases(dbdir,r.SNAPSHOTS)
    roots = [n+'='+packages[n]['VERSION'][0] for n in ROOTS]
    # Existing reviewed print-only CLI permits this small temporary metadata context.
    # All bulk archives and evidence stay in ignored project storage.
    with tempfile.TemporaryDirectory(prefix='cachy-port-',dir='/tmp') as tmp:
        w = Path(tmp); p.setup(w,dbdir,r.SNAPSHOTS,base)
        printed = p.run(w,'preview',roots)
        need(printed.returncode == 0,'metadata resolution failed')
        final = dict(base); additions = []
        for line in printed.stdout.splitlines():
            values = line.split('\t'); need(len(values) == 6,'unexpected print output')
            n,version,repo,arch,size,digest = values
            found = packages[n]
            need(found['VERSION'] == [version] and found['repo'] == repo and found['ARCH'] == [arch] and
                 found['SHA256SUM'] == [digest] and found['CSIZE'] == [size], 'unbound resolution output')
            need(n not in base,'baseline addition collision refused')
            final[n] = found; additions.append(u.package_record(found))
        check_preserved(base,final); finite_packages(additions)
        need(all(final[n]['VERSION'] == packages[n]['VERSION'] for n in ROOTS),'root missing')
        shutil.rmtree(w/'db/local'); p.write_local(w/'db/local',final)
        relations,conflicts = p.alpm_audit(w,final)
        tested = p.run(w,'deps',sorted({x['relation'] for x in relations}))
        need(not conflicts and all(x['provider'] for x in relations) and tested.returncode == 0,
             'dependency/provider/conflict check failed')
    text = inventory(final)
    (output/'expected-packages.lock').write_text(text)
    record = {'schema_version':1,'purpose':'separate-kernel-native-builder-extension','status':'SOURCE-RESOLVED',
        'base_inputs_lock_sha256':BASE,'base_inventory_sha256':INVENTORY,'initial_count':341,
        'expected_inventory_sha256':hashlib.sha256(text.encode()).hexdigest(),'expected_packages':text,
        'final_count':len(final),'baseline_changes':[],'removals':[],
        'snapshots':r.SNAPSHOTS,'root_pins':[{'name':n,'version':packages[n]['VERSION'][0]} for n in ROOTS],
        'packages':sorted(additions,key=lambda x:x['name']),'download_bytes':sum(x['size'] for x in additions),
        'signer_fingerprint':a.SIGNER,'keyring_files':builder['keyring_files'],
        'dependency_relationship_count':len(relations),'deptest_exit':tested.returncode,'conflicts':conflicts,
        'source_helpers':HELPERS,'native_installation':'NOT RUN','native_compiler_execution':'NOT RUN',
        'kernel_build':'NOT RUN','physical_16K_M2':'NOT RUN','publication':'not accepted; private toolchain inputs',
        'complete_corresponding_source_license_closure':'NOT ESTABLISHED; declarations and notice hashes only'}
    a.native.save(output/'resolution.json',record)
    a.native.save(output/'dependency-relationships.json',relations)
    return record


def authenticate(record, output):
    p,a,u,r = helpers(); cache = output/'cache'; cache.mkdir(mode=0o700,exist_ok=True)
    need(not cache.is_symlink() and cache.stat().st_uid == os.getuid() and not cache.stat().st_mode & 0o077,
         'private cache ownership/mode refused')
    finite_packages(record['packages'])
    for k in record['keyring_files']:
        file = u.KEYS/k['filename']
        need(file.is_file() and not file.is_symlink() and file.stat().st_size == k['size'] and sha(file) == k['sha256'],
             'key pin refused')
    def fetch(item):
        reused = []
        for part in (item,a.native.signature_item(item)):
            existing = u.CACHE/part['filename']
            if existing.is_file() and not existing.is_symlink() and existing.stat().st_size == part['size'] and sha(existing) == part['sha256']:
                target = cache/part['filename']
                if not target.exists(): shutil.copyfile(existing,target); target.chmod(0o600)
                reused.append(part['filename'])
            a.fetch(part,cache)
        return item['name'],reused
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: reused = dict(pool.map(fetch,record['packages']))
    results = []; obsdir = output/'observations'; obsdir.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='public-gpg-',dir=output) as tmp:
        home = Path(tmp); home.chmod(0o700)
        gpg = ['/usr/bin/gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve','--no-autostart']
        imported = subprocess.run(gpg+['--import',str(u.KEYS/'archlinuxarm.gpg')],capture_output=True,text=True,timeout=60)
        need(imported.returncode == 0,'pinned key import failed')
        for item in record['packages']:
            verified = subprocess.run(gpg+['--status-fd','1','--verify',str(cache/(item['filename']+'.sig')),
                                          str(cache/item['filename'])],capture_output=True,text=True,timeout=60)
            a.status(verified); observation = a.observe(cache/item['filename'],item)
            file = obsdir/(item['name']+'.json'); a.native.save(file,observation)
            results.append({'name':item['name'],'version':item['version'],'status':'PASS-authenticated-toolchain-data',
                'archive_sha256':sha(cache/item['filename']),'signature_sha256':sha(cache/(item['filename']+'.sig')),
                'gpg_exit':verified.returncode,'gpg_status':verified.stdout,'reused':reused[item['name']],
                'observation_sha256':sha(file),'license_notice_files':observation['license_notice_files'],
                'hook_scriptlets':observation['hooks_and_scriptlets'],'ELF_count':len(observation['ELF'])})
            a.native.save(output/'authentication.json',{'status':'IN PROGRESS','results':results})
    record.update(status='PASS-authenticated-kernel-builder-extension-data',authentication=results,
                  public_only_gpg_home_removed=True,verified_count=len(results))
    a.native.save(output/'authentication.json',record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot-dir',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args(); output = args.output.absolute()
    need(output.is_relative_to(ROOT/'artifacts/kernel-native-stage/dependencies') and not output.exists(), 'new owned output required')
    output.mkdir(parents=True,mode=0o700)
    try:
        record = authenticate(resolve(args.snapshot_dir,output),output)
        print(record['status']);return 0
    except Exception as error:
        (output/'failure.json').write_text(json.dumps({'status':'FAIL','error':type(error).__name__,'message':str(error)})+'\n')
        raise



def validate_data(record):
    """Check frozen packet's finite closure and preserve exact accepted inventory."""
    need(record['base_inputs_lock_sha256'] == BASE and record['base_inventory_sha256'] == INVENTORY,
         'baseline pin refused')
    text = record['expected_inventory']
    need(isinstance(text,str) and hashlib.sha256(text.encode()).hexdigest() == record['expected_inventory_sha256'],
         'inventory digest refused')
    rows = [x.split(' ') for x in text.splitlines()]
    need(all(len(x) == 2 and all(x) for x in rows) and rows == sorted(rows) and len({x[0] for x in rows}) == len(rows),
         'inventory rows refused')
    actual = dict(rows); items = record['packages']; finite_packages(items)
    need(len(items) == 15 and len(actual) == 356 and record['final_count'] == 356 and record['initial_count'] == 341,
         'exact kernel extension count refused')
    need(all(actual.get(p['name']) == p['version'] for p in items), 'addition absent from inventory')
    addition_names = {p['name'] for p in items}
    remaining = ''.join(n+' '+v+'\n' for n,v in rows if n not in addition_names)
    need(hashlib.sha256(remaining.encode()).hexdigest() == INVENTORY, 'baseline replacement/removal refused')
    need(tuple(p['name'] for p in record['root_pins']) == ROOTS and
         all(actual.get(p['name']) == p['version'] for p in record['root_pins']), 'root identity refused')
    need(record['signer_fingerprint'] == '68B3537F39A313B3E574D06777193F152BDBE6A6' and
         record['baseline_changes'] == [] and record['removals'] == [] and record['conflicts'] == [], 'policy refused')
    return actual


if __name__ == '__main__': raise SystemExit(main())
