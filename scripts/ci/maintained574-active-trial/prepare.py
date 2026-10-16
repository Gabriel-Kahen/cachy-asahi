#!/usr/bin/env python3
"""Only held public acquisition/context generation; never invokes docker build."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import support as s


def public_seed(ci, base, public):
    owner = s.load(ci,'maintained574_active_owner.py')
    owner.private(base); owner.private(base/'context'); owner.private(base/'context/deps')
    seed,_ = s.read(base/'seed-report.json')
    s.need(seed['status']=='SIX_EXACT_EXISTING_SEED_FILES_READY' and seed['seeded_files']==6,'six_seed_required')
    for name,pin in s.PUBLIC_PINS.items(): s.pinned(public/name,pin)
    log = base/'public-seed.log'
    owner.command([sys.executable,'-I','-B',str(public/'seed.py'),'--cache',str(base/'context/deps')],
                  log,dict(s.ENV,HOME=str(base/'home'),TMPDIR=str(base)),120)
    s.need(log.stat().st_size<=8192,'public_seed_log_bound')
    result = json.loads(log.read_bytes())
    s.need(result['status']=='SEEDED_EXACT_PUBLIC_INPUTS' and result['files']==14 and
           result['copied']+result['existing']==14,'public_seed_count')
    return {'status':'SEEDED_EXACT_PUBLIC_INPUTS','files':14,'copied':result['copied'],'existing':result['existing'],
            'source_commit':s.PUBLIC_COMMIT,'source_pins':s.PUBLIC_PINS,'signature_authentication':'NOT RUN; held transaction required'}


def acquire(ci, base):
    held = s.load(ci,'maintained_desktop574.py')
    s.pinned(ci/'old_four_seed.py',s.PINS['old_four_seed.py'])
    s.pinned(ci/'maintained-desktop574-inputs.json',s.PINS['maintained-desktop574-inputs.json'])
    owner = s.load(ci,'maintained574_active_owner.py')
    owner.private(base); owner.private(base/'context')
    inputs,_ = s.read(ci/'maintained-desktop574-inputs.json',2*1024**2)
    items = held.plan(inputs,base/'context')
    def fetch(row):
        try:
            held.fetch(row)
            return None
        except Exception as error:
            code = getattr(error,'code',None)
            return {'filename':row['filename'],'kind':type(error).__name__[:64],
                    'http_status':code if type(code) is int and 100<=code<=599 else None}
    with ThreadPoolExecutor(max_workers=6) as pool:
        failures = [row for row in pool.map(fetch,items) if row is not None]
    report = {'status':'FAIL','planned':len(items),'acquired':len(items)-len(failures),
              'failure_count':len(failures),'failures':failures[:32],'failures_truncated':len(failures)>32,
              'legacy_docker_build':'NOT RUN','signature_transaction':'NOT RUN'}
    if not failures:
        held.configure(inputs,base/'context')
        transaction,lock = owner.context(ci,base/'context')
        report.update(status='PREPARED_EXACT_574_CONTEXT',transaction_sha256=s.sha(transaction.encode()),
                      inventory_sha256=s.sha(lock.encode()),objects_verified=1153,
                      helper_sha256=s.PINS['maintained_desktop574.py'],inputs_sha256=s.PINS['maintained-desktop574-inputs.json'])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('public-seed','acquire'))
    for key in ('source-ci','base','public-output'): parser.add_argument('--'+key,required=True,type=Path)
    parser.add_argument('--public-inputs',type=Path)
    args = parser.parse_args(); os.umask(0o077)
    s.need(not any(k.startswith(('CACHY_','DOCKER_')) for k in os.environ),'clean_preparation_environment_required')
    ci,base = args.source_ci.absolute(),args.base.absolute()
    result = {'status':'FAIL','mode':args.mode}
    try:
        result = public_seed(ci,base,args.public_inputs.absolute()) if args.mode=='public-seed' else acquire(ci,base)
    except BaseException as error:
        result['error']=s.error(error)
        raise
    finally:
        s.save(args.public_output,result)
    return int(result['status'] not in ('PREPARED_EXACT_574_CONTEXT','SEEDED_EXACT_PUBLIC_INPUTS'))


if __name__=='__main__': raise SystemExit(main())
