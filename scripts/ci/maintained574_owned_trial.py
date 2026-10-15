#!/usr/bin/env python3
"""One normal token-owned full574 build/probe and existing guarded cleanup."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import uuid

PINS={
 'maintained_desktop574.py':'27ba4be42cf2bd41675073e07cccc917ae033f9d68b07a33cfd7f074ac27b760',
 'maintained-desktop574-inputs.json':'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9',
 'native_arm.py':'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898',
 'asahi-lsp-build/job.py':'29c854180f55fe14475329601580e0345b50bc5ab365850c04003fa0b051c1a9',
 'old_four_seed.py':'a14e0318549d24a9bc91ceeb03ec2c1fa2d12f2b3a4f9b0a4cccfb64be34b2b7'}
ASSET='88a88bc5f3be3998e992881bf090137df16f1aae'
ASSET_PINS={'seed.py':'88d870421b05eec34d444ca8269b3484af0416055324cb5c10d0c9cdd5db728b','index.json':'758ec321b51183d32cffef26648ac9d805c680d44580cd035f22c1b39e37bb66'}
INVENTORY_SHA='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
ENV={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}


def need(value,message):
    if not value:raise ValueError(message)


def sha(path):
    with path.open('rb')as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def private(path):
    need(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute path required')
    s=path.stat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.getuid()and not s.st_mode&0o077,'private owned directory required')


def load(name,path,pin):
    need(not path.is_symlink()and path.is_file()and sha(path)==pin,'held Source differs')
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def save(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


def images(h):
    rows=h.docker('image','ls','-a','--no-trunc','-q').splitlines()
    need(all(re.fullmatch('sha256:[0-9a-f]{64}',v)for v in rows),'invalid daemon image list')
    return sorted(set(rows))


def seeded(h,base,asset,inputs):
    private(base);private(base/'context');private(base/'context/deps')
    need(not (base/'report.json').exists()and not (base/'report.json').is_symlink(),'fresh build report required')
    need(not any((base/name).exists()or(base/name).is_symlink()for name in('image-id','probe-cid')),'unconsumed owned build required')
    receipt=json.loads((base/'seed-report.json').read_bytes())
    need(receipt['status']=='SIX_EXACT_EXISTING_SEED_FILES_READY'and receipt['seeded_files']==6,'original six seed required')
    for name,pin in ASSET_PINS.items():need(sha(asset/name)==pin and not (asset/name).is_symlink(),'public asset Source differs')
    index=json.loads((asset/'index.json').read_bytes());need(index['desktop574_lock_sha256']==PINS['maintained-desktop574-inputs.json']and len(index['files'])==12,'public seed lock differs')
    planned={row['filename']:(row['size'],row['sha256'])for row in h.plan(inputs,base/'context')}
    for row in index['files']:
        target=base/'context/deps'/row['filename'];s=target.lstat()
        need(planned[row['filename']]==(row['size'],row['sha256'])and stat.S_ISREG(s.st_mode)and
             s.st_size==row['size']and sha(target)==row['sha256'],'public seed target differs')


def verify(h,base,token,before,inputs):
    report=json.loads((base/'report.json').read_bytes());owner=report['ownership'];tag,name=h.owner_names(token)
    need(report['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION'and report['native_build']=='PASS'and
         type(report['packages'])is int and report['packages']==574 and report['hardware']=='NOT_RUN'and
         type(report['acquired'])is int and report['acquired']==1153 and report['failures']==[]and
         type(report['build_returncode'])is int and report['build_returncode']==0,'full574 build report differs')
    need(owner['token']==token and owner['image_tag']==tag and owner['probe_name']==name and owner['probe_cidfile']=='probe-cid'and
         owner['before_images']==before and all(owner[k]is True for k in('build_started','build_complete','probe_started','probe_complete')),
         'completed ownership/probe report differs')
    image=(base/'image-id').read_text().strip();cid=(base/'probe-cid').read_text().strip()
    need(re.fullmatch('sha256:[0-9a-f]{64}',image)and image not in before and image==report['image']==owner['image']and
         re.fullmatch('[0-9a-f]{64}',cid),'image/probe identity differs')
    expected=''.join('{} {}\n'.format(r['name'],r['version'])for r in sorted(inputs['packages'],key=lambda r:r['name'])).encode()
    need(len(inputs['packages'])==574 and len({r['name']for r in inputs['packages']})==574 and
         hashlib.sha256(expected).hexdigest()==INVENTORY_SHA and (base/'context/expected-packages.lock').read_bytes()==expected and
         (base/'installed-packages.lock').read_bytes()==expected,'exact574 inventory differs')
    metadata=h.inspect_image(image,token)
    need(metadata['Id']==image and metadata.get('RepoTags')==[tag]and not metadata.get('RepoDigests'),'owned image references differ')
    return dict(image=image,probe_cid=cid,inventory_sha256=INVENTORY_SHA,packages=574,acquired=1153,
                build_returncode=0,probe_complete=True,token=token)


def invoke(process,argv,log,env,seconds):
    need(not log.exists()and not log.is_symlink(),'fresh phase log required')
    process.command(argv,log,env,seconds)
    return 0


def trial(h,process,base,out,inputs):
    token=uuid.uuid4().hex[:16];before=images(h)
    result=dict(status='FAIL',scope='NORMAL_FULL574_BUILD_PROBE_OWNED_CLEANUP',token=token,before_image_ids=before,
                build='NOT_STARTED',cleanup='NOT_STARTED',before_image_ids_preserved=False,cancelled=False,
                active_build_cancellation='NOT_TESTED',running_probe_interruption='NOT_TESTED',daemon_wide_cleanup='NOT_CLAIMED',hardware='NOT_RUN')
    pending=None;phase='build';started=False
    env=dict(ENV,HOME=str(base/'home'))
    argv=[sys.executable,'-I','-B',str(Path(h.__file__).resolve())]
    args=['--inputs',str(Path(h.__file__).parent/'maintained-desktop574-inputs.json'),'--output',str(base),'--job-token',token]
    def fault(error,where):
        nonlocal pending
        if pending is None:
            pending=error;result['first_failure']=dict(phase=where,kind=type(error).__name__)
            if isinstance(error,process.CommandExit):result['first_failure']['exit_code']=error.code
        else:result.setdefault('secondary_failure_phases',[]).append(where)
        if isinstance(error,(KeyboardInterrupt,SystemExit)):result['cancelled']=True
    try:
        result['build']='STARTED';save(out/'public/trial.json',result);started=True
        rc=invoke(process,argv+['build']+args,out/'build.log',env,2400);result['build_returncode']=rc
        need(rc==0,'normal full build did not exit0')
        result['verified_build']=verify(h,base,token,before,inputs);result['build']='PASS'
    except BaseException as error:fault(error,phase)
    finally:
        if started:
            rc=None;result['cleanup']='ATTEMPTED'
            try:rc=invoke(process,argv+['cleanup']+args,out/'cleanup.log',env,240)
            except BaseException as error:fault(error,'cleanup-command')
            try:
                cleanup=json.loads((base/'report.json').read_bytes())['owned_cleanup'];result['owned_cleanup']=cleanup
                need(rc==0 and cleanup['status']=='PASS'and cleanup['build']=='COMPLETED'and
                     cleanup['probe']['absence_verified']is True and cleanup['image']['absence_verified']is True,'owned cleanup did not pass')
                if 'verified_build'in result:
                    need(cleanup['image']['id']==result['verified_build']['image']and cleanup['probe']['cid']==result['verified_build']['probe_cid'],'cleanup identity differs')
                result['cleanup']='PASS'
            except BaseException as error:result['cleanup']='FAIL_OR_UNKNOWN';fault(error,'cleanup')
        try:
            after=images(h);result['after_image_ids']=after
            need(set(before)<=set(after),'original daemon image ID lost');result['before_image_ids_preserved']=True
        except BaseException as error:fault(error,'baseline-preservation')
        if pending is None and result['build']==result['cleanup']=='PASS':result['status']='PASS'
        try:save(out/'public/trial.json',result)
        except BaseException as error:
            result.update(status='FAIL',retention_uncertain=True);fault(error,'trial-retention')
    if isinstance(pending,(KeyboardInterrupt,SystemExit)):raise pending
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--base',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--asset',type=Path,required=True);ap.add_argument('--source-commit',required=True);args=ap.parse_args();os.umask(0o077)
    out=args.output.absolute();base=args.base.absolute();asset=args.asset.absolute()
    need(re.fullmatch('[0-9a-f]{40}',args.source_commit)and args.source_commit==os.environ.get('TRIAL_SOURCE_COMMIT'),'explicit selected Source required')
    need(not any(k.startswith('DOCKER_')for k in os.environ),'Docker overrides forbidden')
    need(not out.exists()and not any(p.is_symlink()for p in(out,*out.parents))and not out.is_relative_to(base)and not base.is_relative_to(out),'fresh separate output required')
    out.mkdir(mode=0o700);(out/'public').mkdir(mode=0o700)
    here=Path(__file__).resolve().parent
    for name,pin in PINS.items():need(sha(here/name)==pin,'held dependency differs')
    h=load('trial574_helper',here/'maintained_desktop574.py',PINS['maintained_desktop574.py'])
    native=load('trial574_native',here/'native_arm.py',PINS['native_arm.py'])
    process=load('trial574_process',here/'asahi-lsp-build/job.py',PINS['asahi-lsp-build/job.py'])
    runner=out/'public/runner';runner.mkdir(mode=0o700);native.probe(runner)
    inputs=json.loads((here/'maintained-desktop574-inputs.json').read_bytes());seeded(h,base,asset,inputs)
    previous={};pending=None;result=None;restore=[];cancelled=False
    def cancel(*_):raise KeyboardInterrupt()
    try:
        for sig in(signal.SIGINT,signal.SIGTERM):previous[sig]=signal.signal(sig,cancel)
        result=trial(h,process,base,out,inputs)
    except BaseException as error:pending=error;cancelled=isinstance(error,(KeyboardInterrupt,SystemExit))
    finally:
        for sig,handler in previous.items():
            try:signal.signal(sig,handler)
            except BaseException as error:
                restore.append(type(error).__name__)
                cancelled=cancelled or isinstance(error,(KeyboardInterrupt,SystemExit))
                if pending is None:pending=error
        if result is None:
            try:result=json.loads((out/'public/trial.json').read_bytes())
            except BaseException as error:
                result=dict(status='FAIL',scope='NORMAL_FULL574_BUILD_PROBE_OWNED_CLEANUP',retention_uncertain=True)
                if pending is None:pending=error
                cancelled=cancelled or isinstance(error,(KeyboardInterrupt,SystemExit))
        if pending is not None:
            result['status']='FAIL'
            result.setdefault('first_failure',dict(phase='wrapper',kind=type(pending).__name__))
            if cancelled:result['cancelled']=True
        if restore:result['signal_restoration_errors']=restore
        result.update(source_commit=args.source_commit,helper_sha256=PINS['maintained_desktop574.py'],public_asset=ASSET)
        try:save(out/'public/trial.json',result)
        except BaseException as error:
            result.update(status='FAIL',retention_uncertain=True)
            if pending is None:pending=error
    if isinstance(pending,(KeyboardInterrupt,SystemExit)):raise pending
    return int(result['status']!='PASS')


if __name__=='__main__':raise SystemExit(main())
