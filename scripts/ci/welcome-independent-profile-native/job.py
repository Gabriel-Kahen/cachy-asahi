#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-gated independent profile owner; original actors and cleanup are reused."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as K
import adapter


def native(source,selected,code):
    adapter.materialize(source,selected,code);sys.path.insert(0,str(code))
    # Each CLI process loads exactly one selected native derivative.
    return K.load('independent_native_job',code/'job.py')


def retain_extra(source,code,manifest,selected,proof,output,value):
    try:
        K.binding(K.read(proof),selected,manifest)
        for origin,prefix in ((code,'profile-harness'),(K.HERE,'profile-owner')):
            for path in sorted(origin.iterdir()):
                if not path.is_file():continue
                info=path.lstat();K.need(info.st_nlink==1 and info.st_size<=2*1024**2 and not path.is_symlink(),'bounded owner provenance required')
                target=output/prefix/path.name;target.parent.mkdir(exist_ok=True)
                K.need(value['total_bytes']+info.st_size<=512*1024**2,'original total evidence cap')
                shutil.copyfile(path,target);value['files'][prefix+'/'+path.name]=K.pin(target);value['total_bytes']+=info.st_size
        # The wrapper's actual run argv is retained separately from the child GUI
        # argv already recorded by the unchanged native command logger.
        runtime=K.read(proof)['runtime_path']
        path=Path(runtime)/'profile-invocation.json';item=K.read(path)
        K.need(item['profile']==selected and K.profile_argv(item['argv'])==['--profile',selected] and item['source_proof_sha256']==K.pin(proof)['sha256'] and item['derivation_sha256']==K.pin(code/'derivation.json')['sha256'],'actual wrapper invocation differs')
        target=output/'profile-invocation.json';K.need(value['total_bytes']+path.stat().st_size<=512*1024**2,'original total evidence cap');shutil.copyfile(path,target)
        value['files'][target.name]=K.pin(target);value['total_bytes']+=target.stat().st_size
        report=K.read(output/'runtime/report.json',4*1024**2)
        K.need(report.get('profile')==selected and all(name.startswith(selected+'-') for name in value.get('frames',{})),'runtime selected profile differs')
    except Exception as error:
        value['status']='FAIL_OR_INCOMPLETE';value['errors'].append('profile provenance: '+str(error)[:256])
    value.update(profile=selected,scope='ONE_PROFILE_NOT_FULL_GUI_ACCEPTANCE',aggregate_gui='REQUIRES_BOTH_SAME_SOURCE_CANDIDATE_ROOT_DECISIONS')
    (output/'retention.json').write_bytes(K.encoded(value));return value


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('proof','run','cleanup','retain'))
    p.add_argument('--profile',required=True,choices=K.PROFILES)
    for name in ('source','manifest','proof','code','base','runtime','cleanup','output'):p.add_argument('--'+name,type=Path)
    a=p.parse_args();operand=K.profile_argv(sys.argv[1:]);source=a.source.absolute();manifest=a.manifest.absolute();selected=K.profile(a.profile)
    K.gate(source,selected,K.read(manifest));api=native(source,selected,a.code.absolute())
    if a.phase=='proof':
        K.need(not a.proof.exists(),'fresh source proof required')
        value=api.prove(source,K.read(manifest),os.environ)
        value.update(profile=selected,scope='ONE_PROFILE_NOT_FULL_GUI_ACCEPTANCE',manifest_sha256=K.pin(manifest)['sha256'],
            entry_argv=operand,runtime_path=str(a.runtime.absolute()),derivation_sha256=K.pin(a.code/'derivation.json')['sha256'])
        a.proof.write_bytes(K.encoded(value))
        with open(os.environ['GITHUB_OUTPUT'],'a') as stream:stream.write('job_token='+value['job_token']+'\nconsumer_token='+value['consumer_token']+'\n')
    else:
        proof=K.read(a.proof);K.binding(proof,selected,manifest)
        K.need(proof['runtime_path']==str(a.runtime.absolute()),'fixed proof runtime differs')
        K.need(proof['derivation_sha256']==K.pin(a.code/'derivation.json')['sha256'],'exact derived owner differs')
        if a.phase=='run':
            run=K.load('independent_native_run',a.code/'run.py')
            try:return run.execute(source,a.base.absolute(),a.runtime.absolute(),proof['consumer_token'])
            finally:
                if a.runtime.is_dir():
                    path=a.runtime/'profile-invocation.json';K.need(not path.exists(),'fresh wrapper invocation required')
                    path.write_bytes(K.encoded(dict(schema_version=1,profile=selected,argv=list(sys.argv[1:]),source_proof_sha256=K.pin(a.proof)['sha256'],derivation_sha256=proof['derivation_sha256'])))
        if a.phase=='cleanup':value=api.cleanup(source,K.read(manifest),proof,a.base.absolute(),a.runtime.absolute(),a.output.absolute())
        else:
            value=api.retain(source,a.base.absolute(),a.runtime.absolute(),a.proof.absolute(),a.cleanup.absolute(),a.output.absolute())
            value=retain_extra(source,a.code,manifest,selected,a.proof,a.output,value)
    print(K.encoded(value).decode(),end='')
    return int(value['status'] not in ('SOURCE_PROOF_PASS','PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP',K.RETAINED))


if __name__=='__main__':raise SystemExit(main())
