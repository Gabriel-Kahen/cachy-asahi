#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reuse exact source proof/owned retirement; export only explicit bounded evidence."""
import argparse
import json
from pathlib import Path
import shutil
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import adapter

MAX_TOTAL=48*1024**2


def namespace(source):
    raw=(source/'scripts/ci/tools-native/job.py').read_text()
    for before,after,count in (('len(names)<=8','len(names)<=4',1),('tools-consumer:','setup5-real-consumer:',1),("if __name__=='__main__':","def inherited_main():",1)):
        raw=adapter.replace(raw,before,after,count)
    value=dict(__file__=str(C.HERE/'job.py'),__name__='accepted_setup5_real_cleanup');exec(compile(raw,value['__file__'],'exec'),value);value['C']=C;return value


def retain(J,source,base,runtime,proof_path,cleanup_path,output):
    C.safe(output);C.need(not output.exists(),'fresh closed evidence output required');output.mkdir(mode=0o700)
    result=dict(status='FAIL_OR_INCOMPLETE',files={},errors=[],total_bytes=0,hardware='NOT_RUN',release='NOT_ADMITTED',notification_delivery='NOT_RUN',current587_600='UNCHANGED')
    def copy(path,name,cap,required=True):
        try:
            if not required and not path.exists():return
            info=J['regular'](path,cap);C.need(result['total_bytes']+info.st_size<=MAX_TOTAL,'closed48MiB export bound')
            target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target);result['files'][name]=dict(bytes=info.st_size,sha256=C.digest(target));result['total_bytes']+=info.st_size
        except Exception as error:result['errors'].append(name+': '+str(error)[:256])
    copy(proof_path,'source-proof.json',65536);copy(cleanup_path,'ordered-cleanup.json',65536)
    for name in ('report.json','installed-packages.lock'):copy(base/name,'base/'+name,1024**2)
    for name,cap in (('report.json',4*1024**2),('lifecycle.json',4*1024**2),('legacy-lifecycle.json',2*1024**2),('real-modules.json',1024**2),('owner.json',65536),('base-inventory.log',256*1024),('lifecycle.log',16*1024**2)):
        copy(runtime/name,'runtime/'+name,cap)
    manifest=C.read(C.HERE/'source-manifest.json')
    copy(C.HERE/'source-manifest.json','source/source-manifest.json',1024**2)
    for relative in manifest['files']:
        if relative.startswith('scripts/ci/setup5-native-real-modules/'):
            copy(source/relative,'harness/'+Path(relative).name,2*1024**2)
    for profile in ('state','journal-before','journal-after','journal-commit','remove-journal','new-grouped-journal'):
        for phase in ('legacy','upgrade','rollback','forward'):
            name=profile+'-'+phase+'.json';copy(runtime/'observations'/name,'observations/'+name,65536)
    context=runtime/'lifecycle-inputs'
    for name in ('accepted-module-index.json','accepted-setup5-index.json','products.json','modules.json','base.json','expected581.lock'):copy(context/name,'inputs/'+name,2*1024**2)
    try:
        products=C.read(context/'modules.json');C.need(set(products)==set(C.NAMES),'all seven installed input records required')
        for name,row in products.items():
            copy(context/row['archive'],'inputs/installed/'+row['archive'],8*1024**2)
            for ref in row['accepted_pair']['files'].values():copy(C.checked(context,ref),'inputs/'+ref['path'],8*1024**2)
        old=C.read(context/'setup4/product.json');copy(context/'setup4/product.json','inputs/setup4/product.json',65536);copy(context/'setup4'/old['archive'],'inputs/setup4/'+old['archive'],8*1024**2)
    except Exception as error:result['errors'].append('retained pairs: '+str(error)[:256])
    try:
        C.verify_source(source);proof=C.read(proof_path);original=C.read(base/'report.json');report=C.read(runtime/'report.json',4*1024**2);ordered=C.read(cleanup_path);owner=C.read(runtime/'owner.json');life=C.read(runtime/'lifecycle.json',4*1024**2)
        C.validate_lifecycle(life)
        C.need(report['lifecycle']==life and C.read(runtime/'legacy-lifecycle.json')==life['legacy'] and C.read(runtime/'real-modules.json')==life['real_modules'],'standalone legacy/real/combined observations differ')
        for row in life['legacy']['actual_observations']:C.need(C.read(runtime/'observations'/(row['profile']+'-'+row['phase']+'.json'))==row['proof'],'standalone legacy observation differs')
        C.need(proof['status']=='SOURCE_PROOF_PASS' and report['status']=='PASS_NATIVE_SETUP5_LEGACY_AND_REAL_MODULES' and report['borrowed_inputs_preserved'] is True and report['base_count']==574 and report['base_lock_sha256']==C.digest(base/'installed-packages.lock') and set(report['products'])==set(C.NAMES),'actual report/source/input preservation required')
        C.need(original['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and original['ownership']['token']==proof['job_token'] and original['image']==report['base_image']==owner['image'] and original['owned_cleanup']['status']=='PASS' and original['owned_cleanup']['image']==dict(id=original['image'],absence_verified=True) and original['owned_cleanup']['probe']['absence_verified'] is True,'original owned574 producer retirement required')
        C.need(ordered['status']=='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP' and ordered['consumer']['status']=='PASS_CONSUMERS_RETIRED' and ordered['producer']==original['owned_cleanup'] and owner['token']==proof['consumer_token']==report['ownership_token'] and owner['label']==C.LABEL and len(owner['containers'])==2 and sum(n.startswith('cachy-asahi-product-probe-') for n in owner['containers'])==1 and sum(n.startswith('cachy-asahi-product-lifecycle-') for n in owner['containers'])==1 and len(ordered['consumer']['containers'])==2 and {r['container'] for r in ordered['consumer']['containers']}==set(owner['containers']) and all(r['status']=='PASS' and r['absence_verified'] is True for r in ordered['consumer']['containers']),'actual two launched consumers before producer absence required')
        for name,row in products.items():
            C.need(row['version']==C.VERSIONS[name] and row['sha256']==report['products'][name]['sha256'] and row['accepted_pair']==report['products'][name]['accepted_pair'] and row['accepted_pair']['files']['a']['sha256']==row['sha256']==row['accepted_pair']['files']['b']['sha256'],'accepted pair/installed/archive report join differs')
        C.need(not result['errors'],'closed evidence incomplete');result['status']='PASS_NATIVE_SETUP5_LEGACY_AND_REAL_MODULES_RETIRED'
    except Exception as error:result['errors'].append(str(error)[:512])
    J['save'](output/'retention.json',result);return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('proof','cleanup','retain'))
    for name in ('source','manifest','proof','base','runtime','cleanup','output'):p.add_argument('--'+name,type=Path)
    a=p.parse_args();C.verify_source(a.source);J=namespace(a.source)
    if a.phase=='proof':
        value=J['prove'](a.source,J['read'](a.manifest),__import__('os').environ);J['save'](a.proof,value)
        with open(__import__('os').environ['GITHUB_OUTPUT'],'a') as stream:stream.write('job_token='+value['job_token']+'\nconsumer_token='+value['consumer_token']+'\n')
    elif a.phase=='cleanup':value=J['cleanup'](a.source,J['read'](a.manifest),J['read'](a.proof),a.base,a.runtime,a.output)
    else:value=retain(J,a.source,a.base,a.runtime,a.proof,a.cleanup,a.output)
    print(json.dumps(value,indent=2));raise SystemExit(value['status'] not in ('SOURCE_PROOF_PASS','PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP','PASS_NATIVE_SETUP5_LEGACY_AND_REAL_MODULES_RETIRED'))
