#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Root-invoked independent DATA consistency wrapper; no lifecycle/acceptance authority."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path,PurePosixPath
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]

def need(ok,why):
    if not ok:raise ValueError(why)


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def load(path,cap=16*1024**2):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size<=cap,'bounded original DATA input')
    return json.loads(path.read_bytes())


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);__import__('sys').modules[name]=value;spec.loader.exec_module(value);return value


def bootstrap_data(root,evidence,binding,hosted,c):
    """Join Source-pinned signed349 observations; performs no cryptographic actor."""
    original=load(root/'original/bootstrap/scripts/ci/inputs.lock.json')
    profile=load(root/'original/native/input-profile.json')
    need(len(original['packages'])==248 and len(profile['additions']['rows'])==8,'exact frozen248+8 input Source')
    combined=dict(original,packages=[*original['packages'],*profile['additions']['rows']])
    need(load(evidence/'bootstrap/inputs.lock.json')==combined,'actual bootstrap input declaration differs from Source')
    signed=[combined['rootfs'],*combined['packages']]
    expected={row['filename']:row for row in signed}
    need(len(expected)==257,'unique frozen signed257 payloads')
    signatures=load(evidence/'bootstrap/signatures.json')
    need(set(signatures)==set(expected),'complete exact257 signed filenames required')
    items=list(combined['keyring_files'])
    for row in signed:
        items.extend([row,dict(filename=row['filename']+'.sig',size=row['signature_size'],sha256=row['signature_sha256'])])
    acquisition=load(evidence/'bootstrap/acquisition.json')
    need(len(items)==517 and set(acquisition['inputs'])=={row['filename'] for row in items} and acquisition['acquisition']=='PASS' and acquisition['counts']==dict(total=517,**{'pass':517,'fail':0,'pending':0}),'all exact517 input acquisition observations required')
    for row in items:
        need(acquisition['inputs'][row['filename']]==dict(status='PASS',expected_bytes=row['size'],expected_sha256=row['sha256']),'Source-pinned bootstrap acquisition declaration differs')
    operations=load(evidence/'bootstrap/operations.json');used=set()
    for name,row in signatures.items():
        signer=combined['signer_fingerprint'];records=[line.split()[1:] for line in row['status'].splitlines() if line.startswith('[GNUPG:] ')]
        valid=[record for record in records if record and record[0]=='VALIDSIG']
        need(row['exit_code']==0 and len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==signer=='68B3537F39A313B3E574D06777193F152BDBE6A6','exact pinned primary signature semantics differ')
        need(not any(record and record[0] in ('BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG') for record in records),'frozen signature failure status')
        argv=row['command'];payload=PurePosixPath(argv[-1]);cache=payload.parent;temp=cache.parent
        need(cache.name=='alarm-cache' and cache.is_absolute() and '..' not in cache.parts and argv==['gpg','--batch','--no-options','--homedir',str(temp/'perl-lifecycle-hosted/bootstrap/gpg'),'--no-auto-key-retrieve','--status-fd','1','--verify',str(cache/(name+'.sig')),str(cache/name)],'exact frozen public GPG verification command differs')
        matches=[(i,operation) for i,operation in enumerate(operations) if operation['argv']==argv]
        need(len(matches)==1 and matches[0][0] not in used,'unique original public signature command receipt required')
        index,operation=matches[0];used.add(index);life=operation['lifecycle']
        need(operation['returncode']==life.get('exit')==0 and life.get('natural_exit') is True and life.get('forced_cleanup') is False and life.get('group_absent') is True and life.get('retirement')=='REAPED' and life.get('ownership_lost') is False and life.get('leader_held_until_group_inspection') is True and life.get('exit_observed_via_waitpid') is True,'signature command retirement differs')
        for channel,body in (('stdout',row['status'].encode()),('stderr',row['diagnostic'].encode())):
            relative=PurePosixPath(operation[channel]);need(not relative.is_absolute() and '..' not in relative.parts,'contained raw signature channel path')
            raw=c.read(evidence/relative,16*1024**2)
            need(raw==body and c.pin(raw)==operation[channel+'_pin'],'original raw public signature channel differs')
    proof=load(evidence/'bootstrap/proof.json');need(proof['status']=='PASS_FRESH_SIGNED349_BOOTSTRAP' and proof['binding']==hosted['binding'],'fresh bootstrap proof binding differs')
    need(proof['image']==hosted['bootstrap']['image']==binding['image'],'actual fresh signed349 image differs')
    for name,key in [('inputs.lock.json','inputs_sha256'),('acquisition.json','acquisition_sha256'),('signatures.json','signatures_sha256'),('image-inspect.json','image_inspect_sha256'),('input-data-preparation.json','preparation_sha256'),('fixed-eight-cache.json','cache_additions_sha256')]:
        need(sha(evidence/'bootstrap'/name)==proof[key]==hosted['bootstrap'][key],'original bootstrap proof channel hash differs')
    image=load(evidence/'bootstrap/image-inspect.json')
    token=hashlib.sha256((binding['source']+':'+binding['ref']+':'+binding['run']).encode()).hexdigest()[:24]
    need(image['Id']==binding['image'] and image['Architecture']=='arm64' and image['Os']=='linux' and image['Config']['Labels']['cachy-asahi.hosted-perl-lifecycle']==token and image['Config']['Labels']['cachy-asahi.hosted-perl-lifecycle.source']==binding['source'] and image['RepoTags']==['perl-lifecycle-native-base:'+token],'actual image Source ownership differs')


def review(binding,binding_sha,evidence,output):
    need(sha(binding)==binding_sha and not output.exists(),'external Root binding and fresh Reader output required')
    b=load(binding);need(b['scope']=='ROOT_AUTHENTICATED_PERL_INSTALLED_LIFECYCLE_DATA_READER_ONLY' and b['operation']=='perl5423-installed-lifecycle-native-v1','independent new-operation DATA Reader scope')
    c=module('lifecycle_reader_source_guards',ROOT/'hosted/common.py');c.verify_source(ROOT,b['source_map_sha256'])
    h=load(evidence/'hosted.json');original=load(evidence/'installed/producer-report.json')
    for key in ('source','ref','run','job','approval','source_map_sha256'):need(h['binding'][key]==b[key],'Root actual Source/ref/run/job/approval tuple differs')
    need(h['status']=='LIFECYCLE_PRODUCED_PENDING_INDEPENDENT_ROOT_REVIEW' and h['cleanup']['image_absent'] and h['cleanup']['gpg_agent_absent'] and not h['cleanup']['errors'],'whole hosted role/retirement incomplete')
    need(sha(evidence/'installed/producer-report.json')==b['producer_report_sha256'],'original producer report Root hash differs')
    readback=load(evidence/'source-readback.json');job=load(evidence/'job-metadata.json')
    need(readback['status']=='PASS_EXACT_HOSTED_SOURCE_READBACK' and all(readback['binding'][key]==b[key] for key in ('source','ref','run','approval','source_map_sha256')),'published Source readback join differs')
    need(job['total_count']==len(job['jobs'])==1 and str(job['jobs'][0]['id'])==b['job'] and str(job['jobs'][0]['run_id'])==b['run'] and job['jobs'][0]['head_sha']==b['source'] and job['jobs'][0]['name']=='perl5423-installed-lifecycle-native-v1','actual unique hosted job/source tuple differs')
    bootstrap_data(ROOT,evidence,b,h,c)
    contract=load(ROOT/'contract.json');need(h['capsule_source_map_sha256']==contract['capsule']['source_map_sha256'] and h['input_review_sha256']==contract['input_review_sha256'],'Root-reviewed capsule/input tuple differs')
    need(sha(evidence/'bootstrap/packages.lock')=='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453','actual signed349 baseline inventory')
    image=load(evidence/'image-qualification.json');need(image['image']==b['image'] and image['status']=='OBSERVED_FRESH_SIGNED349_IMAGE_MATCHES_ROOT_REVIEW_DATA' and image['removed'],'actual image qualification data incomplete')
    image_probe=module('lifecycle_reader_image_metadata',ROOT/'hosted/image_probe.py');image_probe.compare(image['metadata'],load(ROOT/'input-review.json')['image_expectations'])
    a=load(evidence/'inner-admission.json');q=load(evidence/'inner-qualification.json')
    need(a['image']==q['image']==b['image'] and a['source_map_sha256']==q['source_map_sha256']==contract['capsule']['source_map_sha256'] and a['root_qualification_sha256']==sha(evidence/'inner-qualification.json') and original['admission_sha256']==sha(evidence/'inner-admission.json'),'inner actual immutable image/qualification/admission joins')
    need(q['base_labels']==a['base_labels']==image['base_labels'],'actual reviewed inherited labels join')
    output.mkdir(mode=0o700)
    capsule_module=module('lifecycle_reader_capsule_data',ROOT/'hosted/capsule.py');capsule=capsule_module.materialize(ROOT,output)
    reader=module('held_pinned_readonly_result',capsule/'read_result.py')
    result=reader.review(SimpleNamespace(evidence=str(evidence/'installed'),inputs=str(capsule),source_map_sha256=contract['capsule']['source_map_sha256'],producer_report_sha256=b['producer_report_sha256']))
    result.update(outer_source=b['source'],outer_run=b['run'],outer_job=b['job'],outer_source_map_sha256=b['source_map_sha256'],image=b['image'],outer_scope='DATA_CONSISTENCY_ONLY_NOT_INSTALLATION_OR_RELEASE_ACCEPTANCE')
    (output/'hosted-reader.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('binding','evidence','output'):p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--binding-sha256',required=True);a=p.parse_args();print(json.dumps(review(a.binding,a.binding_sha256,a.evidence,a.output),sort_keys=True))
