#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Root-invoked baseline observation DATA checks; no future mutation authority."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path,PurePosixPath

ROOT=Path(__file__).resolve().parents[1]

def need(ok,why):
    if not ok:raise ValueError(why)


def sha(path):
    return hashlib.sha256(guards.read(path,64*1024**2)).hexdigest()


def load(path,cap=16*1024**2):
    return guards.decode(guards.read(path,cap),cap)


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);__import__('sys').modules[name]=value;spec.loader.exec_module(value);return value


guards=module('baseline_reader_bounded_data',ROOT/'hosted/common.py')


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
        need(cache.name=='alarm-cache' and cache.is_absolute() and '..' not in cache.parts and argv==['gpg','--batch','--no-options','--homedir',str(temp/'perl-baseline-observation/bootstrap/gpg'),'--no-auto-key-retrieve','--status-fd','1','--verify',str(cache/(name+'.sig')),str(cache/name)],'exact frozen public GPG verification command differs')
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
    need(image['Id']==binding['image'] and image['Architecture']=='arm64' and image['Os']=='linux' and image['Config']['Labels']['cachy-asahi.hosted-perl-baseline']==token and image['Config']['Labels']['cachy-asahi.hosted-perl-baseline.source']==binding['source'] and image['RepoTags']==['perl-baseline-native-base:'+token],'actual image Source ownership differs')

def review(binding,binding_sha,evidence,output):
    need(sha(binding)==binding_sha and not output.exists(),'external Root binding digest and fresh DATA output')
    b=load(binding);need(b['scope']=='ROOT_AUTHENTICATED_PERL_BASELINE_OBSERVATION_DATA_READER_ONLY' and b['operation']=='perl5423-baseline-observation-native-v1','independent observation-only Root DATA scope')
    c=module('perl_baseline_reader_source',ROOT/'hosted/common.py');c.verify_source(ROOT,b['source_map_sha256'])
    h=load(evidence/'hosted.json')
    for key in ('source','ref','run','job','approval','source_map_sha256'):need(h['binding'][key]==b[key],'actual externally authenticated Source/ref/run/job/admission differs')
    need(h['status']=='BASELINE_OBSERVATION_PRODUCED_PENDING_ROOT_REVIEW' and h['qualification']=='NOT_ISSUED_FOR_LATER_MUTATION' and h['cleanup']['image_absent'] and h['cleanup']['observer_container_absent'] and h['cleanup']['gpg_agent_absent'] and not h['cleanup']['errors'] and h['cleanup'].get('bootstrap_inventory_recovered') is False,'complete natural observation and owned retirement required')
    readback=load(evidence/'source-readback.json');job=load(evidence/'job-metadata.json')
    need(readback['status']=='PASS_EXACT_HOSTED_SOURCE_READBACK' and all(readback['binding'][key]==b[key] for key in ('source','ref','run','approval','source_map_sha256')),'published Source readback differs')
    need(job['total_count']==len(job['jobs'])==1 and str(job['jobs'][0]['id'])==b['job'] and str(job['jobs'][0]['run_id'])==b['run'] and job['jobs'][0]['head_sha']==b['source'] and job['jobs'][0]['name']=='perl5423-baseline-observation-native-v1','actual provider job binding differs')
    need(sha(evidence/'bootstrap/packages.lock')=='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453','actual signed349 complete lock')
    bootstrap_data(ROOT,evidence,b,h,c)
    raw=c.read(evidence/'observation.json',32*1024**2)
    need(c.pin(raw)==h['observation']['observation'] and c.pin(raw)['sha256']==b['observation_sha256'],'externally pinned original observation bytes differ')
    observed=c.decode(raw,32*1024**2);observer=module('perl_baseline_reader_observer',ROOT/'hosted/observer.py');observer.validate(observed)
    contract=load(ROOT/'contract.json');declared=load(evidence/'observation-binding.json')
    expected={key:b[key] for key in ('source','ref','run','job','image')}
    token=hashlib.sha256((b['source']+':'+b['ref']+':'+b['run']).encode()).hexdigest()[:24]
    expected.update(token=token,policy_sha256=contract['observer_policy_sha256'])
    need(observed['binding']==declared==h['observation']['binding']==expected,'original observation Source/image/token/fixed-policy tuple differs')
    domain=load(evidence/'observer-domain.json');entry=module('perl_baseline_reader_domain',ROOT/'hosted/entry.py')
    need(domain['natural_exit'] and domain['container_absent'] and not domain['forced_stop'],'natural observer retirement and absence required')
    image=load(evidence/'bootstrap/image-inspect.json')
    need(domain['image_labels']==image['Config']['Labels'],'exact baseline image label set differs')
    for stage in ('before','after'):entry.inspect_observer(domain[stage],Path(domain[stage]['Mounts'][0]['Source']),b['image'],b,domain['image_labels'])
    need(domain['before']['Mounts']==domain['after']['Mounts'] and domain['after']['State']['Status']=='exited' and domain['after']['State']['ExitCode']==0 and not domain['after']['State']['OOMKilled'],'original observer domain/exit changed')
    operations=load(evidence/'bootstrap/operations.json');name=entry.owner(b)['name']
    selected=[row for row in operations if row['argv']==entry.DOCKER+['start','--attach',name]]
    need(len(selected)==1 and entry._natural(selected[0]['lifecycle']) and selected[0]['returncode']==selected[0]['lifecycle']['exit']==0,'one naturally completed original observer command')
    for row in operations:
        need(entry._natural(row['lifecycle']) and row['returncode']==row['lifecycle']['exit'],'all original hosted CLI ownership/retirement must be known')
        for channel in ('stdout','stderr'):
            relative=PurePosixPath(row[channel]);need(not relative.is_absolute() and '..' not in relative.parts,'contained original channel path')
            body=c.read(evidence/relative,32*1024**2)
            need(c.pin(body)==row[channel+'_pin'],'original hosted channel hash differs')
    need(c.read(evidence/selected[0]['stdout'],32*1024**2)==raw,'original observer stdout differs')
    output.mkdir(mode=0o700)
    result=dict(schema=1,status='PASS_BASELINE_OBSERVATION_DATA_PARITY_ONLY',source=b['source'],run=b['run'],job=b['job'],image=b['image'],observation=c.pin(raw),scope='ROOT_REVIEW_INPUT_ONLY; NO_LATER_IMAGE_MUTATION_QUALIFICATION',holds_preserved=True)
    (output/'reader.json').write_bytes(c.encode(result));return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('binding','evidence','output'):parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--binding-sha256',required=True);args=parser.parse_args()
    print(json.dumps(review(args.binding,args.binding_sha256,args.evidence,args.output),sort_keys=True))
