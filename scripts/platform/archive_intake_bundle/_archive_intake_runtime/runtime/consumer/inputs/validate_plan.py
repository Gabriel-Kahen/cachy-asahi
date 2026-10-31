#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Data-only assembly plan validation. No builder, target, package or network API."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

LIMITS=dict(manifest_bytes=2*1024**2,package_count=261,evidence_count=16,requirements_count=12,config_bytes=65536)
INDEX_SHA='874b7406955baf36c455f8b0a9eeaddbfc0636506e757d3e98ff5ca6b97569a2'
REQUIREMENTS={'build-environment','dependency-install-order','hooks-and-sysusers','package-signature-facts',
              'package-source-license-closure','remaining-config-transforms','filesystem-determinism',
              'esp-platform-artifacts','installer-source-closure','target-firmware-and-stage1','release-output-bindings',
              'resolver-link-and-service'}
ACCEPTANCE={'package_payload','installed_configuration','reproducible_image','image_issuer','key_owner',
            'license_redistribution','installation','recovery','hardware'}
HEX=re.compile(r'[0-9a-f]{64}\Z')


def need(value,code):
    if not value:raise ValueError(code)


def closed(value,fields,code):need(type(value) is dict and set(value)==set(fields),code)


def text(value,maximum=4096):
    return type(value) is str and 0<len(value)<=maximum and not re.search(r'[\x00-\x1f\x7f]',value)


def number(value,maximum,minimum=0):return type(value) is int and minimum<=value<=maximum


def digest(value):return type(value) is str and HEX.fullmatch(value) is not None


def reference(value):
    closed(value,('path','sha256','bytes'),'evidence-schema')
    need(text(value['path']) and not value['path'].startswith('/') and
         all(part not in ('','.','..') for part in value['path'].split('/')) and
         digest(value['sha256']) and number(value['bytes'],8*1024**2,1),'evidence-value')


def decode(raw):
    def pairs(items):
        result={}
        for key,value in items:need(key not in result,'duplicate-json-key');result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite-json'))
    need(type(value) is dict,'manifest-object');return value


def read_json(path,expected,maximum):
    need(digest(expected),'external-manifest-pin');path=Path(path);before=path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=maximum,'manifest-file')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        held=os.fstat(stream.fileno());need(held==before,'manifest-identity')
        raw=stream.read(maximum+1)
        need(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==expected,'manifest-hash')
        need(os.fstat(stream.fileno())==before==path.lstat(),'manifest-drift')
    return decode(raw)


def render_fstab(root_uuid,efi_uuid):
    need(type(root_uuid) is str and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',root_uuid) and
         type(efi_uuid) is str and re.fullmatch(r'[0-9A-F]{4}-[0-9A-F]{4}',efi_uuid),'filesystem-uuid')
    return (f'UUID={root_uuid} / ext4 rw,relatime,x-systemd.growfs 0 1\n'
            f'UUID={efi_uuid} /boot/efi vfat rw,relatime,fmask=0022,dmask=0022,codepage=437,'
            'iocharset=iso8859-1,shortname=mixed,errors=remount-ro    0 2\n').encode()


def file_metadata(row):
    closed(row,('type','mode','uid','gid','bytes','sha256'),'config-metadata-schema')
    need(row['type']=='file' and number(row['mode'],0o7777) and number(row['uid'],2**32-1) and
         number(row['gid'],2**32-1) and number(row['bytes'],LIMITS['config_bytes']) and digest(row['sha256']),'config-metadata')


def validate(value,inventory,fstab,index):
    fields={'schema_version','scope','assembly_authorized','base_strategy','opaque_image_used_as_build_input',
            'selected_inventory_sha256','packages','input_evidence','reference_builder','historical_image','filesystem',
            'boot','layers','fstab_transform','resolver_transform','upstream_transform_inventory','requirements','acceptance','limits'}
    closed(value,fields,'assembly-plan-schema')
    need(type(value['schema_version']) is int and value['schema_version']==1 and
         value['scope']=='PRIVATE_PROJECT_IMAGE_ASSEMBLY_PLAN_V1' and value['assembly_authorized'] is False and
         value['base_strategy']=='EXACT_PACKAGES_IN_NEW_EMPTY_STAGING' and
         value['opaque_image_used_as_build_input'] is False,'assembly-scope-or-opaque-reuse')
    need(type(value['limits']) is dict and value['limits']==LIMITS and all(type(n) is int for n in value['limits'].values()),'plan-limits')
    need(type(value['acceptance']) is dict and set(value['acceptance'])==ACCEPTANCE and
         all(flag is False for flag in value['acceptance'].values()),'acceptance-promotion')
    evidence=value['input_evidence'];need(type(evidence) is dict and 0<len(evidence)<=16,'input-evidence-bound')
    for name,row in evidence.items():need(text(name,128),'input-evidence-name');reference(row)
    need('image-inventory.json' in evidence and value['selected_inventory_sha256']==evidence['image-inventory.json']['sha256'] and
         value['selected_inventory_sha256']=='5c1630b5cdf07898118979895682c3a3b705e416c9840ada4e1a5193dccd6941','canonical-inventory-binding')
    expected={row['metadata']['NAME'][0]:dict(name=row['metadata']['NAME'][0],version=row['metadata']['VERSION'][0],arch=row['metadata']['ARCH'][0])
              for row in inventory['packages']}
    need(len(expected)==261 and 'linux-asahi' in expected,'canonical-package-inventory')
    closed(index,('schema_version','selected_inventory_sha256','metadata_only_not_archive_authentication','sources','packages'),'reference-index-schema')
    need(type(index['schema_version']) is int and index['schema_version']==1 and
         index['selected_inventory_sha256']==value['selected_inventory_sha256'] and
         index['metadata_only_not_archive_authentication'] is True and type(index['sources']) is dict and
         index['sources']=={name:evidence[name]['sha256'] for name in ('image-inventory.json','baseline-258-proposal.json','python-supplement.json')},'reference-index-source-binding')
    need(type(index['packages']) is list and len(index['packages'])==261,'reference-index-count')
    indexed={}
    for row in index['packages']:
        closed(row,('identity','archive'),'reference-index-row');identity=row['identity'];closed(identity,('name','version','arch'),'reference-index-identity')
        need(type(identity['name']) is str and identity['name'] in expected and identity==expected[identity['name']] and
             identity['name'] not in indexed,'reference-index-tuple');indexed[identity['name']]=row
    need(set(indexed)==set(expected),'reference-index-closure')
    packages=value['packages'];need(type(packages) is list and len(packages)==261,'package-count')
    seen=set();missing=[];available=0
    for row in packages:
        closed(row,('identity','archive','evidence_kind','owner','missing_action'),'package-row-schema')
        identity=row['identity'];closed(identity,('name','version','arch'),'package-identity')
        need(all(text(part,256) for part in identity.values()) and identity['name'] in expected and
             identity==expected[identity['name']] and identity['name'] not in seen,'package-tuple-closure')
        seen.add(identity['name']);need(text(row['owner'],64) and row['evidence_kind']=='RETAINED_JSON_METADATA_NOT_FRESH_ARCHIVE_HASH','package-owner-evidence')
        need(row['archive']==indexed[identity['name']]['archive'],'archive-metadata-index-binding')
        archive=row['archive']
        if archive is None:
            need(text(row['missing_action'],1024),'missing-package-action');missing.append('package:'+identity['name'])
        else:
            closed(archive,('path','size','sha256'),'archive-reference-schema')
            need(text(archive['path']) and Path(archive['path']).is_absolute() and '..' not in Path(archive['path']).parts and
                 number(archive['size'],300_000_000,1) and digest(archive['sha256']) and row['missing_action'] is None,'archive-reference')
            available+=1
    need(seen==set(expected),'package-set-closure')
    builder=value['reference_builder'];closed(builder,('repository','commit','historical_zip_source_digest_bound','execute_upstream_builder'),'builder-reference')
    need(builder['repository']=='https://github.com/asahi-alarm/asahi-alarm-builder' and
         builder['commit']=='58cc158c7fda3ef6aeae36606f84a63b4b0867e7' and
         builder['historical_zip_source_digest_bound'] is False and builder['execute_upstream_builder'] is False,'builder-authority')
    historical=value['historical_image'];closed(historical,('sha256','zip_sha256','reproduction_accepted'),'historical-image-schema')
    need(digest(historical['sha256']) and digest(historical['zip_sha256']) and historical['reproduction_accepted'] is False,'historical-image-not-reproduction')
    fs=value['filesystem'];closed(fs,('type','root_uuid','efi_fat_uuid','efi_volume_id','root_image_bytes','root_partition_bytes','maximum_root_image_bytes'),'filesystem-schema')
    need(fs['type']=='ext4' and fs['maximum_root_image_bytes']==4*1024**3 and type(fs['maximum_root_image_bytes']) is int and
         fs['root_uuid']=='725346d2-f127-47bc-b464-9dd46155e8d6' and fs['efi_fat_uuid']=='2ABF-9F91' and
         fs['efi_volume_id']=='0x2abf9f91','filesystem-installer-coherence')
    need(render_fstab(fs['root_uuid'],fs['efi_fat_uuid'])==fstab,'fstab-source-render')
    for key in ('root_image_bytes','root_partition_bytes'):
        if fs[key] is None:missing.append('layout:'+key)
        else:need(number(fs[key],16*1024**3,4096) and fs[key]%4096==0,'layout-size-alignment')
    if fs['root_image_bytes'] is not None:
        need(fs['root_image_bytes']<=fs['maximum_root_image_bytes'],'root-image-cap')
        if fs['root_partition_bytes'] is not None:need(fs['root_partition_bytes']>=fs['root_image_bytes'],'root-partition-capacity')
    boot=value['boot'];closed(boot,('method','kernel','per_install_esp_gpt_uuid','machine_id','firmware_manifest','pc_nvram_or_partition_assumptions'),'boot-schema')
    need(boot['method']=='ASAHI_STUB_STAGE1_TO_INTERNAL_ESP_STAGE2_ARM64_EFI' and boot['kernel']=='linux-asahi' and
         boot['pc_nvram_or_partition_assumptions'] is False,'asahi-platform-preservation')
    for key in ('per_install_esp_gpt_uuid','machine_id','firmware_manifest'):
        if boot[key] is None:missing.append('target:'+key)
        else:
            if key=='per_install_esp_gpt_uuid':need(type(boot[key]) is str and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot[key]),'esp-gpt-identity')
            elif key=='machine_id':need(boot[key] in ('Mac14,2','Mac14,15'),'supported-target-identity')
            else:reference(boot[key])
    layers=value['layers'];closed(layers,('package_payload','installed_configuration','existing_install','silent_mismatch_exceptions'),'layer-schema')
    need(layers==dict(package_payload='COMPARE_PRISTINE_ARCHIVE_OWNED_TREE_BEFORE_CONFIG',installed_configuration='EXACT_SOURCE_BOUND_TRANSFORMS_ON_FRESH_STAGING_ONLY',
                     existing_install='PRESERVE_USER_FILES_AND_REFUSE_UNEXPECTED_PRIOR_HASH',silent_mismatch_exceptions=False) and
         layers['silent_mismatch_exceptions'] is False,'payload-config-or-preservation')
    transform=value['fstab_transform'];closed(transform,('path','package','before','after','template','recipe','metadata_policy','apply_to','existing_user_config_overwrite','historical_image_attribution'),'fstab-transform-schema')
    file_metadata(transform['before']);file_metadata(transform['after']);reference(transform['template'])
    need(transform['path']=='etc/fstab' and transform['package']=='filesystem' and
         transform['before']==dict(type='file',mode=420,uid=0,gid=0,bytes=126,sha256='e54626e74ed8fee4173b62a545ab1c3a3a069e4217a0ee8fc398d9933e9c1696') and
         transform['after']==dict(type='file',mode=420,uid=0,gid=0,bytes=len(fstab),sha256=hashlib.sha256(fstab).hexdigest()) and
         transform['template']==dict(path='config/fstab.ext4.txt',bytes=len(fstab),sha256=hashlib.sha256(fstab).hexdigest()),'fstab-before-after-binding')
    recipe=transform['recipe'];closed(recipe,('commit','git_blob_sha1','lines','path','sha256','url'),'fstab-recipe-schema')
    need(recipe==dict(commit=builder['commit'],git_blob_sha1='fc2dc386a226a3590ac5cabc92eea69af5a5b88d',lines=[9,13],
         path='scripts/base/20-fstab.sh',sha256='3d0f0b6ffaee802b0cf41efe57ca96c9e85387e72773b2566eadc12693a1131f',
         url='https://raw.githubusercontent.com/asahi-alarm/asahi-alarm-builder/'+builder['commit']+'/scripts/base/20-fstab.sh') and
         all(type(line) is int for line in recipe['lines']),'fstab-recipe-binding')
    need(transform['metadata_policy']=='PROJECT_PROPOSAL_PRESERVE_PRISTINE_PACKAGE_METADATA_NOT_UPSTREAM_MODE_PROOF' and
         transform['apply_to']=='NEW_EMPTY_STAGING_AFTER_PRISTINE_CHECK' and transform['existing_user_config_overwrite'] is False and
         transform['historical_image_attribution'] is False,'fstab-preservation-or-attribution')
    resolver=value['resolver_transform'];closed(resolver,('path','package','before','source_record','expected_link_target','service_policy','owner','status','current_link_followed','historical_cause_accepted'),'resolver-transform-schema')
    need(resolver['path']=='etc/resolv.conf' and resolver['package']=='filesystem' and text(resolver['owner'],64) and
         resolver['current_link_followed'] is False and resolver['historical_cause_accepted'] is False,'resolver-source-or-attribution')
    file_metadata(resolver['before'])
    need(resolver['before']==dict(type='file',mode=420,uid=0,gid=0,bytes=65,sha256='5557d8e601b17a80d1ea7de78a9869be69637cb6a02fbfe334e22fdf64e61d4c'),'resolver-pristine-binding')
    if resolver['status']=='MISSING_SOURCE_TARGET_SERVICE':
        need(all(resolver[key] is None for key in ('source_record','expected_link_target','service_policy')),'resolver-unknown-target')
        missing.append('resolver:source-target-service')
    else:
        need(resolver['status']=='SOURCE_RECORD_SUPPLIED' and text(resolver['expected_link_target'],4096),'resolver-recipe-state')
        reference(resolver['source_record']);closed(resolver['service_policy'],('unit','behavior'),'resolver-service-policy')
        need(text(resolver['service_policy']['unit'],128) and resolver['service_policy']['unit'].endswith('.service') and
             text(resolver['service_policy']['behavior'],1024),'resolver-service-semantics')
    reference(value['upstream_transform_inventory'])
    need(value['upstream_transform_inventory']['sha256']=='543061fb699ed41e9f004ad8dd1a55e65ed40f18e15905c0337270da737d71ba','transform-inventory-binding')
    requirements=value['requirements'];need(type(requirements) is list and len(requirements)==12,'requirements-count');ids=set()
    for row in requirements:
        closed(row,('id','owner','status','evidence','action'),'requirement-schema')
        need(row['id'] in REQUIREMENTS and row['id'] not in ids and text(row['owner'],64) and text(row['action'],2048),'requirement-owner-action');ids.add(row['id'])
        if row['status']=='MISSING':need(row['evidence'] is None,'missing-requirement-evidence');missing.append(row['id'])
        else:need(row['status']=='SOURCE_RECORD_SUPPLIED','requirement-state');reference(row['evidence'])
    need(ids==REQUIREMENTS,'requirements-closure')
    return dict(schema_version=1,status='PLAN_VALID_BLOCKED_MISSING_INPUTS' if missing else 'PLAN_VALID_FOR_REVIEW_NOT_AUTHORIZED',
                missing_inputs=sorted(missing),required_packages=261,retained_archive_metadata=available,
                config_candidates=1,assembly_executed=False,assembly_authorized=False,acceptance=value['acceptance'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--manifest',required=True);parser.add_argument('--manifest-sha256',required=True)
    args=parser.parse_args();plan=read_json(args.manifest,args.manifest_sha256,LIMITS['manifest_bytes']);base=Path(args.manifest).absolute().parent
    inv=plan['input_evidence']['image-inventory.json'];reference(inv)
    inventory=read_json(base/inv['path'],inv['sha256'],1024**2)
    index=read_json(base/'inputs/package-reference-index.json',INDEX_SHA,LIMITS['manifest_bytes'])
    template=plan['fstab_transform']['template'];reference(template);path=base/template['path']
    need(path.is_file() and not path.is_symlink() and path.stat().st_size<=LIMITS['config_bytes'],'fstab-template-file')
    raw=path.read_bytes();need(len(raw)==template['bytes'] and hashlib.sha256(raw).hexdigest()==template['sha256'],'fstab-template-hash')
    print(json.dumps(validate(plan,inventory,raw,index),sort_keys=True))


if __name__=='__main__':main()
