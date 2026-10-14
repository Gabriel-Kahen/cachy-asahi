# SPDX-License-Identifier: MIT
"""Recompute private library evidence from selected files; never launch an actor.

The parent supplies live custody and independently checks the borrowed lease,
child retirement and daemon state. JSON process observations alone grant none
of that authority. All package/static/source/comparison checks run in process.
"""
import os
from pathlib import Path
import re
import stat

import boundary
import owned_build

MAX_FILE=64*1024**2
REQUIRED_BUILD_FILES=frozenset(('build.log','validation.json','expected-packages.lock',
    'artifacts/packages.lock','artifacts/generated.SRCINFO','artifacts/environment.txt',
    'artifacts/config.sha256','artifacts/makepkg.conf','artifacts/pacman.conf'))


def need(value,reason):
    if not value:raise ValueError(reason)


def node(info):
    return [getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid',
        'st_size','st_mtime_ns','st_ctime_ns')]


class Reader:
    def __init__(self,record,custody):
        self.record,self.custody=record,custody;self.output=Path(record['output']['path']);self.total=0

    def raw(self,path,limit=8*1024**2,*,borrowed=False):
        path=Path(path);self.custody.guard()
        need(borrowed or path!=self.output and path.is_relative_to(self.output),'EVIDENCE_OUTPUT_SCOPE')
        raw=owned_build.read_regular(path,limit);self.total+=len(raw)
        need(self.total<=1024*1024**2,'EVIDENCE_TOTAL_CAP')
        self.custody.guard();return raw

    def json(self,path):return boundary.decode(self.raw(path))

    def ref(self,path,limit=8*1024**2,*,borrowed=False):
        path=Path(path);raw=self.raw(path,limit,borrowed=borrowed);info=path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size==len(raw),'EVIDENCE_FILE_CHANGED')
        value={'path':str(path),'sha256':owned_build.sha(raw),'bytes':len(raw),'identity':node(info)}
        # Internal downloaded/build archives have their own selected body cap.
        # Terminal evidence-group FileRefs keep the unchanged 8 MiB schema cap.
        boundary.path(value['path']);boundary.pin(value['sha256']);boundary.identity(value['identity'])
        need(type(limit)is int and 0<limit<=MAX_FILE and 0<=value['bytes']<=limit,'EVIDENCE_REFERENCE_CAP')
        if limit<=8*1024**2:boundary.file_ref(value)
        return value

    def expected(self,path,row,*,borrowed=False,limit=MAX_FILE):
        value=self.ref(path,limit,borrowed=borrowed)
        need(value['sha256']==row['sha256'] and value['bytes']==row['bytes'],'EVIDENCE_FILE_PIN')
        if 'identity'in row:need(value['identity']==row['identity'],'EVIDENCE_FILE_IDENTITY')
        return value


def contract_inputs(record):
    import operations
    contract=operations.selected_json(record,operations.CONTRACT,record['inputs']['contract_sha256'])
    need(contract.get('schema_version')==1 and contract.get('public_promotion')is False and
        set(contract.get('recipes',{}))=={'jbigkit','libtiff'} and len(contract.get('builder_extensions',[]))==5,
        'EVIDENCE_FIXED_CONTRACT')
    operations.selected_json(record,operations.PLAN,record['inputs']['materialization_plan_sha256'])
    for key,path in operations.INPUT_MAPS.items():
        actual=operations.selected_json(record,path,record['inputs'][key+'_inputs_sha256'])
        need(actual==contract['recipes'][key]['inputs'],'EVIDENCE_INPUT_MAP')
    return contract


def success_process(row):
    need(row.get('exit_code')==0 and type(row.get('exit_code'))is int and row.get('natural_exit')is True and
        row.get('reaped')is True and row.get('pidfd_owned')is True and row.get('first_failure')is None and
        row.get('uncertainty')==[],'EVIDENCE_PROCESS_NOT_COMPLETE')
    birth=row.get('birth');need(type(birth)is dict and set(birth)=={'pid','ppid','sid','start_ticks'} and
        all(type(v)is int and v>0 for v in birth.values()) and birth['sid']==birth['pid'],'EVIDENCE_PROCESS_BIRTH')


def actor_records(reader,record):
    import operations
    output=reader.output
    paths=list(output.glob('actor-command-*.json'))
    need(len(paths)==110 and {p.name for p in paths}=={'actor-command-'+str(n)+'.json' for n in range(1,111)},
        'EVIDENCE_ACTOR_RECEIPTS')
    result=[]
    for number in range(1,111):
        path=output/('actor-command-'+str(number)+'.json');row=reader.json(path)
        need(type(row)is dict and set(row)=={'exit_code','log_path','sha256','bytes','natural_exit','reaped','birth',
            'pidfd_owned','uncertainty','first_failure','command_id','fields','log_sha256','log_bytes'},'EVIDENCE_ACTOR_SCHEMA')
        success_process(row);operations.command(record,row['command_id'],row['fields'])
        log=reader.expected(row['log_path'],{'sha256':row['sha256'],'bytes':row['bytes']},limit=4*1024**2)
        need(row['log_sha256']==log['sha256'] and row['log_bytes']==log['bytes'],'EVIDENCE_ACTOR_LOG')
        result.append({'receipt':reader.ref(path),'record':row,'log':log})
    schedule=[row for row in operations.resource_schedule() if row['command']in owned_build.COMMAND_IDS]
    need([(r['record']['command_id'],r['record']['fields']['role']) for r in result]==
        [(r['command'],r['role']) for r in schedule],'EVIDENCE_ACTOR_ORDER')
    return result


def selected_actor(records,role,command):
    rows=[row for row in records if row['record']['fields']['role']==role and row['record']['command_id']==command]
    need(len(rows)==1,'EVIDENCE_SELECTED_ACTOR');return rows[0]


def check_extension(library,report,spec):
    meta=report['metadata']['.PKGINFO']
    need(report['errors']==[] and meta.get('pkgname')==[spec['name']] and meta.get('pkgver')==[spec['version']] and
        meta.get('arch')==['aarch64'] and sorted(meta.get('depend',[]))==sorted(spec['depends']) and
        sorted(meta.get('provides',[]))==sorted(spec['provides']) and '.INSTALL'not in report['members'] and
        all(row.get('machine')==183 and not row.get('errors') for row in report['elf'].values()),'EVIDENCE_EXTENSION_PACKAGE')


def collect(record,custody,*,producer_root=None):
    """Re-read/recompute the seven evidence groups, never use child PASS flags."""
    import operations
    reader=Reader(record,custody);contract=contract_inputs(record);oracles=operations.SelectedOracles(record,producer_root=producer_root)
    library=oracles.modules['project_libraries'];root=Path(record['sources']['root']);output=reader.output
    plan=operations.selected_json(record,operations.PLAN,record['inputs']['materialization_plan_sha256'])
    materialized={}
    for key,spec in contract['recipes'].items():
        directory=output/'materialized'/key
        need({p.name for p in directory.iterdir()}==set(spec['inputs']),'EVIDENCE_MATERIALIZED_COPYSET')
        materialized[key]={name:reader.expected(directory/name,{'sha256':pin,'bytes':(directory/name).lstat().st_size})
            for name,pin in spec['inputs'].items()}
        need(oracles.recipe(directory/'PKGBUILD')['input_sha256']==spec['inputs'],'EVIDENCE_MATERIALIZED_RECIPE')
    inputs={}
    fetches=[(key,row)for key,row in plan['upstream'].items()]
    for extension in contract['builder_extensions']:
        for field in ('archive','signature'):fetches.append((extension[field]['filename'],extension[field]))
    need(len(fetches)==14 and len({name for name,_ in fetches})==14,'EVIDENCE_FOURTEEN_INPUTS')
    for name,spec in fetches:
        path=output/('private-input-'+name);ref=reader.expected(path,spec,limit=32*1024**2)
        row=reader.json(output/('private-input-'+name+'.json'))
        need(row.get('url')==spec['url'] and row.get('status')==200 and row.get('bytes')==ref['bytes'] and
            row.get('sha256')==ref['sha256'],'EVIDENCE_FETCH_RECEIPT')
        inputs[name]={'file':ref,'receipt':reader.ref(output/('private-input-'+name+'.json'))}
    keyring=record['baseline']['cache']['archlinuxarm_keyring']
    reader.expected(keyring['path'],keyring,borrowed=True,limit=3098)
    armor=reader.raw(output/'baseline-cache/archlinuxarm.gpg',3098)
    need(owned_build.sha(armor)==keyring['sha256'],'EVIDENCE_BORROWED_KEYRING_COPY')
    binary=library.dearmor(armor)
    need(reader.raw(output/'private-public-keyring.gpg',3098)==binary,'EVIDENCE_DEARMORED_KEYRING')
    signatures={}
    for index,spec in enumerate(contract['builder_extensions']):
        need(spec['archive']['filename'].endswith(('.pkg.tar.xz','.pkg.tar.gz')),'EVIDENCE_EXTENSION_FORMAT')
        process=reader.json(output/('signature-process-'+str(index)+'.json'));success_process(process)
        log=reader.expected(process['log_path'],{'sha256':process['sha256'],'bytes':process['bytes']},limit=65536)
        accepted=library.signature_status(reader.raw(process['log_path'],65536).decode('utf-8'))
        package=oracles.package(output/('private-input-'+spec['archive']['filename']));check_extension(library,package,spec)
        saved=reader.json(output/('private-extension-'+spec['name']+'.json'))
        need(saved=={**accepted,'filename':spec['archive']['filename'],'sha256':spec['archive']['sha256'],
            'name':spec['name'],'version':spec['version'],'package_inspection':'PASS'},'EVIDENCE_EXTENSION_RECEIPT')
        signatures[spec['name']]={'accepted':accepted,'log':log,'process':reader.ref(output/('signature-process-'+str(index)+'.json')),
            'archive':inputs[spec['archive']['filename']]['file'],'signature':inputs[spec['signature']['filename']]['file'],
            'inspection_sha256':owned_build.sha(boundary.encoded(package))}
    records=actor_records(reader,record)
    lock_ref=reader.expected(record['baseline']['packages_lock']['path'],record['baseline']['packages_lock'],borrowed=True)
    lock=reader.raw(lock_ref['path'],borrowed=True).decode()
    wanted=library.expected_layer_lock(lock,contract['builder_extensions'])
    need(len(wanted.splitlines())==346 and owned_build.sha(wanted.encode())==boundary.DERIVED_LOCK and
        reader.raw(output/'private-layer-packages.lock')==wanted.encode(),'EVIDENCE_DERIVED_346')
    raw_journal=reader.raw(output/'resource-ledger.jsonl',boundary.RECORD_LIMIT)
    ledger=boundary.validate_journal(raw_journal,nonce=record['nonce'],baseline_id=record['baseline']['image_id'])
    need(set(ledger['roles'])==set(boundary.ROLES) and all(r['state']=='RETIRED'for r in ledger['roles'].values()),'EVIDENCE_ALL_ROLES_RETIRED')
    derived_id=ledger['roles']['layer-image']['identifier']
    need(len({ledger['roles'][role]['identifier']for role in boundary.BUILDS})==4 and
        all(row['image']==(derived_id if role.startswith(('libtiff-','probe-libtiff-'))or role in('layer-lock','layer-dependencies')
            else record['baseline']['image_id'])for role,row in ledger['roles'].items()),'EVIDENCE_ROLE_IMAGES')
    for actor in records:
        row=actor['record'];fields=row['fields'];role=fields['role'];resource=ledger['roles'][role]
        if row['command_id']=='image-commit':
            need(fields['identifier']==ledger['roles']['layer-provision']['identifier'] and fields['base']==record['baseline']['image_id'],
                'EVIDENCE_COMMIT_JOIN')
            need(reader.raw(actor['log']['path'],65536).decode('ascii').strip()==derived_id,'EVIDENCE_COMMITTED_IMAGE')
        elif row['command_id']=='container-create':
            need((fields['name'],fields['image'],fields['nonce'])==(resource['name'],resource['image'],record['nonce']),
                'EVIDENCE_CREATE_JOIN')
            need(reader.raw(actor['log']['path'],65536).decode('ascii').strip()==resource['identifier'],'EVIDENCE_CREATED_ID')
        else:need(fields['identifier']==resource['identifier'],'EVIDENCE_ACTOR_ID_JOIN')
        if row['command_id']=='container-start-attach'and role in boundary.BUILDS:
            key,number=role.rsplit('-',1)
            need(Path(actor['log']['path'])==output/(key+'-attempt-'+number)/'build.log','EVIDENCE_SINGLE_BUILD_LOG')
        if row['command_id']=='container-inspect':
            observed=reader.json(actor['log']['path']);labels=observed.get('Config',{}).get('Labels')or{}
            need(observed.get('Id')==resource['identifier'] and observed.get('Name')=='/'+resource['name'] and
                observed.get('Image')==resource['image'] and labels.get(owned_build.LABEL+'nonce')==record['nonce'] and
                labels.get(owned_build.LABEL+'role')==role,'EVIDENCE_CONTAINER_OWNER')
        if row['command_id']=='image-inspect':
            observed=reader.json(actor['log']['path']);labels=observed.get('Config',{}).get('Labels')or{}
            need(observed.get('Id')==derived_id and observed.get('Parent')==record['baseline']['image_id'] and
                observed.get('Os')=='linux' and observed.get('Architecture')=='arm64' and
                resource['name']+':latest'in(observed.get('RepoTags')or[]) and
                labels.get(owned_build.LABEL+'nonce')==record['nonce'] and labels.get(owned_build.LABEL+'role')=='layer-image' and
                labels.get(owned_build.LABEL+'base')==record['baseline']['image_id'],'EVIDENCE_IMAGE_OWNER')
        if row['command_id']in('container-absence','image-absence'):
            need(not reader.raw(actor['log']['path'],65536).strip(),'EVIDENCE_RESOURCE_ABSENCE')
        if row['command_id']=='container-wait':need(reader.raw(actor['log']['path'],65536).strip()==b'0','EVIDENCE_CONTAINER_WAIT')
    lock_actor=selected_actor(records,'layer-lock','container-start-attach')
    actual=reader.raw(lock_actor['log']['path']).decode()
    need(''.join(sorted(actual.splitlines(keepends=True)))==wanted,'EVIDENCE_OBSERVED_DERIVED_LOCK')
    selected_actor(records,'layer-dependencies','container-start-attach')
    attempts={};artifact_rows={};providers={};corresponding={};inspected={}
    for role in boundary.BUILDS:
        key,number=role.rsplit('-',1);spec=contract['recipes'][key];attempt=output/(key+'-attempt-'+number)
        provenance=reader.json(attempt/'provenance.json');files=provenance.get('files',{})
        need(type(files)is dict and REQUIRED_BUILD_FILES<=set(files) and len(files)<=80,'EVIDENCE_BUILD_FILES')
        for name,pin in files.items():
            boundary.relative(name);need(reader.ref(attempt/name,MAX_FILE)['sha256']==pin,'EVIDENCE_BUILD_FILE_PIN')
        image=record['baseline']['image_id']if key=='jbigkit'else derived_id
        expected_lock=lock if key=='jbigkit'else wanted
        need(provenance.get('status')=='built-package-static-pass' and provenance.get('mode')=='native' and
            provenance.get('image')==provenance.get('image_id')==image and provenance.get('recipe_inputs')==spec['inputs'] and
            provenance.get('source_date_epoch')==spec['epoch'] and
            provenance.get('expected_packages_sha256')==owned_build.sha(expected_lock.encode()) and
            provenance.get('clean_environment_id')==ledger['roles'][role]['identifier'],'EVIDENCE_BUILD_PROVENANCE')
        need(reader.raw(attempt/'expected-packages.lock')==reader.raw(attempt/'artifacts/packages.lock')==expected_lock.encode(),
            'EVIDENCE_ACTUAL_BUILD_LOCK')
        snapshot=attempt/'inputs';need({p.name for p in snapshot.iterdir()}==set(spec['inputs']),'EVIDENCE_SNAPSHOT_COPYSET')
        for name,pin in spec['inputs'].items():need(reader.ref(snapshot/name)['sha256']==pin,'EVIDENCE_SNAPSHOT_PIN')
        report=oracles.recipe(snapshot/'PKGBUILD');need(report['errors']==[]and report['input_sha256']==spec['inputs'],'EVIDENCE_RECIPE')
        need(provenance.get('recipe_metadata')==report['metadata'],'EVIDENCE_RECIPE_METADATA')
        original=reader.raw(root/'scripts/build/container-entry.sh',borrowed=True)
        entry=reader.raw(attempt/'owned-container-entry.sh')
        need(entry==owned_build.selected_entry(original) and provenance.get('entry_source_sha256')==owned_build.sha(original) and
            provenance.get('entry_script_sha256')==owned_build.sha(entry),'EVIDENCE_SELECTED_BUILD_ENTRY')
        oracles.bind_generated(report['metadata'],oracles.metadata(reader.raw(attempt/'artifacts/generated.SRCINFO').decode()))
        archives=list((attempt/'artifacts').glob('*.pkg.tar.*'));need(len(archives)==1,'EVIDENCE_ONE_PACKAGE')
        archive=archives[0];need(archive.name.endswith(('.pkg.tar.xz','.pkg.tar.gz')),'EVIDENCE_PACKAGE_FORMAT')
        archive_ref=reader.ref(archive,MAX_FILE);package=oracles.package(archive)
        need(package['errors']==[]and oracles.conflicts([package])==[]and
            oracles.bind_artifact(report['metadata'],package,spec['inputs']['PKGBUILD'])==[],'EVIDENCE_PACKAGE_ORACLE')
        validation=reader.json(attempt/'validation.json');need(validation=={'artifacts':[package],'errors':[]},'EVIDENCE_RECOMPUTED_VALIDATION')
        need(provenance.get('artifacts')=={archive.name:archive_ref['sha256']},'EVIDENCE_ARCHIVE_PIN')
        # Existing inspect retains metadata, 16K, provider and corresponding-Source gates.
        class PassiveInspection:
            deadline=record['cutoff_monotonic']
            def guard(self):custody.guard()
            def probe(self,archive_path,member,pin,soname,image):
                index=spec['library_sonames'].index(soname)+1
                actor=selected_actor(records,'probe-'+role+'-'+str(index),'container-start-attach')
                return library.dynamic_report(reader.raw(actor['log']['path'],65536).decode(),pin,soname)
        row=library.Operations.inspect(PassiveInspection(),key,int(number),spec,image,attempt/'expected-packages.lock',attempt)
        need(row['environment']==ledger['roles'][role]['identifier'],'EVIDENCE_ATTEMPT_CID')
        inspected[role]=row;attempts[role]={'container_id':row['environment'],'artifact_sha256':row['sha256'],
            'evidence':reader.ref(attempt/'provenance.json')}
        artifact_rows[role]={'archive':archive_ref,'provenance':attempts[role]['evidence'],'validation':reader.ref(attempt/'validation.json')}
        providers[role]=row['libraries'];corresponding[role]=row['corresponding_source_members']
    for role in ('libtiff-1','libtiff-2'):
        need('libjbig.so.2.2'in providers[role]['libtiff.so.6']['needed'] and
            'libtiff.so.6'in providers[role]['libtiffxx.so.6']['needed'],'EVIDENCE_PROVIDER_ASSOCIATION')
    comparisons={}
    for key in ('jbigkit','libtiff'):
        library.checked_pair(inspected[key+'-1'],inspected[key+'-2'])
        value=oracles.modules['compare'].compare(output/(key+'-attempt-1'),output/(key+'-attempt-2'))
        gates=value.get('packages',{}).get(inspected[key+'-1']['filename'],{})
        need(value.get('status')=='contents-reproduced' and value.get('errors')==[]and
            all(gates.get(k)is True for k in boundary.GATES),'EVIDENCE_FULL_COMPARISON')
        path=output/(key+'-comparison.json');need(reader.json(path)==value,'EVIDENCE_RECOMPUTED_COMPARISON')
        comparisons[key]={**{k:gates[k]for k in boundary.GATES},'evidence':reader.ref(path)}
    derived={'image_id':derived_id,'packages':346,'lock_sha256':boundary.DERIVED_LOCK,'dependency_check':True,
        'evidence':reader.ref(output/'private-layer-packages.lock')}
    groups={'source_inputs':{'manifest_sha256':record['sources']['manifest_sha256'],'inputs':record['inputs'],
                'materialized':materialized,'downloads':inputs},
        'tool_runtime':{'runtime':record['runtime'],'actor_receipts':[row['receipt']for row in records]},
        'baseline':{'lease':record['baseline'],'packages_lock':lock_ref},'artifacts':artifact_rows,
        'signatures':signatures,'providers':providers,'corresponding_sources':corresponding}
    return {'attempts':attempts,'comparisons':comparisons,'derived':derived},groups


def assemble(record,custody):
    """Child writes bounded records only after recomputing the actual business gates."""
    values,groups=collect(record,custody);reader=Reader(record,custody);refs={}
    for name in boundary.PRIVATE_CHECKS:
        path=reader.output/('evidence-'+name+'.json')
        owned_build.save(path,{'schema_version':1,'kind':name,'records':groups[name]});refs[name]=reader.ref(path)
        boundary.output_ref(refs[name],record)
    return {**values,'evidence':refs}


def verify_business(record,custody,child,*,producer_root=None):
    """Parent replays pure checks and rehashes retained files, independent of flags."""
    need(type(child)is dict,'EVIDENCE_CHILD_REQUIRED')
    values,groups=collect(record,custody,producer_root=producer_root);reader=Reader(record,custody);refs={}
    for name in boundary.PRIVATE_CHECKS:
        path=reader.output/('evidence-'+name+'.json')
        need(reader.json(path)=={'schema_version':1,'kind':name,'records':groups[name]},'EVIDENCE_RECOMPUTED_GROUP')
        refs[name]=reader.ref(path);boundary.output_ref(refs[name],record)
    values['evidence']=refs
    need(all(boundary.encoded(child.get(key))==boundary.encoded(value)for key,value in values.items()),'EVIDENCE_TERMINAL_BINDING')
    custody.guard();return values
