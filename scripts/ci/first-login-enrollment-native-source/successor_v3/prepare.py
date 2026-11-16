#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Construct closed current Source DATA from committed code and pinned public tar."""
import argparse
import ast
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('current_v3_common',HERE/'common.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
BASIS='df2efcb6013dcf75c7d5fefe025525d98b8db647'
PROFILE=dict(bytes=21679,sha256='8ad3641649e395b1202363e3368f713f65252a743b12e3a8d69430e4f82bc171')
BASELINE=dict(bytes=6800,sha256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453')
OFFICIAL={'fuse-common','fuse3','gobject-introspection-runtime','graphene','gssdp','gst-plugins-bad-libs','gst-plugins-base-libs',
'gstreamer','gtk4','gupnp','gupnp-igd','libgirepository','libnice','liburing','libva','libxv','numactl','orc','python-gobject',
'vmaf','vulkan-icd-loader','xdg-desktop-portal','xdg-desktop-portal-gtk'}
LOCAL=('common.py','dispatch.py','prepare.py','README.md','owner-closure.TEMPLATE.json')


def git(repo,*args,cap=C.MAX_FILE):
    result=subprocess.run(['/usr/bin/git','--no-replace-objects','--literal-pathspecs','-c','core.hooksPath=/dev/null',
                           '-c','gc.auto=0','-c','maintenance.auto=false','-C',str(repo),*args],
                          stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,
                          env={'PATH':'/usr/bin:/bin','HOME':str(repo),'LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1',
                               'GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_REPLACE_OBJECTS':'1','GIT_OPTIONAL_LOCKS':'0'})
    C.need(result.returncode==0 and len(result.stdout)<=cap,'bounded committed Git DATA operation')
    return result.stdout


def commit(repo,revision):
    C.need(re.fullmatch('[0-9a-f]{40}',revision or ''),'full exact committed Git identity required')
    C.need(git(repo,'cat-file','-t',revision,cap=16)==b'commit\n','actual commit object, never uncommitted worktree')


def blob(repo,revision,name,expected=None):
    C.relative(name)
    raw=git(repo,'ls-tree','-z',revision,'--',name,cap=1024)
    C.need(raw.endswith(b'\0') and raw.count(b'\0')==1,'exact committed closure leaf exists')
    metadata,actual=raw[:-1].split(b'\t');mode,kind,oid=metadata.decode().split(' ')
    C.need(actual.decode()==name and mode in ('100644','100755') and kind=='blob','ordinary committed closure blob/mode')
    body=git(repo,'cat-file','blob',oid)
    value=(body,0o644 if mode=='100644'else 0o755)
    if expected is not None:C.need(dict(C.pin(body),mode=value[1])==expected,'exact committed closure body/mode pin: '+name)
    return value


def metadata(raw):
    rows={}
    for line in raw.decode().splitlines():
        if ' = ' in line:
            name,value=line.strip().split(' = ',1);rows.setdefault(name,[]).append(value)
    return rows


def basis(repo):
    commit(repo,BASIS);raw,mode=blob(repo,BASIS,C.FAMILY+'/successor_v2/profile.json')
    C.need(C.pin(raw)==PROFILE and mode==0o644,'exact current-v2 reviewed profile')
    profile=C.decode(raw);C.need(profile['operation']==C.OPERATION and all(v is None for v in profile['actual'].values()),'unissued exact basis')
    files={}
    for kind,row in profile['packages'].items():
        for name,pin in row['files'].items():
            path=row['path']+'/'+name;files[path]=blob(repo,BASIS,path,pin)
        md=metadata(files[row['path']+'/.SRCINFO'][0])
        C.need(md['pkgname']==[row['name']] and md['pkgver'][0]+'-'+md['pkgrel'][0]==row['version'] and md['arch']==['any'],
               'exact current recipe metadata')
        for source,sha in zip(md.get('source',[]),md.get('sha256sums',[])):
            C.need('://'not in source and '/'not in source and row['files'][source]['sha256']==sha,'exact local recipe source/SHA')
        C.need(len(md.get('source',[]))==len(md.get('sha256sums',[])),'complete local recipe SHA list')
        files['reviewed/'+kind+'.json']=(C.encoded({n:p['sha256']for n,p in row['files'].items()}),0o644)
    C.need(sum(len(row['files'])for row in profile['packages'].values())==42,'complete held42 recipe leaves')
    for name,row in profile['helpers'].items():files[name]=blob(repo,BASIS,name,row)
    for name,row in profile['prior_factory'].items():
        path=C.FAMILY+'/'+name;files[path]=blob(repo,BASIS,path,row)
    for name in ('prepare.py','native.py','profile.json','inputs.TEMPLATE.json'):
        path=C.FAMILY+'/successor_v2/'+name;files[path]=blob(repo,BASIS,path)
    C.need(len(files)==58,'exact original current-v2 Source closure')
    old_lock=C.encoded(dict(schema=1,kind=profile['kind'],operation=profile['operation'],files=C.descriptors(files),actual=profile['actual']))
    baseline,_=blob(repo,BASIS,C.FAMILY+'/fixtures/expected349.lock')
    C.need(C.pin(baseline)==BASELINE,'exact held349 expected inventory')
    C.inventory(baseline,349)
    return files,profile,old_lock,baseline


def owner_closure(repo,raw):
    value=C.decode(raw)
    C.need(set(value)=={'schema','kind','commit','api','operation','owner','route','files'} and value['schema']==1
           and value['kind']=='CURRENT_ONBOARDING_COMMITTED_OWNER_ROUTE_CLOSURE_V3' and value['api']==C.API
           and value['operation']==C.OPERATION,'explicit whole-reviewed committed owner/route closure')
    revision=value['commit'];commit(repo,revision);rows=value['files']
    C.need(type(rows)is dict and 2<=len(rows)<=96 and value['owner']!=value['route']
           and {value['owner'],value['route']}<=set(rows),'real closed owner and route inputs, never NULL hook')
    C.need(all(not name.startswith((C.PREFIX+'/', 'carrier/', 'provenance/', 'inputs/')) and name not in ('source-map.json','source.lock.json')for name in rows),'owner closure cannot occupy generated Source slots')
    files={name:blob(repo,revision,name,row)for name,row in rows.items()}
    C.need(all(len(files[name][0])<=128*1024 for name in (value['owner'],value['route'])),'existing operational code cap')
    for name,entry in ((value['owner'],'open_current_session'),(value['owner'],'launch_lifecycle'),(value['route'],'run_registered')):
        node=ast.parse(files[name][0]);C.need(any(isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef))and item.name==entry for item in node.body),
                                           'committed callback API missing: '+entry)
    C.need(any(isinstance(item,ast.FunctionDef)and item.name=='admission'for item in ast.parse(files[value['route']][0]).body),'committed route admission API missing')
    return value,files


def carrier(raw,manifest):
    value=C.decode(manifest);C.need(value['kind']=='DATA_ONLY_NO_SOURCE_FREEZE' and value['operation']==C.OPERATION,'explicit bridge carrier manifest')
    C.need(all(value[k]is None for k in ('source','source_lock','owner_hook','operation_registry','resources','runtime','official_trust','current_stage_TEST_verification','publication')),'carrier draft carries no future Root/runtime/grant selectors')
    rows=value['materials'];C.need(type(rows)is list and len(rows)==59,'exact59-member public carrier')
    names={};roles={}
    for row in rows:
        name=C.relative(row['member']);role=row['role'];pin=row['source']
        C.need(name not in names and role not in roles and row['mode']==0o644 and type(pin['bytes'])is int and 0<pin['bytes']<=16*1024**2
               and re.fullmatch('[0-9a-f]{64}',pin['sha256']),'exact unique bounded carrier member/role/pin')
        names[name]=row;roles[role]=name
    wanted={'official/'+name+'/'+kind for name in OFFICIAL for kind in ('archive','signature')}
    wanted|={'Setup8/archive','Setup8/current_signature','Setup8/current_public_key','Setup8/current_verification','Setup8/current_decision',
             'expected/backend','expected/ui','expected/lifecycle','official/exact_closure','official/archive_signature_inputs',
             'prospective/inputs','expected/stage_vectors','prospective/signed_lifecycle'}
    C.need(set(roles)==wanted and len(raw)<=32*1024**2,'closed exact public role set and whole carrier cap')
    found={};offset=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as archive:
        for member in archive:
            name=member.name;C.need(name in names and name not in found and member.offset==offset
                                  and member.isfile() and member.type in (tarfile.REGTYPE,tarfile.AREGTYPE)
                                  and member.mode==0o644 and member.uid==member.gid==0 and not member.pax_headers
                                  and raw[member.offset+257:member.offset+265]==b'ustar\x0000','ordinary closed contiguous USTAR carrier')
            expected=names[name]['source'];C.need(member.size==expected['bytes'],'carrier member length')
            body=archive.extractfile(member).read(16*1024**2+1)
            C.need(C.pin(body)=={k:expected[k]for k in ('bytes','sha256')},'whole carrier member hash')
            C.need(not re.search(br'-----BEGIN (?:PGP PRIVATE KEY BLOCK|[A-Z0-9 ]*PRIVATE KEY)-----',body),'public carrier refuses private key markers')
            offset=member.offset_data+((member.size+511)//512)*512
            C.need(not any(raw[member.offset_data+member.size:offset]),'zero ordinary member padding')
            found[name]=(body,0o644)
    C.need(set(found)==set(names) and len(raw)-offset>=1024 and not any(raw[offset:]),'complete59-member carrier with zero EOF only')
    return found,roles,value


def join_inputs(materials,roles,profile,baseline):
    body=lambda role:materials[roles[role]][0]
    catalog=C.decode(body('official/exact_closure'));selected=catalog['selected']
    C.need(set(selected)==OFFICIAL and catalog['addition_count']==23 and catalog['expected_final_official_count']==372
           and all(not catalog[k]for k in ('unresolved','ambiguous','conflicts','ordering_comparisons_pending','conflict_ordering_pending')),
           'exact current23 runtime closure without baseline upgrade')
    C.need(catalog['Root_acceptance']is catalog['Root_current_official_signature_admission']is None,'official current trust remains external and NULL')
    base=C.inventory(baseline,349);official={name:row['version']for name,row in selected.items()}
    C.need(not set(base)&set(official),'no baseline version replacement')
    vectors=dict(backend=dict(base,**{'cachy-asahi-setup':'0.3.0-1'}),
                 ui=dict(base,**official,**{'cachy-asahi-setup':'0.3.0-1','cachy-asahi-first-login':'0.1.0-3'}),lifecycle=dict(base,**official))
    for stage,count in C.STAGES.items():C.need(C.inventory(body('expected/'+stage),count)==vectors[stage],'exact typed stage inventory')
    inputs=C.decode(body('prospective/inputs'))
    for name in ('source','source_date_epoch','Root_admission','Root_capacity','builder_image','builder_inventory','ui_builder_image',
                 'ui_builder_inventory','image_namespace_qualification','matching_Reader'):C.need(inputs[name]is None,'future runtime/admission remains NULL')
    C.need(inputs['official_ui_dependencies']['verification']is None and inputs['setup8']['current_TEST_signature_verification']is None
           and all(inputs['first_login_backend'][name]is None for name in ('native_pair','archive','signature','current_TEST_signature_verification')),
           'no invented current trust/backend verification')
    C.need(C.pin(body('Setup8/archive'))==profile['setup8']['archive_pin'],'unchanged genuine native Setup8 dependency archive')
    table_doc=C.decode(body('official/archive_signature_inputs'));table=table_doc['packages']
    C.need(table_doc['Root_current_official_trust']is table_doc['Root_current_verification']is None and set(table)==OFFICIAL,'same exact unadmitted official input vector')
    for name,row in selected.items():
        C.need(table[name]['version']==row['version'] and table[name]['arch']==row['arch'] and table[name]['filename']==row['filename'],'same official metadata epoch/arch/filename')
        for kind in ('archive','signature'):
            actual=C.pin(body('official/'+name+'/'+kind))
            C.need(actual==row[kind]=={k:table[name][kind][k]for k in ('bytes','sha256')},'same official archive/signature whole pins')
    proof=C.decode(body('Setup8/current_verification'));decision=C.decode(body('Setup8/current_decision'))
    key=proof['public_test_key'];sig=C.pin(body('Setup8/current_signature'));archive=profile['setup8']['archive_pin']
    C.need(proof['Root_issuer']=='Root' and proof['status']=='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE' and proof['verified']is True
           and proof['archive']==archive and proof['signature']==sig and proof['trust_scope']=='TEST_ONLY'
           and {k:key[k]for k in ('bytes','sha256')}==C.pin(body('Setup8/current_public_key')) and key['trust_scope']=='TEST_ONLY', 'scoped genuine public Setup8 proof joins unchanged input bodies')
    C.need(decision['issuer']=='Root' and decision['accepted']is decision['holds_preserved']is True
           and decision['status']=='ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY' and decision['signature']==sig
           and decision['public_test_key']==key and decision['verification_proof_sha256']==C.pin(body('Setup8/current_verification'))['sha256']
           and decision['archive']==dict(archive,package='cachy-asahi-setup',version='0.3.0-1',arch='any'),'same exact limited Root Setup8 TEST decision')
    expected_vectors=C.decode(body('expected/stage_vectors'))
    C.need(all(v is None for v in expected_vectors['future'].values()) and expected_vectors['actual_images']is None
           and expected_vectors['installed_inventory_observations']is None,'expected vectors cannot manufacture runtime observations')
    signed=C.decode(body('prospective/signed_lifecycle'))
    C.need(signed['common_TEST_fingerprint']is None and signed['Root_admission']is None and signed['runtime']is None
           and signed['official_trust']is None and signed['installed_inventory_observations']is None and signed['expected_inventory_counts']==[372,373,376,373,376,373,372], 'unissued exact current lifecycle operands')
    for kind,row in {'setup8':profile['setup8'],**profile['packages']}.items():
        actual=signed['signed'][kind]
        C.need((actual['name'],actual['version'],actual['payload_files'])==(row['name'],row['version'],row['payload_files']), 'all source-bound current payload leaves')
        if kind!='setup8':C.need(all(actual[k]is None for k in ('archive','signature','archive_pin','signature_pin')),'future current native artifacts NULL')
    return vectors


def assemble(repo,closure_raw,carrier_raw,manifest_raw):
    files,profile,old_lock,baseline=basis(repo)
    closure,code=owner_closure(repo,closure_raw)
    materials,roles,manifest=carrier(carrier_raw,manifest_raw)
    join_inputs(materials,roles,profile,baseline)
    for name,value in code.items():C.need(name not in files or files[name]==value,'committed owner cannot replace held recipe/helper body');files[name]=value
    files['provenance/current-v2-source.lock.json']=(old_lock,0o644)
    files['provenance/owner-closure.json']=(closure_raw,0o644)
    files['provenance/public-carrier-manifest.json']=(manifest_raw,0o644)
    files['inputs/public-carrier.tar']=(carrier_raw,0o644)
    for name,value in materials.items():files['carrier/'+name]=value
    files['inputs/stages/baseline349.expected.lock']=(baseline,0o644)
    inventories={}
    for stage,count in C.STAGES.items():
        raw=materials[roles['expected/'+stage]][0];files['inputs/stages/'+stage+'.expected.lock']=(raw,0o644)
        inventories[stage]=dict(C.pin(raw),packages=count)
    for name in LOCAL:files[C.PREFIX+'/'+name]=C.read(HERE/name)
    material_map={role:dict(path='carrier/'+name,**C.pin(materials[name][0]))for role,name in roles.items()}
    files['inputs/materials.json']=(C.encoded(dict(schema=1,kind='PUBLIC_SOURCE_RELATIVE_INPUTS_V3',roles=material_map,
        official_trust=None,current_stage_TEST_verification=None,resources=None,runtime=None,publication=None,Root_admission=None)),0o644)
    program=dict(schema=1,kind='CURRENT_ONBOARDING_COMMITTED_OWNER_PROGRAM_V3',operation=C.OPERATION,api=C.API,
        entrypoint='open_current_session',lifecycle_entrypoint='launch_lifecycle',owner=dict(path=closure['owner'],**C.pin(code[closure['owner']][0])),
        route=dict(path=closure['route'],**C.pin(code[closure['route']][0])),closure_commit=closure['commit'],closure=C.descriptors(code),
        registry=dict(path=C.PREFIX+'/dispatch.py',**C.pin(files[C.PREFIX+'/dispatch.py'][0])),expected_inventories=inventories,
        materials=material_map,delegated_basis=dict(commit=BASIS,files=59,source_lock=C.pin(old_lock),profile=PROFILE),
        actual=dict.fromkeys(('Root_trust','Root_resources','Root_runtime','Root_signing','actual_images','dispatch_grant','publication')))
    files[C.PREFIX+'/owner-program.json']=(C.encoded(program),0o644)
    files[C.PREFIX+'/operation-registry.json']=(C.encoded(dict(schema=3,operations={C.OPERATION:dict(api=C.API,callback='open_current_session',lifecycle_callback='launch_lifecycle',
        owner=program['owner'],route=program['route'],entry=program['registry'])},actual_Root_admission=None)),0o644)
    value=dict(schema=1,kind=C.KIND,operation=C.OPERATION,files=C.descriptors(files),
        actual=dict.fromkeys(('source','ref','run','job','artifact','Root_trust','Root_resources','Root_runtime','Root_signing','actual_images','dispatch_grant','publication')))
    raw=C.encoded(value);files['source-map.json']=(raw,0o644);files['source.lock.json']=(raw,0o644)
    C.need(len(files)<=C.MAX_FILES and sum(len(v[0])for v in files.values())<=C.MAX_TOTAL
           and all(len(v[0])<=C.MAX_FILE for v in files.values()),'unchanged complete Source caps')
    return files,dict(status='CLOSED_CURRENT_SOURCE_DATA_RUNTIME_UNQUALIFIED',files=len(files),bytes=sum(len(v[0])for v in files.values()),
                     source_map=C.pin(raw),source_lock=C.pin(raw),owner_program=C.pin(files[C.PREFIX+'/owner-program.json'][0]),
                     committed_owner=closure['commit'],actual=value['actual'])


def publish(files,output):
    C.need(output.is_absolute() and output==output.resolve() and output.parent.is_dir() and not output.exists()
           and output.parent.stat().st_uid==os.getuid() and not output.parent.stat().st_mode&0o022,'fresh owned output required')
    # mkdir is the no-replace publication boundary; every input is checked first.
    output.mkdir(mode=0o700)
    for name,(raw,mode)in files.items():
        path=output/C.relative(name);path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
        with os.fdopen(fd,'wb')as stream:stream.write(raw);os.fchmod(stream.fileno(),mode)
    C.source(output,C.pin(files['source-map.json'][0])['sha256'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('repo','owner-closure','carrier','carrier-manifest','output'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('owner-closure-sha256','carrier-sha256','carrier-manifest-sha256'):p.add_argument('--'+name,required=True)
    a=p.parse_args();C.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__,'isolated unoptimized DATA constructor')
    raw=lambda path,sha,cap:C.read(path,dict(bytes=path.stat().st_size,sha256=sha),cap=cap)[0]
    closure=raw(a.owner_closure,a.owner_closure_sha256,1024**2)
    public=raw(a.carrier,a.carrier_sha256,32*1024**2)
    manifest=raw(a.carrier_manifest,a.carrier_manifest_sha256,1024**2)
    files,result=assemble(a.repo,closure,public,manifest);publish(files,a.output);print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':
    try:main()
    except (ValueError,KeyError,TypeError,OSError,tarfile.TarError,subprocess.SubprocessError)as error:raise SystemExit('REFUSED: '+str(error))
