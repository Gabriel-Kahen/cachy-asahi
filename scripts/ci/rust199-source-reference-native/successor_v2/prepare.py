#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Exact-parent work-volume successor DATA; never initializes or runs an actor."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource

HERE=Path(__file__).resolve().parent
FS_SHA='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
path=HERE.parent/'filesystem.py'
if hashlib.sha256(path.read_bytes()).hexdigest()!=FS_SHA:raise ValueError('frozen filesystem DATA helper changed')
spec=importlib.util.spec_from_file_location('rust_volume_source_fs',path);fs=importlib.util.module_from_spec(spec);spec.loader.exec_module(fs);fs.MAX_FILES=384
PARENT=dict(development_commit='0e89be82c192640f036adee2c52f93d6861219cf',files=277,bytes=40990238,tree='dd2a89e0ca31ca19819b8d70019013fe283446ef',map_sha256='0ddf2db2abec15b5298ecce7f6b085f447152e3fb904f915e56738a3a8e53b1b',profile_sha256='aa83d68e268f9f3dae0980d4a67cea8c53a1c3b11adc24c204445edd9663aed0')
ACTUAL=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
OPERATION='rust199-source-reference-native-v1'
LLVM_LESSON='724f6b74ebd7c42dfae1d607e28d81a734538b80'


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def replace(raw,old,new,count=1):
    fs.need(raw.count(old)==count,'exact reviewed literal seam: '+old.decode()[:120]);result=raw.replace(old,new)
    fs.need(result.replace(new,old)==raw,'whole literal inverse');return result


VOLUME_GATE=b'''    volume=load('rust199_work_volume',SOURCE/'hosted/volume.py',read(SOURCE/'hosted/volume.py'))
    volume_raw=read(INPUTS/'volume-admission.json',16384)
    need(pin(volume_raw)['sha256']==trust['WORK_VOLUME_ADMISSION_SHA256'],'exact separately bound work-volume admission')
    value=decode(volume_raw);binding=volume.binding(a['source'],a['image']['id'],trust['ROOT_ADMISSION_SHA256'])
    need(value==volume.admission(binding),'work volume joins actual Source/image/Root admission')
    initialized=decode(read(INPUTS/'volume-initialization.json',16384));volume.verify_receipt(initialized,binding)
    return a,n,phase,owned,volume,value,initialized'''
PREENTRY=b'''    observation=None
    if action in ('prepare','makepkg'):
        initial=WORK.lstat();initial_node=dict(device=initial.st_dev,inode=initial.st_ino,uid=initial.st_uid,gid=initial.st_gid,mode=stat.S_IMODE(initial.st_mode))
        print(json.dumps(dict(status='OBSERVED_WORK_ROOT_BEFORE_ENTRY',binding=value['binding'],actual=initial_node,uid=os.getuid(),gid=os.getgid(),phase=action),sort_keys=True),file=sys.stderr,flush=True)
        fd=os.open(WORK,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info=os.fstat(fd);actual=dict(device=info.st_dev,inode=info.st_ino,uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))
            need(stat.S_ISDIR(info.st_mode) and not WORK.is_symlink() and Path.cwd()==WORK and
                 (info.st_dev,info.st_ino)==(WORK.lstat().st_dev,WORK.lstat().st_ino),'same ordinary opened work root')
            need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1001,'actual nonroot outer entry')
            writable=os.access(WORK,os.W_OK|os.X_OK,effective_ids=True) and not os.statvfs(WORK).f_flag&os.ST_RDONLY
            empty=not os.listdir(fd)
            print(json.dumps(dict(status='OBSERVED_OPEN_WORK_ROOT_BEFORE_VERIFICATION',binding=value['binding'],actual=actual,uid=os.getuid(),gid=os.getgid(),writable=writable,empty=empty,phase=action),sort_keys=True),file=sys.stderr,flush=True)
            observation=volume.verify_work(value,initialized,actual,os.getuid(),os.getgid(),writable,empty,action)
        finally:os.close(fd)
    need(WORK.is_dir() and not WORK.is_symlink(),'ordinary owned work volume');OUT.mkdir(mode=0o700,exist_ok=True)'''


def actor_entry(raw):
    raw=replace(raw,b"TRUST=('ROOT_ADMISSION_SHA256','SOURCE_MAP_SHA256','CONTRACT_SHA256')",b"TRUST=('ROOT_ADMISSION_SHA256','SOURCE_MAP_SHA256','CONTRACT_SHA256','WORK_VOLUME_ADMISSION_SHA256')")
    raw=replace(raw,b'exact three inherited Root pins',b'exact four inherited Root and work-volume pins')
    raw=replace(raw,b"expected={'root-admission.json','actor-admission.json'}|",b"expected={'root-admission.json','actor-admission.json','volume-admission.json','volume-initialization.json'}|")
    raw=replace(raw,b'    return a,n,phase,owned',VOLUME_GATE)
    raw=replace(raw,b'a,n,phase,owned=gate(trust);',b'a,n,phase,owned,volume,value,initialized=gate(trust);')
    raw=replace(raw,b"    need(WORK.is_dir() and not WORK.is_symlink(),'ordinary owned work volume');OUT.mkdir(mode=0o700,exist_ok=True)",PREENTRY)
    raw=replace(raw,b"        if action=='prepare':prepare_layout(n)",b"        if observation is not None:result['work_preentry']=retain('work-preentry-'+action+'.json',encode(observation))\n        if action=='prepare':prepare_layout(n)")
    return raw


def parent(source):
    rows=fs.snapshot(source);raw,mode=rows['source-map.json']
    fs.need(mode==0o644 and fs.pin(raw)['sha256']==PARENT['map_sha256'] and len(rows)==PARENT['files'] and
            sum(len(raw) for raw,_ in rows.values())==PARENT['bytes'] and fs.tree(rows)==PARENT['tree'],'complete exact old277 Source DATA checkpoint')
    fs.need(fs.descriptors({n:v for n,v in rows.items() if n!='source-map.json'})==json.loads(raw)['files'],'exact parent Source map membership/bytes/modes');return rows


def render(before):
    fs.need(len(before)==PARENT['files'] and fs.tree(before)==PARENT['tree'],'exact retained parent only')
    files={n:v for n,v in before.items() if n!='source-map.json'}
    payload=fs.snapshot(HERE/'payload');fs.need(set(payload)=={'hosted/producer.py','hosted/volume.py'},'finite reviewed work-volume-only overlay')
    files.update(payload);files['actor/entry.py']=(actor_entry(before['actor/entry.py'][0]),before['actor/entry.py'][1])
    budget=dict(seconds=60,cpus=2,memory_bytes=128*1024**2,swap_bytes=0,pids=32,user='0:0',cap_add=['CHOWN'],recursive=False,additional_actors=0,additional_seconds=0)
    contract=json.loads(before['contract.json'][0]);contract['work_volume_initialization']=dict(revision=2,budget=budget,nocopy='ALL_WORK_VOLUME_REFERENCES',preentry='OUTER_PREPARE_EMPTY_AND_MAIN_NONEMPTY_SAME_INODE_OWNER_MODE_WRITABLE',original_candidate_and_stage0_unchanged=True)
    files['contract.json']=(encode(contract),before['contract.json'][1])
    audit=json.loads(before['builder-audit.json'][0]);audit['work_volume_initialization']=contract['work_volume_initialization'];audit['copy_up_cause']='UNPROVEN_OWNER_STATE_NOT_CAPTURED_IN_LLVM_V1'
    files['builder-audit.json']=(encode(audit),before['builder-audit.json'][1])
    workflow=before['.github/workflows/native-arm-build.yml'][0]
    anchor=b'            ${{ runner.temp }}/rust199-hosted/rust-build/producer.json\n'
    extra=b'            ${{ runner.temp }}/rust199-hosted/rust-build/volume-before.json\n            ${{ runner.temp }}/rust199-hosted/rust-build/volume-initialization.json\n'
    workflow=replace(workflow,anchor,anchor+extra)
    for n in ('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-rust199-source-reference-v1.yml'):files[n]=(workflow,before[n][1])
    protected={n:v for n,v in before.items() if n.startswith(('original/','packages/','stage0-intake/')) or n in ('candidate-map.json','actor/phase.py','recipe/PKGBUILD','recipe-derivation.json','policy.json','root-admission.TEMPLATE.json','admission.py','helpers/owned_child.py')}
    fs.need({n:files[n] for n in protected}==protected,'candidate/runtime/recipe/Root qualification/intake/licenses/resources preserved')
    changes={n:dict(before=fs.descriptors({n:before[n]})[n] if n in before else None,after=fs.descriptors({n:files[n]})[n]) for n in sorted(files) if before.get(n)!=files[n]}
    revision=dict(schema=1,revision=2,parent=PARENT,operation=OPERATION,llvm_work_volume_lesson_source=LLVM_LESSON,llvm_v1_run='43712154101',observed='builder /work/home PermissionError after initializer CLI0; actual owner state not captured',copy_up_cause='UNPROVEN',changes=changes,protected=fs.descriptors(protected),budget=budget,actual=ACTUAL)
    files['work-volume-revision.json']=(encode(revision),0o644)
    files['source-map.json']=(encode(dict(schema=1,operation=OPERATION,actual=ACTUAL,files=fs.descriptors(files))),0o644)
    fs.need(undo(files,before,revision)==before,'full old277 byte/mode/membership inverse')
    fs.need(len(files)<=384 and sum(len(raw) for raw,_ in files.values())<=96*1024**2,'finite Source successor DATA');return files


def undo(files,before,revision):
    restored=dict(files);restored.pop('source-map.json');restored.pop('work-volume-revision.json')
    for n,row in revision['changes'].items():
        fs.need(fs.descriptors({n:restored[n]})[n]==row['after'],'exact inverse changed operand')
        if n in before:
            fs.need(fs.descriptors({n:before[n]})[n]==row['before'],'exact inverse parent operand');restored[n]=before[n]
        else:restored.pop(n)
    restored['source-map.json']=before['source-map.json'];fs.need(restored==before and fs.tree(restored)==PARENT['tree'],'complete parent inverse');return restored


def inputs():
    rows={n:v for n,v in fs.snapshot(HERE).items() if n not in ('constructor-profile.json','validation.json')}
    return fs.descriptors(rows)


def construct(source,output,profile_sha):
    source,output=fs.absolute(source),fs.absolute(output);raw=fs.read(HERE/'constructor-profile.json')[0]
    fs.need(fs.pin(raw)['sha256']==profile_sha,'externally reviewed successor profile SHA required');p=json.loads(raw)
    fs.need(p['parent']==PARENT and p['actual']==ACTUAL and p['constructor_files']==inputs(),'complete successor constructor input closure')
    fs.need(not any(output.is_relative_to(n) or n.is_relative_to(output) for n in (source,HERE)),'fresh disjoint output')
    files=render(parent(source));fs.need(fs.tree(files)==p['tree'] and fs.pin(files['source-map.json'][0])['sha256']==p['map_sha256'],'exact reviewed prospective successor')
    fs.publish(files,output);return dict(status='CONSTRUCTED_SUCCESSOR_DATA_ONLY',files=len(files),bytes=sum(len(raw) for raw,_ in files.values()),tree=fs.tree(files),map=fs.pin(files['source-map.json'][0]),parent=PARENT,actual=ACTUAL,native='NOT_RUN')


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2);p=argparse.ArgumentParser(description=__doc__)
    for name in ('parent-source','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--profile-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.parent_source,a.output,a.profile_sha256),sort_keys=True))
