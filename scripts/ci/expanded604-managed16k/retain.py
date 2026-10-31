# SPDX-License-Identifier: MIT
"""Replay the actual24 frame contract and retain only bounded public evidence."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import os
import textwrap
import subprocess
import contract as C
CAP=128*1024**2
VIEWS=('home','terminal-action','files-action','system','first-steps','updates','recovery','management-absent','management-doctor','management-orphans','management-failure','management-closing')
FRAMES=tuple(stage+'-'+view for stage in ('minimal','overlay') for view in VIEWS)


def retain(output,producer,runtime,runner,kernel,source):
    public=output/'public';public.mkdir(mode=0o700);rows={};spent=0;errors=[]
    def copy(path,name,cap,required=False):
        nonlocal spent
        if not path.exists():C.need(not required,'missing public evidence: '+name);return
        raw=C.read(path,cap);spent+=len(raw);C.need(spent<=CAP,'original128MiB public bound')
        target=public/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        rows[name]=dict(bytes=len(raw),sha256=C.sha(raw))
    for name in ('result.json','owner.json','generated-runner.json','controller.log'):copy(output/name,name,16*1024**2)
    for name in ('producer.json','producer-cleanup.json'):copy(producer/'public'/name,'producer/'+name,4*1024**2)
    for name,cap in (('runtime.json',16*1024**2),('events.log',8*1024**2),('guest.log',8*1024**2),('elf16k.json',16*1024**2),('fixture/installed604-capture.json',65536),('configuration.log',16*1024**2),('fixture.log',16*1024**2),('runtime-image.log',16*1024**2)):
        copy(runtime/name,'runtime/'+name,cap,required=name in ('runtime.json','events.log','elf16k.json'))
    for name in ('candidate-lock.json','adapter.json','context604.json','kernel-profile.json'):copy(runner/name,'runner/'+name,4*1024**2)
    for name in ('build-receipt.json','build/.config'):copy(kernel/'helper/built'/name,'kernel/'+Path(name).name,262144)
    owner=C.json_read(output/'result.json',16*1024**2)
    try:
        C.need(owner['status']==C.FINAL and owner['cleanup']=='PASS' and owner['producer_cleanup']['status']=='PASS','ordered owner result required')
        raw=C.json_read(runtime/'runtime.json',16*1024**2);lock=C.json_read(runner/'candidate-lock.json')
        C.need(raw['status']==C.PASS and raw['runtime_package_count']==604 and raw['workflow_scope']=='installed604-welcome2-management-generic16k','actual604 runtime identity required')
        C.need(owner['controller']['natural_exit'] is True and owner['controller']['group_absent'] is True and owner['controller']['exit']==0,'natural retired controller required')
        loader=C.load(source,'scripts/ci/managed-gui-generic16k/ci/caller.py')
        # Preparation imports the source594 modules. Replay in a fresh isolated interpreter
        # so those parent caches can never substitute for the generated604 contracts.
        code="""import json,sys
from pathlib import Path
runner,runtime=map(Path,sys.argv[1:]);sys.path.insert(0,str(runner))
import contract
raw=json.loads((runtime/'runtime.json').read_bytes());lock=json.loads((runner/'candidate-lock.json').read_bytes())
value=contract.verify_result(raw['events'],lock)
assert value==raw['gui_contract'],'raw actual GUI replay differs'
print(json.dumps(value,sort_keys=True))
"""
        replay=subprocess.run([sys.executable,'-I','-B','-c',code,str(runner),str(runtime)],capture_output=True,timeout=20,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
        C.need(replay.returncode==0 and len(replay.stdout)<=4*1024**2 and len(replay.stderr)<=65536,'isolated original GUI methods replay refused: '+replay.stderr[-512:].decode(errors='replace'))
        observed=json.loads(replay.stdout);C.need(observed==raw['gui_contract'],'raw original GUI methods replay differs')
        C.need(len(raw['frames'])==24 and set(raw['frames'])==set(FRAMES),'exact24 real frames required')
        for name in FRAMES:
            path=runtime/'frames'/(name+'.ppm');fact=loader.frame(path)
            C.need(fact['sha256']==raw['frames'][name]['sha256'],'QMP pixels/runtime hash differ');copy(path,'frames/'+name+'.ppm',8*1024**2,True)
        elf=C.json_read(runtime/'elf16k.json',16*1024**2)
        C.need(elf['status']=='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT' and C.sha(C.read(runtime/'elf16k.json'))==raw['elf16k']['sha256'] and len(elf['ELF'])==raw['elf16k']['ELFs'] and
            {'usr/bin/cachy-asahi-welcome','usr/bin/python3.14','usr/lib/systemd/systemd','usr/local/bin/gbm-probe','usr/local/bin/welcome-a11y'}<={r['path'] for r in elf['ELF']},'complete installed604 ELF view absent')
        C.need(observed['diagnostic_kernel']==owner['diagnostic_kernel'] and owner['diagnostic_kernel']['page_size']==16384,'exact parsed16384 kernel boot/build join absent')
        acquisition=Path(os.environ['RUNNER_TEMP'])/'managed-gui16k-acquisition.json'
        seed=Path(os.environ['RUNNER_TEMP'])/'managed-gui16k-kernel-source-seed.json'
        copy(acquisition,'kernel/acquisition.json',16384,True);copy(seed,'kernel/retained-source-seed.json',16384)
        # Execute the unchanged accepted build/config/acquisition/retained-asset guards.
        text=C.read(source/'scripts/ci/managed-gui-generic16k/ci/caller.py').decode()
        first="        built=report['kernel_build'];cfg=report['kernel_config'].encode()"
        last="        elf=read_json(runtime/'elf16k.json')"
        C.need(text.count(first)==text.count(last)==1,'original kernel/acquisition check block differs')
        block=textwrap.dedent(first+text.split(first)[1].split(last)[0])
        exec(compile(block,'<held-kernel-custody-guards>','exec'),dict(report=owner,kernel=owner['diagnostic_kernel'],
             read_json=C.json_read,need=C.need,hashlib=hashlib,acquisition=acquisition,seed=seed))

        capture=C.json_read(runtime/'fixture/installed604-capture.json',65536)
        final=next(e['receipt'] for e in raw['events'] if e.get('event')=='installed604_preserved')
        C.need(capture['status']=='PASS_COMPLETE_ACTUAL604_CAPTURE' and final['status']=='PASS_COMPLETE_ACTUAL604_VERIFY' and all(capture[k]==final[k] for k in ('packages','nodes','payload_bytes','snapshot_sha256')),'complete actual604 fixture/guest payload/DB join absent')
    except BaseException as error:errors.append(type(error).__name__+': '+str(error)[:512])
    C.save(public/'retention.json',dict(schema_version=1,status='RETAINED_ACTUAL604_GUI_METADATA_PIXELS_PENDING_REVIEW' if not errors else 'NOT_ACCEPTED',files=rows,bytes=spent,errors=errors,scope=C.SCOPE,hardware='NOT_RUN',visual_review='NOT_RUN',release='NOT_ADMITTED'))
    C.need(not errors,'passive604 metadata replay refused: '+'; '.join(errors));return public
