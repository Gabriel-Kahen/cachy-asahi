#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only actual workflow shell/whole-retainer/upload-path regression."""
import importlib.util,json,os,runpy,secrets,shlex,shutil,subprocess,sys,tempfile,zipfile
from pathlib import Path

def need(ok,why):
    if not ok:raise ValueError(why)

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def check(source,workflow,case):
    source=Path(source).absolute();value=json.loads((source/workflow).read_bytes())
    steps=value['jobs']['native']['steps']
    retain=[s for s in steps if 'native4k-source/retain.py' in s.get('run','')]
    upload=[s for s in steps if s.get('uses','').startswith('actions/upload-artifact@')]
    need(len(retain)==len(upload)==1,'one actual retainer and upload')
    run=secrets.randbelow(10**15)+1;proof=dict(run=run,attempt=1,case=case)
    kind='copy4k' if case=='normal' else 'recovery4k'
    owner=Path('/tmp')/f'cachy-asahi-updater604-{kind}-{run}-1-{case}'
    owner.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);workspace=root/'workspace';workspace.mkdir()
            runner=root/'runner';runner.mkdir()
            original=json.loads((source/'profile.json').read_bytes())
            need(original['page_size']==4096,'fixed native4K source policy')
            current=load('_retention_path_control_case',source/'case.py')
            saved=sys.modules.get('case');sys.modules['case']=current
            try:retainer=load('_retention_path_whole_body',source/'retain.py')
            finally:
                if saved is None:sys.modules.pop('case',None)
                else:sys.modules['case']=saved
            for name in retainer.ROLES:
                path=owner/name;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(b'{"source_control":"DATA_ONLY_NOT_ACCEPTANCE"}\n')
            (runner/f'updater604-{kind}-cleanup.json').write_bytes(b'{"inert_cleanup":"DATA_ONLY"}\n')
            command=retain[0]['run'].replace('${{ inputs.source }}','1'*40).replace('${{ github.sha }}','1'*40).replace('${{ inputs.case }}',case)
            prefix='python3 -I -B "$GITHUB_WORKSPACE/native4k-source/retain.py"'
            need(command.count(prefix)==1,'exact original retainer invocation')
            command=command.replace(prefix,shlex.quote(sys.executable)+' -I -B '+shlex.quote(str(Path(__file__).resolve()))+' --retainer '+shlex.quote(str(source/'retain.py')),1)
            env=dict(PATH='/usr/bin:/bin',GITHUB_WORKSPACE=str(workspace),RUNNER_TEMP=str(runner),GITHUB_RUN_ID=str(run),GITHUB_RUN_ATTEMPT='1',RETAINER_CONTROL_PROOF=json.dumps(proof))
            result=subprocess.run(['/bin/bash','-c',command],capture_output=True,env=env,timeout=15)
            need(result.returncode==0,'whole retainer control failed: '+result.stderr.decode())
            receipt=json.loads(result.stdout);target=Path(upload[0]['with']['path'].replace('${{ runner.temp }}',str(runner)))
            actual=runner/f'updater604-{kind}-evidence/evidence.zip'
            need(receipt['missing']==[] and receipt['files']==11 and actual.is_file(),'complete original eleven retained roles')
            need(receipt['archive']==current.pin(actual.read_bytes()),'complete actual retained archive pin')
            with zipfile.ZipFile(actual) as archive:
                need(archive.testzip() is None and len(archive.infolist())==11,'whole ZIP CRC/roles')
                data=json.loads(archive.read('retention.json'))
                need(data['wrapper']==proof and data['missing']==[],'same fixed source-control owner context')
            need(target==actual and target.is_file(),'actual retainer output and upload path differ')
            return dict(status='PASS_SOURCE_ONLY_RETENTION_UPLOAD_PATH',files=11,case=case,actual_acceptance=False)
    finally:shutil.rmtree(owner)

if __name__=='__main__':
    need(len(sys.argv)>2 and sys.argv[1]=='--retainer','control-only whole retainer entry')
    path=Path(sys.argv[2]);sys.argv=[str(path),*sys.argv[3:]]
    C=load('case',path.parent/'case.py');sys.modules['case']=C
    proof=json.loads(os.environ['RETAINER_CONTROL_PROOF']);C.authenticate=lambda *a,**k:proof
    runpy.run_path(str(path),run_name='__main__')
