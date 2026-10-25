# SPDX-License-Identifier: MIT
"""Read-only public fixtures and exact source-owned presecret commands, never actors."""
import argparse,importlib.util,json,os,shlex,shutil,subprocess,sys,time
from pathlib import Path
D=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_gui682_portable',D/'prepare.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)
def run(a):
 q=F.inputs();source=F.canonical(a.source);F.need(F.table(F.files(source))==q['after']['known'],'whole682 controls source');work=F.canonical(a.workspace);F.need(not work.exists()and work.parent.is_dir(),'fresh CI workspace');work.mkdir(mode=0o700)
 root=work/'gui607-source';shutil.copytree(source,root);carrier=work/'apps16-inputs';carrier.mkdir(mode=0o700);selection=json.loads((root/'parent574/apps16-selection.json').read_bytes())['selection']
 F.need(selection['source']=='950b0699a6e3f7a56758d4d17a5d30dabc7b6e11'and len(selection['files'])==94,'exact accepted94 input role')
 for n,w in selection['files'].items():
  b=F.read(F.canonical(a.apps16)/n);F.need(F.pin(b)==w,'whole carrier94 input');p=carrier/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
 temp=work/'runner-temp';temp.mkdir(mode=0o700);original=root/'parent574/original';slice=original/'scripts/ci/welcome5-native-gui';sys.path.insert(0,str(slice));import assets,candidates
 # The original data assembler executes no recipe/native payload or Git command.
 assets.assemble_data(original,F.canonical(a.held)/'payload',F.canonical(a.project)/'payload',temp/'welcome5-assets',candidates.selection(original),F.canonical(a.renewal))
 raw=(root/'.github/workflows/native-arm-build.yml').read_text();scalar=next(x for x in raw.splitlines()if '"run":'in x and 'preflight\\n'in x);commands=json.loads(scalar.strip().split(': ',1)[1]).splitlines()
 expected=[['python3','-I','-B','$CURRENT','preflight'],['python3','-I','-B','gui607-source/implementation/presecret_control.py','--control','apps16-common','--apps16-inputs','$GITHUB_WORKSPACE/apps16-inputs'],['python3','-I','-B','gui607-source/parent574/service_controls.py'],['python3','-I','-B','$SLICE/test_lane.py'],['python3','-I','-B','gui607-source/parent574/original/scripts/ci/test_maintained_desktop574.py']]
 F.need([shlex.split(x)for x in commands]==expected and len(set(commands))==5,'all five decoded exact commands once')
 env=dict(os.environ,GITHUB_WORKSPACE=str(work),RUNNER_TEMP=str(temp),WELCOME5_GUI_ASSETS=str(temp/'welcome5-assets'),WELCOME5_GUI_SOURCE=str(original),PYTHONDONTWRITEBYTECODE='1');env.pop('WELCOME5_GUI_DEVELOPMENT',None)
 values={'$CURRENT':str(root/'implementation/native.py'),'$SLICE/test_lane.py':str(slice/'test_lane.py'),'$GITHUB_WORKSPACE/apps16-inputs':str(carrier)}
 current=[['-I','-B',str(root/'implementation/stage_inputs.py'),'--record',str(F.canonical(a.six_record)),'--output',str(temp/'six991-inputs')],['-I','-B',str(root/'implementation/test_observer.py'),'--assets',str(temp/'welcome5-assets')],['-I','-B','-Werror',str(root/'implementation/test_source.py'),'--record',str(F.canonical(a.six_record)),'--public',str(temp/'six991-inputs'),'--assets',str(temp/'welcome5-assets')]]
 def invoke(argv,ordinal,cap):
  began=time.monotonic();r=subprocess.run([sys.executable,*argv],cwd=work,env=env,capture_output=True,timeout=cap);(work/(ordinal+'.stdout')).write_bytes(r.stdout);(work/(ordinal+'.stderr')).write_bytes(r.stderr);F.need(r.returncode==0,'source control failed '+ordinal);return dict(ordinal=ordinal,seconds=time.monotonic()-began,exit=r.returncode)
 rows=[invoke(words,'current-'+str(i),180)for i,words in enumerate(current,1)];start=time.monotonic()
 for i,words in enumerate(expected,1):rows.append(invoke([values.get(x,x)for x in words[1:]],'original-'+str(i),180-(time.monotonic()-start)))
 F.need(F.table(F.files(root))==q['after']['known'],'whole682 unchanged after all original controls');result=dict(status='PASS_SOURCE_ONLY_EXACT682_AND_FIVE_PRESECRET_COMMANDS',commands=rows,original_cap_seconds=180,source_cap_seconds=300,actual=None,native='NOT_RUN',GUI='NOT_RUN',M2='NOT_RUN');(work/'result.json').write_bytes(F.enc(result));print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('source','workspace','apps16','held','project','renewal','six-record'):p.add_argument('--'+n,type=Path,required=True)
 run(p.parse_args())
