# SPDX-License-Identifier: MIT
"""Read-only public fixtures and exact source-owned presecret commands, never actors."""
import argparse,importlib.util,json,os,shlex,shutil,subprocess,sys,time
from pathlib import Path
from unittest import mock
D=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_gui682_portable',D/'prepare.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)

# These immutable public TEST signatures expired after their source-fixture week.
# Reproduce that historical DATA time only in this source-only CI adapter;
# runtime Source bytes/expiry predicates and monotonic deadlines stay unchanged.
def fixture_time(renewal):
 raw=F.read(renewal/'index.json')
 F.need(F.pin(raw)=={'bytes':69418,'sha256':'e705cc670d11cd188c971a36953dd76941a6f4c706eb9b64ddd131dd55a4898e'},'exact historical TEST source-fixture index')
 value=json.loads(raw)
 F.need(type(value['created'])is int and type(value['expires'])is int and value['expires']-value['created']==604800,'seven-day historical source-fixture window')
 return value['created']+1

def fixture_argv(argv,now,root,files):
 index=next(i for i,word in enumerate(argv)if not word.startswith('-'))
 F.need(argv[:index]in(['-I','-B'],['-I','-B','-Werror'])and now==1792457345,'fixed source-only Python flags/time')
 script=Path(argv[index]);script=script if script.is_absolute()else root.parent/script
 F.need(script==script.resolve()and script.is_relative_to(root),'owned historical source script required')
 name=script.relative_to(root).as_posix()
 F.need(name in ('implementation/stage_inputs.py', 'implementation/test_runner_context.py', 'implementation/test_observer.py', 'implementation/test_source.py', 'implementation/native.py', 'implementation/presecret_control.py', 'parent574/service_controls.py', 'parent574/original/scripts/ci/welcome5-native-gui/test_lane.py', 'parent574/original/scripts/ci/test_maintained_desktop574.py') and F.pin(F.read(script))==files.get(name),'exact presecret source-script role/hash')
 arguments=argv[index+1:];layout={'implementation/stage_inputs.py': ('--record', None, '--output', None), 'implementation/test_observer.py': ('--assets', None), 'implementation/test_source.py': ('--record', None, '--public', None, '--assets', None), 'implementation/native.py': ('preflight',), 'implementation/presecret_control.py': ('--control', 'apps16-common', '--apps16-inputs', None), 'parent574/service_controls.py': (), 'parent574/original/scripts/ci/welcome5-native-gui/test_lane.py': (), 'parent574/original/scripts/ci/test_maintained_desktop574.py': (), 'implementation/test_runner_context.py': ('--assets', None)}.get(name)
 F.need(layout is not None and len(arguments)==len(layout)and all(w is None or w==a for w,a in zip(layout,arguments)),'fixed presecret script arguments')
 launcher="""import hashlib,sys,time,types
from pathlib import Path
now=float(sys.argv[1]);expected=sys.argv[2];sys.argv=sys.argv[3:]
script=Path(sys.argv[0]).absolute();body=script.read_bytes()
if hashlib.sha256(body).hexdigest()!=expected:raise ValueError('source fixture script changed before execution')
module=types.ModuleType('__main__');module.__dict__.update(__file__=str(script),__package__=None,__spec__=None,__cached__=None)
sys.modules['__main__']=module
time.time=lambda:now
exec(compile(body,str(script),'exec'),module.__dict__)
"""
 return [*argv[:index],'-c',launcher,str(now),files[name]['sha256'],*argv[index:]]

def run(a):
 profile_raw=F.read(D/'profile.json');F.need(F.pin(profile_raw)==F.PROFILE,'entry-point-pinned exact GUI source profile');q=json.loads(profile_raw);source=F.ordinary(a.source);F.need({n:F.pin(b)for n,b in F.tree(source).items()}==q['result']['files'],'whole corrected687 controls source');work=F.ordinary(a.workspace);F.need(not work.exists()and work.parent.is_dir(),'fresh CI workspace');protected=[source,D,*[F.ordinary(getattr(a,n))for n in('apps16','held','project','renewal','six_record')]];F.need(all(not work.is_relative_to(p)and not p.is_relative_to(work)for p in protected)and not any('native-actual'in p.name for p in(work,*work.parents)),'disjoint source/factory/fixture workspace outside actual roots');work.mkdir(mode=0o700)
 root=work/'gui607-source';shutil.copytree(source,root);F.need({n:F.pin(b)for n,b in F.tree(root).items()}==q['result']['files'],'whole exact owned source copy before any import');carrier=work/'apps16-inputs';carrier.mkdir(mode=0o700);selection=json.loads((root/'parent574/apps16-selection.json').read_bytes())['selection']
 F.need(selection['source']=='950b0699a6e3f7a56758d4d17a5d30dabc7b6e11'and len(selection['files'])==94,'exact accepted94 input role')
 for n,w in selection['files'].items():
  b=F.read(F.ordinary(a.apps16)/n);F.need(F.pin(b)==w,'whole carrier94 input');p=carrier/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
 temp=work/'runner-temp';temp.mkdir(mode=0o700);original=root/'parent574/original';slice=original/'scripts/ci/welcome5-native-gui';sys.path.insert(0,str(slice));import assets,candidates
 # The original data assembler executes no recipe/native payload or Git command.
 now=fixture_time(F.ordinary(a.renewal))
 with mock.patch('time.time',return_value=now):
  assets.assemble_data(original,F.ordinary(a.held)/'payload',F.ordinary(a.project)/'payload',temp/'welcome5-assets',candidates.selection(original),F.ordinary(a.renewal))
 raw=(root/'.github/workflows/native-arm-build.yml').read_text();scalar=next(x for x in raw.splitlines()if '"run":'in x and 'preflight\\n'in x);commands=json.loads(scalar.strip().split(': ',1)[1]).splitlines()
 expected=[['python3','-I','-B','$CURRENT','preflight'],['python3','-I','-B','gui607-source/implementation/presecret_control.py','--control','apps16-common','--apps16-inputs','$GITHUB_WORKSPACE/apps16-inputs'],['python3','-I','-B','gui607-source/parent574/service_controls.py'],['python3','-I','-B','$SLICE/test_lane.py'],['python3','-I','-B','gui607-source/parent574/original/scripts/ci/test_maintained_desktop574.py']]
 F.need([shlex.split(x)for x in commands]==expected and len(set(commands))==5,'all five decoded exact commands once')
 direct=[shlex.split(x.strip()[5:])for x in raw.splitlines()if x.strip().startswith('run: python3 -I -B')and any('/'+n in x for n in('test_runner_context.py','test_observer.py','test_source.py'))]
 wanted=[['python3','-I','-B','gui607-source/implementation/test_runner_context.py','--assets','$RUNNER_TEMP/welcome5-assets'],['python3','-I','-B','gui607-source/implementation/test_observer.py','--assets','$RUNNER_TEMP/welcome5-assets'],['python3','-I','-B','-Werror','gui607-source/implementation/test_source.py','--record','$GITHUB_WORKSPACE/six22-inputs','--public','$RUNNER_TEMP/six991-inputs','--assets','$RUNNER_TEMP/welcome5-assets']]
 F.need(direct==wanted,'three actual current presecret invocations plus five originals')
 env=dict({k:v for k,v in os.environ.items()if k not in('GH_TOKEN','GITHUB_TOKEN','PYTHONPATH','PYTHONHOME','WELCOME5_GUI_DEVELOPMENT','OBSERVER_AUTHOR_RECEIPTS','OBSERVER_AUTHOR_RECEIPT_PATH')},GITHUB_WORKSPACE=str(work),RUNNER_TEMP=str(temp),TMPDIR=str(temp),WELCOME5_GUI_ASSETS=str(temp/'welcome5-assets'),WELCOME5_GUI_SOURCE=str(original),PYTHONDONTWRITEBYTECODE='1');env.pop('WELCOME5_GUI_DEVELOPMENT',None)
 values={'$CURRENT':str(root/'implementation/native.py'),'$SLICE/test_lane.py':str(slice/'test_lane.py'),'$GITHUB_WORKSPACE/apps16-inputs':str(carrier)}
 current=[['-I','-B',str(root/'implementation/stage_inputs.py'),'--record',str(F.ordinary(a.six_record)),'--output',str(temp/'six991-inputs')],['-I','-B',str(root/'implementation/test_runner_context.py'),'--assets',str(temp/'welcome5-assets')],['-I','-B',str(root/'implementation/test_observer.py'),'--assets',str(temp/'welcome5-assets')],['-I','-B','-Werror',str(root/'implementation/test_source.py'),'--record',str(F.ordinary(a.six_record)),'--public',str(temp/'six991-inputs'),'--assets',str(temp/'welcome5-assets')]]
 def invoke(argv,ordinal,cap):
  began=time.monotonic();r=subprocess.run([sys.executable,*fixture_argv(argv,now,root,q['result']['files'])],cwd=work,env=env,capture_output=True,timeout=cap);(work/(ordinal+'.stdout')).write_bytes(r.stdout);(work/(ordinal+'.stderr')).write_bytes(r.stderr);F.need(r.returncode==0,'source control failed '+ordinal);count={'current-2':4,'current-3':5,'current-4':7}.get(ordinal);F.need(count is None or ('Ran '+str(count)+' tests').encode()in r.stderr,'nonzero exact current control discovery '+ordinal);return dict(ordinal=ordinal,seconds=time.monotonic()-began,exit=r.returncode)
 rows=[invoke(words,'current-'+str(i),180)for i,words in enumerate(current,1)];start=time.monotonic()
 for i,words in enumerate(expected,1):rows.append(invoke([values.get(x,x)for x in words[1:]],'original-'+str(i),180-(time.monotonic()-start)))
 F.need({n:F.pin(b)for n,b in F.tree(root).items()}==q['result']['files'],'whole687 unchanged after all controls');result=dict(status='PASS_SOURCE_ONLY_EXACT687_AND_ALL_EIGHT_PRESECRET_COMMANDS',commands=rows,original_cap_seconds=180,source_cap_seconds=300,fixture_wall_time=now,fixture_clock_scope='HISTORICAL_PINNED_TEST_RENEWAL_SOURCE_ONLY_NOT_CURRENT_AUTHORITY',runtime_expiry_guard='UNCHANGED',actual=None,native='NOT_RUN',GUI='NOT_RUN',M2='NOT_RUN');(work/'result.json').write_bytes(F.encoded(result));print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('source','workspace','apps16','held','project','renewal','six-record'):p.add_argument('--'+n,type=Path,required=True)
 run(p.parse_args())
