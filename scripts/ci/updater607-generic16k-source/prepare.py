#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Construct an exact4K parent or explicit16K child using SOURCE/DATA only."""
import argparse,ast,hashlib,importlib.machinery,importlib.util,json,os
from pathlib import Path
ROOT=Path(__file__).resolve().parent
loader=importlib.machinery.SourceFileLoader('_source_constructor_io',str(ROOT/'templates/custody.py.in'))
spec=importlib.util.spec_from_loader(loader.name,loader);Q=importlib.util.module_from_spec(spec);loader.exec_module(Q)

def verify_factory():
 raw=Q.read(ROOT/'factory-manifest.json');manifest=json.loads(raw)
 actual={name:Q.pin(Q.read(ROOT/name))for name in('prepare.py','profile.json','kernel-descriptor.json')}
 for folder in('templates','tests'):actual.update({folder+'/'+name:row for name,row in Q.rows(ROOT/folder).items()})
 Q.need(manifest['status']=='SOURCE_FACTORY_NOT_NATIVE_ACCEPTANCE'and actual==manifest['files'],'complete pinned constructor/profile/template/test source')
 return dict(manifest=Q.pin(raw),files=actual)

def edit(raw,edits):
 out=raw
 for old,new in edits:
  Q.need(out.count(old.encode())==1,'one constructor seam '+old[:60]);out=out.replace(old.encode(),new.encode(),1)
 restored=out
 for old,new in reversed(edits):
  Q.need(restored.count(new.encode())==1,'one constructor inverse');restored=restored.replace(new.encode(),old.encode(),1)
 Q.need(restored==raw,'whole source inverse');ast.parse(out);return out

def literal(raw,name):
 tree=ast.parse(raw);values=[]
 for n in tree.body:
  if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id==name for t in n.targets):values.extend(ast.literal_eval(n.value))
  elif isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Attribute)and isinstance(n.value.func.value,ast.Name)and n.value.func.value.id==name and n.value.func.attr=='append':values.append(ast.literal_eval(n.value.args[0]))
 Q.need(values,'nonempty trusted literal source edits');return values

def read_dependency(path,role,p):
 path=Q.safe(path);actual=Q.rows(path);Q.need(actual==p['dependencies'][role]['files'],'complete exact '+role+' source input')
 return {n:Q.read(path/n)for n in actual}

def baseline_case(parent,case):
 prefix='cases/'+case+'/';values={n[len(prefix):]:b for n,b in parent.items()if n.startswith(prefix)}
 for name in('selected_package.py','selected-input.json'):values['scripts/ci/latest607-updater/'+name]=parent['implementation/'+name]
 cfg=json.loads(values['upgrade-config.json']);cfg['code_pins'].update({n:Q.pin(b)['sha256']for n,b in values.items()if n.startswith('scripts/ci/latest607-updater/')});values['upgrade-config.json']=Q.enc(cfg)
 parent_profile=json.loads(parent['implementation/profile.json']);receipt=json.loads(values['adapter.json'])
 receipt['latest607_selection']=dict(status='SOURCE_ONLY_NEW_APPS6_TO16_SELECTION_NOT_ACCEPTED',case=case,whole_original_adapter=Q.pin(values['adapter.json']),historical_config_sha256=receipt['config_sha256'],capsule_config=parent_profile['cases'][case]['upgrade-config.json'],current_emitted_config=Q.pin(values['upgrade-config.json']),before=parent_profile['before'],after=parent_profile['after'],archive=parent_profile['selected']['archive'],all_other606='HELD',actual=None)
 receipt['config_sha256']=Q.pin(values['upgrade-config.json'])['sha256'];values['adapter.json']=Q.enc(receipt);return values

def case16(parent,case,descriptor):
 values=baseline_case(parent,case);raw=values['upgrade-config.json'];cfg=json.loads(raw);ledger={}
 pred4="and os.geteuid() == 0 and Path('/.dockerenv').is_file() and os.sysconf('SC_PAGE_SIZE') == 4096"
 pred16="and os.geteuid() == 0 and os.sysconf('SC_PAGE_SIZE') == 16384 and os.uname().release == '7.1.13-generic16k-managed-gui' and 'caa_apps6_update16k=1' in Path('/proc/cmdline').read_text().split()"
 for name,edits in (
  ('scripts/ci/full-root-upgrade-caller/container.py',[(pred4,pred16)]),
  ('scripts/install/local_transaction.py',[("os.uname().release == '7.2.10-1-aarch64-ARCH'","os.uname().release == '7.1.13-generic16k-managed-gui'"),("os.sysconf('SC_PAGE_SIZE') == 4096","os.sysconf('SC_PAGE_SIZE') == 16384")])):
  before=values[name];after=edit(before,edits);Q.need(cfg['code_pins'][name]==Q.pin(before)['sha256'],'complete original case code pin')
  ledger[name]=dict(before=Q.pin(before),after=Q.pin(after),edits=edits,whole_inverse=True);values[name]=after;cfg['code_pins'][name]=Q.pin(after)['sha256']
 values['upgrade-config.json']=Q.enc(cfg);receipt=json.loads(values['adapter.json']);receipt['config_sha256']=Q.pin(values['upgrade-config.json'])['sha256']
 receipt['explicit_generic16k']=dict(status='SOURCE_DERIVED_NOT_EXECUTED',page_size=16384,kernel='7.1.13-generic16k-managed-gui',kernel_input=descriptor,ledger=ledger,original_config=raw.decode(),clocks='UNCHANGED',actual=None)
 values['adapter.json']=Q.enc(receipt);return values

CURRENT_HELPER='''\n_CURRENT607 = None
_KERNEL_DESCRIPTOR = None
def _actual607_boot(boot,selection):
 import kernel_data
 C.need(boot.get('current607')==selection['current607'],'current source/run/attempt/ref boot join')
 kernel_data.actual({n:boot[n]for n in('sysname','architecture','page_size','kernel')},_KERNEL_DESCRIPTOR)
def _current607_runner_bytes(folder,context):
 C.need(type(context)is dict and set(context)=={'source','run','attempt','ref','page_profile'}and context['page_profile']=='generic16k'and re.fullmatch('[0-9a-f]{40}',context['source'])and re.fullmatch('[1-9][0-9]*',context['run'])and context['attempt']=='1'and context['ref'].startswith('refs/heads/codex/'),'current source/run/attempt/ref explicit16K context')
 result={p.name:C.read(p)for p in folder.glob('*.py')}
 old=b'CURRENT607_EXPECTED = None';raw=result['guest.py'];C.need(raw.count(old)==1,'one current guest context binding');result['guest.py']=raw.replace(old,('CURRENT607_EXPECTED = '+repr(context)).encode(),1)
 return result
'''
GUEST_HELPER='''\nCURRENT607_EXPECTED = None
def require_current607(s):
 C.need(type(CURRENT607_EXPECTED)is dict and s.get('current607')==CURRENT607_EXPECTED and CURRENT607_EXPECTED['page_profile']=='generic16k','same current source/run/attempt/ref explicit page context before guest clock/security work')
'''

def vm_source(held):
 lane='scripts/ci/current604-public-pair-updater16k/';names=('contract.py','cap_scope.py','disk.py','guest.py','vm.py','source-manifest.json');values={name:held[lane+name]for name in names};proof={}
 for name,edits in (
  ('contract.py',[("PASS='PASS_GENERIC16K_VM_PUBLIC_PAIRS_APPS5_TO6_CURRENT604_UPDATE'","PASS='PASS_GENERIC16K_VM_LATEST607_APPS6_TO16_UPDATE'")]),
  ('guest.py',[("s=C.decode(C.read('/workspace/selection.json'));", "s=C.decode(C.read('/workspace/selection.json'));require_current607(s);"),("emit(s,dict(event='boot',page_size=16384,","emit(s,dict(event='boot',current607=s['current607'],sysname=os.uname().sysname,page_size=16384,"),("if __name__=='__main__':",GUEST_HELPER+"\nif __name__=='__main__':")]),
  ('vm.py',[("selection=dict(nonce=nonce,case=a.case,","selection=dict(nonce=nonce,case=a.case,current607=_CURRENT607,"),("runner_files={p.name:C.row(p) for p in C.HERE.glob('*.py')}","runner_files={name:dict(bytes=len(raw),sha256=C.sha(raw))for name,raw in _current607_runner_bytes(C.HERE,_CURRENT607).items()}"),("for p in C.HERE.glob('*.py'):shutil.copyfile(p,work/p.name)","for name,body in _current607_runner_bytes(C.HERE,_CURRENT607).items():(work/name).write_bytes(body)"),("boot,result,end=[C.decode(x[len(prefix):]) for x in lines]", "boot,result,end=[C.decode(x[len(prefix):]) for x in lines]\n _actual607_boot(boot,selection)"),("kernel_receipt=C.row(a.kernel_receipt)","kernel_receipt=C.row(a.kernel_input/'kernel-input.json')"),("def authorize(a):",CURRENT_HELPER+'\ndef authorize(a):')])):
  raw=values[name];values[name]=edit(raw,edits);proof[name]=dict(before=Q.pin(raw),after=Q.pin(values[name]),edits=edits,whole_inverse=True)
 return values,proof

def construct(source,output,page_profile='generic4k',fresh16k=None,held=None):
 factory=verify_factory();p=json.loads(Q.read(ROOT/'profile.json'));source=Q.safe(source);output=Q.safe(output)
 Q.need(page_profile in('generic4k','generic16k'),'closed page profile');Q.need(not os.path.lexists(output)and output.parent.is_dir(),'fresh output with existing parent')
 protected=[source,ROOT/'templates',ROOT/'profile.json']+[Q.safe(x)for x in(fresh16k,held)if x is not None]
 Q.need(all(output!=x and not output.is_relative_to(x)and not x.is_relative_to(output)for x in protected),'disjoint source/output roles')
 parent=read_dependency(source,'updater',p)
 if page_profile=='generic4k':
  Q.need(fresh16k is None and held is None,'default4K refuses unused16K operands');values=parent;fact=dict(status='EXACT_DEFAULT4K_PARENT360_SOURCE_ONLY',page_profile=page_profile,files=360,actual=None)
 else:
  Q.need(fresh16k is not None and held is not None,'explicit complete fresh16K and held source operands')
  fresh=read_dependency(fresh16k,'fresh16k',p);support=read_dependency(held,'held',p)
  descriptor=json.loads(Q.read(ROOT/'kernel-descriptor.json'))
  p['kernel_descriptor']=descriptor;p['constructor_source']=factory;values={'parent360/'+n:b for n,b in parent.items()}
  values['LICENSE']=parent['LICENSE'];values['README.md']=Q.read(ROOT/'templates/README.md.in')
  for name in('custody','entry','selected','kernel_data'):values[name+'.py']=Q.read(ROOT/'templates'/(name+'.py.in'))
  vm,vm_proof=vm_source(support);values.update({'vm/'+n:b for n,b in vm.items()});p['vm_derivation']=vm_proof
  original=support['scripts/ci/expanded604-apps6-public-pair-updater/run.py'];parent_owner=edit(original,literal(parent['implementation/runtime.py'],'OWNER_EDITS'));emitted_owner=edit(parent_owner,literal(values['selected.py'],'OWNER_EDITS'));p['emitted_owner']=Q.pin(emitted_owner);p['owner_parent_inverse']=dict(before=Q.pin(parent_owner),after=Q.pin(emitted_owner),whole_inverse=True)
  values['emissions/owner16k.py']=emitted_owner;p['emitted_cases']={}
  for case in('normal','precommit-exit86','postcommit-exit87'):
   bodies=case16(parent,case,descriptor);p['emitted_cases'][case]={n:Q.pin(b)for n,b in bodies.items()};values.update({'emissions/cases/'+case+'/'+n:b for n,b in bodies.items()})
  p['support_scope']='COMPLETE_HELD489_SOURCE_EXTERNAL_AND_CURRENT_GUEST_RUNNER_PINS; NO_4K_OUTCOME_PROJECTION'
  for name in('cleanup.py','retain.py','test_source.py','kernel_stage.py'):values[name]=Q.read(ROOT/'templates'/(name+'.in'))
  workflows,inverse=workflow(parent,values);values.update(workflows);p['workflow_inverse']=inverse;values['profile.json']=Q.enc(p)
  values['source-manifest.json']=Q.enc(dict(status='SOURCE_ONLY_EXPLICIT_GENERIC16K_CURRENT607_NOT_ACCEPTED',actual_source=None,actual_run=None,files={n:Q.pin(b)for n,b in values.items()}))
  Q.need({n[len('parent360/'):]:Q.pin(b)for n,b in values.items()if n.startswith('parent360/')}==p['dependencies']['updater']['files'],'complete whole parent360 inverse')
  fact=dict(status='CONSTRUCTED_EXPLICIT_GENERIC16K_CURRENT607_SOURCE_ONLY',page_profile=page_profile,files=len(values),parent_inverse=360,clocks='UNCHANGED',kernel_bytes='NOT_ACQUIRED_OR_VERIFIED',runtime='NOT_RUN',actual=None)
 # A second full dependency read closes late source drift before the first write.
 Q.need(parent==read_dependency(source,'updater',p),'late parent source drift')
 if page_profile=='generic16k':
  Q.need(fresh==read_dependency(fresh16k,'fresh16k',p)and support==read_dependency(held,'held',p),'late dependency drift')
 Q.need(verify_factory()==factory,'late complete constructor/source drift')
 output.mkdir(mode=0o700)
 for name,raw in values.items():
  target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(0o644)
 Q.need(Q.rows(output)=={n:Q.pin(b)for n,b in values.items()},'complete emitted source readback');return fact

def workflow(parent,values):
 original=json.loads(parent['.github/workflows/native-arm-build.yml']);out=json.loads(json.dumps(original))
 out['name']='native-arm-latest607-updater-generic16k'
 out['concurrency']['group']='updater607-generic16k-${{ inputs.source }}-${{ inputs.case }}'
 fields=out['on']['workflow_dispatch']['inputs']
 fields['page_profile']=dict(description='Explicit generic16k option; generic4k uses the unchanged default constructor output',type='choice',options=['generic4k','generic16k'],default='generic4k',required=True)
 fields['kernel_input_source']=dict(description='Immutable Git SHA of the exact three-file kernel DATA input; no automatic acquisition',type='string',required=True)
 steps=out['jobs']['native']['steps']
 gate=steps[3];gate['env'].update(PAGE_PROFILE='${{ inputs.page_profile }}',KERNEL_DATA_SOURCE='${{ inputs.kernel_input_source }}')
 gate['run']=gate['run'].replace('set -euo pipefail\n','set -euo pipefail\ntest "$PAGE_PROFILE" = generic16k\n[[ "$KERNEL_DATA_SOURCE" =~ ^[0-9a-f]{40}$ ]]\n',1).replace('21c542c7b643dcfe151f7d13dfa40d996db4a719edf7c2e0851af0dfe353f277',Q.pin(values['entry.py'])['sha256'])
 arguments=' --page-profile generic16k --kernel-input "$RUNNER_TEMP/updater607-kernel-data" --fresh16k-source "$GITHUB_WORKSPACE/updater607-fresh16k-source"'
 for step in steps:
  run=step.get('run','')
  for mode in('preflight','decisions','inputs','run'):
   for needle in('native4k-source/entry.py '+mode+' ', 'native4k-source/entry.py" '+mode+' '):
    if needle in run:run=run.replace(needle,needle.rstrip()+arguments+' ',1)
  if step.get('name')=='Run closed607 source and focused nonzero source controls':
   run=run.replace('python3 -I -B native4k-source/test_source.py','python3 -I -B native4k-source/parent360/test_source.py\npython3 -I -B native4k-source/test_source.py')
  if step.get('name')=='Provision host ext4 test tools on disposable runner':
   Q.need(run.count('--no-install-recommends e2fsprogs')==1,'one original disposable tool install')
   run=run.replace('--no-install-recommends e2fsprogs','--no-install-recommends e2fsprogs qemu-system-arm',1).replace('dpkg-query -W e2fsprogs','command -v qemu-system-aarch64\ndpkg-query -W e2fsprogs qemu-system-arm',1)
  if run:step['run']=run
  if 'name'in step:step['name']=step['name'].replace('native ARM4K full interruption/recovery','explicit generic16K VM full interruption/recovery').replace('native4K public roles','current607 generic16K public roles')
  if step.get('uses','').startswith('actions/upload-artifact@'):
   Q.need(step['with']['name'].count('latest607-updater4k-')==1,'one exact original native artifact role')
   step['with']['name']=step['with']['name'].replace('latest607-updater4k-','latest607-updater-generic16k-',1)
   step['name']='Retain exact current607 generic16K source-bound public artifact'
 checkout='actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
 export_gate='set -euo pipefail\ntest "$PAGE_PROFILE" = generic16k\n[[ "$KERNEL_DATA_SOURCE" =~ ^[0-9a-f]{40}$ ]]\n'
 for name in('kernel_stage.py','custody.py','kernel_data.py'):
  export_gate+="printf '%s  %s\\n' '"+Q.pin(values[name])['sha256']+"' 'native4k-source/"+name+"' | sha256sum --check\n"
 added=[
  dict(name='Checkout exact accepted generic16K SOURCE precedent without projecting its outcome',uses=checkout,**{'with':dict(ref='0db9341521b5cb5d9022715b5ba638b3e4018462',path='updater607-fresh16k-source',**{'persist-credentials':False})}),
  dict(name='Checkout explicit exact kernel DATA without executing it',uses=checkout,**{'with':dict(ref='${{ inputs.kernel_input_source }}',path='updater607-kernel-data-source',**{'persist-credentials':False})}),
  dict(name='Export only the three exact pinned kernel DATA members without Git metadata',env=dict(PAGE_PROFILE='${{ inputs.page_profile }}',KERNEL_DATA_SOURCE='${{ inputs.kernel_input_source }}'),run=export_gate+'python3 -I -B native4k-source/kernel_stage.py --source "$GITHUB_WORKSPACE/updater607-kernel-data-source" --revision "$KERNEL_DATA_SOURCE" --output "$RUNNER_TEMP/updater607-kernel-data"\n')]
 changed={str(i):dict(before=before,after=after)for i,(before,after)in enumerate(zip(original['jobs']['native']['steps'],steps))if before!=after}
 steps[3:3]=added
 # Every untouched step, input, environment, clock, cache init and retirement
 # remains the complete original object, not a reconstructed shortened job.
 p={'name','concurrency','on','jobs'};Q.need({k:v for k,v in out.items()if k not in p}=={k:v for k,v in original.items()if k not in p},'all workflow permissions and outer fields held')
 restored=json.loads(json.dumps(out));Q.need(restored['jobs']['native']['steps'][3:6]==added,'exact three new SOURCE/DATA steps');del restored['jobs']['native']['steps'][3:6]
 for i,row in changed.items():
  Q.need(restored['jobs']['native']['steps'][int(i)]==row['after'],'one exact changed workflow step');restored['jobs']['native']['steps'][int(i)]=row['before']
 for key in('name','concurrency','on'):restored[key]=original[key]
 Q.need(restored==original and Q.enc(restored)==parent['.github/workflows/native-arm-build.yml'],'complete original workflow inverse including every cache/input/retirement/clock step')
 raw=Q.enc(out);proof=dict(before=Q.pin(parent['.github/workflows/native-arm-build.yml']),after=Q.pin(raw),changed_steps=changed,added_steps=added,added_at=3,whole_inverse=True)
 return {'.github/workflows/native-arm-build.yml':raw,'.github/workflows/native-arm-latest607-updater-generic16k.yml':raw},proof

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--page-profile',choices=('generic4k','generic16k'),default='generic4k');parser.add_argument('--fresh16k',type=Path);parser.add_argument('--held',type=Path);args=parser.parse_args();print(json.dumps(construct(args.source,args.output,args.page_profile,args.fresh16k,args.held),sort_keys=True))
if __name__=='__main__':main()
