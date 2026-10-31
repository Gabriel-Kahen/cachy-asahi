#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite Apps6-only604 rebase; emit source or closed accepted input data, no actors."""
import argparse,ast,hashlib,importlib.util,json,shutil,stat,sys,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/expanded604-current-management';NEW='scripts/ci/expanded604-apps6'
MODULES=('contract.py','inputs.py','materializer.py','lifecycle.py','installed_shells.py','run.py','gate.py')
OWN=('prepare.py','apps_inputs.py','policy.json','source-pins.json','test_lane.py','README.md','hooks.json')
OLD_SHA='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5';TARGET='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3'
def need(v,s):
 if not v:raise ValueError(s)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
def source(repo):
 rows=json.loads((HERE/'source-pins.json').read_bytes())['files'];need(1<=len(rows)<=512,'finite source closure')
 for n,row in rows.items():
  p=repo/n;need(not any(x.is_symlink() for x in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and pin(p.read_bytes())==row,'pinned current604 source differs: '+n)
 return rows

def adapt(raw,name):
 text=raw.decode();ledger=[]
 def r(before,after,count=1):
  nonlocal text
  need(text.count(before)==count,'Apps6 counted anchor: '+name+': '+before[:90]);text=text.replace(before,after);ledger.append(dict(before=before,after=after,count=count))
 if name=='contract.py':
  r(OLD_SHA,TARGET);r("'cachy-asahi-apps':'0.1.0-5'","'cachy-asahi-apps':'0.1.0-6'")
  r("**{'cachy-asahi-orphans':'0.1.0-1'}","**{'cachy-asahi-orphans':'0.1.0-1','cachy-asahi-apps':'0.1.0-5'}")
  r('org.cachy-asahi.expanded604.current-management.job','org.cachy-asahi.expanded604.apps6.job')
  r("    if bound:\n        welcome=", "    if bound:\n        load('apps6_authority',HERE/'apps_inputs.py').require(sys.modules[__name__],value.get('apps6',{}))\n        welcome=")
  r('ROOT_BOUND_CURRENT604_NATIVE_INPUTS','ROOT_BOUND_APPS6_CURRENT604_NATIVE_INPUTS')
  r('args.welcome_source,value)','args.welcome_source,value,args.apps6_source,args.apps6_native_source)',2)
  r('def bound_inputs(source,legacy,eight,seven,management,setup,welcome,value):','def bound_inputs(source,legacy,eight,seven,management,setup,welcome,value,apps6,apps6_native):')
  r("(welcome,value['welcome']['carrier_source'])):","(welcome,value['welcome']['carrier_source']),(apps6,value['apps6']['carrier_source']),(apps6_native,value['apps6']['native_source'])):")
 if name=='inputs.py':
  r("if name=='cachy-asahi-orphans':continue", "if name in ('cachy-asahi-orphans','cachy-asahi-apps'):continue")
  r('def _validate_inputs(source,legacy,eight,seven,management,setup,welcome,policy):','def _validate_inputs(source,legacy,eight,seven,management,setup,welcome,policy,apps6,apps6_native):')
  r('def validate_inputs(source,legacy,eight,seven,management,setup,welcome,policy):','def validate_inputs(source,legacy,eight,seven,management,setup,welcome,policy,apps6,apps6_native):')
  r('_validate_inputs(source,legacy,eight,seven,management,setup,welcome,policy)','_validate_inputs(source,legacy,eight,seven,management,setup,welcome,policy,apps6,apps6_native)')
  r('    require_welcome(policy)  # First: no source import, scratch directory or actor.','    C.load(\'apps6_authority\',C.HERE/\'apps_inputs.py\').require(C,policy.get(\'apps6\',{}))\n    require_welcome(policy)  # First: no source import, scratch directory or actor.')
  anchor="        result['management']['cachy-asahi-orphans']=C.load"
  r(anchor,"        a=stage_packet(Path(apps6),temporary/'apps6',policy['apps6']['index'])\n        result['management']['cachy-asahi-apps']=C.load('apps6_native_inputs',C.HERE/'apps_inputs.py').validate(C,source,a,policy['apps6'],checks,bind,Path(apps6_native))\n"+anchor)
  r("C.checked(welcome if row.get('name')=='cachy-asahi-orphans' else root,row['files']['a'],8*1024**2)","C.checked(Path(apps6) if row.get('name')=='cachy-asahi-apps' else welcome if row.get('name')=='cachy-asahi-orphans' else root,row['files']['a'],8*1024**2)")
  r('retention(eight,seven,management,setup,welcome,legacy,policy)','retention(eight,seven,management,setup,welcome,legacy,policy,apps6)',2)
  r("('welcome_source',welcome,policy['welcome']['index'],False)):","('welcome_source',welcome,policy['welcome']['index'],False),\n        ('apps6_source',Path(apps6),policy['apps6']['index'],False)):")
 if name=='materializer.py':
  r('def accepted(source,legacy,eight,seven,audio,management,setup,welcome,policy):','def accepted(source,legacy,eight,seven,audio,management,setup,welcome,policy,apps6,apps6_native):')
  r('welcome,policy)','welcome,policy,apps6,apps6_native)',3)
  r('def prepare(ready,producer_root,eight,seven,audio,legacy,target,policy,management,setup,welcome,source):','def prepare(ready,producer_root,eight,seven,audio,legacy,target,policy,management,setup,welcome,source,apps6,apps6_native):')
 if name in ('run.py','gate.py'):
  r("'setup_source','welcome_source')","'setup_source','welcome_source','apps6_source')")
 if name=='run.py':
  r("*CARRIERS,'audio_inputs','output'","*CARRIERS,'apps6_native_source','audio_inputs','output'")
  r('args.welcome_source,args.code)','args.welcome_source,args.code,args.apps6_source,args.apps6_native_source)')
  r('PASS_NATIVE_CURRENT604_COMPOSITION','PASS_NATIVE_APPS6_CURRENT604_COMPOSITION')
 if name=='gate.py':
  r("parser.add_argument('--audio-inputs',type=Path)","parser.add_argument('--audio-inputs',type=Path);parser.add_argument('--apps6-native-source',type=Path)")
  r("welcome_source=policy['welcome']['carrier_source'])","welcome_source=policy['welcome']['carrier_source'],\n            apps6_source=policy['apps6']['carrier_source'],apps6_native_source=policy['apps6']['native_source'])")
  r("C.need(args.audio_inputs is not None,", "C.need(args.apps6_native_source is not None,'exact Apps6 native source required');args.apps6_native_source=C.safe(args.apps6_native_source.absolute())\n    C.need(args.audio_inputs is not None,")
 if name in ('contract.py','lifecycle.py'):r('PASS_CURRENT604_METADATA_LIFECYCLE','PASS_APPS6_CURRENT604_METADATA_LIFECYCLE',2 if name=='lifecycle.py' else 1)
 ast.parse(text);return text.encode(),ledger

def workflow(raw,run_sha,manifest_sha):
 text=raw.decode().replace('native-arm-expanded604-current-management','native-arm-expanded604-apps6').replace(OLD,NEW)
 def r(before,after,count=1):
  nonlocal text
  need(text.count(before)==count,'Apps6 workflow anchor: '+before[:80]);text=text.replace(before,after)
 r('d848d7c7bfe98f948571c9856f1b404b17022a0a1d3c2a7d8e4baf80ebd511d7',run_sha);r('61048018e95c262ecd911ffc4150bbbb3e4857b65dee4f4a69a44016c59e2302',manifest_sha)
 r('      - name: Retrieve only the six original pinned audio inputs', '''      - name: Checkout Root bound Apps6 public native evidence
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ steps.policy604.outputs.apps6_source }}
          path: expanded604-apps6-inputs
          persist-credentials: false
      - name: Checkout exact accepted Apps6 native guards
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ steps.policy604.outputs.apps6_native_source }}
          path: expanded604-apps6-native
          persist-credentials: false
      - name: Retrieve only the six original pinned audio inputs''')
 r('--audio-inputs "$RUNNER_TEMP/audio-archives"', '--apps6-source "$GITHUB_WORKSPACE/expanded604-apps6-inputs/payload" --apps6-native-source "$GITHUB_WORKSPACE/expanded604-apps6-native" \\\n            --audio-inputs "$RUNNER_TEMP/audio-archives"',2)
 r('test_current.py','test_lane.py')
 return text.encode()

def emit(repo,output):
 rows=source(repo);need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary source output');output.mkdir(mode=0o700)
 for name in rows:p=output/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((repo/name).read_bytes())
 lane=output/NEW;lane.mkdir(parents=True);ledger={}
 for n in OWN:(lane/n).write_bytes((HERE/n).read_bytes())
 for n in MODULES:raw,ledger[n]=adapt((repo/OLD/n).read_bytes(),n);(lane/n).write_bytes(raw)
 for n in ('expected604.lock','expected587.lock'):(lane/n).write_bytes((HERE/n).read_bytes())
 (lane/'current_inputs.py').write_bytes((repo/OLD/'current_inputs.py').read_bytes());(lane/'held-pins.json').write_bytes((repo/OLD/'held-pins.json').read_bytes());(lane/'input-policy.json').write_bytes((HERE/'policy.json').read_bytes())
 files={n:pin((output/n).read_bytes()) for n in rows};files.update({p.relative_to(output).as_posix():pin(p.read_bytes()) for p in lane.iterdir() if p.is_file()});(lane/'source-manifest.json').write_bytes(encoded(dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCE',files=files,scope='APPS6_ONLY_NEW604_SOURCE_NO_OLD604_CREDIT',native='NOT_RUN',hardware='NOT_RUN')))
 wf=output/'.github/workflows/native-arm-expanded604-apps6.yml';wf.write_bytes(workflow((repo/'.github/workflows/native-arm-expanded604-current-management.yml').read_bytes(),pin((lane/'run.py').read_bytes())['sha256'],pin((lane/'source-manifest.json').read_bytes())['sha256']))
 result=dict(status='SOURCE_ONLY_APPS6_CURRENT604_UNBOUND',target_sha256=TARGET,changed_versions={'cachy-asahi-apps':['0.1.0-5','0.1.0-6']},other_versions_unchanged=603,package_count=604,anchors=ledger,native='NOT_RUN',fresh='UNBOUND',update='UNBOUND',managed16k='UNBOUND',hardware='NOT_RUN');(output/'adaptation.json').write_bytes(encoded(result));return result

def packet(repo,actual,decision,native_source,output):
 H=load('apps6_packet_identity',HERE/'apps_inputs.py');C=load('apps6_packet_contract',repo/OLD/'contract.py');reader=C.scoped_load('apps6_packet_reader',repo/OLD/'inputs.py',{'contract':C});checks,bind=reader.tools(repo)
 need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh private packet output')
 originals={}
 for n in ('run.json','artifacts.json','collection.json','artifact.zip','logs.zip'):
  path=C.safe(actual/n);info=path.lstat();cap=192*1024**2 if n=='artifact.zip' else 32*1024**2 if n=='logs.zip' else 4*1024**2;need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=cap,'ordinary bounded original retained input');originals[n]=path.read_bytes()
 C.safe(decision);info=decision.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=4*1024**2,'ordinary bounded Root decision')
 need(all(pin(originals[n])==row for n,row in H.ORIGINAL.items()) and pin(decision.read_bytes())['sha256']==H.DECISION,'exact accepted original evidence and Root decision')
 blobs={'originals/'+n:raw for n,raw in originals.items()};blobs['root-decision.json']=decision.read_bytes()
 with zipfile.ZipFile(actual/'artifact.zip') as archive:
  entries=archive.infolist();need(len(entries)==216 and len({r.filename for r in entries})==216,'complete original216 public closure')
  for entry in entries:
   name=C.relative(entry.filename);need(not entry.is_dir() and stat.S_IFMT(entry.external_attr>>16) in (0,stat.S_IFREG) and not entry.flag_bits&1 and entry.file_size<=96*1024**2,'ordinary original public member');blobs['public/'+name]=archive.read(entry)
 def ref(n):return dict(path=n,**pin(blobs[n]))
 index=dict(schema_version=1,kind='ROOT_ACCEPTED_APPS6_COMPLETE_NATIVE_PUBLIC_INPUTS',native_source=H.SOURCE,native_run=H.RUN,attempt=1,files={n[len('public/'):]:ref(n) for n in blobs if n.startswith('public/')},originals={n:ref('originals/'+n) for n in originals},root_decision=ref('root-decision.json'))
 raw=encoded(index);need(len(blobs)+1<=256 and sum(map(len,blobs.values()))+len(raw)<=64*1024**2,'bounded new Apps6 packet');output.mkdir(mode=0o700)
 for n,data in blobs.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
 (output/'index.json').write_bytes(raw);binding=dict(status=H.STATUS,native_source=H.SOURCE,native_run=H.RUN,root_decision_sha256=H.DECISION,carrier_source=None,index=dict(path='index.json',**pin(raw)))
 row=H.validate(C,repo,output,binding,checks,bind,native_source,published=False)
 return dict(status='PRIVATE_APPS6_PACKET_VALIDATED_NOT_PUBLISHED',binding=binding,files=len(blobs)+1,bytes=sum(map(len,blobs.values()))+len(raw),archive_sha256=row['files']['a']['sha256'],current604='NOT_RUN',hardware='NOT_RUN')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--action',choices=('emit','packet'),default='emit');p.add_argument('--repo',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--actual',type=Path);p.add_argument('--decision',type=Path);p.add_argument('--native-source',type=Path);a=p.parse_args()
 if a.action=='emit':result=emit(a.repo.absolute(),a.output.absolute())
 else:
  need(all(v is not None for v in (a.actual,a.decision,a.native_source)),'exact existing original/Root decision/native source operands required');result=packet(a.repo.absolute(),a.actual.absolute(),a.decision.absolute(),a.native_source.absolute(),a.output.absolute())
 print(json.dumps(result,sort_keys=True))
