# SPDX-License-Identifier: MIT
"""Additional source/registered-workflow joins; original13 files remain intact."""
import os,re,subprocess
from pathlib import Path
import contract as C
HERE=Path(__file__).resolve().parent
WF='.github/workflows/native-arm-current604-apps6-updater16k.yml'
REGISTERED='.github/workflows/native-arm-build.yml'

def check_source(root):
 rows=C.decode(C.read(HERE/'wiring-source-manifest.json'))['files'];C.need(0<len(rows)<=512,'bounded complete wiring closure')
 for n,pin in rows.items():C.need(C.row(Path(root)/C.relative(n))==pin,'wiring source differs: '+n)
 return rows

def load(root,name):
 pins=check_source(root);C.need(name in pins,'explicit source module');return C.load('wire_'+name.replace('/','_'),Path(root)/name)

def authorize(root,source,workflow,case):
 old,policy,binding=C.gate(root,case) # FIRST: no secrets, output or actor under UNBOUND.
 C.need(source==workflow and re.fullmatch('[0-9a-f]{40}',source or ''),'requested source and registered workflow revision agree')
 C.own_source(old,root,source);pins=check_source(root)
 subprocess.run(['git','-C',str(root),'diff','--exit-code','HEAD','--',*pins,C.LANE+'/wiring-source-manifest.json',WF,REGISTERED],check=True,capture_output=True,timeout=15)
 actual=subprocess.check_output(['git','-C',str(root),'show',source+':'+REGISTERED],timeout=15)
 C.need(C.read(Path(root)/WF,128*1024)==actual,'dedicated and actual registered workflow bytes must match')
 return old,policy,binding

def old_gate(root,old):return old.scoped('wired_held_gate',Path(root)/C.OLD/'gate.py',{'contract':old})

def output(name,value):
 C.need(re.fullmatch('[a-z][a-z0-9_]*',name) and type(value) is str and '\n' not in value and '\r' not in value,'bounded Actions output')
 if os.environ.get('GITHUB_OUTPUT'):
  with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:stream.write(name+'='+value+'\n')
