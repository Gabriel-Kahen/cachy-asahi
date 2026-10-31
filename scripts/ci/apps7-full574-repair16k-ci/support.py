# SPDX-License-Identifier: MIT
"""Finite orchestration source guards; no new installation authority."""
import importlib.util,os,re,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
LANE='scripts/ci/apps7-full574-repair16k-ci';BRIDGE='scripts/ci/apps7-full574-repair16k'
WF='.github/workflows/native-arm-apps7-full574-repair16k.yml';REGISTERED='.github/workflows/native-arm-build.yml'
def bridge(root):
 path=Path(root)/BRIDGE/'contract.py';spec=importlib.util.spec_from_file_location('_repair16k_ci_bridge_contract',path);C=importlib.util.module_from_spec(spec);sys.modules[spec.name]=C;spec.loader.exec_module(C);return C
def source(root,C):
 rows=C.decode(C.read(HERE/'source-manifest.json'))['files'];C.need(0<len(rows)<=512,'finite closed CI source')
 for name,pin in rows.items():C.need(C.row(Path(root)/C.relative(name))==pin,'CI source differs: '+name)
 return rows
def authorize(root,case):
 C=bridge(root);native,binding=C.gate(root,case) # UNBOUND before outputs/secrets/actors.
 requested=os.environ.get('SOURCE_SHA');C.need(re.fullmatch('[0-9a-f]{40}',requested or '') and requested==os.environ.get('GITHUB_SHA')==os.environ.get('GITHUB_WORKFLOW_SHA') and case==os.environ.get('REPAIR_CASE'),'requested source/workflow/case equal')
 rows=source(root,C);actual=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True,timeout=10).strip();C.need(actual==requested,'actual implementation checkout')
 subprocess.run(['git','-C',str(root),'diff','--exit-code','HEAD','--',*rows,LANE+'/source-manifest.json',WF,REGISTERED],check=True,capture_output=True,timeout=15)
 registered=subprocess.check_output(['git','-C',str(root),'show',requested+':'+REGISTERED],timeout=15);C.need(registered==C.read(Path(root)/WF,128*1024),'registered and dedicated workflow exact bytes')
 return C,native,binding
def output(name,value):
 if os.environ.get('GITHUB_OUTPUT'):
  if not re.fullmatch('[a-z][a-z0-9_]*',name) or type(value) is not str or '\n' in value or '\r' in value:raise ValueError('finite Actions output')
  with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:stream.write(name+'='+value+'\n')
def kernel(C,root,work,receipt):
 namespace=dict(C=C,Path=Path)
 fn=C.function(Path(root)/'scripts/ci/current604-apps6-updater16k/vm.py','kernel',namespace)
 from argparse import Namespace
 return fn(Namespace(implementation=root,kernel_work=work,kernel_receipt=receipt))
