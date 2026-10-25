# SPDX-License-Identifier: MIT
"""Complete current selection AND reconstructed namespace-corrected parent."""
import json, os, subprocess, sys, tempfile
from pathlib import Path
import common as C
import baseline_selection as B
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml')
PARENT=dict(bytes=218432,sha256='63272955cd7e449332dbd7858d30ff3e03bf1916d46844370e279c67e0801835')
FOOTER="\n# Fixed independent Apps6-before607 selection; parent proof remains mandatory.\n_parent_namespace_verify=verify\ndef verify():\n return __import__('baseline_guard').verify()\n"
README_PREFIX="""# Independent Apps6-before607 baseline candidate

This source selects Apps6 with the other606 versions exactly equal to the latest607
Apps16 target. It holds600 original604 archive bodies and selects seven incoming
archives. Native installation, readback, cleanup and Root acceptance are NOT_RUN.
The original parent documentation below describes the Apps16-after607 ancestor;
its complete source proof remains mandatory through a byte-exact reconstruction.

"""
def verify():
 manifest=json.loads(C.read(C.ROOT/'source-manifest.json'))
 names={p.relative_to(C.ROOT).as_posix()for p in C.ROOT.rglob('*')if p.is_file()and'.git'not in p.parts}
 C.need(names==set(manifest['files'])|{'source-manifest.json'}|set(ALIASES),'whole baseline source namespace')
 for n,w in manifest['files'].items():C.checked(C.ROOT/n,w)
 parent=json.loads(C.checked(C.HERE/'baseline-parent.json',PARENT));C.need(len(parent)==1178,'fixed whole namespace-corrected1178 parent')
 profile=C.read(C.HERE/'baseline-before-profile.json');after=C.read(C.HERE/'baseline-after607.lock');before=C.read(C.HERE/'expected607.lock')
 C.need(B.profile(profile,after,before)==C.read(C.HERE/'profile.json'),'entire exact Apps6 selection and other606 custody')
 raw=C.read(C.HERE/'materialize.py');back=raw.decode()
 for old,new in reversed(B.EDITS):C.need(back.count(new)==1,'one baseline inverse seam');back=back.replace(new,old,1)
 C.need(B.materializer(back.encode())==raw,'whole materializer inverse')
 guard=C.read(C.HERE/'source_guard.py');C.need(guard.endswith(FOOTER.encode()),'one mandatory baseline guard footer')
 tests=C.read(C.HERE/'test_source.py');new=b'(600,607)';old=b'(599,607)';C.need(tests.count(new)==1,'one baseline held-count control seam')
 values={}
 for n,w in parent.items():
  if n in ALIASES or n=='source-manifest.json':continue
  b=C.read(C.ROOT/n)
  if n=='implementation/profile.json':b=profile
  elif n=='implementation/expected607.lock':b=after
  elif n=='implementation/materialize.py':b=back.encode()
  elif n=='implementation/source_guard.py':b=guard[:-len(FOOTER.encode())]
  elif n=='implementation/test_source.py':b=tests.replace(new,old,1)
  elif n=='README.md':C.need(b.startswith(README_PREFIX.encode()),'explicit baseline documentation');b=b[len(README_PREFIX.encode()):]
  C.need(C.pin(b)==w,'whole namespace-corrected parent body '+n);values[n]=b
 parent_manifest=dict(manifest,files={n:w for n,w in parent.items()if n not in(*ALIASES,'source-manifest.json')})
 b=C.enc(parent_manifest);C.need(C.pin(b)==parent['source-manifest.json'],'whole parent manifest inverse');values['source-manifest.json']=b
 template=values['implementation/workflow-template.yml'];C.need(template.count(b'@FRESH607_MANIFEST@')==1,'one parent workflow seal')
 for n in ALIASES:
  b=template.replace(b'@FRESH607_MANIFEST@',parent['source-manifest.json']['sha256'].encode());C.need(C.pin(b)==parent[n],'whole parent workflow inverse');values[n]=b
 current_template=C.read(C.HERE/'workflow-template.yml');expected=current_template.replace(b'@FRESH607_MANIFEST@',C.pin(C.read(C.ROOT/'source-manifest.json'))['sha256'].encode())
 for n in ALIASES:C.need(C.read(C.ROOT/n)==expected,'current baseline workflow seal')
 with tempfile.TemporaryDirectory(prefix='apps6-before607-parent-')as folder:
  root=Path(folder)
  for n,b in values.items():p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
  child=subprocess.run([sys.executable,'-I','-B',str(root/'implementation/run.py'),'--source-preflight'],stdin=subprocess.DEVNULL,capture_output=True,timeout=300,env={k:v for k,v in os.environ.items()if k not in('GH_TOKEN','GITHUB_TOKEN','PYTHONPATH','PYTHONHOME')})
  C.need(child.returncode==0 and len(child.stdout)+len(child.stderr)<1024**2,'complete parent source proof required')
  report=json.loads(child.stdout);C.need(report['files']==len(parent),'exact parent source count')
 import adapter
 for n in adapter.NAMES:C.need(adapter.transform(C.read(C.ROOT/'parent604'/n),n)[1]['whole_inverse'],'current baseline six-body inverse')
 return dict(status='PASS_SOURCE_ONLY_APPS6_BEFORE607_AND_COMPLETE_PARENT',files=len(names),parent_files=len(parent),packages=607,Apps_version='0.1.0-6',other606='HELD',native='NOT_RUN',hardware='NOT_RUN',Root_acceptance='NOT_ISSUED')
