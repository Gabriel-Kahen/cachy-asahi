# SPDX-License-Identifier: MIT
"""Complete closed new source AND original853/604 namespaces; no runtime credit."""
import json
import common as C
import adapter,workflow,closure

def verify():
 f=json.loads(C.read(C.ROOT/'source-manifest.json'));names={p.relative_to(C.ROOT).as_posix()for p in C.ROOT.rglob('*')if p.is_file()and'.git'not in p.parts}
 C.need(names==set(f['files'])|{'source-manifest.json'}|set(workflow.ALIASES),'entire closed fresh607 source namespace')
 for n,w in f['files'].items():C.checked(C.ROOT/n,w)
 for role in('parent853','installer604'):
  C.need({p.relative_to(C.ROOT/role).as_posix()for p in(C.ROOT/role).rglob('*')if p.is_file()}==set(f['parents'][role]),'whole original source role '+role)
  for n,w in f['parents'][role].items():C.checked(C.ROOT/role/n,w)
 for n in adapter.NAMES:
  _,r=adapter.transform(C.read(C.ROOT/'parent604'/n),n);C.need(r['whole_inverse'],'entire old604 runtime body')
 from run import derive
 derive(C.read(C.ROOT/'installer604/scripts/ci/expanded604-apps6-public-pair-installer/ci.py'))
 raw=C.read(C.ROOT/'installer604'/workflow.OLD);template=workflow.derive(raw);C.need(template==C.read(C.HERE/'workflow-template.yml'),'whole old manual workflow inverse')
 expected=template.replace(b'@FRESH607_MANIFEST@',C.pin(C.read(C.ROOT/'source-manifest.json'))['sha256'].encode())
 for n in workflow.ALIASES:C.need(C.read(C.ROOT/n)==expected,'exact current workflow alias and manifest seal')
 closure.verify()
 __import__('ci_namespace').verify()
 p=C.profile();C.need(p['actual_source']is p['actual_ref']is p['actual_run']is None and p['clocks']==dict(engine=4500,readback=600,qemu=5400,vm_owner=9600,outer=15600,workflow_minutes=270,owner_workflow_minutes=350),'only fresh607 selector change; all existing clocks held')
 C.need(p['target']==C.pin(C.read(C.HERE/'expected607.lock'))and p['native_container_P0']=='UNCHANGED_FAILED'and p['hardware']=='NOT_RUN','honest new software-only scope')
 return dict(status='PASS_SOURCE_ONLY_FRESH607_WHOLE853_AND604_BYTES_INVERSES',files=len(names),parents={r:len(w)for r,w in f['parents'].items()},fresh607='NOT_RUN',hardware='NOT_RUN',performance='NOT_CLAIMED')

# BEGIN_COMPLETE574_CACHE_PREPARATION
def verify():
 import retained_cache
 return retained_cache.verify()

# BEGIN_CURRENT_CACHE_WORKFLOW_CONTROL
def verify():
 import cache_controls_context
 return cache_controls_context.verify()
