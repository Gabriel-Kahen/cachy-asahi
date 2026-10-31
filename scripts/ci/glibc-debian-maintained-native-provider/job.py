#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate Debian native pair owner: exact source, no inherited GNU acceptance."""
import argparse,hashlib,importlib.util,json,os,platform,re,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import reuse
SLICE='scripts/ci/glibc-debian-maintained-native-provider'
CANDIDATE='scripts/ci/glibc-debian-maintained-provider'
PATCH_PIN=dict(bytes=498952,sha256='9f62b90fb4c7423ed5023698c9014ad0086d26f9b6f46b2a163afcea7e581a02')
def need(ok,message):
 if not ok:raise ValueError(message)
def policy(path=HERE/'input-policy.json'):
 value=json.loads(path.read_bytes());row=value['packet']
 need(value['schema_version']==1 and value['status']=='ROOT_BOUND_IMMUTABLE_MAINTAINED_DEBIAN_SOURCE_PACKET' and type(row.get('ref')) is str and re.fullmatch('[0-9a-f]{40}',row['ref']),'UNBOUND maintained Debian packet: no credentials or native actors')
 need(row['directory']=='payload' and type(row['index'].get('bytes')) is int and 0<row['index']['bytes']<=65536 and type(row['index'].get('sha256')) is str and re.fullmatch('[0-9a-f]{64}',row['index']['sha256']),'exact Root-bound eight-input maintained Debian inventory required')
 return value

def source(root,manifest):
 j=reuse.load(root);j.manifest_files(root,manifest);return j

def prove(root,manifest,environment,policy_path=HERE/'input-policy.json'):
 j=source(root,manifest);binding=policy(policy_path);s=environment['SOURCE_SHA']
 need(re.fullmatch('[0-9a-f]{40}',s) and s==environment['WORKFLOW_SHA']==environment['GITHUB_SHA'],'source must equal exact workflow revision before secrets')
 need(environment['RUNNER_ARCH']=='ARM64' and environment['RUNNER_OS']=='Linux','native ARM runner required')
 run,attempt=environment['GITHUB_RUN_ID'],environment['GITHUB_RUN_ATTEMPT']
 need(re.fullmatch('[1-9][0-9]{0,19}',run) and re.fullmatch('[1-9][0-9]{0,9}',attempt),'bounded run identity required');identity=run+':'+attempt+':'+s
 return dict(status='SOURCE_PROOF_PASS_NEW_MAINTAINED_DEBIAN_PAIR',source_sha=s,workflow_sha=s,run_id=run,run_attempt=attempt,job_token=hashlib.sha256(('maintained-debian-provider-producer:'+identity).encode()).hexdigest()[:16],consumer_token=hashlib.sha256(('maintained-debian-provider-consumer:'+identity).encode()).hexdigest()[:32],debian_source_sha=binding['packet']['ref'],packet_index_sha256=binding['packet']['index']['sha256'],native='NOT_RUN',old_GNU_pair='NOT_REUSED',hardware='NOT_RUN',release='NOT_ADMITTED')

def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def packet(root,inputs,policy_path=HERE/'input-policy.json'):
 binding=policy(policy_path);a=module('maintained_packet_auth',root/'scripts/ci/glibc-debian-provider/auth.py')
 raw=a.read(inputs/'index.json',65536);need(a.pin(raw)==binding['packet']['index'],'Root exact maintained packet index differs')
 index=a.decode(raw);authority=a.decode(a.read(root/CANDIDATE/'authority.json',65536));decision=authority['decision'];expected=dict(a.PUBLIC_PINS);expected['glibc_2.43-7.debian.tar.xz']=PATCH_PIN;expected[decision['path']]={k:decision[k] for k in ('bytes','sha256')}
 need(set(index)=={'schema_version','status','candidate','native','release','files'} and index['schema_version']==1 and index['status']=='PUBLIC_AUTHENTICATED_MAINTAINED_DEBIAN_SOURCE_INPUTS' and index['candidate']=='2.43.caa3-1' and index['native']=='NOT_RUN' and index['release']=='NOT_ADMITTED' and index['files']==expected,'complete eight-file maintained Debian input chain required')
 need(set(p.name for p in inputs.iterdir())==set(expected)|{'index.json'},'exact nine-file maintained packet directory required')
 for n,row in expected.items():need(a.pin(a.read(inputs/n))==row,'maintained source chain file changed: '+n)
 oldpath=list(sys.path);sys.path.insert(0,str(root/CANDIDATE))
 try:g=module('maintained_packet_authority',root/CANDIDATE/'authority.py');decision=g.check(root/CANDIDATE/'authority.json',inputs,root/'scripts/ci/glibc-debian-provider/auth.py')
 finally:sys.path[:]=oldpath
 return dict(status='PASS_EXACT_NEW_MAINTAINED_DEBIAN_SOURCE_PACKET',ref=binding['packet']['ref'],authority=decision,index_sha256=a.pin(raw)['sha256'])

def prepare(root,inputs,harness,bundle,policy_path=HERE/'input-policy.json'):
 receipt=packet(root,inputs,policy_path);oldpath=list(sys.path);sys.path.insert(0,str(root/CANDIDATE))
 try:
  emitter=module('maintained_bundle_emitter',root/CANDIDATE/'bundle.py');emitter.materialize(inputs,inputs/'glibc_2.43-7.debian.tar.xz',bundle)
  adapter=module('maintained_native_adapter',root/SLICE/'adapter.py');bundle_pin=hashlib.sha256((bundle/'bundle.json').read_bytes()).hexdigest();adapter.emit(root,bundle,bundle_pin,harness)
 finally:sys.path[:]=oldpath
 return dict(status='PASS_NEW_MAINTAINED_DEBIAN_SOURCE_PREPARED_NO_NATIVE_CREDIT',packet=receipt,harness_manifest_sha256=hashlib.sha256((harness/'source-manifest.json').read_bytes()).hexdigest(),bundle_manifest_sha256=bundle_pin)

def held_harness(j,harness,pin):
 need(isinstance(pin,str) and re.fullmatch('[0-9a-f]{64}',pin),'explicit emitted harness manifest pin required')
 manifest=harness/'source-manifest.json';j.regular(manifest,65536);need(j.sha(manifest)==pin,'emitted harness manifest changed before export');files=j.read(manifest,65536)['files']
 need(type(files) is dict and 1<=len(files)<=32 and {p.name for p in harness.iterdir()}==set(files)|{'source-manifest.json'},'closed emitted harness required')
 for name,row in files.items():
  need(Path(name).name==name and name not in ('.','..'),'flat emitted harness name required');path=harness/name;info=j.regular(path,256*1024)
  need(info.st_size==row['bytes'] and j.sha(path)==row['sha256'],'emitted harness file changed before export')
 return files

def ordinary_cleanup(j):
 need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and not any(k.startswith('DOCKER_') for k in os.environ),'ordinary local native cleanup required')
 context=j.invoke(['/usr/bin/docker','context','inspect','default']);need(context.returncode==0 and json.loads(context.stdout)[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock','local default cleanup daemon required')
 current=j.invoke(['/usr/bin/docker','context','show']);need(current.returncode==0 and current.stdout.strip()==b'default','default cleanup context required')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('proof','prepare','cleanup','retain'))
 for key in ('workspace','manifest','proof','inputs','harness','bundle','base','runtime','cleanup','output'):p.add_argument('--'+key,type=Path)
 p.add_argument('--harness-manifest-sha256');a=p.parse_args();need(not sys.flags.optimize,'ordinary unoptimized Python required');root=a.workspace.resolve(strict=True);j=source(root,json.loads(a.manifest.read_bytes()))
 if a.phase=='proof':
  value=prove(root,json.loads(a.manifest.read_bytes()),os.environ);value['manifest_sha256']=j.sha(a.manifest)
  with a.proof.open('x') as stream:json.dump(value,stream,sort_keys=True,indent=2);stream.write('\n')
  with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
   for key in ('job_token','consumer_token','debian_source_sha'):stream.write(key+'='+value[key]+'\n')
 elif a.phase=='prepare':
  value=prepare(root,a.inputs,a.harness,a.bundle)
  with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
   for key in ('harness_manifest_sha256','bundle_manifest_sha256'):stream.write(key+'='+value[key]+'\n')
 elif a.phase=='cleanup':
  ordinary_cleanup(j);value=j.cleanup(root,json.loads(a.manifest.read_bytes()),j.read(a.proof),a.base,a.runtime,a.output)
 else:
  held_harness(j,a.harness,a.harness_manifest_sha256);value=j.retain(root,a.base,a.runtime,a.bundle,a.proof,a.cleanup,a.output,a.harness)
 print(json.dumps(value,sort_keys=True));return int(not value['status'].startswith(('SOURCE_PROOF_PASS','PASS_')))
if __name__=='__main__':raise SystemExit(main())
