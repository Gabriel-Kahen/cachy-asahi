# SPDX-License-Identifier: MIT
"""Finite source-defined evidence projection; omitted private trees untouched."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import capsule as C
import privacy_diagnostics as privacy

PRODUCERS = {
    'native/release_alpm_v1.py': '61cb97fc1bdc4f55e398a083b7318c9ff08895917c1066e666d8cd62b24a271f',
    'native/release_tools_v1.py': '911c629ab4426a1379e0f89192e4e3b8e3d769d70d106bbfb3771e249b1ec536',
    'native/release_guest_v1.py': '10eb4d88baabaa0efdecbab684b5caafaa68a7cfc50b668849df99cd3d532c85',
    'native/release-contract-v1.json': 'e6a938f606954c213c5a38709b9cf2680d049c8ac8f20c381fc51800ccff1333',
    'native/release_build_cause_v1.py': '859144a2e90ce7ef5ac6884fed421023b8783e98a335b3f91fcfc522da5736ff',
    'scripts/workflows/developer_workflow.py': '531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba',
    'scripts/virtual/owned_process_retirement_v2.py': '9388d270d06e28fee50160b7c04dd69593e383647d791f8aaff69380032165d5'}
HOST={'transport-diagnostic.json','transport-proof.json','receipt.json','cleanup.json','source-proof.json','consumer-inspect.json','consumer-after.json',
 'consumer-diagnostic.json','image-ledger.json','image-retirement.json','bootstrap-failure-retention.json','provision-diagnostic.json','build-summary.json'}
BOOTSTRAP={phase+'-'+name for phase in ('bootstrap','overlay') for name in
 ('packages.lock','signatures.json','bootstrap.json','cache-checksums.json','Dockerfile','runner.json')}|{
 'bootstrap-acquisition.json','bootstrap-key-import.log','bootstrap-bootstrap.log'}
REPORTS={'release-alpm-v1':{'result.json','commands.json'}}
PRIVATE={'release-alpm-v1':{'home'}}
LOG=re.compile(r'[0-9]{3}-[A-Za-z0-9][A-Za-z0-9_+.-]{0,127}\.log')
PRIVATE_MARKER=re.compile(br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|BEGIN PGP PRIVATE|ssh-(?:rsa|ed25519)|ecdsa-sha2-|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)|(?:access[_-]?token|password|secret)\s*[=:]|CACHY_(?:OLD_FOUR|RETAINED_BUBBLEWRAP)|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b',re.I)


def _read(root,name,optional=False):
 with C.refusal_context('projection-read',name):
  C._name(name)
  try:
   with C._directory(root/Path(name).parent) as fd:
    info=os.stat(Path(name).name,dir_fd=fd,follow_symlinks=False)
    return C._read_at(fd,Path(name).name,info,C.PAYLOAD_CAP),stat.S_IMODE(info.st_mode)
  except FileNotFoundError:
   if optional:return None
   raise


def _names(root,name=''):
 with C.refusal_context('projection-select',name or None):
  try:
   with C._directory(root/name) as fd:
    names=sorted(os.listdir(fd));C.need(len(names)<=3000,'projection directory count cap');return names
  except FileNotFoundError:return []


def _pin(row):
 C.need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and 0<=row['bytes']<=C.PAYLOAD_CAP
  and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'projection typed source pin required')
 return row


def _project(source_root,public_root,projected_root):
 source,public,dest=map(C._absolute,(source_root,public_root,projected_root))
 C.need(not dest.is_relative_to(public) and not public.is_relative_to(dest) and not dest.is_relative_to(source)
  and not source.is_relative_to(dest),'fresh disjoint projection required')
 for name,expected in PRODUCERS.items():
  with C.refusal_context('projection-source',name):C.need(C.pin(_read(source,name)[0])['sha256']==expected,'projection producer source pin differs')
 selected={};source_modes={}
 def add(name,expected=None,optional=False):
  with C.refusal_context('projection-select',name):
   result=_read(public,name,optional)
   if result is None:return None
   raw,mode=result;C._mode(mode)
   if PRIVATE_MARKER.search(raw):
    context=privacy.inspect_privacy(raw,name);privacy.validate_context(context,name)
    error=C.CapsuleRefusal('private material marker in selected public DATA refused',phase='projection-select',path=name)
    error.privacy_context=context
    raise error
   if expected is not None:C.need(C.pin(raw)==_pin(expected),'projection retained source pin differs')
   if name in selected:C.need(selected[name]==raw,'projection duplicate leaf differs')
   selected[name]=raw;source_modes[name]=mode
   C.need(len(selected)<=2998 and sum(map(len,selected.values()))<=C.CAP,'projection aggregate cap')
   return raw
 roots=_names(public)
 for name in roots:
  with C.refusal_context('projection-select',name):C.need(name in HOST|{'artifacts.json','actor-logs','provision-logs','bootstrap-proof','transport-proof','journey'},'unknown public root entry refused')
 for name in sorted(HOST&set(roots)):add(name)
 C.need('receipt.json' in selected or 'provision-diagnostic.json' in selected,'projection authority receipt required')
 C.need(not ('receipt.json' in selected and 'provision-diagnostic.json' in selected),'ambiguous projection authority refused')
 authority='receipt.json' if 'receipt.json' in selected else 'provision-diagnostic.json'
 with C.refusal_context('projection-select',authority):
  value=C._load(selected[authority]);C.need(type(value) is dict,'projection authority object required');binding=value.get('binding');map_hash=value.get('source_map_sha256')
  C.need(type(binding) is dict and set(binding)=={'source','ref','run','attempt','token'} and type(binding['source']) is str
   and re.fullmatch('[0-9a-f]{40}',binding['source']) and type(binding['ref']) is str and binding['ref'].startswith('refs/heads/codex/')
   and type(binding['run']) is str and re.fullmatch('[1-9][0-9]*',binding['run']) and type(binding['attempt']) is int and binding['attempt']==1
   and binding['token']==hashlib.sha256((binding['source']+':'+binding['ref']+':'+binding['run']).encode()).hexdigest()[:24]
   and type(map_hash) is str and re.fullmatch('[0-9a-f]{64}',map_hash),'projection authority binding refused')
 for directory in ('actor-logs','provision-logs','bootstrap-proof'):
  for name in _names(public,directory):
   relative=directory+'/'+name
   with C.refusal_context('projection-select',relative):
    allowed=(re.fullmatch(r'[0-9]{4}\.log',name) if directory=='actor-logs' else re.fullmatch(r'(?:proof\.json|input-transport-owner\.json|input-cache-owner\.json)-[0-9]{3}\.log',name) if directory=='provision-logs' else name in BOOTSTRAP)
    C.need(allowed,'unknown public proof leaf refused');add(relative)
 for name in _names(public,'transport-proof'):
  relative='transport-proof/'+name
  with C.refusal_context('projection-select',relative):
   C.need(name=='receipt.json' or re.fullmatch(r'[0-9]{4}\.(stdout|stderr)',name),'fixed transport proof leaf required');add(relative)
 journey=_names(public,'journey')
 for name in journey:
  with C.refusal_context('projection-select','journey/'+name):C.need(name in {'result.json','build-summary.json',*REPORTS},'unknown journey entry refused')
 add('journey/result.json',optional=True)
 add('journey/build-summary.json',optional=True)
 for feature,reports in REPORTS.items():
  prefix='journey/'+feature;names=_names(public,prefix)
  for name in names:
   with C.refusal_context('projection-select',prefix+'/'+name):C.need(name in reports or name in PRIVATE[feature] or LOG.fullmatch(name),'unknown feature root entry refused')
  for name in sorted(reports):add(prefix+'/'+name,optional=True)
  report_raw=selected.get(prefix+'/result.json')
  if report_raw is None:
   C.need(not any(LOG.fullmatch(n) for n in names),'command log without source report refused');continue
  with C.refusal_context('projection-select',prefix+'/result.json'):
   report=C._load(report_raw);C.need(type(report) is dict,'feature report object required');commands=report.get('commands',[]);C.need(type(commands) is list and len(commands)<=1000,'finite source command records required');wanted=set()
   for row in commands:
    C.need(type(row) is dict and type(row.get('log')) is str and LOG.fullmatch(row['log']) and row['log'] not in wanted,'finite unique source command log required')
    wanted.add(row['log']);add(prefix+'/'+row['log'],_pin(row.get('log_pin')))
   actual_logs={n for n in names if LOG.fullmatch(n)}
   for name in sorted(actual_logs^wanted):
    with C.refusal_context('projection-select',prefix+'/'+name):C.need(False,'source command log namespace differs')

 rows={name:dict(kind='file',mode=0o600,source_mode=source_modes[name],**C.pin(raw)) for name,raw in selected.items()}
 receipt=dict(schema=1,status='PASS_FINITE_RELEASE_ALPM_PUBLIC_DATA_PROJECTION',binding=binding,source_map_sha256=map_hash,
  source_producers=PRODUCERS,selected=rows,omitted_private_scopes=sorted('journey/'+feature+'/'+name for feature,names in PRIVATE.items() for name in names),
  scope='Fixed release-alpm-v1 result, commands and raw referenced logs only; private home trees not retained',
  privacy='Selected text/JSON/log ASCII private-key,SSH,token,secret-env marker refusal; no payload exemption',
  original_output_unchanged=True,omitted_private_trees_walked=False)
 selected['public-projection.json']=C._json(receipt)
 manifest=dict(schema=1,binding=binding,source_map_sha256=map_hash,files={name:dict(kind='file',mode=0o600,**C.pin(raw)) for name,raw in selected.items()})
 selected['artifacts.json']=C._json(manifest)
 C.need(len(selected)<=C.LEAF_CAP and sum(map(len,selected.values()))<=C.CAP,'projection final aggregate cap')
 for name,row in rows.items():
  with C.refusal_context('projection-read',name):
   current=_read(public,name);C.need(C.pin(current[0])=={k:row[k] for k in ('bytes','sha256')} and current[1]==row['source_mode'],'selected source leaf changed before projection')
 with C.refusal_context('projection-copy'):
  with C._directory(dest.parent,mutable=True) as fd:os.mkdir(dest.name,0o700,dir_fd=fd)
  for name,raw in sorted(selected.items()):
   with C.refusal_context('projection-copy',name):
    with C._directory(dest,mutable=True) as rootfd:
     fds=[];fd=rootfd
     try:
      for part in Path(name).parts[:-1]:
       try:os.mkdir(part,0o700,dir_fd=fd)
       except FileExistsError:pass
       fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);fds.append(fd)
      descriptor=os.open(Path(name).name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
      try:
       os.fchmod(descriptor,0o600)
       with os.fdopen(descriptor,'wb',closefd=False) as stream:stream.write(raw)
      finally:os.close(descriptor)
     finally:
      for descriptor in reversed(fds):os.close(descriptor)
    C.need(C._ordinary(dest/name,C.PAYLOAD_CAP)==raw,'projection copy differs')
 return receipt


def project(source_root,public_root,projected_root):
 try:
  with C.refusal_context('projection'):
   return _project(source_root,public_root,projected_root)
 except C.CapsuleRefusal as error:
  C.emit_refusal(error);raise
