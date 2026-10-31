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
 'native/desktop_alpm_v1.py': '4345179192004754c8c6219d63bbefb62d62860fdb81fb2d294751790a3c1f8f',
 'native/desktop_tools_v1.py': '88a8c5a8c188113564c8e0bf1e02176d9cc86f19998b51e19e075c5d0eaf8b62',
 'native/desktop_guest_v1.py': '2818cb5257433b290dd96dc8b1824e4c7932ac5ceff5b190004765caa1191e31',
 'native/desktop-contract-v1.json': 'f2c72aa0d24272966eb323a5a2bb11bca89569a9542330eedafe9f09cc46a894'}
HOST={'transport-diagnostic.json','transport-proof.json','receipt.json','cleanup.json','source-proof.json','consumer-inspect.json','consumer-after.json',
 'consumer-diagnostic.json','image-ledger.json','image-retirement.json','bootstrap-failure-retention.json','provision-diagnostic.json','build-summary.json'}
BOOTSTRAP={phase+'-'+name for phase in ('bootstrap','overlay') for name in
 ('packages.lock','signatures.json','bootstrap.json','cache-checksums.json','Dockerfile','runner.json')}|{
 'bootstrap-acquisition.json','bootstrap-key-import.log','bootstrap-bootstrap.log'}
REPORTS={'desktop-alpm-v1':{'result.json','commands.json'}}
PRIVATE={'desktop-alpm-v1':{'home'}}
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


def _metadata(raw):
 C.need(type(raw) is bytes and len(raw)<=256*1024,'bounded package metadata text required')
 result={}
 for line in raw.decode('utf-8').splitlines():
  if not line or line.startswith('#'):continue
  C.need(' = ' in line,'canonical makepkg metadata separator required')
  key,value=line.split(' = ',1);result.setdefault(key,[]).append(value)
 return result


def _archive_custody(raw, command, contract, index):
    """Independently parse exact public source bodies and every tar byte boundary."""
    import io
    import tarfile
    C.need(type(raw) is bytes and 0<len(raw)<=2*1024**2 and len(raw)%512==0,
         'bounded block-aligned package tar required')
    label={'archive-a':'a','archive-b':'b','archive-update':'update'}.get(command.get('step'))
    recipe=contract['update_recipe'] if label=='update' else contract['recipe'];fixed=Path(contract['invocation']['source']).parent
    C.need(label is not None and type(index) is int and index>=0
         and command.get('log')=='%03d-archive-%s.log'%(index,label)
         and command.get('argv')==['/usr/bin/zstd','-dc',str(fixed/'build-inputs'/label/recipe['archive'])]
         and type(command.get('expected')) is int and command['expected']==0
         and command.get('log_pin')==C.pin(raw), 'exact source-owned archive decoder command and raw pin required')
    expected=recipe['payload_files'];C.need(len(expected)==6,'exact6 source-bound package payload required')
    ancestors={str(parent) for leaf in expected for parent in Path(leaf).parents if str(parent)!='.'}
    payload={};metadata={};seen=set();directories=set();cursor=0;headers=0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
            for member in archive:
                name=member.name.rstrip('/')
                C.need(member.offset==cursor and member.offset_data==cursor+512 and not member.pax_headers
                     and member.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE),
                     'contiguous single-header ordinary tar member required; hidden headers refused')
                header=raw[cursor:cursor+512]
                C.need(len(header)==512 and not PRIVATE_MARKER.search(header),'private marker in package tar header refused')
                C.need(name not in seen and member.uid==member.gid==0 and name==Path(name).as_posix()
                     and '..' not in Path(name).parts,'unique canonical root-owned package members required')
                C.need(type(member.size) is int and 0<=member.size<=1024**2,'finite nonnegative package member size required')
                seen.add(name);start=member.offset_data;end=start+member.size;padded=start+((member.size+511)//512)*512
                C.need(end<=padded<=len(raw) and not any(raw[end:padded]),'package tar padding must be zero')
                if member.isdir():
                    C.need(name in ancestors and member.mode==0o755 and member.size==0,'exact zero-body package directory required')
                    directories.add(name)
                else:
                    C.need(member.isfile() and member.size<=1024**2,'ordinary finite package body required')
                    body=raw[start:end];C.need(len(body)==member.size,'complete raw package body required')
                    if name in ('.PKGINFO','.BUILDINFO','.MTREE'):
                        C.need(member.mode==0o644 and not PRIVATE_MARKER.search(body),'private marker or wrong mode in package metadata refused')
                        metadata[name]=body
                    else:
                        C.need(name in expected and member.mode==expected[name]['mode']
                             and C.pin(body)=={key:expected[name][key] for key in ('bytes','sha256')},'exact source-bound public package body required')
                        payload[name]=dict(mode=member.mode,**C.pin(body))
                cursor=padded;headers+=1
    except (tarfile.TarError,UnicodeError,EOFError):
        raise ValueError('bounded source-bound package tar structure refused') from None
    C.need(set(payload)==set(expected) and directories==ancestors and set(metadata)=={'.PKGINFO','.BUILDINFO','.MTREE'},
         'complete finite package payload and metadata namespace required')
    C.need(len(raw)-cursor>=1024 and not any(raw[cursor:]),'complete zero package tar trailer required')
    for name in ('.PKGINFO','.BUILDINFO'):
        C.need(len(metadata[name])<=256*1024,'bounded textual package metadata required')
    pkg=_metadata(metadata['.PKGINFO']);build=_metadata(metadata['.BUILDINFO'])
    C.need(all(re.fullmatch('[a-z][a-z0-9_]*',key) and all(len(value)<=8192 for value in values)
         for doc in (pkg,build) for key,values in doc.items()),'bounded canonical makepkg metadata fields required')
    for key,value in (('pkgname','cachy-asahi-desktop-tools'),('pkgbase','cachy-asahi-desktop-tools'),('pkgver',recipe['version']),('arch','any')):
        C.need(pkg.get(key)==[value],'exact package identity required')
    C.need(pkg.get('license')==['MIT'] and pkg.get('depend')==['python>=3.11'],'exact MIT package/runtime dependency metadata required')
    for key,value in (('format','2'),('pkgname','cachy-asahi-desktop-tools'),('pkgbase','cachy-asahi-desktop-tools'),
                      ('pkgver',recipe['version']),('pkgarch','any'),('pkgbuild_sha256sum',recipe['source_files']['PKGBUILD']['sha256'])):
        C.need(build.get(key)==[value],'exact package BUILDINFO identity required')
    installed=build.get('installed',[])
    C.need(len(installed)==len(set(installed))==349 and sorted(installed)==contract['buildinfo_installed']
         and 'check' in build.get('buildenv',[]) and '!check' not in build['buildenv'],'exact349 provenance and checks required')
    return dict(kind='exact-source-bound-desktop-package-tar-v1',label=label,step=command['step'],argv=command['argv'],
        raw_pin=C.pin(raw),contract_sha256=PRODUCERS['native/desktop-contract-v1.json'],payload_files=len(payload),
        metadata={name:C.pin(body) for name,body in metadata.items()},
        framing=dict(headers=headers,blocks=len(raw)//512,zero_padding=True,zero_trailer_bytes=len(raw)-cursor),
        privacy='Exact6 bound public payload bodies; every raw header and metadata body scanned; padding and trailer zero')




def archive_custody(raw, command, contract, index):
 import tarfile
 try:return _archive_custody(raw,command,contract,index)
 except C.CapsuleRefusal:raise
 except (tarfile.TarError,ValueError,UnicodeError,EOFError,KeyError,TypeError):
  C.need(False,'bounded source-bound package tar structure refused')


def _project(source_root,public_root,projected_root):
 source,public,dest=map(C._absolute,(source_root,public_root,projected_root))
 C.need(not dest.is_relative_to(public) and not public.is_relative_to(dest) and not dest.is_relative_to(source)
  and not source.is_relative_to(dest),'fresh disjoint projection required')
 for name,expected in PRODUCERS.items():
  with C.refusal_context('projection-source',name):C.need(C.pin(_read(source,name)[0])['sha256']==expected,'projection producer source pin differs')
 selected={};source_modes={};archive_rows={}
 def add(name,expected=None,optional=False,archive_command=None,command_index=None):
  with C.refusal_context('projection-select',name):
   result=_read(public,name,optional)
   if result is None:return None
   raw,mode=result;C._mode(mode)
   if archive_command is not None:
    C.need(name=='journey/desktop-alpm-v1/'+archive_command['log'],'fixed package archive log namespace required')
    contract_raw=_read(source,'native/desktop-contract-v1.json')[0]
    C.need(C.pin(contract_raw)['sha256']==PRODUCERS['native/desktop-contract-v1.json'],'archive contract source pin differs')
    archive_rows[name]=archive_custody(raw,archive_command,C._load(contract_raw),command_index)
   elif PRIVATE_MARKER.search(raw):
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
   for index,row in enumerate(commands):
    C.need(type(row) is dict and type(row.get('log')) is str and LOG.fullmatch(row['log']) and row['log'] not in wanted,'finite unique source command log required')
    wanted.add(row['log']);add(prefix+'/'+row['log'],_pin(row.get('log_pin')),
      archive_command=row if row.get('step') in ('archive-a','archive-b','archive-update') else None,command_index=index)
   actual_logs={n for n in names if LOG.fullmatch(n)}
   for name in sorted(actual_logs^wanted):
    with C.refusal_context('projection-select',prefix+'/'+name):C.need(False,'source command log namespace differs')

 rows={name:dict(kind='file',mode=0o600,source_mode=source_modes[name],**C.pin(raw)) for name,raw in selected.items()}
 receipt=dict(schema=1,status='PASS_FINITE_DESKTOP_ALPM_PUBLIC_DATA_PROJECTION',binding=binding,source_map_sha256=map_hash,
  source_producers=PRODUCERS,selected=rows,omitted_private_scopes=sorted('journey/'+feature+'/'+name for feature,names in PRIVATE.items() for name in names),
  scope='Fixed desktop-alpm-v1 result, commands and raw referenced logs only; private home trees not retained',
  privacy='Ordinary DATA marker refusal; only exact source-bound package tar custody permits bound public source identifiers',
  archive_custody=archive_rows,
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
