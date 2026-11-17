#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Construct an opt-in Source sibling with exact predecessors and finite edits."""
import argparse,hashlib,importlib.util,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
INITIALIZED=dict(bytes=2188,sha256='f51c3110877cc9f8d4056c064a43c339af4f6d026b9f7055d5a1ea749ad7e55a')
SOURCE65=dict(bytes=10598,sha256='da1c8749a281b767f50ca696cf7818d1925aa852057d7de011b4c3ddd8eca75d')
def need(ok,why):
 if not ok:raise ValueError(why)
def canonical(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def load(root,name):
 s=importlib.util.spec_from_file_location('lifecycle_constructor_'+name,root/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def replace(raw,old,new):
 need(raw.count(old)==1,'exact single constructor seam: '+old[:80]);return raw.replace(old,new)
def between(raw,start,end,new):
 need(raw.count(start)==raw.count(end)==1,'exact bounded constructor block');a=raw.index(start);b=raw.index(end,a);return raw[:a]+new+raw[b:]
def transform(files):
 """Pure bytes transform; changed actor bodies are never used under old seals."""
 result=dict(files)
 def text(name,fn):
  body,mode=result[name];result[name]=(fn(body.decode()).encode(),mode)
 def adapter(s):
  s=replace(s,'validated=K.validate(case,observed,**cert)','validated=K.validate(case,observed,**cert)\n Q=__import__(\'importlib\').util.spec_from_file_location(\'initialized_fixture\',HERE/\'initialized_integration.py\');J=__import__(\'importlib\').util.module_from_spec(Q);Q.loader.exec_module(J)\n qualified=J.qualify(case,observed,cert,J.refs(materials),lock);cert[\'_initialized_state\']=qualified[\'state\'];cert[\'_initialized_qualified\']=qualified')
  s=replace(s,"put('preboot-context.json',K.canonical(P.context(K,cert,lock,nonce,case_pin or K.json_pin(case))))","put('preboot-context.json',K.canonical(P.context(K,cert,lock,nonce,case_pin or K.json_pin(case))))\n put('initialized-state.DATA.json',K.canonical(cert['_initialized_state']))\n put('initialized-empty-proof.json',K.canonical(cert['_initialized_qualified']['proof']))")
  s=replace(s,"for name in('root.sh','probe.sh'","for name in('initialized-state.sh','root.sh','probe.sh'")
  s=replace(s,"report=dict(schema=1,status=", "report=dict(initialized_inputs=cert['_initialized_qualified']['bindings'],initialized_state=K.json_pin(cert['_initialized_state']),schema=1,status=")
  return s
 text('adapter.py',adapter)
 def guest(s):
  s=replace(s,'. "$D/root-ssh.sh"','. "$D/initialized-state.sh"')
  s=between(s,'preboot_parents=(etc etc/audit etc/udev)','cache_snapshot() (','')
  # Keep the old finite cache byte/xattr snapshot checks, never copy the selected inode.
  s=between(s,'cache_etc_timestamp_capture\nfor path in /etc/ld.so.cache /var/cache/ldconfig/aux-cache; do','[[ ! -L /var/log/pacman.log ]]','cache_etc_timestamp_capture\n')
  start='for path in /etc/ld.so.cache /var/cache/ldconfig/aux-cache; do'
  s=between(s,start,'cache_snapshot > "$S/after.cache"','initialized_guard\n')
  s=replace(s,'# Compare the recovered running state first: certified preboot cleanup changes parent nlinks.\n# Final preboot absence/identity/mtime remains subject to the unchanged host preserve gate.','# Require exact selected initialized state throughout recovery.\n# The host independently rechecks the same inode/content/xattr/mtime snapshot.')
  need('touch -m --reference'not in s and 'preboot_parent_fd'not in s,'no cold timestamp/deletion implementation survives')
  return s
 text('guest/root.sh',guest)
 result['guest/root-ssh.sh']=(b'# SPDX-License-Identifier: MIT\n# Cold SSH cleanup is inaccessible in this sibling.\nreturn 2\n',0o644)
 result['guest/initialized-state.sh']=((HERE/'guest/initialized-state.sh').read_bytes(),0o644)
 result['preboot.py']=((HERE/'context.py').read_bytes(),0o644)
 result['root_ssh.py']=(b"# SPDX-License-Identifier: MIT\nfrom pathlib import Path\nimport importlib.util\ns=importlib.util.spec_from_file_location('initialized_preboot',Path(__file__).parent/'preboot.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)\ndef descriptor(K,I,packet,cert,scan,context_raw):\n P.descriptor(K,I,packet,cert,scan,context_raw)\n return ('PERL5423_INITIALIZED_SSH_V1 '+packet['nonce']+' '+K.json_pin(P.context(K,cert,packet['Source_lock'],packet['nonce'],packet['case']))['sha256']+'\\n').encode()\ndef preserve(K,before,after):return P.preserve(K,before,after)\n",0o644)
 def actor(s):
  s=replace(s,"descriptor_path=W/'preboot-etc.tsv'","descriptor_path=W/'initialized-state.tsv'")
  s=replace(s,"descriptor_pin=K.pin(descriptor_path,4096)","descriptor_pin=K.pin(descriptor_path,8192)")
  s=replace(s,"file(D+'/preboot-etc.tsv',descriptor_path,descriptor_pin,0o600)","file(D+'/initialized-state.tsv',descriptor_path,descriptor_pin,0o600)")
  need(s.count("(D+'/preboot-etc.tsv').lstrip('/')")==2,'exact size/link descriptor readbacks');s=s.replace("(D+'/preboot-etc.tsv').lstrip('/')","(D+'/initialized-state.tsv').lstrip('/')")
  # Preparation also preserves every selected initialized inode, not only old parents.
  s=replace(s,"I.owners(after,base['inventory']);I.qualify(after,rt['baseline_files'],owned)","module('root_ssh').preserve(K,scan,after)\n I.owners(after,base['inventory']);I.qualify(after,rt['baseline_files'],owned)")
  return s
 text('actor.py',actor)
 def controller(s):
  return replace(s,'K.validate(case,observed,**cert)','K.validate(case,observed,**cert)\n module(\'initialized_integration\').verify_packet(case,observed,cert,packet)')
 text('controller.py',controller)
 def image(s):
  s=replace(s,' class Reader(F.Ext4Reader):',''' class Reader(F.Ext4Reader):
  _metadata_only=True
  _ssh_inode=None
  _verified_blocks=None
  def xattrs(self,raw,extra):
   return {}if self._metadata_only else super().xattrs(raw,extra)
  def chunks(self,fields,raw):
   if fields['inode']==self._ssh_inode:
    if self._metadata_only:
     for block in super().chunks(fields,raw):self._verified_blocks.append(block);yield block
    else:
     K.need(module('initialized_integration').initialized('ssh_empty').metadata(fields)==self._empty['inode_metadata'],'same verified empty inode before inventory')
     yield from self._verified_blocks
   else:yield from super().chunks(fields,raw)''')
  s=replace(s,"module('ssh_privacy').guard_root_ssh_absence(K,self)","module('initialized_integration').guard_empty(K,self)")
  s=replace(s,'return dict(nodes=nodes,records=records,filesystem_free_bytes=free_bytes,log_data_b64=log_data,retained_log_data_b64=retained_log)','return dict(nodes=nodes,records=records,filesystem_free_bytes=free_bytes,log_data_b64=log_data,retained_log_data_b64=retained_log,root_ssh_empty_proof=r._empty)')
  return s
 text('image.py',image)
 result['initialized_integration.py']=((HERE/'integration.py').read_bytes(),0o644)
 return result

def construct(legacy,initialized,output):
 legacy=Path(legacy);initialized=Path(initialized);out=Path(output)
 for p in(legacy,initialized,out):need(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary explicit unaliased Source/output paths')
 need(out.is_absolute()and not out.exists()and out.parent.is_dir()and out.parent.stat().st_uid==os.getuid()and not out.parent.stat().st_mode&0o022,'fresh private owned explicit output directory')
 need(all(not out.is_relative_to(p)and not p.is_relative_to(out)for p in(legacy,initialized,HERE)),'Source output disjoint from each immutable dependency')
 Q=load(initialized,'qualification');need(Q.SOURCE65==SOURCE65,'unchanged Source65 dependency');Q.source(INITIALIZED);Q.legacy(legacy)
 # Verify this constructor's whole own closed source before emitting any bytes.
 own=json.loads((HERE/'source.lock.json').read_bytes());found={p.relative_to(HERE).as_posix():dict(**pin(p.read_bytes()),mode=stat.S_IMODE(p.stat().st_mode))for p in HERE.rglob('*')if p.is_file()and p.name!='source.lock.json'}
 need(found==own['files']and not any(p.is_symlink()for p in HERE.rglob('*')),'closed lifecycle constructor Source')
 original={p.relative_to(legacy).as_posix():(p.read_bytes(),stat.S_IMODE(p.stat().st_mode))for p in legacy.rglob('*')if p.is_file()};base={k:v for k,v in original.items()if k!='source.lock.json'};files=transform(base)
 for prefix,root in(('_legacy',legacy),('_initialized',initialized)):
  for p in root.rglob('*'):
   if p.is_file():files[prefix+'/'+p.relative_to(root).as_posix()]=(p.read_bytes(),stat.S_IMODE(p.stat().st_mode))
 changed={k:dict(before=dict(**pin(base[k][0]),mode=base[k][1])if k in base else None,after=dict(**pin(v[0]),mode=v[1]))for k,v in files.items()if not k.startswith(('_legacy/','_initialized/'))and base.get(k)!=v}
 files['initialized-construction.DATA.json']=(canonical(dict(kind='NEW_OPT_IN_INITIALIZED_LIFECYCLE_SOURCE_V2',predecessor=SOURCE65,initialized=INITIALIZED,constructor=pin((HERE/'source.lock.json').read_bytes()),changes=changed,inverse='WHOLE_BYTE_MODE_EXACT_PREDECESSOR_UNDER__legacy',actual=dict(Root_qualification=None,fixture=None,authority=None,VM=None,ALPM=None,Perl_preservation=None,M2=None,release=None))),0o644)
 lock=json.loads(original['source.lock.json'][0]);lock['files']={k:dict(**pin(raw),mode=mode)for k,(raw,mode)in sorted(files.items())};files['source.lock.json']=(canonical(lock),0o644)
 os.umask(0o077);out.mkdir(mode=0o700)
 for n,(raw,mode)in sorted(files.items()):
  p=out/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(mode)
 load(out/'_initialized','qualification').source(INITIALIZED);load(out/'_initialized','qualification').legacy(out/'_legacy');load(out,'adapter').source(pin(files['source.lock.json'][0])['sha256'])
 return dict(status='CONSTRUCTED_SOURCE_NOT_QUALIFIED_OR_EXECUTED',path=str(out),source_lock=pin(files['source.lock.json'][0]),changed=sorted(changed),Root_acceptance=None,VM=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('legacy','initialized','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(construct(a.legacy,a.initialized,a.output),sort_keys=True))
