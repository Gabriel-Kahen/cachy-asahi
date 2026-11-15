#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Prepare a verified Perl case packet; never clones, boots, installs or compiles."""
import argparse,hashlib,importlib.util,json,os,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('perl_vm_contracts',HERE/'contracts.py');K=importlib.util.module_from_spec(s);s.loader.exec_module(K)
PKG='perl-5.42.3-1.3-aarch64.pkg.tar.zst'
NAMES=dict(archive=PKG,signature=PKG+'.sig',public_TEST_certificate='TEST-public.asc',signing_receipt='signing-receipt.json',baseline_certificate='baseline-certificate.json',runtime_certificate='runtime-certificate.json',resource_certificate='resource-certificate.json',Root_decision='Root-decision.json',installed_Reader='installed-Reader.json',installed_component_decision='installed-component-decision.json')
CAPS=('gpg_seconds','install_seconds','probe_wait_seconds','remove_seconds','run_seconds','sync_seconds','log_bytes','guest_output_cap_bytes')

def source(expected):
 raw=(HERE/'source.lock.json').read_bytes();K.need(hashlib.sha256(raw).hexdigest()==expected,'external exact closed adapter Source lock')
 lock=K.load(HERE/'source.lock.json');K.need(set(lock)=={'schema','kind','operation','files','actual'}and type(lock['schema'])is int and lock['schema']==1 and lock['kind']=='ARM16K_PERL5423_CASE_SOURCE_LOCK_V1'and lock['operation']==K.OP and set(lock['actual'])=={'source','ref','authority','case_prepared','image_prepared','VM','ALPM','runtime','Root_acceptance'}and all(v is None for v in lock['actual'].values()),'closed unissued adapter Source declaration')
 found={};directories=set()
 for current,dirs,files in os.walk(HERE,followlinks=False):
  for name in dirs:
   q=Path(current)/name;K.need(not q.is_symlink(),'Source directory alias');directories.add(q.relative_to(HERE).as_posix())
  for name in files:
   p=Path(current)/name;n=p.relative_to(HERE).as_posix()
   if n=='source.lock.json':continue
   found[n]=dict(**K.pin(p),mode=stat.S_IMODE(p.stat().st_mode))
 expected_dirs={p.as_posix()for n in lock['files']for p in Path(n).parents if p.as_posix()!='.'}
 K.need(found==lock['files']and directories==expected_dirs,'complete adapter Source bytes/modes/membership');return dict(bytes=len(raw),sha256=expected)

def material_paths(operand):
 operand=K.ordinary(operand)
 if operand.is_dir():return {n:operand/name for n,name in NAMES.items()}
 value=K.load(operand);K.keys(value,NAMES,'retained material reference map')
 return {n:K.ordinary(path)for n,path in value.items()}

def preflight(case_path,case_sha256,materials,source_sha256,baseline,baseline_report):
 lock=source(source_sha256);case_path=K.ordinary(case_path);K.need(K.pin(case_path)['sha256']==case_sha256,'external Root-selected actual case bytes')
 case=K.load(case_path);paths=material_paths(materials)
 observed={name:K.pin(path,2*1024**3 if name=='archive' else 4*1024**2)for name,path in paths.items()}
 cert={name:K.load(paths[name])for name in K.EVIDENCE};validated=K.validate(case,observed,**cert)
 # Extra operands are selected by a separate small path map. No archive copies.
 extra=K.ordinary(materials)
 extra_file=(extra if extra.is_dir()else extra.parent)/'extra-materials.json'
 extras=K.load(extra_file)if extra_file.exists() else {}
 rollback=cert['runtime_certificate']['rollback'];dependency=cert['runtime_certificate']['dependency_transaction']
 needed=set()
 if rollback['mode']=='SIGNED_EXACT_OLD_PACKAGE':needed|={'rollback_archive','rollback_signature'}
 if dependency:needed|={'dependency_archive','dependency_signature'}
 K.keys(extras,needed,'exact extra retained original archive references')
 for role in needed:
  group,name=role.split('_');expected=(rollback if group=='rollback'else dependency)[name]
  K.need(K.pin(K.ordinary(extras[role]))==expected,'actual exact '+role)
 base=K.ordinary(baseline);report=K.ordinary(baseline_report);expected=cert['baseline_certificate']
 for name,key in [('guest.raw','raw'),('prepared.json','prepared'),('ownership.json','ownership')]:
  K.need(K.pin(base/name,expected[key]['bytes'])==expected[key],'exact actual readonly baseline file: '+name)
 K.need(K.pin(report,expected['report']['bytes'])==expected['report'],'exact accepted baseline PAM report bytes')
 return validated,cert,observed,lock,paths,extras

def contents(case,cert,lock,nonce):
 K.need(type(nonce)is str and len(nonce)==32 and all(c in'0123456789abcdef'for c in nonce),'fresh literal case nonce')
 base=cert['baseline_certificate'];runtime=cert['runtime_certificate'];limits=cert['resource_certificate'];trust=case['trust']
 files={}
 def put(name,raw,mode=0o644):files[name]=(raw.encode()if isinstance(raw,str)else raw,mode)
 for name in('root.sh','probe.sh','case.sh','runtime.pl','smoke.t'):put(name,(HERE/'guest'/name).read_bytes())
 for name in('rtc-clock.sh','guest-runtime.sh'):put('frozen/'+name,(HERE/'frozen'/name).read_bytes())
 inventory=dict(base['inventory']);deps=dict(inventory,**({'db5.3':runtime['dependency_transaction']['version']}if runtime['dependency_transaction']else{}));installed=dict(deps,**{K.PACKAGE['name']:K.PACKAGE['version']})
 def inv(rows):return ''.join(n+' '+v+'\n'for n,v in sorted(rows.items()))
 put('expected-base.lock',inv(inventory));put('expected-dependencies.lock',inv(deps));put('expected-installed.lock',inv(installed))
 env=dict(baseline_perl_version=inventory.get('perl','NONE'),dependency_mode='DB53'if runtime['dependency_transaction']else'NONE',recovery_mode=runtime['rollback']['mode'],nonce=nonce,signer_fingerprint=trust['fingerprint'],cert_not_before=trust['created_utc'],cert_not_after=trust['expires_utc'],**{n:limits[n]for n in CAPS})
 put('case.env',''.join(n+'='+str(v)+'\n'for n,v in env.items()))
 paths={}
 for row in runtime['files'].values():
  path=row['resolved'];K.need(path not in paths or paths[path]==row['sha256'],'aliases resolving to one runtime file must have one actual hash');paths[path]=row['sha256']
 K.need(all(not any(c.isspace()for c in p)for p in paths),'literal runtime paths')
 put('runtime-paths.sha256',''.join(h+'  '+p+'\n'for p,h in sorted(paths.items())))
 before=[];aliases=[]
 if runtime['kind']=='ROOT_REVIEWED_PERL5423_VM_EXPECTED_PAYLOAD_INPUTS_V1':
  for r in runtime['expected_payload']['rows']:
   if r['expected_package']=='perl' or r['expected_package']not in inventory:continue
   p=r['expected_path'];f=runtime['baseline_files'][p]
   before.append('\t'.join((p,str(r['expected_member_bytes']),r['expected_member_sha256'],format(f['mode'],'o'),r['expected_package'],r['expected_package_version']))+'\n')
  for p,r in sorted(runtime['expected_payload']['aliases'].items()):
   if r['owner']!='perl'and r['owner']in inventory:aliases.append('\t'.join((p,r['target'],r['owner'],r['version']))+'\n')
 put('expected-before-alpm-providers.tsv',''.join(before));put('expected-before-alpm-aliases.tsv',''.join(aliases))
 put('baseline-paths.sha256',''.join(r['sha256']+'  '+r['resolved']+'\n'for p,r in sorted(runtime['baseline_files'].items())))
 payload=runtime['candidate_namespace'];put('payload.sha256',''.join(r['sha256']+'  '+p+'\n'for p,r in sorted(payload.items())if r['kind']=='f'))
 put('payload-metadata.tsv',''.join('\t'.join((r['kind'],format(r['mode'],'o'),str(r['uid']),str(r['gid']),p,r.get('link_target','-')))+'\n'for p,r in sorted(payload.items())))
 put('expected-payload.paths',''.join(p+'\n'for p in sorted(payload)))
 put('hardlinks.tsv',''.join(p+'\t'+t+'\n'for p,t in sorted(runtime['hardlinks'].items())))
 put('dependencies.txt',''.join(n+'\n'for n in runtime['alpm_dependencies']))
 elfs=[p for p in sorted(runtime['elfs']) if runtime['files'][p]['owner']=='perl']
 put('elf-paths.tsv',''.join(str(i)+'.elf\t'+p+'\t'+runtime['files'][p]['sha256']+'\n' for i,p in enumerate(elfs)))
 dependency=runtime['dependency_transaction']
 if dependency:
  put('dependency-requires.txt',''.join(p+'\n'for p in dependency['requires']))
  put('dependency-payload.sha256',''.join(r['sha256']+'  '+p+'\n'for p,r in sorted(dependency['namespace'].items())if r['kind']=='f'))
  put('expected-dependency.paths',''.join(p+'\n'for p in sorted(dependency['namespace'])))
 material_rows={NAMES[n]:case['package'][n]['sha256'] for n in K.MATERIALS}
 rollback=runtime['rollback']
 if rollback['mode']=='SIGNED_EXACT_OLD_PACKAGE':
  for n,name in [('archive','rollback.pkg.tar.zst'),('signature','rollback.pkg.tar.zst.sig')]:material_rows[name]=rollback[n]['sha256']
 if dependency:
  for n,name in [('archive','db5.3-5.3.28-7-aarch64.pkg.tar.xz'),('signature','db5.3-5.3.28-7-aarch64.pkg.tar.xz.sig')]:material_rows[name]=dependency[n]['sha256']
 put('materials.sha256',''.join(h+'  '+n+'\n'for n,h in sorted(material_rows.items())))
 put('recovery-reason',str(rollback['reason'])+'\n')
 d='/var/lib/arm16k-perl5423-vm';o='/run/arm16k-perl5423-vm'
 put('dependency-pacman.conf','[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nGPGDir = /etc/pacman.d/gnupg\nCacheDir = '+d+'/cache\nLogFile = /var/log/pacman.log\n')
 put('pacman.conf','[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nGPGDir = '+d+'/trust\nCacheDir = '+d+'/cache\nLogFile = /var/log/pacman.log\n')
 unit='[Unit]\nDescription=Disposable Root-bound PERL5423 system-perl case\nAfter=local-fs.target\nBefore=multi-user.target\nConditionPathExists='+d+'/case.env\n[Service]\nType=oneshot\nUser=root\nExecStart=/usr/bin/bash --noprofile --norc '+d+'/root.sh\nTimeoutStartSec='+str(limits['boot_seconds'])+'\n[Install]\nWantedBy=multi-user.target\n'
 put('arm16k-perl5423-vm.service',unit)
 for n in K.EVIDENCE:put(n+'.json',K.canonical(cert[n]))
 put('case-inputs.json',K.canonical(case));put('source-lock-selection.json',K.canonical(lock));return files

def prepare(case_path,case_sha256,materials,source_sha256,nonce,output,baseline,baseline_report):
 case,cert,observed,lock,paths,extras=preflight(case_path,case_sha256,materials,source_sha256,baseline,baseline_report)
 out=K.ordinary(output);K.need(not out.exists()and out.parent.is_dir()and out.parent.stat().st_uid==os.getuid()and not out.parent.stat().st_mode&0o022,'fresh private owned case output')
 K.need(not any(out==p or out in p.parents or p in out.parents for p in(HERE,materials,K.ordinary(case_path))),'case output disjoint from Source/materials')
 rows=contents(case,cert,lock,nonce);fixture_bytes=sum(len(b)for b,_ in rows.values());K.need(fixture_bytes<=cert['resource_certificate']['fixture_source_bytes'],'actual generated fixture must fit the Root-reviewed physical staging plan')
 os.umask(0o077);out.mkdir(mode=0o700)
 for name,(raw,mode)in rows.items():
  p=out/name;p.parent.mkdir(parents=True,exist_ok=True)
  with p.open('xb')as stream:stream.write(raw)
  p.chmod(mode)
 def rows_for(group,names):
  spec=cert['runtime_certificate'][group]
  if not spec or group=='rollback'and spec['mode']=='REMOVE':return {}
  return {n:dict(path=extras[('rollback'if group=='rollback'else'dependency')+'_'+n],guest_name=name,**spec[n])for n,name in names}
 report=dict(schema=1,status='PREPARED_CASE_PACKET_NOT_INSTALLED_OR_BOOTED',operation=K.OP,nonce=nonce,Source_lock=lock,case=K.pin(case_path),
 materials={n:dict(path=str(paths[n]),guest_name=NAMES[n],**observed[n])for n in NAMES},
 rollback_materials=rows_for('rollback',[('archive','rollback.pkg.tar.zst'),('signature','rollback.pkg.tar.zst.sig')]),
 dependency_materials=rows_for('dependency_transaction',[('archive','db5.3-5.3.28-7-aarch64.pkg.tar.xz'),('signature','db5.3-5.3.28-7-aarch64.pkg.tar.xz.sig')]),
 files={n:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=mode)for n,(raw,mode)in rows.items()},staging_target='/var/lib/arm16k-perl5423-vm',
 root_service='arm16k-perl5423-vm.service',kernel_nonce='arm16k_perl5423_vm_nonce='+nonce,
 host_VM_binding=dict(entry='controller.py',authority=None,prepared=None),actual=dict(prepare=None,VM=None,ALPM=None,runtime=None,Reader=None,Root_acceptance=None))
 (out/'case-packet.json').write_bytes(K.canonical(report));return report

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prepare-case-packet',action='store_true')
 for n in('case','materials','output','baseline','baseline-report'):p.add_argument('--'+n,type=Path,required=True)
 for n in('case-sha256','source-lock-sha256','nonce'):p.add_argument('--'+n,required=True)
 a=p.parse_args();K.need(a.prepare_case_packet and sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.getuid()==os.geteuid()!=0,'explicit ordinary isolated case preparation')
 print(json.dumps(prepare(a.case,a.case_sha256,a.materials,a.source_lock_sha256,a.nonce,a.output,a.baseline,a.baseline_report),sort_keys=True))
if __name__=='__main__':main()
