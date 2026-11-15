#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Prepare a verified LLVM case packet; never clones, boots, installs or compiles."""
import argparse,hashlib,importlib.util,json,os,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('llvm_vm_contracts',HERE/'contracts.py');K=importlib.util.module_from_spec(s);s.loader.exec_module(K)
PKG='cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst'
NAMES=dict(archive=PKG,signature=PKG+'.sig',public_TEST_certificate='TEST-public.asc',signing_receipt='signing-receipt.json',baseline_certificate='baseline-certificate.json',runtime_certificate='runtime-certificate.json',resource_certificate='resource-certificate.json',Root_decision='Root-decision.json',Reader4_report='Reader4-report.json')
CAPS=('gpg_seconds','install_seconds','probe_wait_seconds','remove_seconds','compile_seconds','run_seconds','sync_seconds','log_bytes','guest_output_cap_bytes')

def source(expected):
 raw=(HERE/'source.lock.json').read_bytes();K.need(hashlib.sha256(raw).hexdigest()==expected,'external exact closed adapter Source lock')
 lock=K.load(HERE/'source.lock.json');K.need(set(lock)=={'schema','kind','operation','files','actual'}and type(lock['schema'])is int and lock['schema']==1 and lock['kind']=='ARM16K_LLVM23_CASE_SOURCE_LOCK_V1'and lock['operation']==K.OP and set(lock['actual'])=={'source','ref','authority','case_prepared','image_prepared','VM','ALPM','compiler','Root_acceptance'}and all(v is None for v in lock['actual'].values()),'closed unissued adapter Source declaration')
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

def preflight(case_path,case_sha256,materials,source_sha256,baseline,baseline_report,baseline_ownership=None):
 lock=source(source_sha256);case_path=K.ordinary(case_path);K.need(K.pin(case_path)['sha256']==case_sha256,'external Root-selected actual case bytes')
 case=K.load(case_path);materials=K.ordinary(materials);K.need(materials.is_dir(),'ordinary retained materials directory')
 observed={name:K.pin(materials/path,2*1024**3 if name=='archive' else 4*1024**2)for name,path in NAMES.items()}
 cert={name:K.load(materials/NAMES[name])for name in K.EVIDENCE}
 validated=K.validate(case,observed,**cert)
 base=K.ordinary(baseline);report=K.ordinary(baseline_report);expected=cert['baseline_certificate']
 for name,key in [('guest.raw','raw'),('prepared.json','prepared')]:
  K.need(K.pin(base/name,expected[key]['bytes'])==expected[key],'exact actual readonly baseline file: '+name)
 ownership=K.ordinary(baseline_ownership)if baseline_ownership is not None else base/'ownership.json'
 K.need(K.pin(ownership,expected['ownership']['bytes'])==expected['ownership'],'exact independent readonly baseline ownership certificate')
 K.need(K.pin(report,expected['report']['bytes'])==expected['report'],'exact accepted baseline PAM report bytes')
 # This gate selects Root's actual inputs; it does not turn a certificate into a run.
 return validated,cert,observed,lock

def contents(case,cert,lock,nonce):
 K.need(type(nonce)is str and len(nonce)==32 and all(c in'0123456789abcdef'for c in nonce),'fresh literal case nonce')
 base=cert['baseline_certificate'];runtime=cert['runtime_certificate'];limits=cert['resource_certificate'];trust=case['trust']
 files={}
 def put(name,raw,mode=0o644):files[name]=(raw.encode()if isinstance(raw,str)else raw,mode)
 for name in('root.sh','probe.sh','case.sh','smoke.c','unwind.cpp'):put(name,(HERE/'guest'/name).read_bytes())
 for name in('rtc-clock.sh','guest-runtime.sh','durable.sh'):put('frozen/'+name,(HERE/'frozen'/name).read_bytes())
 inventory=dict(base['inventory']);installed=dict(inventory,**{K.PACKAGE['name']:K.PACKAGE['version']})
 def inv(rows):return ''.join(n+' '+v+'\n'for n,v in sorted(rows.items()))
 put('expected-base.lock',inv(inventory));put('expected-installed.lock',inv(installed))
 env=dict(nonce=nonce,signer_fingerprint=trust['fingerprint'],cert_not_before=trust['created_utc'],cert_not_after=trust['expires_utc'],**{n:limits[n]for n in CAPS})
 put('case.env',''.join(n+'='+str(v)+'\n'for n,v in env.items()))
 put('probe-link.env',''.join(n+'='+p+'\n'for n,p in K.probe_inputs(runtime).items()))
 paths={}
 for row in runtime['files'].values():
  path=row['resolved'];K.need(path not in paths or paths[path]==row['sha256'],'aliases resolving to one runtime file must have one actual hash');paths[path]=row['sha256']
 K.need(all(not any(c.isspace()for c in p)for p in paths),'literal runtime paths')
 put('runtime-paths.sha256',''.join(h+'  '+p+'\n'for p,h in sorted(paths.items())))
 payload=runtime['candidate_namespace'];put('payload.sha256',''.join(r['sha256']+'  '+p+'\n'for p,r in sorted(payload.items())if r['kind']=='f'))
 put('payload-metadata.tsv',''.join('\t'.join((r['kind'],format(r['mode'],'o'),str(r['uid']),str(r['gid']),p,r.get('link_target','-')))+'\n'for p,r in sorted(payload.items())))
 put('materials.sha256',''.join(case['package'][n]['sha256']+'  '+NAMES[n]+'\n'for n in K.MATERIALS))
 d='/var/lib/arm16k-llvm23-vm';o='/run/arm16k-llvm23-vm'
 put('pacman.conf','[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nGPGDir = '+d+'/trust\nCacheDir = '+d+'/cache\nLogFile = '+o+'/root/pacman.log\n')
 unit='[Unit]\nDescription=Disposable Root-bound LLVM23 private-prefix case\nAfter=local-fs.target\nBefore=multi-user.target\nConditionPathExists='+d+'/case.env\n[Service]\nType=oneshot\nUser=root\nExecStart=/usr/bin/bash --noprofile --norc '+d+'/root.sh\nTimeoutStartSec='+str(limits['boot_seconds'])+'\n[Install]\nWantedBy=multi-user.target\n'
 put('arm16k-llvm23-vm.service',unit)
 put('case-inputs.json',K.canonical(case));put('source-lock-selection.json',K.canonical(lock));return files

def prepare(case_path,case_sha256,materials,source_sha256,nonce,output,baseline,baseline_report,baseline_ownership=None):
 case,cert,observed,lock=preflight(case_path,case_sha256,materials,source_sha256,baseline,baseline_report,baseline_ownership)
 out=K.ordinary(output);K.need(not out.exists()and out.parent.is_dir()and out.parent.stat().st_uid==os.getuid()and not out.parent.stat().st_mode&0o022,'fresh private owned case output')
 K.need(not any(out==p or out in p.parents or p in out.parents for p in(HERE,materials,K.ordinary(case_path))),'case output disjoint from Source/materials')
 rows=contents(case,cert,lock,nonce);fixture_bytes=sum(len(b)for b,_ in rows.values());K.need(fixture_bytes<=cert['resource_certificate']['fixture_source_bytes'],'actual generated fixture must fit the Root-reviewed physical staging plan')
 os.umask(0o077);out.mkdir(mode=0o700)
 for name,(raw,mode)in rows.items():
  p=out/name;p.parent.mkdir(parents=True,exist_ok=True)
  with p.open('xb')as stream:stream.write(raw)
  p.chmod(mode)
 report=dict(schema=1,status='PREPARED_CASE_PACKET_NOT_INSTALLED_OR_BOOTED',operation=K.OP,nonce=nonce,Source_lock=lock,case=K.pin(case_path),materials={n:dict(path=str(materials/NAMES[n]),**observed[n])for n in NAMES},files={n:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=mode)for n,(raw,mode)in rows.items()},staging_target='/var/lib/arm16k-llvm23-vm',root_service='arm16k-llvm23-vm.service',kernel_nonce='arm16k_llvm23_vm_nonce='+nonce,guest_PAM_command='/usr/bin/env -i HOME=/home/builder USER=builder LOGNAME=builder PATH=/usr/bin LC_ALL=C /usr/bin/bash --noprofile --norc /var/lib/arm16k-llvm23-vm/probe.sh '+nonce,host_VM_binding=None,actual=dict(prepare=None,VM=None,ALPM=None,compiler=None,Reader=None,Root_acceptance=None),missing_before_VM=['Root-bound disposable prepared image with exact readonly baseline/runtime reinspection and service-only delta','Root-reviewed host controller/actor binding to this packet and finite physical plan','actual ordinary PAM session, natural QMP retirement and offline output/ELF/restoration review'])
 (out/'case-packet.json').write_bytes(K.canonical(report));return report

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prepare-case-packet',action='store_true')
 for n in('case','materials','output','baseline','baseline-report','baseline-ownership'):p.add_argument('--'+n,type=Path,required=True)
 for n in('case-sha256','source-lock-sha256','nonce'):p.add_argument('--'+n,required=True)
 a=p.parse_args();K.need(a.prepare_case_packet and sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.getuid()==os.geteuid()!=0,'explicit ordinary isolated case preparation')
 print(json.dumps(prepare(a.case,a.case_sha256,a.materials,a.source_lock_sha256,a.nonce,a.output,a.baseline,a.baseline_report,a.baseline_ownership),sort_keys=True))
if __name__=='__main__':main()
