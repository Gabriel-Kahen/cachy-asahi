# SPDX-License-Identifier: MIT
"""Pinned C01 DATA adapter and exact successful RTC KSM prerequisite schema."""
import importlib.util,json,re
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

L=load('frozen_c01_data',HERE/'frozen/c01/inputs.py');L.HERE=HERE
pin,checked,elf_geometry,package,closure,fixtures=L.pin,L.checked,L.elf_geometry,L.package,L.closure,L.fixtures

def reference():
 origin=json.loads((HERE/'origin.json').read_text());rtc=HERE.parent/'arm16k_project_lifecycle_rtc'
 for name,ref in origin['frozen_c01'].items():checked(HERE/'frozen/c01'/name,ref)
 for name,ref in origin['rtc_reference_files'].items():checked(rtc/name,ref)
 lock=json.loads((HERE/'inputs.lock.json').read_text());base=HERE.parent/'arm16k_systemd_tcg_guest'
 for name,ref in lock['reference_files'].items():checked(base/name,ref)
 return lock,base,load('c01_rtc_base_primitives',base/'boot.py')

def signature_dates(statuses):
 if set(statuses)!={'cachy-asahi-zlib-baseline','cachy-asahi-zlib-lto'}:raise ValueError('exact two signature date records required')
 out={}
 for name,line in statuses.items():
  fields=line.split()
  if len(fields)not in (11,12)or fields[:2]!=['[GNUPG:]','VALIDSIG']or not all(re.fullmatch(r'(0|[1-9][0-9]{0,11})',v)for v in fields[4:6]):raise ValueError('unhandled signature date format')
  out[name.removeprefix('cachy-asahi-zlib-')]={'created':int(fields[4]),'expires':int(fields[5])}
 return out

def trust_prerequisite(path,sha256,approved):
 if not re.fullmatch('[0-9a-f]{64}',sha256):raise ValueError('explicit Root receipt SHA required')
 if path.stat().st_size>65536:raise ValueError('Root receipt bound exceeded')
 expected={'bytes':path.stat().st_size,'sha256':sha256};checked(path,expected)
 if approved.get('ksm_pass_receipt')!=expected:raise ValueError('genuine RTC KSM receipt requires separate exact Root authority')
 report=json.loads(path.read_text());fields=report.get('project',{})
 if report.get('schema_version')!=1 or report.get('status')!='PASS_EMULATED_ARM16K_RTC_SIGNED_PROJECT_INSTALL_REMOVE_ONLY'or fields.get('STATUS')!='PASS':raise ValueError('KSM trust/install/remove HOLD must be resolved by genuine Root RTC result')
 rtc=load('exact_ksm_rtc_receipt_parser',HERE.parent/'arm16k_project_lifecycle_rtc/boot.py')
 nonce='0'*32
 frame=('ARM16K_RTC_PROJECT_BEGIN '+nonce+'\n'+''.join(k+'='+str(v)+'\n'for k,v in fields.items())+'ARM16K_RTC_PROJECT_END '+nonce).encode()
 host=fields.get('HOST_BOOT_UTC')
 if type(host)is not int:raise ValueError('actual RTC KSM integer clock receipt required')
 rtc.parse_lifecycle(frame,nonce,host,host+480)
 for key,value in {'UID':'1000','PID1':'systemd','ARCH':'aarch64','PAGESIZE':'16384','LOGIND':'active','DBUS':'active','Service':'login','Type':'tty','Active':'yes'}.items():
  if report.get('session',{}).get(key)!=value:raise ValueError('genuine PAM session proof required')
 for key in ('normal_PAM_logout_observed','QMP_quit_requested','owned_container_absence_verified','owned_container_removed','cleanup_ownership_verified'):
  if report.get(key)is not True:raise ValueError('normal logout and owned retirement required')
 retirement=report.get('QEMU_retirement',{})
 if any(retirement.get(k)!=v for k,v in {'passed':True,'reaped':True,'ownership':'REAPED','group_census':'EMPTY_TWICE','timeout':False,'output_complete':True,'exit':0}.items())or retirement.get('actor_cancelled')or report.get('cleanup_errors')or report.get('cancelled_signals'):raise ValueError('clean owned retirement required')
 if report.get('image_id')!=json.loads((HERE/'inputs.lock.json').read_text())['tool_image_id']:raise ValueError('actual pinned RTC host tool image required')
 return pin(path)
