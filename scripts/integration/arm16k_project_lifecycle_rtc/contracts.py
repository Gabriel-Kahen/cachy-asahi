# SPDX-License-Identifier: MIT
"""Strict external Root kernel/tool authority and live signing-time gates."""
import hashlib,json,re,struct,time
from pathlib import Path
RTC={'CONFIG_RTC_CLASS':'y','CONFIG_RTC_I2C_AND_SPI':'y','CONFIG_RTC_LIB':'y','CONFIG_RTC_HCTOSYS':'y','CONFIG_RTC_HCTOSYS_DEVICE':'"rtc0"','CONFIG_RTC_DRV_PL031':'y','CONFIG_RTC_INTF_SYSFS':'y','CONFIG_RTC_SYSTOHC':'n','CONFIG_RTC_NVMEM':'n','CONFIG_RTC_INTF_PROC':'n','CONFIG_RTC_INTF_DEV':'n'}
METADATA_DELTA={'CONFIG_LOCALVERSION':{'before':'"-generic16k-managed-gui"','after':'"-generic16k-managed-gui-rtc1"'}}
TOOL='sha256:ee1aa3da22a5d89dc1bc273fa818b1d996b7e62851f50d7b629144f6bba9f207'


def pin(path):
 if path.is_symlink()or not path.is_file():raise ValueError('ordinary external material required')
 with path.open('rb')as stream:return {'bytes':path.stat().st_size,'sha256':hashlib.file_digest(stream,'sha256').hexdigest()}


def config(raw):
 values={}
 for line in raw.splitlines():
  if line.startswith('CONFIG_')and'='in line:key,value=line.split('=',1)
  elif re.fullmatch(r'# CONFIG_[A-Za-z0-9_]+ is not set',line):key=line.split()[1];value='n'
  else:continue
  if key in values:raise ValueError('duplicate config option')
  values[key]=value
 return values


def authority(path,digest,actor):
 if not re.fullmatch('[0-9a-f]{64}',digest)or pin(path)['sha256']!=digest:raise ValueError('Root authority digest differs')
 if path.stat().st_size>65536:raise ValueError('authority bound exceeded')
 data=json.loads(path.read_text())
 if set(data)!={'kind','issued_by','tool_image_id','rtc_actor','kernel_bundle','approved_compiler_facts','clock_policy','allow_prepare','allow_boot'}:raise ValueError('finite Root authority fields required')
 if data.get('kind')!='ARM16K_RTC_LIFECYCLE_AUTHORITY_V1'or data.get('issued_by')!='Root':raise ValueError('explicit external Root authority required')
 if data.get('tool_image_id')!=TOOL or data.get('rtc_actor')!=pin(actor):raise ValueError('RTC actor/tool contract differs')
 if not isinstance(data.get('kernel_bundle'),dict)or not re.fullmatch('[0-9a-f]{64}',str(data['kernel_bundle'].get('sha256'))):raise ValueError('actual built kernel bundle required; pending refuses')
 if type(data.get('approved_compiler_facts'))is not dict:raise ValueError('explicit finite compiler fact approval required')
 if data.get('clock_policy')!={'host_skew_seconds':5,'max_start_delay_seconds':30,'max_guest_elapsed_seconds':480}:raise ValueError('fixed real-UTC bounds required')
 return data


def kernel(directory,approved,baseline):
 if directory.is_symlink()or {p.name for p in directory.iterdir()}!={'Image','config','bundle.json'}:raise ValueError('exact three-file kernel bundle required')
 manifest=directory/'bundle.json'
 if pin(manifest)!=approved['kernel_bundle']:raise ValueError('external RTC bundle pin differs')
 if manifest.stat().st_size>1048576 or(directory/'config').stat().st_size>262144 or(directory/'Image').stat().st_size>67108864:raise ValueError('kernel bundle bound exceeded')
 bundle=json.loads(manifest.read_text())
 if bundle.get('schema_version')!=1 or bundle.get('kind')!='ARM16K_RTC_REFERENCE_KERNEL_BUNDLE_V1'or bundle.get('status')!='BUILT_ONLY_RTC_BOOT_NOT_RUN':raise ValueError('built-only RTC bundle required')
 if bundle.get('kernel_release')!='7.1.13-generic16k-managed-gui-rtc1':raise ValueError('RTC release differs')
 for name in ('Image','config'):
  if pin(directory/name)!=bundle['files'][name]:raise ValueError('RTC payload differs')
 # image_size is the effective memory span (_end-_text), including BSS;
 # it is independent of the separately enforced64MiB file-byte cap.
 with (directory/'Image').open('rb')as stream:head=stream.read(64)
 if len(head)!=64 or head[56:60]!=b'ARM\x64'or struct.unpack_from('<Q',head,24)[0]&1 or(struct.unpack_from('<Q',head,24)[0]>>1)&3!=2 or not 0<struct.unpack_from('<Q',head,16)[0]<=134217728:raise ValueError('16K ARM64 Image required')
 old=config(baseline.read_text());new=config((directory/'config').read_text())
 for key,value in RTC.items():
  if new.get(key,'n')!=value:raise ValueError('RTC prerequisite differs: '+key)
 for key in ('CONFIG_ARM64_16K_PAGES','CONFIG_ARM_AMBA','CONFIG_VIRTIO_MMIO','CONFIG_VIRTIO_BLK','CONFIG_EXT4_FS'):
  if new.get(key)!='y':raise ValueError('baseline guest feature lost')
 if new.get('CONFIG_MODULES','n')!='n':raise ValueError('builtin-only kernel required')
 proof=bundle['config_proof'];compiler=approved['approved_compiler_facts']
 if proof.get('baseline')!=pin(baseline)or proof.get('rtc_required')!=RTC or proof.get('compiler_facts')!=compiler or proof.get('non_rtc_features_unchanged')is not True:raise ValueError('config proof/finite compiler facts differ')
 delta={key:{'before':old.get(key,'n'),'after':new.get(key,'n')}for key in old.keys()|new.keys()if old.get(key,'n')!=new.get(key,'n')}
 features=proof['feature_delta']
 if any(features.get(k)!=v for k,v in METADATA_DELTA.items()):raise ValueError('exact release metadata delta required')
 if set(features)-(RTC.keys()|METADATA_DELTA.keys())or set(features)&set(compiler)or{**features,**compiler}!=delta:raise ValueError('unapproved config delta; no prefix exceptions')
 source=bundle['source']
 if source.get('revision')!='94fb23346d522edf53722357c426a3e58030beea'or source.get('original_source')!='4056e2505ed7081674e949e0460258672cce14ff'or source.get('original_run')!=39156901928:raise ValueError('kernel source lineage differs')
 if source.get('archive')!={'bytes':262965559,'sha256':'874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad'}:raise ValueError('kernel source archive differs')
 tool=bundle['toolchain'];build=bundle['build']
 if tool.get('mode')not in ('NATIVE_ARM64','HOST_CROSS_ARM64')or not re.fullmatch('[0-9a-f]{64}',str(tool.get('profile_sha256')))or not tool.get('actual_tools')or tool.get('same_toolchain')is not False:raise ValueError('actual explicit toolchain facts required')
 if not build.get('commands')or not build.get('actual_started_utc')or not build.get('actual_finished_utc'):raise ValueError('actual build facts required, no pending substitution')
 if any(bundle.get(k)!='NOT RUN'for k in ('guest_boot','native16K','M2'))or bundle.get('release_accepted')is not False:raise ValueError('bundle acceptance scope differs')
 return bundle


def signing(receipt,lock,now=None):
 if pin(receipt)!={k:lock['Root_signing_receipt'][k]for k in ('bytes','sha256')}:raise ValueError('fresh Root signing receipt differs')
 if receipt.stat().st_size>32768:raise ValueError('signing receipt bound exceeded')
 data=json.loads(receipt.read_text());spec=lock['Root_signing_receipt'];now=time.time()if now is None else now
 if data.get('issued_by')!='Root'or data.get('private_key_supplied_to_actors')is not False or data.get('signer_fingerprint')!=spec['signer']:raise ValueError('fresh signing authority differs')
 if(data.get('key_created_epoch'),data.get('key_expires_epoch'))!=(spec['created_epoch'],spec['expires_epoch'])or not spec['created_epoch']<=now<spec['expires_epoch']:raise ValueError('actual current UTC outside fresh TEST key validity')
 for field,name in (('archive','cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz'),('signature','cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz.sig'),('public_key','TEST-public.asc')):
  if data.get(field)!={k:lock['materials'][name][k]for k in ('bytes','sha256')}:raise ValueError('authorized signing byte lineage differs')
 return {key:data[key]for key in ('issued_by','archive','signature','public_key','signer_fingerprint','key_created_epoch','key_expires_epoch','private_key_supplied_to_actors')}
