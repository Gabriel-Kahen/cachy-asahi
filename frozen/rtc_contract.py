#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure finite RTC config construction and independent final-config checks."""
import hashlib,json,re,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
RTC={'CONFIG_RTC_CLASS':'y','CONFIG_RTC_LIB':'y','CONFIG_RTC_HCTOSYS':'y','CONFIG_RTC_HCTOSYS_DEVICE':'"rtc0"','CONFIG_RTC_SYSTOHC':'n','CONFIG_RTC_NVMEM':'n','CONFIG_RTC_INTF_SYSFS':'y','CONFIG_RTC_INTF_PROC':'n','CONFIG_RTC_INTF_DEV':'n','CONFIG_RTC_DRV_PL031':'y','CONFIG_RTC_I2C_AND_SPI':'y'}
BASELINE_OFF={'CONFIG_ARM64_LSUI':'n','CONFIG_WARN_CONTEXT_ANALYSIS':'n'}
CHANGES={**RTC,'CONFIG_LOCALVERSION':'"-generic16k-managed-gui-rtc1"'}
# Names only are not exemptions. Every accepted before/after value must appear
# in the independently reviewed, externally SHA-pinned configure result table.
COMPILER_NAMES={'CONFIG_AS_HAS_LSUI','CONFIG_AS_VERSION','CONFIG_CC_CAN_LINK','CONFIG_CC_HAS_ASSUME','CONFIG_CC_HAS_BROKEN_COUNTED_BY_REF','CONFIG_CC_HAS_COUNTED_BY','CONFIG_CC_HAS_COUNTED_BY_PTR','CONFIG_CC_HAS_MULTIDIMENSIONAL_NONSTRING','CONFIG_CC_HAS_SANCOV_STACK_DEPTH_CALLBACK','CONFIG_CC_VERSION_TEXT','CONFIG_CLANG_VERSION','CONFIG_LD_CAN_USE_KEEP_IN_OVERLAY','CONFIG_LLD_VERSION','CONFIG_OPENSSL_SUPPORTS_ML_DSA','CONFIG_PAHOLE_VERSION'}


def pin(path):
 path=Path(path)
 if path.is_symlink() or not path.is_file():raise ValueError('ordinary input required')
 with path.open('rb') as f:return {'bytes':path.stat().st_size,'sha256':hashlib.file_digest(f,'sha256').hexdigest()}


def checked(path,ref):
 if pin(path)!={k:ref[k] for k in ('bytes','sha256')}:raise ValueError('input pin differs: '+str(path))
 return path


def lock():return json.loads((HERE/'inputs.lock.json').read_text())


def data():
 for name,ref in lock()['data'].items():checked(HERE/'data'/name,ref)
 return (HERE/'data/baseline.config').read_bytes()


def values(raw):
 result={}
 for line in raw.decode('ascii').splitlines():
  match=re.fullmatch(r'(CONFIG_[A-Za-z0-9_]+)=(.*)',line)
  off=re.fullmatch(r'# (CONFIG_[A-Za-z0-9_]+) is not set',line)
  if match or off:
   key,value=(match[1],match[2]) if match else (off[1],'n')
   if key in result:raise ValueError('duplicate config assignment: '+key)
   result[key]=value
  elif line.startswith(('CONFIG_','# CONFIG_')):raise ValueError('malformed config assignment')
 return result


def delta(before,after):
 a,b=values(before),values(after)
 return {k:{'before':a.get(k,'n'),'after':b.get(k,'n')} for k in sorted(a.keys()|b.keys()) if a.get(k,'n')!=b.get(k,'n')}


def construct(raw):
 if raw!=data():raise ValueError('exact original config required')
 baseline=values(raw)
 if baseline.get('CONFIG_RTC_CLASS')!='n':raise ValueError('original RTC class must be disabled')
 out=[]
 for line in raw.decode('ascii').splitlines(keepends=True):
  if line.startswith('CONFIG_LOCALVERSION='):out.append('CONFIG_LOCALVERSION='+CHANGES['CONFIG_LOCALVERSION']+'\n')
  elif line=='# CONFIG_RTC_CLASS is not set\n':
   out.extend(k+'='+v+'\n' if v!='n' else '# '+k+' is not set\n' for k,v in RTC.items())
  else:out.append(line)
 candidate=seed_off(''.join(out).encode('ascii'))
 if values(candidate)!={**baseline,**CHANGES,**BASELINE_OFF}:raise ValueError('requested config is not exact RTC/localversion/off-seed overlay')
 return candidate


def seed_off(raw):
 parsed=values(raw)
 if any(parsed.get(k,'n')!='n' for k in BASELINE_OFF):raise ValueError('off-seed original semantic n required')
 lines=raw.decode('ascii').splitlines(keepends=True);seen=set();out=[]
 for line in lines:
  key=next((k for k in BASELINE_OFF if line.startswith(k+'=') or line.rstrip('\n')=='# '+k+' is not set'),None)
  if key is None:out.append(line)
  else:out.append('# '+key+' is not set\n');seen.add(key)
 for key in BASELINE_OFF:
  if key in seen:continue
  if out and not out[-1].endswith('\n'):out.append('\n')
  out.append('# '+key+' is not set\n')
 return ''.join(out).encode('ascii')


def inverse(candidate):
 original=data()
 if candidate!=construct(original):raise ValueError('changed candidate cannot be inverted as the declared overlay')
 return original


def dependencies():
 text=(HERE/'data/rtc.Kconfig').read_text();base=values(data())
 classified=json.loads((HERE/'data/configure-r2-facts.json').read_text())
 if set(classified['genuine_compiler_auxiliary_facts'])!=COMPILER_NAMES:raise ValueError('exact validated configure fact whitelist differs')
 if set(classified['prompted_original_off'])!=set(BASELINE_OFF):raise ValueError('exact prompted baseline-off source classification differs')
 for key in BASELINE_OFF:
  definition=classified['definitions'][key]['text']
  if not re.search(r'\n\s+bool "',definition) or base.get(key,'n')!='n':raise ValueError('prompted original-off feature proof differs: '+key)
 def stanza(name):
  match=re.search(r'^(?:menu)?config '+name+r'\n(.*?)(?=^(?:menu)?config |\Z)',text,re.M|re.S)
  if not match:raise ValueError('missing original RTC Kconfig symbol: '+name)
  return match[1]
 for symbol,fragment in [('RTC_CLASS','depends on !S390'),('RTC_CLASS','select RTC_LIB'),('RTC_DRV_PL031','depends on ARM_AMBA'),('RTC_HCTOSYS','default y'),('RTC_HCTOSYS_DEVICE','depends on RTC_HCTOSYS'),('RTC_HCTOSYS_DEVICE','default "rtc0"'),('RTC_INTF_SYSFS','depends on SYSFS')]:
  if fragment not in stanza(symbol):raise ValueError('RTC dependency source differs: '+symbol)
 for key in ('CONFIG_ARM64','CONFIG_ARM64_16K_PAGES','CONFIG_ARM_AMBA','CONFIG_OF','CONFIG_HAS_IOMEM','CONFIG_SYSFS','CONFIG_VIRTIO_MMIO','CONFIG_VIRTIO_BLK','CONFIG_EXT4_FS','CONFIG_UNIX98_PTYS','CONFIG_SERIAL_AMBA_PL011_CONSOLE'):
  if base.get(key)!='y':raise ValueError('existing generic reference prerequisite differs: '+key)
 if any(base.get(k,'n')!='n' for k in ('CONFIG_S390','CONFIG_MODULES','CONFIG_ARM64_4K_PAGES','CONFIG_ARM64_64K_PAGES','CONFIG_LOCALVERSION_AUTO')):raise ValueError('architecture/module/localversion policy differs')
 make=(HERE/'data/rtc.Makefile').read_text()
 if 'obj-$(CONFIG_RTC_DRV_PL031)' not in make or 'rtc-pl031.o' not in make:raise ValueError('builtin driver make binding differs')
 helper=stanza('RTC_I2C_AND_SPI')
 if any(s in helper for s in ('select ','imply ')) or 'tristate\n' not in helper or 'default y if I2C=y' not in helper or 'default y if SPI_MASTER=y' not in helper or 'CONFIG_RTC_I2C_AND_SPI' in make:raise ValueError('exact derived RTC helper/no-object proof differs')
 if base.get('CONFIG_I2C')!='y' or base.get('CONFIG_SPI','n')!='n' or base.get('CONFIG_SPI_MASTER','n')!='n':raise ValueError('held original I2C-on/SPI-off prerequisites differ')
 return {'rtc_required':RTC,'existing_dependencies_held':True,'driver':'PL031 builtin','clock_seed':'RTC_HCTOSYS rtc0','clock_writes':'RTC_SYSTOHC disabled','runtime':'NOT RUN'}


def final_config(raw,compiler_facts):
 original=data();requested=construct(original);a,b=values(requested),values(raw);old=values(original)
 facts={}
 for key,row in compiler_facts.items():
  if key in CHANGES or key in BASELINE_OFF or key not in COMPILER_NAMES:raise ValueError('not an explicit disjoint validated compiler/auxiliary fact: '+key)
  if set(row)!={'before','after'} or row['before']!=old.get(key,'n') or a.get(key,'n')!=old.get(key,'n') or not isinstance(row['after'],str):raise ValueError('exact original-baseline compiler before/after required')
  facts[key]=row['after']
 expected={**a,**facts}
 for key in expected.keys()|b.keys():
  if expected.get(key,'n')!=b.get(key,'n'):raise ValueError('unprofiled final config change: '+key)
 dependencies()
 return {'baseline':pin(HERE/'data/baseline.config'),'requested':{'bytes':len(requested),'sha256':hashlib.sha256(requested).hexdigest()},'feature_delta':delta(original,requested),'compiler_facts':compiler_facts,'rtc_required':RTC,'non_rtc_features_unchanged':True}


IMAGE_FILE_CAP=64*1024**2
IMAGE_MEMORY_CAP=128*1024**2


def header_fields(path):
 path=Path(path)
 with path.open('rb') as f:raw=f.read(64)
 fields={'header_bytes':len(raw),'file_bytes':path.stat().st_size,'header_sha256':hashlib.sha256(raw).hexdigest(),'magic_hex':raw[56:60].hex()}
 if len(raw)==64:fields.update(text_offset=struct.unpack_from('<Q',raw,8)[0],effective_image_size=struct.unpack_from('<Q',raw,16)[0],flags=struct.unpack_from('<Q',raw,24)[0])
 return raw,fields


def header(path):
 raw,fields=header_fields(path)
 if len(raw)!=64 or raw[56:60]!=b'ARM\x64':raise ValueError('ARM64 Image header required')
 flags=fields['flags']
 if flags&1 or (flags>>1)&3!=2:raise ValueError('little-endian16K Image required')
 if not 64<=fields['file_bytes']<=IMAGE_FILE_CAP or not 0<fields['effective_image_size']<=IMAGE_MEMORY_CAP:raise ValueError('64MiB file/128MiB effective memory span bounds required')
 return {'bytes':64,'sha256':fields['header_sha256'],'page_size':16384,'file_bytes':fields['file_bytes'],'effective_image_size':fields['effective_image_size']}


def bundle(image,config,profile,profile_sha256,actual_tools,commands,started,finished):
 header(image);proof=final_config(config.read_bytes(),profile['compiler_facts']);spec=lock()
 return {'schema_version':1,'kind':'ARM16K_RTC_REFERENCE_KERNEL_BUNDLE_V1','status':'BUILT_ONLY_RTC_BOOT_NOT_RUN','kernel_release':spec['kernel_release'],'files':{'Image':pin(image),'config':pin(config)},'source':{'revision':spec['upstream_revision'],'archive':{k:spec['archive'][k] for k in ('bytes','sha256')},'original_source':spec['original_native_source'],'original_run':spec['original_run']},'config_proof':proof,'toolchain':{'mode':profile['mode'],'profile_sha256':profile_sha256,'actual_tools':actual_tools,'original_receipt':pin(HERE/'data/original-build-receipt.json'),'same_toolchain':False},'build':{'commands':commands,'actual_started_utc':started,'actual_finished_utc':finished},'guest_boot':'NOT RUN','native16K':'NOT RUN','M2':'NOT RUN','release_accepted':False}
