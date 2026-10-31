# SPDX-License-Identifier: MIT
"""Private KSM scalar-test kernel derivative; historical profiles are held."""
import ast,hashlib,json,os,stat,sys,types
from pathlib import Path
BASE="scripts/ci/managed-gui-generic16k/"
OLD="MANAGED_GUI_GENERIC16K_DIAGNOSTIC_V1"
PROFILE="KSM_ADVICE_GENERIC16K_DIAGNOSTIC_V1"
PINS={'build_kernel.py': {'bytes': 12900, 'sha256': 'ccbead2912144c5aa4fcb3ce7af76b3c11f28fcde7987e5f32edb060ff7b0ee9'}, 'kernel.fragment': {'bytes': 1808, 'sha256': '88819f00ebef80e385ebdfae6cc101ef21145e0bbd6bb12532b0d41a85c16d28'}, 'kernel_contract.py': {'bytes': 4659, 'sha256': '30a4544e5407dbf932d9ec26bbd6bf21eab53347544afa134cd3a5870752cbff'}, 'run.py': {'bytes': 10493, 'sha256': '64e279b7ce4b04f115a7e1897377ce59ea5c15010a97a0f22cf16e35ce5e7e46'}}

def need(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):
 path=Path(path);st=path.lstat()
 need(not any(p.is_symlink()for p in(path,*path.parents))and stat.S_ISREG(st.st_mode)and st.st_nlink==1 and 0<st.st_size<=262144,"ordinary bounded kernel source required")
 raw=path.read_bytes();need(len(raw)==st.st_size,"kernel source length drift");return raw
def held(root,name):
 raw=read(Path(root)/BASE/name);need(dict(bytes=len(raw),sha256=sha(raw))==PINS[name],"whole historical GUI kernel source differs: "+name);return raw
def one(text,old,new):
 need(text.count(old)==1,"counted ksm profile anchor differs");return text.replace(old,new)
def fragment(raw):
 need(dict(bytes=len(raw),sha256=sha(raw))==PINS['kernel.fragment'],"whole historical fragment differs")
 need(b'CONFIG_ARM64_16K_PAGES=y\n'in raw and b'CONFIG_MODULES=n\n'in raw and b'CONFIG_KSM='not in raw,"exact single private16K builtin KSM profile")
 return raw+b'CONFIG_KSM=y\nCONFIG_ADVISE_SYSCALLS=y\n'
def build_helper(raw):
 need(dict(bytes=len(raw),sha256=sha(raw))==PINS['build_kernel.py'],"whole historical build helper differs")
 return one(raw.decode(),repr(OLD),repr(PROFILE)).encode()
def contract_bytes(root):
 raw=held(root,'kernel_contract.py');text=one(raw.decode(),repr(OLD),repr(PROFILE))
 derived=fragment(held(root,'kernel.fragment'));helper=build_helper(held(root,'build_kernel.py'))
 for name,value in (('HELPER_SHA',sha(helper)),('FRAGMENT_SHA',sha(derived)),('DIAGNOSTIC_SHA',sha(derived+b'CONFIG_KALLSYMS=y\nCONFIG_PRINTK_TIME=y\n'))):
  tree=ast.parse(text);node=next(n for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name)
  text=one(text,ast.get_source_segment(text,node),name+'='+repr(value))
 return text.encode()
def module(raw,name,path):
 result=types.ModuleType(name);result.__file__=str(path);exec(compile(raw,str(path),'exec'),result.__dict__);return result
def contract(root):return module(contract_bytes(root),'_private_gui_ksm_contract',Path(root)/BASE/'kernel_contract.py')
def helper(root):return module(build_helper(held(root,'build_kernel.py')),'_private_gui_ksm_build',Path(root)/BASE/'build_kernel.py')
def check_config(path):
 lines=read(path).decode().splitlines();values={}
 for line in lines:
  if line.startswith('CONFIG_'):
   name,value=line.split('=',1);need(name not in values,"duplicate kernel configuration value");values[name]=value
 need(all(values.get(n)=="y"for n in('CONFIG_MMU','CONFIG_KSM','CONFIG_XXHASH','CONFIG_SYSFS','CONFIG_ARM64_16K_PAGES','CONFIG_ADVISE_SYSCALLS'))and values.get('CONFIG_MODULES','n')=='n',"exact private KSM profile and Kconfig-selected XXHASH required")
def prepare_kernel(root,directory):
 root=Path(root);directory=Path(directory)
 need(directory.is_dir()and not any(p.is_symlink()for p in(directory,*directory.parents))and directory.stat().st_uid==os.getuid(),"owned ordinary copied kernel helper directory")
 need({p.name for p in directory.iterdir()}=={'build_kernel.py','kernel.fragment'},"exact initial copied helper closure")
 for name in('build_kernel.py','kernel.fragment'):need(read(directory/name)==held(root,name),"copied historical kernel input differs")
 (directory/'build_kernel.py').write_bytes(build_helper(held(root,'build_kernel.py')));(directory/'kernel.fragment').write_bytes(fragment(held(root,'kernel.fragment')))
def kernel(original,args):
 raw=held(args.source,'run.py');tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='kernel');text=ast.get_source_segment(raw.decode(),node)
 text=one(text,"helper=s.load(args.source,'scripts/ci/managed-gui-generic16k/build_kernel.py')","helper=KP.helper(args.source);helper.HERE=Path(receipt['helper']['path']).parent")
 text=one(text,"K=s.load(args.source,'scripts/ci/managed-gui-generic16k/kernel_contract.py')","K=KP.contract(args.source)")
 text=one(text,"fragment=s.read(s.HERE/'kernel.fragment')","fragment=KP.fragment(s.read(s.HERE/'kernel.fragment'))")
 text=one(text,"s.sha(s.read(s.HERE/'build_kernel.py'))","KP.sha(KP.build_helper(KP.held(args.source,'build_kernel.py')))")
 text=one(text,'    return profile,receipt,image,config','    KP.check_config(config)\n    return profile,receipt,image,config')
 namespace=dict(original.__dict__,KP=sys.modules[__name__]);exec(compile(text,'<whole-pinned-private-gui-ksm-kernel>','exec'),namespace);return namespace['kernel'](args)
