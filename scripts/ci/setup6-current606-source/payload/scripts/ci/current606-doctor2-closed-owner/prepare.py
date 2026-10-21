#!/usr/bin/env python3
"""Reproduce this exact closed Setup606 source; no actors or selection reset."""
import argparse,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
ARCHIVE20_NATIVE4={'libei-1.6.0-1-aarch64.pkg.tar.xz','libei-1.6.0-1-aarch64.pkg.tar.xz.sig','libgudev-238-3-aarch64.pkg.tar.xz','libgudev-238-3-aarch64.pkg.tar.xz.sig'}

def seed_archive20_native(helper,policy,inputs,native_inputs,cache,destination):
 """Full20 cache custody; exactly four native-base files copied, never full20 credit."""
 import ast,importlib.util
 raw=Path(helper).read_bytes();C.need(C.pin(raw)==dict(bytes=11096,sha256='e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968'),'whole archive20 helper source')
 C.need(C.pin(Path(policy).read_bytes())==dict(bytes=6155,sha256='1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae'),'whole archive20 policy source')
 spec=importlib.util.spec_from_file_location('_archive20_native_subset',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);v=module.policy(policy,inputs)
 native_raw=module.read(native_inputs,1024**2);module.need(module.pin(native_raw)==dict(bytes=328101,sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'),'whole original native-base lock')
 native={}
 for row in json.loads(native_raw)['packages']:
  native[row['filename']]=dict(bytes=row['size'],sha256=row['sha256']);native[row['filename']+'.sig']=dict(bytes=row['signature_size'],sha256=row['signature_sha256'])
 selected={n:r for n,r in v['files'].items()if n in native};module.need(set(selected)==ARCHIVE20_NATIVE4 and all({k:r[k]for k in('bytes','sha256')}==native[n]for n,r in selected.items()),'exact4 native-base intersection of whole20; no other files')
 module.checked_index(cache,v)
 for n,row in v['files'].items():module.digest_file(Path(cache)/n,row)
 # Derive only the original exact copy loop's finite iterable and honest receipt.
 tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='seed_exact');old=ast.get_source_segment(raw.decode(),node)
 before="for name,row in v['files'].items():";after='for name,row in selected.items():';module.need(old.count(before)==1,'one original exact seed loop')
 receipt="return dict(status='EXACT_ORIGINAL20_SEEDED_BEFORE_UNCHANGED_BUILD',files=20,bytes=TOTAL,original_inputs=v['original_inputs'])"
 replacement="return dict(status='EXACT_NATIVE_BASE4_FROM_ARCHIVE20_SEEDED_NOT_FULL20',files=4,bytes=sum(r['bytes']for r in selected.values()),original_inputs=v['original_inputs'])"
 module.need(old.count(receipt)==1,'one original seed receipt');new=old.replace(before,after).replace(receipt,replacement);module.need(new.replace(after,before).replace(replacement,receipt)==old,'whole seed function inverse')
 space=dict(vars(module),selected=selected);exec(compile(new,'<source-owned-exact4-archive20-subset>','exec'),space)
 return space['seed_exact'](cache,destination,v)

ARCHIVE8_NATIVE8={name+suffix for name in('libx11-1.8.13-2-aarch64.pkg.tar.xz','libxi-1.8.3-1-aarch64.pkg.tar.xz','libxrender-0.9.12-1-aarch64.pkg.tar.xz','libxtst-1.2.5-1-aarch64.pkg.tar.xz')for suffix in('','.sig')}

def seed_archive8_native(helper,policy,inputs,native_inputs,cache,destination):
 import importlib.util
 C.checked(Path(helper),dict(bytes=11040,sha256='5e24808152c727f5dcd19252c66e1ab121bdb9dbd6b90becb943820634898565'));C.checked(Path(policy),dict(bytes=2589,sha256='2b21c05d30a9c5efd2f717cfa8475c9de3150d7729f710b348b70a84f5b16e20'))
 spec=importlib.util.spec_from_file_location('_source_owned_archive8_native_seed',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 v=module.policy(Path(policy),Path(inputs));raw=module.read(Path(native_inputs),1024**2);expected=dict(bytes=328101,sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f');module.need(module.pin(raw)==expected,'whole original native-base lock required')
 native={}
 for row in json.loads(raw)['packages']:
  native[row['filename']]=dict(bytes=row['size'],sha256=row['sha256']);native[row['filename']+'.sig']=dict(bytes=row['signature_size'],sha256=row['signature_sha256'])
 files={n:{k:row[k]for k in('bytes','sha256')}for n,row in v['files'].items()}
 module.need(set(files)==ARCHIVE8_NATIVE8 and len(files)==8 and set(files)&set(native)==set(files)and all(native[n]==row for n,row in files.items())and sum(row['bytes']for row in files.values())==2220315,'exact full8 original native-base intersection required')
 result=module.seed_exact(Path(cache),Path(destination),v);module.need(result['files']==8 and result['bytes']==2220315,'complete8 native seed required');result.update(native_inputs=expected,native_base_files=8,native_base_scope='EXACT_FULL8_UNCHANGED_ORIGINAL_NATIVE_INPUTS_DATA_ONLY');return result

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();fact=C.verify();target=a.output.absolute();C.need(not target.exists()and target.parent.is_dir()and not any(p.is_symlink()for p in(target,*target.parents))and not target.is_relative_to(C.ROOT)and not C.ROOT.is_relative_to(target),'fresh disjoint output');shutil.copytree(C.ROOT,target,ignore=shutil.ignore_patterns('.git','__pycache__'));print(json.dumps(dict(status='SOURCE_ONLY_SETUP606_PACKAGE_PRESERVATION',files=fact['files'],actual=None,full606_real_shell='NOT_RUN',Apps7='NOT_RUN')))
