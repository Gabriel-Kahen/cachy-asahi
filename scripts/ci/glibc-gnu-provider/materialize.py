#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the complete official GNU2.43 release and materialize an offline bundle.

Data hashing, tar inspection and public-only gpgv; no source/recipe execution.
Derived payload tree identity does not claim an upstream Git revision.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import re
import shutil
import tarfile
import time


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(path):
    with Path(path).open('rb') as file:return hashlib.file_digest(file,'sha256').hexdigest()


def blob(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()


def inspect(path,expected_tree,limits):
    need(Path(path).is_file() and not Path(path).is_symlink() and Path(path).stat().st_size<=limits['source_compressed'],'bounded ordinary source archive required')
    deadline=time.monotonic()+limits['seconds'];entries={};total=0;root=None;directories=set()
    class Decoded:
        def __init__(self,stream):self.stream=stream;self.count=0
        def read(self,size):
            need(time.monotonic()<deadline and 0<=size<=1024**2,'bounded source decoder request')
            data=self.stream.read(size);self.count+=len(data)
            need(self.count<=limits['source_bytes']+limits['source_members']*1024,'decoded tar byte bound')
            return data
    with gzip.open(path,'rb') as stream,tarfile.open(fileobj=Decoded(stream),mode='r|') as archive:
        for count,member in enumerate(archive,1):
            need(time.monotonic()<deadline and count<=limits['source_members'],'source member/deadline bound')
            need(not member.mode&0o7000,'ordinary source mode required')
            parts=PurePosixPath(member.name).parts
            need(parts and not member.name.startswith('/') and '..' not in parts and '\0' not in member.name and
                 member.name.rstrip('/')=='/'.join(parts),'canonical archive member required')
            if root is None:root=parts[0];need(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',root),'source root name differs')
            need(parts[0]==root,'one source root required')
            if len(parts)==1:need(member.isdir(),'source root must be directory');continue
            name='/'.join(parts[1:]);need(name not in entries and name not in directories,'duplicate source path')
            if member.isdir():directories.add(name);continue
            need(not member.sparse and not member.islnk() and (member.isfile() or member.issym()) and not member.mode&0o7000,'ordinary source file/link required')
            need(member.size<=limits['source_file'],'source file bound');total+=member.size;need(total<=limits['source_bytes'],'source bytes bound')
            if member.issym():
                data=member.linkname.encode();target=PurePosixPath(name).parent/PurePosixPath(member.linkname)
                need(not member.linkname.startswith('/') and '\0' not in member.linkname,'relative source link required')
                depth=0
                for part in target.parts:
                    depth+=-1 if part=='..' else 0 if part=='.' else 1
                    need(depth>=0,'source link escapes root')
                mode='120000'
            else:
                data=archive.extractfile(member).read(limits['source_file']+1);need(len(data)==member.size,'source file changed/truncated')
                mode='100755' if member.mode&0o111 else '100644'
            entries[name]=(mode,blob(data))
    tree={}
    for name,(mode,digest) in entries.items():
        node=tree
        for part in name.split('/')[:-1]:
            need(not (part in node and not isinstance(node[part],dict)),'source parent alias')
            node=node.setdefault(part,{})
        need(name.split('/')[-1] not in node,'source leaf/directory collision');node[name.split('/')[-1]]=(mode,digest)
    def encode(node):
        rows=[]
        for name,value in node.items():
            directory=isinstance(value,dict);mode,digest=('40000',encode(value)) if directory else value
            rows.append(((name+('/' if directory else '')).encode(),mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(digest)))
        data=b''.join(value for _,value in sorted(rows));return hashlib.sha1(b'tree '+str(len(data)).encode()+b'\0'+data).hexdigest()
    actual=encode(tree);need(expected_tree is None or actual==expected_tree,'complete upstream Git tree differs')
    parents={str(parent) for name in entries for parent in PurePosixPath(name).parents if str(parent)!='.'}
    need(directories<=parents,'unexpected empty source directories')
    need(all(name in entries for name in ('configure','Makefile','COPYINGv2','COPYING.LESSERv2','COPYING.LIB','LICENSES')),'complete source/license roots required')
    return dict(root=root,payload_tree=actual,files=len(entries),bytes=total,sha256=sha(path))


RELEASE='2.43'
PREFIX='/usr'
ARCHIVE='glibc-2.43.tar.gz'
ARCHIVE_SHA='e1e622cbd635019090fa23260e5d9ec219b12f97ae7ae02f033d4ae42cf2c004'
PAYLOAD_TREE='97ac10e146c65ecbd22d36e3743eb5b5e9166ae9'
PRIMARY='35B17DF5752577CA0C541CEB94BFDF4484AD142F'
SUBKEY='FD19E6D31B192EE4DC63EAD3DC2B16215ED5412A'
LIMITS=dict(seconds=180,source_compressed=96*1024**2,source_bytes=512*1024**2,source_members=60000,source_file=64*1024**2)


PATCH_FILES={'0001-mount-macro-guards.patch': '09117692cd3a1d5838ea700df68b512f9f625a6d2af497a1afcf92046deca8f5', '0002-held-builder-test-expectations.patch': 'f730c778ba51f9e525c9f6a7949a76af00364d49f41eedb5d73b8e86a3d4c132'}

def verify_patches(recipe,lock):
    rows=lock['patch_order']
    need(type(rows) is list and all(type(r) is dict for r in rows) and [r.get('path') for r in rows]==list(PATCH_FILES),'exact reviewed patch order required')
    for row in rows:
        name=row['path'];path=Path(recipe)/name
        need(row.get('sha256')==PATCH_FILES[name] and path.is_file() and not path.is_symlink() and sha(path)==PATCH_FILES[name], 'reviewed patch bytes differ: '+name)


def verify_configuration(recipe,lock):
    text=(Path(recipe)/'PKGBUILD').read_text()
    need(sha(Path(recipe)/'PKGBUILD')=='a2d08f4786879a86af14cccf1cffe21811aa8dfa4428559848fa4cede839ab64',
         'exact reviewed conventional provider recipe required')
    helper=Path(recipe)/'stage.py'
    need(helper.is_file() and not helper.is_symlink() and
         sha(helper)==lock['packaging']['stage_helper_sha256']=='43b1b441dcc384379ab80c4864bbf7ffd898d56e4ba629c0faa966c25a979e6c',
         'exact reviewed provider staging source required')
    need(lock['pkgrel']==1 and lock['layout'].get('multiarch')=='disabled' and
         lock['feature_choices'].get('multiarch')=='disabled', 'baseline non-multiarch policy required')
    need(re.search(r'^pkgrel=1$',text,re.M) and text.count('--disable-multi-arch')==1 and
         '\n    --disable-multi-arch \\\n' in text and '--enable-multi-arch' not in text,
         'concrete provider pkgrel1 non-multiarch configure option required')


def signature_status(text,returncode):
    rows=[line.removeprefix('[GNUPG:] ').split() for line in text.splitlines() if line.startswith('[GNUPG:] ')]
    valid=[row for row in rows if row[0]=='VALIDSIG']
    need(returncode==0 and len(valid)==1 and len(valid[0])==11 and valid[0][1]==SUBKEY and valid[0][-1]==PRIMARY and
         valid[0][3]=='1769208137','exact GNU release signature required')
    need(not any(row[0] in ('BADSIG','ERRSIG','REVKEYSIG','NO_PUBKEY','NODATA','FAILURE','EXPSIG') for row in rows),'bad/revoked/expired signature refused')
    return dict(status='CRYPTOGRAPHICALLY_VALID_GNU_PUBLISHER_KEYRING',primary_fingerprint=PRIMARY,subkey_fingerprint=SUBKEY,
                current_key_expiration_reported=any(row[0] in ('KEYEXPIRED','EXPKEYSIG') for row in rows),
                trust='UNSELECTED; GNU HTTPS publisher keyring, no independent pretrusted fingerprint authority',
                gpg_status=text,returncode=returncode)


def verify_release(inputs,lock):
    import subprocess,tempfile
    need(inputs is not None,'MISSING_PREREQUISITE: three exact official release inputs')
    inputs=Path(inputs).resolve(strict=True)
    need(lock['prefix']==PREFIX and lock['version']=='2.43.caa1' and lock['pkgrel']==1 and lock['layout'].get('multiarch')=='disabled' and
         lock['layout']['gettext_catalogs']=='/usr/share/locale' and len(('/usr/share/locale').encode())+1==18, 'ABI-preserving conventional /usr layout required')
    need(lock['release']==RELEASE and lock['source']['sha256']==ARCHIVE_SHA and lock['payload_tree']==PAYLOAD_TREE and
         lock['name']=='cachy-asahi-glibc-gnu-provider' and [r.get('path') for r in lock['patch_order']]==list(PATCH_FILES),'separate official release identity required')
    need([(r['path'],r['bytes'],r['sha256']) for r in lock['public_inputs']]==[
        (ARCHIVE,40287809,ARCHIVE_SHA),
        (ARCHIVE+'.sig',1018,'bfd0c5a9924e4f084281cd2f3ba96e5c6e87a6d363113e7a0f98c5151463c9e3'),
        ('gnu-keyring.gpg',3698125,'0fe55175b96a8ea1c4b670cc3fe11d56b341e4eff81b161ea49958ae550be6ca')],
        'exact retained original GNU public input set required')
    for row in lock['public_inputs']:
        need(Path(row['path']).name==row['path'],'flat public input required')
        path=inputs/row['path']
        need(path.is_file() and not path.is_symlink() and path.stat().st_size==row['bytes'] and sha(path)==row['sha256'],'official input hash/size differs: '+row['path'])
    need({row['path'] for row in lock['public_inputs']}=={ARCHIVE,ARCHIVE+'.sig','gnu-keyring.gpg'},'exact three public source inputs required')
    need(sha(inputs/ARCHIVE)==ARCHIVE_SHA,'exact official release archive bytes required')
    observed=inspect(inputs/ARCHIVE,PAYLOAD_TREE,LIMITS)
    with tempfile.TemporaryDirectory(prefix='glibc-public-gpgv-') as home:
        argv=['/usr/bin/gpgv','--homedir',home,'--keyring',str(inputs/'gnu-keyring.gpg'),'--status-fd','1',str(inputs/(ARCHIVE+'.sig')),str(inputs/ARCHIVE)]
        result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              env=dict(PATH='/usr/bin:/bin',LC_ALL='C',TZ='UTC'),timeout=30)
    need(len(result.stdout)+len(result.stderr)<=65536,'bounded GNU verification output required')
    auth=signature_status(result.stdout.decode('utf-8','strict'),result.returncode)
    auth['diagnostic']=result.stderr.decode('utf-8','replace')
    return observed,auth


def materialize(recipe,inputs,output):
    recipe=Path(recipe).resolve(strict=True);output=Path(output).absolute()
    need(not output.exists() and not output.is_symlink() and not any(p.is_symlink() for p in output.parents),'fresh ordinary bundle required')
    lock=json.loads((recipe/'source-lock.json').read_bytes())
    verify_patches(recipe,lock)
    observed,auth=verify_release(inputs,lock)
    verify_configuration(recipe,lock)
    output.mkdir(mode=0o700)
    try:
        for path in recipe.iterdir():
            need(path.is_file() and not path.is_symlink(),'flat ordinary recipe input required')
            shutil.copyfile(path,output/path.name)
        for row in lock['public_inputs']:shutil.copyfile(Path(inputs)/row['path'],output/row['path'])
        (output/'source-authentication.json').write_text(json.dumps(auth,sort_keys=True,indent=2)+'\n')
        files={p.name:dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(output.iterdir())}
        receipt=dict(schema_version=1,status='SOURCE_BUNDLE_READY_UNSELECTED_GNU_PROVIDER',release=RELEASE,payload_tree=PAYLOAD_TREE,
                     source=observed,authentication=auth,files=files,declared_patches=lock['patch_order'],configured_layout=lock['layout'],
                     configured_features=lock['feature_choices'],package_version='2.43.caa1-1',native_build='NOT RUN',old_binary_source_gap='UNRESOLVED')
        (output/'bundle.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n');return receipt
    except BaseException:shutil.rmtree(output);raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Materialize the separately pinned complete official GNU2.43 source bundle, no recipe execution.')
    for name in ('recipe','inputs','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    try:print(json.dumps(materialize(args.recipe,args.inputs,args.output),sort_keys=True))
    except (ValueError,OSError) as error:
        print(json.dumps(dict(status='REFUSED_SOURCE_INPUTS',error=str(error)[:256])));raise SystemExit(1)
