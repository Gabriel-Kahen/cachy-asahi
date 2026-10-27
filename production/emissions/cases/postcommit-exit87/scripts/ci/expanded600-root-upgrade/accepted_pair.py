# SPDX-License-Identifier: MIT
"""Unchanged data-only accepted149 inspection extracted from frozen probe0bb."""
import hashlib
import json
from pathlib import Path
import tarfile

INDEX_SHA='b1e4208d2f32935f2e5cb1c1e3535cc49f44c7bfe08e7d64692b8ac3781d5a5d'
ARCHIVE_SHA='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc'
CLI_SHA='ea505b6437a416c49e494e9ee0a16a9b160e95fed232ef920ad29aa510e28afd'

def need(ok,why):
    if not ok:raise ValueError(why)

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def safe(path):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute paths required');return path

def accepted_cli(root,out):
    root=safe(root);index=root/'index.json';need(index.stat().st_size==25005 and digest(index)==INDEX_SHA,'accepted setup5 index identity differs')
    value=json.loads(index.read_text());need(value['status']=='ROOT_ACCEPTED_NATIVE_SETUP5_PAIR_AND_LEGACY_LIFECYCLE_INPUTS' and value['native_run']==38934198468 and value['version']=='0.1.0-5' and len(value['files'])==147,'exact accepted setup5 input set required')
    nodes=list(root.rglob('*'));need(len(nodes)<256 and all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in nodes),'ordinary bounded accepted tree required')
    actual={str(p.relative_to(root)) for p in nodes if p.is_file()};need(actual==set(value['files'])|{'index.json','README.md'} and len(actual)==149 and sum((root/n).stat().st_size for n in actual)==1305823,'complete accepted149 file/byte closure required')
    for name,row in value['files'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts,'safe accepted member required');path=safe(root/name)
        need(path.is_file() and path.stat().st_size==row['bytes']<=2*1024**2 and digest(path)==row['sha256'],'accepted member bytes differ: '+name)
    archives=[root/'packages'/('cachy-asahi-setup-'+side)/'cachy-asahi-setup-0.1.0-5-any.pkg.tar.xz' for side in ('a','b')]
    need(all(p.stat().st_size==26872 and digest(p)==ARCHIVE_SHA for p in archives),'accepted exact native archive pair differs')
    with tarfile.open(archives[0],'r:xz') as archive:
        members=[m for m in archive if m.name.removeprefix('./')=='usr/bin/cachy-asahi-setup']
        need(len(members)==1 and members[0].isfile() and members[0].size<=131072 and members[0].mode==0o755,'one ordinary accepted setup CLI required')
        raw=archive.extractfile(members[0]).read()
    need(hashlib.sha256(raw).hexdigest()==CLI_SHA,'accepted setup CLI byte pin differs');target=out/'accepted-setup5-cli';target.write_bytes(raw);target.chmod(0o755)
    return target,dict(index_sha256=INDEX_SHA,archive_sha256=ARCHIVE_SHA,cli_sha256=CLI_SHA,native_input_run=38934198468,input_ref='79d8d2f53510e4f3a04f39c1b1e24c999aa32e44',scope='accepted input provenance only; this execution is host-only')
