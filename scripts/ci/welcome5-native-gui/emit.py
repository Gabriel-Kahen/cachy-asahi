#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit this finite lane; registered-name alias exists only in the emitted trial."""
import argparse,json,os,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import candidates as C
HERE=Path(__file__).resolve().parent
ROLE='scripts/ci/welcome5-native-gui'
WORKFLOW='.github/workflows/native-arm-welcome5-dns-gui.yml'
ALIAS='.github/workflows/native-arm-build.yml'

def closed(root):
    """Git checkouts may have ONLY their top-level .git metadata in addition."""
    manifest=C.read(root/ROLE/'source-manifest.json');expected=set(manifest['files'])|{ROLE+'/source-manifest.json',WORKFLOW,ALIAS};actual=set()
    for directory,dirs,files in os.walk(root,topdown=True,followlinks=False):
        relative=Path(directory).relative_to(root)
        if relative==Path('.'):
            dirs[:]=[n for n in dirs if n!='.git'];files=[n for n in files if n!='.git']
        for name in dirs:
            path=Path(directory)/name;C.need(not path.is_symlink(),'source directory alias refused')
        for name in files:
            path=Path(directory)/name;C.regular(path.absolute(),16*1024**2);actual.add(str(path.relative_to(root)))
    C.need(actual==expected,'unexpected or missing emitted source file')
    for name,row in manifest['files'].items():C.pinned(root,name,row)
    C.need((root/WORKFLOW).read_bytes()==(root/ALIAS).read_bytes(),'exact dedicated/registered-name alias required')
    return actual

def emit(source,out):
    C.verify_source(source)
    C.need(out.is_absolute()and not out.exists()and out.parent.is_dir()and
        not any(p.is_symlink()for p in (out,*out.parents))and not out.is_relative_to(source)and not source.is_relative_to(out),'fresh ordinary disjoint emitted source required')
    value=C.read(HERE/'source-manifest.json');out.mkdir(mode=0o700)
    for name,row in value['files'].items():
        path=C.pinned(source,name,row);target=out/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
    target=out/ROLE/'source-manifest.json';shutil.copyfile(HERE/'source-manifest.json',target)
    text=(source/WORKFLOW).read_text()
    C.need(text.count(C.digest(HERE/'job.py'))==1 and text.count(C.digest(HERE/'source-manifest.json'))==1 and '__JOB_SHA__'not in text and '__MF_SHA__'not in text,'actual workflow inline source stamps differ')
    for name in (WORKFLOW,ALIAS):
        path=out/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
    actual=closed(out)
    return dict(status='EMITTED_SOURCE_ONLY_NOT_NATIVE_ACCEPTANCE',files=len(actual),actuals={'minimal':None,'overlay':None},GUI='NOT_RUN',hardware='NOT_RUN')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('source','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.output.absolute()),sort_keys=True))
