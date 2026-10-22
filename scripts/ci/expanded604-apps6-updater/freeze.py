#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root freezes only this separate adopted lane; never supplies prerequisite truth."""
import argparse
from pathlib import Path
import stat
import contract as C


def freeze(root):
    C.policy();root=C.safe(root.absolute());C.need(root==C.SOURCE,'freeze only adopted604 updater root')
    directory=root/'scripts/ci/expanded600-root-upgrade';old=C.read(directory/'source-manifest.json')
    names=set(old)|{'scripts/ci/expanded600-root-upgrade/source-manifest.json'}
    names.update(C.read(C.HERE/'source-pins.json')['files'])
    names.update(C.read(C.HERE/'source-pins.json')['fresh_files'])
    # The accepted installer checkout separately verifies its full immutable closure at the gate.
    names|={p.relative_to(root).as_posix() for p in C.HERE.iterdir() if p.is_file() and p.name!='source-manifest.json'}
    C.need(1<=len(names)<=512,'finite604 updater source closure required')
    files={}
    for name in sorted(names):
        path=C.safe(root/name);info=path.lstat()
        C.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=4*1024**2,'ordinary bounded source required')
        files[name]=dict(bytes=info.st_size,sha256=C.sha(path))
    manifest=C.HERE/'source-manifest.json'
    manifest.write_bytes(C.encoded(dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCE',files=files,native='NOT_RUN',hardware='NOT_RUN')))
    workflow=root/'.github/workflows/native-arm-expanded604-apps6-updater.yml';text=workflow.read_text()
    for marker,path in (('@OWNER_SHA256@',C.HERE/'run.py'),('@MANIFEST_SHA256@',manifest)):
        C.need(text.count(marker)==1,'Root must explicitly refresh workflow digest markers');text=text.replace(marker,C.sha(path))
    workflow.write_text(text)
    return dict(status='FROZEN_SOURCE_ONLY',files=len(files),manifest_sha256=C.sha(manifest),native='NOT_RUN')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True)
    print(freeze(p.parse_args().root))
