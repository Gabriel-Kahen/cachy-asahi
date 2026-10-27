#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the actual recipe package() only into a fresh private directory, then CLI controls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import contract as C


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    source=C.safe(a.source.absolute());out=C.safe(a.output.absolute());C.need(not out.exists(),'fresh host staging output required')
    out.mkdir(mode=0o700);recipe=source/'packages/tools'/C.NAMES[0];review=C.recipe(source,C.NAMES[0]);stage=out/'stage';stage.mkdir()
    commands=[]
    def run(argv,log,timeout=120):
        start=time.monotonic();row=subprocess.run(argv,capture_output=True,timeout=timeout,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
        (out/log).write_bytes(row.stdout+row.stderr);C.need(len(row.stdout)+len(row.stderr)<=4*1024**2,'host log cap')
        commands.append(dict(argv=list(map(str,argv)),returncode=row.returncode,log=log,seconds=time.monotonic()-start))
        C.need(row.returncode==0,'host check failed: '+log)
    run([sys.executable,'-B',str(recipe/'test_mirrors.py')],'product-tests.log')
    # Positional shell arguments carry paths; no evaluated interpolation of path strings.
    run(['/bin/bash','-euc','source "$1/PKGBUILD"; srcdir="$1"; pkgdir="$2"; package','mirror-stage',str(recipe),str(stage)],'package-stage.log')
    expected=C.files(C.NAMES[0]);actual={p.relative_to(stage).as_posix() for p in stage.rglob('*') if p.is_file()}
    C.need(actual==set(expected),'stage exact four-file map differs')
    payload={}
    for relative,(original,mode) in expected.items():
        path=stage/relative;C.need(not path.is_symlink() and (path.stat().st_mode&0o777)==mode and C.digest(path)==C.digest(recipe/original),'stage source/mode mismatch')
        payload[relative]=dict(sha256=C.digest(path),mode=mode,bytes=path.stat().st_size)
    work=out/'private-cli';work.mkdir(mode=0o700);run([sys.executable,'-B',str(HERE/'lifecycle.py'),'--cli',str(stage/'usr/bin'/C.NAMES[0]),'--work',str(work),'--report',str(work/'report.json')],'real-cli.log',180)
    proof=json.loads((work/'report.json').read_bytes());C.need(proof['status']=='PASS_LOCAL_MIRROR_LIFECYCLE','real CLI receipt absent')
    result=dict(status='PASS_HOST_RECIPE_STAGE_AND_REAL_CLI',architecture=os.uname().machine,python=sys.version,recipe_inputs=review['input_sha256'],payload=payload,
        commands=commands,lifecycle=proof,native='NOT_RUN',ALPM_installed='NOT_RUN',hardware='NOT_RUN',external_mirror_trust='NOT_TESTED',network_performance='NOT_MEASURED')
    (out/'report.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(dict(status=result['status'],native='NOT_RUN',hardware='NOT_RUN'),sort_keys=True))


if __name__=='__main__':main()
