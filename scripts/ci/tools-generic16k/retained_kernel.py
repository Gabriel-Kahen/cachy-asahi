# SPDX-License-Identifier: MIT
"""One fixed checksum-bound public source asset; no configurable authenticated URL."""
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time

ASSET_ID=647949735
RELEASE_ID=415175342
SIZE=262965559
SHA='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad'
URL='https://api.github.com/repos/Gabriel-Kahen/cachy-asahi/releases/assets/647949735'
COMMAND=['gh','api','-H','Accept: application/octet-stream',URL]


def need(ok,why):
    if not ok:raise ValueError(why)


def download(archive,acquire,deadline_alarm,receipt_path):
    archive=Path(archive);acquire.ordinary(archive);acquire.ordinary(receipt_path)
    need(acquire.SIZE==SIZE and acquire.SHA==SHA,'retained source and original archive pins must join')
    need(archive.name=='kernel.tar.gz' and archive.parent.name==SHA and not archive.exists() and not archive.is_symlink(),'fresh exact archive cache path required')
    token=os.environ.get('GH_TOKEN');need(type(token) is str and 0<len(token)<=16384,'read-only workflow token required')
    partial=Path(str(archive)+'.partial');created=False;process=None;poll=None;digest=hashlib.sha256();count=0;stderr=bytearray();natural=False;group_absent=False
    report=dict(status='FAIL',asset_id=ASSET_ID,release_id=RELEASE_ID,release_draft=False,release_prerelease=True,source_kind='PUBLIC_ORIGINAL_KERNEL_SOURCE_CI_ASSET_ONLY',
        url=URL,expected_bytes=SIZE,expected_sha256=SHA,extraction='NOT_PERFORMED',deadline_seconds=300,
        authentication='READ_ONLY_WORKFLOW_TOKEN_FIXED_GITHUB_API_VIA_GH',release_admission=False)
    try:
        with deadline_alarm(300),tempfile.TemporaryDirectory(prefix='kernel-seed-gh-',dir=archive.parent.parent) as home:
            env=dict(PATH='/usr/local/bin:/usr/bin:/bin',HOME=home,GH_CONFIG_DIR=home+'/config',GH_HOST='github.com',GH_TOKEN=token,LANG='C',LC_ALL='C',GH_PROMPT_DISABLED='1')
            with partial.open('xb') as output:
                created=True;os.chmod(partial,0o600);started=time.monotonic()
                process=subprocess.Popen(COMMAND,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                try:
                    poll=selectors.DefaultSelector()
                    for index,pipe in enumerate((process.stdout,process.stderr)):
                        os.set_blocking(pipe.fileno(),False);poll.register(pipe,selectors.EVENT_READ,index)
                    while poll.get_map() or os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
                        need(time.monotonic()-started<300,'retained asset deadline')
                        for key,_ in poll.select(.05):
                            raw=os.read(key.fd,65536)
                            if not raw:poll.unregister(key.fileobj);continue
                            if key.data:
                                need(len(stderr)+len(raw)<=8192,'retained asset stderr cap');stderr.extend(raw)
                            else:
                                count+=len(raw);need(count<=SIZE,'retained asset byte cap');digest.update(raw);output.write(raw)
                    natural=True
                finally:
                    # The unreaped leader pins the owned process-group ID through signals.
                    for sig in (signal.SIGTERM,signal.SIGKILL):
                        try:os.killpg(process.pid,sig)
                        except ProcessLookupError:pass
                    code=process.wait(timeout=5)
                    if poll is not None:poll.close()
                    process.stdout.close();process.stderr.close()
                    try:os.killpg(process.pid,0)
                    except ProcessLookupError:group_absent=True
                    report.update(natural_exit=natural,exit=code,group_absent=group_absent)
                need(natural and code>=0 and group_absent,'retained asset command exit/group differs')
                if code:
                    report.update(status='RETAINED_ASSET_UNAVAILABLE',direct_url_fallback='ALLOWED_TRUE_CACHE_MISS_ONLY')
                    return report
                output.flush();os.fsync(output.fileno())
            need(count==SIZE and digest.hexdigest()==SHA,'retained asset exact size/hash differs')
            os.link(partial,archive,follow_symlinks=False);partial.unlink();created=False
            parent=os.open(archive.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:os.fsync(parent)
            finally:os.close(parent)
            report.update(status='RETAINED_ASSET_DOWNLOADED_HASH_VERIFIED',bytes=count,sha256=digest.hexdigest(),natural_exit=natural,exit=code,group_absent=group_absent)
            return report
    except BaseException as error:
        report.update(error_type=type(error).__name__,reason=str(error)[:160]);raise
    finally:
        if created:partial.unlink()
        report.update(observed_bytes=count,observed_sha256=digest.hexdigest(),stderr_bytes=len(stderr),stderr_sha256=hashlib.sha256(stderr).hexdigest(),partial_absent=not partial.exists())
        # No token, environment, response body or stderr text enters public evidence.
        raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();need(len(raw)<=16384,'retained source receipt bound')
        with receipt_path.open('xb') as stream:stream.write(raw)
