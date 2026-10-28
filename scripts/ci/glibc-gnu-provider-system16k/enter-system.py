# SPDX-License-Identifier: MIT
"""Enter one VM-only data root, drop privilege, then kernel-normal execve."""
import json
import os
from pathlib import Path
import sys


def main(argv):
    assert os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.sysconf('SC_PAGE_SIZE')==16384
    assert 'glibcsystem16k=1' in Path('/proc/cmdline').read_text().split()
    assert argv and argv[0] in ('/usr/bin/locale','/usr/bin/iconv','/tmp/provider-lifecycle/smoke-normal')
    assert not any(k.startswith('LD_') or k in ('GCONV_PATH','LOCPATH') for k in os.environ)
    os.chroot('/system');os.chdir('/tmp/provider-lifecycle/run');os.setgroups([]);os.setgid(23001);os.setuid(23001)
    assert os.getresuid()==os.getresgid()==(23001,23001,23001) and os.getgroups()==[]
    Path('execution-identity.json').write_text(json.dumps(dict(uid=os.getuid(),gid=os.getgid(),groups=os.getgroups(),program=argv[0])))
    env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',HOME='/tmp/provider-lifecycle/run',TMPDIR='/tmp/provider-lifecycle/run')
    os.execve(argv[0],argv,env)


if __name__=='__main__':main(sys.argv[1:])
