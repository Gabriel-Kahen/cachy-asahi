#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Ordinary native ARM installed packages → complete Setup5 RCs → existing PTYs."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C


def exercise(source,out,*,native=True):
    C.need(os.getuid()==os.geteuid()>0 and (not native or (platform.machine()=='aarch64' and Path('/.dockerenv').is_file() and not Path('/dev/snd').exists() and os.environ.get('CACHY_SETUP5_REAL_USER')=='1')),'marked ordinary native ARM user required')
    source=C.safe(source);C.verify_source(source);out=C.safe(out);C.need(not out.exists(),'fresh private user work required');out.mkdir(mode=0o700)
    H=C.load('setup5_real_rc_adapter',source/'scripts/ci/setup5-real-modules/run.py')
    raw=(source/'scripts/ci/shell-modules-coexistence/run.py').read_text();anchor='unset ZSH_AUTOSUGGEST_USE_ASYNC';replacement='(( ${+ZSH_AUTOSUGGEST_USE_ASYNC} )) || exit 25'
    C.need(raw.count(anchor)==1,'exact inherited synchronous-mode override required');adapted=raw.replace(anchor,replacement)
    import types
    B=types.ModuleType('installed_setup5_existing_coexistence');B.__file__=str(source/'scripts/ci/shell-modules-coexistence/run.py');exec(compile(adapted,B.__file__,'exec'),B.__dict__)
    join=C.load('accepted_installed_shell_join',source/'scripts/ci/expanded-development-composition/installed_shells.py')
    join.installed_join(source,B);joined=dict(status='PASS_SOURCE_IDENTICAL_RUNTIME',modules=list(C.MODULES))
    cli=Path('/usr/bin/cachy-asahi-setup');C.need(C.digest(cli)==H.CLI_SHA,'actual installed setup5 helper differs')
    homes=H.SetupHomes(cli,Path('/usr/share/cachy-asahi'),out);B.combined=homes.combined;D,Z=H.fixture_modules(B,source,homes)
    report=dict(status='FAIL',scope='ACTUAL_INSTALLED_SETUP5_AND_SIX_MODULE_GENERATED_RCS',machine=platform.machine(),page_size=os.sysconf('SC_PAGE_SIZE'),uid=os.getuid(),installed_helper_sha256=C.digest(cli),installed_runtime_join=joined,zsh_mode='DEFAULT_ASYNC_PRESENCE_ASSERTED',zsh_fixture_adapter=dict(before=anchor,after=replacement,original_sha256=C.hash_bytes(raw.encode()),adapted_sha256=C.hash_bytes(adapted.encode())),cases={},lifecycle={},notification_delivery='NOT_RUN',notification_scope='PRIVATE_NOTIFY_SEND_RECORDER_ONLY',hardware='NOT_RUN',release='NOT_ADMITTED',defaults_enabled=False)
    jobs=[('fish-request-forward',lambda:B.fish_case(D,source,out,('bang','autopair','done'))),('fish-request-reverse',lambda:B.fish_case(D,source,out,('done','autopair','bang'))),('zsh-request-forward',lambda:B.zsh_case(Z,source,out,('autosuggest','highlight','substring'))),('zsh-request-reordered',lambda:B.zsh_case(Z,source,out,('highlight','substring','autosuggest')))]
    jobs.extend((shell+'-noninteractive',lambda shell=shell:B.noninteractive(D,Z,source,out,shell)) for shell in ('fish','zsh'))
    def expired(*_):raise TimeoutError('finite30s installed generated-RC case deadline')
    old=signal.signal(signal.SIGALRM,expired)
    try:
        for name,job in jobs:
            signal.setitimer(signal.ITIMER_REAL,30)
            try:report['cases'][name]=job()
            except Exception as error:report['cases'][name]=dict(status='FAIL',error_type=type(error).__name__,reason=str(error))
            finally:signal.setitimer(signal.ITIMER_REAL,0)
        for home in list(homes.records):
            C.need((home/'setup5-user-sourced').read_text()=='user-sourced','complete generated user file not sourced')
            report['lifecycle'][home.name]=dict(activation=homes.records[home],removal=homes.remove(home))
        report['conflicts']=homes.conflicts()
        if all(r['status']=='PASS' for r in report['cases'].values()):report['status']='PASS_NATIVE_INSTALLED_SETUP5_REAL_MODULE_GENERATED_RCS'
    except Exception as error:report.update(error_type=type(error).__name__,reason=str(error))
    finally:signal.signal(signal.SIGALRM,old)
    report['versions']={shell:subprocess.check_output([shutil.which(shell),'--version'],env=dict(PATH='/usr/bin:/bin',HOME=str(out)),text=True,timeout=5).strip() for shell in ('fish','zsh')}
    report['interpreter_sha256']={shell:C.digest(Path(shutil.which(shell)).resolve()) for shell in ('fish','zsh')}
    (out/'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    C.validate_real(report);return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(exercise(a.source.absolute(),a.output.absolute())))
