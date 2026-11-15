#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Ordinary real-login client; starts only private session bus/Xvfb children."""
import hashlib, importlib.util, json, os, subprocess, sys, time
from pathlib import Path
H = Path('/home/builder'); R = Path('/run/ui-session')
def accept_retirement(retirement):
    assert retirement['passed'] and retirement['group_census']=='EMPTY_TWICE' and retirement['signals']==[], 'real installed GTK process/retirement refused'

def main():
    assert __debug__ and sys.flags.isolated and os.geteuid() == 1000 and os.ttyname(0) == '/dev/tty1'
    os.umask(0o077); deadline = time.monotonic() + 280
    def wait(path):
        while not path.exists():
            if (R/'failure.json').exists(): raise RuntimeError('root fixture refused; inspect sanitized root report')
            if time.monotonic() > deadline: raise TimeoutError('UI session root stage deadline')
            time.sleep(.1)
    report = {'status': 'HOLD', 'uid': os.geteuid(), 'pid': os.getpid(), 'process_session': os.getsid(0), 'tty': os.ttyname(0)}
    try:
        wait(R/'installed.json')
        private = H/'UI-runtime'; private.mkdir(mode=0o700)
        env = {'PATH':'/usr/bin:/bin','HOME':str(H),'XDG_RUNTIME_DIR':str(private),'XDG_CACHE_HOME':str(private/'cache'),'XDG_CONFIG_HOME':str(private/'config'),'GDK_BACKEND':'x11','GSK_RENDERER':'cairo','GDK_DISABLE':'gl,vulkan,dmabuf','GDK_DEBUG':'no-portals','GTK_A11Y':'none','LC_ALL':'C.UTF-8'}
        args = ['/usr/bin/python3','-I','-B','/usr/local/libexec/ui-gui-session.py']
        spec=importlib.util.spec_from_file_location('ui_owned_process','/usr/local/libexec/ui-owned-process.py');owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
        owned.prepare()
        with (private/'gui.stderr').open('wb') as error:
            child=subprocess.Popen(args,cwd='/',env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=error,start_new_session=True)
            retirement=owned.supervise(child,cap=90,retirement=3,grace=.5,max_output=128*1024)
        output=retirement.pop('output');report['owned_GUI_process_retirement']=retirement
        with (private/'gui.stdout').open('xb')as stream:stream.write(output);stream.flush();os.fsync(stream.fileno())
        report['GUI_stdout']={'bytes':len(output),'sha256':hashlib.sha256(output).hexdigest()}
        lifecycle=private/'session-lifecycle.json'
        if lifecycle.exists():report['session_lifecycle_receipt']={'bytes':lifecycle.stat().st_size,'sha256':hashlib.sha256(lifecycle.read_bytes()).hexdigest()}
        accept_retirement(retirement)
        report['gui'] = json.loads(output); assert report['gui']['status'] == 'PASS_REAL_INSTALLED_GTK_CONTROLS'
        (H/'UI_READY_FOR_REMOVAL.json').write_text(json.dumps(report, sort_keys=True)+'\n')
        wait(R/'removed.json')
        observed = {str(p.relative_to(H/'UI-profile')):hashlib.sha256(p.read_bytes()).hexdigest() for p in (H/'UI-profile').rglob('*') if p.is_file()}
        assert observed == report['gui']['user_files'], 'package removal changed private user settings'
        report.update(status='PASS_REAL_SEAT_UI_CLIENT', removal_preserved_user_files=True, private_X_server_and_session_bus_retired=True)
    except BaseException as e: report['failure'] = {'category':type(e).__name__,'message':str(e)[:1024]}
    (H/'UI_CLIENT_REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return 0 if report['status'].startswith('PASS_') else 1
if __name__ == '__main__': raise SystemExit(main())
