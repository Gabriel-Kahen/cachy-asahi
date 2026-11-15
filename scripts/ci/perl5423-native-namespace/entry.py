#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Future in-container diagnostic producer; Root owns launch, retirement and trust."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('perl_ns_entry_data',HERE/'data.py');data=importlib.util.module_from_spec(spec);spec.loader.exec_module(data)


class Cancelled(BaseException):pass


def run():
    raw=data.read(HERE/'admission.json');a=data.decode(raw);data.admission(a)
    data.need(raw==data.encode(a) and data.pin(raw)['sha256']==os.environ.get('ADAPTER_ADMISSION_SHA256'),'canonical external Root admission hash')
    data.verify_source(HERE,a['source_map_sha256'])
    host_raw=data.read(HERE/'host.json');host=data.decode(host_raw)
    data.need(host_raw==data.encode(host) and host['binding_sha256']==data.pin(raw)['sha256'],'canonical Root-authenticated host receipt')
    classifier=data.load('perl_ns_baseline_reader',HERE/'reader.py')
    classifier.host_domain(host,a)
    observe=data.load('perl_ns_entry_observe',HERE/'observe.py');probe=data.load('perl_ns_entry_probe',HERE/'probe.py')
    os.umask(0o022)
    for name in ('home','tmp','recipe'):(Path('/work')/name).mkdir(mode=0o700)
    os.chdir('/work/recipe')
    env=dict(PATH='/usr/bin',HOME='/work/home',XDG_CONFIG_HOME='/work/home/.config',TMPDIR='/work/tmp',LC_ALL='C',TZ='UTC',MAKEFLAGS='-j2',CACHY_ASAHI_PERL_BUILD='1',SOURCE_DATE_EPOCH='1785628800',PKGDEST='/work/output',LOGDEST='/work/output',PYTHONDONTWRITEBYTECODE='1')
    os.environ.clear();os.environ.update(env)
    entry,parent=observe.context(),observe.context(1)
    owned_path=HERE/'helpers/owned_child.py';data.need(data.pin(data.read(owned_path))['sha256']==data.OWNED_SHA,'immutable owned-child primitive')
    owned=data.load('perl_ns_owned_child',owned_path)
    output=Path('/work/output');output.mkdir(mode=0o700)
    report=dict(schema=1,operation=data.OPERATION,status='FAIL_NAMESPACE_DATA',native_acceptance=False,admission_sha256=data.pin(raw)['sha256'],source_map_sha256=a['source_map_sha256'],domain_sha256=data.DOMAIN_SHA,host_sha256=data.pin(host_raw)['sha256'],token=a['token'],entry=entry,parent=parent,commands=[],failure=None)
    cancelled=[False];previous={s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
    def request(number,frame):cancelled[0]=True
    def tick():
        if cancelled[0]:raise Cancelled('Root cancellation requested')
    def save():(output/'report.json').write_bytes(data.encode(report))
    start=time.monotonic();save()
    try:
        for sig in previous:signal.signal(sig,request)
        classifier.baseline(entry,parent)
        for case in probe.CASES:
            tick();lifecycle={};name=case+'.log';argv=probe.arguments(case,report['admission_sha256'],a['source_map_sha256'],a['token'],'--exec-probe')
            row=dict(case=case,argv=argv,log=name,log_pin=None,returncode=None,lifecycle=lifecycle)
            try:
                data.need(time.monotonic()-start<48,'finite two-command diagnostic budget')
                with (output/name).open('xb') as log:
                    result=owned.run(argv,timeout=25,cwd=Path('/work/recipe'),env=env,stdout=log,stderr=subprocess.STDOUT,stdout_limit=512*1024,lifecycle=lifecycle,on_tick=tick)
                row['returncode']=result.returncode;tick()
            finally:
                row['log_pin']=data.pin(data.read(output/name,512*1024));report['commands'].append(row);save()
        report['status']='OBSERVED_NAMESPACE_DATA'
    except BaseException as error:report['failure']=type(error).__name__+': '+str(error)
    finally:
        if cancelled[0]:report.update(status='FAIL_NAMESPACE_DATA',failure='Root cancellation requested')
        save()
        for sig,handler in previous.items():signal.signal(sig,handler)
    return 0 if report['status']=='OBSERVED_NAMESPACE_DATA' else 2


if __name__=='__main__':
    data.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized diagnostic entry')
    raise SystemExit(run())
