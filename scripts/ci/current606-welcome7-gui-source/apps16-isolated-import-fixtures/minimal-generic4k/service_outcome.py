# SPDX-License-Identifier: MIT
import importlib.util,os,signal,sys,time
from pathlib import Path
def load(name,filename):
    p=Path(__file__).with_name(filename);s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def main():
    signal.alarm(2)
    for name in ('doctor_lifetime','management_contract','management_root'):load(name,name+'.py')
    b=load('outcome_base','base_guest.py');b.guard(True);b.EVENTS=b.event_port();b.need(b.EVENTS is not None,'event port absent')
    v={k:os.environ.get(k,'UNKNOWN') for k in ('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS')}
    b.need(all(len(x)<=64 and all(c.isalnum() or c in '_-' for c in x) for x in v.values()),'bounded service outcome')
    b.emit('independent_service_outcome',profile='minimal',monotonic_ns=time.monotonic_ns(),**v)
if __name__=='__main__':main()
