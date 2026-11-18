# SPDX-License-Identifier: MIT
"""Finite exact-anchor derivative; original sequential runners remain unchanged."""
import ast
import hashlib
import json
from pathlib import Path

PROFILES=('minimal','overlay')
VIEWS=('home','terminal-action','files-action','system','first-steps','updates','recovery',
       'management-absent','management-doctor','management-orphans','management-failure','management-closing')
GUI='PASS_INSTALLED_WELCOME_SINGLE_PROFILE_GUI_METADATA'

def need(ok,reason):
    if not ok:raise ValueError(reason)

def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def replace(text,old,new,count=1):
    need(text.count(old)==count,'independent profile anchor differs: '+old[:100]);return text.replace(old,new)

def runner(output,selected):
    need(selected in PROFILES,'explicit profile required');changes={}
    def edit(name,operation):
        path=output/name;raw=path.read_bytes();text=operation(raw.decode());ast.parse(text,filename=name)
        path.write_text(text);changes[name]=dict(original=pin(raw),derived=pin(text.encode()))
    singleton=repr((selected,));full="('minimal','overlay')"
    edit('base_guest.py',lambda t:replace(t,"for stage, config in [('minimal', SHARE / 'minimal.lua'),\n                          ('overlay', Path('/usr/share/cachy-asahi/hyprland/hyprland.lua'))]:",
        "for stage, config in "+("[('minimal', SHARE / 'minimal.lua')]:" if selected=='minimal' else "[('overlay', Path('/usr/share/cachy-asahi/hyprland/hyprland.lua'))]:")))
    def guest(t):
        t=replace(t,"if stage=='minimal':","if stage=="+repr(selected)+':')
        return replace(t,"completed=={'minimal','overlay'}","completed=={"+repr(selected)+'}')
    edit('desktop574_guest.py',guest)
    edit('managed_contract.py',lambda t:replace(t,"for stage in ('minimal', 'overlay'):", 'for stage in '+singleton+':'))
    def legacy(t):
        t=replace(t,'for stage in '+full+':','for stage in '+singleton+':')
        return replace(t,"C.need(events.index(phases[0])<events.index(phases[1]),'minimal/overlay order differs')",
            "C.need(len(phases)==1 and phases[0]['stage']=="+repr(selected)+",'exact independent profile required')")
    edit('legacy_contract.py',legacy)
    # management_contract and management_root are already selected in the native
    # derivative. The unchanged full generator copies them byte-for-byte.
    for name in ('management_contract.py','management_root.py'):
        text=(output/name).read_text();need('INDEPENDENT_PROFILE = '+repr(selected) in text,'selected native module required')
    def contract(t):
        t=replace(t,'def verify_result(events,lock):',"def verify_result(events,lock):\n    C.need({e['stage'] for e in events if 'stage' in e}=={"+repr(selected)+"},'foreign or missing profile event')")
        t=replace(t,'for stage in '+full+':','for stage in '+singleton+':')
        t=replace(t,'DL.validate_profiles(profile_retirements)',"C.need(len(profile_retirements)==1 and profile_retirements[0]['stage']=="+repr(selected)+",'one validated actual Doctor profile required')")
        return replace(t,"return dict(baseline=original,",'return dict(profile='+repr(selected)+",scope='ONE_PROFILE_NOT_FULL_GUI_ACCEPTANCE',baseline=original,")
    edit('contract.py',contract)
    fullframes=repr(tuple(s+'-'+v for s in PROFILES for v in VIEWS));frames=tuple(selected+'-'+v for v in VIEWS)
    def runtime(t):
        t=replace(t,fullframes,repr(frames),2)
        t=replace(t,"phases == {'minimal', 'overlay'}","phases == {"+repr(selected)+'}')
        t=replace(t,'PASS_INSTALLED_WELCOME_MANAGEMENT_GUI_METADATA',GUI,2)
        return replace(t,"'workflow_scope': 'installed-welcome-doctor-managed-gui'","'profile': "+repr(selected)+", 'workflow_scope': 'independent-installed-welcome-management-profile'")
    edit('desktop574_runtime.py',runtime)
    # No additional actor: the existing service manager records its own bounded
    # stop result through the same guarded virtio event port, before guest shutdown.
    stop=output/'service_outcome.py'
    stop.write_text("# SPDX-License-Identifier: MIT\nimport importlib.util,os,signal,sys,time\nfrom pathlib import Path\n"
        "def load(name,filename):\n    p=Path(__file__).with_name(filename);s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m\n"
        "def main():\n    signal.alarm(2)\n    for name in ('doctor_lifetime','management_contract','management_root'):load(name,name+'.py')\n"
        "    b=load('outcome_base','base_guest.py');b.guard(True);b.EVENTS=b.event_port();b.need(b.EVENTS is not None,'event port absent')\n"
        "    v={k:os.environ.get(k,'UNKNOWN') for k in ('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS')}\n"
        "    b.need(all(len(x)<=64 and all(c.isalnum() or c in '_-' for c in x) for x in v.values()),'bounded service outcome')\n"
        "    b.emit('independent_service_outcome',profile="+repr(selected)+",monotonic_ns=time.monotonic_ns(),**v)\n"
        "if __name__=='__main__':main()\n")
    fixture=output/'desktop574_fixture.sh';raw=fixture.read_bytes();text=raw.decode()
    text=replace(text,'TimeoutStartSec=1200','ExecStopPost=/usr/bin/python3 -I -B /usr/local/share/desktop574/service_outcome.py\nTimeoutStartSec=1200')
    text=replace(text,'cp /runner/native_contract.py ', 'cp /runner/service_outcome.py "$root/usr/local/share/desktop574/"\ncp /runner/native_contract.py ')
    fixture.write_text(text);changes[fixture.name]=dict(original=pin(raw),derived=pin(text.encode()))
    proof=output/'runner-proof.json';value=json.loads(proof.read_bytes())
    value.update(profile=selected,scope='ONE_PROFILE_NOT_FULL_GUI_ACCEPTANCE',profile_derivation=changes)
    value['files']={p.name:pin(p.read_bytes()) for p in output.iterdir() if p.is_file() and p.name not in ('candidate-lock.json','runner-proof.json')}
    proof.write_bytes(encoded(value));return value
