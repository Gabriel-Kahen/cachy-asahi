# SPDX-License-Identifier: MIT
"""Exact-source extension of the emitted original twelve-view runner."""
import ast,hashlib,json
from pathlib import Path

HERE=Path(__file__).resolve().parent

def need(ok,message):
    if not ok:raise ValueError(message)
def once(text,old,new):
    need(text.count(old)==1,'Welcome5 adapter anchor differs: '+old[:90]);return text.replace(old,new)
def source_text(root,name):
    relative='scripts/ci/welcome-management-native/'+name
    pins=json.loads((HERE/'held-source.json').read_text())
    raw=(root/relative).read_bytes();need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==pins[relative],'whole held source differs: '+relative)
    return raw.decode()

def management(root):
    text=source_text(root,'management_contract.py')
    text=once(text,"{'cachy-asahi-welcome','cachy-asahi-doctor','cachy-asahi-orphans'}","{'cachy-asahi-welcome','cachy-asahi-doctor','cachy-asahi-orphans','cachy-asahi-dns'}")
    text=once(text,"result.get('present_count')==594 and result.get('absent_count')==592 and len(result.get('inventory',{}))==594","result.get('present_count')==595 and result.get('absent_count')==593 and len(result.get('inventory',{}))==595")
    return text

def phase(root):
    text=source_text(root,'management_phase.py')
    text=once(text,"argv=['/usr/bin/cachy-asahi-'+('orphans' if tool=='failure' else tool),'--json' if tool=='doctor' else 'assess']","argv=['/usr/bin/cachy-asahi-doctor','--json'] if tool=='doctor' else (['/usr/bin/cachy-asahi-dns','--json','profiles'] if tool=='dns' else ['/usr/bin/cachy-asahi-orphans','assess'])")
    for old,new in (("len(missing['inventory'])==592","len(missing['inventory'])==593"),("len(inventory)==594","len(inventory)==595"),('present_count=594,absent_count=592','present_count=595,absent_count=593')):text=once(text,old,new)
    text=once(text,"        closing_before=stable();action(ui['labels']['orphans'],scroll=True);closing=observed('orphans',True)","        import dns_phase\n        dns_phase.exercise(base,stage,env,workspace,current,hooks,request,stable,C)\n        closing_before=stable();action(ui['labels']['orphans'],scroll=True);closing=observed('orphans',True)")
    return text

def root_fixture(root):
    text=source_text(root,'management_root.py')
    text=once(text,"expected=['/usr/bin/cachy-asahi-'+tool,'--json' if tool=='doctor' else 'assess'];found=[]","expected=['/usr/bin/cachy-asahi-dns','--json','profiles'] if tool=='dns' else ['/usr/bin/cachy-asahi-'+tool,'--json' if tool=='doctor' else 'assess'];found=[]")
    text=once(text,"row['raw_argv'][-2:]!=expected","row['raw_argv'][-len(expected):]!=expected")
    text=once(text,"len(baseline)==594","len(baseline)==595")
    text=once(text,"sequence=0;armed=None;observed=None;fd=None;superfd=None;holder=None;lock_identity=None;progress=None","sequence=0;armed=None;observed=None;fd=None;superfd=None;holder=None;lock_identity=None;progress=None;dns=None;dns_stages=[]")
    text=once(text,"            elif op in ('remove','restore'):","""            elif op=='dns-open':
                import dns_fixture
                C.need(dns is None and data.get('stage')==('minimal' if not dns_stages else 'overlay') and len(dns_stages)<2 and holder is None and inventory()==baseline,'ordered fresh DNS fixture required')
                dns=dns_fixture.Fixture(base.guard,metadata);dns_stages.append(data['stage'])
            elif op=='dns-check':
                C.need(dns is not None,'DNS fixture absent');answer['readonly']=dns.check()
            elif op=='dns-close':
                C.need(dns is not None,'DNS fixture absent');answer['fixture']=dns.close();dns=None
            elif op in ('remove','restore'):""")
    text=once(text,"len(inventory())==592","len(inventory())==593")
    text=once(text,"data.get('tool') in ('doctor','orphans')","data.get('tool') in ('doctor','orphans','dns')")
    text=once(text,"if session.returncode==0:C.need(set(profiles)==retired_profiles=={'minimal','overlay'},'both profile companions must retire')","if session.returncode==0:C.need(set(profiles)==retired_profiles=={'minimal','overlay'} and dns is None and dns_stages==['minimal','overlay'],'both profile companions and DNS fixtures must retire')")
    text=once(text,"        unlock()\n        # Only", "        if dns is not None:dns.close()\n        unlock()\n        # Only")
    return text

def runner(root,output):
    """Input is a real staged original runner, never accepted original GUI evidence."""
    changed={}
    def put(name,text):ast.parse(text,filename=name)if name.endswith('.py')else None;(output/name).write_text(text);changed[name]=hashlib.sha256(text.encode()).hexdigest()
    for name,text in (('management_contract.py',management(root)),('management_phase.py',phase(root)),('management_root.py',root_fixture(root))):put(name,text)
    for name in ('dns_contract.py','dns_phase.py','dns_fixture.py'):put(name,(HERE/name).read_text())
    a11y=source_text(root,'a11y_driver.c')
    a11y=once(a11y,'"Management", "Run Doctor", "Assess orphan packages", "View report"','"Management", "Run Doctor", "Assess orphan packages", "List stored DNS profiles", "View report"')
    a11y=once(a11y,'!strcmp(name, "Doctor") || !strcmp(name, "Orphan assessment")','!strcmp(name, "Doctor") || !strcmp(name, "Orphan assessment") || !strcmp(name, "Stored DNS profiles")')
    a11y=once(a11y,'!strcmp(argv[4], "Doctor") || !strcmp(argv[4], "Orphan assessment")','!strcmp(argv[4], "Doctor") || !strcmp(argv[4], "Orphan assessment") || !strcmp(argv[4], "Stored DNS profiles")')
    put('a11y_driver.c',a11y)
    # Source-owned siblings are registered before their imports under isolated Python.
    for filename in ('desktop574_guest.py','doctor_worker.py'):
        text=(output/filename).read_text();anchor="load('management_contract','management_contract.py')"
        put(filename,once(text,anchor,"load('dns_contract','dns_contract.py')\nload('dns_fixture','dns_fixture.py')\nload('dns_phase','dns_phase.py')\n"+anchor))
    gui=(output/'gui_contract.py').read_text()
    gui=once(gui,"'cachy-asahi-welcome':'0.1.0-4'","'cachy-asahi-welcome':'0.1.0-5'")
    gui+='''\nimport dns_contract as DNS
VIEWS=VIEWS[:-1]+(DNS.VIEW,)+VIEWS[-1:]
_original_management_snapshot=validate_snapshot

def validate_snapshot(value,pid,view,text_sha=None):
    if view==DNS.VIEW:return DNS.snapshot(MG,value,pid,text_sha)
    return _original_management_snapshot(value,pid,view,text_sha)
'''
    put('gui_contract.py',gui)
    contract=(output/'contract.py').read_text()
    contract+='''\nimport dns_contract as DNS
_original_twelve_views=verify_result

def verify_result(events,lock):
    held=[e for e in events if not (e.get('event')=='frame_ready' and e.get('view')==DNS.VIEW)]
    original=_original_twelve_views(held,lock)
    return dict(original_twelve=original,stored_DNS=DNS.verify(events,lock,M,C),visual_review='NOT_RUN',hardware='NOT_RUN')
'''
    put('contract.py',contract)
    runtime=(output/'desktop574_runtime.py').read_text()
    old=tuple(stage+'-'+view for stage in ('minimal','overlay')for view in ('home','terminal-action','files-action','system','first-steps','updates','recovery','management-absent','management-doctor','management-orphans','management-failure','management-closing'))
    new=tuple(stage+'-'+view for stage in ('minimal','overlay')for view in ('home','terminal-action','files-action','system','first-steps','updates','recovery','management-absent','management-doctor','management-orphans','management-failure','management-dns','management-closing'))
    need(runtime.count(repr(old))==2,'two exact original twelve-view frame gates required');runtime=runtime.replace(repr(old),repr(new))
    runtime=once(runtime,'cachy_asahi_welcome_management=1','cachy_asahi_welcome_management=1 cachy_asahi_welcome5_dns=1')
    put('desktop574_runtime.py',runtime)
    fixture=(output/'desktop574_fixture.sh').read_text()
    anchor='cp /runner/native_contract.py /runner/input-policy.json'
    put('desktop574_fixture.sh',once(fixture,anchor,'cp /runner/dns_contract.py /runner/dns_phase.py /runner/dns_fixture.py "$root/usr/local/share/desktop574/"\n'+anchor))
    return changed

def independent(root,output,selected):
    need(selected in ('minimal','overlay'),'explicit independent profile required')
    # The original single-profile runner is whole-pinned. Its only source
    # derivatives here are the 13-view tuple and both wrapper-entry guards.
    relative='scripts/ci/welcome-independent-profile-native/profile_adapter.py'
    raw=(root/relative).read_bytes();pins=json.loads((HERE/'held-source.json').read_text())
    need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==pins[relative],'held independent-profile adapter differs')
    text=raw.decode()
    text=once(text,"'management-failure','management-closing')","'management-failure','management-dns','management-closing')")
    anchor='    C.need({e[\'stage\'] for e in events if \'stage\' in e}=={'
    # There are now exactly two source-owned verify_result entry points.
    text=once(text,"+repr(selected)+\"},'foreign or missing profile event')\")", "+repr(selected)+\"},'foreign or missing profile event')\",2)")
    namespace={};exec(compile(text,'derived-independent-profile-adapter','exec'),namespace)
    for name in ('management_contract.py','management_root.py'):
        p=output/name;body=p.read_text()
        if name=='management_contract.py':
            body=once(body,"for stage in ('minimal','overlay'):",'for stage in '+repr((selected,))+':')
        else:
            body=once(body,"stage==('minimal' if not profiles else 'overlay') and stage not in profiles and (not profiles or retired_profiles=={'minimal'})",'stage=='+repr(selected)+' and not profiles and not retired_profiles')
            body=once(body,"set(profiles)==retired_profiles=={'minimal','overlay'}",'set(profiles)==retired_profiles=={'+repr(selected)+'}')
            body=once(body,"data.get('stage')==('minimal' if not dns_stages else 'overlay') and len(dns_stages)<2",'data.get(\'stage\')=='+repr(selected)+' and not dns_stages')
            body=once(body,"dns_stages==['minimal','overlay']",'dns_stages==['+repr(selected)+']')
        p.write_text('INDEPENDENT_PROFILE = '+repr(selected)+'\n'+body)
    value=namespace['runner'](output,selected)
    return dict(adapter_original=pins[relative],adapter_derived=dict(bytes=len(text.encode()),sha256=hashlib.sha256(text.encode()).hexdigest()),runner=value['profile_derivation'])
