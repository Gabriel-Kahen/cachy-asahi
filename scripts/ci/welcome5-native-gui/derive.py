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

def contract(text):
 text=once(text,'def visible_control(proof,pid,label,window):','def visible_control(proof,pid,label,window,report_scope=None):\n    need(report_scope is None or (report_scope==\'Stored DNS profiles\' and label==\'View report\'),\'exact DNS report visibility scope required\')')
 text=once(text,"need(roles[0]==43 and roles[-1]==23", "need(roles[0]==(62 if report_scope is not None else 43) and roles[-1]==23")
 text=once(text,"if scroll:visible_control(proof,pid,label,row.get('window'))", "if scroll:visible_control(proof,pid,label,row.get('window'),report_scope=scope)")
 return text

def driver(text):
 anchor='static void walk(AtspiAccessible *node, guint depth, const char *scope)'
 text=once(text,anchor,'/* Failure DATA only: fixed-label candidates and bounded owned ancestry; no text. */\nstatic AtspiAccessible *candidate_path[13], *candidate_nodes[2][13];\nstatic struct {\n    guint role, pid; gboolean showing, visible, enabled, sensitive, rect_valid, role_valid, pid_valid, state_valid;\n    AtspiRect rect;\n} candidate_rows[2][13];\nstatic guint candidate_depth[2], candidate_count, candidate_total;\n\nstatic void remember_candidate(AtspiAccessible *node, guint depth, const char *scope,\n                               const char *name)\n{\n    candidate_path[depth] = node;\n    if (!wanted || strcmp(name, wanted) ||\n        (wanted_scope && (!scope || strcmp(scope, wanted_scope)))) return;\n    candidate_total++;\n    if (candidate_count == G_N_ELEMENTS(candidate_rows)) return;\n    guint slot = candidate_count++; candidate_depth[slot] = depth + 1;\n    for (guint i = 0; i <= depth; i++)\n        candidate_nodes[slot][i] = g_object_ref(candidate_path[depth - i]);\n}\n\nstatic void clear_candidates(void)\n{\n    for (guint slot = 0; slot < candidate_count; slot++)\n        for (guint i = 0; i < candidate_depth[slot]; i++)\n            g_object_unref(candidate_nodes[slot][i]);\n}\n\nstatic void observe_candidates(void)\n{\n    for (guint slot = 0; slot < candidate_count; slot++)\n      for (guint i = 0; i < candidate_depth[slot]; i++) {\n        GError *local = NULL; AtspiAccessible *item = candidate_nodes[slot][i];\n        candidate_rows[slot][i].role = atspi_accessible_get_role(item, &local);\n        candidate_rows[slot][i].role_valid = local == NULL;\n        g_clear_error(&local);\n        candidate_rows[slot][i].pid = atspi_accessible_get_process_id(item, &local);\n        candidate_rows[slot][i].pid_valid = local == NULL;\n        g_clear_error(&local);\n        AtspiStateSet *states = atspi_accessible_get_state_set(item);\n        candidate_rows[slot][i].state_valid = states != NULL;\n        candidate_rows[slot][i].showing = state(states, ATSPI_STATE_SHOWING);\n        candidate_rows[slot][i].visible = state(states, ATSPI_STATE_VISIBLE);\n        candidate_rows[slot][i].enabled = state(states, ATSPI_STATE_ENABLED);\n        candidate_rows[slot][i].sensitive = state(states, ATSPI_STATE_SENSITIVE);\n        if (states) g_object_unref(states);\n        AtspiComponent *component = atspi_accessible_get_component_iface(item);\n        if (component) {\n            AtspiRect *rect = atspi_component_get_extents(component, ATSPI_COORD_TYPE_SCREEN, &local);\n            if (rect && !local) {\n                candidate_rows[slot][i].rect = *rect;\n                candidate_rows[slot][i].rect_valid = TRUE;\n            }\n            g_clear_error(&local); if (rect) g_free(rect); g_object_unref(component);\n        }\n      }\n}\n\nstatic void failed_candidates(guint pid)\n{\n    observe_candidates();\n    /* Compact fixed fields keep the entire bounded receipt below 4096B. */\n    fprintf(stderr, "WELCOME_A11Y_CANDIDATES {\\"schema_version\\":1,\\"purpose\\":\\"FAILURE_DATA_ONLY\\","\n            "\\"observation\\":\\"NONATOMIC_SAME_CALL_AFTER_REFUSED_MATCH\\","\n            "\\"pid\\":%u,\\"label\\":\\"%s\\",\\"scope\\":\\"%s\\",\\"matching_controls\\":%u,"\n            "\\"candidate_total\\":%u,\\"truncated\\":%s,"\n            "\\"chain_fields\\":[\\"pid\\",\\"role\\",\\"valid_mask\\",\\"state_mask\\",\\"rect\\"],"\n            "\\"valid_bits\\":[\\"pid\\",\\"role\\",\\"states\\",\\"rect\\"],"\n            "\\"state_bits\\":[\\"showing\\",\\"visible\\",\\"enabled\\",\\"sensitive\\"],\\"candidates\\":[",\n            pid, wanted, wanted_scope ? wanted_scope : "", matches,\n            candidate_total, candidate_total > candidate_count ? "true" : "false");\n    for (guint slot = 0; slot < candidate_count; slot++) {\n        fprintf(stderr, "%s{\\"chain\\":[", slot ? "," : "");\n        for (guint i = 0; i < candidate_depth[slot]; i++) {\n            guint valid = candidate_rows[slot][i].pid_valid |\n                          (candidate_rows[slot][i].role_valid << 1) |\n                          (candidate_rows[slot][i].state_valid << 2) |\n                          (candidate_rows[slot][i].rect_valid << 3);\n            guint states = candidate_rows[slot][i].showing |\n                           (candidate_rows[slot][i].visible << 1) |\n                           (candidate_rows[slot][i].enabled << 2) |\n                           (candidate_rows[slot][i].sensitive << 3);\n            fprintf(stderr, "%s[%u,%u,%u,%u,[%d,%d,%d,%d]]",\n                    i ? "," : "", candidate_rows[slot][i].pid, candidate_rows[slot][i].role,\n                    valid, states, candidate_rows[slot][i].rect.x, candidate_rows[slot][i].rect.y,\n                    candidate_rows[slot][i].rect.width, candidate_rows[slot][i].rect.height);\n        }\n        fputs("]}", stderr);\n    }\n    fputs("]}\\n", stderr);\n}\n'+'\n'+anchor)
 text=once(text,'    gboolean showing = state(states, ATSPI_STATE_SHOWING);\n    if (scrolling', '    gboolean showing = state(states, ATSPI_STATE_SHOWING);\n    remember_candidate(node, depth, scope, name);\n    if (scrolling')
 text=once(text,'        check(matches == 1 && target, "one showing control required");','        if (matches != 1 || !target) failed_candidates((guint)pid);\n        clear_candidates();\n        check(matches == 1 && target, "one showing control required");')
 return text


def management(root):
    text=source_text(root,'management_contract.py')
    text=once(text,"{'cachy-asahi-welcome','cachy-asahi-doctor','cachy-asahi-orphans'}","{'cachy-asahi-welcome','cachy-asahi-doctor','cachy-asahi-orphans','cachy-asahi-dns'}")
    text=once(text,"result.get('present_count')==594 and result.get('absent_count')==592 and len(result.get('inventory',{}))==594","result.get('present_count')==595 and result.get('absent_count')==593 and len(result.get('inventory',{}))==595")
    return contract(text)

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
    put('a11y_driver.c',driver(a11y))
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
