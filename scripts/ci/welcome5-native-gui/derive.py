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
 text=once(text,"(method=='PEER_FOCUS_SCROLL' and not proof['focus_called'] and not proof['focused'] and not proof['unclipped_after_scroll']),","(method=='PEER_FOCUS_SCROLL' and not proof['focus_called'] and not proof['focused'] and not proof['unclipped_after_scroll']) or\n         (method=='EXPANDED_DNS_REPORT_TEXT_FOCUS_SCROLL' and proof['focus_called'] and not proof['unclipped_after_scroll']),")
 text=once(text,'    # AT-SPI screen origins can differ',"    if method=='EXPANDED_DNS_REPORT_TEXT_FOCUS_SCROLL':\n        need(report_scope=='Stored DNS profiles' and label=='View report','expanded report exact scope required')\n        report=proof.get('report_focus')\n        need(type(report) is dict and set(report)=={'scope','pid','role','matches','reply','target_checked','enabled','sensitive','visible','showing','focusable','focused','chain'},'complete typed report focus required')\n        need(type(report.get('pid')) is int and type(report.get('role')) is int and type(report.get('matches')) is int and\n             report['pid']==pid and report['role']==61 and report['matches']==1 and report['reply']=='REPLIED' and\n             report['scope']=='Stored DNS profiles' and all(report.get(k) is True for k in\n             ('target_checked','enabled','sensitive','visible','showing','focusable','focused')),'actual expanded owned unique text focus required')\n        inner=report['chain'];need(type(inner) is list and 2<=len(inner)<=12 and len(inner)+len(chain)-1<=13 and inner[-1]==chain[0],\n             'complete focus ancestry must join exact selected report')\n        ix,iy,iw,ih=rectangle(inner[0])\n        need(inner[0]['role']==61 and inner[-1]['role']==62,'text descendant to report roles required')\n        for row in inner:\n            x,y,w,h=rectangle(row)\n            need(x<=ix and y<=iy and ix+iw<=x+w and iy+ih<=y+h,'focused report text clipped by ancestor')\n    else:need('report_focus' not in proof,'unexpected report text focus evidence')\n    # AT-SPI screen origins can differ")
 return text

def driver(text):
 anchor='static void walk(AtspiAccessible *node, guint depth, const char *scope)'
 text=once(text,anchor,'/* Failure DATA only: fixed-label candidates and bounded owned ancestry; no text. */\nstatic AtspiAccessible *candidate_path[13], *candidate_nodes[2][13];\nstatic struct {\n    guint role, pid; gboolean showing, visible, enabled, sensitive, rect_valid, role_valid, pid_valid, state_valid;\n    AtspiRect rect;\n} candidate_rows[2][13];\nstatic guint candidate_depth[2], candidate_count, candidate_total;\n\nstatic void remember_candidate(AtspiAccessible *node, guint depth, const char *scope,\n                               const char *name)\n{\n    candidate_path[depth] = node;\n    if (!wanted || strcmp(name, wanted) ||\n        (wanted_scope && (!scope || strcmp(scope, wanted_scope)))) return;\n    candidate_total++;\n    if (candidate_count == G_N_ELEMENTS(candidate_rows)) return;\n    guint slot = candidate_count++; candidate_depth[slot] = depth + 1;\n    for (guint i = 0; i <= depth; i++)\n        candidate_nodes[slot][i] = g_object_ref(candidate_path[depth - i]);\n}\n\nstatic void clear_candidates(void)\n{\n    for (guint slot = 0; slot < candidate_count; slot++)\n        for (guint i = 0; i < candidate_depth[slot]; i++)\n            g_object_unref(candidate_nodes[slot][i]);\n}\n\nstatic void observe_candidates(void)\n{\n    for (guint slot = 0; slot < candidate_count; slot++)\n      for (guint i = 0; i < candidate_depth[slot]; i++) {\n        GError *local = NULL; AtspiAccessible *item = candidate_nodes[slot][i];\n        candidate_rows[slot][i].role = atspi_accessible_get_role(item, &local);\n        candidate_rows[slot][i].role_valid = local == NULL;\n        g_clear_error(&local);\n        candidate_rows[slot][i].pid = atspi_accessible_get_process_id(item, &local);\n        candidate_rows[slot][i].pid_valid = local == NULL;\n        g_clear_error(&local);\n        AtspiStateSet *states = atspi_accessible_get_state_set(item);\n        candidate_rows[slot][i].state_valid = states != NULL;\n        candidate_rows[slot][i].showing = state(states, ATSPI_STATE_SHOWING);\n        candidate_rows[slot][i].visible = state(states, ATSPI_STATE_VISIBLE);\n        candidate_rows[slot][i].enabled = state(states, ATSPI_STATE_ENABLED);\n        candidate_rows[slot][i].sensitive = state(states, ATSPI_STATE_SENSITIVE);\n        if (states) g_object_unref(states);\n        AtspiComponent *component = atspi_accessible_get_component_iface(item);\n        if (component) {\n            AtspiRect *rect = atspi_component_get_extents(component, ATSPI_COORD_TYPE_SCREEN, &local);\n            if (rect && !local) {\n                candidate_rows[slot][i].rect = *rect;\n                candidate_rows[slot][i].rect_valid = TRUE;\n            }\n            g_clear_error(&local); if (rect) g_free(rect); g_object_unref(component);\n        }\n      }\n}\n\nstatic void failed_candidates(guint pid)\n{\n    observe_candidates();\n    /* Compact fixed fields keep the entire bounded receipt below 4096B. */\n    fprintf(stderr, "WELCOME_A11Y_CANDIDATES {\\"schema_version\\":1,\\"purpose\\":\\"FAILURE_DATA_ONLY\\","\n            "\\"observation\\":\\"NONATOMIC_SAME_CALL_AFTER_REFUSED_MATCH\\","\n            "\\"pid\\":%u,\\"label\\":\\"%s\\",\\"scope\\":\\"%s\\",\\"matching_controls\\":%u,"\n            "\\"candidate_total\\":%u,\\"truncated\\":%s,"\n            "\\"chain_fields\\":[\\"pid\\",\\"role\\",\\"valid_mask\\",\\"state_mask\\",\\"rect\\"],"\n            "\\"valid_bits\\":[\\"pid\\",\\"role\\",\\"states\\",\\"rect\\"],"\n            "\\"state_bits\\":[\\"showing\\",\\"visible\\",\\"enabled\\",\\"sensitive\\"],\\"candidates\\":[",\n            pid, wanted, wanted_scope ? wanted_scope : "", matches,\n            candidate_total, candidate_total > candidate_count ? "true" : "false");\n    for (guint slot = 0; slot < candidate_count; slot++) {\n        fprintf(stderr, "%s{\\"chain\\":[", slot ? "," : "");\n        for (guint i = 0; i < candidate_depth[slot]; i++) {\n            guint valid = candidate_rows[slot][i].pid_valid |\n                          (candidate_rows[slot][i].role_valid << 1) |\n                          (candidate_rows[slot][i].state_valid << 2) |\n                          (candidate_rows[slot][i].rect_valid << 3);\n            guint states = candidate_rows[slot][i].showing |\n                           (candidate_rows[slot][i].visible << 1) |\n                           (candidate_rows[slot][i].enabled << 2) |\n                           (candidate_rows[slot][i].sensitive << 3);\n            fprintf(stderr, "%s[%u,%u,%u,%u,[%d,%d,%d,%d]]",\n                    i ? "," : "", candidate_rows[slot][i].pid, candidate_rows[slot][i].role,\n                    valid, states, candidate_rows[slot][i].rect.x, candidate_rows[slot][i].rect.y,\n                    candidate_rows[slot][i].rect.width, candidate_rows[slot][i].rect.height);\n        }\n        fputs("]}", stderr);\n    }\n    fputs("]}\\n", stderr);\n}\n'+'\n'+anchor)
 text=once(text,'    gboolean showing = state(states, ATSPI_STATE_SHOWING);\n    if (scrolling', '    gboolean showing = state(states, ATSPI_STATE_SHOWING);\n    remember_candidate(node, depth, scope, name);\n    if (scrolling')
 text=once(text,'        check(matches == 1 && target, "one showing control required");','        if (matches != 1 || !target) failed_candidates((guint)pid);\n        clear_candidates();\n        check(matches == 1 && target, "one showing control required");')
 text=once(text,'static void ensure_visible(guint pid)','/* Exact expanded DNS report only; no activation or text-based matching. */\nstatic AtspiAccessible *report_text;\nstatic guint report_nodes, report_matches;\nstatic Geometry report_geometry;\n\nstatic gboolean expanded_dns_report(guint pid)\n{\n    if (!wanted_scope || strcmp(wanted_scope, "Stored DNS profiles") || strcmp(wanted, "View report")) return FALSE;\n    atspi_accessible_clear_cache(target);\n    check(atspi_accessible_get_process_id(target, &error) == pid &&\n          atspi_accessible_get_role(target, &error) == ATSPI_ROLE_TOGGLE_BUTTON, "DNS report identity");\n    AtspiStateSet *states = atspi_accessible_get_state_set(target);\n    gboolean expanded = state(states, ATSPI_STATE_CHECKED);\n    check(state(states, ATSPI_STATE_ENABLED) && state(states, ATSPI_STATE_SENSITIVE) &&\n          state(states, ATSPI_STATE_VISIBLE), "DNS report enabled visible");\n    if (states) g_object_unref(states);\n    AtspiAccessible *panel = tool_panel(target, pid, "Stored DNS profiles"); g_object_unref(panel);\n    return expanded;\n}\n\nstatic void find_report_text(AtspiAccessible *node, guint pid, guint depth)\n{\n    check(depth <= 12 && report_nodes++ < 64, "DNS report descendant bound");\n    atspi_accessible_clear_cache(node);\n    check(atspi_accessible_get_process_id(node, &error) == pid, "DNS report descendant process");\n    AtspiRole role = atspi_accessible_get_role(node, &error); check(TRUE, "DNS report descendant role");\n    AtspiStateSet *states = atspi_accessible_get_state_set(node);\n    if (role == ATSPI_ROLE_TEXT && state(states, ATSPI_STATE_FOCUSABLE)) {\n        report_matches++; if (!report_text) report_text = g_object_ref(node);\n    }\n    if (states) g_object_unref(states);\n    gint count = atspi_accessible_get_child_count(node, &error);\n    check(count >= 0 && count <= 64, "DNS report child count");\n    for (gint i = 0; i < count; i++) {\n        AtspiAccessible *child = atspi_accessible_get_child_at_index(node, i, &error); check(child != NULL, "DNS report child");\n        find_report_text(child, pid, depth + 1); g_object_unref(child);\n    }\n}\n\nstatic void report_ancestry(guint pid, gboolean after_focus)\n{\n    report_geometry.count = 0;\n    AtspiAccessible *node = g_object_ref(report_text);\n    for (guint depth = 0; depth <= 12; depth++) {\n        atspi_accessible_clear_cache(node);\n        check(atspi_accessible_get_process_id(node, &error) == pid, "DNS report focus ancestry process");\n        AtspiRole role = atspi_accessible_get_role(node, &error); check(TRUE, "DNS report focus ancestry role");\n        AtspiStateSet *states = atspi_accessible_get_state_set(node);\n        check(state(states, ATSPI_STATE_VISIBLE), "DNS report focus ancestry visible");\n        if (!depth) check(role == ATSPI_ROLE_TEXT && state(states, ATSPI_STATE_FOCUSABLE) &&\n                         state(states, ATSPI_STATE_ENABLED) && state(states, ATSPI_STATE_SENSITIVE) &&\n                         (!after_focus || state(states, ATSPI_STATE_FOCUSED)), "DNS report text focus state");\n        if (after_focus) check(state(states, ATSPI_STATE_SHOWING), "DNS report focus ancestry showing");\n        if (states) g_object_unref(states);\n        if (after_focus) {\n            AtspiComponent *component = atspi_accessible_get_component_iface(node); check(component != NULL, "DNS report ancestry component");\n            AtspiRect *rect = atspi_component_get_extents(component, ATSPI_COORD_TYPE_SCREEN, &error); check(rect != NULL, "DNS report ancestry extents");\n            check(rect->x >= -32768 && rect->x <= 32768 && rect->y >= -32768 && rect->y <= 32768 &&\n                  rect->width > 0 && rect->width <= 8192 && rect->height > 0 && rect->height <= 8192 &&\n                  (!depth || contains(rect, &report_geometry.rects[0])), "DNS report text geometry");\n            report_geometry.rects[depth] = *rect; report_geometry.roles[depth] = role; report_geometry.count++;\n            g_free(rect); g_object_unref(component);\n        }\n        if (node == target) { g_object_unref(node); check(depth > 0, "DNS report strict descendant required"); return; }\n        AtspiAccessible *parent = atspi_accessible_get_parent(node, &error); check(parent != NULL, "DNS report focus parent");\n        g_object_unref(node); node = parent;\n    }\n    g_object_unref(node); check(FALSE, "DNS report focus ancestor bound");\n}\n\nstatic void focus_report_text(guint pid)\n{\n    check(expanded_dns_report(pid), "expanded DNS report required");\n    find_report_text(target, pid, 0);\n    check(report_matches == 1 && report_text, "one focusable DNS report text required");\n    report_ancestry(pid, FALSE);\n    AtspiComponent *component = atspi_accessible_get_component_iface(report_text); check(component != NULL, "DNS report text component");\n    check(atspi_component_grab_focus(component, &error), "actual DNS report text focus reply");\n    g_object_unref(component);\n    check(expanded_dns_report(pid), "DNS report expansion preserved");\n}\n\nstatic void print_report_focus(guint pid, const Geometry *outer)\n{\n    check(report_geometry.count >= 2 && report_geometry.count + outer->count - 1 <= 13,\n          "complete DNS focus chain bound");\n    guint last = report_geometry.count - 1;\n    AtspiRect a = report_geometry.rects[last], b = outer->rects[0];\n    check(report_geometry.roles[last] == outer->roles[0] && a.x == b.x && a.y == b.y &&\n          a.width == b.width && a.height == b.height, "DNS report geometry join");\n    printf("\\"report_focus\\":{\\"scope\\":\\"Stored DNS profiles\\",\\"pid\\":%u,\\"role\\":%u,"\n           "\\"matches\\":1,\\"reply\\":\\"REPLIED\\",\\"target_checked\\":true,\\"enabled\\":true,\\"sensitive\\":true,"\n           "\\"visible\\":true,\\"showing\\":true,\\"focusable\\":true,\\"focused\\":true,\\"chain\\":[", pid, (guint)ATSPI_ROLE_TEXT);\n    for (guint i = 0; i < report_geometry.count; i++) {\n        AtspiRect r = report_geometry.rects[i];\n        printf("%s{\\"pid\\":%u,\\"role\\":%u,\\"visible\\":true,\\"showing\\":true,\\"rect\\":[%d,%d,%d,%d]}",\n               i ? "," : "", pid, (guint)report_geometry.roles[i], r.x, r.y, r.width, r.height);\n    }\n    fputs("]},", stdout); g_object_unref(report_text); report_text = NULL;\n}\n\nstatic void ensure_visible(guint pid)')
 text=once(text,'    Geometry value; gboolean unclipped = settled_geometry(pid, &value), focus_called = FALSE, peer_focused = FALSE, peer_timed_out = FALSE;','    Geometry value; gboolean unclipped = settled_geometry(pid, &value), focus_called = FALSE, peer_focused = FALSE, peer_timed_out = FALSE, report_focused = FALSE;')
 text=once(text,'        check(settled_geometry(pid, &value), "focused control remains clipped");','        gboolean final_visible = settled_geometry(pid, &value);\n        if (!final_visible && focus_called && expanded_dns_report(pid)) {\n            focus_report_text(pid); report_focused = TRUE;\n            final_visible = settled_geometry(pid, &value);\n            if (final_visible) report_ancestry(pid, TRUE);\n        }\n        check(final_visible, "focused control remains clipped");')
 text=once(text,'    check(!focus_called || focused, "actual focused control required");','    check(!focus_called || focused || report_focused, "actual focused control required");')
 text=once(text,'peer_focused ? "PEER_FOCUS_SCROLL" : focus_called ? "FOCUS_SCROLL"','report_focused ? "EXPANDED_DNS_REPORT_TEXT_FOCUS_SCROLL" : peer_focused ? "PEER_FOCUS_SCROLL" : focus_called ? "FOCUS_SCROLL"')
 text=once(text,'    printf("\\"chain\\":[");','    if (report_focused) print_report_focus(pid, &value);\n    printf("\\"chain\\":[");')
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
