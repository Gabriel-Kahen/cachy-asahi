# SPDX-License-Identifier: MIT
"""Narrow deterministic extension after the whole current606 original emitter."""
import ast,shutil
from pathlib import Path
HERE=Path(__file__).resolve().parent

def once(s,a,b):
 if s.count(a)!=1:raise ValueError('one exact Welcome8 emission seam '+a[:100])
 return s.replace(a,b,1)

def settle_peer_focus(text):
    # Check the geometry and fresh AT-SPI focus in the same bounded settle pass.
    # GrabFocus already ran once; asynchronous state never triggers another action.
    before = '''static gboolean settled_geometry(guint pid, Geometry *value)
{
    gint64 until = g_get_monotonic_time() + 2 * G_USEC_PER_SEC;
    do {
        while (g_main_context_iteration(NULL, FALSE)) {}
        if (geometry(pid, value)) return TRUE;
        g_usleep(25000);
    } while (g_get_monotonic_time() < until);
    return FALSE;
}'''
    after = '''static gboolean settled_geometry_with(guint pid, Geometry *value,
                                      gboolean (*postcondition)(void), gboolean *visible)
{
    gint64 until = g_get_monotonic_time() + 2 * G_USEC_PER_SEC;
    do {
        while (g_get_monotonic_time() < until && g_main_context_iteration(NULL, FALSE)) {}
        if (geometry(pid, value)) {
            if (visible) *visible = TRUE;
            if (!postcondition || postcondition()) return TRUE;
        }
        if (g_get_monotonic_time() >= until) break;
        g_usleep(25000);
    } while (g_get_monotonic_time() < until);
    return FALSE;
}

static gboolean settled_geometry(guint pid, Geometry *value)
{
    return settled_geometry_with(pid, value, NULL, NULL);
}

static gboolean actual_peer_focus(void)
{
    atspi_accessible_clear_cache(scroll_peer);
    AtspiStateSet *states = atspi_accessible_get_state_set(scroll_peer);
    gboolean focused = state(states, ATSPI_STATE_FOCUSED);
    if (focused) check(state(states, ATSPI_STATE_ENABLED) && state(states, ATSPI_STATE_SENSITIVE),
                       "focused peer must remain enabled");
    if (states) g_object_unref(states);
    if (!focused) return FALSE;
    atspi_accessible_clear_cache(target);
    states = atspi_accessible_get_state_set(target);
    check(states && !state(states, ATSPI_STATE_ENABLED) && !state(states, ATSPI_STATE_SENSITIVE),
          "disabled target state preserved");
    g_object_unref(states);
    return TRUE;
}'''
    text = once(text, before, after)
    text = once(text, '        gboolean final_visible = settled_geometry(pid, &value);',
                '''        gboolean geometry_seen = FALSE;
        gboolean final_visible = peer_focused
            ? settled_geometry_with(pid, &value, actual_peer_focus, &geometry_seen)
            : settled_geometry(pid, &value);
        if (peer_focused && geometry_seen)
            check(final_visible, "actual peer focused state");''')
    before = '''        if (peer_focused) {
            atspi_accessible_clear_cache(scroll_peer); states = atspi_accessible_get_state_set(scroll_peer);
            check(state(states, ATSPI_STATE_FOCUSED), "actual peer focused state"); if (states) g_object_unref(states);
            atspi_accessible_clear_cache(target); states = atspi_accessible_get_state_set(target);
            check(!state(states, ATSPI_STATE_ENABLED) && !state(states, ATSPI_STATE_SENSITIVE), "disabled target state preserved");
            if (states) g_object_unref(states);
        }
'''
    return once(text, before, '')


def settle_target_focus(text):
    # Join the scoped orphan expander's own AT-SPI focus with complete geometry.
    # A successful GrabFocus reply requests focus and does not prove convergence.
    before = 'static void ensure_visible(guint pid)'
    after = '''static gboolean actual_orphan_report_focus(void)
{
    atspi_accessible_clear_cache(target);
    AtspiStateSet *states = atspi_accessible_get_state_set(target);
    gboolean focused = state(states, ATSPI_STATE_FOCUSED);
    if (focused) check(state(states, ATSPI_STATE_ENABLED) && state(states, ATSPI_STATE_SENSITIVE),
                       "focused orphan report must remain enabled");
    if (states) g_object_unref(states);
    return focused;
}

static void ensure_visible(guint pid)'''
    text = once(text, before, after)
    before = '''        gboolean geometry_seen = FALSE;
        gboolean final_visible = peer_focused
            ? settled_geometry_with(pid, &value, actual_peer_focus, &geometry_seen)
            : settled_geometry(pid, &value);
        if (peer_focused && geometry_seen)
            check(final_visible, "actual peer focused state");'''
    after = '''        gboolean orphan_report_focus = focus_called && wanted_scope &&
            !strcmp(wanted_scope, "Orphan assessment") && !strcmp(wanted, "View report");
        gboolean geometry_seen = FALSE;
        gboolean final_visible = peer_focused
            ? settled_geometry_with(pid, &value, actual_peer_focus, &geometry_seen)
            : orphan_report_focus
                ? settled_geometry_with(pid, &value, actual_orphan_report_focus, &geometry_seen)
                : settled_geometry(pid, &value);
        if (peer_focused && geometry_seen)
            check(final_visible, "actual peer focused state");
        if (orphan_report_focus && geometry_seen)
            check(final_visible, "actual focused control required");'''
    return once(text, before, after)


def expanded_dns_visibility(out):
    """Focus the report body after its one open action, even if the header is visible."""
    path = out/'a11y_driver.c'
    text = path.read_text()
    text = once(text, 'static gboolean snapshot, scrolling;',
                'static gboolean snapshot, scrolling, report_scrolling;')
    text = once(text, '    scrolling = !strcmp(argv[2], "scroll");', '''    report_scrolling = !strcmp(argv[2], "scroll-report");
    check(!report_scrolling || (argc == 5 && !strcmp(argv[3], "View report") &&
          !strcmp(argv[4], "Stored DNS profiles")), "exact post-open DNS report scope");
    scrolling = report_scrolling || !strcmp(argv[2], "scroll");''')
    text = once(text, 'static void ensure_visible(guint pid)', '''static gboolean wait_expanded_dns_report(guint pid)
{
    gint64 until = g_get_monotonic_time() + 2 * G_USEC_PER_SEC;
    do {
        while (g_get_monotonic_time() < until && g_main_context_iteration(NULL, FALSE)) {}
        if (expanded_dns_report(pid)) return TRUE;
        if (g_get_monotonic_time() >= until) break;
        g_usleep(25000);
    } while (g_get_monotonic_time() < until);
    return FALSE;
}

static gboolean actual_dns_report_focus(void)
{
    atspi_accessible_clear_cache(report_text);
    AtspiStateSet *states = atspi_accessible_get_state_set(report_text);
    gboolean ready = state(states, ATSPI_STATE_VISIBLE) && state(states, ATSPI_STATE_SHOWING) &&
        state(states, ATSPI_STATE_FOCUSED) && state(states, ATSPI_STATE_FOCUSABLE) &&
        state(states, ATSPI_STATE_ENABLED) && state(states, ATSPI_STATE_SENSITIVE);
    if (states) g_object_unref(states);
    return ready;
}

static void focus_expanded_dns_report(guint pid, Geometry *value)
{
    check(wait_expanded_dns_report(pid), "DNS report did not expand after its activation");
    focus_report_text(pid);
    check(settled_geometry_with(pid, value, actual_dns_report_focus, NULL),
          "expanded DNS report text is not focused and showing");
    check(expanded_dns_report(pid), "DNS report expansion preserved after settling");
    report_ancestry(pid, TRUE);
}

static void ensure_visible(guint pid)''')
    text = once(text, '''    Geometry value; gboolean unclipped = settled_geometry(pid, &value), focus_called = FALSE, peer_focused = FALSE, peer_timed_out = FALSE, report_focused = FALSE;
    if (!unclipped) {''', '''    Geometry value;
    gboolean unclipped = report_scrolling ? geometry(pid, &value) : settled_geometry(pid, &value);
    gboolean focus_called = FALSE, peer_focused = FALSE, peer_timed_out = FALSE, report_focused = FALSE;
    if (report_scrolling) {
        focus_expanded_dns_report(pid, &value);
        focus_called = report_focused = TRUE;
    } else if (!unclipped) {''')
    path.write_text(text)

    path = out/'management_contract.py'
    text = path.read_text()
    path.write_text(once(text,
        "(method=='EXPANDED_DNS_REPORT_TEXT_FOCUS_SCROLL' and proof['focus_called'] and not proof['unclipped_after_scroll'])",
        "(method=='EXPANDED_DNS_REPORT_TEXT_FOCUS_SCROLL' and proof['focus_called'])"))

    path = out/'dns_phase.py'
    text = path.read_text()
    text = once(text, '    def action(label,scope=None,scroll=False):',
                '    def action(label,scope=None,scroll=False,expanded=False):')
    text = once(text, "        proof=hooks['a11y']('scroll'if scroll else'activate',label,scope=scope)",
        """        operation='scroll-report' if expanded else 'scroll' if scroll else 'activate'
        proof=hooks['a11y'](operation,label,scope=scope)
        if expanded:D.expanded_focus(proof)""")
    text = once(text, "        action('View report',D.TITLE,scroll=True)\n        expected=",
                     "        action('View report',D.TITLE,scroll=True,expanded=True)\n        expected=")
    path.write_text(text)

    path = out/'dns_contract.py'
    text = path.read_text()
    text = once(text, 'def fixture(value):', '''def expanded_focus(proof):
    need(proof.get('method')=='EXPANDED_DNS_REPORT_TEXT_FOCUS_SCROLL',
         'post-open DNS visibility requires focus on the expanded report body')

def fixture(value):''')
    text = once(text,
                "len(result['inventory'])==595,'same complete595 inventory required'",
                "len(result['inventory'])==606,'same complete606 inventory required'")
    path.write_text(once(text, "        fast=result['retirement_observation'];",
                              "        expanded_focus(actions[4]['proof'])\n        fast=result['retirement_observation'];"))




def apply(out,selected):
 # These are typed installed-version expectations, not a substitute for execution.
 for name in('gui_contract.py','dns_contract.py','doctor_worker.py'):
  p=out/name;s=p.read_text();assert '0.1.0-7'in s;s=s.replace('0.1.0-7','0.1.0-8');p.write_text(s)
 shutil.copyfile(HERE/'welcome8_stop.py',out/'welcome8_stop.py')
 p=out/'a11y_driver.c';s=p.read_text();s=once(s,'"List stored DNS profiles", "View report" };','"List stored DNS profiles", "View report", "Stop check" };');s=once(s,'check(!strcmp(wanted, "View report") &&','check((!strcmp(wanted, "View report") || (!strcmp(wanted, "Stop check") && !strcmp(argv[4], "Doctor") && !scrolling)) &&');p.write_text(settle_target_focus(settle_peer_focus(s)))
 p=out/'management_phase.py';s=p.read_text();a="        closing_before=stable();action(ui['labels']['orphans'],scroll=True);closing=observed('orphans',True)";b="        import welcome8_stop\n        welcome8_stop.exercise(base,stage,current,inventory,hooks,request,stable)\n"+a;p.write_text(once(s,a,b))
 # Isolated guest Python registers only independently regenerated source siblings.
 for name in('desktop574_guest.py','doctor_worker.py'):
  p=out/name;s=p.read_text();a="load('management_phase','management_phase.py')"if name=='desktop574_guest.py'else"load('management_root','management_root.py')";p.write_text(once(s,a,a+"\nload('welcome8_stop','welcome8_stop.py')"))
 p=out/'desktop574_fixture.sh';s=p.read_text();a='cp /runner/current_products.py';p.write_text(once(s,a,'cp /runner/welcome8_stop.py "$root/usr/local/share/desktop574/"\n'+a))
 p=out/'gui_contract.py';s=p.read_text();s+='''
import welcome8_stop as W8
VIEWS=VIEWS+W8.VIEWS
_welcome8_snapshot=validate_snapshot
def validate_snapshot(value,pid,view,text_sha=None):
    if view in W8.VIEWS:return W8.snapshot(value,pid,view,text_sha)
    return _welcome8_snapshot(value,pid,view,text_sha)
''';p.write_text(s)
 p=out/'contract.py';s=p.read_text();s+='''
_welcome8_full_original=verify_result
def verify_result(events,lock):
    import welcome8_stop as W8
    result=W8.validate(events,lock,C)
    held=[e for e in events if not(e.get('event')=='frame_ready'and e.get('view')in W8.VIEWS)]
    original=_welcome8_full_original(held,lock)
    return dict(original,welcome8_stop_retry=result)
''';p.write_text(s)
 p=out/'desktop574_runtime.py';s=p.read_text();old=tuple(selected+'-'+v for v in('home','terminal-action','files-action','system','first-steps','updates','recovery','management-absent','management-doctor','management-orphans','management-failure','management-dns','management-closing'));new=old+(selected+'-welcome8-stopped',selected+'-welcome8-retry');assert s.count(repr(old))==2;s=s.replace(repr(old),repr(new));p.write_text(s)
 for p in out.glob('*.py'):ast.parse(p.read_text(),filename=str(p))
