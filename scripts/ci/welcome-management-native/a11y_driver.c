/* SPDX-License-Identifier: MIT */
/* Bounded existing AT-SPI calls for one owned Welcome process, not a GUI framework. */
#include <atspi/atspi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static GError *error;
static guint nodes, matches;
static AtspiAccessible *target;
static const char *wanted;
static gboolean snapshot, scrolling;
static const char *wanted_scope;
static gsize text_total;
static AtspiAccessible *scroll_peer;
static guint peer_matches;

static const char *tool_scope(void)
{
    if (!strcmp(wanted, "Run Doctor")) return "Doctor";
    if (!strcmp(wanted, "Assess orphan packages")) return "Orphan assessment";
    return NULL;
}

static void check(gboolean ok, const char *message)
{
    if (!ok || error) {
        fprintf(stderr, "Welcome accessibility failure: %s: %.160s\n", message, error ? error->message : "contract refused");
        g_clear_error(&error); exit(2);
    }
}

static gboolean state(AtspiStateSet *states, AtspiStateType value)
{
    return states && atspi_state_set_contains(states, value);
}

static gboolean control_role(AtspiRole role, const char *name)
{
    return role == ATSPI_ROLE_BUTTON || role == ATSPI_ROLE_TOGGLE_BUTTON || role == ATSPI_ROLE_PAGE_TAB ||
        (role == ATSPI_ROLE_RADIO_BUTTON &&
         (!strcmp(name, "Welcome") || !strcmp(name, "System") || !strcmp(name, "Guides") || !strcmp(name, "Management")));
}

typedef struct { AtspiRect rects[13]; AtspiRole roles[13]; guint count; } Geometry;

static gboolean contains(const AtspiRect *outer, const AtspiRect *inner)
{
    return outer->x <= inner->x && outer->y <= inner->y &&
        (gint64)inner->x + inner->width <= (gint64)outer->x + outer->width &&
        (gint64)inner->y + inner->height <= (gint64)outer->y + outer->height;
}

static gboolean geometry(guint pid, Geometry *value)
{
    value->count = 0;
    AtspiAccessible *node = g_object_ref(target);
    for (guint depth = 0; depth <= 12; depth++) {
        atspi_accessible_clear_cache(node);
        check(atspi_accessible_get_process_id(node, &error) == pid, "geometry process");
        AtspiRole role = atspi_accessible_get_role(node, &error); check(TRUE, "geometry role");
        AtspiStateSet *states = atspi_accessible_get_state_set(node);
        gboolean showing = state(states, ATSPI_STATE_VISIBLE) && state(states, ATSPI_STATE_SHOWING);
        if (states) g_object_unref(states);
        AtspiComponent *component = atspi_accessible_get_component_iface(node);
        if (!showing || !component) {
            if (component) g_object_unref(component);
            g_object_unref(node); return FALSE;
        }
        AtspiRect *rect = atspi_component_get_extents(component, ATSPI_COORD_TYPE_SCREEN, &error);
        check(rect != NULL, "geometry extents"); g_object_unref(component);
        gboolean valid = rect->x >= -32768 && rect->x <= 32768 && rect->y >= -32768 && rect->y <= 32768 &&
            rect->width > 0 && rect->width <= 8192 && rect->height > 0 && rect->height <= 8192 &&
            (!depth || contains(rect, &value->rects[0]));
        if (valid) { value->rects[depth] = *rect; value->roles[depth] = role; value->count++; }
        g_free(rect);
        if (!valid) { g_object_unref(node); return FALSE; }
        AtspiAccessible *parent = atspi_accessible_get_parent(node, &error); check(parent != NULL, "geometry parent");
        g_object_unref(node);
        if (role == ATSPI_ROLE_FRAME) {
            check(atspi_accessible_get_role(parent, &error) == ATSPI_ROLE_APPLICATION &&
                  atspi_accessible_get_process_id(parent, &error) == pid, "owned top-level geometry");
            g_object_unref(parent); return TRUE;
        }
        node = parent;
    }
    g_object_unref(node); check(FALSE, "geometry depth bound"); return FALSE;
}

static gboolean settled_geometry(guint pid, Geometry *value)
{
    gint64 until = g_get_monotonic_time() + 2 * G_USEC_PER_SEC;
    do {
        while (g_main_context_iteration(NULL, FALSE)) {}
        if (geometry(pid, value)) return TRUE;
        g_usleep(25000);
    } while (g_get_monotonic_time() < until);
    return FALSE;
}

static AtspiAccessible *tool_panel(AtspiAccessible *start, guint pid, const char *scope)
{
    AtspiAccessible *node = g_object_ref(start);
    for (guint depth = 0; depth <= 12; depth++) {
        check(atspi_accessible_get_process_id(node, &error) == pid, "peer ancestor process");
        AtspiRole role = atspi_accessible_get_role(node, &error);
        char *name = atspi_accessible_get_name(node, &error); check(name != NULL, "peer ancestor name");
        gboolean found = role == ATSPI_ROLE_PANEL && !strcmp(name, scope); g_free(name);
        if (found) return node;
        AtspiAccessible *parent = atspi_accessible_get_parent(node, &error); check(parent != NULL, "peer ancestor parent");
        g_object_unref(node); node = parent;
    }
    g_object_unref(node); check(FALSE, "peer ancestor bound"); return NULL;
}


static gboolean peer_focus_timeout(gboolean replied)
{
    if (!replied && error && !strcmp(error->message, "timeout from dbind")) {
        /* A reply timeout leaves the outcome unknown. Do not repeat the action:
         * the original fresh focus, disabled-target and full geometry checks
         * below must independently confirm the requested state before PASS. */
        fprintf(stderr, "Welcome accessibility: exact peer focus reply timeout; checking owned postconditions without repeating focus\n");
        g_clear_error(&error); return TRUE;
    }
    check(replied, "actual peer focus scroll"); return FALSE;
}

static void ensure_visible(guint pid)
{
    AtspiComponent *component = atspi_accessible_get_component_iface(target);
    check(component != NULL, "scroll component");
    gboolean scrolled = atspi_component_scroll_to(component, ATSPI_SCROLL_ANYWHERE, &error);
    check(TRUE, "actual component scroll"); /* FALSE without an error still needs complete visibility proof. */
    Geometry value; gboolean unclipped = settled_geometry(pid, &value), focus_called = FALSE, peer_focused = FALSE, peer_timed_out = FALSE;
    if (!unclipped) {
        AtspiStateSet *states = atspi_accessible_get_state_set(target);
        gboolean enabled = state(states, ATSPI_STATE_ENABLED), sensitive = state(states, ATSPI_STATE_SENSITIVE);
        if (states) g_object_unref(states);
        if (enabled && sensitive) {
            focus_called = TRUE;
            check(atspi_component_grab_focus(component, &error), "actual component focus scroll");
        } else {
            /* A missing optional tool deliberately disables its button. Focus
             * its enabled, same-tool report expander to scroll the viewport;
             * never enable or activate the disabled check itself. */
            const char *scope = tool_scope();
            check(!enabled && !sensitive && scope && peer_matches == 1 && scroll_peer, "one disabled tool scroll peer");
            AtspiAccessible *a = tool_panel(target, pid, scope), *b = tool_panel(scroll_peer, pid, scope);
            check(a == b, "scroll peer must share actual tool panel"); g_object_unref(a); g_object_unref(b);
            check(atspi_accessible_get_process_id(scroll_peer, &error) == pid &&
                  atspi_accessible_get_role(scroll_peer, &error) == ATSPI_ROLE_TOGGLE_BUTTON, "scroll peer identity");
            atspi_accessible_clear_cache(scroll_peer); states = atspi_accessible_get_state_set(scroll_peer);
            check(state(states, ATSPI_STATE_ENABLED) && state(states, ATSPI_STATE_SENSITIVE), "scroll peer enabled");
            if (states) g_object_unref(states);
            AtspiComponent *peer_component = atspi_accessible_get_component_iface(scroll_peer);
            check(peer_component != NULL, "peer component required");
            peer_timed_out = peer_focus_timeout(atspi_component_grab_focus(peer_component, &error));
            g_object_unref(peer_component);
            peer_focused = TRUE;
        }
        check(settled_geometry(pid, &value), "focused control remains clipped");
        if (peer_focused) {
            atspi_accessible_clear_cache(scroll_peer); states = atspi_accessible_get_state_set(scroll_peer);
            check(state(states, ATSPI_STATE_FOCUSED), "actual peer focused state"); if (states) g_object_unref(states);
            atspi_accessible_clear_cache(target); states = atspi_accessible_get_state_set(target);
            check(!state(states, ATSPI_STATE_ENABLED) && !state(states, ATSPI_STATE_SENSITIVE), "disabled target state preserved");
            if (states) g_object_unref(states);
        }
    }
    atspi_accessible_clear_cache(target);
    AtspiStateSet *states = atspi_accessible_get_state_set(target);
    gboolean focused = state(states, ATSPI_STATE_FOCUSED);
    if (states) g_object_unref(states);
    check(!focus_called || focused, "actual focused control required");
    char *name = atspi_accessible_get_name(target, &error); check(name && !strcmp(name, wanted), "visible target identity");
    char *encoded = g_base64_encode((const guchar *)name, strlen(name)); g_free(name);
    printf("{\"status\":\"PASS\",\"pid\":%u,\"actions\":0,\"interface\":\"Component\",\"action_name\":\"ensure-visible\","
           "\"scroll_called\":true,\"scroll_returned\":%s,\"focus_called\":%s,\"focused\":%s,\"unclipped_after_scroll\":%s,"
           "\"method\":\"%s\",\"coordinate_space\":\"ATSPI_SCREEN\",\"name_base64\":\"%s\",",
           pid, scrolled ? "true" : "false", focus_called ? "true" : "false", focused ? "true" : "false",
           unclipped ? "true" : "false", peer_focused ? "PEER_FOCUS_SCROLL" : focus_called ? "FOCUS_SCROLL" : scrolled ? "COMPONENT_SCROLL" : "ALREADY_UNCLIPPED", encoded);
    if (peer_focused) {
        printf("\"peer_focus_reply\":\"%s\",\"peer_focus_error\":%s,",
               peer_timed_out ? "TIMEOUT_STATE_CONFIRMED" : "REPLIED",
               peer_timed_out ? "\"timeout from dbind\"" : "null");
        printf("\"peer_focus\":{\"pid\":%u,\"role\":%u,\"name_base64\":\"VmlldyByZXBvcnQ=\",\"scope\":\"%s\","
               "\"enabled\":true,\"sensitive\":true,\"focused\":true,\"same_panel\":true,\"target_enabled\":false,\"target_sensitive\":false},",
               pid, (guint)ATSPI_ROLE_TOGGLE_BUTTON, tool_scope());
    }
    printf("\"chain\":[");
    for (guint i = 0; i < value.count; i++) {
        AtspiRect r = value.rects[i];
        printf("%s{\"pid\":%u,\"role\":%u,\"visible\":true,\"showing\":true,\"rect\":[%d,%d,%d,%d]}",
               i ? "," : "", pid, (guint)value.roles[i], r.x, r.y, r.width, r.height);
    }
    puts("]}"); g_free(encoded); g_object_unref(component);
}

static void walk(AtspiAccessible *node, guint depth, const char *scope)
{
    check(depth <= 12 && nodes < 192, "tree bound");
    char *name = atspi_accessible_get_name(node, &error); check(name != NULL, "node name");
    check(strlen(name) <= 65536, "name bound");
    if (!strcmp(name, "Doctor") || !strcmp(name, "Orphan assessment")) scope = name;
    AtspiRole role = atspi_accessible_get_role(node, &error); check(TRUE, "node role");
    AtspiStateSet *states = atspi_accessible_get_state_set(node);
    gboolean showing = state(states, ATSPI_STATE_SHOWING);
    if (scrolling && tool_scope() && scope && !strcmp(scope, tool_scope()) &&
        !strcmp(name, "View report") && role == ATSPI_ROLE_TOGGLE_BUTTON) {
        peer_matches++; if (!scroll_peer) scroll_peer = g_object_ref(node);
    }
    if (wanted && (showing || scrolling) && !strcmp(name, wanted) && control_role(role, name) &&
        (!wanted_scope || (scope && !strcmp(scope, wanted_scope)))) {
        if (!scrolling) check(state(states, ATSPI_STATE_ENABLED) && state(states, ATSPI_STATE_SENSITIVE), "disabled control");
        matches++; if (!target) target = g_object_ref(node);
    }
    if (snapshot) {
        char *encoded = g_base64_encode((const guchar *)name, MIN(strlen(name), 160));
        printf("%s{\"name_base64\":\"%s\",\"role\":%u,\"showing\":%s,\"selected\":%s,\"checked\":%s",
            nodes ? "," : "", encoded, (guint)role, showing ? "true" : "false",
            state(states, ATSPI_STATE_SELECTED) ? "true" : "false", state(states, ATSPI_STATE_CHECKED) ? "true" : "false");
        printf(",\"enabled\":%s,\"sensitive\":%s", state(states, ATSPI_STATE_ENABLED) ? "true" : "false",
               state(states, ATSPI_STATE_SENSITIVE) ? "true" : "false");
        g_free(encoded);
        AtspiText *text = atspi_accessible_get_text_iface(node);
        if (text && showing) {
            gint count = atspi_text_get_character_count(text, &error); check(count >= 0 && count <= 65664, "text bound");
            char *body = atspi_text_get_text(text, 0, count, &error); check(body != NULL && strlen(body) <= 262144, "text");
            char *hash = g_compute_checksum_for_string(G_CHECKSUM_SHA256, body, -1);
            char *prefix = g_base64_encode((const guchar *)body, MIN(strlen(body), 192));
            printf(",\"text_sha256\":\"%s\",\"text_bytes\":%zu,\"prefix_base64\":\"%s\"", hash, strlen(body), prefix);
            text_total += strlen(body); check(text_total <= 131328 && strlen(body) <= 65664, "total retained text bound");
            char *full = g_base64_encode((const guchar *)body, strlen(body));
            printf(",\"body_base64\":\"%s\"", full); g_free(full);
            g_free(prefix); g_free(hash); g_free(body);
        }
        printf("}");
    }
    nodes++;
    gint count = atspi_accessible_get_child_count(node, &error); check(count >= 0 && count <= 192, "child count");
    for (gint i = 0; i < count; i++) {
        AtspiAccessible *child = atspi_accessible_get_child_at_index(node, i, &error); check(child != NULL, "child");
        walk(child, depth + 1, scope); g_object_unref(child);
    }
    if (states) g_object_unref(states);
    g_free(name);
}


static void select_guide_tab(guint pid)
{
    const char *guides[] = { "First steps", "Updates", "Recovery" };
    gint expected = -1;
    for (guint i = 0; i < G_N_ELEMENTS(guides); i++)
        if (!strcmp(wanted, guides[i])) expected = (gint)i;
    check(expected >= 0, "guide tab allowlist");
    check(atspi_accessible_get_process_id(target, &error) == pid, "guide tab process");
    AtspiAccessible *parent = atspi_accessible_get_parent(target, &error); check(parent != NULL, "guide tab parent");
    check(atspi_accessible_get_process_id(parent, &error) == pid, "notebook process");
    check(atspi_accessible_get_role(parent, &error) == ATSPI_ROLE_PAGE_TAB_LIST, "notebook role");
    AtspiStateSet *states = atspi_accessible_get_state_set(parent);
    check(state(states, ATSPI_STATE_SHOWING) && state(states, ATSPI_STATE_ENABLED) &&
          state(states, ATSPI_STATE_SENSITIVE), "notebook state");
    if (states) g_object_unref(states);
    gint count = atspi_accessible_get_child_count(parent, &error); check(count == 3, "guide tab count");
    gint index = atspi_accessible_get_index_in_parent(target, &error);
    check(index == expected && index >= 0 && index < count, "guide tab index");
    AtspiAccessible *child = atspi_accessible_get_child_at_index(parent, index, &error); check(child != NULL, "indexed guide tab");
    check(atspi_accessible_get_process_id(child, &error) == pid &&
          atspi_accessible_get_role(child, &error) == ATSPI_ROLE_PAGE_TAB, "indexed guide tab identity");
    char *name = atspi_accessible_get_name(child, &error); check(name != NULL && !strcmp(name, wanted), "indexed guide tab name");
    g_free(name); g_object_unref(child);
    AtspiSelection *selection = atspi_accessible_get_selection_iface(parent); check(selection != NULL, "notebook selection interface");
    check(atspi_selection_select_child(selection, index, &error), "guide tab selection");
    check(atspi_selection_is_child_selected(selection, index, &error) &&
          atspi_selection_get_n_selected_children(selection, &error) == 1, "selected guide tab");
    printf("{\"status\":\"PASS\",\"pid\":%u,\"actions\":1,\"action_name\":\"select-child\","
           "\"interface\":\"Selection\",\"target_role\":%u,\"parent_role\":%u,\"child_index\":%d,"
           "\"child_count\":%d,\"selected\":true,\"selected_count\":1}\n",
           pid, (guint)ATSPI_ROLE_PAGE_TAB, (guint)ATSPI_ROLE_PAGE_TAB_LIST, index, count);
    g_object_unref(parent);
}

int main(int argc, char **argv)
{
    const char *labels[] = { "Welcome", "System", "Guides", "First steps", "Updates", "Recovery",
                            "Open Terminal", "Open Files", "Refresh system status",
                            "Management", "Run Doctor", "Assess orphan packages", "View report" };
    char *cmdline = NULL; gsize bytes = 0;
    check(getuid() == 23001 && geteuid() == 23001 &&
          g_file_get_contents("/proc/cmdline", &cmdline, &bytes, NULL) &&
          strstr(cmdline, "cachy_asahi_welcome_gui=1"), "private guest guard");
    g_free(cmdline);
    check(argc == 3 || argc == 4 || argc == 5, "arguments");
    char *end = NULL; guint64 pid = g_ascii_strtoull(argv[1], &end, 10);
    check(pid > 0 && pid <= G_MAXUINT && end && !*end, "process id");
    snapshot = !strcmp(argv[2], "snapshot");
    scrolling = !strcmp(argv[2], "scroll");
    check((snapshot && argc == 3) || ((!strcmp(argv[2], "activate") || scrolling) && (argc == 4 || argc == 5)), "operation");
    if (!snapshot) {
        wanted = argv[3]; gboolean allowed = FALSE;
        if (argc == 5) {
            check(!strcmp(wanted, "View report") &&
                  (!strcmp(argv[4], "Doctor") || !strcmp(argv[4], "Orphan assessment")), "known report frame scope");
            wanted_scope = argv[4];
        }
        for (guint i = 0; i < G_N_ELEMENTS(labels); i++) allowed |= !strcmp(wanted, labels[i]);
        check(allowed, "control allowlist");
    }
    alarm(20); atspi_set_timeout(1000, 1000); check(atspi_init() == 0, "AT-SPI initialization");
    AtspiAccessible *desktop = atspi_get_desktop(0); check(desktop != NULL, "desktop");
    gint apps = atspi_accessible_get_child_count(desktop, &error); check(apps >= 0 && apps <= 32, "application count");
    AtspiAccessible *application = NULL;
    for (gint i = 0; i < apps; i++) {
        AtspiAccessible *candidate = atspi_accessible_get_child_at_index(desktop, i, &error); check(candidate != NULL, "application");
        guint owner = atspi_accessible_get_process_id(candidate, &error); check(TRUE, "application process");
        if (owner == pid) { check(application == NULL, "duplicate process application"); application = g_object_ref(candidate); }
        g_object_unref(candidate);
    }
    if (!application) { puts("{\"status\":\"WAITING_FOR_OWNED_WELCOME\"}"); atspi_exit(); return 75; }
    if (snapshot) printf("{\"status\":\"PASS\",\"pid\":%u,\"nodes\":[", (guint)pid);
    walk(application, 0, NULL);
    if (snapshot) puts("]}");
    else {
        check(matches == 1 && target, "one showing control required");
        AtspiRole role = atspi_accessible_get_role(target, &error); check(TRUE, "control role");
        if (scrolling) {
            ensure_visible((guint)pid);
        } else if (role == ATSPI_ROLE_PAGE_TAB) select_guide_tab((guint)pid);
        else {
            AtspiAction *action = atspi_accessible_get_action_iface(target); check(action != NULL, "action interface");
            gint count = atspi_action_get_n_actions(action, &error); check(count > 0 && count <= 8, "action count");
            gint selected = -1; char *selected_name = NULL;
            for (gint i = 0; i < count; i++) {
                char *name = atspi_action_get_action_name(action, i, &error); check(name != NULL, "action name");
                if (!strcmp(name, "click") || !strcmp(name, "activate") || !strcmp(name, "press") || !strcmp(name, "switch")) {
                    check(selected < 0, "ambiguous action"); selected = i; selected_name = g_strdup(name);
                }
                g_free(name);
            }
            check(selected >= 0 && atspi_action_do_action(action, selected, &error), "control activation");
            printf("{\"status\":\"PASS\",\"pid\":%u,\"actions\":1,\"action_name\":\"%s\"}\n", (guint)pid, selected_name);
            g_free(selected_name);
        }
    }
    if (target) g_object_unref(target);
    if (scroll_peer) g_object_unref(scroll_peer);
    g_object_unref(application); g_object_unref(desktop); atspi_exit(); return 0;
}
