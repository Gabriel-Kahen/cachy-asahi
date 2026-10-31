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
static gboolean snapshot;

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
         (!strcmp(name, "Welcome") || !strcmp(name, "System") || !strcmp(name, "Guides")));
}

static void walk(AtspiAccessible *node, guint depth)
{
    check(depth <= 12 && nodes < 192, "tree bound");
    char *name = atspi_accessible_get_name(node, &error); check(name != NULL, "node name");
    check(strlen(name) <= 65536, "name bound");
    AtspiRole role = atspi_accessible_get_role(node, &error); check(TRUE, "node role");
    AtspiStateSet *states = atspi_accessible_get_state_set(node);
    gboolean showing = state(states, ATSPI_STATE_SHOWING);
    if (wanted && showing && !strcmp(name, wanted) && control_role(role, name)) {
        check(state(states, ATSPI_STATE_ENABLED) && state(states, ATSPI_STATE_SENSITIVE), "disabled control");
        matches++; if (!target) target = g_object_ref(node);
    }
    if (snapshot) {
        char *encoded = g_base64_encode((const guchar *)name, MIN(strlen(name), 160));
        printf("%s{\"name_base64\":\"%s\",\"role\":%u,\"showing\":%s,\"selected\":%s,\"checked\":%s",
            nodes ? "," : "", encoded, (guint)role, showing ? "true" : "false",
            state(states, ATSPI_STATE_SELECTED) ? "true" : "false", state(states, ATSPI_STATE_CHECKED) ? "true" : "false");
        g_free(encoded);
        AtspiText *text = atspi_accessible_get_text_iface(node);
        if (text && showing) {
            gint count = atspi_text_get_character_count(text, &error); check(count >= 0 && count <= 65536, "text bound");
            char *body = atspi_text_get_text(text, 0, count, &error); check(body != NULL && strlen(body) <= 262144, "text");
            char *hash = g_compute_checksum_for_string(G_CHECKSUM_SHA256, body, -1);
            char *prefix = g_base64_encode((const guchar *)body, MIN(strlen(body), 192));
            printf(",\"text_sha256\":\"%s\",\"text_bytes\":%zu,\"prefix_base64\":\"%s\"", hash, strlen(body), prefix);
            g_free(prefix); g_free(hash); g_free(body);
        }
        printf("}");
    }
    nodes++;
    gint count = atspi_accessible_get_child_count(node, &error); check(count >= 0 && count <= 192, "child count");
    for (gint i = 0; i < count; i++) {
        AtspiAccessible *child = atspi_accessible_get_child_at_index(node, i, &error); check(child != NULL, "child");
        walk(child, depth + 1); g_object_unref(child);
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
                            "Open Terminal", "Open Files", "Refresh system status" };
    char *cmdline = NULL; gsize bytes = 0;
    check(getuid() == 23001 && geteuid() == 23001 &&
          g_file_get_contents("/proc/cmdline", &cmdline, &bytes, NULL) &&
          strstr(cmdline, "cachy_asahi_welcome_gui=1"), "private guest guard");
    g_free(cmdline);
    check(argc == 3 || argc == 4, "arguments");
    char *end = NULL; guint64 pid = g_ascii_strtoull(argv[1], &end, 10);
    check(pid > 0 && pid <= G_MAXUINT && end && !*end, "process id");
    snapshot = !strcmp(argv[2], "snapshot");
    check((snapshot && argc == 3) || (!strcmp(argv[2], "activate") && argc == 4), "operation");
    if (!snapshot) {
        wanted = argv[3]; gboolean allowed = FALSE;
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
    walk(application, 0);
    if (snapshot) puts("]}");
    else {
        check(matches == 1 && target, "one showing control required");
        AtspiRole role = atspi_accessible_get_role(target, &error); check(TRUE, "control role");
        if (role == ATSPI_ROLE_PAGE_TAB) select_guide_tab((guint)pid);
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
    g_object_unref(application); g_object_unref(desktop); atspi_exit(); return 0;
}
