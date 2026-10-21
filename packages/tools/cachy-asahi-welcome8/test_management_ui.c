/* SPDX-License-Identifier: MIT
 * Private GTK integration harness; never installed. */
#define _GNU_SOURCE
#define main welcome_application_main
#include "welcome.c"
#undef main
#include "boot-fixtures.h"
#include <errno.h>
#include <signal.h>
#include <unistd.h>

static void assert_static_management(GtkWidget *widget)
{
    g_assert_false(GTK_IS_SPINNER(widget));
    if (GTK_IS_CONTAINER(widget)) {
        GList *children = gtk_container_get_children(GTK_CONTAINER(widget));
        for (GList *child = children; child; child = child->next)
            assert_static_management(GTK_WIDGET(child->data));
        g_list_free(children);
    }
}

static void wait_job(ManagementView *view)
{
    gint64 until = g_get_monotonic_time() + 10000000;
    while ((view->job || view->reporting) && g_get_monotonic_time() < until) {
        while (g_main_context_iteration(NULL, FALSE)) {}
        g_usleep(1000);
    }
    g_assert_null(view->job);
    g_assert_false(view->reporting);
    g_assert_null(view->report_cancel);
}

static void report_test_pump(void)
{
    gint64 until = g_get_monotonic_time() + 100000;
    do {
        while (g_main_context_iteration(NULL, FALSE)) {}
        g_usleep(1000);
    } while (g_get_monotonic_time() < until);
}

static void report_test_state(GtkWidget *text, gboolean showing)
{
    AtkObject *object = gtk_widget_get_accessible(text);
    AtkStateSet *states = atk_object_ref_state_set(object);
    AtkStateSet *parent = ATK_OBJECT_CLASS(welcome_report_accessible_parent_class)->ref_state_set(object);
    g_assert_cmpint(atk_state_set_contains_state(states, ATK_STATE_SHOWING), ==, showing);
    atk_state_set_remove_state(states, ATK_STATE_SHOWING);
    atk_state_set_remove_state(parent, ATK_STATE_SHOWING);
    AtkStateSet *difference = atk_state_set_xor_sets(states, parent);
    g_assert_null(difference);
    g_object_unref(states); g_object_unref(parent);
    gint x, y, width, height;
    atk_component_get_extents(ATK_COMPONENT(object), &x, &y, &width, &height, ATK_XY_SCREEN);
    g_assert_cmpint(width, ==, gtk_widget_get_allocated_width(text));
    g_assert_cmpint(height, ==, gtk_widget_get_allocated_height(text));
    if (!showing) { g_assert_cmpint(x, ==, G_MININT); g_assert_cmpint(y, ==, G_MININT); }
    else {
        GtkWidget *top = gtk_widget_get_toplevel(text);
        gint measured_x, measured_y, origin_x, origin_y;
        g_assert_true(gtk_widget_translate_coordinates(text, top, 0, 0, &measured_x, &measured_y));
        g_assert_true(gdk_window_get_origin(gtk_widget_get_window(top), &origin_x, &origin_y));
        g_assert_cmpint(x, ==, measured_x + origin_x); g_assert_cmpint(y, ==, measured_y + origin_y);
        atk_component_get_extents(ATK_COMPONENT(object), &x, &y, &width, &height, ATK_XY_WINDOW);
        g_assert_cmpint(x, ==, measured_x); g_assert_cmpint(y, ==, measured_y);
        g_assert_true(gtk_widget_translate_coordinates(text, gtk_widget_get_parent(text), 0, 0, &measured_x, &measured_y));
        atk_component_get_extents(ATK_COMPONENT(object), &x, &y, &width, &height, ATK_XY_PARENT);
        g_assert_cmpint(x, ==, measured_x); g_assert_cmpint(y, ==, measured_y);
    }
}

static int report_accessibility_tests(int argc, char **argv)
{
    if (geteuid() == 0) return 77;
    argc = 1; gtk_init(&argc, &argv);
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(window), 320, 240);
    gtk_window_move(GTK_WINDOW(window), 80, 90);
    GtkWidget *outer = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *fixed = gtk_fixed_new(); gtk_widget_set_size_request(fixed, 300, 1000);
    gtk_container_add(GTK_CONTAINER(window), outer); gtk_container_add(GTK_CONTAINER(outer), fixed);
    GtkWidget *expander = gtk_expander_new("View report");
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL); gtk_widget_set_size_request(scroll, 250, 160);
    GtkWidget *text = g_object_new(welcome_report_text_get_type(), NULL);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text), FALSE);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(text)), "Exact raw report\nsecond line", -1);
    gtk_container_add(GTK_CONTAINER(scroll), text); gtk_container_add(GTK_CONTAINER(expander), scroll);
    gtk_fixed_put(GTK_FIXED(fixed), expander, 20, 400);
    report_test_state(text, FALSE); /* Unrealized coordinates stay unavailable. */
    gtk_expander_set_expanded(GTK_EXPANDER(expander), TRUE);
    gtk_widget_show_all(window); report_test_pump();
    GtkAdjustment *adjustment = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(outer));
    gtk_adjustment_set_value(adjustment, 0); report_test_pump();
    report_test_state(text, FALSE); /* Fully below the real viewport. */
    gint content_x, content_y;
    g_assert_true(gtk_widget_translate_coordinates(text, fixed, 0, 0, &content_x, &content_y));
    gtk_adjustment_set_value(adjustment, content_y); report_test_pump();
    report_test_state(text, TRUE);
    AtkObject *object = gtk_widget_get_accessible(text);
    g_assert_cmpint(atk_object_get_role(object), ==, ATK_ROLE_TEXT);
    g_assert_true(ATK_IS_TEXT(object));
    char *raw = atk_text_get_text(ATK_TEXT(object), 0, -1);
    g_assert_cmpstr(raw, ==, "Exact raw report\nsecond line"); g_free(raw);
    AtkStateSet *states = atk_object_ref_state_set(object);
    g_assert_false(atk_state_set_contains_state(states, ATK_STATE_EDITABLE)); g_object_unref(states);
    /* A partly clipped widget has real full extents; no invented clipped box. */
    gtk_adjustment_set_value(adjustment, content_y + 40); report_test_pump();
    report_test_state(text, TRUE);
    gint translated_x, translated_y;
    GtkWidget *viewport = gtk_widget_get_parent(fixed);
    g_assert_true(gtk_widget_translate_coordinates(text, viewport, 0, 0, &translated_x, &translated_y));
    g_assert_cmpint(translated_y, <, 0);
    gtk_adjustment_set_value(adjustment, content_y + gtk_widget_get_allocated_height(text) + 5);
    report_test_pump(); report_test_state(text, FALSE); /* Fully above viewport. */
    gtk_adjustment_set_value(adjustment, content_y); report_test_pump(); report_test_state(text, TRUE);
    gtk_widget_hide(text); report_test_pump(); report_test_state(text, FALSE);
    gtk_widget_show(text); report_test_pump(); report_test_state(text, TRUE);
    gtk_widget_hide(outer); report_test_pump(); report_test_state(text, FALSE);
    gtk_widget_show(outer); report_test_pump();
    gtk_expander_set_expanded(GTK_EXPANDER(expander), FALSE); report_test_pump(); report_test_state(text, FALSE);
    gtk_expander_set_expanded(GTK_EXPANDER(expander), TRUE); report_test_pump();
    gtk_adjustment_set_value(adjustment, content_y); report_test_pump(); report_test_state(text, TRUE);
    gint x, y, width, height;
    report_get_extents(ATK_COMPONENT(object), &x, &y, &width, &height, (AtkCoordType)-1);
    g_assert_cmpint(x, ==, G_MININT); g_assert_cmpint(y, ==, G_MININT);
    g_object_ref(object); gtk_widget_destroy(window); report_test_pump();
    states = atk_object_ref_state_set(object);
    g_assert_true(atk_state_set_contains_state(states, ATK_STATE_DEFUNCT));
    g_assert_false(atk_state_set_contains_state(states, ATK_STATE_SHOWING)); g_object_unref(states);
    atk_component_get_extents(ATK_COMPONENT(object), &x, &y, &width, &height, ATK_XY_SCREEN);
    g_assert_cmpint(x, ==, G_MININT); g_assert_cmpint(y, ==, G_MININT); g_object_unref(object);
    g_print("PASS_REPORT_ACCESSIBILITY: parent states/AtkText, real translated extents, hidden/ancestor-hidden/collapsed/unrealized/defunct/fully-clipped refusal, partial clipping remains full geometry\n");
    return 0;
}

/* Private test mode only: the production report tree with fixed inert data.
 * No installed helper, journal, network, device or hardware query is invoked. */
static Welcome *viewport_welcome;
static GtkWidget *viewport_expander;
static guint viewport_stage;
static gboolean viewport_ready(gpointer unused)
{
    (void)unused;
    if (viewport_stage == 0 || viewport_stage == 2)
        gtk_widget_grab_focus(viewport_expander);
    else if (viewport_stage == 1)
        gtk_expander_set_expanded(GTK_EXPANDER(viewport_expander), TRUE);
    else {
        g_print("READY %ld\n", (long)getpid()); fflush(stdout);
        return G_SOURCE_REMOVE;
    }
    viewport_stage++; return G_SOURCE_CONTINUE;
}
static int viewport_fixture(int argc, char **argv)
{
    g_assert_cmpint(argc, ==, 3);
    g_assert_true(!strcmp(argv[2], "orphans") || !strcmp(argv[2], "dns"));
    if (geteuid() == 0) return 77;
    gboolean dns = !strcmp(argv[2], "dns");
    int gtk_argc = 1; gtk_init(&gtk_argc, &argv);
    management_test_configure("/nonexistent/welcome7-viewport-private-fixture", NULL, 30000, 1048576, TRUE);
    GtkApplication *app = gtk_application_new(APP_ID, G_APPLICATION_NON_UNIQUE);
    GError *error = NULL;
    g_assert_true(g_application_register(G_APPLICATION(app), NULL, &error));
    g_assert_no_error(error); activate(app, NULL);
    GtkWindow *window = gtk_application_get_active_window(app);
    viewport_welcome = g_object_get_data(G_OBJECT(window), "welcome-state");
    g_assert_nonnull(viewport_welcome);
    GtkWidget *page = gtk_stack_get_child_by_name(GTK_STACK(viewport_welcome->stack), "management");
    gtk_stack_set_transition_type(GTK_STACK(viewport_welcome->stack), GTK_STACK_TRANSITION_TYPE_NONE);
    gtk_stack_set_visible_child(GTK_STACK(viewport_welcome->stack), page);
    ManagementView *view = &viewport_welcome->management[dns ? MANAGEMENT_DNS : MANAGEMENT_ORPHANS];
    const char *raw = dns ?
        "{\"status\":\"STORED_CONNECTION_PROFILES\",\"profiles\":[{\"uuid\":\"11111111-2222-4333-8444-555555555555\",\"type\":\"vpn\",\"name\":\"Owned private DNS fixture\"}],\"live_dns\":\"NOT_REAPPLIED_STORED_PROFILE_ONLY\"}" :
        "{\"schema_version\":1,\"scope\":\"LOCAL_INSTALLED_METADATA_ONLY_NOT_PAYLOAD_RELEASE_REMOVAL_OR_HARDWARE_PROOF\",\"apply_supported\":false,\"packages\":{\"fixture-leaf\":{\"candidate\":true}},\"candidates\":[\"fixture-leaf\"],\"broken_dependencies\":[]}";
    ManagementResult result = {MANAGEMENT_COMPLETE, raw, "fixed private viewport fixture", 0, TRUE, 1};
    viewport_welcome->refs++; g_application_hold(G_APPLICATION(app));
    gtk_widget_set_sensitive(view->button, FALSE); management_done(NULL, &result, view); wait_job(view);
    GtkWidget *scroll = gtk_widget_get_parent(view->raw); g_assert_true(GTK_IS_SCROLLED_WINDOW(scroll));
    viewport_expander = gtk_widget_get_parent(scroll); g_assert_true(GTK_IS_EXPANDER(viewport_expander));
    g_assert_false(gtk_text_view_get_editable(GTK_TEXT_VIEW(view->raw)));
    g_assert_false(gtk_text_view_get_cursor_visible(GTK_TEXT_VIEW(view->raw)));
    g_assert_true(gtk_text_view_get_monospace(GTK_TEXT_VIEW(view->raw)));
    g_assert_cmpint(gtk_text_view_get_wrap_mode(GTK_TEXT_VIEW(view->raw)), ==, GTK_WRAP_WORD_CHAR);
    gint width, height; gtk_widget_get_size_request(scroll, &width, &height); g_assert_cmpint(height, ==, 160);
    gtk_window_resize(window, 1000, 550);
    g_timeout_add(600, viewport_ready, NULL); gtk_main();
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--report-accessibility-tests")) return report_accessibility_tests(argc, argv);
    if (argc == 3 && !strcmp(argv[1], "--viewport-fixture")) return viewport_fixture(argc, argv);
    if (argc == 2 && !strcmp(argv[1], "list")) { g_print("%s", BOOT_LISTED); return 0; }
    if (argc == 2 && !strcmp(argv[1], "boot-unavailable")) { g_print("%s", BOOT_UNAVAILABLE); return 1; }
    if (argc == 2 && !strcmp(argv[1], "boot-bad")) { g_print("{\"state\":\"captured\"}"); return 0; }
    if (argc == 3 && !strcmp(argv[1], "--json") && !strcmp(argv[2], "profiles")) {
        if (fputs("{\"status\":\"STORED_CONNECTION_PROFILES\",\"profiles\":[{\"uuid\":\"11111111-2222-4333-8444-555555555555\",\"type\":\"vpn\",\"name\":\"Café 東京 <b>\\t\\u001b\"}],\"live_dns\":\"NOT_REAPPLIED_STORED_PROFILE_ONLY\"}", stdout) == EOF || fflush(stdout) == EOF) return 1;
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "dns-bad")) { g_print("{\"status\":\"APPLIED\"}"); return 0; }
    if (argc == 2 && !strcmp(argv[1], "doctor")) {
        g_print("{\"schema_version\":1,\"tool\":\"cachy-asahi-doctor\",\"scope\":\"local observations only\",\"checks\":[{\"check\":\"sample\",\"state\":\"unknown\",\"value\":null,\"note\":\"unavailable\"}],\"coverage\":{\"checked\":0,\"unavailable\":0,\"unknown\":1}}");
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "refused")) {
        g_print("{\"verification\":\"REFUSED\",\"reason\":\"fixture unavailable\"}");
        return 1;
    }
    if (argc == 2 && !strcmp(argv[1], "orphans")) {
        g_print("{\"schema_version\":1,\"scope\":\"LOCAL_INSTALLED_METADATA_ONLY_NOT_PAYLOAD_RELEASE_REMOVAL_OR_HARDWARE_PROOF\",\"apply_supported\":false,\"packages\":{\"sample-leaf\":{\"candidate\":true}},\"candidates\":[\"sample-leaf\"],\"broken_dependencies\":[]}");
        return 0;
    }
    if (argc == 2 && g_str_has_prefix(argv[1], "cancel-tree:")) {
        pid_t child = fork(); g_assert_cmpint(child, >=, 0);
        if (child == 0) { g_assert_cmpint(setsid(), >=, 0); g_usleep(30000000); _exit(0); }
        char *pids = g_strdup_printf("%ld %ld\n", (long)getpid(), (long)child);
        g_assert_true(g_file_set_contents(argv[1] + strlen("cancel-tree:"), pids, -1, NULL));
        g_free(pids); g_usleep(30000000); return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "waiting")) {
        g_usleep(30000000); return 0;
    }
    if (geteuid() == 0) { g_print("SKIP: GTK management checks require an ordinary user.\n"); return 77; }
    const char *snapshot = argc == 3 && !strcmp(argv[1], "--screenshot") ? argv[2] : NULL;
    argc = 1;
    gtk_init(&argc, &argv);
    char *self = g_file_read_link("/proc/self/exe", NULL);
    g_assert_nonnull(self);
    management_test_configure("/nonexistent/welcome-private-fixture", NULL, 30000, 1048576, TRUE);
    GtkApplication *app = gtk_application_new(APP_ID, G_APPLICATION_NON_UNIQUE);
    GError *error = NULL;
    g_assert_true(g_application_register(G_APPLICATION(app), NULL, &error));
    g_assert_no_error(error);
    activate(app, NULL);
    GtkWindow *window = gtk_application_get_active_window(app);
    g_assert_nonnull(window);
    Welcome *welcome = g_object_get_data(G_OBJECT(window), "welcome-state");
    g_assert_nonnull(gtk_stack_get_child_by_name(GTK_STACK(welcome->stack), "management"));
    for (guint i = 0; i < MANAGEMENT_TOOL_COUNT; i++) {
        g_assert_null(welcome->management[i].job);
        g_assert_false(gtk_widget_get_sensitive(welcome->management[i].stop));
        g_assert_false(gtk_widget_get_sensitive(welcome->management[i].button));
        g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(welcome->management[i].summary)), "unavailable"));
    }
    management_test_configure(self, "doctor", 30000, 1048576, TRUE);
    ManagementView *doctor = &welcome->management[MANAGEMENT_DOCTOR];
    gtk_widget_set_sensitive(doctor->button, TRUE);
    gtk_button_clicked(GTK_BUTTON(doctor->button));
    g_assert_nonnull(doctor->job);
    g_assert_false(gtk_widget_get_sensitive(doctor->button));
    g_assert_cmpstr(gtk_label_get_text(GTK_LABEL(doctor->summary)), ==, "Running check…");
    assert_static_management(gtk_stack_get_child_by_name(GTK_STACK(welcome->stack), "management"));
    wait_job(doctor);
    const char *summary = gtk_label_get_text(GTK_LABEL(doctor->summary));
    g_print("Doctor UI summary: %s\n", summary);
    g_assert_nonnull(strstr(summary, "0 observed, 0 unavailable, 1 unknown"));
    g_assert_null(strstr(summary, "exit status"));
    g_assert_null(strstr(summary, "Read-only command completed"));
    management_test_configure(self, "refused", 30000, 1048576, TRUE);
    ManagementView *orphans = &welcome->management[MANAGEMENT_ORPHANS];
    gtk_widget_set_sensitive(orphans->button, TRUE);
    gtk_button_clicked(GTK_BUTTON(orphans->button));
    wait_job(orphans);
    summary = gtk_label_get_text(GTK_LABEL(orphans->summary));
    g_assert_nonnull(strstr(summary, "Check failed"));
    g_assert_nonnull(strstr(summary, "Exit status: 1"));
    g_assert_nonnull(strstr(summary, "Assessment refused: fixture unavailable"));
    management_test_configure(self, "orphans", 30000, 1048576, TRUE);
    gtk_button_clicked(GTK_BUTTON(orphans->button));
    wait_job(orphans);
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(orphans->summary)), "1 possible orphan"));
    /* The supervision result's buffer may disappear as soon as its callback
     * returns. Also refuse duplicate starts throughout report preparation. */
    char *padding = g_strnfill(9000, 'x');
    char *owned_raw = g_strdup_printf("{\"schema_version\":1,\"scope\":\"LOCAL_INSTALLED_METADATA_ONLY_NOT_PAYLOAD_RELEASE_REMOVAL_OR_HARDWARE_PROOF\",\"apply_supported\":false,\"padding\":\"%s\",\"packages\":{\"after-preview\":{\"candidate\":true}},\"candidates\":[\"after-preview\"],\"broken_dependencies\":[]}", padding);
    g_free(padding);
    char *first_bytes = g_strndup(owned_raw, 8192);
    char *expected_preview = g_strconcat(first_bytes, "\n[Raw preview truncated at 8 KiB.]", NULL);
    g_free(first_bytes);
    ManagementResult owned_result = {MANAGEMENT_COMPLETE, owned_raw, "fixture", 0, TRUE, 1};
    welcome->refs++; g_application_hold(G_APPLICATION(app));
    gtk_widget_set_sensitive(orphans->button, FALSE);
    management_done(NULL, &owned_result, orphans);
    g_assert_true(orphans->reporting);
    management_run(NULL, orphans);
    g_assert_null(orphans->job);
    memset(owned_raw, 'x', strlen(owned_raw)); g_free(owned_raw);
    wait_job(orphans);
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(orphans->summary)), "1 possible orphan"));
    GtkTextBuffer *raw_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(orphans->raw));
    GtkTextIter first_byte, last_byte;
    gtk_text_buffer_get_bounds(raw_buffer, &first_byte, &last_byte);
    char *actual_preview = gtk_text_buffer_get_text(raw_buffer, &first_byte, &last_byte, FALSE);
    g_assert_cmpstr(actual_preview, ==, expected_preview);
    g_free(actual_preview); g_free(expected_preview);
    ManagementView *dns = &welcome->management[MANAGEMENT_DNS];
    management_test_configure(self, NULL, 30000, 1048576, TRUE);
    gtk_widget_set_sensitive(dns->button, TRUE);
    gtk_button_clicked(GTK_BUTTON(dns->button));
    g_assert_nonnull(dns->job);
    management_run(NULL, dns); /* Duplicate click cannot launch another child. */
    wait_job(dns);
    summary = gtk_label_get_text(GTK_LABEL(dns->summary));
    g_assert_nonnull(strstr(summary, "1 stored connection profile."));
    g_assert_nonnull(strstr(summary, "Café 東京 <b>\\u0009\\u001b"));
    g_assert_false(gtk_label_get_use_markup(GTK_LABEL(dns->summary)));
    g_assert_true(gtk_widget_get_sensitive(dns->button));
    management_test_configure(self, "dns-bad", 30000, 1048576, TRUE);
    gtk_button_clicked(GTK_BUTTON(dns->button)); wait_job(dns);
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(dns->summary)), "invalid or unsupported"));
    management_test_configure(self, "waiting", 80, 1048576, TRUE);
    gtk_button_clicked(GTK_BUTTON(dns->button)); wait_job(dns);
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(dns->summary)), "time limit"));
    /* Real owned helper plus separate-session descendant: cancel just this
     * panel, keep the window/other panel alive, and retry only after retirement. */
    GError *temporary_error = NULL;
    char *temporary = g_dir_make_tmp("welcome-stop-XXXXXX", &temporary_error);
    g_assert_no_error(temporary_error); g_assert_nonnull(temporary);
    char *pid_path = g_build_filename(temporary, "pids", NULL);
    char *cancel_argument = g_strconcat("cancel-tree:", pid_path, NULL);
    management_test_configure(self, cancel_argument, 30000, 1048576, TRUE);
    gtk_button_clicked(GTK_BUTTON(dns->button));
    g_assert_nonnull(dns->job); g_assert_true(gtk_widget_get_sensitive(dns->stop));
    gint64 ready_until = g_get_monotonic_time() + 5000000;
    while (!g_file_test(pid_path, G_FILE_TEST_EXISTS) && g_get_monotonic_time() < ready_until) {
        while (g_main_context_iteration(NULL, FALSE)) {} g_usleep(1000);
    }
    char *pid_text = NULL; g_assert_true(g_file_get_contents(pid_path, &pid_text, NULL, NULL));
    long helper, descendant; g_assert_cmpint(sscanf(pid_text, "%ld %ld", &helper, &descendant), ==, 2);
    g_assert_cmpint(kill((pid_t)helper, 0), ==, 0); g_assert_cmpint(kill((pid_t)descendant, 0), ==, 0);
    while (getsid((pid_t)descendant) != (pid_t)descendant && g_get_monotonic_time() < ready_until) {
        while (g_main_context_iteration(NULL, FALSE)) {} g_usleep(1000);
    }
    g_assert_cmpint(getsid((pid_t)descendant), ==, descendant);
    gtk_button_clicked(GTK_BUTTON(dns->stop));
    g_assert_true(dns->stopping); g_assert_nonnull(dns->job);
    g_assert_false(gtk_widget_get_sensitive(dns->button));
    g_assert_false(gtk_widget_get_sensitive(dns->stop));
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(dns->summary)), "Waiting for its processes to retire"));
    management_stop(NULL, dns); management_run(NULL, dns); /* No duplicate request/start. */
    wait_job(dns);
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(dns->summary)), "Check cancelled."));
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(dns->summary)), "processes were retired"));
    g_assert_false(dns->stopping); g_assert_false(gtk_widget_get_sensitive(dns->stop));
    g_assert_true(gtk_widget_get_sensitive(dns->button));
    g_assert_false(welcome->closing); g_assert_true(gtk_widget_get_visible(GTK_WIDGET(window)));
    g_assert_true(gtk_widget_get_sensitive(doctor->button));
    errno = 0; g_assert_cmpint(kill((pid_t)helper, 0), ==, -1); g_assert_cmpint(errno, ==, ESRCH);
    errno = 0; g_assert_cmpint(kill((pid_t)descendant, 0), ==, -1); g_assert_cmpint(errno, ==, ESRCH);
    management_stop(NULL, dns); /* An idle panel remains unchanged. */
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(dns->summary)), "Check cancelled."));
    g_assert_cmpint(unlink(pid_path), ==, 0); g_assert_cmpint(rmdir(temporary), ==, 0);
    g_free(pid_text); g_free(cancel_argument); g_free(pid_path); g_free(temporary);
    g_print("PASS_STOP_CHECK: owned helper/separate-session descendant retired, Run held, repeated stop/start refused, window/other panel preserved, idle stop ignored\n");
    /* Restore a useful read-only summary for the optional fixture screenshot. */
    management_test_configure(self, NULL, 30000, 1048576, TRUE);
    gtk_button_clicked(GTK_BUTTON(dns->button)); wait_job(dns);
    ManagementView *boot = &welcome->management[MANAGEMENT_BOOT_HISTORY];
    management_test_configure(self, NULL, 30000, 1048576, TRUE);
    gtk_widget_set_sensitive(boot->button, TRUE);
    gtk_button_clicked(GTK_BUTTON(boot->button)); management_run(NULL, boot); wait_job(boot);
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(boot->summary)), "Boot ID: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(boot->summary)), "History completeness unknown"));
    g_assert_false(gtk_label_get_use_markup(GTK_LABEL(boot->summary)));
    GtkTextBuffer *boot_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(boot->raw));
    GtkTextIter boot_first, boot_last; gtk_text_buffer_get_bounds(boot_buffer, &boot_first, &boot_last);
    char *boot_raw = gtk_text_buffer_get_text(boot_buffer, &boot_first, &boot_last, FALSE);
    g_assert_cmpstr(boot_raw, ==, BOOT_LISTED); g_free(boot_raw);
    management_test_configure(self, "boot-unavailable", 30000, 1048576, TRUE);
    gtk_button_clicked(GTK_BUTTON(boot->button)); wait_job(boot);
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(boot->summary)), "unavailable to this login"));
    management_test_configure(self, "boot-bad", 30000, 1048576, TRUE);
    gtk_button_clicked(GTK_BUTTON(boot->button)); wait_job(boot);
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(boot->summary)), "invalid or unsupported"));
    management_test_configure(self, "waiting", 80, 1048576, TRUE);
    gtk_button_clicked(GTK_BUTTON(boot->button)); wait_job(boot);
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(boot->summary)), "time limit"));
    /* A synthetic unconfirmed-retirement reply must never unlock this panel. */
    ManagementResult incomplete = {MANAGEMENT_CANCELLED, "", "fixture unconfirmed retirement", -1, FALSE, 1};
    welcome->refs++; g_application_hold(G_APPLICATION(app));
    management_done(NULL, &incomplete, dns); wait_job(dns);
    g_assert_false(gtk_widget_get_sensitive(dns->button));
    g_assert_false(gtk_widget_get_sensitive(dns->stop));
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(dns->summary)), "retirement is unconfirmed"));
    g_assert_nonnull(strstr(gtk_label_get_text(GTK_LABEL(dns->summary)), "No assessment conclusion"));
    if (snapshot) {
        gtk_window_move(window, 0, 0);
        gtk_window_resize(window, 820, 900);
        gtk_stack_set_transition_type(GTK_STACK(welcome->stack), GTK_STACK_TRANSITION_TYPE_NONE);
        gtk_stack_set_visible_child_name(GTK_STACK(welcome->stack), "management");
        gint64 until = g_get_monotonic_time() + 200000;
        while (g_get_monotonic_time() < until) {
            while (g_main_context_iteration(NULL, FALSE)) {}
            g_usleep(1000);
        }
        GdkWindow *surface = gtk_widget_get_window(GTK_WIDGET(window));
        GdkPixbuf *pixels = gdk_pixbuf_get_from_window(surface, 0, 0,
            gdk_window_get_width(surface), gdk_window_get_height(surface));
        g_assert_nonnull(pixels);
        g_assert_true(gdk_pixbuf_save(pixels, snapshot, "png", &error, NULL));
        g_assert_no_error(error); g_object_unref(pixels);
    }
    management_test_configure(self, "waiting", 30000, 1048576, TRUE);
    gtk_widget_set_sensitive(doctor->button, TRUE);
    gtk_button_clicked(GTK_BUTTON(doctor->button));
    g_assert_nonnull(doctor->job);
    g_assert_false(gtk_widget_get_sensitive(doctor->button));
    g_assert_cmpstr(gtk_label_get_text(GTK_LABEL(doctor->summary)), ==, "Running check…");
    assert_static_management(gtk_stack_get_child_by_name(GTK_STACK(welcome->stack), "management"));
    welcome->refs++; /* Keep state inspectable through the close callback. */
    gtk_widget_destroy(GTK_WIDGET(window));
    g_assert_true(welcome->closing);
    wait_job(doctor);
    welcome_unref(welcome);
    /* A second owned window closes while report preparation is pending.
     * No helper is launched; the complete result is an immutable test datum. */
    activate(app, NULL);
    window = gtk_application_get_active_window(app);
    welcome = g_object_get_data(G_OBJECT(window), "welcome-state");
    orphans = &welcome->management[MANAGEMENT_ORPHANS];
    const char *raw = "{\"schema_version\":1,\"scope\":\"LOCAL_INSTALLED_METADATA_ONLY_NOT_PAYLOAD_RELEASE_REMOVAL_OR_HARDWARE_PROOF\",\"apply_supported\":false,\"packages\":{},\"candidates\":[],\"broken_dependencies\":[]}";
    ManagementResult complete = {MANAGEMENT_COMPLETE, raw, "fixture", 0, TRUE, 1};
    welcome->refs++; g_application_hold(G_APPLICATION(app));
    management_done(NULL, &complete, orphans);
    g_assert_true(orphans->reporting);
    g_assert_cmpstr(gtk_label_get_text(GTK_LABEL(orphans->summary)), ==, "Preparing report…");
    welcome->refs++; /* Inspect cancellation through the last worker callback. */
    gtk_widget_destroy(GTK_WIDGET(window));
    g_assert_true(welcome->closing);
    g_assert_true(g_cancellable_is_cancelled(orphans->report_cancel));
    wait_job(orphans);
    welcome_unref(welcome);
    g_object_unref(app); g_free(self);
    g_print("PASS_GTK_MANAGEMENT: absent tool, no startup job, explicit run, unknown/refusal/candidate/DNS summaries, DNS malformed/timeout refusal, close retirement\n");
    return 0;
}
