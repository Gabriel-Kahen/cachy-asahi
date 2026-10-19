/* SPDX-License-Identifier: MIT
 * Private GTK integration harness; never installed. */
#define main welcome_application_main
#include "welcome.c"
#undef main
#include "boot-fixtures.h"

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

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "list")) { g_print("%s", BOOT_LISTED); return 0; }
    if (argc == 2 && !strcmp(argv[1], "boot-unavailable")) { g_print("%s", BOOT_UNAVAILABLE); return 1; }
    if (argc == 2 && !strcmp(argv[1], "boot-bad")) { g_print("{\"state\":\"captured\"}"); return 0; }
    if (argc == 3 && !strcmp(argv[1], "--json") && !strcmp(argv[2], "profiles")) {
        g_print("{\"status\":\"STORED_CONNECTION_PROFILES\",\"profiles\":[{\"uuid\":\"11111111-2222-4333-8444-555555555555\",\"type\":\"vpn\",\"name\":\"Café 東京 <b>\\t\\u001b\"}],\"live_dns\":\"NOT_REAPPLIED_STORED_PROFILE_ONLY\"}");
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
