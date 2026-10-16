/* SPDX-License-Identifier: MIT
 * Private GTK integration harness; never installed. */
#define main welcome_application_main
#include "welcome.c"
#undef main

static void wait_job(ManagementView *view)
{
    gint64 until = g_get_monotonic_time() + 10000000;
    while (view->job && g_get_monotonic_time() < until) {
        while (g_main_context_iteration(NULL, FALSE)) {}
        g_usleep(1000);
    }
    g_assert_null(view->job);
}

int main(int argc, char **argv)
{
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
    welcome->refs++; /* Keep state inspectable through the close callback. */
    gtk_widget_destroy(GTK_WIDGET(window));
    g_assert_true(welcome->closing);
    wait_job(doctor);
    welcome_unref(welcome);
    g_object_unref(app); g_free(self);
    g_print("PASS_GTK_MANAGEMENT: absent tool, no startup job, explicit run, unknown/refusal/candidate summaries, close retirement\n");
    return 0;
}
