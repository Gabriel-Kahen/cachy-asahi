/* SPDX-License-Identifier: MIT
 * Actual report task/lifetime code, with presentation-only stubs. No display,
 * helper, DB, package or network actor. Real GTK is exercised separately. */
#include <gtk/gtk.h>
#include <string.h>
#include "management.h"
static char *label_text, *raw_text;
static gboolean sensitive;
static void fixture_label(GtkLabel *label, const char *text)
{ (void)label; g_free(label_text); label_text = g_strdup(text); }
static GtkTextBuffer *fixture_buffer(GtkTextView *view) { (void)view; return NULL; }
static void fixture_text(GtkTextBuffer *buffer, const char *text, gint length)
{ (void)buffer; g_free(raw_text); raw_text = length < 0 ? g_strdup(text) : g_strndup(text, (gsize)length); }
static void fixture_sensitive(GtkWidget *widget, gboolean value) { (void)widget; sensitive = value; }
static gboolean fixture_available(ManagementTool tool) { (void)tool; return TRUE; }
static ManagementJob *forbidden_start(ManagementTool tool, ManagementDone done, gpointer data, GError **error)
{ (void)tool; (void)done; (void)data; (void)error; g_error("report test attempted a helper start"); return NULL; }
#define gtk_label_set_text fixture_label
#define gtk_text_view_get_buffer fixture_buffer
#define gtk_text_buffer_set_text fixture_text
#define gtk_widget_set_sensitive fixture_sensitive
#define management_available fixture_available
#define management_start forbidden_start
#define main unused_welcome_main
#include "welcome.c"
#undef main

static void settle(ManagementView *view)
{
    gint64 until = g_get_monotonic_time() + 5000000;
    while (view->reporting && g_get_monotonic_time() < until) {
        while (g_main_context_iteration(NULL, FALSE)) {}
        g_usleep(1000);
    }
    g_assert_false(view->reporting);
    g_assert_null(view->report_cancel);
    g_assert_null(view->job);
    g_assert_cmpuint(view->owner->refs, ==, 1);
}
static char *large_report(void)
{
    char *padding = g_strnfill(9000, 'x');
    char *raw = g_strdup_printf("{\"schema_version\":1,\"scope\":\"LOCAL_INSTALLED_METADATA_ONLY_NOT_PAYLOAD_RELEASE_REMOVAL_OR_HARDWARE_PROOF\",\"apply_supported\":false,\"padding\":\"%s\",\"packages\":{\"after-preview\":{\"candidate\":true}},\"candidates\":[\"after-preview\"],\"broken_dependencies\":[]}", padding);
    g_free(padding); return raw;
}
static void begin(Welcome *owner, char *raw)
{
    owner->refs = 2; /* caller plus the existing command lifetime hold */
    owner->application = (GtkApplication *)g_application_new(APP_ID ".ReportTest", G_APPLICATION_NON_UNIQUE);
    ManagementView *view = &owner->management[MANAGEMENT_ORPHANS];
    view->owner = owner; view->tool = MANAGEMENT_ORPHANS;
    char *diagnostic = g_strdup("caller-owned diagnostic");
    ManagementResult result = {MANAGEMENT_COMPLETE, raw, diagnostic, 0, TRUE, 123};
    g_application_hold(G_APPLICATION(owner->application));
    management_done(NULL, &result, view);
    g_assert_true(view->reporting);
    g_assert_cmpstr(label_text, ==, "Preparing report…");
    /* The real supervisor frees both operands after its callback returns. */
    memset(raw, 'x', strlen(raw)); g_free(raw);
    memset(diagnostic, 'x', strlen(diagnostic)); g_free(diagnostic);
}
static void copied_buffer(void)
{
    Welcome owner = {0}; char *raw = large_report();
    char *prefix = g_strndup(raw, 8192);
    char *expected = g_strconcat(prefix, "\n[Raw preview truncated at 8 KiB.]", NULL);
    g_free(prefix); begin(&owner, raw);
    settle(&owner.management[MANAGEMENT_ORPHANS]);
    g_assert_nonnull(strstr(label_text, "1 possible orphan"));
    g_assert_nonnull(strstr(label_text, "Elapsed: 0.1 seconds."));
    g_assert_cmpstr(raw_text, ==, expected);
    g_assert_cmpint(sensitive, ==, geteuid() != 0);
    g_free(expected); g_object_unref(owner.application);
}
static void close_pending(void)
{
    Welcome owner = {0}; g_clear_pointer(&raw_text, g_free);
    begin(&owner, large_report());
    ManagementView *view = &owner.management[MANAGEMENT_ORPHANS];
    welcome_close(NULL, &owner);
    g_assert_true(owner.closing);
    g_assert_true(g_cancellable_is_cancelled(view->report_cancel));
    g_assert_cmpuint(owner.refs, ==, 2);
    settle(view);
    g_assert_null(raw_text); /* No widget update after close. */
    g_assert_cmpstr(label_text, ==, "Preparing report…");
    g_object_unref(owner.application);
}
static void duplicate_start(void)
{
    Welcome owner = {0}; ManagementView view = {.owner = &owner, .reporting = TRUE};
    management_run(NULL, &view);
    g_assert_true(view.reporting); g_assert_null(view.job);
}
int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/report-work/copied-buffer-and-display", copied_buffer);
    g_test_add_func("/report-work/close-pending-lifetime", close_pending);
    g_test_add_func("/report-work/no-second-start", duplicate_start);
    int result = g_test_run(); g_free(label_text); g_free(raw_text); return result;
}
