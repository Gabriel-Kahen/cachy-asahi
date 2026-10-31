/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 cachy-asahi contributors */
#include <gtk/gtk.h>
#include <string.h>
#include <unistd.h>
#include "management.h"
#include "management-report.h"
#include "status.h"

#ifndef WELCOME_DOC_DIR
#define WELCOME_DOC_DIR "/usr/share/doc/cachy-asahi-welcome"
#endif
#define APP_ID "io.github.GabrielKahen.CachyAsahiWelcome"
#define PACKAGE_DB "/var/lib/pacman/local"

static const char *const guides[] = { "first-run", "updates", "recovery" };
static const char *const guide_titles[] = { "First steps", "Updates", "Recovery" };

typedef struct Welcome Welcome;
typedef struct {
    Welcome *owner;
    ManagementTool tool;
    GtkWidget *button, *summary, *raw;
    ManagementJob *job;
    GCancellable *report_cancel;
    gboolean reporting;
} ManagementView;
struct Welcome {
    GtkWidget *window, *stack, *notebook, *system_text;
    GtkApplication *application;
    guint refs;
    gboolean closing;
    ManagementView management[MANAGEMENT_TOOL_COUNT];
};

static void welcome_unref(gpointer data)
{
    Welcome *welcome = data;
    if (--welcome->refs == 0) {
        g_object_unref(welcome->application);
        g_free(welcome);
    }
}

static void welcome_close(GtkWidget *widget, gpointer data)
{
    (void)widget;
    Welcome *welcome = data;
    welcome->closing = TRUE;
    for (guint i = 0; i < MANAGEMENT_TOOL_COUNT; i++) {
        if (welcome->management[i].job) management_cancel(welcome->management[i].job);
        if (welcome->management[i].report_cancel) g_cancellable_cancel(welcome->management[i].report_cancel);
    }
}


static GtkWidget *paragraph(const char *text)
{
    GtkWidget *label = gtk_label_new(text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0);
    gtk_label_set_selectable(GTK_LABEL(label), TRUE);
    return label;
}

static GtkWidget *column(void)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    gtk_container_set_border_width(GTK_CONTAINER(box), 24);
    return box;
}

/* Plain text only. Retain a bounded preview even when JSON validation fails. */
static void management_raw(ManagementView *view, const char *output)
{
    gsize length = output ? strlen(output) : 0;
    gsize shown = MIN(length, (gsize)(view->tool == MANAGEMENT_ORPHANS ? 8192 : 65536));
    char *valid = g_utf8_make_valid(output ? output : "", (gssize)shown);
    char *text = g_strconcat(valid, length > shown ? (view->tool == MANAGEMENT_ORPHANS ? "\n[Raw preview truncated at 8 KiB.]" : "\n[Raw preview truncated at 64 KiB.]") : "", NULL);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view->raw)), text, -1);
    g_free(valid); g_free(text);
}

static void management_present(const ManagementResult *result, ManagementView *view, ManagementReport report)
{
    Welcome *welcome = view->owner;
    if (!welcome->closing) {
        const char *outcome = "Check failed.";
        switch (result->state) {
        case MANAGEMENT_COMPLETE: outcome = "Check completed."; break;
        case MANAGEMENT_FAILED: outcome = "Check failed."; break;
        case MANAGEMENT_TIMEOUT: outcome = "Check stopped: time limit reached."; break;
        case MANAGEMENT_OUTPUT_LIMIT: outcome = "Check stopped: output limit reached."; break;
        case MANAGEMENT_CANCELLED: outcome = "Check cancelled."; break;
        case MANAGEMENT_UNAVAILABLE: outcome = "The installed tool is unavailable."; break;
        case MANAGEMENT_UNSUPPORTED: outcome = "This check is unsupported in the current session."; break;
        }
        if (!result->retired) outcome = "Check incomplete: process retirement is unconfirmed.";
        if (!result->retired) {
            management_report_clear(&report);
            report.summary = g_strdup("No assessment conclusion is available from this incomplete run.");
        }
        char *text;
        if (result->state == MANAGEMENT_COMPLETE && result->retired) {
            text = g_strdup_printf("%s\nElapsed: %.1f seconds.", report.summary, result->elapsed_ms / 1000.0);
        } else {
            text = g_strdup_printf("%s\n%s\n%s\nExit status: %d; elapsed: %.1f seconds.",
                outcome, report.summary,
                result->diagnostic && *result->diagnostic ? result->diagnostic : "",
                result->exit_code, result->elapsed_ms / 1000.0);
        }
        gtk_label_set_text(GTK_LABEL(view->summary), text);
        management_raw(view, result->output);
        gtk_widget_set_sensitive(view->button, result->retired && management_available(view->tool) && geteuid() != 0);
        g_free(text);
    }
    management_report_clear(&report);
    g_application_release(G_APPLICATION(welcome->application));
    welcome_unref(welcome);
}

/* Parsing up to1MiB is pure GLib work. Keep it off the GTK/AT-SPI main
 * context; all widget updates and lifetime release remain on that context. */
typedef struct {
    ManagementTool tool;
    ManagementResult result;
    ManagementReport report;
} ReportWork;

static void report_work_free(gpointer data)
{
    ReportWork *work = data;
    g_free((char *)work->result.output);
    g_free((char *)work->result.diagnostic);
    management_report_clear(&work->report);
    g_free(work);
}

static void report_prepare(GTask *task, gpointer source, gpointer data, GCancellable *cancel)
{
    (void)source; (void)cancel;
    ReportWork *work = data;
    if (g_task_return_error_if_cancelled(task)) return;
    work->report = management_report_parse(work->tool, work->result.output);
    g_task_return_boolean(task, TRUE);
}

static void report_ready(GObject *source, GAsyncResult *result, gpointer data)
{
    (void)source;
    ManagementView *view = data;
    ReportWork *work = g_task_get_task_data(G_TASK(result));
    GError *error = NULL;
    gboolean prepared = g_task_propagate_boolean(G_TASK(result), &error);
    view->reporting = FALSE;
    g_clear_object(&view->report_cancel);
    if (!prepared && !view->owner->closing) {
        management_report_clear(&work->report);
        work->report.summary = g_strdup("Report preparation was cancelled. No assessment conclusion is available.");
    }
    g_clear_error(&error);
    ManagementReport report = work->report;
    work->report.summary = NULL;
    management_present(&work->result, view, report);
}

static void management_done(ManagementJob *job, const ManagementResult *result, gpointer data)
{
    (void)job;
    ManagementView *view = data;
    view->job = NULL;
    if (view->owner->closing) {
        ManagementReport report = {MANAGEMENT_REPORT_INVALID, NULL};
        management_present(result, view, report);
        return;
    }
    ReportWork *work = g_new0(ReportWork, 1);
    work->tool = view->tool;
    work->result = *result;
    /* The supervision callback owns these strings only until we return. */
    work->result.output = g_strdup(result->output ? result->output : "");
    work->result.diagnostic = g_strdup(result->diagnostic ? result->diagnostic : "");
    view->reporting = TRUE;
    view->report_cancel = g_cancellable_new();
    gtk_label_set_text(GTK_LABEL(view->summary), "Preparing report…");
    GTask *task = g_task_new(NULL, view->report_cancel, report_ready, view);
    g_task_set_task_data(task, work, report_work_free);
    g_task_set_return_on_cancel(task, FALSE);
    /* Default return-on-cancel=FALSE keeps the existing application/state hold
     * until the worker has actually returned, including window close. */
    g_task_run_in_thread(task, report_prepare);
    g_object_unref(task);
}

static void management_run(GtkButton *button, gpointer data)
{
    (void)button;
    ManagementView *view = data;
    if (view->job || view->reporting || view->owner->closing) return;
    GError *error = NULL;
    ManagementJob *job = management_start(view->tool, management_done, view, &error);
    if (!job) {
        gtk_label_set_text(GTK_LABEL(view->summary), error ? error->message : "Could not start this check.");
        g_clear_error(&error); return;
    }
    view->job = job;
    view->owner->refs++;
    g_application_hold(G_APPLICATION(view->owner->application));
    gtk_widget_set_sensitive(view->button, FALSE);
    gtk_label_set_text(GTK_LABEL(view->summary), "Running check…");
    management_raw(view, "");
}

static GtkWidget *management_page(Welcome *welcome)
{
    static const char *const titles[] = { "Doctor", "Orphan assessment" };
    static const char *const descriptions[] = {
        "Check local system and service status.",
        "Find possible orphan packages and broken dependencies."
    };
    static const char *const buttons[] = { "Run Doctor", "Assess orphan packages" };
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    GtkWidget *box = column();
    gtk_container_add(GTK_CONTAINER(scroll), box);
    gtk_box_pack_start(GTK_BOX(box), paragraph("Run local checks and inspect installed packages. Checks do not change your system."), FALSE, FALSE, 0);
    for (guint i = 0; i < MANAGEMENT_TOOL_COUNT; i++) {
        ManagementView *view = &welcome->management[i];
        view->owner = welcome; view->tool = (ManagementTool)i;
        GtkWidget *frame = gtk_frame_new(titles[i]);
        GtkWidget *content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
        gtk_container_set_border_width(GTK_CONTAINER(content), 14);
        gtk_container_add(GTK_CONTAINER(frame), content);
        gtk_box_pack_start(GTK_BOX(content), paragraph(descriptions[i]), FALSE, FALSE, 0);
        GtkWidget *actions = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
        view->button = gtk_button_new_with_label(buttons[i]);
        gtk_box_pack_start(GTK_BOX(actions), view->button, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(content), actions, FALSE, FALSE, 0);
        gboolean available = management_available(view->tool);
        const char *state = geteuid() == 0 ? "Run Welcome from your regular desktop login to use management checks." :
            available ? "Ready. No check has run." : "The optional tool is not installed or executable. This check is unavailable.";
        view->summary = paragraph(state);
        gtk_box_pack_start(GTK_BOX(content), view->summary, FALSE, FALSE, 0);
        gtk_widget_set_sensitive(view->button, available && geteuid() != 0);
        g_signal_connect(view->button, "clicked", G_CALLBACK(management_run), view);
        GtkWidget *expander = gtk_expander_new("View report");
        GtkWidget *raw_scroll = gtk_scrolled_window_new(NULL, NULL);
        gtk_widget_set_size_request(raw_scroll, -1, 160);
        view->raw = gtk_text_view_new();
        gtk_text_view_set_editable(GTK_TEXT_VIEW(view->raw), FALSE);
        gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view->raw), FALSE);
        gtk_text_view_set_monospace(GTK_TEXT_VIEW(view->raw), TRUE);
        gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view->raw), GTK_WRAP_WORD_CHAR);
        gtk_container_add(GTK_CONTAINER(raw_scroll), view->raw);
        gtk_container_add(GTK_CONTAINER(expander), raw_scroll);
        gtk_box_pack_start(GTK_BOX(content), expander, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(box), frame, FALSE, FALSE, 0);
    }
    return scroll;
}

static char *read_guide(guint index, GError **error)
{
    char *name = g_strconcat(guides[index], ".txt", NULL);
    char *path = g_build_filename(WELCOME_DOC_DIR, name, NULL);
    char *text = NULL;
    gsize size = 0;
    if (g_file_get_contents(path, &text, &size, error)) {
        if (size > 65536 || memchr(text, '\0', size) || !g_utf8_validate(text, (gssize)size, NULL)) {
            g_clear_pointer(&text, g_free);
            g_set_error_literal(error, G_FILE_ERROR, G_FILE_ERROR_INVAL, "Local guide is not valid UTF-8 text within 64 KiB.");
        }
    }
    g_free(name); g_free(path);
    return text;
}

static void refresh(GtkButton *button, gpointer data)
{
    (void)button;
    Welcome *welcome = data;
    WelcomeStatus status;
    welcome_status_read(&status, PACKAGE_DB);
    char *text = welcome_status_text(&status);
    gtk_label_set_text(GTK_LABEL(welcome->system_text), text);
    g_free(text); welcome_status_clear(&status);
}

static void launch(GtkButton *button, gpointer data)
{
    Welcome *welcome = data;
    const char *kind = g_object_get_data(G_OBJECT(button), "launch-kind");
    const char *program = g_str_equal(kind, "terminal") ? "/usr/bin/alacritty" : "/usr/bin/thunar";
    if (!g_file_test(program, G_FILE_TEST_IS_EXECUTABLE) && g_str_equal(kind, "files")) program = "/usr/bin/Thunar";
    const char *home = g_get_home_dir();
    GError *error = NULL;
    char *uri = NULL;
    gboolean ok = FALSE;
    if (g_file_test(program, G_FILE_TEST_IS_EXECUTABLE) && home && g_path_is_absolute(home)) {
        if (g_str_equal(kind, "files")) uri = g_filename_to_uri(home, NULL, &error);
        if (!error) {
            char *argv[] = { (char *)program, uri, NULL };
            /* Fixed executable, no command string, shell, elevation or PATH search.
             * Files receives only a locally generated file URI; Terminal no command. */
            ok = g_spawn_async(home, argv, NULL,
                G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL, NULL, &error);
        }
    }
    if (!ok) {
        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(welcome->window), GTK_DIALOG_DESTROY_WITH_PARENT,
            GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "%s", g_str_equal(kind, "terminal") ? "Could not open Terminal" : "Could not open Files");
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(dialog), "%s",
            error ? error->message : "The application or your home directory is unavailable. Use your desktop's existing app launcher. Welcome does not install applications.");
        gtk_dialog_run(GTK_DIALOG(dialog)); gtk_widget_destroy(dialog);
    }
    g_clear_error(&error); g_free(uri);
}

static void show_guide(GtkButton *button, gpointer data)
{
    Welcome *welcome = data;
    guint index = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(button), "guide-index"));
    gtk_notebook_set_current_page(GTK_NOTEBOOK(welcome->notebook), (gint)index);
    gtk_stack_set_visible_child_name(GTK_STACK(welcome->stack), "guides");
}

static GtkWidget *action_button(Welcome *welcome, const char *title, const char *kind, gboolean available)
{
    GtkWidget *button = gtk_button_new_with_mnemonic(title);
    gtk_widget_set_size_request(button, -1, 44);
    gtk_widget_set_sensitive(button, available);
    if (!available) gtk_widget_set_tooltip_text(button, "Application not found. Use an installed app from your desktop launcher.");
    g_object_set_data(G_OBJECT(button), "launch-kind", (gpointer)kind);
    g_signal_connect(button, "clicked", G_CALLBACK(launch), welcome);
    return button;
}

static void activate(GtkApplication *application, gpointer unused)
{
    (void)unused;
    GtkWindow *existing = gtk_application_get_active_window(application);
    if (existing) { gtk_window_present(existing); return; }
    Welcome *welcome = g_new0(Welcome, 1);
    welcome->application = g_object_ref(application);
    welcome->refs = 1;
    welcome->window = gtk_application_window_new(application);
    g_object_set_data_full(G_OBJECT(welcome->window), "welcome-state", welcome, welcome_unref);
    g_signal_connect(welcome->window, "destroy", G_CALLBACK(welcome_close), welcome);
    gtk_window_set_title(GTK_WINDOW(welcome->window), "cachy-asahi Welcome");
    gtk_window_set_default_size(GTK_WINDOW(welcome->window), 720, 580);
    gtk_window_set_icon_name(GTK_WINDOW(welcome->window), "cachy-asahi-welcome");

    GtkWidget *header = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), "cachy-asahi Welcome");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(header), "Independent desktop companion");
    gtk_window_set_titlebar(GTK_WINDOW(welcome->window), header);
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(welcome->window), outer);
    welcome->stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(welcome->stack), GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    GtkWidget *switcher = gtk_stack_switcher_new();
    gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(switcher), GTK_STACK(welcome->stack));
    gtk_widget_set_halign(switcher, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(switcher, 12);
    gtk_box_pack_start(GTK_BOX(outer), switcher, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(outer), welcome->stack, TRUE, TRUE, 0);

    GtkWidget *home_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(home_scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    GtkWidget *home = column(); gtk_container_add(GTK_CONTAINER(home_scroll), home);
    gtk_stack_add_titled(GTK_STACK(welcome->stack), home_scroll, "home", "Welcome");
    GtkWidget *title = paragraph("Make yourself at home.");
    PangoAttrList *style = pango_attr_list_new();
    pango_attr_list_insert(style, pango_attr_scale_new(1.7));
    pango_attr_list_insert(style, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
    gtk_label_set_attributes(GTK_LABEL(title), style); pango_attr_list_unref(style);
    gtk_box_pack_start(GTK_BOX(home), title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(home), paragraph("Open your tools, find local guidance, and see what is installed. Your existing desktop settings remain yours."), FALSE, FALSE, 0);

    gboolean terminal = g_file_test("/usr/bin/alacritty", G_FILE_TEST_IS_EXECUTABLE);
    gboolean files = g_file_test("/usr/bin/thunar", G_FILE_TEST_IS_EXECUTABLE) || g_file_test("/usr/bin/Thunar", G_FILE_TEST_IS_EXECUTABLE);
    GtkWidget *actions = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_pack_start(GTK_BOX(actions), action_button(welcome, "Open _Terminal", "terminal", terminal), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(actions), action_button(welcome, "Open _Files", "files", files), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(home), actions, FALSE, FALSE, 0);
    if (!terminal || !files)
        gtk_box_pack_start(GTK_BOX(home), paragraph("An unavailable app has a disabled button. Use your desktop launcher for alternatives; Welcome never installs packages."), FALSE, FALSE, 0);
    for (guint i = 0; i < G_N_ELEMENTS(guides); i++) {
        GtkWidget *button = gtk_button_new_with_label(guide_titles[i]);
        gtk_widget_set_halign(button, GTK_ALIGN_FILL);
        g_object_set_data(G_OBJECT(button), "guide-index", GUINT_TO_POINTER(i));
        g_signal_connect(button, "clicked", G_CALLBACK(show_guide), welcome);
        gtk_box_pack_start(GTK_BOX(home), button, FALSE, FALSE, 0);
    }
    gtk_box_pack_end(GTK_BOX(home), paragraph("Independent cachy-asahi project · " WELCOME_VERSION "\nLocal help; hardware compatibility is not assessed by Welcome."), FALSE, FALSE, 0);

    GtkWidget *system = column();
    GtkWidget *system_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(system_scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    welcome->system_text = paragraph("");
    gtk_label_set_selectable(GTK_LABEL(welcome->system_text), TRUE);
    gtk_container_add(GTK_CONTAINER(system_scroll), welcome->system_text);
    gtk_box_pack_start(GTK_BOX(system), system_scroll, TRUE, TRUE, 0);
    GtkWidget *reload = gtk_button_new_with_mnemonic("_Refresh system status");
    g_signal_connect(reload, "clicked", G_CALLBACK(refresh), welcome);
    gtk_box_pack_start(GTK_BOX(system), reload, FALSE, FALSE, 0);
    gtk_stack_add_titled(GTK_STACK(welcome->stack), system, "system", "System");
    refresh(NULL, welcome);

    gtk_stack_add_titled(GTK_STACK(welcome->stack), management_page(welcome), "management", "Management");

    welcome->notebook = gtk_notebook_new();
    gtk_container_set_border_width(GTK_CONTAINER(welcome->notebook), 18);
    for (guint i = 0; i < G_N_ELEMENTS(guides); i++) {
        GError *error = NULL;
        char *text = read_guide(i, &error);
        if (!text) text = g_strdup("Local guide unavailable. Reinstall this package through your established package workflow, or consult the documentation for your existing Asahi base. Welcome will not change the system.");
        GtkWidget *view = gtk_text_view_new();
        gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
        gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
        gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 18);
        gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 18);
        gtk_text_view_set_top_margin(GTK_TEXT_VIEW(view), 18);
        gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(view), 18);
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)), text, -1);
        GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
        gtk_container_add(GTK_CONTAINER(scroll), view);
        gtk_notebook_append_page(GTK_NOTEBOOK(welcome->notebook), scroll, gtk_label_new(guide_titles[i]));
        g_free(text); g_clear_error(&error);
    }
    gtk_stack_add_titled(GTK_STACK(welcome->stack), welcome->notebook, "guides", "Guides");
    gtk_widget_show_all(welcome->window);
}

int main(int argc, char **argv)
{
    gboolean status = FALSE, json = FALSE, version = FALSE;
    char *guide = NULL;
    GOptionEntry entries[] = {
        { "status", 0, 0, G_OPTION_ARG_NONE, &status, "Show read-only system and project package status", NULL },
        { "json", 0, 0, G_OPTION_ARG_NONE, &json, "Use JSON with --status", NULL },
        { "guide", 0, 0, G_OPTION_ARG_STRING, &guide, "Print an installed local guide", "first-run|updates|recovery" },
        { "version", 0, 0, G_OPTION_ARG_NONE, &version, "Show Welcome version", NULL },
        { NULL, 0, 0, 0, NULL, NULL, NULL }
    };
    GOptionContext *options = g_option_context_new("— local help and desktop tools");
    g_option_context_add_main_entries(options, entries, NULL);
    GError *error = NULL;
    gboolean parsed = g_option_context_parse(options, &argc, &argv, &error);
    g_option_context_free(options);
    if (!parsed || argc != 1 || (json && !status) || (guide && status) || (version && (status || guide || json))) {
        g_printerr("%s\nUse --help for supported options.\n", error ? error->message : "Choose one operation; --json requires --status.");
        g_clear_error(&error); g_free(guide); return 2;
    }
    if (version) { g_print("cachy-asahi Welcome %s\n", WELCOME_VERSION); return 0; }
    if (status) {
        WelcomeStatus current; welcome_status_read(&current, PACKAGE_DB);
        char *text = json ? welcome_status_json(&current) : welcome_status_text(&current);
        g_print("%s", text); g_free(text); welcome_status_clear(&current); return 0;
    }
    if (guide) {
        guint index;
        for (index = 0; index < G_N_ELEMENTS(guides) && !g_str_equal(guide, guides[index]); index++) {}
        g_free(guide);
        if (index == G_N_ELEMENTS(guides)) { g_printerr("Unknown guide. Choose first-run, updates, or recovery.\n"); return 2; }
        char *text = read_guide(index, &error);
        if (!text) { g_printerr("Guide unavailable: %s\n", error->message); g_clear_error(&error); return 1; }
        g_print("%s", text); g_free(text); return 0;
    }
    if (!gtk_init_check(NULL, NULL)) {
        g_printerr("No graphical display is available. Use cachy-asahi-welcome --status or --guide first-run.\n");
        return 1;
    }
    g_set_application_name("cachy-asahi Welcome");
    GtkApplication *application = gtk_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(application, "activate", G_CALLBACK(activate), NULL);
    int result = g_application_run(G_APPLICATION(application), argc, argv);
    g_object_unref(application);
    return result;
}
