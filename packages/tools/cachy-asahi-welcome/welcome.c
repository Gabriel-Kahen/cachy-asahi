/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 cachy-asahi contributors */
#include <gtk/gtk.h>
#include <string.h>
#include "status.h"

#ifndef WELCOME_DOC_DIR
#define WELCOME_DOC_DIR "/usr/share/doc/cachy-asahi-welcome"
#endif
#define APP_ID "io.github.GabrielKahen.CachyAsahiWelcome"
#define PACKAGE_DB "/var/lib/pacman/local"

static const char *const guides[] = { "first-run", "updates", "recovery" };
static const char *const guide_titles[] = { "First steps", "Updates", "Recovery" };

typedef struct {
    GtkWidget *window, *stack, *notebook, *system_text;
} Welcome;

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
    welcome->window = gtk_application_window_new(application);
    g_object_set_data_full(G_OBJECT(welcome->window), "welcome-state", welcome, g_free);
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
