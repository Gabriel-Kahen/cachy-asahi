/* SPDX-License-Identifier: MIT
 * Finite protocol test: the tray is installed product code; only its watcher
 * and transaction-free Check action endpoint are test fixtures.
 */
#include <gio/gio.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static GDBusConnection *bus;
static gchar *item;
static GPid tray;
static const char *watcher = "org.kde.StatusNotifierWatcher";
static const char *sni = "org.kde.StatusNotifierItem";
static const char *menu = "com.canonical.dbusmenu";
static void cleanup(void) {
    if (tray) { kill(tray, SIGKILL); waitpid(tray, NULL, 0); }
}
static void require(gboolean ok, const char *what) {
    if (!ok) { fprintf(stderr, "FAIL: %s\n", what); exit(1); }
}
static GVariant *call(const char *dest, const char *path, const char *iface,
                      const char *method, GVariant *args) {
    GError *error = NULL;
    GVariant *r = g_dbus_connection_call_sync(bus, dest, path, iface, method,
        args, NULL, G_DBUS_CALL_FLAGS_NO_AUTO_START, 2000, NULL, &error);
    if (!r) { fprintf(stderr, "FAIL: %s: %s\n", method, error->message); exit(1); }
    return r;
}
static void method(GDBusConnection *c, const gchar *sender, const gchar *path,
                   const gchar *iface, const gchar *name, GVariant *args,
                   GDBusMethodInvocation *inv, gpointer data) {
    (void)c; (void)path; (void)iface; (void)data;
    if (!strcmp(name, "RegisterStatusNotifierItem")) {
        const gchar *service;
        g_variant_get(args, "(&s)", &service);
        if (g_atomic_pointer_get(&item) || !g_str_has_prefix(service, "org.kde.StatusNotifierItem-")) {
            g_dbus_method_invocation_return_dbus_error(inv,
                "org.test.InvalidRegistration", "unexpected tray registration");
            return;
        }
        g_atomic_pointer_set(&item, g_strdup(sender));
    }
    g_dbus_method_invocation_return_value(inv, NULL);
}
static GVariant *property(GDBusConnection *c, const gchar *sender,
    const gchar *path, const gchar *iface, const gchar *name,
    GError **error, gpointer data) {
    (void)c; (void)sender; (void)path; (void)iface; (void)error; (void)data;
    if (!strcmp(name, "IsStatusNotifierHostRegistered")) return g_variant_new_boolean(TRUE);
    if (!strcmp(name, "ProtocolVersion")) return g_variant_new_int32(0);
    return g_variant_new_strv(NULL, 0);
}
static const GDBusInterfaceVTable vtable = {
    .method_call = method, .get_property = property
};
static const char xml[] =
 "<node><interface name='org.kde.StatusNotifierWatcher'>"
 "<method name='RegisterStatusNotifierItem'><arg type='s' direction='in'/></method>"
 "<method name='RegisterStatusNotifierHost'><arg type='s' direction='in'/></method>"
 "<property name='RegisteredStatusNotifierItems' type='as' access='read'/>"
 "<property name='IsStatusNotifierHostRegistered' type='b' access='read'/>"
 "<property name='ProtocolVersion' type='i' access='read'/>"
 "<signal name='StatusNotifierHostRegistered'/>"
 "<signal name='StatusNotifierItemRegistered'><arg type='s'/></signal>"
 "</interface></node>";

static void string_property(const char *name, const char *expected) {
    GVariant *r = call(item, "/StatusNotifierItem", "org.freedesktop.DBus.Properties",
        "Get", g_variant_new("(ss)", sni, name));
    GVariant *v; g_variant_get(r, "(v)", &v);
    require(g_variant_is_of_type(v, G_VARIANT_TYPE_STRING), name);
    require(!strcmp(g_variant_get_string(v, NULL), expected), name);
    g_variant_unref(v); g_variant_unref(r);
}
static gpointer serve(gpointer data) {
    g_main_loop_run(data);
    return NULL;
}
static int check_id = -1, exit_id = -1;
static gboolean has_run, has_packages, has_count;
static void visit(GVariant *node) {
    gint32 id;
    GVariant *props, *children;
    g_variant_get(node, "(i@a{sv}@av)", &id, &props, &children);
    const char *label = NULL;
    if (g_variant_lookup(props, "label", "&s", &label)) {
        if (!strcmp(label, "Check for updates")) check_id = id;
        if (!strcmp(label, "Exit")) exit_id = id;
        if (!strcmp(label, "Run Cachy-Update")) has_run = TRUE;
        if (!strcmp(label, "Packages (1)")) has_packages = TRUE;
        if (!strcmp(label, "1 update available")) has_count = TRUE;
        if (!strcmp(label, "Check for updates") || !strcmp(label, "Exit")) {
            gboolean enabled = TRUE;
            g_variant_lookup(props, "enabled", "b", &enabled);
            require(enabled, "menu action enabled");
        }
    }
    for (gsize i = 0; i < g_variant_n_children(children); ++i) {
        GVariant *boxed = g_variant_get_child_value(children, i);
        GVariant *child = g_variant_get_variant(boxed);
        visit(child); g_variant_unref(child); g_variant_unref(boxed);
    }
    g_variant_unref(props); g_variant_unref(children);
}
static int self_test(const char *mode) {
    GVariantBuilder children;
    g_variant_builder_init(&children, G_VARIANT_TYPE("av"));
    const char *labels[] = {"Check for updates", "Exit", "Run Cachy-Update",
        "Packages (1)", "1 update available"};
    for (int i = 0; i < 5; i++) {
        if (!strcmp(mode, "missing") && i == 1) continue;
        GVariantBuilder props;
        g_variant_builder_init(&props, G_VARIANT_TYPE("a{sv}"));
        g_variant_builder_add(&props, "{sv}", "label", g_variant_new_string(labels[i]));
        g_variant_builder_add(&props, "{sv}", "enabled",
            g_variant_new_boolean(strcmp(mode, "disabled") != 0));
        g_variant_builder_add(&children, "v", g_variant_new("(i@a{sv}@av)",
            i+1, g_variant_builder_end(&props), g_variant_new_array(G_VARIANT_TYPE_VARIANT, NULL, 0)));
    }
    GVariant *root = g_variant_new("(i@a{sv}@av)", 0,
        g_variant_new_array(G_VARIANT_TYPE("{sv}"), NULL, 0), g_variant_builder_end(&children));
    visit(root);
    require(check_id > 0 && exit_id > 0 && has_run && has_packages && has_count,
        "menu decoder completeness");
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--self-test")) return self_test(argv[2]);
    require(argc == 1, "no runtime arguments");
    require(getuid() != 0, "non-root session required");
    require(getenv("DBUS_SESSION_BUS_ADDRESS") && getenv("HOME"), "private session env");
    atexit(cleanup);
    GError *error = NULL;
    bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    require(bus != NULL, "private session bus");
    GDBusNodeInfo *info = g_dbus_node_info_new_for_xml(xml, &error);
    require(info != NULL, "watcher introspection");
    require(g_dbus_connection_register_object(bus, "/StatusNotifierWatcher",
        info->interfaces[0], &vtable, NULL, NULL, &error), "watcher registration");
    GVariant *r = call("org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "RequestName", g_variant_new("(su)", watcher, 4u));
    guint32 owned; g_variant_get(r, "(u)", &owned); g_variant_unref(r);
    require(owned == 1, "private watcher ownership");
    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    g_thread_new("watcher", serve, loop);
    char *tray_argv[] = {"/usr/lib/arch-update/arch-update-tray", NULL};
    require(g_spawn_async(NULL, tray_argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
        NULL, NULL, &tray, &error), "installed tray launch");
    gint64 deadline = g_get_monotonic_time() + 8 * G_TIME_SPAN_SECOND;
    while (!g_atomic_pointer_get(&item) && g_get_monotonic_time() < deadline) {
        int status;
        int reaped = waitpid(tray, &status, WNOHANG);
        if (reaped == tray) tray = 0;
        require(reaped == 0, "tray alive before registration");
        g_usleep(10000);
    }
    require(item != NULL, "tray registers with watcher");
    string_property("Id", "Cachy-Update");
    string_property("Title", "Cachy-Update");
    string_property("Category", "SystemServices");
    string_property("Status", "Active");
    string_property("IconName", "arch-update");
    r = call(item, "/StatusNotifierItem", "org.freedesktop.DBus.Properties",
        "Get", g_variant_new("(ss)", sni, "ToolTip"));
    GVariant *v; g_variant_get(r, "(v)", &v);
    GVariant *title = g_variant_get_child_value(v, 2);
    GVariant *description = g_variant_get_child_value(v, 3);
    require(!strcmp(g_variant_get_string(title, NULL), "Cachy-Update") &&
        !strcmp(g_variant_get_string(description, NULL), "1 update available"), "tooltip");
    g_variant_unref(title); g_variant_unref(description);
    g_variant_unref(v); g_variant_unref(r);
    r = call(item, "/StatusNotifierItem", "org.freedesktop.DBus.Properties",
        "Get", g_variant_new("(ss)", sni, "Menu"));
    g_variant_get(r, "(v)", &v);
    require(g_variant_is_of_type(v, G_VARIANT_TYPE_OBJECT_PATH) &&
        !strcmp(g_variant_get_string(v, NULL), "/MenuBar"), "menu object path");
    g_variant_unref(v); g_variant_unref(r);
    r = call(item, "/MenuBar", menu, "AboutToShow", g_variant_new("(i)", 0));
    g_variant_unref(r);
    r = call(item, "/MenuBar", menu, "GetLayout", g_variant_new("(ii@as)",
        0, -1, g_variant_new_strv(NULL, 0)));
    GVariant *layout = g_variant_get_child_value(r, 1);
    visit(layout); g_variant_unref(layout); g_variant_unref(r);
    require(check_id > 0 && exit_id > 0 && has_run && has_packages && has_count,
        "installed tray menu content");
    r = call(item, "/MenuBar", menu, "Event", g_variant_new("(isvu)",
        check_id, "clicked", g_variant_new_int32(0), 0u));
    g_variant_unref(r);
    gchar *marker = g_build_filename(getenv("HOME"), "check-action", NULL);
    deadline = g_get_monotonic_time() + 3 * G_TIME_SPAN_SECOND;
    while (!g_file_test(marker, G_FILE_TEST_EXISTS) && g_get_monotonic_time() < deadline)
        g_usleep(10000);
    gchar *text = NULL;
    require(g_file_get_contents(marker, &text, NULL, NULL) &&
        !strcmp(text, "--check\n"), "safe Check action dispatch");
    g_free(text); g_free(marker);
    /* Exit intentionally terminates the service before a reply may be sent. */
    r = g_dbus_connection_call_sync(bus, item, "/MenuBar", menu, "Event",
        g_variant_new("(isvu)", exit_id, "clicked", g_variant_new_int32(0), 0u),
        NULL, G_DBUS_CALL_FLAGS_NO_AUTO_START, 2000, NULL, NULL);
    if (r) g_variant_unref(r);
    int status = 0, waited = 0;
    deadline = g_get_monotonic_time() + 3 * G_TIME_SPAN_SECOND;
    do {
        waited = waitpid(tray, &status, WNOHANG);
        if (!waited) g_usleep(10000);
    } while (!waited && g_get_monotonic_time() < deadline);
    gboolean exited = waited == tray && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (waited == tray) tray = 0;
    require(exited,
        "tray Exit menu terminates successfully");
    tray = 0;
    puts("{\"tray_registration\":\"PASS\",\"tray_properties\":\"PASS\",\"tray_menu\":\"PASS\",\"check_dispatch_recorder\":\"PASS\",\"tray_exit\":\"PASS\",\"real_update_check\":\"NOT RUN\",\"rendering\":\"NOT RUN\"}");
    return 0;
}
