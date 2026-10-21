/* SPDX-License-Identifier: MIT */
#include "status.h"
#include <glib/gstdio.h>
#include <string.h>

static char *fixture(void)
{
    GError *error = NULL;
    char *path = g_dir_make_tmp("cachy-asahi-welcome-XXXXXX", &error);
    g_assert_no_error(error); g_assert_nonnull(path);
    return path;
}

static void record(const char *root, const char *entry, const char *text)
{
    char *dir = g_build_filename(root, entry, NULL);
    g_assert_cmpint(g_mkdir_with_parents(dir, 0700), ==, 0);
    char *path = g_build_filename(dir, "desc", NULL);
    g_assert_true(g_file_set_contents(path, text, -1, NULL));
    g_free(path); g_free(dir);
}

static void remove_fixture(char *root)
{
    GDir *dir = g_dir_open(root, 0, NULL);
    const char *name;
    while ((name = g_dir_read_name(dir))) {
        char *entry = g_build_filename(root, name, NULL);
        char *desc = g_build_filename(entry, "desc", NULL);
        g_assert_cmpint(g_remove(desc), ==, 0); g_assert_cmpint(g_rmdir(entry), ==, 0);
        g_free(desc); g_free(entry);
    }
    g_dir_close(dir); g_assert_cmpint(g_rmdir(root), ==, 0); g_free(root);
}

static void installed(void)
{
    char *root = fixture();
    record(root, "cachy-asahi-setup-0.1.0-4", "%NAME%\ncachy-asahi-setup\n\n%VERSION%\n0.1.0-4\n");
    WelcomeStatus status; welcome_status_read(&status, root);
    g_assert_true(status.database_available);
    g_assert_cmpint(status.packages[1].state, ==, PACKAGE_INSTALLED);
    g_assert_cmpstr(status.packages[1].version, ==, "0.1.0-4");
    g_assert_cmpint(status.packages[0].state, ==, PACKAGE_NOT_FOUND);
    g_assert_nonnull(status.architecture); g_assert_cmpint(status.page_size, >, 0);
    welcome_status_clear(&status); remove_fixture(root);
}

static void unavailable(void)
{
    char *root = fixture(); char *missing = g_build_filename(root, "missing", NULL);
    WelcomeStatus status; welcome_status_read(&status, missing);
    g_assert_false(status.database_available);
    for (guint i = 0; i < WELCOME_PACKAGE_COUNT; i++) {
        g_assert_cmpint(status.packages[i].state, ==, PACKAGE_UNKNOWN);
        g_assert_null(status.packages[i].version);
    }
    welcome_status_clear(&status); g_free(missing); remove_fixture(root);
}

static void duplicate(void)
{
    char *root = fixture();
    record(root, "cachy-asahi-setup-1-1", "%NAME%\ncachy-asahi-setup\n%VERSION%\n1-1\n");
    record(root, "cachy-asahi-setup-2-1", "%NAME%\ncachy-asahi-setup\n%VERSION%\n2-1\n");
    WelcomeStatus status; welcome_status_read(&status, root);
    g_assert_cmpint(status.packages[1].state, ==, PACKAGE_UNKNOWN); g_assert_null(status.packages[1].version);
    welcome_status_clear(&status); remove_fixture(root);
}

static void lookalike(void)
{
    char *root = fixture();
    record(root, "cachy-asahi-setup-other-1", "%NAME%\ncachy-asahi-setup-other\n%VERSION%\n1-1\n");
    WelcomeStatus status; welcome_status_read(&status, root);
    g_assert_cmpint(status.packages[1].state, !=, PACKAGE_INSTALLED);
    welcome_status_clear(&status); remove_fixture(root);
}

static void malformed(void)
{
    const char *values[] = { "%NAME%\ncachy-asahi-setup\n", "%NAME%\ncachy-asahi-setup\n%VERSION%\n1\n%VERSION%\n2\n",
                            "%NAME%\ncachy-asahi-setup\n%VERSION%\nbad version\n", "invalid\xff\n" };
    for (guint i = 0; i < G_N_ELEMENTS(values); i++) {
        char *root = fixture(); record(root, "cachy-asahi-setup-1", values[i]);
        WelcomeStatus status; welcome_status_read(&status, root);
        g_assert_cmpint(status.packages[1].state, ==, PACKAGE_UNKNOWN); g_assert_null(status.packages[1].version);
        welcome_status_clear(&status); remove_fixture(root);
    }
}

static void oversized(void)
{
    char *root = fixture(); char *large = g_strnfill(70000, 'x');
    record(root, "cachy-asahi-setup-1", large); g_free(large);
    WelcomeStatus status; welcome_status_read(&status, root);
    g_assert_cmpint(status.packages[1].state, ==, PACKAGE_UNKNOWN);
    welcome_status_clear(&status); remove_fixture(root);
}

static void json_controls(void)
{
    char *root = fixture(); WelcomeStatus status; welcome_status_read(&status, root);
    g_free(status.kernel); status.kernel = g_strdup("quote\" slash\\ newline\ncontrol\001");
    char *json = welcome_status_json(&status);
    g_assert_nonnull(strstr(json, "quote\\\" slash\\\\ newline\\u000acontrol\\u0001"));
    g_assert_nonnull(strstr(json, "\"hardware_compatibility\":\"not-assessed\""));
    status.page_size = -1;
    g_free(json); json = welcome_status_json(&status); g_assert_nonnull(strstr(json, "\"page_size\":null"));
    g_free(json); welcome_status_clear(&status); remove_fixture(root);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/status/installed", installed);
    g_test_add_func("/status/unavailable", unavailable);
    g_test_add_func("/status/duplicate", duplicate);
    g_test_add_func("/status/lookalike", lookalike);
    g_test_add_func("/status/malformed", malformed);
    g_test_add_func("/status/oversized", oversized);
    g_test_add_func("/status/json-controls", json_controls);
    return g_test_run();
}
