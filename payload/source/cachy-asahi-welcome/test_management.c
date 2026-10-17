/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "management.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static char *self;
typedef struct {
    GMainLoop *loop;
    ManagementJob *job;
    guint calls;
    ManagementResult result;
    char *output, *diagnostic;
} Case;

static void completed(ManagementJob *job, const ManagementResult *result, gpointer data)
{
    Case *test = data;
    g_assert_true(job == test->job);
    g_assert_cmpuint(++test->calls, ==, 1);
    test->result = *result;
    test->output = g_strdup(result->output);
    test->diagnostic = g_strdup(result->diagnostic);
    test->job = NULL;
    g_main_loop_quit(test->loop);
}

static gboolean cancel_job(gpointer data)
{
    Case *test = data;
    management_cancel(test->job);
    return G_SOURCE_REMOVE;
}

static gboolean deadline(gpointer data)
{
    (void)data;
    g_error("Management callback did not arrive within the test deadline");
    return G_SOURCE_REMOVE;
}

static Case run(const char *argument, guint ms, gsize limit, gboolean cancel)
{
    Case test = { .loop = g_main_loop_new(NULL, FALSE) };
    management_test_configure(self, argument, ms, limit, TRUE);
    GError *error = NULL;
    test.job = management_start(MANAGEMENT_DOCTOR, completed, &test, &error);
    g_assert_no_error(error);
    g_assert_nonnull(test.job);
    g_assert_cmpuint(test.calls, ==, 0);
    guint watchdog = g_timeout_add(8000, deadline, NULL);
    if (cancel) g_timeout_add(40, cancel_job, &test);
    g_main_loop_run(test.loop);
    g_source_remove(watchdog);
    g_assert_cmpuint(test.calls, ==, 1);
    g_assert_null(test.job);
    g_assert_true(test.result.retired);
    g_assert_cmpint(test.result.elapsed_ms, >=, 0);
    g_assert_cmpint(test.result.elapsed_ms, <, 7000);
    /* All readiness sources must have been removed with the job. */
    while (g_main_context_iteration(NULL, FALSE)) {}
    g_assert_cmpuint(test.calls, ==, 1);
    g_main_loop_unref(test.loop);
    test.loop = NULL;
    return test;
}

static void clear(Case *test)
{
    g_free(test->output); g_free(test->diagnostic);
}

static void no_children(void)
{
    int status;
    errno = 0;
    g_assert_cmpint(waitpid(-1, &status, WNOHANG), ==, -1);
    g_assert_cmpint(errno, ==, ECHILD);
}

static pid_t output_pid(const char *output, const char *name)
{
    const char *field = strstr(output, name);
    g_assert_nonnull(field);
    char *end;
    long pid = strtol(field + strlen(name), &end, 10);
    g_assert_true(end > field + strlen(name));
    g_assert_cmpint(pid, >, 1);
    return (pid_t)pid;
}

static void absent(pid_t pid)
{
    errno = 0;
    g_assert_cmpint(kill(pid, 0), ==, -1);
    g_assert_cmpint(errno, ==, ESRCH);
}

static void success(void)
{
    Case test = run("success", 1000, 4096, FALSE);
    g_assert_cmpint(test.result.state, ==, MANAGEMENT_COMPLETE);
    g_assert_cmpint(test.result.exit_code, ==, 0);
    g_assert_cmpstr(test.output, ==, "{\"status\":\"PASS\"}\nstandard error\n");
    clear(&test); no_children();
}

static void nonzero(void)
{
    Case test = run("fail", 1000, 4096, FALSE);
    g_assert_cmpint(test.result.state, ==, MANAGEMENT_FAILED);
    g_assert_cmpint(test.result.exit_code, ==, 7);
    g_assert_cmpstr(test.output, ==, "unsupported fixture\n");
    clear(&test); no_children();
}

static void missing(void)
{
    Case test = { .loop = g_main_loop_new(NULL, FALSE) };
    management_test_configure("/nonexistent/cachy-asahi-welcome-test", "success", 1000, 4096, TRUE);
    g_assert_false(management_available(MANAGEMENT_DOCTOR));
    GError *error = NULL;
    test.job = management_start(MANAGEMENT_DOCTOR, completed, &test, &error);
    g_assert_no_error(error); g_assert_nonnull(test.job);
    g_assert_cmpuint(test.calls, ==, 0);
    g_main_loop_run(test.loop);
    g_assert_cmpint(test.result.state, ==, MANAGEMENT_UNAVAILABLE);
    g_assert_true(test.result.retired);
    clear(&test); g_main_loop_unref(test.loop); no_children();
}

static void output_limit(void)
{
    Case test = run("flood", 1000, 128, FALSE);
    g_assert_cmpint(test.result.state, ==, MANAGEMENT_OUTPUT_LIMIT);
    g_assert_cmpuint(strlen(test.output), ==, 128);
    clear(&test); no_children();
}

static void timeout(void)
{
    Case test = run("sleep", 80, 4096, FALSE);
    g_assert_cmpint(test.result.state, ==, MANAGEMENT_TIMEOUT);
    absent(output_pid(test.output, "root="));
    clear(&test); no_children();
}

static void cancellation(void)
{
    Case test = run("detached-wait", 1000, 4096, TRUE);
    g_assert_cmpint(test.result.state, ==, MANAGEMENT_CANCELLED);
    absent(output_pid(test.output, "root="));
    absent(output_pid(test.output, "descendant="));
    clear(&test); no_children();
}

static void detached(void)
{
    Case test = run("detached-exit", 1000, 4096, FALSE);
    g_assert_cmpint(test.result.state, ==, MANAGEMENT_COMPLETE);
    absent(output_pid(test.output, "descendant="));
    clear(&test); no_children();
}

static void isolation(void)
{
    pid_t unrelated = fork();
    g_assert_cmpint(unrelated, >=, 0);
    if (unrelated == 0) { usleep(10000); _exit(23); }
    Case test = run("detached-exit", 1000, 4096, FALSE);
    g_assert_cmpint(test.result.state, ==, MANAGEMENT_COMPLETE);
    int status;
    g_assert_cmpint(waitpid(unrelated, &status, 0), ==, unrelated);
    g_assert_true(WIFEXITED(status));
    g_assert_cmpint(WEXITSTATUS(status), ==, 23);
    clear(&test); no_children();
}

static void clean_environment(void)
{
    g_setenv("LD_PRELOAD", "/not/an/installed-library.so", TRUE);
    g_setenv("PYTHONPATH", "/untrusted/test", TRUE);
    g_setenv("GCONV_PATH", "/untrusted/test", TRUE);
    g_setenv("HYPRLAND_INSTANCE_SIGNATURE", "fixture-session", TRUE);
    Case test = run("environment", 1000, 4096, FALSE);
    g_unsetenv("LD_PRELOAD"); g_unsetenv("PYTHONPATH"); g_unsetenv("GCONV_PATH");
    g_unsetenv("HYPRLAND_INSTANCE_SIGNATURE");
    g_assert_cmpint(test.result.state, ==, MANAGEMENT_COMPLETE);
    g_assert_cmpstr(test.output, ==, "environment clean\n");
    clear(&test); no_children();
}

static void binary(void)
{
    Case test = run("binary", 1000, 4096, FALSE);
    g_assert_cmpint(test.result.state, ==, MANAGEMENT_FAILED);
    g_assert_cmpstr(test.output, ==, "");
    g_assert_nonnull(strstr(test.diagnostic, "invalid text"));
    clear(&test); no_children();
}

static void invalid_utf8(void)
{
    Case test = run("utf8", 1000, 4096, FALSE);
    g_assert_cmpint(test.result.state, ==, MANAGEMENT_FAILED);
    g_assert_cmpstr(test.output, ==, "");
    g_assert_nonnull(strstr(test.diagnostic, "invalid text"));
    clear(&test); no_children();
}

static void api(void)
{
    g_assert_cmpstr(management_program(MANAGEMENT_DOCTOR), ==, "/usr/bin/cachy-asahi-doctor");
    g_assert_cmpstr(management_program(MANAGEMENT_ORPHANS), ==, "/usr/bin/cachy-asahi-orphans");
    g_assert_null(management_program(MANAGEMENT_TOOL_COUNT));
    g_assert_false(management_available(MANAGEMENT_TOOL_COUNT));
    GError *error = NULL;
    g_assert_null(management_start(MANAGEMENT_TOOL_COUNT, completed, NULL, &error));
    g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_INVAL); g_clear_error(&error);
    g_assert_null(management_start(MANAGEMENT_DOCTOR, NULL, NULL, &error));
    g_assert_error(error, G_FILE_ERROR, G_FILE_ERROR_INVAL); g_clear_error(&error);
    management_cancel(NULL);
    no_children();
}

static void root_guard(void)
{
    if (getuid() != 0 && geteuid() != 0) { g_test_skip("Root guard requires an actual root test process"); return; }
    Case test = { .loop = g_main_loop_new(NULL, FALSE) };
    management_test_configure(self, "success", 1000, 4096, FALSE);
    GError *error = NULL;
    test.job = management_start(MANAGEMENT_DOCTOR, completed, &test, &error);
    g_assert_no_error(error); g_assert_nonnull(test.job);
    g_assert_cmpuint(test.calls, ==, 0);
    g_main_loop_run(test.loop);
    g_assert_cmpint(test.result.state, ==, MANAGEMENT_UNSUPPORTED);
    g_assert_true(test.result.retired);
    clear(&test); g_main_loop_unref(test.loop); no_children();
}

static int stub(const char *mode)
{
    if (strcmp(mode, "success") == 0) {
        const char report[] = "{\"status\":\"PASS\"}\n";
        if (write(1, report, sizeof report - 1) < 0 || write(2, "standard error\n", 15) < 0) return 50;
    } else if (strcmp(mode, "fail") == 0) { puts("unsupported fixture"); return 7; }
    else if (strcmp(mode, "binary") == 0) { const char b[] = { '{', 0, '}' }; if (write(1, b, sizeof b) < 0) return 50; }
    else if (strcmp(mode, "utf8") == 0) { const char b[] = { '{', (char)0xff, '}' }; if (write(1, b, sizeof b) < 0) return 50; }
    else if (strcmp(mode, "environment") == 0) {
        if (getenv("LD_PRELOAD") || getenv("PYTHONPATH") || getenv("GCONV_PATH") ||
            !getenv("PATH") || strcmp(getenv("PATH"), "/usr/bin:/bin") ||
            !getenv("PYTHONNOUSERSITE") || strcmp(getenv("PYTHONNOUSERSITE"), "1") ||
            !getenv("HYPRLAND_INSTANCE_SIGNATURE") || strcmp(getenv("HYPRLAND_INSTANCE_SIGNATURE"), "fixture-session")) return 51;
        puts("environment clean");
    } else if (strcmp(mode, "flood") == 0) {
        char bytes[4096]; memset(bytes, 'x', sizeof bytes);
        for (;;) if (write(1, bytes, sizeof bytes) < 0) return 50;
    } else if (strcmp(mode, "sleep") == 0) {
        printf("root=%ld\n", (long)getpid()); fflush(stdout);
        for (;;) pause();
    } else if (g_str_has_prefix(mode, "detached-")) {
        int ready[2];
        if (pipe(ready) < 0) return 52;
        pid_t child = fork();
        if (child < 0) return 53;
        if (child == 0) {
            close(ready[0]);
            if (setsid() < 0) _exit(54);
            signal(SIGTERM, SIG_IGN);
            printf("descendant=%ld\n", (long)getpid()); fflush(stdout);
            if (write(ready[1], "x", 1) != 1) _exit(55);
            close(ready[1]);
            for (;;) pause();
        }
        close(ready[1]);
        char byte;
        if (read(ready[0], &byte, 1) != 1) return 56;
        close(ready[0]);
        printf("root=%ld\n", (long)getpid()); fflush(stdout);
        if (strcmp(mode, "detached-wait") == 0) for (;;) pause();
    } else return 57;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && argv[1][0] != '-') return stub(argv[1]);
    self = g_file_read_link("/proc/self/exe", NULL);
    g_assert_nonnull(self);
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/management/api", api);
    g_test_add_func("/management/success", success);
    g_test_add_func("/management/nonzero", nonzero);
    g_test_add_func("/management/missing", missing);
    g_test_add_func("/management/output-limit", output_limit);
    g_test_add_func("/management/timeout", timeout);
    g_test_add_func("/management/cancel-detached", cancellation);
    g_test_add_func("/management/complete-detached", detached);
    g_test_add_func("/management/unrelated-child-isolation", isolation);
    g_test_add_func("/management/environment", clean_environment);
    g_test_add_func("/management/binary-output", binary);
    g_test_add_func("/management/invalid-utf8", invalid_utf8);
    g_test_add_func("/management/root-guard", root_guard);
    int result = g_test_run();
    g_free(self);
    return result;
}
