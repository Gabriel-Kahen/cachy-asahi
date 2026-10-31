/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "management.h"
#include "management-report.h"
#include <errno.h>
#include <fcntl.h>
#include <glib-unix.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

#define OUTPUT_LIMIT (1024U * 1024U)
#define RUN_MS 30000U
#define CLEANUP_MS 3000U
#define SEND_MS 2000U
#define WIRE_MAGIC 0x574d4731U

typedef struct {
    uint32_t magic, state, length, retired;
    int32_t exit_code;
    int64_t elapsed_ms;
} Wire;

struct ManagementJob {
    ManagementDone done;
    gpointer data;
    GPid pid;
    int read_fd, cancel_fd, child_status;
    guint read_source, child_source, timer_source, idle_source;
    gboolean child_done, eof, cancelled, protocol_error, outer_timeout, finished;
    gsize limit;
    GByteArray *bytes;
    ManagementState immediate;
    gint64 started_us;
};

static const char *const programs[] = {
    "/usr/bin/cachy-asahi-doctor", "/usr/bin/cachy-asahi-orphans", "/usr/bin/cachy-asahi-dns", "/usr/bin/cachy-asahi-boot-report"
};
static const char *const arguments[] = { "--json", "assess", "--json", "list" };

#ifdef MANAGEMENT_TEST
static const char *test_program, *test_argument, *test_dns_metadata;
void management_test_dns_metadata(const char *path)
{
    g_assert(path == NULL || g_path_is_absolute(path));
    test_dns_metadata = path;
}
static guint test_ms = RUN_MS;
static gsize test_limit = OUTPUT_LIMIT;
static gboolean test_root;
void management_test_configure(const char *program, const char *argument,
                               guint ms, gsize limit, gboolean allow_root)
{
    g_assert(program == NULL || g_path_is_absolute(program));
    g_assert(ms > 0 && ms <= RUN_MS && limit > 0 && limit <= OUTPUT_LIMIT);
    test_program = program; test_argument = argument;
    test_ms = ms; test_limit = limit; test_root = allow_root;
}
#endif

const char *management_program(ManagementTool tool)
{
    return tool >= 0 && tool < MANAGEMENT_TOOL_COUNT ? programs[tool] : NULL;
}

static const char *selected_program(ManagementTool tool)
{
#ifdef MANAGEMENT_TEST
    if (test_program != NULL) return test_program;
#endif
    return management_program(tool);
}

static gboolean dns_metadata_available(void)
{
    char text[16385];
    const char *path = "/usr/share/doc/cachy-asahi-dns/source-provenance.json";
#ifdef MANAGEMENT_TEST
    if (test_dns_metadata != NULL) path = test_dns_metadata;
#endif
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat info;
    if (fd < 0) return FALSE;
    gboolean valid = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_size > 0 && info.st_size <= 16384;
    gsize length = 0;
    while (valid && length < sizeof(text) - 1) {
        ssize_t n = read(fd, text + length, sizeof(text) - 1 - length);
        if (n > 0) length += (gsize)n;
        else if (n == 0) break;
        else if (errno != EINTR) valid = FALSE;
    }
    close(fd);
    if (!valid || length != (gsize)info.st_size || memchr(text, 0, length)) return FALSE;
    text[length] = 0;
    return management_dns_version_supported(text);
}

gboolean management_available(ManagementTool tool)
{
    struct stat info;
    if (management_program(tool) == NULL) return FALSE;
    const char *path = selected_program(tool);
    if (!(stat(path, &info) == 0 && S_ISREG(info.st_mode) && access(path, X_OK) == 0)) return FALSE;
#ifdef MANAGEMENT_TEST
    if (test_program != NULL && (tool != MANAGEMENT_DNS || test_dns_metadata == NULL)) return TRUE;
#endif
    return tool != MANAGEMENT_DNS || dns_metadata_available();
}

static char **environment(void)
{
    static const char *const hints[] = {
        "HOME", "USER", "LOGNAME", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE",
        "XDG_CURRENT_DESKTOP", "WAYLAND_DISPLAY", "DISPLAY",
        "HYPRLAND_INSTANCE_SIGNATURE", "DBUS_SESSION_BUS_ADDRESS"
    };
    GPtrArray *env = g_ptr_array_new();
    g_ptr_array_add(env, g_strdup("PATH=/usr/bin:/bin"));
    g_ptr_array_add(env, g_strdup("LANG=C.UTF-8"));
    g_ptr_array_add(env, g_strdup("LC_ALL=C.UTF-8"));
    g_ptr_array_add(env, g_strdup("PYTHONNOUSERSITE=1"));
    g_ptr_array_add(env, g_strdup("PYTHONSAFEPATH=1"));
    g_ptr_array_add(env, g_strdup("PYTHONDONTWRITEBYTECODE=1"));
    for (gsize i = 0; i < G_N_ELEMENTS(hints); i++) {
        const char *value = g_getenv(hints[i]);
        if (value != NULL && strlen(value) <= 4096)
            g_ptr_array_add(env, g_strdup_printf("%s=%s", hints[i], value));
    }
    g_ptr_array_add(env, NULL);
    return (char **)g_ptr_array_free(env, FALSE);
}

/* All supervisor/tool code after fork uses stack storage, preallocated bytes,
 * and syscall-style interfaces only. It never calls GLib, malloc or GTK. */
static int64_t monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void close_from(unsigned first, unsigned maximum)
{
#if defined(__linux__) && defined(SYS_close_range)
    if (syscall(SYS_close_range, first, UINT_MAX, 0) == 0) return;
#endif
    for (unsigned fd = first; fd < maximum; fd++) close((int)fd);
}

static gboolean drain(int fd, unsigned char *buffer, gsize limit, gsize *length)
{
    while (*length <= limit) {
        ssize_t n = read(fd, buffer + *length, limit + 1 - *length);
        if (n > 0) { *length += (gsize)n; if (*length > limit) return FALSE; }
        else if (n == 0 || errno == EAGAIN || errno == EWOULDBLOCK) return TRUE;
        else if (errno != EINTR) return FALSE;
    }
    return FALSE;
}

static void kill_adopted(void)
{
    char children[65536];
    int fd = open("/proc/thread-self/children", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t length = read(fd, children, sizeof children);
    close(fd);
    if (length <= 0 || length >= (ssize_t)sizeof children) return;
    ssize_t i = 0;
    while (i < length) {
        unsigned long pid = 0;
        while (i < length && children[i] == ' ') i++;
        while (i < length && children[i] >= '0' && children[i] <= '9') {
            if (pid > (unsigned long)INT_MAX / 10) return;
            pid = pid * 10 + (unsigned)(children[i++] - '0');
        }
        if (pid > 1 && pid <= INT_MAX) kill((pid_t)pid, SIGKILL);
        else return;
        if (i < length && children[i] != ' ' && children[i] != '\n') return;
        while (i < length && (children[i] == ' ' || children[i] == '\n')) i++;
    }
}

static gboolean retire(pid_t child, gboolean reaped, int *status)
{
    if (!reaped) { kill(-child, SIGKILL); kill(child, SIGKILL); }
    int64_t until = monotonic_ms() + CLEANUP_MS;
    unsigned attempts = 0;
    do {
        kill_adopted();
        pid_t got;
        int observed;
        while ((got = waitpid(-1, &observed, WNOHANG)) > 0)
            if (got == child) *status = observed;
        if (got == -1 && errno == ECHILD) return TRUE;
        struct timespec delay = { .tv_nsec = 10000000 };
        nanosleep(&delay, NULL);
    } while (++attempts < CLEANUP_MS / 10 && monotonic_ms() < until);
    return FALSE;
}

static gboolean send_bytes(int fd, const void *buffer, gsize length, int64_t until)
{
    const unsigned char *bytes = buffer;
    while (length > 0 && monotonic_ms() < until) {
        ssize_t n = write(fd, bytes, length);
        if (n > 0) { bytes += n; length -= (gsize)n; }
        else if (n < 0 && errno != EAGAIN && errno != EINTR) return FALSE;
        else { struct pollfd p = { .fd = fd, .events = POLLOUT }; poll(&p, 1, 20); }
    }
    return length == 0;
}

static void supervise(int output, int cancel, int null_fd, unsigned maximum,
                      char *const argv[], char *const env[], unsigned char *buffer,
                      gsize limit, guint budget)
{
    Wire wire = { .magic = WIRE_MAGIC, .state = MANAGEMENT_FAILED,
                  .exit_code = -1, .retired = TRUE };
    int64_t started = monotonic_ms();
    /* Inputs were duplicated above fd 9 before fork, so these dup2s cannot
     * overwrite one another. The supervisor closes all inherited GUI fds. */
    if (dup2(output, 3) < 0 || dup2(cancel, 4) < 0 || dup2(null_fd, 5) < 0) _exit(125);
    close_from(6, maximum);
    close(0); close(1); close(2);
    struct sigaction ignored = { .sa_handler = SIG_IGN };
    sigemptyset(&ignored.sa_mask);
    struct sigaction normal = { .sa_handler = SIG_DFL };
    sigemptyset(&normal.sa_mask);
    for (int sig = 1; sig < NSIG; sig++)
        if (sig != SIGKILL && sig != SIGSTOP) sigaction(sig, &normal, NULL);
    sigaction(SIGPIPE, &ignored, NULL);
    sigset_t empty;
    sigemptyset(&empty);
    sigprocmask(SIG_SETMASK, &empty, NULL);
    int pipes[2] = { -1, -1 };
#ifdef __linux__
    if (started < 0 || setsid() < 0 || prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) {
        wire.state = MANAGEMENT_UNSUPPORTED;
    } else if (pipe2(pipes, O_CLOEXEC | O_NONBLOCK) == 0) {
        pid_t child = fork();
        if (child == 0) {
            if (setpgid(0, 0) != 0 || dup2(5, 0) < 0 ||
                dup2(pipes[1], 1) < 0 || dup2(pipes[1], 2) < 0) _exit(126);
            /* Tool writes are blocking; only the supervisor read end is not. */
            int flags = fcntl(1, F_GETFL);
            if (flags < 0 || fcntl(1, F_SETFL, flags & ~O_NONBLOCK) < 0 ||
                fcntl(1, F_SETFD, 0) < 0) _exit(126);
            close_from(3, maximum);
            sigaction(SIGPIPE, &normal, NULL);
            if (chdir("/") != 0) _exit(126);
            execve(argv[0], argv, env);
            _exit(127);
        }
        close(pipes[1]); pipes[1] = -1;
        if (child > 0) {
            gsize length = 0;
            int status = 0;
            gboolean reaped = FALSE;
            for (;;) {
                struct pollfd fds[] = {
                    { .fd = 4, .events = POLLIN | POLLHUP },
                    { .fd = pipes[0], .events = POLLIN | POLLHUP }
                };
                int polled = poll(fds, 2, 20);
                if (polled < 0 && errno != EINTR) break;
                if (fds[0].revents != 0) { wire.state = MANAGEMENT_CANCELLED; break; }
                if (!drain(pipes[0], buffer, limit, &length)) {
                    wire.state = length > limit ? MANAGEMENT_OUTPUT_LIMIT : MANAGEMENT_FAILED;
                    break;
                }
                pid_t got = waitpid(child, &status, WNOHANG);
                if (got == child) {
                    reaped = TRUE;
                    wire.state = WIFEXITED(status) && WEXITSTATUS(status) == 0 ?
                        MANAGEMENT_COMPLETE : MANAGEMENT_FAILED;
                    break;
                }
                if (got < 0 && errno != EINTR) break;
                int64_t now = monotonic_ms();
                if (now < 0 || now - started >= budget) { wire.state = MANAGEMENT_TIMEOUT; break; }
            }
            wire.retired = retire(child, reaped, &status);
            if (!drain(pipes[0], buffer, limit, &length) && length > limit)
                wire.state = MANAGEMENT_OUTPUT_LIMIT;
            wire.length = (uint32_t)(length > limit ? limit : length);
            if (reaped || wire.retired)
                wire.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) :
                    WIFSIGNALED(status) ? 128 + WTERMSIG(status) : -1;
        }
    }
#else
    (void)argv; (void)env; (void)buffer; (void)limit; (void)budget;
    wire.state = MANAGEMENT_UNSUPPORTED;
#endif
    if (pipes[0] >= 0) close(pipes[0]);
    wire.elapsed_ms = monotonic_ms() - started;
    int64_t until = monotonic_ms() + SEND_MS;
    gboolean sent = send_bytes(3, &wire, sizeof wire, until) &&
        send_bytes(3, buffer, wire.length, until);
    close(3); close(4); close(5);
    _exit(sent ? 0 : 125);
}

static const char *diagnostic(ManagementState state, gboolean retired)
{
    if (!retired) return "Process retirement could not be verified. This report is incomplete.";
    switch (state) {
    case MANAGEMENT_COMPLETE: return "Read-only command completed.";
    case MANAGEMENT_FAILED: return "The tool failed; its output may describe an unsupported or incomplete assessment.";
    case MANAGEMENT_TIMEOUT: return "The command exceeded its elapsed-time limit and was retired.";
    case MANAGEMENT_OUTPUT_LIMIT: return "The combined output limit was exceeded; the displayed report is truncated.";
    case MANAGEMENT_CANCELLED: return "The command was cancelled and its processes were retired.";
    case MANAGEMENT_UNAVAILABLE: return "The optional tool is not installed or executable.";
    case MANAGEMENT_UNSUPPORTED: return "This action requires an ordinary unprivileged Linux user and process supervision support.";
    default: return "Unknown command outcome.";
    }
}

static void finish(ManagementJob *job, ManagementState state, gboolean retired,
                   int exit_code, gint64 elapsed, const unsigned char *output, gsize length)
{
    job->finished = TRUE;
    if (job->read_source) g_source_remove(job->read_source);
    if (job->timer_source) g_source_remove(job->timer_source);
    if (job->read_fd >= 0) close(job->read_fd);
    if (job->cancel_fd >= 0) close(job->cancel_fd);
    /* GTK text receives valid UTF-8, no embedded NULs, and at most the cap. */
    gboolean binary = output != NULL && (memchr(output, 0, length) != NULL ||
        !g_utf8_validate((const char *)output, (gssize)length, NULL));
    if (binary) { state = MANAGEMENT_FAILED; length = 0; }
    char *raw = g_malloc(length + 1);
    if (length != 0) memcpy(raw, output, length);
    raw[length] = 0;
    char *text = g_utf8_make_valid(raw, (gssize)length);
    g_free(raw);
    if (strlen(text) > job->limit) {
        char *end = text + job->limit;
        while (end > text && ((*end & 0xc0) == 0x80)) end--;
        *end = 0;
    }
    ManagementResult result = { state, text, binary ? "The tool emitted invalid text report data (NUL or UTF-8)." :
        diagnostic(state, retired), exit_code, retired, elapsed };
    job->done(job, &result, job->data);
    g_free(text);
    g_byte_array_unref(job->bytes);
    g_free(job);
}

static void maybe_finish(ManagementJob *job)
{
    if (!job->child_done || !job->eof) return;
    Wire wire;
    gboolean valid = !job->protocol_error && !job->outer_timeout &&
        WIFEXITED(job->child_status) && WEXITSTATUS(job->child_status) == 0 &&
        job->bytes->len >= sizeof wire;
    if (valid) {
        memcpy(&wire, job->bytes->data, sizeof wire);
        valid = wire.magic == WIRE_MAGIC && wire.state <= MANAGEMENT_UNSUPPORTED &&
            wire.length <= job->limit && wire.retired <= 1 && wire.elapsed_ms >= 0 &&
            job->bytes->len == sizeof wire + wire.length;
    }
    if (valid) {
        ManagementState state = job->cancelled ? MANAGEMENT_CANCELLED : (ManagementState)wire.state;
        finish(job, state, wire.retired, wire.exit_code, wire.elapsed_ms,
               job->bytes->data + sizeof wire, wire.length);
    } else {
        finish(job, job->outer_timeout ? MANAGEMENT_TIMEOUT : MANAGEMENT_FAILED,
               FALSE, -1, (g_get_monotonic_time() - job->started_us) / 1000, NULL, 0);
    }
}

static gboolean read_ready(gint fd, GIOCondition condition, gpointer data)
{
    ManagementJob *job = data;
    unsigned char buffer[8192];
    (void)condition;
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof buffer);
        if (n > 0) {
            if (job->bytes->len + (gsize)n > sizeof(Wire) + job->limit) {
                job->protocol_error = TRUE; management_cancel(job); break;
            }
            g_byte_array_append(job->bytes, buffer, (guint)n);
        } else if (n == 0) break;
        else if (errno == EINTR) continue;
        else if (errno == EAGAIN || errno == EWOULDBLOCK) return G_SOURCE_CONTINUE;
        else { job->protocol_error = TRUE; management_cancel(job); break; }
    }
    close(job->read_fd); job->read_fd = -1;
    job->read_source = 0; job->eof = TRUE;
    maybe_finish(job);
    return G_SOURCE_REMOVE;
}

static void child_done(GPid pid, gint status, gpointer data)
{
    ManagementJob *job = data;
    job->child_source = 0; job->child_done = TRUE; job->child_status = status;
    g_spawn_close_pid(pid);
    maybe_finish(job);
}

static gboolean outer_timeout(gpointer data)
{
    ManagementJob *job = data;
    job->timer_source = 0; job->outer_timeout = TRUE;
    management_cancel(job);
    if (!job->child_done) kill(job->pid, SIGKILL);
    return G_SOURCE_REMOVE;
}

static gboolean immediate_done(gpointer data)
{
    ManagementJob *job = data;
    job->idle_source = 0;
    finish(job, job->cancelled ? MANAGEMENT_CANCELLED : job->immediate,
           TRUE, -1, 0, NULL, 0);
    return G_SOURCE_REMOVE;
}

void management_cancel(ManagementJob *job)
{
    if (job == NULL || job->finished) return;
    job->cancelled = TRUE;
    /* EOF is the cancellation request, including when the UI process exits. */
    if (job->cancel_fd >= 0) { close(job->cancel_fd); job->cancel_fd = -1; }
}

ManagementJob *management_start(ManagementTool tool, ManagementDone done,
                                gpointer data, GError **error)
{
    if (management_program(tool) == NULL || done == NULL) {
        g_set_error_literal(error, G_FILE_ERROR, G_FILE_ERROR_INVAL, "Invalid management action or callback");
        return NULL;
    }
    ManagementJob *job = g_new0(ManagementJob, 1);
    job->started_us = g_get_monotonic_time();
    job->done = done; job->data = data; job->read_fd = -1; job->cancel_fd = -1;
    job->bytes = g_byte_array_new(); job->limit = OUTPUT_LIMIT;
    guint budget = RUN_MS;
    gboolean allow_root = FALSE;
#ifdef MANAGEMENT_TEST
    budget = test_ms; job->limit = test_limit; allow_root = test_root;
#endif
    job->immediate = MANAGEMENT_COMPLETE;
    if ((!allow_root && (getuid() == 0 || geteuid() == 0)) || getuid() != geteuid() || getgid() != getegid())
        job->immediate = MANAGEMENT_UNSUPPORTED;
#ifndef __linux__
    job->immediate = MANAGEMENT_UNSUPPORTED;
#endif
    if (job->immediate == MANAGEMENT_COMPLETE && !management_available(tool))
        job->immediate = MANAGEMENT_UNAVAILABLE;
    if (job->immediate != MANAGEMENT_COMPLETE) {
        job->idle_source = g_idle_add(immediate_done, job);
        return job;
    }
    int report[2] = { -1, -1 }, cancellation[2] = { -1, -1 };
    int out = -1, cancel = -1, null_fd = -1;
    unsigned char *buffer = g_malloc(job->limit + 1);
    char **env = environment();
    char *program = g_strdup(selected_program(tool));
    const char *argument = arguments[tool];
#ifdef MANAGEMENT_TEST
    if (test_argument != NULL) argument = test_argument;
#endif
    char *arg = g_strdup(argument);
    char *second = tool == MANAGEMENT_DNS ? g_strdup("profiles") : NULL;
#ifdef MANAGEMENT_TEST
    if (test_argument != NULL) g_clear_pointer(&second, g_free);
#endif
    char *argv[] = { program, arg, second, NULL };
    struct rlimit descriptors;
    unsigned maximum = getrlimit(RLIMIT_NOFILE, &descriptors) == 0 && descriptors.rlim_cur < INT_MAX ?
        (unsigned)descriptors.rlim_cur : 1048576;
    if (pipe2(report, O_CLOEXEC | O_NONBLOCK) != 0 || pipe2(cancellation, O_CLOEXEC | O_NONBLOCK) != 0 ||
        (out = fcntl(report[1], F_DUPFD_CLOEXEC, 10)) < 0 ||
        (cancel = fcntl(cancellation[0], F_DUPFD_CLOEXEC, 10)) < 0 ||
        (null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC)) < 0) goto failed;
    if (null_fd < 10) {
        int duplicate = fcntl(null_fd, F_DUPFD_CLOEXEC, 10);
        close(null_fd); null_fd = duplicate;
        if (null_fd < 0) goto failed;
    }
    job->pid = fork();
    if (job->pid < 0) goto failed;
    if (job->pid == 0)
        supervise(out, cancel, null_fd, maximum, argv, env, buffer, job->limit, budget);
    close(report[1]); close(cancellation[0]); close(out); close(cancel); close(null_fd);
    g_free(buffer); g_strfreev(env); g_free(program); g_free(arg); g_free(second);
    job->read_fd = report[0]; job->cancel_fd = cancellation[1];
    job->read_source = g_unix_fd_add(job->read_fd, G_IO_IN | G_IO_HUP | G_IO_ERR, read_ready, job);
    job->child_source = g_child_watch_add(job->pid, child_done, job);
    job->timer_source = g_timeout_add(budget + CLEANUP_MS + SEND_MS + 1000, outer_timeout, job);
    return job;
failed: {
    int saved = errno;
    if (report[0] >= 0) close(report[0]);
    if (report[1] >= 0) close(report[1]);
    if (cancellation[0] >= 0) close(cancellation[0]);
    if (cancellation[1] >= 0) close(cancellation[1]);
    if (out >= 0) close(out);
    if (cancel >= 0) close(cancel);
    if (null_fd >= 0) close(null_fd);
    g_free(buffer); g_strfreev(env); g_free(program); g_free(arg); g_free(second);
    g_byte_array_unref(job->bytes); g_free(job);
    g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(saved),
                "Cannot supervise management command: %s", g_strerror(saved));
    return NULL;
}
}
