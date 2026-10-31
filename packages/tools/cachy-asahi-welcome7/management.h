/* SPDX-License-Identifier: MIT */
#ifndef WELCOME_MANAGEMENT_H
#define WELCOME_MANAGEMENT_H

#include <glib.h>

typedef enum { MANAGEMENT_DOCTOR, MANAGEMENT_ORPHANS, MANAGEMENT_DNS, MANAGEMENT_BOOT_HISTORY, MANAGEMENT_TOOL_COUNT } ManagementTool;
typedef struct ManagementJob ManagementJob;
typedef enum {
    MANAGEMENT_COMPLETE, MANAGEMENT_FAILED, MANAGEMENT_TIMEOUT,
    MANAGEMENT_OUTPUT_LIMIT, MANAGEMENT_CANCELLED, MANAGEMENT_UNAVAILABLE,
    MANAGEMENT_UNSUPPORTED
} ManagementState;
typedef struct {
    ManagementState state;
    const char *output;
    const char *diagnostic;
    int exit_code;
    gboolean retired;
    gint64 elapsed_ms;
} ManagementResult;
typedef void (*ManagementDone)(ManagementJob *, const ManagementResult *, gpointer);

const char *management_program(ManagementTool tool);
gboolean management_available(ManagementTool tool);
/* Default-main-context use only. The callback is asynchronous and runs once.
 * Job and result strings are valid through the callback, then freed. A NULL
 * return sets error and does not schedule a callback. No startup scan occurs. */
ManagementJob *management_start(ManagementTool tool, ManagementDone done,
                                gpointer data, GError **error);
void management_cancel(ManagementJob *job);

#ifdef MANAGEMENT_TEST
/* Private compile-time seam: never compiled into the installed application. */
void management_test_dns_metadata(const char *absolute_path);
void management_test_configure(const char *absolute_program, const char *argument,
                               guint timeout_ms, gsize output_limit,
                               gboolean allow_root);
#endif
#endif
