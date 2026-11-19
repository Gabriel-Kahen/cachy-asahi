/* SPDX-License-Identifier: MIT */
#ifndef MANAGEMENT_REPORT_H
#define MANAGEMENT_REPORT_H
#include <glib.h>
#include "management.h"

typedef enum {
    MANAGEMENT_REPORT_VALID, MANAGEMENT_REPORT_REFUSED, MANAGEMENT_REPORT_INVALID
} ManagementReportState;
typedef struct { ManagementReportState state; char *summary; } ManagementReport;

/* Input must be NUL-terminated; callers must reject embedded NUL in captured bytes.
 * Summaries are plain text, never markup. Caller owns the returned summary. */
ManagementReport management_report_parse(ManagementTool tool, const char *text);
/* Declared installed metadata only; execution/schema support is checked on click. */
gboolean management_dns_version_supported(const char *text);
void management_report_clear(ManagementReport *report);
#endif
