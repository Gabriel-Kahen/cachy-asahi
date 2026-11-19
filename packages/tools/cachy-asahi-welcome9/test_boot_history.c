/* SPDX-License-Identifier: MIT; offline fixtures do not establish real history. */
#include "management-report.h"
#include "boot-fixtures.h"
#include <string.h>
static void expected(const char *text, ManagementReportState state) {
    ManagementReport r=management_report_parse(MANAGEMENT_BOOT_HISTORY,text);
    g_assert_cmpint(r.state,==,state);g_assert_nonnull(r.summary);management_report_clear(&r);
}
static void changed(const char *before,const char *after) {
    const char *at=strstr(BOOT_LISTED,before);g_assert_nonnull(at);
    char *value=g_strdup_printf("%.*s%s%s",(int)(at-BOOT_LISTED),BOOT_LISTED,after,at+strlen(before));
    expected(value,MANAGEMENT_REPORT_INVALID);g_free(value);
}
static void listed(void) {
    ManagementReport r=management_report_parse(MANAGEMENT_BOOT_HISTORY,BOOT_LISTED);
    g_assert_cmpint(r.state,==,MANAGEMENT_REPORT_VALID);
    g_assert_nonnull(strstr(r.summary,"Boot ID: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    g_assert_nonnull(strstr(r.summary,"18446744073709551615"));
    g_assert_nonnull(strstr(r.summary,"History completeness unknown; crash diagnosis not established"));
    g_assert_nonnull(strstr(r.summary,"No export or pstore read"));management_report_clear(&r);
    expected(BOOT_EMPTY,MANAGEMENT_REPORT_VALID);expected(BOOT_UNAVAILABLE,MANAGEMENT_REPORT_REFUSED);
    r=management_report_parse(MANAGEMENT_BOOT_HISTORY,BOOT_EMPTY);
    g_assert_nonnull(strstr(r.summary,"does not establish absent history"));management_report_clear(&r);
}
static void schema(void) {
    changed("\"list\"","\"export\"");changed("\"UNKNOWN\"","\"COMPLETE\"");
    changed("\"schema_version\":1","\"schema_version\":2");
    changed("\"schema_version\":1","\"schema_version\":1,\"extra\":true");
    changed("\"tool\":\"cachy-asahi-boot-report\"","\"tool\":\"cachy-asahi-doctor\"");
    changed("local system journal visible to caller","/fixture/untrusted-journal");
    changed("\"child_reaped\":true","\"child_reaped\":false");changed("\"exit_code\":0","\"exit_code\":1");
    changed("\"--list-boots\"","\"--boot=0\"");changed("\"PAGER\":\"cat\"","\"PAGER\":\"shell\"");
    changed("\"command_seconds\":20","\"command_seconds\":30");
    changed("\"created_utc\":\"2026-10-19T00:00:00+00:00\"","\"created_utc\":\"now\"");
    changed("\"boot_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"","\"boot_id\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"");
    changed("\"first_entry\":1","\"first_entry\":18446744073709551616");
    changed("\"first_entry\":1","\"first_entry\":true");changed("\"last_entry\":18446744073709551615","\"last_entry\":0");
    changed("\"index\":-1","\"index\":1.0");changed("\"index\":-1","\"index\":9223372036854775808");
    changed("\"index\":-1","\"index\":-1,\"index\":0");
    changed("\"sensitive_local_contents\":true","\"sensitive_local_contents\":false");
}
static void bounded(void) {
    const char *start=strstr(BOOT_LISTED,"\"boots\":[")+strlen("\"boots\":[");const char *end=strchr(start,']');g_assert_nonnull(end);
    char *row=g_strndup(start,(gsize)(end-start));GString *dupe=g_string_new_len(BOOT_LISTED,start-BOOT_LISTED);
    g_string_append_printf(dupe,"%s,%s%s",row,row,end);expected(dupe->str,MANAGEMENT_REPORT_INVALID);g_string_free(dupe,TRUE);
    char *huge=g_strnfill(1048577,'x');expected(huge,MANAGEMENT_REPORT_INVALID);g_free(huge);g_free(row);
    expected("{\"schema_version\":1}tail",MANAGEMENT_REPORT_INVALID);
    expected("{\"x\":\"\\u0000\"}",MANAGEMENT_REPORT_INVALID);
    expected("{\"x\":NaN}",MANAGEMENT_REPORT_INVALID);
    expected("{\"x\":\"\xff\"}",MANAGEMENT_REPORT_INVALID);
}
int main(int argc,char **argv) {
    g_test_init(&argc,&argv,NULL);
    g_test_add_func("/boot-history/listed-empty-unavailable",listed);
    g_test_add_func("/boot-history/schema-refusals",schema);
    g_test_add_func("/boot-history/bounds-duplicate-full-json",bounded);
    return g_test_run();
}
