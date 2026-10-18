/* SPDX-License-Identifier: MIT */
#include "management-report.h"
#include <string.h>

#define DOCTOR "{\"schema_version\":1,\"tool\":\"cachy-asahi-doctor\",\"scope\":\"local observations only\",\"checks\":[{\"check\":\"platform\",\"state\":\"checked\",\"value\":{},\"note\":\"observed\"},{\"check\":\"bus\",\"state\":\"unavailable\",\"value\":null,\"note\":\"missing\"}],\"coverage\":{\"checked\":1,\"unavailable\":1,\"unknown\":0}}"
#define ORPHANS "{\"schema_version\":1,\"scope\":\"LOCAL_INSTALLED_METADATA_ONLY_NOT_PAYLOAD_RELEASE_REMOVAL_OR_HARDWARE_PROOF\",\"apply_supported\":false,\"packages\":{\"unused\":{\"candidate\":true}},\"candidates\":[\"unused\"],\"broken_dependencies\":[]}"
static void state(ManagementTool tool, const char *text, ManagementReportState expected) {
    ManagementReport report = management_report_parse(tool, text);
    g_assert_cmpint(report.state, ==, expected); g_assert_nonnull(report.summary);
    management_report_clear(&report); g_assert_null(report.summary);
}
static char *replace(const char *text, const char *before, const char *after) {
    const char *at = strstr(text, before); g_assert_nonnull(at);
    return g_strdup_printf("%.*s%s%s", (int)(at - text), text, after, at + strlen(before));
}
static void changed(ManagementTool tool, const char *text, const char *before, const char *after) {
    char *copy = replace(text, before, after); state(tool, copy, MANAGEMENT_REPORT_INVALID); g_free(copy);
}
static void doctor_valid(void) {
    ManagementReport report = management_report_parse(MANAGEMENT_DOCTOR, DOCTOR);
    g_assert_cmpint(report.state, ==, MANAGEMENT_REPORT_VALID);
    g_assert_nonnull(strstr(report.summary, "1 observed, 1 unavailable, 0 unknown"));
    g_assert_null(strstr(report.summary, "healthy")); management_report_clear(&report);
    const char *empty = "{\"schema_version\":1,\"tool\":\"cachy-asahi-doctor\",\"scope\":\"local observations only\",\"checks\":[],\"coverage\":{\"checked\":0,\"unavailable\":0,\"unknown\":0}}";
    state(MANAGEMENT_DOCTOR, empty, MANAGEMENT_REPORT_VALID);
}
static void doctor_schema(void) {
    changed(MANAGEMENT_DOCTOR, DOCTOR, "\"checked\":1", "\"checked\":2");
    changed(MANAGEMENT_DOCTOR, DOCTOR, "\"unknown\":0", "\"unknown\":false");
    changed(MANAGEMENT_DOCTOR, DOCTOR, "\"unknown\":0", "\"unknown\":0.0");
    changed(MANAGEMENT_DOCTOR, DOCTOR, "\"state\":\"checked\"", "\"state\":\"healthy\"");
    changed(MANAGEMENT_DOCTOR, DOCTOR, "\"check\":\"bus\"", "\"check\":\"platform\"");
    changed(MANAGEMENT_DOCTOR, DOCTOR, "\"schema_version\":1", "\"schema_version\":2");
    changed(MANAGEMENT_DOCTOR, DOCTOR, "local observations only", "hardware certified");
    state(MANAGEMENT_ORPHANS, DOCTOR, MANAGEMENT_REPORT_INVALID);
}
static void orphans_valid(void) {
    ManagementReport report = management_report_parse(MANAGEMENT_ORPHANS, ORPHANS);
    g_assert_cmpint(report.state, ==, MANAGEMENT_REPORT_VALID);
    g_assert_nonnull(strstr(report.summary, "1 possible orphan"));
    g_assert_nonnull(strstr(report.summary, "Assessment only; packages remain installed.")); management_report_clear(&report);
    char *empty = replace(ORPHANS, "true", "false"), *none = replace(empty, "[\"unused\"]", "[]");
    report = management_report_parse(MANAGEMENT_ORPHANS, none);
    g_assert_cmpint(report.state, ==, MANAGEMENT_REPORT_VALID); g_assert_nonnull(strstr(report.summary, "0 possible orphans"));
    management_report_clear(&report); g_free(empty); g_free(none);
    char *broken = replace(ORPHANS, "\"broken_dependencies\":[]", "\"broken_dependencies\":[{\"package\":\"unused\",\"dependency\":\"libfoo>=1\"}]");
    report = management_report_parse(MANAGEMENT_ORPHANS, broken);
    g_assert_cmpint(report.state, ==, MANAGEMENT_REPORT_VALID); g_assert_nonnull(strstr(report.summary, "1 broken dependency"));
    management_report_clear(&report); g_free(broken);
}
static void orphans_schema(void) {
    changed(MANAGEMENT_ORPHANS, ORPHANS, "\"apply_supported\":false", "\"apply_supported\":true");
    changed(MANAGEMENT_ORPHANS, ORPHANS, "\"candidate\":true", "\"candidate\":false");
    changed(MANAGEMENT_ORPHANS, ORPHANS, "[\"unused\"]", "[\"unused\",\"unused\"]");
    changed(MANAGEMENT_ORPHANS, ORPHANS, "[\"unused\"]", "[42]");
    changed(MANAGEMENT_ORPHANS, ORPHANS, "\"broken_dependencies\":[]", "\"broken_dependencies\":[{\"package\":\"absent\",\"dependency\":\"x\"}]");
    changed(MANAGEMENT_ORPHANS, ORPHANS, "LOCAL_INSTALLED_METADATA_ONLY_NOT_PAYLOAD_RELEASE_REMOVAL_OR_HARDWARE_PROOF", "COMPLETE_PROTECTION");
}
static void invalid_json(void) {
    const char *bad[] = {"", " ", "null", "[]", "{", "{\"x\":}", "{\"x\":1,}", "{\"x\":[1,]}", "{\"x\":01}", "{\"x\":1.}", "{\"x\":1e}", "{\"x\":NaN}", "{\"x\":true}tail", "{\"x\":\"raw\nnewline\"}", "{\"x\":\"\\q\"}"};
    for (guint i = 0; i < G_N_ELEMENTS(bad); i++) state(MANAGEMENT_DOCTOR, bad[i], MANAGEMENT_REPORT_INVALID);
    state(MANAGEMENT_DOCTOR, NULL, MANAGEMENT_REPORT_INVALID);
    state((ManagementTool)99, DOCTOR, MANAGEMENT_REPORT_INVALID);
    changed(MANAGEMENT_DOCTOR, DOCTOR, "\"schema_version\":1", "\"schema_version\":1,\"schema_version\":1");
    changed(MANAGEMENT_DOCTOR, DOCTOR, "\"checked\":1", "\"checked\":1,\"\\u0063hecked\":1");
}
static void unicode(void) {
    const char *valid = "{\"verification\":\"REFUSED\",\"reason\":\"\\uD83D\\uDE00 café <b>\\ntext\"}";
    ManagementReport report = management_report_parse(MANAGEMENT_ORPHANS, valid);
    g_assert_cmpint(report.state, ==, MANAGEMENT_REPORT_REFUSED);
    g_assert_nonnull(strstr(report.summary, "😀 café <b> text")); management_report_clear(&report);
    const char *bad[] = {"\\uD800", "\\uDC00", "\\uD800\\u0041", "\\u0000", "\xc0\xaf", "\xed\xa0\x80"};
    for (guint i = 0; i < G_N_ELEMENTS(bad); i++) { char *copy = g_strdup_printf("{\"verification\":\"REFUSED\",\"reason\":\"%s\"}", bad[i]); state(MANAGEMENT_ORPHANS, copy, MANAGEMENT_REPORT_INVALID); g_free(copy); }
}
static void refusal(void) {
    state(MANAGEMENT_ORPHANS, "{\"status\":\"NOT_APPLIED\",\"verification\":\"REFUSED\",\"reason\":\"DB locked\",\"apply_supported\":false}", MANAGEMENT_REPORT_REFUSED);
    state(MANAGEMENT_DOCTOR, "{\"verification\":\"REFUSED\",\"reason\":false}", MANAGEMENT_REPORT_INVALID);
    state(MANAGEMENT_DOCTOR, "{\"verification\":\"REFUSED\",\"reason\":\"\"}", MANAGEMENT_REPORT_INVALID);
    char *long_reason = g_strnfill(1000, 'x'), *json = g_strdup_printf("{\"verification\":\"REFUSED\",\"reason\":\"%s\"}", long_reason);
    ManagementReport report = management_report_parse(MANAGEMENT_DOCTOR, json);
    g_assert_cmpint(report.state, ==, MANAGEMENT_REPORT_REFUSED); g_assert_cmpuint(strlen(report.summary), ==, strlen("Assessment refused: ") + 300);
    management_report_clear(&report); g_free(json); g_free(long_reason);
}
static void bounds(void) {
    char *padding = g_strnfill(1024 * 1024, ' '), *large = g_strconcat(padding, DOCTOR, NULL);
    state(MANAGEMENT_DOCTOR, large, MANAGEMENT_REPORT_INVALID); g_free(large); g_free(padding);
    GString *deep = g_string_new_len(DOCTOR, strlen(DOCTOR) - 1); g_string_append(deep, ",\"extra\":");
    for (guint i = 0; i < 40; i++) g_string_append_c(deep, '[');
    g_string_append_c(deep, '0'); for (guint i = 0; i < 40; i++) g_string_append_c(deep, ']'); g_string_append_c(deep, '}');
    state(MANAGEMENT_DOCTOR, deep->str, MANAGEMENT_REPORT_INVALID); g_string_free(deep, TRUE);
    GString *many = g_string_new_len(DOCTOR, strlen(DOCTOR) - 1); g_string_append(many, ",\"extra\":[0");
    for (guint i = 0; i < 65536; i++) g_string_append(many, ",0");
    g_string_append(many, "]}");
    state(MANAGEMENT_DOCTOR, many->str, MANAGEMENT_REPORT_INVALID); g_string_free(many, TRUE);
    GString *checks = g_string_new("{\"schema_version\":1,\"tool\":\"cachy-asahi-doctor\",\"scope\":\"local observations only\",\"checks\":[");
    for (guint i = 0; i < 513; i++) g_string_append_printf(checks, "%s{\"check\":\"item%u\",\"state\":\"checked\",\"value\":0,\"note\":\"\"}", i ? "," : "", i);
    g_string_append(checks, "],\"coverage\":{\"checked\":513,\"unavailable\":0,\"unknown\":0}}");
    state(MANAGEMENT_DOCTOR, checks->str, MANAGEMENT_REPORT_INVALID); g_string_free(checks, TRUE);
}
int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/report/doctor/valid", doctor_valid); g_test_add_func("/report/doctor/schema", doctor_schema);
    g_test_add_func("/report/orphans/valid", orphans_valid); g_test_add_func("/report/orphans/schema", orphans_schema);
    g_test_add_func("/report/json", invalid_json); g_test_add_func("/report/unicode", unicode);
    g_test_add_func("/report/refusal", refusal); g_test_add_func("/report/bounds", bounds);
    return g_test_run();
}
