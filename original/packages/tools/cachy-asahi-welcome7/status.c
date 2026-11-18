/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 cachy-asahi contributors */
#include "status.h"
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

static const char *const package_names[WELCOME_PACKAGE_COUNT] = {
    "cachy-asahi-welcome", "cachy-asahi-setup", "cachy-asahi-hyprland-settings",
    "cachy-asahi-update", "cachy-asahi-topmem", "cachy-asahi-ksmctl"
};

/* Read only matching project records. Missing/unreadable/malformed data is never
 * a hardware verdict. A duplicate record is ambiguous, not a version choice. */
static char *record_version(const char *path, const char *wanted)
{
    char data[65537];
    FILE *file = g_fopen(path, "rb");
    if (!file) return NULL;
    size_t bytes = fread(data, 1, sizeof(data), file);
    gboolean valid = !ferror(file) && bytes < sizeof(data);
    fclose(file);
    if (!valid || memchr(data, '\0', bytes) || !g_utf8_validate(data, (gssize)bytes, NULL)) return NULL;
    data[bytes] = '\0';
    char **lines = g_strsplit(data, "\n", -1);
    const char *name = NULL, *version = NULL;
    guint names = 0, versions = 0;
    for (guint i = 0; lines[i]; i++) {
        if (g_str_equal(lines[i], "%NAME%") && lines[i + 1]) { name = lines[i + 1]; names++; }
        if (g_str_equal(lines[i], "%VERSION%") && lines[i + 1]) { version = lines[i + 1]; versions++; }
    }
    valid = names == 1 && versions == 1 && g_strcmp0(name, wanted) == 0 && version && *version && strlen(version) <= 256;
    if (valid) {
        for (const unsigned char *p = (const unsigned char *)version; *p; p++)
            if (*p < 0x21 || *p == 0x7f || *p == '%' || *p == '/') valid = FALSE;
    }
    char *result = valid ? g_strdup(version) : NULL;
    g_strfreev(lines);
    return result;
}

void welcome_status_read(WelcomeStatus *status, const char *database)
{
    memset(status, 0, sizeof(*status));
    status->page_size = sysconf(_SC_PAGESIZE);
    struct utsname kernel;
    if (uname(&kernel) == 0) {
        status->architecture = g_utf8_make_valid(kernel.machine, -1);
        status->kernel = g_utf8_make_valid(kernel.release, -1);
    }
    for (guint i = 0; i < WELCOME_PACKAGE_COUNT; i++) status->packages[i].name = package_names[i];
    GDir *dir = g_dir_open(database, 0, NULL);
    if (!dir) return;
    status->database_available = TRUE;
    for (guint i = 0; i < WELCOME_PACKAGE_COUNT; i++) status->packages[i].state = PACKAGE_NOT_FOUND;
    guint seen[WELCOME_PACKAGE_COUNT] = {0};
    const char *entry;
    while ((entry = g_dir_read_name(dir))) {
        for (guint i = 0; i < WELCOME_PACKAGE_COUNT; i++) {
            WelcomePackage *package = &status->packages[i];
            size_t length = strlen(package->name);
            if (strncmp(entry, package->name, length) || entry[length] != '-') continue;
            char *path = g_build_filename(database, entry, "desc", NULL);
            char *version = record_version(path, package->name);
            g_free(path);
            /* A similarly named package is not an installed record for this one.
             * Its directory still makes absence ambiguous if it cannot be read. */
            seen[i]++;
            g_free(package->version);
            package->version = version;
            package->state = version && seen[i] == 1 ? PACKAGE_INSTALLED : PACKAGE_UNKNOWN;
        }
    }
    g_dir_close(dir);
    for (guint i = 0; i < WELCOME_PACKAGE_COUNT; i++) {
        if (status->packages[i].state != PACKAGE_INSTALLED) g_clear_pointer(&status->packages[i].version, g_free);
    }
}

void welcome_status_clear(WelcomeStatus *status)
{
    g_free(status->architecture); g_free(status->kernel);
    for (guint i = 0; i < WELCOME_PACKAGE_COUNT; i++) g_free(status->packages[i].version);
    memset(status, 0, sizeof(*status));
}

const char *welcome_package_state(PackageState state)
{
    switch (state) {
    case PACKAGE_INSTALLED: return "installed";
    case PACKAGE_NOT_FOUND: return "not-found";
    default: return "unknown";
    }
}

char *welcome_status_text(const WelcomeStatus *status)
{
    GString *out = g_string_new("cachy-asahi Welcome " WELCOME_VERSION "\n");
    char page[40];
    if (status->page_size > 0) g_snprintf(page, sizeof(page), "%ld bytes", status->page_size);
    else g_strlcpy(page, "unknown", sizeof(page));
    g_string_append_printf(out, "Architecture: %s\nPage size: %s\nKernel: %s\nPackage database: %s\n",
        status->architecture ? status->architecture : "unknown", page,
        status->kernel ? status->kernel : "unknown", status->database_available ? "readable" : "unavailable");
    for (guint i = 0; i < WELCOME_PACKAGE_COUNT; i++) {
        const WelcomePackage *p = &status->packages[i];
        g_string_append_printf(out, "%s: %s%s%s\n", p->name, welcome_package_state(p->state), p->version ? " " : "", p->version ? p->version : "");
    }
    g_string_append(out, "Hardware compatibility: not assessed\nPackage records are observations, not release or hardware acceptance.\n");
    return g_string_free(out, FALSE);
}

static void json_string(GString *out, const char *text)
{
    if (!text) { g_string_append(out, "null"); return; }
    g_string_append_c(out, '"');
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (*p == '"' || *p == '\\') { g_string_append_c(out, '\\'); g_string_append_c(out, (char)*p); }
        else if (*p < 0x20) g_string_append_printf(out, "\\u%04x", (unsigned)*p);
        else g_string_append_c(out, (char)*p);
    }
    g_string_append_c(out, '"');
}

char *welcome_status_json(const WelcomeStatus *status)
{
    GString *out = g_string_new("{\"schema_version\":1,\"project\":\"cachy-asahi\",\"welcome_version\":\"" WELCOME_VERSION "\",\"architecture\":");
    json_string(out, status->architecture);
    g_string_append(out, ",\"kernel\":"); json_string(out, status->kernel);
    g_string_append(out, ",\"page_size\":");
    if (status->page_size > 0) g_string_append_printf(out, "%ld", status->page_size); else g_string_append(out, "null");
    g_string_append(out, ",\"package_database\":"); json_string(out, status->database_available ? "readable" : "unavailable");
    g_string_append(out, ",\"hardware_compatibility\":\"not-assessed\",\"packages\":{");
    for (guint i = 0; i < WELCOME_PACKAGE_COUNT; i++) {
        const WelcomePackage *p = &status->packages[i];
        if (i) g_string_append_c(out, ',');
        json_string(out, p->name); g_string_append(out, ":{\"state\":");
        json_string(out, welcome_package_state(p->state)); g_string_append(out, ",\"version\":");
        json_string(out, p->version); g_string_append_c(out, '}');
    }
    g_string_append(out, "}}\n");
    return g_string_free(out, FALSE);
}
