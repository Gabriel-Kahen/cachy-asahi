/* SPDX-License-Identifier: MIT */
#ifndef CACHY_ASAHI_WELCOME_STATUS_H
#define CACHY_ASAHI_WELCOME_STATUS_H
#include <glib.h>

#define WELCOME_VERSION "0.1.0"
#define WELCOME_PACKAGE_COUNT 6
typedef enum { PACKAGE_UNKNOWN, PACKAGE_NOT_FOUND, PACKAGE_INSTALLED } PackageState;
typedef struct { const char *name; PackageState state; char *version; } WelcomePackage;
typedef struct {
    char *architecture, *kernel;
    long page_size;
    gboolean database_available;
    WelcomePackage packages[WELCOME_PACKAGE_COUNT];
} WelcomeStatus;

void welcome_status_read(WelcomeStatus *status, const char *database);
void welcome_status_clear(WelcomeStatus *status);
const char *welcome_package_state(PackageState state);
char *welcome_status_text(const WelcomeStatus *status);
char *welcome_status_json(const WelcomeStatus *status);
#endif
