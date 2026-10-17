# SPDX-License-Identifier: MIT
PREFIX ?= /usr
CC ?= cc
PKG_CONFIG ?= pkg-config
PYTHON ?= python3
RECIPE_ROOT ?= .
CPPFLAGS += -DWELCOME_DOC_DIR='"$(PREFIX)/share/doc/cachy-asahi-welcome"'
CFLAGS ?= -O2
CFLAGS += -std=c11 -Wall -Wextra -Wformat=2 -Werror
LDFLAGS += -Wl,-z,max-page-size=16384
GTK_CFLAGS := $(shell $(PKG_CONFIG) --cflags gtk+-3.0)
GTK_LIBS := $(shell $(PKG_CONFIG) --libs gtk+-3.0)
GLIB_CFLAGS := $(shell $(PKG_CONFIG) --cflags gio-2.0)
GLIB_LIBS := $(shell $(PKG_CONFIG) --libs gio-2.0)

.PHONY: all check install clean
all: cachy-asahi-welcome

cachy-asahi-welcome: welcome.c status.c status.h management.c management.h management-report.c management-report.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(GTK_CFLAGS) welcome.c status.c management.c management-report.c -o $@ $(LDFLAGS) $(GTK_LIBS)

test-status: test_status.c status.c status.h
	$(CC) $(CFLAGS) $(GLIB_CFLAGS) test_status.c status.c -o $@ $(LDFLAGS) $(GLIB_LIBS)

test-management: test_management.c management.c management.h
	$(CC) $(CFLAGS) -DMANAGEMENT_TEST $(GLIB_CFLAGS) test_management.c management.c -o $@ $(LDFLAGS) $(GLIB_LIBS)

test-management-report: test_management_report.c management-report.c management-report.h management.h
	$(CC) $(CFLAGS) $(GLIB_CFLAGS) test_management_report.c management-report.c -o $@ $(LDFLAGS) $(GLIB_LIBS)

test-management-ui: test_management_ui.c welcome.c status.c status.h management.c management.h management-report.c management-report.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -DMANAGEMENT_TEST $(GTK_CFLAGS) test_management_ui.c status.c management.c management-report.c -o $@ $(LDFLAGS) $(GTK_LIBS)

test-report-work: test_report_work.c welcome.c status.c status.h management.c management.h management-report.c management-report.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(GTK_CFLAGS) test_report_work.c status.c management.c management-report.c -o $@ $(LDFLAGS) $(GTK_LIBS)

check: all test-status test-management test-management-report test-report-work
	./test-status
	./test-management
	./test-management-report
	./test-report-work
	$(PYTHON) -B test_cli.py ./cachy-asahi-welcome
	$(PYTHON) -B check_source.py --root "$(RECIPE_ROOT)"

install: all
	@test -n "$(DESTDIR)" || { echo 'Set an absolute private DESTDIR; direct host installation is unsupported.' >&2; exit 1; }
	@case "$(DESTDIR)" in /*) ;; *) echo 'DESTDIR must be absolute.' >&2; exit 1 ;; esac
	install -Dm755 cachy-asahi-welcome $(DESTDIR)$(PREFIX)/bin/cachy-asahi-welcome
	install -Dm644 io.github.GabrielKahen.CachyAsahiWelcome.desktop $(DESTDIR)$(PREFIX)/share/applications/io.github.GabrielKahen.CachyAsahiWelcome.desktop
	install -Dm644 cachy-asahi-welcome.svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/cachy-asahi-welcome.svg
	install -Dm644 first-run.txt $(DESTDIR)$(PREFIX)/share/doc/cachy-asahi-welcome/first-run.txt
	install -Dm644 updates.txt $(DESTDIR)$(PREFIX)/share/doc/cachy-asahi-welcome/updates.txt
	install -Dm644 recovery.txt $(DESTDIR)$(PREFIX)/share/doc/cachy-asahi-welcome/recovery.txt
	install -Dm644 README.md $(DESTDIR)$(PREFIX)/share/doc/cachy-asahi-welcome/README.md
	install -Dm644 LICENSE $(DESTDIR)$(PREFIX)/share/licenses/cachy-asahi-welcome/LICENSE
	install -Dm644 NOTICE $(DESTDIR)$(PREFIX)/share/licenses/cachy-asahi-welcome/NOTICE

clean:
	rm -f cachy-asahi-welcome test-status test-management test-management-report test-management-ui test-report-work
