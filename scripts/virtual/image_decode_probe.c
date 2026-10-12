/* SPDX-License-Identifier: MIT */
/* Fixed-input observations only. The cache hash identifies a captured file, not
 * proof that GIO used those bytes. Stream decoding is not GTK filename loading.
 * The caller must supervise library work with its own resource/time policy. */
#define _GNU_SOURCE
#include <gio/gio.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ASSET "/usr/share/icons/Adwaita/scalable/status/image-missing.svg"
#define CACHE "/usr/share/mime/mime.cache"
#define MAX_FORMATS 64

typedef struct {
    const char *status;
    int error;
    gsize size;
    guchar *bytes;
    gchar *sha256;
} Snapshot;
typedef struct { gchar *name; gboolean disabled; } Format;

static gboolean identity(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_nlink == b->st_nlink;
}
static gboolean unchanged(const struct stat *a, const struct stat *b) {
    return identity(a, b) && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static void io_error(Snapshot *s) {
    s->error = errno;
    s->status = errno == ENOENT ? "missing" :
        (errno == ELOOP || errno == ENOTDIR ? "refused" : "io-error");
}

/* Retain every nofollow parent while capturing; named identities are checked
 * again before accepting bytes. Metadata stability covers this interval only. */
static Snapshot snapshot(const char *path, gsize limit) {
    Snapshot s = { .status = "refused" };
    gchar **parts = g_strsplit(path + 1, "/", -1);
    guint count = g_strv_length(parts), depth = 0;
    int dirs[16], fd = -1;
    struct stat parents[16], named, before, after;
    if (count < 2 || count > 16) goto done;
    dirs[0] = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dirs[0] < 0) { io_error(&s); goto done; }
    depth = 1;
    if (fstat(dirs[0], &parents[0]) < 0) { io_error(&s); goto done; }
    for (guint i = 0; i + 1 < count; i++) {
        if (fstatat(dirs[i], parts[i], &named, AT_SYMLINK_NOFOLLOW) < 0) { io_error(&s); goto done; }
        if (!S_ISDIR(named.st_mode)) goto done;
        dirs[i + 1] = openat(dirs[i], parts[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dirs[i + 1] < 0) { io_error(&s); goto done; }
        depth++;
        if (fstat(dirs[i + 1], &parents[i + 1]) < 0) { io_error(&s); goto done; }
        if (!identity(&named, &parents[i + 1])) { s.status = "changed"; goto done; }
    }
    if (fstatat(dirs[count - 1], parts[count - 1], &named, AT_SYMLINK_NOFOLLOW) < 0) { io_error(&s); goto done; }
    if (!S_ISREG(named.st_mode) || named.st_nlink != 1 || named.st_size < 0 ||
        (uint64_t)named.st_size > limit) goto done;
    fd = openat(dirs[count - 1], parts[count - 1], O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { io_error(&s); goto done; }
    if (fstat(fd, &before) < 0) { io_error(&s); goto done; }
    if (!unchanged(&named, &before)) { s.status = "changed"; goto done; }
    s.size = (gsize)before.st_size;
    s.bytes = g_try_malloc(s.size + 1);
    if (!s.bytes) { s.status = "io-error"; s.error = ENOMEM; goto done; }
    gsize used = 0;
    while (used < s.size) {
        ssize_t n = read(fd, s.bytes + used, s.size - used);
        if (n < 0) { if (errno == EINTR) continue; io_error(&s); goto done; }
        if (n == 0) { s.status = "changed"; goto done; }
        used += (gsize)n;
    }
    ssize_t n;
    do { n = read(fd, s.bytes + s.size, 1); } while (n < 0 && errno == EINTR);
    if (n < 0) { io_error(&s); goto done; }
    if (n != 0) { s.status = "changed"; goto done; }
    if (fstat(fd, &after) < 0 ||
        fstatat(dirs[count - 1], parts[count - 1], &named, AT_SYMLINK_NOFOLLOW) < 0) { io_error(&s); goto done; }
    if (!unchanged(&before, &after) || !unchanged(&before, &named)) { s.status = "changed"; goto done; }
    for (guint i = 0; i + 1 < count; i++) {
        if (fstatat(dirs[i], parts[i], &named, AT_SYMLINK_NOFOLLOW) < 0) { io_error(&s); goto done; }
        if (!identity(&parents[i + 1], &named)) { s.status = "changed"; goto done; }
    }
    s.sha256 = g_compute_checksum_for_data(G_CHECKSUM_SHA256, s.bytes, s.size);
    s.status = "ok";
done:
    if (fd >= 0 && close(fd) < 0 && strcmp(s.status, "ok") == 0) io_error(&s);
    while (depth) close(dirs[--depth]);
    g_strfreev(parts);
    if (strcmp(s.status, "ok") != 0) {
        g_clear_pointer(&s.bytes, g_free); g_clear_pointer(&s.sha256, g_free); s.size = 0;
    }
    return s;
}

static gboolean token(const char *s) {
    size_t n = strnlen(s, 65);
    if (!n || n > 64 || !g_ascii_isalnum(s[0])) return FALSE;
    for (size_t i = 0; i < n; i++)
        if (!g_ascii_isalnum(s[i]) && !strchr("_+.- ", s[i])) return FALSE;
    return TRUE;
}
static gboolean mime(const char *s) {
    if (!s) return FALSE;
    size_t n = strnlen(s, 129), slash = 0;
    if (!n || n > 128 || !g_ascii_isalnum(s[0]) || s[n - 1] == '/') return FALSE;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '/') {
            if (!g_ascii_isalnum(s[i + 1])) return FALSE;
            slash++; continue;
        }
        if (!g_ascii_isalnum(s[i]) && !strchr("!#$&^_.+-", s[i])) return FALSE;
    }
    return slash == 1;
}
static int format_order(const void *a, const void *b) {
    const Format *left = a, *right = b;
    int name = strcmp(left->name, right->name);
    return name ? name : (int)!!left->disabled - (int)!!right->disabled;
}
static void snapshot_json(GString *out, const Snapshot *s) {
    g_string_append_printf(out, "{\"status\":\"%s\",\"size\":", s->status);
    if (strcmp(s->status, "ok") == 0)
        g_string_append_printf(out, "%zu,\"sha256\":\"%s\"", (size_t)s->size, s->sha256);
    else g_string_append(out, "null,\"sha256\":null");
    g_string_append_printf(out, ",\"errno\":%d}", s->error);
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) return 64;
    int result = 2;
    Snapshot asset = snapshot(ASSET, 256 * 1024), cache = snapshot(CACHE, 16 * 1024 * 1024);
    Format formats[MAX_FORMATS] = {0}; guint count = 0;
    const char *format_status = "observed", *decode_status = "not-attempted";
    gchar *content = NULL, *type = NULL; gboolean uncertain = FALSE, is_svg = FALSE;
    GError *error = NULL; GdkPixbuf *pixbuf = NULL; GInputStream *stream = NULL;
    int width = 0, height = 0;
    GString *out = NULL;
    if (strcmp(asset.status, "ok") == 0) {
        type = g_content_type_guess(ASSET, asset.bytes, asset.size, &uncertain);
        if (!type) goto done;
        content = g_content_type_get_mime_type(type);
        if (!mime(content)) goto done;
        is_svg = g_content_type_is_a(type, "image/svg+xml");
    }
    GSList *available = gdk_pixbuf_get_formats();
    for (GSList *p = available; p; p = p->next) {
        if (count == MAX_FORMATS) { format_status = "limit"; break; }
        gchar *name = gdk_pixbuf_format_get_name(p->data);
        if (!name || !token(name)) { g_free(name); format_status = "name-refused"; break; }
        formats[count++] = (Format){name, gdk_pixbuf_format_is_disabled(p->data)};
    }
    g_slist_free(available);
    qsort(formats, count, sizeof(Format), format_order);
    if (strcmp(asset.status, "ok") == 0) {
        stream = g_memory_input_stream_new_from_data(asset.bytes, (gssize)asset.size, NULL);
        pixbuf = gdk_pixbuf_new_from_stream(stream, NULL, &error); /* Exactly one decode. */
        if (pixbuf) {
            if (error) goto done;
            width = gdk_pixbuf_get_width(pixbuf); height = gdk_pixbuf_get_height(pixbuf);
            if (width < 1 || width > 32768 || height < 1 || height > 32768) goto done;
            decode_status = "success";
        } else {
            if (!error) goto done;
            decode_status = "error";
        }
    }
    out = g_string_new("{\"schema_version\":1,\"scope\":\"fixed-adwaita-svg-observation\",\"observation_only\":true,\"asset\":");
    snapshot_json(out, &asset); g_string_append(out, ",\"cache\":"); snapshot_json(out, &cache);
    g_string_append(out, ",\"content_type\":{");
    if (content) g_string_append_printf(out, "\"status\":\"observed\",\"value\":\"%s\",\"uncertain\":%s,\"is_svg\":%s}",
        content, uncertain ? "true" : "false", is_svg ? "true" : "false");
    else g_string_append(out, "\"status\":\"not-attempted\",\"value\":null,\"uncertain\":null,\"is_svg\":null}");
    g_string_append_printf(out, ",\"formats\":{\"status\":\"%s\",\"entries\":[", format_status);
    if (strcmp(format_status, "observed") == 0)
        for (guint i = 0; i < count; i++) g_string_append_printf(out, "%s{\"name\":\"%s\",\"disabled\":%s}",
            i ? "," : "", formats[i].name, formats[i].disabled ? "true" : "false");
    g_string_append_printf(out, "]},\"decode\":{\"status\":\"%s\",\"width\":", decode_status);
    if (pixbuf) g_string_append_printf(out, "%d,\"height\":%d", width, height);
    else g_string_append(out, "null,\"height\":null");
    if (error) g_string_append_printf(out, ",\"error_domain\":%" G_GUINT32_FORMAT ",\"error_code\":%" G_GINT32_FORMAT "}}\n",
        (guint32)error->domain, (gint32)error->code);
    else g_string_append(out, ",\"error_domain\":null,\"error_code\":null}}\n");
    if (out->len <= 16384 && fwrite(out->str, 1, out->len, stdout) == out->len && fflush(stdout) == 0) result = 0;
done:
    if (out) g_string_free(out, TRUE);
    g_clear_object(&pixbuf); g_clear_object(&stream); g_clear_error(&error);
    g_free(type); g_free(content);
    for (guint i = 0; i < count; i++) g_free(formats[i].name);
    g_free(asset.bytes); g_free(asset.sha256); g_free(cache.bytes); g_free(cache.sha256);
    return result;
}
