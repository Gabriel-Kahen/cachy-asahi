/* SPDX-License-Identifier: MIT
 * Private fixture notify-send recorder; no notification service or bus access.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static char record[4096];
static size_t used;

static int append(const char *text, size_t length)
{
    if (length >= sizeof(record) - used)
        return -1;
    memcpy(record + used, text, length);
    used += length;
    return 0;
}

static int unicode(unsigned int value)
{
    char escape[7];
    int length = snprintf(escape, sizeof(escape), "\\u%04x", value);
    return length == 6 ? append(escape, 6) : -1;
}

static int quoted(const unsigned char *text)
{
    if (append("\"", 1))
        return -1;
    while (*text) {
        unsigned int value = *text++;
        if (value >= 0x80) {
            unsigned int minimum;
            size_t count;
            const unsigned char *continuation = text;
            if (value >= 0xc2 && value <= 0xdf) {
                count = 1; minimum = 0x80; value &= 0x1f;
            } else if (value >= 0xe0 && value <= 0xef) {
                count = 2; minimum = 0x800; value &= 0x0f;
            } else if (value >= 0xf0 && value <= 0xf4) {
                count = 3; minimum = 0x10000; value &= 0x07;
            } else {
                count = 0; minimum = 1;
            }
            size_t index = 0;
            while (index < count && continuation[index] >= 0x80 && continuation[index] <= 0xbf) {
                value = (value << 6) | (continuation[index] & 0x3f);
                index++;
            }
            if (count && index == count && value >= minimum && value <= 0x10ffff &&
                !(value >= 0xd800 && value <= 0xdfff))
                text += count;
            else
                value = 0xdc00 + text[-1]; /* Python argv UTF-8 surrogateescape. */
        }
        const char *escape = NULL;
        switch (value) {
        case '"': escape = "\\\""; break;
        case '\\': escape = "\\\\"; break;
        case '\b': escape = "\\b"; break;
        case '\f': escape = "\\f"; break;
        case '\n': escape = "\\n"; break;
        case '\r': escape = "\\r"; break;
        case '\t': escape = "\\t"; break;
        }
        if (escape) {
            if (append(escape, 2)) return -1;
        } else if (value >= 0x10000) {
            value -= 0x10000;
            if (unicode(0xd800 + (value >> 10)) || unicode(0xdc00 + (value & 0x3ff))) return -1;
        } else if (value < 0x20 || value >= 0x7f) {
            if (unicode(value)) return -1;
        } else {
            char byte = (char)value;
            if (append(&byte, 1)) return -1;
        }
    }
    return append("\"", 1);
}

static char *home_path(const char *home, const char *leaf)
{
    size_t first = strlen(home), second = strlen(leaf);
    if (first > SIZE_MAX - second - 2) return NULL;
    char *path = malloc(first + second + 2);
    if (path) snprintf(path, first + second + 2, "%s/%s", home, leaf);
    return path;
}

int main(int argc, char **argv)
{
    const char *home = getenv("HOME");
    if (!home) return 1;
    char *path = home_path(home, "notifications.jsonl");
    if (!path) return 1;
    int output = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    free(path);
    if (output < 0) return 1;
    int invalid = append("{\"argv\": [", 10);
    for (int index = 1; !invalid && index < argc; index++)
        invalid = (index > 1 && append(", ", 2)) || quoted((unsigned char *)argv[index]);
    char end[64];
    int length = snprintf(end, sizeof(end), "], \"pid\": %ld}\n", (long)getpid());
    if (invalid || length < 0 || (size_t)length >= sizeof(end) || append(end, (size_t)length)) {
        close(output);
        return 1;
    }
    ssize_t written = write(output, record, used);
    int closed = close(output);
    if (written != (ssize_t)used || closed) return 1;

    path = home_path(home, "notify-mode");
    if (!path) return 1;
    FILE *input = fopen(path, "rb");
    free(path);
    char mode[5];
    size_t count = 0;
    if (input) {
        count = fread(mode, 1, sizeof(mode), input);
        int failed = ferror(input);
        if (fclose(input) || failed) return 1;
    } else if (errno != ENOENT) return 1;
    if (count == 4 && !memcmp(mode, "hang", 4)) {
        if (signal(SIGTERM, SIG_IGN) == SIG_ERR) return 1;
        struct timespec remaining = {20, 0};
        while (nanosleep(&remaining, &remaining))
            if (errno != EINTR) return 1;
    }
    return count == 4 && !memcmp(mode, "fail", 4) ? 9 : 0;
}
