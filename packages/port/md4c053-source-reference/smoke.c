/* SPDX-License-Identifier: MIT */
#include <md4c-html.h>
#include <stdio.h>
#include <string.h>

struct output { char data[2048]; size_t size; int overflow; };

static void collect(const MD_CHAR *data, MD_SIZE size, void *userdata)
{
    struct output *out = userdata;
    if (size > sizeof(out->data) - out->size) { out->overflow = 1; return; }
    memcpy(out->data + out->size, data, size);
    out->size += size;
}

static int render(const char *input, const char *expected, unsigned flags)
{
    struct output out = {{0}, 0, 0};
    int result = md_html(input, (MD_SIZE)strlen(input), collect, &out, flags, 0);
    if (result || out.overflow || out.size != strlen(expected) ||
        memcmp(out.data, expected, out.size)) {
        fprintf(stderr, "md_html output mismatch for %s\n", input);
        return 1;
    }
    return 0;
}

static int enter(MD_BLOCKTYPE type, void *detail, void *userdata)
{
    (void)detail;
    if (type == MD_BLOCK_H) (*(int *)userdata)++;
    return 0;
}
static int leave(MD_BLOCKTYPE type, void *detail, void *userdata)
{ (void)type; (void)detail; (void)userdata; return 0; }
static int span(MD_SPANTYPE type, void *detail, void *userdata)
{ (void)type; (void)detail; (void)userdata; return 0; }
static int text(MD_TEXTTYPE type, const MD_CHAR *value, MD_SIZE size, void *userdata)
{ (void)type; (void)value; (void)size; (void)userdata; return 0; }

int main(void)
{
    int headings = 0, failed = 0;
    MD_PARSER parser = {0};
    parser.enter_block = enter; parser.leave_block = leave;
    parser.enter_span = span; parser.leave_span = span; parser.text = text;
    if (md_parse("# API\n", 6, &parser, &headings) || headings != 1) return 1;
    failed |= render("# hello\n", "<h1>hello</h1>\n", 0);
    failed |= render("*hello* & <world>\n", "<p><em>hello</em> &amp; <world></p>\n", 0);
    failed |= render("[link](https://example.org)\n", "<p><a href=\"https://example.org\">link</a></p>\n", 0);
    failed |= render("café\n", "<p>café</p>\n", 0);
    failed |= render("a | b\n--|--\n1 | 2\n",
        "<table>\n<thead>\n<tr>\n<th>a</th>\n<th>b</th>\n</tr>\n</thead>\n<tbody>\n<tr>\n<td>1</td>\n<td>2</td>\n</tr>\n</tbody>\n</table>\n", MD_FLAG_TABLES);
    return failed;
}
