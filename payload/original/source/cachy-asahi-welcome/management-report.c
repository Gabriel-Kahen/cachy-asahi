/* SPDX-License-Identifier: MIT */
#include "management-report.h"
#include <string.h>

enum { MAX_BYTES = 1024 * 1024, MAX_DEPTH = 32, MAX_NODES = 65536 };
typedef enum { NIL, BOOL, NUMBER, STRING, ARRAY, OBJECT } Kind;
typedef struct Node Node;
struct Node { Kind kind; char *text; gboolean truth; GPtrArray *array; GHashTable *object; };
typedef struct { const char *p, *end; guint nodes; gboolean failed; } Parser;

static void node_free(gpointer data) {
    Node *n = data;
    if (!n) return;
    g_free(n->text);
    if (n->array) g_ptr_array_unref(n->array);
    if (n->object) g_hash_table_unref(n->object);
    g_free(n);
}
static void space(Parser *p) {
    while (p->p < p->end && strchr(" \t\r\n", *p->p)) p->p++;
}
static gboolean take(Parser *p, char c) {
    space(p);
    if (p->p < p->end && *p->p == c) { p->p++; return TRUE; }
    p->failed = TRUE; return FALSE;
}
static guint hex4(Parser *p) {
    guint value = 0;
    for (guint i = 0; i < 4; i++) {
        if (p->p == p->end || !g_ascii_isxdigit(*p->p)) { p->failed = TRUE; return 0; }
        value = value * 16 + (guint)g_ascii_xdigit_value(*p->p++);
    }
    return value;
}
static char *string(Parser *p) {
    if (!take(p, '"')) return NULL;
    GString *out = g_string_new(NULL);
    while (p->p < p->end && !p->failed) {
        guint8 c = (guint8)*p->p++;
        if (c == '"') return g_string_free(out, FALSE);
        if (c < 0x20) break;
        if (c != '\\') { g_string_append_c(out, (char)c); continue; }
        if (p->p == p->end) break;
        c = (guint8)*p->p++;
        switch (c) {
        case '"': case '\\': case '/': g_string_append_c(out, (char)c); break;
        case 'b': g_string_append_c(out, '\b'); break;
        case 'f': g_string_append_c(out, '\f'); break;
        case 'n': g_string_append_c(out, '\n'); break;
        case 'r': g_string_append_c(out, '\r'); break;
        case 't': g_string_append_c(out, '\t'); break;
        case 'u': {
            guint cp = hex4(p);
            if (p->failed) break;
            if (cp >= 0xd800 && cp <= 0xdbff) {
                if (p->end - p->p < 6 || p->p[0] != '\\' || p->p[1] != 'u') { p->failed = TRUE; break; }
                p->p += 2;
                guint low = hex4(p);
                if (p->failed || low < 0xdc00 || low > 0xdfff) { p->failed = TRUE; break; }
                cp = 0x10000 + (cp - 0xd800) * 0x400 + low - 0xdc00;
            } else if (cp >= 0xdc00 && cp <= 0xdfff) { p->failed = TRUE; break; }
            if (!cp) { p->failed = TRUE; break; }
            g_string_append_unichar(out, cp); break;
        }
        default: p->failed = TRUE;
        }
    }
    p->failed = TRUE; g_string_free(out, TRUE); return NULL;
}
static Node *value(Parser *p, guint depth) {
    space(p);
    if (depth > MAX_DEPTH || ++p->nodes > MAX_NODES || p->p == p->end) { p->failed = TRUE; return NULL; }
    Node *n = g_new0(Node, 1);
    char c = *p->p;
    if (c == '"') { n->kind = STRING; n->text = string(p); }
    else if (c == '{' || c == '[') {
        gboolean object = c == '{'; char end = object ? '}' : ']';
        n->kind = object ? OBJECT : ARRAY; p->p++;
        if (object) n->object = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, node_free);
        else n->array = g_ptr_array_new_with_free_func(node_free);
        space(p);
        if (p->p < p->end && *p->p == end) p->p++;
        else while (!p->failed) {
            char *key = NULL;
            if (object) {
                key = string(p);
                if (!key || !take(p, ':') || g_hash_table_contains(n->object, key)) { g_free(key); p->failed = TRUE; break; }
            }
            Node *child = value(p, depth + 1);
            if (!child) { g_free(key); break; }
            if (object) g_hash_table_insert(n->object, key, child);
            else g_ptr_array_add(n->array, child);
            space(p);
            if (p->p < p->end && *p->p == end) { p->p++; break; }
            if (!take(p, ',')) break;
        }
    } else if (c == '-' || g_ascii_isdigit(c)) {
        const char *start = p->p; n->kind = NUMBER;
        if (c == '-') p->p++;
        if (p->p == p->end || !g_ascii_isdigit(*p->p)) p->failed = TRUE;
        else if (*p->p == '0') p->p++;
        else while (p->p < p->end && g_ascii_isdigit(*p->p)) p->p++;
        if (p->p < p->end && *p->p == '.') {
            p->p++;
            if (p->p == p->end || !g_ascii_isdigit(*p->p)) p->failed = TRUE;
            while (p->p < p->end && g_ascii_isdigit(*p->p)) p->p++;
        }
        if (p->p < p->end && (*p->p == 'e' || *p->p == 'E')) {
            p->p++;
            if (p->p < p->end && (*p->p == '+' || *p->p == '-')) p->p++;
            if (p->p == p->end || !g_ascii_isdigit(*p->p)) p->failed = TRUE;
            while (p->p < p->end && g_ascii_isdigit(*p->p)) p->p++;
        }
        n->text = g_strndup(start, (gsize)(p->p - start));
    } else {
        const char *word = c == 't' ? "true" : c == 'f' ? "false" : "null";
        gsize length = strlen(word);
        if ((gsize)(p->end - p->p) < length || memcmp(p->p, word, length)) p->failed = TRUE;
        else { p->p += length; n->kind = c == 'n' ? NIL : BOOL; n->truth = c == 't'; }
    }
    if (p->failed) { node_free(n); return NULL; }
    return n;
}
static Node *get(Node *n, const char *key) { return n && n->kind == OBJECT ? g_hash_table_lookup(n->object, key) : NULL; }
static gboolean is(Node *n, const char *text) { return n && n->kind == STRING && !strcmp(n->text, text); }
static gboolean integer(Node *n, guint expected) { char *text = g_strdup_printf("%u", expected); gboolean same = n && n->kind == NUMBER && !strcmp(n->text, text); g_free(text); return same; }
static gboolean nonempty(Node *n) { return n && n->kind == STRING && n->text[0]; }
static gboolean false_value(Node *n) { return n && n->kind == BOOL && !n->truth; }
static gboolean name_valid(const char *s) {
    gsize len = strlen(s);
    if (!len || len > 128 || !(g_ascii_islower(*s) || g_ascii_isdigit(*s))) return FALSE;
    for (; *s; s++) if (!(g_ascii_islower(*s) || g_ascii_isdigit(*s) || strchr("+_.-", *s))) return FALSE;
    return TRUE;
}
static char *reason_text(const char *text) {
    GString *out = g_string_new(NULL); guint count = 0;
    for (const char *p = text; *p && count < 300; p = g_utf8_next_char(p), count++) {
        gunichar c = g_utf8_get_char(p);
        g_string_append_unichar(out, g_unichar_iscntrl(c) || g_unichar_iszerowidth(c) ? ' ' : c);
    }
    return g_string_free(out, FALSE);
}
static char *doctor(Node *root) {
    Node *checks = get(root, "checks"), *coverage = get(root, "coverage");
    if (!is(get(root, "tool"), "cachy-asahi-doctor") || !is(get(root, "scope"), "local observations only") ||
        !checks || checks->kind != ARRAY || checks->array->len > 512 || !coverage || coverage->kind != OBJECT || g_hash_table_size(coverage->object) != 3) return NULL;
    guint counts[3] = {0}; const char *states[] = {"checked", "unavailable", "unknown"};
    GHashTable *seen = g_hash_table_new(g_str_hash, g_str_equal); gboolean valid = TRUE;
    for (guint i = 0; i < checks->array->len && valid; i++) {
        Node *row = g_ptr_array_index(checks->array, i), *name = get(row, "check"), *note = get(row, "note");
        if (!nonempty(name) || !note || note->kind != STRING || !get(row, "value") || g_hash_table_contains(seen, name->text)) { valid = FALSE; break; }
        g_hash_table_add(seen, name->text); gboolean known = FALSE;
        for (guint j = 0; j < 3; j++) if (is(get(row, "state"), states[j])) { counts[j]++; known = TRUE; }
        valid = known;
    }
    g_hash_table_unref(seen);
    for (guint j = 0; j < 3; j++) if (!integer(get(coverage, states[j]), counts[j])) valid = FALSE;
    if (!valid) return NULL;
    return g_strdup_printf("%u observed, %u unavailable, %u unknown.", counts[0], counts[1], counts[2]);
}
static char *orphans(Node *root) {
    Node *candidates = get(root, "candidates"), *broken = get(root, "broken_dependencies"), *packages = get(root, "packages");
    if (!is(get(root, "scope"), "LOCAL_INSTALLED_METADATA_ONLY_NOT_PAYLOAD_RELEASE_REMOVAL_OR_HARDWARE_PROOF") || !false_value(get(root, "apply_supported")) ||
        !candidates || candidates->kind != ARRAY || candidates->array->len > 2048 || !broken || broken->kind != ARRAY || broken->array->len > 32768 ||
        !packages || packages->kind != OBJECT || g_hash_table_size(packages->object) > 2048) return NULL;
    GHashTable *seen = g_hash_table_new(g_str_hash, g_str_equal); gboolean valid = TRUE;
    for (guint i = 0; i < candidates->array->len && valid; i++) {
        Node *name = g_ptr_array_index(candidates->array, i);
        if (!nonempty(name) || !name_valid(name->text) || g_hash_table_contains(seen, name->text)) { valid = FALSE; break; }
        Node *flag = get(get(packages, name->text), "candidate");
        if (!flag || flag->kind != BOOL || !flag->truth) { valid = FALSE; break; }
        g_hash_table_add(seen, name->text);
    }
    GHashTableIter iter; gpointer key, data; g_hash_table_iter_init(&iter, packages->object);
    while (valid && g_hash_table_iter_next(&iter, &key, &data)) {
        Node *flag = get(data, "candidate");
        if (!name_valid(key) || !flag || flag->kind != BOOL || flag->truth != g_hash_table_contains(seen, key)) valid = FALSE;
    }
    g_hash_table_unref(seen);
    for (guint i = 0; i < broken->array->len && valid; i++) {
        Node *row = g_ptr_array_index(broken->array, i), *name = get(row, "package");
        if (!nonempty(name) || !get(packages, name->text) || !nonempty(get(row, "dependency"))) valid = FALSE;
    }
    if (!valid) return NULL;
    return g_strdup_printf("%u possible orphan%s; %u broken dependenc%s. Assessment only; packages remain installed.", candidates->array->len, candidates->array->len == 1 ? "" : "s", broken->array->len, broken->array->len == 1 ? "y" : "ies");
}
ManagementReport management_report_parse(ManagementTool tool, const char *text) {
    ManagementReport result = {MANAGEMENT_REPORT_INVALID, g_strdup("Report format is invalid or unsupported.")};
    if (!text || (tool != MANAGEMENT_DOCTOR && tool != MANAGEMENT_ORPHANS)) return result;
    gsize length = 0;
    while (length <= MAX_BYTES && text[length]) length++;
    if (!length || length > MAX_BYTES || !g_utf8_validate(text, (gssize)length, NULL)) return result;
    Parser p = {text, text + length, 0, FALSE}; Node *root = value(&p, 0); space(&p);
    if (!root || p.failed || p.p != p.end || root->kind != OBJECT) { node_free(root); return result; }
    char *summary = NULL;
    if (is(get(root, "verification"), "REFUSED")) {
        Node *reason = get(root, "reason");
        if (nonempty(reason)) { char *safe = reason_text(reason->text); summary = g_strdup_printf("Assessment refused: %s", safe); g_free(safe); result.state = MANAGEMENT_REPORT_REFUSED; }
    } else if (integer(get(root, "schema_version"), 1)) {
        summary = tool == MANAGEMENT_DOCTOR ? doctor(root) : orphans(root);
        if (summary) result.state = MANAGEMENT_REPORT_VALID;
    }
    if (summary) { g_free(result.summary); result.summary = summary; }
    node_free(root); return result;
}
void management_report_clear(ManagementReport *report) {
    if (report) { g_clear_pointer(&report->summary, g_free); report->state = MANAGEMENT_REPORT_INVALID; }
}
