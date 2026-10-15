/* SPDX-License-Identifier: MIT
 * Fixed offline development cases. No devices, files containing samples, UI,
 * installed-plugin scan, state restore, worker scheduler or acceptance claim.
 * The external caller owns isolation, file hashes and hard process deadlines.
 */
#define _GNU_SOURCE
#include <lilv/lilv.h>
#include <lv2/urid/urid.h>
#include <dlfcn.h>
#include <link.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BASE "http://lsp-plug.in/plugins/lv2/"
#define CORE "http://lv2plug.in/ns/lv2core#"
#define ATOM "http://lv2plug.in/ns/ext/atom#"
#define PORT_LIMIT 512
#define MAP_LIMIT 4096
#define URI_LIMIT 1024
#define FRAMES 256
#define BLOCKS 96
#define SETTLE 32
#define STIMULUS 32
#define TOTAL (FRAMES * BLOCKS)
#define GUARDS 4
#define CANARY 12345.25f
_Static_assert(sizeof(float) == 4 && FLT_RADIX == 2 && FLT_MANT_DIG == 24 && FLT_MAX_EXP == 128,
               "IEEE binary32 samples required");

typedef struct { const char *symbol; float value; } Setting;
typedef struct {
    const char *name, *uri;
    unsigned channels, count;
    const Setting *settings;
} Profile;
static const Setting loud0[] = {{"enabled",1}, {"input",1}, {"fft",2}, {"volume",0}};
static const Setting loud47[] = {{"enabled",1}, {"input",1}, {"fft",2}, {"volume",-47.5f}};
static const Setting multiband[] = {
    {"mode",0}, {"ce_0",1}, {"sla_0",5}, {"cr_0",1.75f}, {"al_0",.725f},
    {"at_0",1}, {"rt_0",100}, {"kn_0",.125f}, {"cbe_1",1}, {"sf_1",200},
    {"ce_1",0}, {"cbe_2",0}, {"ce_2",0}, {"cbe_3",0}, {"ce_3",0},
    {"cbe_4",0}, {"ce_4",0}, {"cbe_5",0}, {"ce_5",0}, {"cbe_6",0}, {"ce_6",0}
};
static const Setting compressor[] = {{"sla",5}, {"al",1}, {"at",1}, {"rt",100}, {"cr",15}, {"kn",.5f}};
static const Profile profiles[] = {
    {"volume-0", BASE "loud_comp_mono",1,4,loud0},
    {"volume-minus47_5", BASE "loud_comp_mono",1,4,loud47},
    {"asahi-woofer-band", BASE "mb_compressor_stereo",2,21,multiband},
    {"asahi-woofer-limiter", BASE "compressor_stereo",2,6,compressor}
};
static const unsigned rates[] = {44100,48000,88200,96000};
static const char *fixtures[] = {"zero", "bypass", "synthetic"};
static const char *failure;
static unsigned instance_count;
static FILE *json;
static bool bad(const char *name) { if (!failure) failure = name; return false; }

typedef struct {
    unsigned count;
    atomic_flag lock;
    atomic_bool overflow;
    char text[MAP_LIMIT][URI_LIMIT + 1];
} Map;
static LV2_URID map_uri(LV2_URID_Map_Handle handle, const char *uri)
{
    Map *map = handle;
    if (!uri || strnlen(uri, URI_LIMIT + 1) > URI_LIMIT) { map->overflow = true; return 0; }
    /* Offline callback: stable IDs even if a plugin-owned worker maps a URI.
       No hard-real-time feature is advertised. The process deadline is external. */
    while (atomic_flag_test_and_set_explicit(&map->lock, memory_order_acquire)) {}
    LV2_URID id = 0;
    for (unsigned i = 0; i < map->count; ++i)
        if (!strcmp(map->text[i], uri)) { id = i + 1; break; }
    if (!id) {
        if (map->count == MAP_LIMIT) map->overflow = true;
        else { strcpy(map->text[map->count++], uri); id = map->count; }
    }
    atomic_flag_clear_explicit(&map->lock, memory_order_release);
    return id;
}

static bool safe_symbol(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (!n || n > 64) return false;
    for (size_t i = 0; i < n; ++i)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') ||
              s[i] == '_' || (i && s[i] >= '0' && s[i] <= '9'))) return false;
    return true;
}

static bool numeric(const LilvNode *node, float *out)
{
    if (!node) return false;
    if (lilv_node_is_int(node)) *out = (float)lilv_node_as_int(node);
    else if (lilv_node_is_float(node)) *out = lilv_node_as_float(node);
    else return false;
    return isfinite(*out);
}

static bool within_bundle(const LilvNode *node, const char *bundle)
{
    char *host = NULL, *path = lilv_node_get_path(node, &host);
    char actual[PATH_MAX];
    bool ok = path && (!host || !*host || !strcmp(host, "localhost")) && realpath(path, actual);
    if (ok) ok = !strncmp(actual, bundle, strlen(bundle)) && actual[strlen(bundle)] == '/';
    lilv_free(path); lilv_free(host);
    return ok;
}

typedef struct {
    const LilvPort *rdf;
    const char *symbol;
    bool input, audio, control, atom;
    float guard_before[GUARDS], value, guard_after[GUARDS];
    float *allocation, *buffer;
} Port;

typedef struct {
    LilvWorld *world;
    LilvNode *input, *output, *audio, *control, *atom, *optional, *integer, *toggle, *enumeration, *sample_rate;
    LilvNode *buffer_type, *sequence;
} World;

static bool property(World *w, const LilvPlugin *plugin, const Port *p, const LilvNode *key)
{ (void)w; return lilv_port_has_property(plugin, p->rdf, key); }

static bool control_value(World *w, const LilvPlugin *plugin, const Port *p,
                          float value, unsigned rate, bool override)
{
    LilvNode *def = NULL, *min = NULL, *max = NULL;
    float lo = 0, hi = 0;
    lilv_port_get_range(plugin, p->rdf, &def, &min, &max);
    bool ok = isfinite(value), scaled = property(w, plugin, p, w->sample_rate);
    if (min) ok = ok && numeric(min, &lo) && value >= lo * (scaled ? rate : 1.0f);
    if (max) ok = ok && numeric(max, &hi) && value <= hi * (scaled ? rate : 1.0f);
    if (override && (!min || !max)) ok = false;
    if (property(w, plugin, p, w->integer)) ok = ok && fabsf(value - roundf(value)) <= 1e-6f;
    if (property(w, plugin, p, w->toggle)) ok = ok && (value == 0 || value == 1);
    if (property(w, plugin, p, w->enumeration)) {
        bool found = false;
        LilvScalePoints *points = lilv_port_get_scale_points(plugin, p->rdf);
        if (lilv_scale_points_size(points) > 512) ok = false;
        else LILV_FOREACH(scale_points, i, points) {
            float v;
            const LilvScalePoint *point = lilv_scale_points_get(points, i);
            if (numeric(lilv_scale_point_get_value(point), &v) && fabsf(v - value) <= 1e-6f) found = true;
        }
        ok = ok && found;
        lilv_scale_points_free(points);
    }
    lilv_node_free(def); lilv_node_free(min); lilv_node_free(max);
    return ok || bad("control-value-invalid");
}

static Port *find_port(Port *ports, unsigned count, const char *symbol)
{
    for (unsigned i = 0; i < count; ++i) if (!strcmp(ports[i].symbol, symbol)) return &ports[i];
    return NULL;
}

static bool prepare_ports(World *w, const LilvPlugin *plugin, const Profile *profile,
                          unsigned rate, unsigned fixture, Port *ports, unsigned n)
{
    unsigned ins = 0, outs = 0, atoms = 0;
    for (unsigned i = 0; i < n; ++i) {
        Port *p = &ports[i];
        p->rdf = lilv_plugin_get_port_by_index(plugin, i);
        if (!p->rdf || lilv_port_get_index(plugin, p->rdf) != i) return bad("port-index-invalid");
        p->symbol = lilv_node_as_string(lilv_port_get_symbol(plugin, p->rdf));
        if (!safe_symbol(p->symbol)) return bad("port-symbol-invalid");
        for (unsigned j = 0; j < i; ++j) if (!strcmp(p->symbol, ports[j].symbol)) return bad("duplicate-port-symbol");
        p->input = lilv_port_is_a(plugin, p->rdf, w->input);
        if (p->input == lilv_port_is_a(plugin, p->rdf, w->output)) return bad("port-direction-invalid");
        p->audio = lilv_port_is_a(plugin, p->rdf, w->audio);
        p->control = lilv_port_is_a(plugin, p->rdf, w->control);
        p->atom = lilv_port_is_a(plugin, p->rdf, w->atom);
        if ((unsigned)p->audio + p->control + p->atom != 1) return bad("unsupported-port-type");
        for (unsigned j = 0; j < GUARDS; ++j) p->guard_before[j] = p->guard_after[j] = CANARY;
        if (p->audio) {
            unsigned channel;
            if (profile->channels == 1) {
                if (strcmp(p->symbol, p->input ? "in" : "out")) return bad("audio-symbol-invalid");
                channel = 0;
            } else {
                if (!strcmp(p->symbol, p->input ? "in_l" : "out_l")) channel = 0;
                else if (!strcmp(p->symbol, p->input ? "in_r" : "out_r")) channel = 1;
                else return bad("audio-symbol-invalid");
            }
            (void)channel;
            if (p->input) ++ins; else ++outs;
            p->allocation = calloc(FRAMES + 2 * GUARDS, sizeof(float));
            if (!p->allocation) return bad("allocation-failed");
            p->buffer = p->allocation + GUARDS;
            for (unsigned j = 0; j < GUARDS; ++j) p->allocation[j] = p->buffer[FRAMES+j] = CANARY;
        } else if (p->control && p->input) {
            LilvNode *def = NULL, *min = NULL, *max = NULL;
            lilv_port_get_range(plugin, p->rdf, &def, &min, &max);
            bool ok = numeric(def, &p->value);
            if (property(w, plugin, p, w->sample_rate)) p->value *= rate;
            lilv_node_free(def); lilv_node_free(min); lilv_node_free(max);
            if (!ok || !control_value(w, plugin, p, p->value, rate, false)) return bad("control-default-invalid");
        } else if (p->atom) {
            LilvNode *type = lilv_port_get(plugin, p->rdf, w->buffer_type);
            bool ok = type && lilv_node_equals(type, w->sequence) && property(w, plugin, p, w->optional) &&
                !strcmp(p->symbol, p->input ? "in_ui" : "out_ui");
            lilv_node_free(type);
            if (!ok) return bad("unsupported-atom-port");
            ++atoms;
        }
    }
    if (ins != profile->channels || outs != profile->channels || atoms != 2) return bad("port-shape-invalid");
    for (unsigned i = 0; i < profile->count; ++i) {
        Port *p = find_port(ports, n, profile->settings[i].symbol);
        if (!p || !p->control || !p->input) return bad("profile-control-missing");
        if (!control_value(w, plugin, p, profile->settings[i].value, rate, true)) return false;
        p->value = profile->settings[i].value;
    }
    Port *enabled = find_port(ports, n, "enabled"), *latency = find_port(ports, n, "out_latency");
    if (!enabled || !enabled->control || !enabled->input || enabled->value != 1 ||
        !latency || !latency->control || latency->input) return bad("enabled-or-latency-invalid");
    if (fixture == 1) enabled->value = 0;
    if (profile->channels == 1) {
        Port *refer = find_port(ports, n, "refer");
        if (!refer || !refer->control || !refer->input || refer->value != 0) return bad("reference-generator-not-off");
    }
    return true;
}

/* Integer-generated bounded signal; no libc PRNG, files or captured audio. */
static float input_sample(unsigned frame, unsigned channel, unsigned fixture)
{
    if (!fixture || frame < SETTLE * FRAMES || frame >= (SETTLE + STIMULUS) * FRAMES) return 0;
    unsigned t = frame - SETTLE * FRAMES;
    if (!t) return channel ? -.0009f : .0009f;
    uint32_t word = (t + 1u) * UINT32_C(1664525) + (channel + 1u) * UINT32_C(1013904223);
    return ((int32_t)(word >> 16) - 32768) * (.0008f / 32768.0f);
}

typedef struct { double peak, rms, bypass_error; unsigned latency; uint64_t hash; } Metrics;
static uint64_t sample_hash(const float *samples, unsigned count)
{
    uint64_t h = UINT64_C(14695981039346656037);
    for (unsigned i = 0; i < count; ++i) {
        float v = samples[i] == 0 ? 0 : samples[i];
        uint32_t bits; memcpy(&bits, &v, sizeof(bits));
        for (unsigned j = 0; j < 4; ++j) { h ^= (bits >> (j * 8)) & 255; h *= UINT64_C(1099511628211); }
    }
    return h;
}

static bool run_instance(World *w, const LilvPlugin *plugin, const Profile *profile,
                         unsigned rate, unsigned fixture, float *output, Metrics *metrics)
{
    bool ok = false, active = false;
    unsigned n = lilv_plugin_get_num_ports(plugin);
    Port *ports = NULL;
    Map *map = NULL;
    LilvInstance *instance = NULL;
    float controls[PORT_LIMIT] = {0};
    if (!n || n > PORT_LIMIT) return bad("port-count-invalid");
    ports = calloc(n, sizeof(Port)); map = calloc(1, sizeof(Map));
    if (!ports || !map) { bad("allocation-failed"); goto done; }
    map->lock = (atomic_flag)ATOMIC_FLAG_INIT; atomic_init(&map->overflow, false);
    if (!prepare_ports(w, plugin, profile, rate, fixture, ports, n)) goto done;
    for (unsigned i = 0; i < n; ++i) controls[i] = ports[i].value;
    LV2_URID_Map mapper = {map, map_uri};
    LV2_Feature feature = {LV2_URID__map, &mapper};
    const LV2_Feature *features[] = {&feature, NULL};
    ++instance_count;
    instance = lilv_plugin_instantiate(plugin, rate, features);
    if (!instance || map->overflow) { bad("instantiation-or-urid-failed"); goto done; }
    for (unsigned i = 0; i < n; ++i)
        lilv_instance_connect_port(instance, i, ports[i].atom ? NULL : ports[i].audio ? ports[i].buffer : &ports[i].value);
    lilv_instance_activate(instance); active = true;
    Port *latency = find_port(ports, n, "out_latency");
    double energy = 0;
    for (unsigned block = 0; block < BLOCKS; ++block) {
        for (unsigned i = 0; i < n; ++i) if (ports[i].audio) {
            unsigned channel = profile->channels == 2 && strstr(ports[i].symbol, "_r") ? 1 : 0;
            for (unsigned j = 0; j < FRAMES; ++j)
                ports[i].buffer[j] = ports[i].input ? input_sample(block * FRAMES + j, channel, fixture) : NAN;
        }
        lilv_instance_run(instance, FRAMES);
        if (map->overflow) { bad("urid-overflow"); goto done; }
        for (unsigned i = 0; i < n; ++i) if (ports[i].control) {
            for (unsigned j = 0; j < GUARDS; ++j)
                if (ports[i].guard_before[j] != CANARY || ports[i].guard_after[j] != CANARY) {
                    bad("control-guard-changed"); goto done;
                }
            if (ports[i].input && ports[i].value != controls[i]) { bad("control-input-changed"); goto done; }
        }
        float delay = latency->value;
        if (!isfinite(delay) || delay < 0 || delay > 8192 || fabsf(delay - roundf(delay)) > .001f) {
            bad("latency-invalid"); goto done;
        }
        if (block == SETTLE) metrics->latency = (unsigned)roundf(delay);
        if (block >= SETTLE && (unsigned)roundf(delay) != metrics->latency) { bad("latency-unstable"); goto done; }
        for (unsigned i = 0; i < n; ++i) if (ports[i].audio) {
            Port *p = &ports[i];
            unsigned channel = profile->channels == 2 && strstr(p->symbol, "_r") ? 1 : 0;
            for (unsigned j = 0; j < GUARDS; ++j)
                if (p->allocation[j] != CANARY || p->buffer[FRAMES+j] != CANARY) { bad("buffer-guard-changed"); goto done; }
            for (unsigned j = 0; j < FRAMES; ++j) {
                unsigned frame = block * FRAMES + j;
                float value = p->buffer[j];
                if (p->input) {
                    if (value != input_sample(frame, channel, fixture)) { bad("audio-input-changed"); goto done; }
                } else {
                    if (!isfinite(value)) { bad("audio-output-nonfinite"); goto done; }
                    if (fixture == 2 && fabsf(value) > 16) { bad("audio-output-runaway"); goto done; }
                    output[channel * TOTAL + frame] = value;
                    if (block < SETTLE) continue;
                    metrics->peak = fmax(metrics->peak, fabs(value)); energy += (double)value * value;
                    if (fixture == 1) {
                        float expected = frame < metrics->latency ? 0 : input_sample(frame - metrics->latency, channel, fixture);
                        double error = fabs((double)value - expected);
                        metrics->bypass_error = fmax(metrics->bypass_error, error);
                        if (error > 1e-7 + 1e-5 * fabs(expected)) { bad("bypass-identity-failed"); goto done; }
                    }
                }
            }
        }
    }
    metrics->rms = sqrt(energy / (profile->channels * (BLOCKS - SETTLE) * FRAMES));
    if ((!fixture && metrics->peak > 1e-7) || (fixture == 2 && (metrics->peak > 16 || energy <= 1e-20))) {
        bad("silence-or-energy-gate-failed"); goto done;
    }
    metrics->hash = sample_hash(output, profile->channels * TOTAL);
    ok = true;
done:
    if (active) lilv_instance_deactivate(instance);
    lilv_instance_free(instance);
    if (map && map->overflow) ok = bad("urid-overflow");
    if (ports) for (unsigned i = 0; i < n; ++i) free(ports[i].allocation);
    free(ports); free(map);
    return ok;
}

static bool plugin_contract(World *w, const LilvPlugin *plugin, const char *bundle)
{
    (void)w;
    if (!within_bundle(lilv_plugin_get_library_uri(plugin), bundle)) return bad("library-outside-bundle");
    const LilvNodes *data = lilv_plugin_get_data_uris(plugin);
    if (lilv_nodes_size(data) > 512) return bad("metadata-file-count-invalid");
    LILV_FOREACH(nodes, i, data)
        if (!within_bundle(lilv_nodes_get(data, i), bundle)) return bad("metadata-outside-bundle");
    LilvNodes *features = lilv_plugin_get_required_features(plugin);
    bool have_map = false, ok = lilv_nodes_size(features) <= 32;
    LILV_FOREACH(nodes, i, features) {
        const char *uri = lilv_node_as_uri(lilv_nodes_get(features, i));
        if (!uri || strcmp(uri, LV2_URID__map)) ok = false;
        else have_map = true;
    }
    lilv_nodes_free(features);
    return (ok && have_map) || bad("required-feature-unsupported");
}

/* Build bounded selected metadata privately before committing any JSON field. */
static bool metadata(World *w, const char *bundle)
{
    char *data = NULL;
    size_t size = 0;
    FILE *stream = open_memstream(&data, &size);
    if (!stream) return bad("allocation-failed");
    bool ok = true;
    unsigned selection[] = {0,2,3};
    fprintf(stream,"\"control_binding_count\":31,\"plugins\":[");
    for (unsigned k = 0; k < 3 && ok; ++k) {
        const Profile *profile = &profiles[selection[k]];
        LilvNode *uri = lilv_new_uri(w->world, profile->uri);
        const LilvPlugin *plugin = lilv_plugins_get_by_uri(lilv_world_get_all_plugins(w->world), uri);
        lilv_node_free(uri);
        unsigned n = plugin ? lilv_plugin_get_num_ports(plugin) : 0;
        if (!plugin || !n || n > PORT_LIMIT || !plugin_contract(w,plugin,bundle)) {
            ok = bad("selected-plugin-invalid"); break;
        }
        Port *ports = calloc(n,sizeof(Port));
        if (!ports) { ok = bad("allocation-failed"); break; }
        ok = prepare_ports(w,plugin,profile,44100,0,ports,n);
        if (ok) {
            fprintf(stream,"%s{\"uri\":\"%s\",\"port_count\":%u,\"required_features\":[\"%s\"],"
                "\"audio_inputs\":%s,\"audio_outputs\":%s,\"optional_null_atoms\":[\"in_ui\",\"out_ui\"],\"controls\":[",
                k ? "," : "",profile->uri,n,LV2_URID__map,
                profile->channels == 1 ? "[\"in\"]" : "[\"in_l\",\"in_r\"]",
                profile->channels == 1 ? "[\"out\"]" : "[\"out_l\",\"out_r\"]");
            for (unsigned i = 0; i < profile->count && ok; ++i) {
                Port *p = find_port(ports,n,profile->settings[i].symbol);
                LilvNode *def = NULL, *min = NULL, *max = NULL;
                float d = 0, lo = 0, hi = 0;
                lilv_port_get_range(plugin,p->rdf,&def,&min,&max);
                ok = numeric(def,&d) && numeric(min,&lo) && numeric(max,&hi) && !property(w,plugin,p,w->sample_rate);
                lilv_node_free(def); lilv_node_free(min); lilv_node_free(max);
                if (!ok) { bad("binding-metadata-invalid"); break; }
                fprintf(stream,"%s{\"symbol\":\"%s\",\"index\":%u,\"default\":%.9g,\"minimum\":%.9g,\"maximum\":%.9g,"
                    "\"integer\":%s,\"toggled\":%s,\"enum_values\":[", i ? "," : "",p->symbol,
                    lilv_port_get_index(plugin,p->rdf),(double)d,(double)lo,(double)hi,
                    property(w,plugin,p,w->integer) ? "true" : "false",property(w,plugin,p,w->toggle) ? "true" : "false");
                if (property(w,plugin,p,w->enumeration)) {
                    LilvScalePoints *points = lilv_port_get_scale_points(plugin,p->rdf);
                    unsigned count = 0;
                    if (lilv_scale_points_size(points) > 512) ok = bad("enum-count-invalid");
                    else LILV_FOREACH(scale_points,j,points) {
                        float v;
                        if (!numeric(lilv_scale_point_get_value(lilv_scale_points_get(points,j)),&v)) {
                            ok = bad("enum-value-invalid"); break;
                        }
                        fprintf(stream,"%s%.9g",count++ ? "," : "",(double)v);
                    }
                    lilv_scale_points_free(points);
                }
                fprintf(stream,"]}");
            }
            fprintf(stream,"]}");
        }
        for (unsigned i = 0; i < n; ++i) free(ports[i].allocation);
        free(ports);
    }
    fprintf(stream,"],");
    if (fclose(stream)) ok = bad("metadata-write-failed");
    if (ok && size > 32768) ok = bad("metadata-size-invalid");
    if (ok) fwrite(data,1,size,json);
    free(data);
    return ok;
}

static bool processing(const char *argument)
{
    char bundle[PATH_MAX], slash[PATH_MAX];
    struct stat st;
    bool ok = false;
    unsigned cases = 0;
    World w = {0};
    float *first = NULL, *second = NULL;
    if (!realpath(argument, bundle) || stat(bundle, &st) || !S_ISDIR(st.st_mode) ||
        snprintf(slash, sizeof(slash), "%s/", bundle) >= (int)sizeof(slash)) return bad("bundle-path-invalid");
    w.world = lilv_world_new();
    if (!w.world) return bad("world-allocation-failed");
    LilvNode *disabled = lilv_new_bool(w.world, false), *search = lilv_new_string(w.world, "");
    LilvNode *location = lilv_new_file_uri(w.world, NULL, slash);
    lilv_world_set_option(w.world, LILV_OPTION_DYN_MANIFEST, disabled);
    lilv_world_set_option(w.world, LILV_OPTION_LV2_PATH, search);
    lilv_world_load_bundle(w.world, location);
    lilv_node_free(disabled); lilv_node_free(search); lilv_node_free(location);
#define NODE(field, uri) do { w.field = lilv_new_uri(w.world, uri); if (!w.field) { bad("node-allocation-failed"); goto done; } } while (0)
    NODE(input, CORE "InputPort"); NODE(output, CORE "OutputPort"); NODE(audio, CORE "AudioPort");
    NODE(control, CORE "ControlPort"); NODE(atom, ATOM "AtomPort"); NODE(optional, CORE "connectionOptional");
    NODE(integer, CORE "integer"); NODE(toggle, CORE "toggled"); NODE(enumeration, CORE "enumeration");
    NODE(sample_rate, CORE "sampleRate"); NODE(buffer_type, ATOM "bufferType"); NODE(sequence, ATOM "Sequence");
#undef NODE
    first = calloc(2 * TOTAL, sizeof(float)); second = calloc(2 * TOTAL, sizeof(float));
    if (!first || !second) { bad("allocation-failed"); goto done; }
    if (!metadata(&w,bundle)) goto done;
    fprintf(json, "\"cases\":[");
    for (unsigned p = 0; p < 4; ++p) {
        LilvNode *uri = lilv_new_uri(w.world, profiles[p].uri);
        const LilvPlugin *plugin = lilv_plugins_get_by_uri(lilv_world_get_all_plugins(w.world), uri);
        lilv_node_free(uri);
        if (!plugin || !plugin_contract(&w, plugin, bundle)) { bad("selected-plugin-invalid"); goto cases_done; }
        for (unsigned r = 0; r < 4; ++r) for (unsigned f = 0; f < 3; ++f) {
            Metrics a = {0}, b = {0}; double repeat = 0;
            bool pass = run_instance(&w, plugin, &profiles[p], rates[r], f, first, &a) &&
                        run_instance(&w, plugin, &profiles[p], rates[r], f, second, &b);
            if (pass && a.latency != b.latency) pass = bad("repeat-latency-differs");
            if (pass) for (unsigned i = 0; i < profiles[p].channels * TOTAL; ++i) {
                double error = fabs((double)first[i] - second[i]); repeat = fmax(repeat, error);
                if (error > 1e-6 + 1e-5 * fabs(first[i])) { pass = bad("repeat-output-differs"); break; }
            }
            fprintf(json, "%s{\"profile\":\"%s\",\"uri\":\"%s\",\"rate_hz\":%u,\"fixture\":\"%s\","
                "\"status\":\"%s\",\"latency_frames\":%u,\"peak\":%.17g,\"rms\":%.17g,"
                "\"max_bypass_error\":%.17g,\"max_repeat_error\":%.17g,\"sample_count_per_channel\":%u,"
                "\"sample_fnv1a64\":[\"%016llx\",\"%016llx\"]}",
                cases ? "," : "", profiles[p].name, profiles[p].uri, rates[r], fixtures[f], pass ? "PASS" : "FAIL",
                a.latency, fmax(a.peak,b.peak), fmax(a.rms,b.rms), fmax(a.bypass_error,b.bypass_error), repeat,
                TOTAL, (unsigned long long)a.hash, (unsigned long long)b.hash);
            ++cases;
            if (!pass) goto cases_done;
        }
    }
    ok = cases == 48 && instance_count == 96;
cases_done:
    fprintf(json, "],\"case_count\":%u,\"instance_count\":%u,", cases, instance_count);
done:
    free(first); free(second);
#define FREE(field) lilv_node_free(w.field)
    FREE(input); FREE(output); FREE(audio); FREE(control); FREE(atom); FREE(optional); FREE(integer);
    FREE(toggle); FREE(enumeration); FREE(sample_rate); FREE(buffer_type); FREE(sequence);
#undef FREE
    lilv_world_free(w.world);
    return ok;
}

static bool basename_safe(const char *s)
{
    if (!*s || strlen(s) > 255) return false;
    for (; *s; ++s) if (!( (*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
        (*s >= '0' && *s <= '9') || strchr("._+-", *s))) return false;
    return true;
}

/* Loader paths are private observations; Python normalizes/hashes before export. */
static void private_path(const char *path)
{
    if (!path) { fprintf(json,"null"); return; }
    fputc('"',json);
    for (const unsigned char *p = (const unsigned char *)path; *p; ++p) {
        if (*p == '"' || *p == '\\') fprintf(json,"\\%c",*p);
        else if (*p < 32) fprintf(json,"\\u%04x",*p);
        else fputc(*p,json);
    }
    fputc('"',json);
}

static bool loader(const char *argument)
{
    char expected[PATH_MAX], origin[PATH_MAX];
    struct stat st; bool ok = false, selected[3] = {false,false,false};
    if (!realpath(argument, expected) || stat(expected, &st) || !S_ISREG(st.st_mode)) return bad("library-path-invalid");
    void *handle = dlopen(expected, RTLD_NOW | RTLD_LOCAL);
    if (!handle) return bad("dlopen-failed");
    dlerror();
    const LV2_Descriptor *(*descriptor)(uint32_t) = NULL;
    void *symbol = dlsym(handle, "lv2_descriptor");
    if (dlerror() || !symbol) { bad("descriptor-symbol-missing"); goto done; }
    memcpy(&descriptor, &symbol, sizeof(descriptor));
    Dl_info info;
    if (!dladdr(symbol, &info) || !info.dli_fname || !realpath(info.dli_fname, origin) || strcmp(expected,origin)) {
        bad("descriptor-origin-differs"); goto done;
    }
    unsigned count;
    for (count = 0; count < 512; ++count) {
        const LV2_Descriptor *d = descriptor(count);
        if (!d) break;
        if (!d->URI || strnlen(d->URI,URI_LIMIT+1) > URI_LIMIT) { bad("descriptor-uri-invalid"); goto done; }
        const char *wanted[] = {BASE "loud_comp_mono",BASE "mb_compressor_stereo",BASE "compressor_stereo"};
        for (unsigned j = 0; j < 3; ++j) if (!strcmp(d->URI,wanted[j])) {
            if (selected[j]) { bad("descriptor-uri-duplicate"); goto done; }
            selected[j] = true;
        }
    }
    if (count == 512 || !selected[0] || !selected[1] || !selected[2]) { bad("descriptor-set-invalid"); goto done; }
    struct link_map *map;
    if (dlinfo(handle,RTLD_DI_LINKMAP,&map) || !map) { bad("link-map-unavailable"); goto done; }
    for (unsigned i = 0; map->l_prev; ++i) {
        if (i == 128) { bad("link-map-limit"); goto done; } map = map->l_prev;
    }
    char names[128][256], paths[128][PATH_MAX]; unsigned n = 0;
    for (; map; map = map->l_next) {
        if (!map->l_name || !*map->l_name) continue;
        const char *name = strrchr(map->l_name,'/'); name = name ? name+1 : map->l_name;
        if (n == 128 || !basename_safe(name)) { bad("link-map-name-invalid"); goto done; }
        strcpy(names[n],name);
        paths[n][0] = '\0';
        if (strcmp(name,"linux-vdso.so.1") && !realpath(map->l_name,paths[n])) {
            bad("link-map-path-invalid"); goto done;
        }
        ++n;
    }
    fprintf(json,"\"descriptor_count\":%u,\"selected_uris\":[\"%sloud_comp_mono\",\"%smb_compressor_stereo\",\"%scompressor_stereo\"],\"loaded_basenames\":[",count,BASE,BASE,BASE);
    for (unsigned i = 0; i < n; ++i) fprintf(json,"%s\"%s\"",i ? "," : "",names[i]);
    fprintf(json,"],\"loaded_paths\":[");
    for (unsigned i = 0; i < n; ++i) {
        if (i) fputc(',',json);
        private_path(paths[i][0] ? paths[i] : NULL);
    }
    fprintf(json,"],");
    ok = true;
done:
    if (dlclose(handle)) ok = bad("dlclose-failed");
    return ok;
}

int main(int argc, char **argv)
{
    /* Preserve a result channel before plugin constructors/callbacks can print. */
    int fd = dup(STDOUT_FILENO);
    if (fd < 0 || dup2(STDERR_FILENO,STDOUT_FILENO) < 0 || !(json = fdopen(fd,"w"))) return 2;
    bool valid = argc == 3 && (!strcmp(argv[1],"--bundle") || !strcmp(argv[1],"--loader"));
    const char *mode = valid && !strcmp(argv[1],"--loader") ? "loader" : "processing";
    fprintf(json,"{\"schema_version\":1,\"mode\":\"%s\",",mode);
    bool pass = valid ? (!strcmp(mode,"loader") ? loader(argv[2]) : processing(argv[2])) : bad("cli-invalid");
    fprintf(json,"\"status\":\"%s\",\"failure_class\":",pass ? "PASS" : "FAIL");
    if (failure) fprintf(json,"\"%s\"",failure); else fprintf(json,"null");
    fprintf(json,",\"audio_devices\":\"NOT USED\",\"hardware\":\"NOT RUN\",\"optimization_acceptance\":\"NOT RUN\"}\n");
    int error = fflush(json); fclose(json);
    return pass && !error ? 0 : 1;
}
