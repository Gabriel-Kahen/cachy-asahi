/* SPDX-License-Identifier: MIT
 * Fixed individual Rust LV2 cases from PLAN.md. External caller owns hashes,
 * isolation and deadlines. No device, installed scan, UI or sample export.
 */
#define _GNU_SOURCE
#include <lilv/lilv.h>
#include <dlfcn.h>
#include <link.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CORE "http://lv2plug.in/ns/lv2core#"
#define BANK "https://chadmed.au/bankstown"
#define TRI "https://chadmed.au/triforce"
#define PORT_LIMIT 512
#define URI_LIMIT 1024
#define FRAMES 256
#define SETTLE 32
#define STIMULUS 32
#define GUARDS 4
#define CANARY 12345.25f
#define PI 3.14159265358979323846
_Static_assert(sizeof(float) == 4 && FLT_RADIX == 2 && FLT_MANT_DIG == 24 && FLT_MAX_EXP == 128,
               "IEEE binary32 samples required");

typedef struct { const char *symbol; float def, lo, hi; bool toggled; } Control;
typedef struct {
    const char *uri, *bundle;
    unsigned inputs, outputs, blocks;
    const char *audio[4];
    Control controls[8];
} Spec;
static const Spec specs[] = {
    {BANK,"bankstown.lv2",2,2,96,{"in_l","in_r","out_l","out_r"}, {
        {"bypass",0,0,1,true},{"amt",1,0,15,false},{"floor",20,10,250,false},
        {"ceil",200,10,250,false},{"final_hp",200,10,250,false},
        {"sat_second",1,0,15,false},{"sat_third",1,0,15,false},{"blend",.5f,0,1,false}}},
    {TRI,"triforce.lv2",3,1,128,{"in_1","in_2","in_3","out"}, {
        {"h_angle",0,0,360,false},{"v_angle",0,0,360,false},{"opt_freq",2000,20,20000,false},
        {"t_win",100,100,3500,false},{"mic2_x",.02f,0,1,false},{"mic2_y",.02f,0,1,false},
        {"mic3_x",.02f,0,1,false},{"mic3_y",.02f,0,1,false}}}
};
typedef struct { const char *name; unsigned spec; float values[8]; } Profile;
static const Profile profiles[] = {
    {"j413",0,{0,1.2f,140,220,200,1.05f,1.3f,1}},
    {"j415",0,{0,1.65f,20,200,200,1.75f,1.85f,1}},
    {"asahi-microphone",1,{80,0,1100,500,.02f,0,.01f,.0173f}}
};
static const unsigned rates[] = {44100,48000,88200,96000};
static const char *bank_fixtures[] = {"zero","bypass","amount-zero","configured",
    "channel-exchange","sign-reversal","wet-amount-scaling"};
static const char *tri_fixtures[] = {"zero","common-mode-dc","common-mode-quarter-wave","unequal"};
static const char *failure;
static FILE *json;
static unsigned instance_count;
static bool bad(const char *name) { if (!failure) failure = name; return false; }
static unsigned frames(const Spec *s) { return s->blocks * FRAMES; }
static const char *pair_role(const Profile *p, unsigned fixture)
{ return p->spec || fixture < 4 ? "repeat" : bank_fixtures[fixture]; }

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
    char *host = NULL, *path = node ? lilv_node_get_path(node,&host) : NULL;
    char actual[PATH_MAX];
    bool ok = path && (!host || !*host || !strcmp(host,"localhost")) && realpath(path,actual);
    if (ok) ok = !strncmp(actual,bundle,strlen(bundle)) && actual[strlen(bundle)] == '/';
    lilv_free(path); lilv_free(host);
    return ok;
}
typedef struct {
    LilvWorld *world;
    LilvNode *input, *output, *audio, *control, *integer, *toggle, *enumeration, *sample_rate;
    LilvNode *atom, *optional, *logarithmic, *strict_bounds;
} World;
typedef struct {
    const LilvPort *rdf;
    bool input, audio;
    unsigned channel;
    float guard_before[GUARDS], value, guard_after[GUARDS];
    float *allocation, *buffer;
} Port;

static bool control_metadata(World *w, const LilvPlugin *plugin, const Port *p, const Spec *s, unsigned index)
{
    const Control *c=&s->controls[index];
    bool logarithmic=s==&specs[0] ? index>=2 && index<=4 : index==2;
    bool strict=s==&specs[1] || logarithmic;
    LilvNode *def = NULL, *min = NULL, *max = NULL;
    float d=0, lo=0, hi=0;
    lilv_port_get_range(plugin,p->rdf,&def,&min,&max);
    bool ok = numeric(def,&d) && numeric(min,&lo) && numeric(max,&hi) &&
        d == c->def && lo == c->lo && hi == c->hi &&
        !lilv_port_has_property(plugin,p->rdf,w->integer) &&
        lilv_port_has_property(plugin,p->rdf,w->toggle) == c->toggled &&
        !lilv_port_has_property(plugin,p->rdf,w->enumeration) &&
        !lilv_port_has_property(plugin,p->rdf,w->sample_rate) &&
        lilv_port_has_property(plugin,p->rdf,w->logarithmic) == logarithmic &&
        lilv_port_has_property(plugin,p->rdf,w->strict_bounds) == strict;
    lilv_node_free(def); lilv_node_free(min); lilv_node_free(max);
    return ok || bad("control-metadata-invalid");
}
static bool control_valid(const Control *c, float value)
{
    return (isfinite(value) && value >= c->lo && value <= c->hi &&
        (!c->toggled || value == 0 || value == 1)) || bad("control-value-invalid");
}
static bool prepare_ports(World *w, const LilvPlugin *plugin, const Profile *profile,
                          unsigned fixture, unsigned role, Port *ports)
{
    const Spec *s = &specs[profile->spec];
    if (lilv_plugin_get_num_ports(plugin) != 12) return bad("port-count-invalid");
    for (unsigned i=0; i<12; ++i) {
        Port *p = &ports[i];
        p->rdf = lilv_plugin_get_port_by_index(plugin,i);
        if (!p->rdf || lilv_port_get_index(plugin,p->rdf) != i) return bad("port-index-invalid");
        const LilvNode *symbol = lilv_port_get_symbol(plugin,p->rdf);
        const char *text = symbol ? lilv_node_as_string(symbol) : NULL;
        const char *expected = i < 4 ? s->audio[i] : s->controls[i-4].symbol;
        if (!text || strcmp(text,expected)) return bad("port-symbol-invalid");
        p->audio = i < 4; p->input = i < s->inputs || i >= 4;
        if (lilv_port_is_a(plugin,p->rdf,w->input) != p->input ||
            lilv_port_is_a(plugin,p->rdf,w->output) == p->input ||
            lilv_port_is_a(plugin,p->rdf,w->audio) != p->audio ||
            lilv_port_is_a(plugin,p->rdf,w->control) == p->audio ||
            lilv_port_is_a(plugin,p->rdf,w->atom) ||
            lilv_port_has_property(plugin,p->rdf,w->optional)) return bad("port-shape-invalid");
        for (unsigned g=0; g<GUARDS; ++g) p->guard_before[g]=p->guard_after[g]=CANARY;
        if (p->audio) {
            p->channel = p->input ? i : i-s->inputs;
            p->allocation = calloc(FRAMES+2*GUARDS,sizeof(float));
            if (!p->allocation) return bad("allocation-failed");
            p->buffer = p->allocation+GUARDS;
            for (unsigned g=0; g<GUARDS; ++g) p->allocation[g]=p->buffer[FRAMES+g]=CANARY;
        } else {
            const Control *c = &s->controls[i-4];
            if (!control_metadata(w,plugin,p,s,i-4)) return false;
            p->value = c->def;
            /* J413 final_hp is a retained default, not an explicit graph write. */
            if (!(profile == &profiles[0] && i == 8)) p->value = profile->values[i-4];
            if (!profile->spec && fixture == 1 && i == 4) p->value = 1;
            if (!profile->spec && fixture == 2 && i == 5) p->value = 0;
            if (!profile->spec && fixture == 6 && role && i == 5) p->value *= 2;
            if (!control_valid(c,p->value)) return false;
        }
    }
    return true;
}

/* Bounded reproducible synthetic input, including a declared 180Hz tone. */
static float active_sample(unsigned frame, unsigned channel, unsigned rate)
{
    uint32_t word = (frame+1u)*UINT32_C(1664525)+(channel+1u)*UINT32_C(1013904223);
    double noise = ((int32_t)(word>>16)-32768)*(.015/32768.0);
    return (float)(.04*sin(2*PI*180*frame/rate+.7*channel)+noise);
}
static float input_sample(const Profile *p, unsigned rate, unsigned fixture,
                           unsigned role, unsigned frame, unsigned channel)
{
    if (!fixture) return 0;
    if (p->spec) {
        if (fixture == 1) return .0625f;
        if (fixture == 2) { const float quarter[] = {.0625f,0,-.0625f,0}; return quarter[frame%4]; }
        return active_sample(frame,channel,rate);
    }
    if (frame < SETTLE*FRAMES || frame >= (SETTLE+STIMULUS)*FRAMES) return 0;
    unsigned t = frame-SETTLE*FRAMES;
    if (fixture == 6) return (float)(.0625*sin(2*PI*180*t/rate+.7*channel));
    if (fixture == 4) return channel == role ? active_sample(t,0,rate) : 0;
    float value = active_sample(t,channel,rate);
    return fixture == 5 && role ? -value : value;
}

typedef struct { double peak, rms, energy; uint64_t hash; } Metrics;
static bool output_valid(float value, unsigned spec)
{
    if (!isfinite(value)) return bad("audio-output-nonfinite");
    return fabsf(value)<=(spec ? 10 : 16) || bad("audio-output-runaway");
}
static uint64_t sample_hash(const float *samples, unsigned count)
{
    uint64_t h = UINT64_C(14695981039346656037);
    for (unsigned i=0; i<count; ++i) {
        float v = samples[i] == 0 ? 0 : samples[i];
        uint32_t bits; memcpy(&bits,&v,sizeof(bits));
        for (unsigned j=0; j<4; ++j) { h ^= (bits>>(j*8))&255; h *= UINT64_C(1099511628211); }
    }
    return h;
}
static bool run_instance(World *w, const LilvPlugin *plugin, const Profile *profile,
                         unsigned rate, unsigned fixture, unsigned role, float *output, Metrics *m)
{
    const Spec *s = &specs[profile->spec];
    bool ok=false, active=false;
    Port ports[12] = {0}; float controls[12] = {0};
    LilvInstance *instance = NULL;
    if (!prepare_ports(w,plugin,profile,fixture,role,ports)) goto done;
    for (unsigned i=0; i<12; ++i) controls[i]=ports[i].value;
    LV2_Feature marker = {CORE "inPlaceBroken",NULL};
    const LV2_Feature *features[] = {&marker,NULL};
    ++instance_count;
    instance = lilv_plugin_instantiate(plugin,rate,features);
    if (!instance) { bad("instantiation-failed"); goto done; }
    for (unsigned i=0; i<12; ++i)
        lilv_instance_connect_port(instance,i,ports[i].audio ? ports[i].buffer : &ports[i].value);
    lilv_instance_activate(instance); active=true;
    for (unsigned block=0; block<s->blocks; ++block) {
        for (unsigned i=0; i<4; ++i) for (unsigned j=0; j<FRAMES; ++j)
            ports[i].buffer[j] = ports[i].input ? input_sample(profile,rate,fixture,role,block*FRAMES+j,ports[i].channel) : NAN;
        lilv_instance_run(instance,FRAMES);
        for (unsigned i=0; i<12; ++i) {
            Port *p=&ports[i];
            for (unsigned g=0; g<GUARDS; ++g)
                if (p->guard_before[g]!=CANARY || p->guard_after[g]!=CANARY ||
                    (p->audio && (p->allocation[g]!=CANARY || p->buffer[FRAMES+g]!=CANARY))) {
                    bad("port-guard-changed"); goto done;
                }
            if (!p->audio) {
                if (p->value != controls[i]) { bad("control-input-changed"); goto done; }
                continue;
            }
            for (unsigned j=0; j<FRAMES; ++j) {
                unsigned frame=block*FRAMES+j;
                float value=p->buffer[j];
                if (p->input) {
                    if (value != input_sample(profile,rate,fixture,role,frame,p->channel)) { bad("audio-input-changed"); goto done; }
                } else {
                    if (!output_valid(value,profile->spec)) goto done;
                    output[p->channel*frames(s)+frame]=value;
                    m->peak=fmax(m->peak,fabs(value));
                    if (profile->spec || block>=SETTLE) m->energy+=(double)value*value;
                }
            }
        }
    }
    m->rms=sqrt(m->energy/(s->outputs*(s->blocks-(profile->spec ? 0 : SETTLE))*FRAMES));
    m->hash=sample_hash(output,s->outputs*frames(s));
    ok=true;
done:
    if (active) lilv_instance_deactivate(instance);
    lilv_instance_free(instance);
    for (unsigned i=0; i<12; ++i) free(ports[i].allocation);
    return ok;
}

/* Pure numerical gates: no FFT/filter/SVD code is shared with these oracles. */
static bool compare_pair(const Profile *p, unsigned rate, unsigned fixture,
                          const float *first, const float *second, const Metrics *a, const Metrics *b,
                          double *oracle, double *repeat, double *wet, double wet_rms[2])
{
    const Spec *s=&specs[p->spec]; unsigned total=frames(s);
    bool repeats=p->spec || fixture<4;
    if (!fixture && fmax(a->peak,b->peak)>1e-7) return bad("silence-gate-failed");
    if ((p->spec ? fixture==3 : fixture>=3) && (a->energy<=1e-20 || b->energy<=1e-20))
        return bad("nonzero-energy-gate-failed");
    for (unsigned c=0; c<s->outputs; ++c) for (unsigned t=0; t<total; ++t) {
        double x=input_sample(p,rate,fixture,0,t,c), one=first[c*total+t], two=second[c*total+t];
        double expected=one, tolerance=1e-6+1e-5*fabs(one);
        if (repeats) {
            double error=fabs(two-one); *repeat=fmax(*repeat,error);
            if (error>tolerance) return bad("repeat-output-differs");
        }
        if ((!p->spec && (fixture==1 || fixture==2)) || (p->spec && (fixture==1 || fixture==2))) {
            double abs_tol=p->spec ? 1e-4 : 1e-7, rel_tol=p->spec ? 1e-3 : 1e-5;
            double error=fmax(fabs(one-x),fabs(two-x)); *oracle=fmax(*oracle,error);
            if (error>abs_tol+rel_tol*fabs(x)) return bad("direct-oracle-failed");
        } else if (!p->spec && fixture==4) {
            if (c) continue;
            if (fabs(first[total+t])>1e-7 || fabs(second[t])>1e-7) return bad("channel-isolation-failed");
            two=second[total+t];
            double error=fabs(two-one); *oracle=fmax(*oracle,error);
            if (error>tolerance) return bad("channel-exchange-failed");
        } else if (!p->spec && fixture==5) {
            expected=-one;
            double error=fabs(two-expected); *oracle=fmax(*oracle,error);
            if (error>1e-6+1e-5*fabs(expected)) return bad("sign-reversal-failed");
        } else if (!p->spec && fixture==6) {
            expected=x+2*(one-x); *wet+=(one-x)*(one-x);
            if (t>=SETTLE*FRAMES && t<(SETTLE+STIMULUS)*FRAMES) wet_rms[c]+=(one-x)*(one-x);
            double error=fabs(two-expected); *oracle=fmax(*oracle,error);
            if (error>1e-6+1e-5*fabs(expected)) return bad("wet-amount-scaling-failed");
        }
    }
    if (!p->spec && fixture==6) for (unsigned c=0; c<2; ++c) {
        wet_rms[c]=sqrt(wet_rms[c]/(STIMULUS*FRAMES));
    }
    if (!p->spec && fixture==6 && (wet_rms[0]<1e-4 || wet_rms[1]<1e-4)) return bad("wet-rms-gate-failed");
    return true;
}

static bool plugin_contract(World *w, const LilvPlugin *plugin, const char *bundle)
{
    (void)w;
    if (lilv_plugin_get_num_ports(plugin)!=12 || !within_bundle(lilv_plugin_get_library_uri(plugin),bundle))
        return bad("library-or-port-count-invalid");
    const LilvNodes *data=lilv_plugin_get_data_uris(plugin);
    if (!lilv_nodes_size(data) || lilv_nodes_size(data)>PORT_LIMIT) return bad("metadata-file-count-invalid");
    LILV_FOREACH(nodes,i,data) if (!within_bundle(lilv_nodes_get(data,i),bundle)) return bad("metadata-outside-bundle");
    LilvNodes *required=lilv_plugin_get_required_features(plugin);
    bool ok=lilv_nodes_size(required)==1;
    LILV_FOREACH(nodes,i,required) {
        const char *uri=lilv_node_as_uri(lilv_nodes_get(required,i));
        if (!uri || strcmp(uri,CORE "inPlaceBroken")) ok=false;
    }
    lilv_nodes_free(required);
    return ok || bad("required-feature-unsupported");
}
static const LilvPlugin *lookup(World *w, unsigned spec)
{
    LilvNode *uri=lilv_new_uri(w->world,specs[spec].uri);
    const LilvPlugin *plugin=uri ? lilv_plugins_get_by_uri(lilv_world_get_all_plugins(w->world),uri) : NULL;
    lilv_node_free(uri); return plugin;
}
static bool metadata(World *w, char bundles[2][PATH_MAX])
{
    char *data=NULL; size_t size=0; FILE *stream=open_memstream(&data,&size);
    if (!stream) return bad("allocation-failed");
    bool ok=true;
    fprintf(stream,"\"control_binding_count\":16,\"plugins\":[");
    for (unsigned k=0; k<2 && ok; ++k) {
        const Spec *s=&specs[k]; const Profile *profile=&profiles[k ? 2 : 0];
        const LilvPlugin *plugin=lookup(w,k); Port ports[12]={0};
        ok=plugin && plugin_contract(w,plugin,bundles[k]) && prepare_ports(w,plugin,profile,0,0,ports);
        if (!ok) bad("selected-plugin-invalid");
        if (ok) {
            fprintf(stream,"%s{\"uri\":\"%s\",\"port_count\":12,\"required_features\":[\"%s\"],\"audio_inputs\":[",k ? "," : "",s->uri,CORE "inPlaceBroken");
            for (unsigned i=0; i<s->inputs; ++i) fprintf(stream,"%s\"%s\"",i ? "," : "",s->audio[i]);
            fprintf(stream,"],\"audio_outputs\":[");
            for (unsigned i=0; i<s->outputs; ++i) fprintf(stream,"%s\"%s\"",i ? "," : "",s->audio[s->inputs+i]);
            fprintf(stream,"],\"controls\":[");
            for (unsigned i=0; i<8; ++i) {
                const Control *c=&s->controls[i];
                fprintf(stream,"%s{\"symbol\":\"%s\",\"index\":%u,\"default\":%.9g,\"minimum\":%.9g,\"maximum\":%.9g,\"integer\":false,\"toggled\":%s,\"enum_values\":[]}",
                    i ? "," : "",c->symbol,i+4,(double)c->def,(double)c->lo,(double)c->hi,c->toggled ? "true" : "false");
            }
            fprintf(stream,"]}");
        }
        for (unsigned i=0; i<12; ++i) free(ports[i].allocation);
    }
    fprintf(stream,"],");
    if (fclose(stream)) ok=bad("metadata-write-failed");
    if (size>32768) ok=bad("metadata-size-invalid");
    if (ok && fwrite(data,1,size,json)!=size) ok=bad("metadata-write-failed");
    free(data); return ok;
}
static bool processing(const char *argument)
{
    char parent[PATH_MAX], bundles[2][PATH_MAX]; struct stat st;
    World w={0}; bool ok=false; unsigned cases=0; float *first=NULL,*second=NULL;
    if (!realpath(argument,parent) || stat(parent,&st) || !S_ISDIR(st.st_mode)) return bad("bundle-parent-invalid");
    w.world=lilv_world_new(); if (!w.world) return bad("world-allocation-failed");
    LilvNode *disabled=lilv_new_bool(w.world,false), *search=lilv_new_string(w.world,"");
    if (!disabled || !search) { lilv_node_free(disabled); lilv_node_free(search); bad("node-allocation-failed"); goto done; }
    lilv_world_set_option(w.world,LILV_OPTION_DYN_MANIFEST,disabled);
    lilv_world_set_option(w.world,LILV_OPTION_LV2_PATH,search);
    lilv_node_free(disabled); lilv_node_free(search);
    for (unsigned k=0; k<2; ++k) {
        char path[PATH_MAX],slash[PATH_MAX];
        if (snprintf(path,sizeof(path),"%s/%s",parent,specs[k].bundle)>=(int)sizeof(path) ||
            !realpath(path,bundles[k]) || strcmp(path,bundles[k]) || stat(path,&st) || !S_ISDIR(st.st_mode) ||
            snprintf(slash,sizeof(slash),"%s/",bundles[k])>=(int)sizeof(slash)) { bad("bundle-path-invalid"); goto done; }
        LilvNode *location=lilv_new_file_uri(w.world,NULL,slash);
        if (!location) { bad("node-allocation-failed"); goto done; }
        lilv_world_load_bundle(w.world,location); lilv_node_free(location);
    }
#define NODE(field, uri) do { w.field=lilv_new_uri(w.world,uri); if (!w.field) { bad("node-allocation-failed"); goto done; } } while (0)
    NODE(input,CORE "InputPort"); NODE(output,CORE "OutputPort"); NODE(audio,CORE "AudioPort");
    NODE(control,CORE "ControlPort"); NODE(integer,CORE "integer"); NODE(toggle,CORE "toggled");
    NODE(enumeration,CORE "enumeration"); NODE(sample_rate,CORE "sampleRate");
    NODE(atom,"http://lv2plug.in/ns/ext/atom#AtomPort"); NODE(optional,CORE "connectionOptional");
    NODE(logarithmic,"http://lv2plug.in/ns/ext/port-props#logarithmic");
    NODE(strict_bounds,"http://lv2plug.in/ns/ext/port-props#hasStrictBounds");
#undef NODE
    if (lilv_plugins_size(lilv_world_get_all_plugins(w.world))!=2) { bad("plugin-set-invalid"); goto done; }
    first=calloc(2*128*FRAMES,sizeof(float)); second=calloc(2*128*FRAMES,sizeof(float));
    if (!first || !second) { bad("allocation-failed"); goto done; }
    if (!metadata(&w,bundles)) goto done;
    fprintf(json,"\"cases\":[");
    for (unsigned p=0; p<3; ++p) {
        const Profile *profile=&profiles[p]; const Spec *s=&specs[profile->spec];
        const LilvPlugin *plugin=lookup(&w,profile->spec);
        if (!plugin || !plugin_contract(&w,plugin,bundles[profile->spec])) { bad("selected-plugin-invalid"); goto cases_done; }
        unsigned nr=profile->spec ? 1 : 4, nf=profile->spec ? 4 : 7;
        for (unsigned r=0; r<nr; ++r) for (unsigned f=0; f<nf; ++f) {
            unsigned rate=profile->spec ? 48000 : rates[r]; Metrics a={0},b={0}; double oracle=0,repeat=0,wet=0,wet_rms[2]={0};
            bool pass=run_instance(&w,plugin,profile,rate,f,0,first,&a) &&
                run_instance(&w,plugin,profile,rate,f,1,second,&b) &&
                compare_pair(profile,rate,f,first,second,&a,&b,&oracle,&repeat,&wet,wet_rms);
            fprintf(json,"%s{\"profile\":\"%s\",\"uri\":\"%s\",\"rate_hz\":%u,\"fixture\":\"%s\",\"pair_role\":\"%s\","
                "\"frames_per_instance\":%u,\"latency_frames\":null,\"peak\":%.17g,\"rms\":%.17g,\"max_oracle_error\":%.17g,\"max_repeat_error\":",
                cases ? "," : "",profile->name,s->uri,rate,profile->spec ? tri_fixtures[f] : bank_fixtures[f],pair_role(profile,f),frames(s),
                fmax(a.peak,b.peak),fmax(a.rms,b.rms),oracle);
            if (profile->spec || f<4) fprintf(json,"%.17g",repeat); else fprintf(json,"null");
            fprintf(json,",\"wet_energy\":%.17g,\"wet_rms\":[%.17g,%.17g],\"sample_fnv1a64\":[\"%016llx\",\"%016llx\"],\"status\":\"%s\"}",
                wet,wet_rms[0],wet_rms[1],(unsigned long long)a.hash,(unsigned long long)b.hash,pass ? "PASS" : "FAIL");
            ++cases; if (!pass) goto cases_done;
        }
    }
    ok=cases==60 && instance_count==120;
cases_done:
    fprintf(json,"],\"case_count\":%u,\"instance_count\":%u,",cases,instance_count);
done:
    free(first); free(second);
#define FREE(field) lilv_node_free(w.field)
    FREE(input); FREE(output); FREE(audio); FREE(control); FREE(integer); FREE(toggle); FREE(enumeration); FREE(sample_rate);
    FREE(atom); FREE(optional); FREE(logarithmic); FREE(strict_bounds);
#undef FREE
    lilv_world_free(w.world); return ok;
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

static bool loader(const char *argument, const char *wanted)
{
    char expected[PATH_MAX], origin[PATH_MAX];
    struct stat st; bool ok = false, selected = false;
    if (strcmp(wanted, BANK) && strcmp(wanted, TRI)) return bad("loader-uri-invalid");
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
        if (strcmp(d->URI,wanted) || selected) { bad("descriptor-set-invalid"); goto done; }
        selected = true;
    }
    if (count != 1 || !selected) { bad("descriptor-set-invalid"); goto done; }
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
    fprintf(json,"\"descriptor_count\":%u,\"selected_uris\":[\"%s\"],\"loaded_basenames\":[",count,wanted);
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
    int fd=dup(STDOUT_FILENO);
    if (fd<0 || dup2(STDERR_FILENO,STDOUT_FILENO)<0 || !(json=fdopen(fd,"w"))) return 2;
    bool process=argc==3 && !strcmp(argv[1],"--bundle");
    bool load=argc==5 && !strcmp(argv[1],"--loader") && !strcmp(argv[3],"--uri");
    fprintf(json,"{\"schema_version\":1,\"mode\":\"%s\",",load ? "loader" : "processing");
    bool pass=load ? loader(argv[2],argv[4]) : process ? processing(argv[2]) : bad("cli-invalid");
    fprintf(json,"\"status\":\"%s\",\"failure_class\":",pass ? "PASS" : "FAIL");
    if (failure) fprintf(json,"\"%s\"",failure); else fprintf(json,"null");
    fprintf(json,",\"audio_devices\":\"NOT USED\",\"hardware\":\"NOT RUN\",\"optimization_acceptance\":\"NOT RUN\"}\n");
    int error=fflush(json); fclose(json); return pass && !error ? 0 : 1;
}
