/* Four literal Asahi graphs: metadata, load, activation and retirement only.
 * No sample processing. Caller verifies every immutable input file before exec.
 * SPA AudioPlugin ABI below: PipeWire 8fa27cab, audio-plugin.h (MIT, Wim Taymans).
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <link.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <lilv/lilv.h>
#include <serd/serd.h>
#include <pipewire/pipewire.h>
#include <pipewire/loop.h>
#include <spa/filter-graph/filter-graph.h>
#include <spa/support/plugin-loader.h>
#include <spa/support/log.h>
#include <spa/utils/json.h>
#include <spa/pod/parser.h>
#include <spa/pod/iter.h>
#include <spa/param/props.h>

#define ROOT "/candidate/lv2"
#define CORE "http://lv2plug.in/ns/lv2core#"
#define RDF "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
#define RDFS "http://www.w3.org/2000/01/rdf-schema#"
#define URID "http://lv2plug.in/ns/ext/urid#"
#define MAX_NODES 16
#define MAX_PORTS 400
#define MAX_KEYS 400
#define AUDIO 8u
#define CONTROL 4u
#define INPUT 1u
#define OUTPUT 2u

struct fga_port { uint32_t index; const char *name; uint64_t flags, hint; float def, min, max; };
struct fga_plugin { struct spa_interface iface; };
struct fga_desc {
    const char *name; uint64_t flags; void (*free)(const struct fga_desc *);
    uint32_t n_ports; struct fga_port *ports;
};
struct fga_plugin_methods { uint32_t version; const struct fga_desc *(*make_desc)(void *, const char *); };
#define FGA_IFACE SPA_TYPE_INFO_INTERFACE_BASE "FilterGraph:AudioPlugin"

struct span { const char *p; int n; };
struct kv { char key[128]; struct span value; };
struct scalar { char name[128]; float value; };
struct port { char name[128]; unsigned flags, value_type; float def, min, max, wanted; bool seen, explicit; };
struct node {
    char name[64], type[16], uri[256], label[64];
    struct scalar controls[64]; unsigned n_controls;
    struct port ports[MAX_PORTS]; unsigned n_ports;
    struct span config; char fir[4][PATH_MAX];
    bool metadata, observed;
};
struct retained_handle { struct spa_handle *handle; bool live; };
struct run {
    const char *case_id, *expect, *failure;
    unsigned n_nodes, n_lv2, n_builtin, n_convolvers, n_links, n_controls, n_readbacks;
    unsigned want_nodes, want_lv2, want_builtin, want_convolvers, want_links, want_inputs, want_outputs;
    struct node nodes[MAX_NODES]; struct span graph;
    struct span inputs, outputs, links, volumes;
    bool full_input, unique_keys, metadata, ports, controls, volume_gate, activation;
    bool stages, fir_gate, library_gate, readback, retired;
    bool deactivated, graph_unloaded, children_unloaded, loop_destroyed;
    bool fir_unavailable, observer_bad, entered, initialized, check_current, current_info;
    struct { char node[64], path[PATH_MAX]; unsigned rate; } firs[8]; unsigned n_firs;
    char libs[128][PATH_MAX]; unsigned n_libs;
    char dsp[3][PATH_MAX]; bool used_dsp[3];
    struct retained_handle children[16]; unsigned n_children;
    struct spa_support support[40]; unsigned n_support;
    struct spa_plugin_loader loader; struct spa_log log;
    struct pw_loop *loop; struct spa_handle *graph_handle;
    struct spa_filter_graph *engine; LilvWorld *world;
    struct node *current;
};

static bool fail(struct run *r, const char *kind) { if (!r->failure) r->failure=kind; return false; }
static bool copystr(char *dst, size_t cap, const char *src) {
    size_t n=strlen(src); if (n>=cap) return false; memcpy(dst,src,n+1); return true;
}
static bool regular(const char *path) {
    struct stat st; return lstat(path,&st)==0 && S_ISREG(st.st_mode) && st.st_size>0 && st.st_size<=32*1024*1024;
}
static bool contained(const char *path, const char *root) {
    size_t n=strlen(root); return !strncmp(path,root,n) && path[n]=='/';
}
static bool decode(struct span s, char *out, size_t n) {
    return s.p && s.n>0 && spa_json_parse_stringn(s.p,s.n,out,(int)n)>0;
}
static bool number(struct span s, float *out) {
    return s.p && spa_json_parse_float(s.p,s.n,out)>0 && isfinite(*out);
}
/* These helpers only traverse SPA's existing tokenizer; no replacement grammar. */
static int object(struct span s, struct kv *out, unsigned cap) {
    struct spa_json it; const char *v; int n; unsigned count=0;
    if (!s.p || spa_json_begin_object(&it,s.p,(size_t)s.n)<=0) return -1;
    while (true) {
        char key[128]; n=spa_json_get_string(&it,key,sizeof(key));
        if (n<=0) return n<0 ? -1 : (int)count;
        if (count==cap || !copystr(out[count].key,sizeof(out[count].key),key)) return -1;
        n=spa_json_next(&it,&v); if (n<=0) return -1;
        if (spa_json_is_container(v,n)) n=spa_json_container_len(&it,v,n);
        if (n<=0) return -1;
        out[count++].value=(struct span){v,n};
    }
}
static struct span member(struct span s, const char *key) {
    struct kv pairs[MAX_KEYS]; int n=object(s,pairs,MAX_KEYS);
    for (int i=0;i<n;i++) if (!strcmp(pairs[i].key,key)) return pairs[i].value;
    return (struct span){0};
}
static int array(struct span s, struct span *out, unsigned cap) {
    struct spa_json it; const char *v; int n; unsigned count=0;
    if (!s.p || spa_json_begin_array(&it,s.p,(size_t)s.n)<=0) return -1;
    while ((n=spa_json_next(&it,&v))>0) {
        if (count==cap) return -1;
        if (spa_json_is_container(v,n)) n=spa_json_container_len(&it,v,n);
        if (n<=0) return -1;
        out[count++]=(struct span){v,n};
    }
    return n<0 ? -1 : (int)count;
}
static bool unique(struct run *r, struct span s, unsigned depth) {
    if (depth>16) return fail(r,"syntax");
    if (s.p[0]=='{') {
        struct kv pairs[MAX_KEYS]; int n=object(s,pairs,MAX_KEYS);
        if (n<0) return fail(r,"syntax");
        for (int i=0;i<n;i++) {
            for (int j=0;j<i;j++) if (!strcmp(pairs[i].key,pairs[j].key)) return fail(r,"duplicate");
            if (spa_json_is_container(pairs[i].value.p,pairs[i].value.n) && !unique(r,pairs[i].value,depth+1)) return false;
        }
    } else if (s.p[0]=='[') {
        struct span vals[MAX_KEYS]; int n=array(s,vals,MAX_KEYS);
        if (n<0) return fail(r,"syntax");
        for (int i=0;i<n;i++) if (spa_json_is_container(vals[i].p,vals[i].n) && !unique(r,vals[i],depth+1)) return false;
    }
    return true;
}
static struct node *node_named(struct run *r, const char *name) {
    for (unsigned i=0;i<r->n_nodes;i++) if (!strcmp(r->nodes[i].name,name)) return &r->nodes[i];
    return NULL;
}
static struct port *port_named(struct node *node, const char *name, unsigned flags) {
    for (unsigned i=0;i<node->n_ports;i++) if (!strcmp(node->ports[i].name,name) &&
        (node->ports[i].flags&flags)==flags) return &node->ports[i];
    return NULL;
}
static bool overrides(struct run *r, struct node *node) {
    for (unsigned i=0;i<node->n_controls;i++) {
        struct port *p=port_named(node,node->controls[i].name,INPUT|CONTROL);
        float v=node->controls[i].value;
        if (!p || v<p->min || v>p->max) return fail(r,"control");
        p->wanted=v; p->explicit=true;
    }
    return true;
}
static bool load_input(struct run *r, const char *path, char **storage) {
    if (!regular(path)) return fail(r,"input");
    FILE *f=fopen(path,"rb"); if (!f) return fail(r,"input");
    char *b=calloc(1,65537); if (!b) { fclose(f); return fail(r,"input"); }
    size_t n=fread(b,1,65537,f); bool ok=!ferror(f); int close_result=fclose(f);
    ok=ok && close_result==0 && n>0 && n<=65536 && !memchr(b,0,n);
    if (!ok) { free(b); return fail(r,"input"); }
    *storage=b;
    struct spa_json it; const char *v; int len=spa_json_begin(&it,b,n,&v);
    if (len<=0 || *v!='{') return fail(r,"syntax");
    const char *start=v; int total=spa_json_container_len(&it,v,len);
    if (total<=0) return fail(r,"syntax");
    len=spa_json_next(&it,&v);
    if (len<0) return fail(r,"syntax");
    if (len!=0) return fail(r,"trailing");
    r->full_input=true;
    struct span root={start,total}; if (!unique(r,root,0)) return false;
    r->unique_keys=true; r->graph=member(root,"filter.graph");
    struct span ns[MAX_NODES]; int count=array(member(r->graph,"nodes"),ns,MAX_NODES);
    if (count!=(int)r->want_nodes) return fail(r,"metadata");
    for (int i=0;i<count;i++) {
        struct node *node=&r->nodes[r->n_nodes++];
        if (!decode(member(ns[i],"name"),node->name,sizeof(node->name)) || !node->name[0] ||
            !decode(member(ns[i],"type"),node->type,sizeof(node->type))) return fail(r,"metadata");
        for (int j=0;j<i;j++) if (!strcmp(r->nodes[j].name,node->name)) return fail(r,"duplicate");
        if (!strcmp(node->type,"lv2")) {
            if (!decode(member(ns[i],"plugin"),node->uri,sizeof(node->uri))) return fail(r,"missing_uri");
            r->n_lv2++;
        } else if (!strcmp(node->type,"builtin")) {
            if (!decode(member(ns[i],"label"),node->label,sizeof(node->label))) return fail(r,"metadata");
            if (strcmp(node->label,"mixer") && strcmp(node->label,"convolver") && strcmp(node->label,"copy") && strcmp(node->label,"bq_highpass")) return fail(r,"metadata");
            r->n_builtin++; if (!strcmp(node->label,"convolver")) r->n_convolvers++;
        } else return fail(r,"metadata");
        struct span cs=member(ns[i],"control"); struct kv pairs[64]; int nc=cs.p ? object(cs,pairs,64) : 0;
        if (nc<0) return fail(r,"control");
        for (int j=0;j<nc;j++) {
            struct scalar *c=&node->controls[node->n_controls++];
            if (!copystr(c->name,sizeof(c->name),pairs[j].key) || !number(pairs[j].value,&c->value)) return fail(r,"control");
        }
        node->config=member(ns[i],"config");
        if (!strcmp(node->label,"convolver")) {
            struct span fs[4]; int nf=array(member(node->config,"filename"),fs,4);
            if (nf!=4) return fail(r,"metadata");
            for (int j=0;j<4;j++) if (!decode(fs[j],node->fir[j],sizeof(node->fir[j])) ||
                (!contained(node->fir[j],"/usr/share/asahi-audio") && !contained(node->fir[j],"/tmp/offline"))) return fail(r,"metadata");
        }
    }
    if (r->n_lv2!=r->want_lv2 || r->n_builtin!=r->want_builtin || r->n_convolvers!=r->want_convolvers) return fail(r,"metadata");
    r->inputs=member(r->graph,"inputs"); r->outputs=member(r->graph,"outputs");
    r->links=member(r->graph,"links"); r->volumes=member(r->graph,"capture.volumes");
    return true;
}

struct rdf_check { struct run *r; SerdEnv *env; const char *bundle; };
static SerdStatus rdf_base(void *h,const SerdNode *uri) { return serd_env_set_base_uri(((struct rdf_check*)h)->env,uri); }
static SerdStatus rdf_prefix(void *h,const SerdNode *name,const SerdNode *uri) { return serd_env_set_prefix(((struct rdf_check*)h)->env,name,uri); }
static SerdStatus rdf_statement(void *h,SerdStatementFlags flags,const SerdNode *graph,
        const SerdNode *subject,const SerdNode *predicate,const SerdNode *value,
        const SerdNode *datatype,const SerdNode *lang) {
    (void)flags; (void)graph; (void)datatype; (void)lang;
    struct rdf_check *c=h; SerdNode p=serd_env_expand_node(c->env,predicate), o=SERD_NODE_NULL;
    const SerdNode *terms[5]={subject,predicate,value,graph,datatype};
    for (unsigned i=0;i<5;i++) if (terms[i] && (terms[i]->type==SERD_URI || terms[i]->type==SERD_CURIE)) {
        SerdNode x=serd_env_expand_node(c->env,terms[i]);
        static const char dyn[]="http://lv2plug.in/ns/ext/dynmanifest";
        bool bad=x.buf && !strncmp((const char*)x.buf,dyn,sizeof(dyn)-1);
        serd_node_free(&x); if (bad) { serd_node_free(&p); fail(c->r,"metadata"); return SERD_ERR_BAD_ARG; }
    }
    if (p.buf && (!strcmp((const char*)p.buf,RDFS "seeAlso") || !strcmp((const char*)p.buf,CORE "binary"))) {
        o=serd_env_expand_node(c->env,value);
        uint8_t *host=NULL, *path=o.buf ? serd_file_uri_parse(o.buf,&host) : NULL;
        char canonical[PATH_MAX];
        bool ok=path && (!host || !host[0]) && realpath((const char*)path,canonical) &&
            contained(canonical,c->bundle) && regular(canonical);
        serd_free(host); serd_free(path); serd_node_free(&o);
        if (!ok) { serd_node_free(&p); fail(c->r,"metadata"); return SERD_ERR_BAD_ARG; }
    }
    serd_node_free(&p); return SERD_SUCCESS;
}
static bool rdf_bundle(struct run *r,const char *path) {
    DIR *d=opendir(path); if (!d) return fail(r,"metadata");
    struct dirent *de; unsigned count=0; bool ok=true;
    while ((de=readdir(d))) {
        if (!strcmp(de->d_name,".") || !strcmp(de->d_name,"..")) continue;
        if (++count>512) { ok=fail(r,"metadata"); break; }
        char file[PATH_MAX]; int n=snprintf(file,sizeof(file),"%s/%s",path,de->d_name);
        if (n<0 || n>=(int)sizeof(file) || !regular(file)) { ok=fail(r,"metadata"); break; }
        size_t len=strlen(file); if (len<4 || strcmp(file+len-4,".ttl")) continue;
        SerdNode uri=serd_node_new_file_uri((const uint8_t*)file,NULL,NULL,false);
        SerdEnv *env=serd_env_new(&uri); struct rdf_check c={r,env,path};
        SerdReader *reader=serd_reader_new(SERD_TURTLE,&c,NULL,rdf_base,rdf_prefix,rdf_statement,NULL);
        if (reader) serd_reader_set_strict(reader,true);
        if (!env || !reader || serd_reader_read_file(reader,uri.buf)!=SERD_SUCCESS) ok=fail(r,"metadata");
        if (reader) serd_reader_free(reader);
        if (env) serd_env_free(env);
        serd_node_free(&uri);
        if (!ok) break;
    }
    closedir(d); return ok;
}
static const char *const uris[]={"https://chadmed.au/bankstown","https://chadmed.au/triforce",
    "http://lsp-plug.in/plugins/lv2/loud_comp_mono","http://lsp-plug.in/plugins/lv2/mb_compressor_stereo",
    "http://lsp-plug.in/plugins/lv2/compressor_stereo"};
static int uri_index(const char *uri) { for (unsigned i=0;i<5;i++) if (!strcmp(uri,uris[i])) return (int)i; return -1; }
static bool is_a(LilvWorld *world,const LilvPlugin *p,const LilvPort *port,const char *uri) {
    LilvNode *n=lilv_new_uri(world,uri); bool result=lilv_port_is_a(p,port,n); lilv_node_free(n); return result;
}
static bool lv2_preflight(struct run *r) {
    static const char *const bundles[]={ROOT "/bankstown.lv2/",ROOT "/triforce.lv2/",ROOT "/lsp-plugins.lv2/"};
    static const char *const dsp_names[]={ROOT "/bankstown.lv2/bankstown.so",ROOT "/triforce.lv2/triforce.so",ROOT "/lsp-plugins.lv2/lsp-plugins-lv2.so"};
    r->world=lilv_world_new(); if (!r->world) return fail(r,"metadata");
    LilvNode *no=lilv_new_bool(r->world,false); lilv_world_set_option(r->world,LILV_OPTION_DYN_MANIFEST,no); lilv_node_free(no);
    for (unsigned i=0;i<3;i++) {
        char path[PATH_MAX]; if (!realpath(bundles[i],path) || !rdf_bundle(r,path)) return fail(r,"metadata");
        LilvNode *uri=lilv_new_file_uri(r->world,NULL,bundles[i]); lilv_world_load_bundle(r->world,uri); lilv_node_free(uri);
        if (!realpath(dsp_names[i],r->dsp[i])) return fail(r,"metadata");
    }
    const LilvPlugins *plugins=lilv_world_get_all_plugins(r->world);
    for (unsigned ni=0;ni<r->n_nodes;ni++) {
        struct node *node=&r->nodes[ni]; if (strcmp(node->type,"lv2")) continue;
        int idx=uri_index(node->uri); if (idx<0) return fail(r,"missing_uri");
        LilvNode *uri=lilv_new_uri(r->world,node->uri); const LilvPlugin *p=lilv_plugins_get_by_uri(plugins,uri); lilv_node_free(uri);
        if (!p) return fail(r,"missing_uri");
        unsigned lib=idx<2 ? (unsigned)idx : 2u;
        char *path=lilv_file_uri_parse(lilv_node_as_uri(lilv_plugin_get_library_uri(p)),NULL), canonical[PATH_MAX];
        bool origin=path && realpath(path,canonical) && !strcmp(canonical,r->dsp[lib]); lilv_free(path);
        if (!origin) return fail(r,"metadata");
        r->used_dsp[lib]=true;
        LilvNodes *features=lilv_plugin_get_required_features(p); bool feature=false, feature_ok=lilv_nodes_size(features)==1;
        LILV_FOREACH(nodes,j,features) {
            const char *s=lilv_node_as_uri(lilv_nodes_get(features,j));
            feature=s && !strcmp(s,idx<2 ? CORE "inPlaceBroken" : URID "map"); feature_ok &= feature;
        }
        lilv_nodes_free(features); if (!feature_ok) return fail(r,"metadata");
        unsigned np=lilv_plugin_get_num_ports(p), want=idx<2 ? 12u : idx==2 ? 23u : idx==3 ? 319u : 68u;
        if (np!=want || np>MAX_PORTS) return fail(r,"metadata");
        float defaults[MAX_PORTS], mins[MAX_PORTS], maxs[MAX_PORTS];
        lilv_plugin_get_port_ranges_float(p,mins,maxs,defaults);
        unsigned atoms=0;
        for (unsigned j=0;j<np;j++) {
            const LilvPort *lp=lilv_plugin_get_port_by_index(p,j); struct port *fp=&node->ports[node->n_ports++];
            const LilvNode *symbol=lilv_port_get_symbol(p,lp);
            if (!symbol || !copystr(fp->name,sizeof(fp->name),lilv_node_as_string(symbol))) return fail(r,"metadata");
            bool in=is_a(r->world,p,lp,CORE "InputPort"), out=is_a(r->world,p,lp,CORE "OutputPort");
            bool audio=is_a(r->world,p,lp,CORE "AudioPort"), ctl=is_a(r->world,p,lp,CORE "ControlPort");
            bool atom=is_a(r->world,p,lp,"http://lv2plug.in/ns/ext/atom#AtomPort");
            if (in==out || (unsigned)audio+ctl+atom!=1) return fail(r,"metadata");
            fp->flags=(in ? INPUT : OUTPUT) | (audio ? AUDIO : ctl ? CONTROL : 0u);
            if (atom) {
                LilvNode *opt=lilv_new_uri(r->world,CORE "connectionOptional");
                bool allowed=idx>=2 && lilv_port_has_property(p,lp,opt) && !strcmp(fp->name,in ? "in_ui" : "out_ui");
                lilv_node_free(opt); if (!allowed) return fail(r,"metadata"); atoms++;
            }
            if (ctl && in) {
                if (!isfinite(defaults[j]) || !isfinite(mins[j]) || !isfinite(maxs[j]) || defaults[j]<mins[j] || defaults[j]>maxs[j]) return fail(r,"metadata");
                fp->def=fp->wanted=defaults[j]; fp->min=mins[j]; fp->max=maxs[j]; r->n_controls++;
            }
        }
        if (atoms!=(idx<2 ? 0u : 2u) || !overrides(r,node)) return fail(r,"metadata");
        node->metadata=true;
    }
    return true;
}

static void observe(struct run *r,const char *file,const char *func,const char *fmt,va_list args) {
    char line[PATH_MAX+512]; int len=vsnprintf(line,sizeof(line),fmt,args);
    if (len<0 || len>=(int)sizeof(line)) { r->observer_bad=true; return; }
    const char *base=strrchr(file ? file : "",'/'); base=base ? base+1 : file;
    if (base && !strcmp(base,"filter-graph.c") && func && !strcmp(func,"impl_activate") &&
        !strncmp(line,"instantiate ",12)) {
        char plugin[256],name[64]; int index; unsigned long rate;
        if (sscanf(line,"instantiate %255s %63[^[][%d] rate:%lu",plugin,name,&index,&rate)!=4 || index!=0 || rate!=48000) { r->observer_bad=true; return; }
        struct node *node=node_named(r,name); if (!node || node->observed) { r->observer_bad=true; return; }
        if (strcmp(plugin,!strcmp(node->type,"lv2") ? node->uri : node->label)) { r->observer_bad=true; return; }
        node->observed=true; r->current=node;
    }
    if (base && !strcmp(base,"plugin_builtin.c") && func && !strcmp(func,"read_closest")) {
        if (!strncmp(line,"Can't open any sample file",26)) r->fir_unavailable=true;
        if (!strncmp(line,"loading best rate:",18)) {
            if (!r->current || strcmp(r->current->label,"convolver") || r->n_firs>=8) { r->observer_bad=true; return; }
            unsigned i=r->n_firs++;
            if (sscanf(line,"loading best rate:%u %4095s",&r->firs[i].rate,r->firs[i].path)!=2 ||
                !copystr(r->firs[i].node,sizeof(r->firs[i].node),r->current->name)) r->observer_bad=true;
        }
    }
}
static void logv(void *h,enum spa_log_level level,const char *file,int line,const char *func,const char *fmt,va_list ap) {
    (void)level; (void)line; observe(h,file,func,fmt,ap);
}
static void logf0(void *h,enum spa_log_level level,const char *file,int line,const char *func,const char *fmt,...) {
    va_list ap; va_start(ap,fmt); logv(h,level,file,line,func,fmt,ap); va_end(ap);
}
static const struct spa_log_methods log_methods={.version=0,.log=logf0,.logv=logv};

static bool builtin_metadata(struct run *r,struct spa_handle *handle) {
    struct fga_plugin *plugin=NULL;
    if (spa_handle_get_interface(handle,FGA_IFACE,(void**)&plugin)<0) return fail(r,"metadata");
    for (unsigned i=0;i<r->n_nodes;i++) {
        struct node *node=&r->nodes[i]; if (strcmp(node->type,"builtin") || node->metadata) continue;
        const struct fga_desc *d=spa_api_method_r(const struct fga_desc *,NULL,fga_plugin,&plugin->iface,make_desc,0,node->label);
        if (!d || d->n_ports>MAX_PORTS) return fail(r,"metadata");
        for (unsigned j=0;j<d->n_ports;j++) {
            struct port *p=&node->ports[node->n_ports++]; const struct fga_port *fp=&d->ports[j];
            if (!copystr(p->name,sizeof(p->name),fp->name)) return fail(r,"metadata");
            p->flags=(unsigned)fp->flags;
            p->value_type=(fp->hint&1u) ? 1u : (fp->hint&4u) ? 2u : 0u;
            float scale=(fp->hint&2u) ? 48000.0f : 1.0f;
            p->def=p->wanted=fp->def*scale; p->min=fp->min*scale; p->max=fp->max*scale;
            if ((p->flags&(INPUT|CONTROL))==(INPUT|CONTROL)) {
                if (!isfinite(p->def) || !isfinite(p->min) || !isfinite(p->max) || p->def<p->min || p->def>p->max) return fail(r,"metadata");
                r->n_controls++;
            }
        }
        if (!overrides(r,node)) return false;
        node->metadata=true; if (d->free) d->free(d);
    }
    return true;
}
static bool port_gate(struct run *r);
static struct spa_handle *loader_load(void *object,const char *factory,const struct spa_dict *info) {
    struct run *r=object; const char *lib=spa_dict_lookup(info,SPA_KEY_LIBRARY_NAME), *path=spa_dict_lookup(info,"filter.graph.path");
    bool builtin=!strcmp(factory,"filter.graph.plugin.builtin");
    bool lv2=!strcmp(factory,"filter.graph.plugin.lv2");
    if (!lib || !path || (!builtin && !lv2) ||
        strcmp(lib,builtin ? "filter-graph/libspa-filter-graph-plugin-builtin" : "filter-graph/libspa-filter-graph-plugin-lv2") ||
        (builtin ? strcmp(path,"builtin")!=0 : uri_index(path)<0) || r->n_children>=16) {
        fail(r,"load"); errno=EINVAL; return NULL;
    }
    struct spa_handle *h=pw_load_spa_handle(lib,factory,info,r->n_support,r->support);
    if (!h) { fail(r,"load"); return NULL; }
    r->children[r->n_children++]=(struct retained_handle){h,true}; r->children_unloaded=false;
    if (builtin && (!builtin_metadata(r,h) || !port_gate(r))) { errno=EINVAL; return NULL; }
    return h;
}
static int loader_unload(void *object,struct spa_handle *handle) {
    struct run *r=object;
    for (unsigned i=0;i<r->n_children;i++) if (r->children[i].handle==handle && r->children[i].live) {
        int result=pw_unload_spa_handle(handle); if (result>=0) r->children[i].live=false; else fail(r,"cleanup"); return result;
    }
    fail(r,"cleanup"); return -EINVAL;
}
static const struct spa_plugin_loader_methods loader_methods={.version=0,.load=loader_load,.unload=loader_unload};
static bool endpoint(struct run *r,const char *text,unsigned flags,unsigned fallback) {
    char value[256]; if (!copystr(value,sizeof(value),text)) return false;
    char *sep=strchr(value,':'); struct node *node;
    const char *symbol=value;
    if (sep) { *sep=0; node=node_named(r,value); symbol=sep+1; } else node=&r->nodes[fallback];
    return node && port_named(node,symbol,flags);
}
static bool port_gate(struct run *r) {
    struct span a[32]; char name[256];
    int n=array(r->inputs,a,32); if (n!=(int)r->want_inputs) return fail(r,"port");
    for (int i=0;i<n;i++) if (!decode(a[i],name,sizeof(name)) || !endpoint(r,name,INPUT|AUDIO,0)) return fail(r,"port");
    n=array(r->outputs,a,32); if (n!=(int)r->want_outputs) return fail(r,"port");
    for (int i=0;i<n;i++) if (!decode(a[i],name,sizeof(name)) || !endpoint(r,name,OUTPUT|AUDIO,r->n_nodes-1)) return fail(r,"port");
    n=array(r->links,a,32); if (n!=(int)r->want_links) return fail(r,"port");
    for (int i=0;i<n;i++) {
        if (!decode(member(a[i],"input"),name,sizeof(name)) || !endpoint(r,name,INPUT|AUDIO,0) ||
            !decode(member(a[i],"output"),name,sizeof(name)) || !endpoint(r,name,OUTPUT|AUDIO,0)) return fail(r,"port");
    }
    r->n_links=(unsigned)n; r->ports=true;
    if (r->want_convolvers) {
        n=array(r->volumes,a,32); if (n!=2) return fail(r,"control");
        for (int i=0;i<2;i++) {
            char scale[32]; float min,max;
            if (!decode(member(a[i],"control"),name,sizeof(name)) || strcmp(name,i ? "elr:volume" : "ell:volume") ||
                !decode(member(a[i],"scale"),scale,sizeof(scale)) || strcmp(scale,"cubic") ||
                !number(member(a[i],"min"),&min) || min!=-47.5f || !number(member(a[i],"max"),&max) || max!=0 ||
                !endpoint(r,name,INPUT|CONTROL,0)) return fail(r,"control");
        }
    } else if (r->volumes.p) return fail(r,"control");
    r->controls=true; return true;
}
static bool props_read(struct run *r,bool count) {
    uint8_t buffer[131072]; struct spa_pod_builder b=SPA_POD_BUILDER_INIT(buffer,sizeof(buffer)); struct spa_pod *props=NULL;
    if (spa_filter_graph_get_props(r->engine,&b,&props)<=0 || !props) return fail(r,"readback");
    const struct spa_pod_prop *params=spa_pod_find_prop(props,NULL,SPA_PROP_params);
    if (!params || !spa_pod_is_struct(&params->value)) return fail(r,"readback");
    for (unsigned i=0;i<r->n_nodes;i++) for (unsigned j=0;j<r->nodes[i].n_ports;j++) r->nodes[i].ports[j].seen=false;
    struct spa_pod_parser parser; struct spa_pod_frame f; spa_pod_parser_pod(&parser,&params->value);
    if (spa_pod_parser_push_struct(&parser,&f)<0) return fail(r,"readback");
    unsigned seen=0;
    while (true) {
        const char *name; if (spa_pod_parser_get_string(&parser,&name)<0) break;
        char copy[256]; if (!copystr(copy,sizeof(copy),name)) return fail(r,"readback");
        char *sep=strchr(copy,':'); if (!sep) return fail(r,"readback"); *sep=0;
        struct node *node=node_named(r,copy); struct port *p=node ? port_named(node,sep+1,INPUT|CONTROL) : NULL;
        if (!p || p->seen) return fail(r,"readback");
        float value;
        if (p->value_type==1) {
            bool v; if (spa_pod_parser_get_bool(&parser,&v)<0) return fail(r,"readback"); value=v ? 1.0f : 0.0f;
        } else if (p->value_type==2) {
            int32_t v; if (spa_pod_parser_get_int(&parser,&v)<0) return fail(r,"readback"); value=(float)v;
        } else if (spa_pod_parser_get_float(&parser,&value)<0) return fail(r,"readback");
        if (!isfinite(value) || value!=p->wanted) return fail(r,"readback");
        p->seen=true; seen++;
    }
    if (seen!=r->n_controls) return fail(r,"readback");
    if (count) r->n_readbacks=seen;
    return true;
}
static bool volume_readback(struct run *r) {
    if (!r->want_convolvers) { r->volume_gate=true; return true; }
    uint8_t buf[256]; float values[2]={0.125f,0.421875f};
    struct spa_pod_builder b=SPA_POD_BUILDER_INIT(buf,sizeof(buf));
    struct spa_pod *p=spa_pod_builder_add_object(&b,SPA_TYPE_OBJECT_Props,SPA_PARAM_Props,
        SPA_PROP_channelVolumes,SPA_POD_Array(sizeof(float),SPA_TYPE_Float,2,values));
    struct port *left=port_named(node_named(r,"ell"),"volume",INPUT|CONTROL);
    struct port *right=port_named(node_named(r,"elr"),"volume",INPUT|CONTROL);
    if (!p || !left || !right || spa_filter_graph_set_props(r->engine,SPA_DIRECTION_INPUT,p)<0) return fail(r,"readback");
    float oldl=left->wanted, oldr=right->wanted; left->wanted=-23.75f; right->wanted=-11.875f;
    if (!props_read(r,false)) return false;
    values[0]=values[1]=1; b=(struct spa_pod_builder)SPA_POD_BUILDER_INIT(buf,sizeof(buf));
    p=spa_pod_builder_add_object(&b,SPA_TYPE_OBJECT_Props,SPA_PARAM_Props,
        SPA_PROP_channelVolumes,SPA_POD_Array(sizeof(float),SPA_TYPE_Float,2,values));
    if (!p || spa_filter_graph_set_props(r->engine,SPA_DIRECTION_INPUT,p)<0) return fail(r,"readback");
    left->wanted=oldl; right->wanted=oldr;
    if (oldl!=0 || oldr!=0 || !props_read(r,false)) return fail(r,"readback");
    r->volume_gate=true; return true;
}
static int inventory(struct dl_phdr_info *info,size_t size,void *data) {
    (void)size; struct run *r=data; if (!info->dlpi_name || !info->dlpi_name[0] || !strcmp(info->dlpi_name,"linux-vdso.so.1")) return 0;
    char path[PATH_MAX]; if (!realpath(info->dlpi_name,path)) { r->observer_bad=true; return 0; }
    if (r->n_libs>=128 || !copystr(r->libs[r->n_libs++],PATH_MAX,path)) { r->observer_bad=true; return 0; }
    return 0;
}
static bool libraries(struct run *r) {
    dl_iterate_phdr(inventory,r); bool found[3]={false,false,false};
    for (unsigned i=0;i<r->n_libs;i++) {
        if (strstr(r->libs[i],"lsp-plugins-lv2ui") || strstr(r->libs[i],"lsp-plugins-lv2-ui")) return fail(r,"library");
        if (contained(r->libs[i],ROOT)) {
            bool allowed=false;
            for (unsigned j=0;j<3;j++) if (!strcmp(r->libs[i],r->dsp[j]) && r->used_dsp[j]) { found[j]=true; allowed=true; }
            if (!allowed) return fail(r,"library");
        }
    }
    for (unsigned i=0;i<3;i++) if (r->used_dsp[i]!=found[i]) return fail(r,"library");
    if (r->observer_bad) return fail(r,"observe");
    r->library_gate=true; return true;
}
static void info_event(void *data,const struct spa_filter_graph_info *info) {
    struct run *r=data; char in[16],out[16];
    snprintf(in,sizeof(in),"%u",r->want_inputs); snprintf(out,sizeof(out),"%u",r->want_outputs);
    const char *di=spa_dict_lookup(info->props,"n_default_inputs"), *dout=spa_dict_lookup(info->props,"n_default_outputs");
    if (!di || !dout || strcmp(di,in) || strcmp(dout,out)) { fail(r,"port"); return; }
    if (r->check_current) {
        const char *ci=spa_dict_lookup(info->props,"n_inputs"), *co=spa_dict_lookup(info->props,"n_outputs");
        if (!ci || !co || strcmp(ci,in) || strcmp(co,out)) { fail(r,"port"); return; }
        r->current_info=true;
    }
}
static const struct spa_filter_graph_events events={.version=0,.info=info_event};
static bool activate_graph(struct run *r) {
    pw_init(NULL,NULL); r->initialized=true; r->n_support=pw_get_support(r->support,32);
    r->loop=pw_loop_new(NULL); if (!r->loop) return fail(r,"load"); r->loop_destroyed=false;
    pw_loop_enter(r->loop); r->entered=true;
    r->log.iface=SPA_INTERFACE_INIT(SPA_TYPE_INTERFACE_Log,SPA_VERSION_LOG,&log_methods,r); r->log.level=SPA_LOG_LEVEL_INFO;
    r->loader.iface=SPA_INTERFACE_INIT(SPA_TYPE_INTERFACE_PluginLoader,SPA_VERSION_PLUGIN_LOADER,&loader_methods,r);
    for (unsigned i=0;i<r->n_support;i++) if (!strcmp(r->support[i].type,SPA_TYPE_INTERFACE_Log)) r->support[i].data=&r->log;
    r->support[r->n_support++]=SPA_SUPPORT_INIT(SPA_TYPE_INTERFACE_PluginLoader,&r->loader);
    r->support[r->n_support++]=SPA_SUPPORT_INIT(SPA_TYPE_INTERFACE_Loop,r->loop->loop);
    r->support[r->n_support++]=SPA_SUPPORT_INIT(SPA_TYPE_INTERFACE_DataLoop,r->loop->loop);
    char *graph=strndup(r->graph.p,(size_t)r->graph.n); if (!graph) return fail(r,"load");
    char in_count[8],out_count[8];
    snprintf(in_count,sizeof(in_count),"%u",r->want_inputs); snprintf(out_count,sizeof(out_count),"%u",r->want_outputs);
    struct spa_dict_item items[]={SPA_DICT_ITEM_INIT("filter.graph",graph),SPA_DICT_ITEM_INIT("clock.quantum-limit","8192"),
        SPA_DICT_ITEM_INIT("filter-graph.n_inputs",in_count),SPA_DICT_ITEM_INIT("filter-graph.n_outputs",out_count)};
    struct spa_dict dict=SPA_DICT_INIT(items,4);
    r->graph_handle=pw_load_spa_handle("filter-graph/libspa-filter-graph","filter.graph",&dict,r->n_support,r->support); free(graph);
    if (!r->graph_handle) return fail(r,"load");
    r->graph_unloaded=false;
    if (spa_handle_get_interface(r->graph_handle,SPA_TYPE_INTERFACE_FilterGraph,(void**)&r->engine)<0) return fail(r,"load");
    for (unsigned i=0;i<r->n_nodes;i++) if (!r->nodes[i].metadata) return fail(r,"metadata");
    r->metadata=true;
    if (!port_gate(r)) return false;
    struct spa_hook hook;
    if (spa_filter_graph_add_listener(r->engine,&hook,&events,r)<0) return fail(r,"load");
    if (r->failure) { spa_hook_remove(&hook); return false; }
    int result=spa_filter_graph_activate(r->engine,&SPA_DICT_ITEMS(SPA_DICT_ITEM("audio.rate","48000")));
    r->deactivated=false;
    if (result<0) { spa_hook_remove(&hook); return fail(r,r->fir_unavailable ? "fir_unavailable" : "activate"); }
    r->activation=true;
    r->check_current=true;
    struct spa_hook active_hook;
    if (spa_filter_graph_add_listener(r->engine,&active_hook,&events,r)<0) { spa_hook_remove(&hook); return fail(r,"port"); }
    spa_hook_remove(&active_hook);
    if (!r->current_info || r->failure) { spa_hook_remove(&hook); return fail(r,"port"); }
    if (r->observer_bad) { spa_hook_remove(&hook); return fail(r,"observe"); }
    for (unsigned i=0;i<r->n_nodes;i++) if (!r->nodes[i].observed) { spa_hook_remove(&hook); return fail(r,"observe"); }
    r->stages=true;
    if (r->n_firs!=r->want_convolvers) { spa_hook_remove(&hook); return fail(r,"fir_selection"); }
    for (unsigned i=0;i<r->n_firs;i++) {
        struct node *n=node_named(r,r->firs[i].node);
        if (!n || r->firs[i].rate!=48000 || strcmp(r->firs[i].path,n->fir[1])) { spa_hook_remove(&hook); return fail(r,"fir_selection"); }
        for (unsigned j=0;j<i;j++) if (!strcmp(r->firs[i].node,r->firs[j].node)) { spa_hook_remove(&hook); return fail(r,"fir_selection"); }
    }
    r->fir_gate=true;
    bool ok=libraries(r) && props_read(r,true) && volume_readback(r); if (ok) r->readback=true;
    spa_hook_remove(&hook); return ok;
}
static void cleanup(struct run *r) {
    if (r->engine) { if (spa_filter_graph_deactivate(r->engine)>=0) r->deactivated=true; else fail(r,"cleanup"); }
    if (r->graph_handle) {
        if (pw_unload_spa_handle(r->graph_handle)>=0) r->graph_unloaded=true; else fail(r,"cleanup");
        r->graph_handle=NULL; r->engine=NULL;
    }
    for (unsigned i=r->n_children;i>0;i--) if (r->children[i-1].live) (void)loader_unload(r,r->children[i-1].handle);
    r->children_unloaded=true; for (unsigned i=0;i<r->n_children;i++) if (r->children[i].live) r->children_unloaded=false;
    if (r->loop) { if (r->entered) pw_loop_leave(r->loop); pw_loop_destroy(r->loop); r->loop=NULL; r->loop_destroyed=true; }
    if (r->world) { lilv_world_free(r->world); r->world=NULL; }
    if (r->initialized) { pw_deinit(); r->initialized=false; }
    r->retired=r->deactivated && r->graph_unloaded && r->children_unloaded && r->loop_destroyed;
    if (!r->retired) fail(r,"cleanup");
}
static void string_json(FILE *out,const char *s) {
    fputc('"',out); for (const unsigned char *p=(const unsigned char*)s;*p;p++) {
        if (*p=='"' || *p=='\\') fprintf(out,"\\%c",*p);
        else if (*p<32 || *p>=127) fprintf(out,"\\u%04x",*p); else fputc(*p,out);
    } fputc('"',out);
}
static const char *yes(bool value) { return value ? "true" : "false"; }
static void report(FILE *out,struct run *r) {
    fprintf(out,"{\"schema\":\"asahi-audio-offline-graph-host-v1\",\"status\":\"%s\",\"failure_class\":",r->failure ? "FAIL" : "PASS");
    if (r->failure) string_json(out,r->failure); else fputs("null",out);
    fputs(",\"case\":",out); string_json(out,r->case_id ? r->case_id : "invalid");
    fputs(",\"expect\":",out); string_json(out,r->expect ? r->expect : "positive");
    fprintf(out,",\"rate\":48000,\"process_calls\":0,\"counts\":{\"nodes\":%u,\"lv2\":%u,\"builtin\":%u,\"convolvers\":%u,\"links\":%u,\"controls\":%u,\"readbacks\":%u},",r->n_nodes,r->n_lv2,r->n_builtin,r->n_convolvers,r->n_links,r->n_controls,r->n_readbacks);
    fprintf(out,"\"gates\":{\"full_input\":%s,\"unique_keys\":%s,\"metadata\":%s,\"ports\":%s,\"controls\":%s,\"volumes\":%s,\"activation\":%s,\"stages\":%s,\"fir_selection\":%s,\"libraries\":%s,\"readback\":%s,\"retired\":%s},",yes(r->full_input),yes(r->unique_keys),yes(r->metadata),yes(r->ports),yes(r->controls),yes(r->volume_gate),yes(r->activation),yes(r->stages),yes(r->fir_gate),yes(r->library_gate),yes(r->readback),yes(r->retired));
    fputs("\"stage_names\":[",out); bool comma=false;
    for (unsigned i=0;i<r->n_nodes;i++) if (r->nodes[i].observed) { if (comma) fputc(',',out); string_json(out,r->nodes[i].name); comma=true; }
    fputs("],\"fir_selections\":[",out);
    for (unsigned i=0;i<r->n_firs;i++) { if (i) fputc(',',out); fputs("{\"node\":",out); string_json(out,r->firs[i].node); fputs(",\"path\":",out); string_json(out,r->firs[i].path); fprintf(out,",\"rate\":%u}",r->firs[i].rate); }
    fputs("],\"libraries\":[",out); for (unsigned i=0;i<r->n_libs;i++) { if (i) fputc(',',out); string_json(out,r->libs[i]); }
    fprintf(out,"],\"cleanup\":{\"deactivated\":%s,\"graph_unloaded\":%s,\"children_unloaded\":%s,\"loop_destroyed\":%s}}\n",yes(r->deactivated),yes(r->graph_unloaded),yes(r->children_unloaded),yes(r->loop_destroyed));
}
int main(int argc,char **argv) {
    struct run *r=calloc(1,sizeof(*r)); if (!r) return 2;
    r->deactivated=r->graph_unloaded=r->children_unloaded=r->loop_destroyed=true;
    const char *path=NULL;
    for (int i=1;i<argc;i+=2) {
        if (i+1>=argc) { fail(r,"input"); break; }
        if (!strcmp(argv[i],"--graph") && !path) path=argv[i+1];
        else if (!strcmp(argv[i],"--case") && !r->case_id) r->case_id=argv[i+1];
        else if (!strcmp(argv[i],"--expect") && !r->expect) r->expect=argv[i+1];
        else { fail(r,"input"); break; }
    }
    if (!r->expect) r->expect="positive";
    static const char *const cases[]={"j413-speakers","j415-speakers","j413-mic","j415-mic"}; int which=-1;
    for (unsigned i=0;i<4;i++) if (r->case_id && !strcmp(r->case_id,cases[i])) which=(int)i;
    if (which<0 || !path || path[0]!='/') fail(r,"input");
    if (which>=0) {
        r->want_nodes=which==0 ? 9 : which==1 ? 13 : 7; r->want_lv2=which<2 ? 5 : 1;
        r->want_builtin=r->want_nodes-r->want_lv2; r->want_convolvers=which<2 ? 4 : 0;
        r->want_links=which==0 ? 10 : which==1 ? 14 : 6; r->want_inputs=which<2 ? 2 : 3; r->want_outputs=which==0 ? 4 : which==1 ? 6 : 1;
    }
    int public_fd=dup(STDOUT_FILENO); FILE *out=public_fd<0 ? NULL : fdopen(public_fd,"w");
    if (!out) { free(r); return 2; }
    if (dup2(STDERR_FILENO,STDOUT_FILENO)<0) fail(r,"input");
    const char *const environment[][2]={{"LV2_PATH",ROOT},{"SPA_PLUGIN_DIR","/usr/lib/spa-0.2"},
        {"SPA_SUPPORT_LIB","support/libspa-support"},{"PIPEWIRE_DLCLOSE","true"},
        {"PIPEWIRE_LOG_SYSTEMD","false"},{"PIPEWIRE_LOG_COLOR","false"},
        {"PIPEWIRE_NO_CONFIG","true"},{"PIPEWIRE_DEBUG","0"}};
    for (unsigned i=0;i<sizeof(environment)/sizeof(environment[0]);i++)
        if (setenv(environment[i][0],environment[i][1],1)<0) fail(r,"input");
    if ((getenv("LD_PRELOAD") && getenv("LD_PRELOAD")[0]) ||
        (getenv("LD_LIBRARY_PATH") && getenv("LD_LIBRARY_PATH")[0])) fail(r,"input");
    const char *const remove_env[]={"PIPEWIRE_LOG","PIPEWIRE_CPU","PIPEWIRE_VM"};
    for (unsigned i=0;i<sizeof(remove_env)/sizeof(remove_env[0]);i++) if (unsetenv(remove_env[i])<0) fail(r,"input");
    char *storage=NULL;
    if (!r->failure && load_input(r,path,&storage) && lv2_preflight(r)) (void)activate_graph(r);
    cleanup(r); report(out,r); bool ok=!r->failure; fclose(out); free(storage); free(r); return ok ? 0 : 1;
}
