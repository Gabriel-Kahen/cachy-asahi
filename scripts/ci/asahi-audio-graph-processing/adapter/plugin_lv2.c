/* PipeWire */
/* SPDX-FileCopyrightText: Copyright © 2021 Wim Taymans */
/* SPDX-License-Identifier: MIT */

#include <dlfcn.h>
#include <math.h>

#include <lilv/lilv.h>

#include <spa/utils/defs.h>
#include <spa/utils/list.h>
#include <spa/utils/string.h>
#include <spa/utils/json.h>
#include <spa/support/loop.h>
#include <spa/support/log.h>

#if defined __has_include
#	if __has_include (<lv2/atom/atom.h>)

		#include <lv2/atom/atom.h>
		#include <lv2/buf-size/buf-size.h>
		#include <lv2/worker/worker.h>
		#include <lv2/state/state.h>
		#include <lv2/options/options.h>
		#include <lv2/parameters/parameters.h>
		#include <lv2/log/log.h>

#	else

		#include <lv2/lv2plug.in/ns/ext/atom/atom.h>
		#include <lv2/lv2plug.in/ns/ext/buf-size/buf-size.h>
		#include <lv2/lv2plug.in/ns/ext/worker/worker.h>
		#include <lv2/lv2plug.in/ns/ext/state/state.h>
		#include <lv2/lv2plug.in/ns/ext/options/options.h>
		#include <lv2/lv2plug.in/ns/ext/parameters/parameters.h>
		#include <lv2/lv2plug.in/ns/ext/log/log.h>

#	endif

#endif

#include "audio-plugin.h"

static struct context *_context;

typedef struct URITable {
	char **data;
	size_t alloc;
	size_t len;
} URITable;

static void uri_table_init(URITable *table)
{
	table->data = NULL;
	table->len = table->alloc = 0;
}

static void uri_table_destroy(URITable *table)
{
	size_t i;
	for (i = 0; i < table->len; i++)
		free(table->data[i]);
	free(table->data);
	uri_table_init(table);
}

static LV2_URID uri_table_map(LV2_URID_Map_Handle handle, const char *uri)
{
	URITable *table = (URITable*)handle;
	size_t i;

	for (i = 0; i < table->len; i++)
		if (spa_streq(table->data[i], uri))
			return i+1;

	if (table->len == table->alloc) {
		table->alloc += 64;
		table->data = realloc(table->data, table->alloc * sizeof(char *));
 	}
	table->data[table->len++] = strdup(uri);
	return table->len;
}

static const char *uri_table_unmap(LV2_URID_Map_Handle handle, LV2_URID urid)
{
	URITable *table = (URITable*)handle;
	if (urid > 0 && urid <= table->len)
		return table->data[urid-1];
	return NULL;
}

struct context {
	int ref;
	LilvWorld *world;

	LilvNode *lv2_InputPort;
	LilvNode *lv2_OutputPort;
	LilvNode *lv2_AudioPort;
	LilvNode *lv2_ControlPort;
	LilvNode *lv2_Optional;
	LilvNode *atom_AtomPort;
	LilvNode *atom_Sequence;
	LilvNode *atom_bufferType;
	LilvNode *resize_minimumSize;
	LilvNode *urid_map;
	LilvNode *powerOf2BlockLength;
	LilvNode *fixedBlockLength;
	LilvNode *boundedBlockLength;
	LilvNode* worker_schedule;
	LilvNode* worker_iface;
	LilvNode* state_iface;

	URITable uri_table;
	LV2_URID_Map map;
	LV2_Feature map_feature;
	LV2_URID_Unmap unmap;
	LV2_Feature unmap_feature;

	LV2_URID atom_Int;
	LV2_URID atom_Float;
	LV2_URID sequence_type;
	LV2_URID chunk_type;
};

#define context_map(c,uri) ((c)->map.map((c)->map.handle,(uri)))

static void context_free(struct context *c)
{
	if (c->world) {
		lilv_node_free(c->worker_schedule);
		lilv_node_free(c->powerOf2BlockLength);
		lilv_node_free(c->fixedBlockLength);
		lilv_node_free(c->boundedBlockLength);
		lilv_node_free(c->urid_map);
		lilv_node_free(c->atom_Sequence);
		lilv_node_free(c->atom_bufferType);
		lilv_node_free(c->resize_minimumSize);
		lilv_node_free(c->atom_AtomPort);
		lilv_node_free(c->lv2_Optional);
		lilv_node_free(c->lv2_ControlPort);
		lilv_node_free(c->lv2_AudioPort);
		lilv_node_free(c->lv2_OutputPort);
		lilv_node_free(c->lv2_InputPort);
		lilv_world_free(c->world);
	}
	uri_table_destroy(&c->uri_table);
	free(c);
}

static const LV2_Feature buf_size_features[3] = {
	{ LV2_BUF_SIZE__powerOf2BlockLength, NULL },
	{ LV2_BUF_SIZE__fixedBlockLength,    NULL },
	{ LV2_BUF_SIZE__boundedBlockLength,  NULL },
};

static struct context *context_new(void)
{
	struct context *c;

	c = calloc(1, sizeof(*c));
	if (c == NULL)
		return NULL;

	uri_table_init(&c->uri_table);
	c->world = lilv_world_new();
	if (c->world == NULL)
		goto error;

	lilv_world_load_all(c->world);

	c->lv2_InputPort = lilv_new_uri(c->world, LV2_CORE__InputPort);
	c->lv2_OutputPort = lilv_new_uri(c->world, LV2_CORE__OutputPort);
	c->lv2_AudioPort = lilv_new_uri(c->world, LV2_CORE__AudioPort);
	c->lv2_ControlPort = lilv_new_uri(c->world, LV2_CORE__ControlPort);
	c->lv2_Optional = lilv_new_uri(c->world, LV2_CORE__connectionOptional);
	c->atom_AtomPort = lilv_new_uri(c->world, LV2_ATOM__AtomPort);
	c->atom_Sequence = lilv_new_uri(c->world, LV2_ATOM__Sequence);
	c->atom_bufferType = lilv_new_uri(c->world, LV2_ATOM__bufferType);
	c->resize_minimumSize = lilv_new_uri(c->world,
		"http://lv2plug.in/ns/ext/resize-port#minimumSize");
	c->urid_map = lilv_new_uri(c->world, LV2_URID__map);
	c->powerOf2BlockLength = lilv_new_uri(c->world, LV2_BUF_SIZE__powerOf2BlockLength);
	c->fixedBlockLength = lilv_new_uri(c->world, LV2_BUF_SIZE__fixedBlockLength);
	c->boundedBlockLength = lilv_new_uri(c->world, LV2_BUF_SIZE__boundedBlockLength);
        c->worker_schedule = lilv_new_uri(c->world, LV2_WORKER__schedule);
	c->worker_iface = lilv_new_uri(c->world, LV2_WORKER__interface);
	c->state_iface = lilv_new_uri(c->world, LV2_STATE__interface);

	c->map.handle = &c->uri_table;
	c->map.map = uri_table_map;
	c->map_feature.URI = LV2_URID__map;
	c->map_feature.data = &c->map;
	c->unmap.handle = &c->uri_table;
	c->unmap.unmap  = uri_table_unmap;
	c->unmap_feature.URI = LV2_URID__unmap;
	c->unmap_feature.data = &c->unmap;

	c->atom_Int = context_map(c, LV2_ATOM__Int);
	c->atom_Float = context_map(c, LV2_ATOM__Float);
	c->sequence_type = context_map(c, LV2_ATOM__Sequence);
	c->chunk_type = context_map(c, LV2_ATOM__Chunk);

	return c;
error:
	context_free(c);
	return NULL;
}

static struct context *context_ref(void)
{
	if (_context == NULL) {
		_context = context_new();
		if (_context == NULL)
			return NULL;
	}
	_context->ref++;
	return _context;
}

static void context_unref(struct context *context)
{
	if (--_context->ref == 0) {
		context_free(_context);
		_context = NULL;
	}
}

struct plugin {
	struct spa_handle handle;
	struct spa_fga_plugin plugin;

	struct spa_log *log;
	struct spa_loop *data_loop;
	struct spa_loop *main_loop;

	struct context *c;
	const LilvPlugin *p;
};

struct descriptor {
	struct spa_fga_descriptor desc;
	struct plugin *p;
};

/* Bounded offline candidate: two optional UI Sequence ports, no events. */
#define ATOM_BUFFER_BYTES (512u * 1024u)
#define MAX_ATOM_PORTS 2u

struct atom_port {
	uint32_t index;
	bool output;
	LV2_Atom_Sequence *data;
};

struct instance {
	struct descriptor *desc;
	struct plugin *p;

	LilvInstance *instance;
	LV2_Worker_Schedule work_schedule;
	LV2_Feature work_schedule_feature;
	LV2_Log_Log log;
	LV2_Feature log_feature;
	LV2_Options_Option options[6];
	LV2_Feature options_feature;

	const LV2_Feature *features[10];

	const LV2_Worker_Interface *work_iface;
	const LV2_State_Interface *state_iface;

	int32_t block_length;
	struct atom_port atom_ports[MAX_ATOM_PORTS];
	uint32_t n_atom_ports;
};

/* Atom ownership/reset helpers: also compiled by the inert mock controls. */
static void atom_ports_clear(struct instance *i)
{
	for (uint32_t n = 0; n < i->n_atom_ports; n++) {
		free(i->atom_ports[n].data);
		i->atom_ports[n].data = NULL;
	}
	i->n_atom_ports = 0;
}

static void atom_ports_reset(struct instance *i)
{
	struct context *c = i->p->c;
	for (uint32_t n = 0; n < i->n_atom_ports; n++) {
		struct atom_port *p = &i->atom_ports[n];
		memset(p->data, 0, ATOM_BUFFER_BYTES);
		p->data->atom.type = p->output ? c->chunk_type : c->sequence_type;
		p->data->atom.size = p->output ?
			ATOM_BUFFER_BYTES - sizeof(LV2_Atom) :
			sizeof(LV2_Atom_Sequence_Body);
	}
}

static int atom_port_add(struct instance *i, uint32_t index, bool output)
{
	struct atom_port *p;
	if (i->n_atom_ports == MAX_ATOM_PORTS)
		return -E2BIG;
	p = &i->atom_ports[i->n_atom_ports];
	p->data = calloc(1, ATOM_BUFFER_BYTES);
	if (p->data == NULL)
		return -ENOMEM;
	p->index = index;
	p->output = output;
	i->n_atom_ports++;
	return 0;
}
/* End Atom ownership/reset helpers. */

static int atom_ports_init(struct instance *i)
{
	struct plugin *p = i->p;
	struct context *c = p->c;
	for (uint32_t n = 0; n < i->desc->desc.n_ports; n++) {
		const LilvPort *port = lilv_plugin_get_port_by_index(p->p, n);
		LilvNodes *types, *sizes;
		const LilvNode *size;
		bool input, output, valid;
		int res;
		if (!lilv_port_is_a(p->p, port, c->atom_AtomPort))
			continue;
		input = lilv_port_is_a(p->p, port, c->lv2_InputPort);
		output = lilv_port_is_a(p->p, port, c->lv2_OutputPort);
		types = lilv_port_get_value(p->p, port, c->atom_bufferType);
		sizes = lilv_port_get_value(p->p, port, c->resize_minimumSize);
		valid = input != output &&
			lilv_port_has_property(p->p, port, c->lv2_Optional) &&
			lilv_nodes_size(types) == 1 &&
			lilv_node_equals(lilv_nodes_get_first(types), c->atom_Sequence) &&
			lilv_nodes_size(sizes) <= 1;
		if ((size = lilv_nodes_get_first(sizes)) != NULL)
			valid = valid && lilv_node_is_int(size) &&
				lilv_node_as_int(size) >= 0 &&
				(uint32_t)lilv_node_as_int(size) <= ATOM_BUFFER_BYTES;
		lilv_nodes_free(types);
		lilv_nodes_free(sizes);
		if (!valid)
			return -EINVAL;
		if ((res = atom_port_add(i, n, output)) < 0)
			return res;
	}
	atom_ports_reset(i);
	return 0;
}

static int
do_respond(struct spa_loop *loop, bool async, uint32_t seq, const void *data,
		size_t size, void *user_data)
{
	struct instance *i = (struct instance*)user_data;
	i->work_iface->work_response(lilv_instance_get_handle(i->instance), size, data);
	return 0;
}

/** Called by the plugin to respond to non-RT work. */
static LV2_Worker_Status
work_respond(LV2_Worker_Respond_Handle handle, uint32_t size, const void *data)
{
	struct instance *i = (struct instance*)handle;
	spa_loop_invoke(i->p->data_loop, do_respond, 1, data, size, false, i);
	return LV2_WORKER_SUCCESS;
}

static int
do_schedule(struct spa_loop *loop, bool async, uint32_t seq, const void *data,
		size_t size, void *user_data)
{
	struct instance *i = (struct instance*)user_data;
	i->work_iface->work(lilv_instance_get_handle(i->instance), work_respond, i, size, data);
	return 0;
}

/** Called by the plugin to schedule non-RT work. */
static LV2_Worker_Status
work_schedule(LV2_Worker_Schedule_Handle handle, uint32_t size, const void *data)
{
	struct instance *i = (struct instance*)handle;
	spa_loop_invoke(i->p->main_loop, do_schedule, 1, data, size, false, i);
	return LV2_WORKER_SUCCESS;
}

struct state_data {
	struct instance *i;
	const char *config;
	char *tmp;
};

static const void *state_retrieve_function(LV2_State_Handle handle,
		uint32_t key, size_t *size, uint32_t *type, uint32_t *flags)
{
	struct state_data *sd = (struct state_data*)handle;
	struct plugin *p = sd->i->p;
	struct context *c = p->c;
	const char *uri = c->unmap.unmap(c->unmap.handle, key), *val;
	struct spa_json it[3];
	char k[strlen(uri)+3];
	int len;

	if (sd->config == NULL) {
		spa_log_info(p->log, "lv2: restore %d %s without a config", key, uri);
		return NULL;
	}

	if (spa_json_begin_object(&it[0], sd->config, strlen(sd->config)) <= 0) {
		spa_log_error(p->log, "lv2: config must be an object");
		return NULL;
	}

	while ((len = spa_json_object_next(&it[0], k, sizeof(k), &val)) > 0) {
		if (!spa_streq(k, uri))
			continue;

		if (spa_json_is_container(val, len))
			if ((len = spa_json_container_len(&it[0], val, len)) <= 0)
				return NULL;

		sd->tmp = realloc(sd->tmp, len+1);
		spa_json_parse_stringn(val, len, sd->tmp, len+1);

		spa_log_info(p->log, "lv2: restore %d %s %s", key, uri, sd->tmp);
		if (size)
			*size = strlen(sd->tmp);
		if (type)
			*type = 0;
		if (flags)
			*flags = LV2_STATE_IS_POD | LV2_STATE_IS_PORTABLE;
		return sd->tmp;
	}
	spa_log_info(p->log, "lv2: restore %d %s not found in config", key, uri);
	return NULL;
}

SPA_PRINTF_FUNC(3, 0)
static int log_vprintf(LV2_Log_Handle handle, LV2_URID type, const char* fmt, va_list ap)
{
	struct instance *i = (struct instance*)handle;
	spa_log_logv(i->p->log, SPA_LOG_LEVEL_INFO, __FILE__,__LINE__,__func__, fmt, ap);
	return 0;
}

SPA_PRINTF_FUNC(3, 4)
static int log_printf(LV2_Log_Handle handle, LV2_URID type, const char* fmt, ...)
{
	va_list args;
	int ret;
	va_start(args, fmt);
	ret = log_vprintf(handle, type, fmt, args);
	va_end(args);
	return ret;
}

static void *lv2_instantiate(const struct spa_fga_plugin *plugin, const struct spa_fga_descriptor *desc,
                        unsigned long SampleRate, int index, const char *config)
{
	struct descriptor *d = (struct descriptor*)desc;
	struct plugin *p = d->p;
	struct context *c = p->c;
	struct instance *i;
	uint32_t n, n_features = 0;
	int res;
	static const int32_t min_block_length = 1;
	static const int32_t max_block_length = 8192;
	static const int32_t seq_size = ATOM_BUFFER_BYTES;
	float fsample_rate = SampleRate;

	i = calloc(1, sizeof(*i));
	if (i == NULL)
		return NULL;

	i->block_length = 1024;
	i->desc = d;
	i->p = p;
	if ((res = atom_ports_init(i)) < 0) {
		atom_ports_clear(i);
		free(i);
		errno = -res;
		return NULL;
	}
	i->log.handle = i;
	i->log.printf = log_printf;
	i->log.vprintf = log_vprintf;
	i->log_feature.URI = LV2_LOG__log;
	i->log_feature.data = &i->log;
	i->features[n_features++] = &i->log_feature;
	i->features[n_features++] = &c->map_feature;
	i->features[n_features++] = &c->unmap_feature;
	i->features[n_features++] = &buf_size_features[0];
	i->features[n_features++] = &buf_size_features[1];
	i->features[n_features++] = &buf_size_features[2];
	if (lilv_plugin_has_feature(p->p, c->worker_schedule)) {
		i->work_schedule.handle = i;
		i->work_schedule.schedule_work = work_schedule;
		i->work_schedule_feature.URI = LV2_WORKER__schedule;
		i->work_schedule_feature.data = &i->work_schedule;
		i->features[n_features++] = &i->work_schedule_feature;
	}

	i->options[0] = (LV2_Options_Option) { LV2_OPTIONS_INSTANCE, 0,
		context_map(c, LV2_BUF_SIZE__minBlockLength), sizeof(int32_t),
		c->atom_Int, &min_block_length };
	i->options[1] = (LV2_Options_Option) { LV2_OPTIONS_INSTANCE, 0,
		context_map(c, LV2_BUF_SIZE__maxBlockLength), sizeof(int32_t),
		c->atom_Int, &max_block_length };
	i->options[2] = (LV2_Options_Option) { LV2_OPTIONS_INSTANCE, 0,
		context_map(c, LV2_BUF_SIZE__sequenceSize), sizeof(int32_t),
		c->atom_Int, &seq_size };
	i->options[3] = (LV2_Options_Option) { LV2_OPTIONS_INSTANCE, 0,
		context_map(c, "http://lv2plug.in/ns/ext/buf-size#nominalBlockLength"), sizeof(int32_t),
		c->atom_Int, &i->block_length },
	i->options[4] = (LV2_Options_Option) { LV2_OPTIONS_INSTANCE, 0,
		context_map(c, LV2_PARAMETERS__sampleRate), sizeof(float),
		c->atom_Float, &fsample_rate };
	i->options[5] = (LV2_Options_Option) { LV2_OPTIONS_INSTANCE, 0, 0, 0, 0, NULL };

	i->options_feature.URI = LV2_OPTIONS__options;
	i->options_feature.data = i->options;
	i->features[n_features++] = &i->options_feature;
	i->features[n_features++] = NULL;
	spa_assert(n_features < SPA_N_ELEMENTS(i->features));

	i->instance = lilv_plugin_instantiate(p->p, SampleRate, i->features);
	if (i->instance == NULL) {
		atom_ports_clear(i);
		free(i);
		return NULL;
	}
	if (lilv_plugin_has_extension_data(p->p, c->worker_iface)) {
                i->work_iface = (const LV2_Worker_Interface*)
			lilv_instance_get_extension_data(i->instance, LV2_WORKER__interface);
        }
	if (lilv_plugin_has_extension_data(p->p, c->state_iface)) {
                i->state_iface = (const LV2_State_Interface*)
			lilv_instance_get_extension_data(i->instance, LV2_STATE__interface);
        }
	for (n = 0; n < i->n_atom_ports; n++)
		lilv_instance_connect_port(i->instance,
			i->atom_ports[n].index, i->atom_ports[n].data);
	if (i->state_iface && i->state_iface->restore) {
		struct state_data sd = { .i = i, .config = config, .tmp = NULL };
		i->state_iface->restore(lilv_instance_get_handle(i->instance), state_retrieve_function,
				&sd, 0, i->features);
		free(sd.tmp);
	}
	return i;
}

static void lv2_cleanup(void *instance)
{
	struct instance *i = instance;
	spa_loop_invoke(i->p->data_loop, NULL, 0, NULL, 0, true, NULL);
	spa_loop_invoke(i->p->main_loop, NULL, 0, NULL, 0, true, NULL);
	lilv_instance_free(i->instance);
	atom_ports_clear(i);
	free(i);
}

static void lv2_connect_port(void *instance, unsigned long port, void *data)
{
	struct instance *i = instance;
	lilv_instance_connect_port(i->instance, port, data);
}

static void lv2_activate(void *instance)
{
	struct instance *i = instance;
	atom_ports_reset(i);
	lilv_instance_activate(i->instance);
}

static void lv2_deactivate(void *instance)
{
	struct instance *i = instance;
	lilv_instance_deactivate(i->instance);
}

static void lv2_run(void *instance, unsigned long SampleCount)
{
	struct instance *i = instance;
	atom_ports_reset(i);
	lilv_instance_run(i->instance, SampleCount);
	if (i->work_iface != NULL && i->work_iface->end_run != NULL)
		i->work_iface->end_run(lilv_instance_get_handle(i->instance));
}

static void lv2_free(const struct spa_fga_descriptor *desc)
{
	struct descriptor *d = (struct descriptor*)desc;
	uint32_t i;
	for (i = 0; i <  d->desc.n_ports; i++)
		free((void*)d->desc.ports[i].name);
	free((char*)d->desc.name);
	free(d->desc.ports);
	free(d);
}

static const struct spa_fga_descriptor *lv2_plugin_make_desc(void *plugin, const char *name)
{
	struct plugin *p = (struct plugin *)plugin;
	struct context *c = p->c;
	struct descriptor *desc;
	uint32_t i;
	float *mins, *maxes, *controls;
	bool latent;
	uint32_t latency_index;

	desc = calloc(1, sizeof(*desc));
	if (desc == NULL)
		return NULL;

	desc->p = p;
	desc->desc.instantiate = lv2_instantiate;
	desc->desc.cleanup = lv2_cleanup;
	desc->desc.connect_port = lv2_connect_port;
	desc->desc.activate = lv2_activate;
	desc->desc.deactivate = lv2_deactivate;
	desc->desc.run = lv2_run;

	desc->desc.free = lv2_free;

	desc->desc.name = strdup(name);
	desc->desc.flags = 0;

	desc->desc.n_ports = lilv_plugin_get_num_ports(p->p);
	desc->desc.ports = calloc(desc->desc.n_ports, sizeof(struct spa_fga_port));

	mins = alloca(desc->desc.n_ports * sizeof(float));
	maxes = alloca(desc->desc.n_ports * sizeof(float));
	controls = alloca(desc->desc.n_ports * sizeof(float));

	latent = lilv_plugin_has_latency(p->p);
	latency_index = latent ? lilv_plugin_get_latency_port_index(p->p) : 0;

	lilv_plugin_get_port_ranges_float(p->p, mins, maxes, controls);

	for (i = 0; i < desc->desc.n_ports; i++) {
		const LilvPort *port = lilv_plugin_get_port_by_index(p->p, i);
                const LilvNode *symbol = lilv_port_get_symbol(p->p, port);
		struct spa_fga_port *fp = &desc->desc.ports[i];

		fp->index = i;
		fp->name = strdup(lilv_node_as_string(symbol));

		fp->flags = 0;
		if (lilv_port_is_a(p->p, port, c->lv2_InputPort))
			fp->flags |= SPA_FGA_PORT_INPUT;
		if (lilv_port_is_a(p->p, port, c->lv2_OutputPort))
			fp->flags |= SPA_FGA_PORT_OUTPUT;
		if (lilv_port_is_a(p->p, port, c->lv2_ControlPort))
			fp->flags |= SPA_FGA_PORT_CONTROL;
		if (lilv_port_is_a(p->p, port, c->lv2_AudioPort))
			fp->flags |= SPA_FGA_PORT_AUDIO;
		if (lilv_port_has_property(p->p, port, c->lv2_Optional))
			fp->flags |= SPA_FGA_PORT_SUPPORTS_NULL_DATA;

		fp->hint = 0;
		if (latent && latency_index == i)
			fp->hint |= SPA_FGA_HINT_LATENCY;

		fp->min = mins[i];
		fp->max = maxes[i];
		fp->def = controls[i];

		if (isnan(fp->min))
			fp->min = -FLT_MAX;
		if (isnan(fp->max))
			fp->max = FLT_MAX;
		if (isnan(fp->def))
			fp->def = 0.0f;
		if (fp->max <= fp->min)
			fp->max = FLT_MAX;
		if (fp->def <= fp->min)
			fp->min = -FLT_MAX;
	}
	return &desc->desc;
}

static struct spa_fga_plugin_methods impl_plugin = {
	SPA_VERSION_FGA_PLUGIN_METHODS,
	.make_desc = lv2_plugin_make_desc,
};

static int impl_get_interface(struct spa_handle *handle, const char *type, void **interface)
{
	struct plugin *impl;

	spa_return_val_if_fail(handle != NULL, -EINVAL);
	spa_return_val_if_fail(interface != NULL, -EINVAL);

	impl = (struct plugin *) handle;

	if (spa_streq(type, SPA_TYPE_INTERFACE_FILTER_GRAPH_AudioPlugin))
		*interface = &impl->plugin;
	else
		return -ENOENT;

	return 0;
}

static int impl_clear(struct spa_handle *handle)
{
	struct plugin *p = (struct plugin *)handle;
	context_unref(p->c);
	return 0;
}

static size_t
impl_get_size(const struct spa_handle_factory *factory,
	      const struct spa_dict *params)
{
	return sizeof(struct plugin);
}

static int
impl_init(const struct spa_handle_factory *factory,
	  struct spa_handle *handle,
	  const struct spa_dict *info,
	  const struct spa_support *support,
	  uint32_t n_support)
{
	struct plugin *impl;
	uint32_t i;
	int res;
	const char *path = NULL;
	const LilvPlugins *plugins;
	LilvNode *uri;

	handle->get_interface = impl_get_interface;
	handle->clear = impl_clear;

	impl = (struct plugin *) handle;
	impl->log = spa_support_find(support, n_support, SPA_TYPE_INTERFACE_Log);
	impl->data_loop = spa_support_find(support, n_support, SPA_TYPE_INTERFACE_DataLoop);
	impl->main_loop = spa_support_find(support, n_support, SPA_TYPE_INTERFACE_Loop);

	for (i = 0; info && i < info->n_items; i++) {
		const char *k = info->items[i].key;
		const char *s = info->items[i].value;
		if (spa_streq(k, "filter.graph.path"))
			path = s;
	}
	if (path == NULL)
		return -EINVAL;

	impl->c = context_ref();
	if (impl->c == NULL)
		return -EINVAL;

	uri = lilv_new_uri(impl->c->world, path);
	if (uri == NULL) {
		spa_log_warn(impl->log, "invalid URI %s", path);
		res = -EINVAL;
		goto error_cleanup;
	}

	plugins = lilv_world_get_all_plugins(impl->c->world);
	impl->p = lilv_plugins_get_by_uri(plugins, uri);
	lilv_node_free(uri);

	if (impl->p == NULL) {
		spa_log_warn(impl->log, "can't load plugin %s", path);
		res = -EINVAL;
		goto error_cleanup;
	}
	impl->plugin.iface = SPA_INTERFACE_INIT(
			SPA_TYPE_INTERFACE_FILTER_GRAPH_AudioPlugin,
			SPA_VERSION_FGA_PLUGIN,
			&impl_plugin, impl);

	return 0;

error_cleanup:
	if (impl->c)
		context_unref(impl->c);
	return res;
}


static const struct spa_interface_info impl_interfaces[] = {
	{ SPA_TYPE_INTERFACE_FILTER_GRAPH_AudioPlugin },
};

static int
impl_enum_interface_info(const struct spa_handle_factory *factory,
			 const struct spa_interface_info **info,
			 uint32_t *index)
{
	spa_return_val_if_fail(factory != NULL, -EINVAL);
	spa_return_val_if_fail(info != NULL, -EINVAL);
	spa_return_val_if_fail(index != NULL, -EINVAL);

	switch (*index) {
	case 0:
		*info = &impl_interfaces[*index];
		break;
	default:
		return 0;
	}
	(*index)++;
	return 1;
}

static struct spa_handle_factory spa_fga_plugin_lv2_factory = {
	SPA_VERSION_HANDLE_FACTORY,
	"filter.graph.plugin.lv2",
	NULL,
	impl_get_size,
	impl_init,
	impl_enum_interface_info,
};

SPA_EXPORT
int spa_handle_factory_enum(const struct spa_handle_factory **factory, uint32_t *index)
{
	spa_return_val_if_fail(factory != NULL, -EINVAL);
	spa_return_val_if_fail(index != NULL, -EINVAL);

	switch (*index) {
	case 0:
		*factory = &spa_fga_plugin_lv2_factory;
		break;
	default:
		return 0;
	}
	(*index)++;
	return 1;
}
