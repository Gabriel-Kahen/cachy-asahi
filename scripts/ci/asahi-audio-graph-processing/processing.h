/* SPDX-License-Identifier: MIT
 * Fixed finite synthetic-buffer checks; no device/service/plugin loader.
 * Sample file: IEEE binary32 little endian, block-major then channel-major.
 */
#ifndef ASAHI_GRAPH_PROCESSING_H
#define ASAHI_GRAPH_PROCESSING_H
#include <float.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROCESS_FRAMES 1024u
#define PROCESS_BLOCKS 128u
#define PROCESS_GUARDS 8u
#define PROCESS_INPUTS 3u
#define PROCESS_OUTPUTS 6u
#define PROCESS_CANARY 12345.25f
#define PROCESS_SILENCE_LIMIT 1e-7
_Static_assert(sizeof(float)==4 && FLT_RADIX==2 && FLT_MANT_DIG==24 && FLT_MAX_EXP==128,
               "IEEE binary32 samples required");

struct processing_metrics {
    unsigned calls, inputs, outputs;
    bool input_immutable, guards, finite, duplicates;
    double peak[PROCESS_OUTPUTS], energy[PROCESS_OUTPUTS];
    size_t bytes;
};
struct processing_buffer {
    float before[PROCESS_GUARDS], data[PROCESS_FRAMES], after[PROCESS_GUARDS];
};
enum processing_error {
    PROCESS_OK, PROCESS_ARGUMENT, PROCESS_ALLOCATION, PROCESS_API,
    PROCESS_GUARD, PROCESS_INPUT, PROCESS_FINITE, PROCESS_DUPLICATE,
    PROCESS_WRITE, PROCESS_SILENCE, PROCESS_ENERGY
};
typedef int (*processing_callback)(void *, const void *[], void *[], uint32_t);

static bool processing_guards(const struct processing_buffer *b)
{
    for (unsigned i=0;i<PROCESS_GUARDS;i++)
        if (b->before[i]!=PROCESS_CANARY || b->after[i]!=PROCESS_CANARY) return false;
    return true;
}
static enum processing_error processing_stream(unsigned inputs, unsigned outputs,
        bool silence, bool duplicate_woofers, processing_callback process,
        void *object, FILE *samples, struct processing_metrics *m)
{
    struct processing_buffer *in[PROCESS_INPUTS]={0}, *out[PROCESS_OUTPUTS]={0};
    float snapshot[PROCESS_INPUTS][PROCESS_FRAMES];
    const void *input[PROCESS_INPUTS]={0}; void *output[PROCESS_OUTPUTS]={0};
    uint32_t seed[PROCESS_INPUTS];
    enum processing_error error=PROCESS_ARGUMENT;
    uint32_t endian=1;
    if (!m) return error;
    memset(m,0,sizeof(*m)); m->inputs=inputs; m->outputs=outputs;
    m->input_immutable=m->guards=m->finite=m->duplicates=true;
    if (!inputs || inputs>PROCESS_INPUTS || !outputs || outputs>PROCESS_OUTPUTS ||
        !process || !samples || *(const unsigned char *)&endian!=1 ||
        (duplicate_woofers && outputs!=6)) return error;
    error=PROCESS_ALLOCATION;
    for (unsigned c=0;c<inputs;c++) {
        if (!(in[c]=calloc(1,sizeof(*in[c])))) goto done;
        input[c]=in[c]->data;
        seed[c]=UINT32_C(0x2468ace1) ^ (UINT32_C(0x9e3779b9)*(c+1));
        for (unsigned g=0;g<PROCESS_GUARDS;g++)
            in[c]->before[g]=in[c]->after[g]=PROCESS_CANARY;
    }
    for (unsigned c=0;c<outputs;c++) {
        if (!(out[c]=calloc(1,sizeof(*out[c])))) goto done;
        output[c]=out[c]->data;
        for (unsigned g=0;g<PROCESS_GUARDS;g++)
            out[c]->before[g]=out[c]->after[g]=PROCESS_CANARY;
    }
    for (unsigned block=0;block<PROCESS_BLOCKS;block++) {
        for (unsigned c=0;c<inputs;c++) {
            for (unsigned f=0;f<PROCESS_FRAMES;f++) {
                seed[c]=UINT32_C(1664525)*seed[c]+UINT32_C(1013904223);
                int32_t value=(int32_t)(seed[c]>>16)-32768;
                in[c]->data[f]=silence ? 0.0f : (float)value/67108864.0f;
            }
            memcpy(snapshot[c],in[c]->data,sizeof(snapshot[c]));
        }
        for (unsigned c=0;c<outputs;c++)
            for (unsigned f=0;f<PROCESS_FRAMES;f++) out[c]->data[f]=NAN;
        int result=process(object,input,output,PROCESS_FRAMES); m->calls++;
        if (result<0) { error=PROCESS_API; goto done; }
        for (unsigned c=0;c<inputs;c++) {
            if (!processing_guards(in[c])) {
                m->guards=false; error=PROCESS_GUARD; goto done;
            }
            if (memcmp(snapshot[c],in[c]->data,sizeof(snapshot[c]))) {
                m->input_immutable=false; error=PROCESS_INPUT; goto done;
            }
        }
        for (unsigned c=0;c<outputs;c++) {
            if (!processing_guards(out[c])) {
                m->guards=false; error=PROCESS_GUARD; goto done;
            }
            for (unsigned f=0;f<PROCESS_FRAMES;f++) {
                double value=out[c]->data[f];
                if (!isfinite(value)) { m->finite=false; error=PROCESS_FINITE; goto done; }
                double magnitude=fabs(value);
                if (magnitude>m->peak[c]) m->peak[c]=magnitude;
                m->energy[c]+=value*value;
            }
        }
        if (duplicate_woofers &&
            (memcmp(out[0]->data,out[4]->data,sizeof(out[0]->data)) ||
             memcmp(out[1]->data,out[5]->data,sizeof(out[1]->data)))) {
            m->duplicates=false; error=PROCESS_DUPLICATE; goto done;
        }
        for (unsigned c=0;c<outputs;c++) {
            if (fwrite(out[c]->data,sizeof(float),PROCESS_FRAMES,samples)!=PROCESS_FRAMES) {
                error=PROCESS_WRITE; goto done;
            }
            m->bytes+=PROCESS_FRAMES*sizeof(float);
        }
    }
    for (unsigned c=0;c<outputs;c++) {
        if (!isfinite(m->energy[c]) || !isfinite(m->peak[c])) {
            m->finite=false; error=PROCESS_FINITE; goto done;
        }
        if (silence && m->peak[c]>PROCESS_SILENCE_LIMIT) { error=PROCESS_SILENCE; goto done; }
        if (!silence && !(m->energy[c]>0)) { error=PROCESS_ENERGY; goto done; }
    }
    error=PROCESS_OK;
done:
    for (unsigned c=0;c<PROCESS_INPUTS;c++) free(in[c]);
    for (unsigned c=0;c<PROCESS_OUTPUTS;c++) free(out[c]);
    return error;
}
#endif
