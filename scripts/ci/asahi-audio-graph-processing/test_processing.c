/* Inert negative-oracle controls. No native plugin or graph is loaded. */
#define _GNU_SOURCE
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned allocation_calls, allocation_fail_at, live_allocations;
static void *mock_calloc(size_t count,size_t bytes) {
    if (++allocation_calls==allocation_fail_at) return NULL;
    void *result=calloc(count,bytes); if (result) live_allocations++;
    return result;
}
static void mock_free(void *p) {
    if (p) { assert(live_allocations); live_allocations--; } free(p);
}
#define calloc mock_calloc
#define free mock_free
#include "processing.h"
#undef calloc
#undef free

enum mode { GOOD, OMIT, NAN_SAMPLE, INF_SAMPLE, INPUT_CHANGE, INPUT_GUARD,
    OUTPUT_GUARD, ZERO_GRAPH, BROKEN_COPY, API_ERROR, NONZERO_SILENCE, LATE_CHANGE };
struct mock { unsigned inputs, outputs, calls; bool silence; enum mode mode; };
static int mock_process(void *object,const void *input[],void *output[],uint32_t frames) {
    struct mock *m=object;
    assert(frames==PROCESS_FRAMES);
    const int first[]={14309,-11215,-1313};
    for (unsigned i=0;i<m->inputs;i++) {
        assert(input[i]);
        for (unsigned j=0;j<i;j++)
            assert((uintptr_t)input[i]+sizeof(float)*frames<=(uintptr_t)input[j] ||
                   (uintptr_t)input[j]+sizeof(float)*frames<=(uintptr_t)input[i]);
        for (unsigned j=0;j<m->outputs;j++)
            assert((uintptr_t)input[i]+sizeof(float)*frames<=(uintptr_t)output[j] ||
                   (uintptr_t)output[j]+sizeof(float)*frames<=(uintptr_t)input[i]);
        if (!m->calls) assert(((const float *)input[i])[0]==
                             (m->silence ? 0.0f : (float)first[i]/67108864.0f));
    }
    for (unsigned i=0;i<m->outputs;i++)
        for (unsigned j=0;j<i;j++)
            assert((uintptr_t)output[i]+sizeof(float)*frames<=(uintptr_t)output[j] ||
                   (uintptr_t)output[j]+sizeof(float)*frames<=(uintptr_t)output[i]);
    m->calls++;
    if (m->mode==API_ERROR) return -1;
    for (unsigned c=0;c<m->outputs;c++) {
        unsigned source=c==4 ? 0 : c==5 ? 1 : c % m->inputs;
        for (unsigned f=0;f<frames;f++) {
            if (m->mode==OMIT && c==0 && f==frames-1) continue;
            ((float *)output[c])[f]=m->mode==ZERO_GRAPH ? 0.0f :
                m->mode==NONZERO_SILENCE ? 0.01f : ((const float *)input[source])[f];
        }
    }
    if (m->mode==NAN_SAMPLE) ((float *)output[0])[frames-1]=NAN;
    if (m->mode==INF_SAMPLE) ((float *)output[0])[0]=INFINITY;
    if (m->mode==INPUT_CHANGE || (m->mode==LATE_CHANGE && m->calls==PROCESS_BLOCKS))
        ((float *)input[0])[0]+=1.0f;
    if (m->mode==INPUT_GUARD) {
        struct processing_buffer *p=(void *)((char *)input[0]-offsetof(struct processing_buffer,data));
        p->before[7]=0;
    }
    if (m->mode==OUTPUT_GUARD) {
        struct processing_buffer *p=(void *)((char *)output[0]-offsetof(struct processing_buffer,data));
        p->after[0]=0;
    }
    if (m->mode==BROKEN_COPY) ((float *)output[4])[8]+=1.0f;
    return 0;
}
static void check(const char *scratch,unsigned inputs,unsigned outputs,bool silence,
                  bool duplicate,enum mode mode,enum processing_error expected) {
    FILE *f=fopen(scratch,"wb+"); assert(f);
    struct mock mock={inputs,outputs,0,silence,mode};
    struct processing_metrics metrics;
    enum processing_error actual=processing_stream(inputs,outputs,silence,duplicate,
                                                    mock_process,&mock,f,&metrics);
    assert(actual==expected);
    assert(metrics.calls==mock.calls);
    assert(live_allocations==0);
    if (expected==PROCESS_OK) {
        assert(metrics.calls==128 && metrics.bytes==outputs*128u*1024u*4u);
        assert(ftell(f)==(long)metrics.bytes);
        assert(metrics.input_immutable && metrics.guards && metrics.finite && metrics.duplicates);
        for (unsigned c=0;c<outputs;c++)
            assert(silence ? metrics.peak[c]==0 : metrics.energy[c]>0);
    }
    if (mode==LATE_CHANGE) assert(mock.calls==128 && !metrics.input_immutable);
    if (mode==OUTPUT_GUARD || mode==INPUT_GUARD) assert(!metrics.guards);
    if (mode==BROKEN_COPY) assert(!metrics.duplicates);
    if (mode==OMIT || mode==NAN_SAMPLE || mode==INF_SAMPLE) assert(!metrics.finite);
    assert(fclose(f)==0);
}
int main(int argc,char **argv) {
    assert(argc==2);
    unsigned positives=0, negatives=0;
    const unsigned channels[][2]={{2,4},{2,6},{3,1}};
    for (unsigned c=0;c<3;c++) for (unsigned zero=0;zero<2;zero++) {
        check(argv[1],channels[c][0],channels[c][1],zero!=0,c==1,GOOD,PROCESS_OK); positives++;
    }
    const struct { enum mode mode; enum processing_error error; } errors[]={
        {OMIT,PROCESS_FINITE},{NAN_SAMPLE,PROCESS_FINITE},{INF_SAMPLE,PROCESS_FINITE},
        {INPUT_CHANGE,PROCESS_INPUT},{INPUT_GUARD,PROCESS_GUARD},{OUTPUT_GUARD,PROCESS_GUARD},
        {ZERO_GRAPH,PROCESS_ENERGY},{BROKEN_COPY,PROCESS_DUPLICATE},{API_ERROR,PROCESS_API},
        {LATE_CHANGE,PROCESS_INPUT}};
    for (unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++) {
        check(argv[1],2,6,false,true,errors[i].mode,errors[i].error); negatives++;
    }
    check(argv[1],2,4,true,false,NONZERO_SILENCE,PROCESS_SILENCE); negatives++;
    for (unsigned fail=1;fail<=4;fail++) {
        allocation_calls=0; allocation_fail_at=fail;
        check(argv[1],3,1,false,false,GOOD,PROCESS_ALLOCATION); negatives++;
    }
    allocation_fail_at=0;
    char bytes[32]; FILE *limited=fmemopen(bytes,sizeof(bytes),"w"); assert(limited);
    assert(setvbuf(limited,NULL,_IONBF,0)==0);
    struct mock mock={2,4,0,false,GOOD}; struct processing_metrics metrics;
    assert(processing_stream(2,4,false,false,mock_process,&mock,limited,&metrics)==PROCESS_WRITE);
    assert(live_allocations==0); (void)fclose(limited); negatives++;
    assert(remove(argv[1])==0);
    printf("PASS inert C oracle controls: %u positive, %u negative; no plugin/graph actors\n",positives,negatives);
    return 0;
}
