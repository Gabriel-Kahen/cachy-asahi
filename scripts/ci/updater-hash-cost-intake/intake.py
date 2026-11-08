"""Passive exact-original intake API. Operator installs actor denial before import.

Inputs are already acquired original metadata and artifact bytes; no downloads,
source preparation, lifecycle acceptance, retry or disk mutation is performed.
The unchanged static closed-reader guard runs through explicit C.binding.
"""
import context as C
import transport_v2 as T

def qualify(raws,binding_path):
 C.need(type(raws)is dict and set(raws)=={'run.json','jobs.json','artifacts.json','artifact.zip'},'exact supplied original input roles')
 caps={'run.json':2*C.P.M,'jobs.json':2*C.P.M,'artifacts.json':2*C.P.M,'artifact.zip':16*C.P.M}
 for name,raw in raws.items():C.need(type(raw)is bytes and 0<len(raw)<=caps[name],'bounded supplied original '+name)
 bound=C.binding(binding_path)
 run=C.obj(raws['run.json']);T.identity(run,bound,False)
 job=T.jobs(C.obj(raws['jobs.json']),run,False)
 artifact=T.metadata(run,C.obj(raws['artifacts.json']),bound)
 C.need(artifact is not None,'original source-owned artifact required')
 inner,data,telemetry=T.decode_bound(raws['artifact.zip'],artifact,bound)
 T.source_join(data,bound)
 return dict(status='SOURCE_BOUND_UPDATER_PASSIVE_DATA_NOT_ACCEPTANCE',source=bound['source'],ref=bound['ref'],run=bound['run'],attempt=1,case=bound['case'],job=job['id'],artifact=artifact['id'],originals={n:C.pin(b)for n,b in raws.items()},inner=C.pin(inner),retained={n:C.pin(b)for n,b in data.items()},telemetry=telemetry,Root_acceptance=None,normal_updater_acceptance=False)
