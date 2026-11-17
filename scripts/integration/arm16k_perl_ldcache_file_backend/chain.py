"""Exact immutable529 qcow2/raw + ordinary file backend graph, pure DATA only."""
import hashlib,json
RAW_BYTES=1610612736
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def chain(raw,overlay_bytes):
 need(type(raw)is bytes and 0<len(raw)<=16384,'bounded qemu-img chain frame')
 need(type(overlay_bytes)is int and 0<overlay_bytes<=4294967296,'Root whole-pinned overlay EOF')
 def unique(rows):
  result={}
  for k,v in rows:need(k not in result,'duplicate chain JSON key');result[k]=v
  return result
 def exact(got,wanted):
  if type(got)is not type(wanted):return False
  if type(wanted)is dict:return set(got)==set(wanted)and all(exact(got[k],wanted[k])for k in wanted)
  return got==wanted
 rows=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:need(False,'finite JSON only'))
 need(type(rows)is list and len(rows)==2 and all(type(row)is dict for row in rows),'exact two-node chain only')
 common={'children','virtual-size','filename','format','actual-size','dirty-flag'}
 qcow_extra={'backing-filename-format','cluster-size','format-specific','full-backing-filename','backing-filename'}
 for row,name,kind,eof in zip(rows,('/inputs/overlay.qcow2','/prepared/guest.raw'),('qcow2','raw'),(overlay_bytes,RAW_BYTES)):
  need(set(row)==common|(qcow_extra if kind=='qcow2'else set()),'closed exact immutable529 format node fields')
  need(row['filename']==name and row['format']==kind and type(row['virtual-size'])is int and row['virtual-size']==RAW_BYTES and row['dirty-flag']is False,'fixed original chain paths/formats/virtual size and clean state')
  allocated=row['actual-size'];cap=268435456 if kind=='qcow2'else RAW_BYTES
  need(type(allocated)is int and 0<=allocated<=cap and allocated%512==0,'finite bounded format allocation')
  children=row['children'];need(type(children)is list and len(children)==1,'one ordinary file protocol backend only')
  child=children[0];need(type(child)is dict and set(child)=={'name','info'}and child['name']=='file','exact file backend child name/schema')
  info=child['info'];need(type(info)is dict and set(info)==common|{'format-specific'},'closed file protocol info fields')
  need(info['filename']==name and info['format']=='file'and type(info['virtual-size'])is int and info['virtual-size']==eof and info['dirty-flag']is False,'same pinned local file backend name/format/EOF')
  need(type(info['children'])is list and info['children']==[],'no nested or external backend children')
  need(type(info['actual-size'])is int and info['actual-size']==allocated,'same format/backend allocation')
  need(exact(info['format-specific'],{'type':'file','data':{}}),'ordinary file protocol only; no external graph fields')
 first=rows[0]
 need(first['backing-filename']==first['full-backing-filename']=='/prepared/guest.raw'and first['backing-filename-format']=='raw','original embedded absolute backing path, no rewrite/rebase')
 need(type(first['cluster-size'])is int and first['cluster-size']==65536,'frozen original qcow2 cluster geometry')
 need(exact(first['format-specific'],{'type':'qcow2','data':{'compat':'1.1','compression-type':'zlib','lazy-refcounts':False,'refcount-bits':16,'corrupt':False,'extended-l2':False}}),'exact original qcow2 flags; no encryption/corrupt/external data')
 return dict(status='EXACT_TWO_NODE_CHAIN_METADATA_ONLY',frame=pin(raw))
