# SPDX-License-Identifier: MIT
"""Retain bounded original failure DATA; never a positive native result."""
import os,re,time
from pathlib import Path
import transport as T
from transport import need,pin,obj,safe,M,PACKET,FILE,TOTAL,MAX_FILES,RECONSTRUCTION,SCOPE

def reconstruct_bytes(packets):
 need(set(packets['part-0000'])=={'retention.json'},'exact original index frame');raw=packets['part-0000']['retention.json'];index=obj(raw)
 need(set(index)=={'files','bytes','cap','packet_raw_cap','packet_count','reconstruction','scope'}and index['cap']==TOTAL and index['packet_raw_cap']==PACKET and index['reconstruction']==RECONSTRUCTION and index['scope']==SCOPE,'whole original retention schema/bounds')
 count=index['packet_count'];need(type(count)is int and 0<=count<=35 and set(packets)=={'part-%04d'%n for n in range(count+1)},'complete original contiguous frame closure');files=index['files'];need(type(files)is dict and len(files)<=MAX_FILES and type(index['bytes'])is int and 0<=index['bytes']<=TOTAL,'original file count/aggregate');values={};used=set();ids=set();total=0
 for name,row in files.items():
  safe(name);need(type(row)is dict and set(row)=={'bytes','sha256','chunks'}and type(row['bytes'])is int and 0<=row['bytes']<=FILE and re.fullmatch('[a-f0-9]{64}',row['sha256'])and type(row['chunks'])is list and len(row['chunks'])<=8,'whole original file reference');data=bytearray()
  for number,ref in enumerate(row['chunks']):
   need(set(ref)=={'packet','path','bytes','sha256'}and ref['packet']in packets and ref['packet']!='part-0000'and re.fullmatch(r'chunk-[0-9]{4}\.bin',ref['path']),'exact original chunk reference');key=(ref['packet'],ref['path']);need(key not in used and ref['path']in packets[ref['packet']],'original chunk unique/existing');chunk=packets[ref['packet']][ref['path']];need(type(ref['bytes'])is int and 0<len(chunk)<=PACKET and pin(chunk)=={k:ref[k]for k in('bytes','sha256')}and(number==len(row['chunks'])-1 or len(chunk)==PACKET),'whole original chunk bytes and position');used.add(key);ident=int(ref['path'][6:10]);need(ident not in ids,'unique global chunk number');ids.add(ident);data.extend(chunk);need(len(data)<=row['bytes'],'original fullfile cap')
  value=bytes(data);need(pin(value)=={k:row[k]for k in('bytes','sha256')},'whole reassembled original file');values[name]=value;total+=len(value);need(total<=TOTAL,'original aggregate cap')
 expected={(label,name)for label,group in packets.items()if label!='part-0000'for name in group};need(used==expected and ids==set(range(1,len(ids)+1))and total==index['bytes'],'all original chunks used, total exact')
 need(total-len(values.get('report.json',b''))<=64*M,'original public64MiB cap')
 return raw,values

def diagnose(step, original_error):
 need(type(original_error)is ValueError and str(original_error)=='whole original retained input closure', 'only exact retained-input semantic refusal')
 packets,frames=T.decode_step(step)
 # Every original chunk, full-file, aggregate and public-byte check runs above
 # the two product semantic checks, copied byte-for-byte from the pinned source.
 index,files=reconstruct_bytes(packets)
 try:T.reconstruct(packets)
 except ValueError as error:need(str(error)==str(original_error),'same original semantic refusal')
 else:raise ValueError('successful closure cannot enter failure DATA route')
 refs=obj(files['input-summary.json'])['retention'];need(type(refs)is list and len(refs)<=1024,'original input reference count')
 missing=[]
 for ref in refs:
  name='inputs/'+safe(ref['root'])+'/'+safe(ref['ref']['path'])
  expected={k:ref['ref'][k]for k in('bytes','sha256')}
  need(type(expected['bytes'])is int and 0<=expected['bytes']<=FILE and type(expected['sha256'])is str and re.fullmatch('[a-f0-9]{64}',expected['sha256']),'bounded declared input identity')
  if name not in files:missing.append(dict(path=name,expected=expected,actual=None,reason='MISSING'))
  elif pin(files[name])!=expected:missing.append(dict(path=name,expected=expected,actual=pin(files[name]),reason='PIN_MISMATCH'))
 need(missing,'actual retained-input semantic defect required')
 return index,files,frames,missing

def retain(step, original_error, output, p, env, started):
 need(env.get('CAA_BOOT607_COMPOSITION_OUTCOME')=='failure','explicit failed original composition only')
 need(p==T.BOOT607_POLICY,'complete Boot607-only transport policy')
 ctx=T.context(p,env);output=Path(output).absolute()
 need(not output.exists() and output.parent.is_dir() and not any(q.is_symlink()for q in(output,*output.parents)),'fresh separate ordinary failure output')
 parent=output.parent.stat();need(parent.st_uid==os.getuid()and not(parent.st_mode&0o022),'caller-owned output parent without foreign write access')
 index,files,frames,missing=diagnose(step,original_error)
 nonce_raw=files.get(p['nonce_path']);need(nonce_raw is not None and len(nonce_raw)<=65536,'original indexed nonce document required')
 nonce=obj(nonce_raw).get(p['nonce_field']);need(type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce),'actual original owner nonce required')
 seconds=time.monotonic()-started;need(0<=seconds<=90,'original shared capture deadline')
 receipt=dict(purpose='SOURCE_OWNED_BOOT607_FAILURE_DATA_V1',status='ORIGINAL_FRAMED_DATA_WITH_FAILED_INPUT_CLOSURE',
  context=dict(ctx,nonce=nonce),capture_source=pin(T.read(Path(T.__file__),M)),
  failure_source=pin(T.read(Path(__file__),M)),policy=pin(T.encoded(p)),encoder=T.ENCODER,
  frames=frames,retention_index=pin(index),nonce_reference=dict(path=p['nonce_path'],field=p['nonce_field'],**pin(nonce_raw)),
  stdout=pin(step),semantic_error=str(original_error),input_summary=pin(files['input-summary.json']),missing_inputs=missing,
  clock=dict(seconds=seconds,time_limit=90),original_composition_outcome='failure',
  acceptance='NOT_GRANTED',cleanup='UNKNOWN',hardware='NOT_RUN',release='NOT_ADMITTED')
 raw=T.encoded(receipt);need(len(raw)<=M,'bounded failure receipt')
 output.mkdir(mode=0o700);T.write(output/'retention-step.txt',step);T.write(output/'transport.json',raw)
 return receipt
