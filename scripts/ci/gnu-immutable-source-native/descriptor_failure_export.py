# SPDX-License-Identifier: MIT
"""Counted diagnostic-only export derivative; original guards remain mandatory."""
import hashlib

BEFORE_PIN={'bytes':9932,'sha256':'046f37e8523d509b1bee678ac9f42bfc6d7532f701d958c7d812d006820a0331'}
RUNTIME_PATHS=(
 'runtime-vm/scripts/ci/glibc-debian-maintained-installed16k/export.py',)
PREFIX='GNU_RECOVERY_DESC_FAILURE_DATA '
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

SCHEMA_SOURCE=r'''
def descriptor_failure_value(raw,case):
    # Raw package DB evidence only. No comparison normalization or acceptance.
    import base64,hashlib,json,re
    def require(ok,why):
        if not ok:raise ValueError(why)
    def pairs(rows):
        value={}
        for key,item in rows:
            require(key not in value,'duplicate descriptor evidence field');value[key]=item
        return value
    def digest(value,nullable=False):
        return (nullable and value is None)or(type(value)is str and re.fullmatch('[a-f0-9]{64}',value)is not None)
    def count(value,maximum):return type(value)is int and 0<=value<=maximum
    require(type(raw)is bytes and 0<len(raw)<=256*1024,'bounded descriptor failure log')
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:require(False,'finite descriptor evidence'))
    require(type(value)is dict and set(value)=={'schema','operation','case','descriptor_path','before','after','comparison','database_checks','status','diagnostic'},'complete descriptor diagnostic schema')
    require(type(value['schema'])is int and value['schema']==1 and case in('pristine','modified')and value['case']==case and value['operation']in('remove-interruption','candidate-extraction-interruption'),'fixed case and operation descriptor diagnostic')
    require(type(value['descriptor_path'])is str and re.fullmatch(r'var/lib/pacman/local/glibc-[A-Za-z0-9][A-Za-z0-9.+_:~@-]{0,127}/desc',value['descriptor_path']),'only exact held glibc descriptor evidence')
    require(value['status']in('PASS','FAILURE_DIAGNOSTIC_NOT_ACCEPTANCE')and value['diagnostic']in(None,'BEFORE_DESCRIPTOR_GRAMMAR_REFUSED','ORIGINAL_EXERCISE_FAILED','ORIGINAL_EXERCISE_FAILED_CURRENT_DESCRIPTOR_UNAVAILABLE','RAW_DESCRIPTOR_OR_DATABASE_POSTCONDITION_REFUSED','POSTCONDITION_OBSERVATION_FAILED'),'finite source-owned descriptor outcome')
    for phase in('before','after'):
        row=value[phase]
        if row is None:
            require(phase=='after'and value['status']=='FAILURE_DIAGNOSTIC_NOT_ACCEPTANCE','only failed after evidence may be unavailable');continue
        require(type(row)is dict and set(row)=={'raw_base64','bytes','sha256','identity','logical_node','install_date','non_date_sha256','parse_error'},'complete raw descriptor capture')
        require(type(row['raw_base64'])is str and len(row['raw_base64'])<=87384 and count(row['bytes'],65536)and digest(row['sha256']),'bounded raw descriptor pin')
        try:body=base64.b64decode(row['raw_base64'],validate=True)
        except (ValueError,base64.binascii.Error):raise ValueError('canonical raw descriptor base64')
        require(base64.b64encode(body).decode('ascii')==row['raw_base64']and len(body)==row['bytes']and hashlib.sha256(body).hexdigest()==row['sha256'],'whole unmodified raw descriptor bytes and hash')
        require(row['logical_node']==dict(type='file',mode=420,uid=0,gid=0,bytes=len(body),sha256=row['sha256']),'plain root-owned0644 descriptor node')
        identity=row['identity'];require(type(identity)is list and len(identity)==9 and all(count(item,2**64-1)for item in identity)and identity[2:7]==[33188,0,0,1,len(body)],'whole bounded single-link raw descriptor identity')
        require((row['install_date']is None or count(row['install_date'],2**63-1))and digest(row['non_date_sha256'],True)and row['parse_error']in(None,'INVALID_CANONICAL_DESCRIPTOR'),'typed descriptor parse diagnostics')
    comparison=value['comparison'];flags={'metadata_equal','field_order_equal','field_values_equal_except_install_date','normalized_bytes_equal'}
    require(type(comparison)is dict and set(comparison)==flags|{'fields'}and all(type(comparison[key])is bool for key in flags)and type(comparison['fields'])is list and len(comparison['fields'])<=255,'complete finite comparison diagnostics')
    names=set()
    for row in comparison['fields']:
        require(type(row)is dict and set(row)=={'name','before_sha256','after_sha256','equal'}and type(row['name'])is str and re.fullmatch('[A-Z][A-Z0-9_]{0,63}',row['name'])and row['name']not in names and digest(row['before_sha256'],True)and digest(row['after_sha256'],True)and type(row['equal'])is bool,'bounded unique per-field diagnostics');names.add(row['name'])
    checks=value['database_checks']
    if checks is not None:
        counters={'base_packages','before_rows','after_rows'};hashes={'before_rows_sha256','after_rows_sha256'};flags={'rows_equal','inventory_equal','ownership_equal','unrelated_db_equal','held_other_db_equal','configs_equal','user_equal','capabilities_equal'}
        require(type(checks)is dict and set(checks)==counters|hashes|flags and checks['base_packages']==574 and type(checks['base_packages'])is int and checks['before_rows']==574 and type(checks['before_rows'])is int and count(checks['after_rows'],500000)and all(digest(checks[key])for key in hashes)and all(type(checks[key])is bool for key in flags),'complete bounded database postcondition diagnostics')
    return value

def descriptor_failure_emit(raw,case,request):
    import hashlib,json,re
    value=descriptor_failure_value(raw,case)
    if not(type(request)is dict and re.fullmatch('[a-f0-9]{32}',request.get('nonce')or'')and re.fullmatch('[a-f0-9]{40}',request.get('source_sha')or'')):
        raise ValueError('exact original failure diagnostic identity')
    reference=dict(path=case+'-recovery-db-descriptors.log',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    envelope=dict(schema=1,status='GNU_RECOVERY_DESC_FAILURE_DATA_ONLY',nonce=request['nonce'],source_sha=request['source_sha'],case=case,reference=reference,descriptor=value,acceptance=False,source_authority=False,native_authority=False,Root_acceptance=None)
    text=json.dumps(envelope,sort_keys=True,separators=(',',':'),allow_nan=False)
    if len(text.encode('ascii'))>300*1024:raise ValueError('bounded descriptor failure stdout record')
    print('GNU_RECOVERY_DESC_FAILURE_DATA '+text,flush=True)
    return dict(status='RAW_PACKAGE_DB_DIAGNOSTIC_ONLY_NO_ACCEPTANCE',reference=reference,stdout_prefix='GNU_RECOVERY_DESC_FAILURE_DATA ',acceptance=False,source_authority=False,native_authority=False)
'''

def derive(raw,case='pristine'):
 need(type(raw)is bytes and pin(raw)==BEFORE_PIN,'exact whole775 failure exporter before derivative')
 need(case in('pristine','modified'),'one explicitly selected diagnostic case')
 out=raw.decode('utf-8');rows=[]
 def change(before,after):
  nonlocal out
  need(out.count(before)==1,'one exact original exporter seam');out=out.replace(before,after,1);rows.append(dict(before=before,after=after,count=1))
 before="    for name,cap in (('result.json',8*1024**2),('pristine-guest-progress.log',65536)):"
 after=before[:-2]+",("+repr(case+'-recovery-db-descriptors.log')+",256*1024)):"
 change(before,after)
 before="            if name=='result.json':entry['projection']=diagnostic_projection(raw)\n            else:"
 after="            if name=='result.json':entry['projection']=diagnostic_projection(raw)\n            elif name=="+repr(case+'-recovery-db-descriptors.log')+":entry['descriptor_failure']=descriptor_failure_emit(raw,"+repr(case)+",request)\n            else:"
 change(before,after)
 change("if __name__=='__main__':main()",SCHEMA_SOURCE+"\nif __name__=='__main__':main()")
 encoded=out.encode('utf-8');need(inverse(encoded,rows)==raw,'whole exact exporter inverse');return encoded,rows

def inverse(after,edits):
 need(type(after)is bytes and type(edits)is list and len(edits)==3,'complete counted diagnostic exporter inverse');value=after.decode('utf-8')
 for row in reversed(edits):
  need(row['count']==1 and value.count(row['after'])==1,'one complete diagnostic exporter inverse seam');value=value.replace(row['after'],row['before'],1)
 raw=value.encode('utf-8');need(pin(raw)==BEFORE_PIN,'every original exporter byte recovered');return raw
