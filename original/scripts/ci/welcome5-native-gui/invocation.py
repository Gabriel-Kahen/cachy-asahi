# SPDX-License-Identifier: MIT
"""Exact bounded wrapper argv receipt. This helper never admits a workflow/run."""
import hashlib,json,os,re
from pathlib import Path
PURPOSE='WELCOME5_DNS_GUI_ACTUAL_WRAPPER_INVOCATION'
CAP=32768

def need(ok,message):
    if not ok:raise ValueError(message)
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def pin(path):
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def absolute(value):
    need(type(value)is str and 0<len(value)<=4096 and not any(c in value for c in '\0\r\n'),'bounded actual path required')
    path=Path(value);need(path.is_absolute()and '..'not in path.parts,'ordinary actual path required');return path

def expected(proof):
    # The owner and passive reader separately authenticate the complete source,
    # actual run and proof. This function only preserves their exact argv join.
    profile=proof.get('profile');need(profile in ('minimal','overlay'),'explicit actual profile required')
    source=absolute(proof['source_path']);runtime=absolute(proof['runtime_path']);temp=runtime.parent
    need(runtime.name=='welcome5-runtime','fixed actual runtime directory required')
    return ['run','--source',str(source),'--profile',profile,'--proof',str(temp/'welcome5-proof.json'),
        '--base',str(temp/('desktop574-'+profile)),'--runtime',str(runtime),'--assets',str(temp/'welcome5-assets')]

def validate(value,proof,proof_pin,manifest_pin,runner_pin):
    need(type(value)is dict and set(value)=={'schema_version','purpose','profile','argv','source_proof','source_manifest','runner_proof'},'closed wrapper receipt required')
    need(value.get('schema_version')==1 and value.get('purpose')==PURPOSE and value.get('profile')==proof['profile']and value.get('argv')==expected(proof),'exact actual wrapper argv/profile differs')
    for key,reference in [('source_proof',proof_pin),('source_manifest',manifest_pin),('runner_proof',runner_pin)]:
        need(type(reference)is dict and set(reference)=={'bytes','sha256'}and type(reference['bytes'])is int and 0<reference['bytes']<=2*1024**2 and re.fullmatch('[0-9a-f]{64}',reference['sha256']or'')and value[key]==reference,'actual wrapper '+key+' byte pin differs')
    need(proof.get('manifest_sha256')==manifest_pin['sha256']and len(encoded(value))<=CAP,'wrapper manifest or byte bound differs')
    return value

def write(path,argv,proof,proof_pin,manifest_pin,runner_pin):
    value=dict(schema_version=1,purpose=PURPOSE,profile=proof['profile'],argv=argv,source_proof=proof_pin,source_manifest=manifest_pin,runner_proof=runner_pin)
    validate(value,proof,proof_pin,manifest_pin,runner_pin)
    raw=encoded(value);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
    return value
