# SPDX-License-Identifier: MIT
"""Present-state descriptors; deliberately no absence or restoration policy."""
import importlib.util,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
PARENTS=('etc','etc/audit','etc/udev')
def dep(name):
 s=importlib.util.spec_from_file_location('initialized_context_'+name,HERE/'_initialized'/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def selected(cert):
 return cert['_initialized_state'] if '_initialized_state'in cert else json.loads(Path('/packet/initialized-state.DATA.json').read_bytes())
def context(K,cert,lock,nonce,case_pin):
 K.need(type(nonce)is str and len(nonce)==32 and all(c in'0123456789abcdef'for c in nonce),'fresh literal initialized lifecycle nonce')
 return dict(kind='PERL5423_INITIALIZED_PREBOOT_CONTEXT_V1',nonce=nonce,Source_lock=lock,case=case_pin,baseline_certificate=K.json_pin(cert['baseline_certificate']),baseline_raw=cert['baseline_certificate']['raw'],baseline_prepared=cert['baseline_certificate']['prepared'],baseline_namespace=cert['runtime_certificate']['baseline_namespace_pin'],initialized_state=K.json_pin(selected(cert)),cold_cleanup=False,root_ssh='PRESERVE_EXISTING_VERIFIED_EMPTY')
def descriptor(K,I,packet,cert,scan,context_raw):
 expected=context(K,cert,packet['Source_lock'],packet['nonce'],packet['case']);K.need(context_raw==K.canonical(expected),'exact initialized case/Source/nonce/context')
 snap=dep('policy').snapshot(scan);K.need(K.json_pin(snap)==expected['initialized_state'],'exact qualified initialized snapshot before preparing')
 K.need(K.json_pin({n:I.stable(v)for n,v in scan['nodes'].items()})==expected['baseline_namespace'],'complete authenticated initialized preboot namespace')
 rows=[]
 for path in [p for p,_,_ in dep('policy').PUBLIC]+list(dep('policy').PARENTS)+['root/.ssh']:
  r=scan['nodes'][path];kind={'file':'f','directory':'d','symlink':'l'}[r['type']];payload=r.get('sha256',r.get('target_b64','-'))
  rows.append('N '+path+' '+' '.join(str(r[n])for n in('inode','links'))+' '+kind+' '+format(r['mode'],'o')+' '+' '.join(str(r[n])for n in('uid','gid','size'))+' '+str(r['mtime'])+'.'+format(r['mtime_ns'],'09d')+' '+payload+'\n')
 raw=('PERL5423_INITIALIZED_STATE_V1 '+packet['nonce']+' '+K.json_pin(expected)['sha256']+'\n'+''.join(rows)).encode();K.need(len(raw)<=8192,'bounded initialized descriptor');return raw
def preserve_etc(K,before,after):
 fields=('inode','links','type','mode','uid','gid','xattrs','mtime','mtime_ns')
 for p in PARENTS:K.need(all(n in before['nodes'][p]and before['nodes'][p][n]==after['nodes'].get(p,{}).get(n)for n in fields),'exact initialized parent inode metadata and mtime')
def preserve(K,before,after):
 K.need(dep('policy').snapshot(before)==dep('policy').snapshot(after),'exact initialized public9/parents/existing empty SSH preserved; no repair')
