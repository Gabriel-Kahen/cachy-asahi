# SPDX-License-Identifier: MIT
"""Bounded public DATA derived only after authenticated readonly preboot scan."""
PARENTS=('etc','etc/audit','etc/udev')
ABSENCE_POLICY=(
 ('etc/.pwd.lock','f','600',0),
 ('etc/.updated','f','644',4096),
 ('etc/audisp','d','755',0),
 ('etc/audit/plugins.d','d','750',0),
 ('etc/audit/rules.d','d','755',0),
 ('etc/ld.so.cache','f','644',1048576),
 ('etc/os-release','l','777',4096),
 ('etc/udev/hwdb.bin','f','444',16777216),
 ('etc/vconsole.conf','f','644',4096),
)
PRESERVATION_ERROR='exact original preboot parent identity metadata and mtime'


def context(K,cert,lock,nonce,case_pin):
 return dict(kind='PERL5423_PREBOOT_CONTEXT_V2',nonce=nonce,Source_lock=lock,case=case_pin,
  baseline_certificate=K.json_pin(cert['baseline_certificate']),baseline_raw=cert['baseline_certificate']['raw'],
  baseline_prepared=cert['baseline_certificate']['prepared'],baseline_namespace=cert['runtime_certificate']['baseline_namespace_pin'],
  parents=list(PARENTS),absence_policy=[dict(path=p,kind=k,mode=m,cap=c)for p,k,m,c in ABSENCE_POLICY])


def descriptor(K,I,packet,cert,scan,context_raw):
 expected=context(K,cert,packet['Source_lock'],packet['nonce'],packet['case'])
 K.need(context_raw==K.canonical(expected),'exact packet Source/case/nonce/baseline preboot context')
 nodes=scan['nodes'];rows=[]
 for path in PARENTS:
  row=nodes.get(path,{})
  K.need(all(type(row.get(n))is int for n in ('mode','uid','gid'))and row.get('type')=='directory'and row['mode']==0o755 and row['uid']==row['gid']==0,'ordinary certified preboot parent directory: '+path)
  for key,low,high in [('inode',1,2**32-1),('links',2,65535),('mtime',0,2**33-1),('mtime_ns',0,999999999)]:
   K.need(type(row.get(key))is int and low<=row[key]<=high,'bounded preboot parent '+key+': '+path)
  rows.append('P '+path+' '+' '.join(str(row[n])for n in ('inode','links','mtime','mtime_ns'))+'\n')
 for path,kind,mode,cap in ABSENCE_POLICY:
  K.need(not any(n==path or n.startswith(path+'/')for n in nodes),'certified preboot policy path and descendants absent: '+path)
  rows.append('A '+path+' '+kind+' '+mode+' '+str(cap)+'\n')
 # The independently pinned whole raw certifies times; stable omits directory time.
 K.need(K.json_pin({n:I.stable(v)for n,v in nodes.items()})==expected['baseline_namespace'],'authenticated complete preboot namespace')
 text='PERL5423_PREBOOT_ETC_V2 '+packet['nonce']+' '+K.json_pin(expected)['sha256']+'\n'+''.join(rows)
 K.need(len(text)<=4096,'bounded preboot etc descriptor')
 return text.encode()


def preserve_etc(K,before,after):
 # Atime protection applies to timestamp restoration itself, not the whole boot.
 # Never normalize final parent identity, links, xattrs or mtime.
 fields=('inode','links','type','mode','uid','gid','xattrs','mtime','mtime_ns')
 for path in PARENTS:
  left=before['nodes'].get(path,{});right=after['nodes'].get(path,{})
  K.need(all(type(left.get(n))is type(right.get(n))is int for n in ('inode','links','mode','uid','gid','mtime','mtime_ns'))and
   left.get('type')=='directory'and type(left.get('xattrs'))is type(right.get('xattrs'))is dict and
   all(n in left and left[n]==right.get(n)for n in fields),PRESERVATION_ERROR)
