# SPDX-License-Identifier: MIT
"""Fixed public root-directory metadata DATA; never opens SSH or image contents."""
import importlib.util
from pathlib import Path
HERE=Path(__file__).resolve().parent
POLICY=dict(kind='ROOT_SSH_PREBOOT_V1',parent='root',path='root/.ssh',node_kind='d',mode='700',cap=0,descriptor_max_bytes=1024,late_empty_creation=True,private_contents=False)
PRESERVATION_ERROR='exact original preboot root identity metadata and mtime'
BOUNDS=(('inode',1,2**32-1),('links',2,65535),('mtime',0,2**33-1),('mtime_ns',0,999999999))


def _preboot():
 spec=importlib.util.spec_from_file_location('root_ssh_preboot_context',HERE/'preboot.py')
 value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def _ordinary_root(row):
 return (type(row)is dict and row.get('type')=='directory'and
  all(type(row.get(n))is int for n in ('mode','uid','gid'))and row['mode']==0o700 and row['uid']==row['gid']==0 and
  type(row.get('xattrs'))is dict and all(type(row.get(n))is int and low<=row[n]<=high for n,low,high in BOUNDS))


def _absent(nodes):
 return not any(n=='root/.ssh'or n.startswith('root/.ssh/')for n in nodes)


def descriptor(K,I,packet,cert,scan,context_raw):
 nonce=packet['nonce']
 K.need(type(nonce)is str and len(nonce)==32 and all(c in '0123456789abcdef'for c in nonce),'literal root SSH preboot nonce')
 expected=_preboot().context(K,cert,packet['Source_lock'],nonce,packet['case'])
 K.need(K.canonical(expected.get('root_ssh_policy'))==K.canonical(POLICY),'fixed root SSH preboot policy')
 K.need(context_raw==K.canonical(expected),'exact packet Source/case/nonce/baseline root SSH context')
 nodes=scan['nodes'];row=nodes.get('root',{})
 K.need(_ordinary_root(row),'ordinary bounded certified preboot root directory')
 # Check names before visiting any selected subtree row. No private contents are read.
 K.need(_absent(nodes),'certified preboot root SSH path and descendants absent')
 K.need(K.json_pin({n:I.stable(v)for n,v in nodes.items()})==expected['baseline_namespace'],'authenticated complete root SSH preboot namespace')
 raw=('PERL5423_ROOT_SSH_PREBOOT_V1 '+nonce+' '+K.json_pin(expected)['sha256']+'\nP root '+
  ' '.join(str(row[n])for n in ('inode','links','mtime','mtime_ns'))+'\nA root/.ssh d 700 0\n').encode()
 K.need(len(raw)<=1024,'bounded root SSH preboot descriptor')
 return raw


def preserve(K,before,after):
 K.need(_absent(before['nodes']),'certified preboot root SSH path and descendants absent')
 K.need(_absent(after['nodes']),'final certified root SSH path and descendants absent')
 left=before['nodes'].get('root',{});right=after['nodes'].get('root',{})
 fields=('inode','links','type','mode','uid','gid','xattrs','mtime','mtime_ns')
 # Current atime is protected around restoration by the guest, not across boot.
 K.need(_ordinary_root(left)and _ordinary_root(right)and all(left[n]==right[n]for n in fields),PRESERVATION_ERROR)
