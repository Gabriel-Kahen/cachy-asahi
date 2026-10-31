# SPDX-License-Identifier: MIT
"""Selected four logical restoration: exactly bounded INSTALLDATE byte edits."""
import base64,hashlib,re
import latest_plan as plan
SELECTED=tuple((role,name,old)for role,name,old,_ in plan.PRODUCTS if old is not None)
DIRECTORY=dict(mode=0o755,uid=0,gid=0,capability=None,children=['desc','files','mtree'])
DATE=re.compile(rb'(?m)^%INSTALLDATE%\n([0-9]{1,20})\n\n')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def date(raw):
 plan.need(type(raw)is bytes and 0<len(raw)<=1024**2 and b'\0'not in raw,'bounded complete raw desc bytes')
 matches=list(DATE.finditer(raw));plan.need(len(matches)==1 and raw.count(b'%INSTALLDATE%')==1,'one exact numeric INSTALLDATE block')
 match=matches[0];value=int(match.group(1));plan.need(0<value<2**63 and str(value).encode()==match.group(1),'canonical positive numeric INSTALLDATE')
 return value,match.span(1)
def interval(value):
 plan.need(type(value)is dict and set(value)=={'authority','start_seconds','end_seconds','monotonic_seconds'},'closed source-owned transaction clock interval')
 plan.need(value['authority']=='SOURCE_OWNED_TRANSACTION_WALLCLOCK_NOT_ROOT_OBSERVATION'and type(value['start_seconds'])is type(value['end_seconds'])is int and 0<value['start_seconds']<=value['end_seconds']<2**63 and value['end_seconds']-value['start_seconds']<=90 and type(value['monotonic_seconds'])in(int,float)and 0<=value['monotonic_seconds']<=90,'original90s bounded transaction interval')
 return value['start_seconds'],value['end_seconds']
def desc(before,after,transaction):
 original,oldspan=date(before);current,newspan=date(after);start,end=interval(transaction);plan.need(start<=current<=end,'INSTALLDATE belongs to actual restoring transaction interval')
 restored=after[:newspan[0]]+before[oldspan[0]:oldspan[1]]+after[newspan[1]:];plan.need(restored==before,'every other desc byte/framing/order/field must match original')
 return dict(field='INSTALLDATE',original=original,current=current,source_owned_transaction=transaction,before=pin(before),after=pin(after),all_other_desc_bytes='EXACT_BYTE_EQUAL')
def scalar(raw,key):
 marker=('%'+key+'%').encode();matches=list(re.finditer(rb'(?m)^'+re.escape(marker)+rb'\n([^\n]+)\n\n',raw));plan.need(raw.count(marker)==1 and len(matches)==1,'one exact selected desc scalar '+key)
 return matches[0].group(1).decode('ascii')
def records(before,after,transactions):
 names={name for _,name,_ in SELECTED};plan.need(type(before)is type(after)is dict and set(before)==set(after)==names and set(transactions)=={role for role,_,_ in SELECTED},'exact four selected original/final raw DB roles')
 proofs={};spent=[0,0]
 for role,name,version in SELECTED:
  a,b=before[name],after[name];plan.need(type(a)is type(b)is dict and set(a)==set(b)=={'version','leaves','directory'}and a['version']==b['version']==version,'exact original selected package version')
  plan.need(a['directory']==b['directory']==DIRECTORY,'selected record directory mode/ownership/capability/complete children held')
  left,right=a['leaves'],b['leaves'];plan.need(type(left)is type(right)is dict and set(left)==set(right)=={'desc','files','mtree'},'complete exact selected raw ALPM leaf set')
  for leaf in left:
   x,y=left[leaf],right[leaf];plan.need(type(x)is type(y)is dict and set(x)==set(y)=={'body_base64','mode','uid','gid','nlink'}and all(type(v)is int for n in('mode','uid','gid','nlink')for v in(x[n],y[n]))and all(x[n]==y[n]for n in('mode','uid','gid','nlink'))and x['uid']==x['gid']==0 and x['nlink']==1,'selected record permissions/ownership/single-link semantics held')
   u=base64.b64decode(x['body_base64'],validate=True);v=base64.b64decode(y['body_base64'],validate=True)
   spent[0]+=len(u);spent[1]+=len(v);plan.need(0<len(u)<=1024**2 and 0<len(v)<=1024**2 and max(spent)<=1024**2,'complete selected raw DB capture one-MiB bound')
   if leaf=='desc':
    plan.need(all(scalar(body,'NAME')==name and scalar(body,'VERSION')==version for body in(u,v)),'actual selected desc NAME/VERSION matches original package')
    proofs[name]=desc(u,v,transactions[role])
   else:plan.need(u==v,'all original files/mtree bytes held')
 return dict(status='PASS_SELECTED_SETUP5_LOGICAL_RESTORATION',scope='ORIGINAL_VERSIONS_PAYLOAD_OWNERSHIP_FILES_MTREE_DESC_EXCEPT_BOUNDED_INSTALLDATE',selected_inode_restoration='NOT_CLAIMED',records=proofs)

def unselected_base(held):
 # Original native606's complete604 before-state remains retained; only the
 # fixed four selected records/payloads leave its physical-preservation domain.
 plan.need(type(held)is dict and set(held)=={'packages','nodes'}and len(held['packages'])==604,'whole original native604 before-state')
 selected={name:version for _,name,version in SELECTED};packages={row['name']:row for row in held['packages']};plan.need(len(packages)==604 and all(packages.get(name,{}).get('version')==version for name,version in selected.items()),'all four original selected packages in native604')
 excluded={};wanted={}
 for name,version in selected.items():
  row=packages[name];plan.need(type(row['files'])is list,'original full selected ownership paths')
  excluded.update({('/'+p):name for p in row['files']});wanted[name]='/var/lib/pacman/local/'+name+'-'+version+'/'
 def selected_node(path):return path in excluded or any(path.startswith(prefix)for prefix in wanted.values())
 nodes={name:row for name,row in held['nodes'].items()if not selected_node(name)};protected=[row for row in held['packages']if row['name']not in selected];plan.need(len(protected)==603 and nodes and len(nodes)<len(held['nodes']),'exact other600 physical baseline domain')
 return dict(packages=protected,nodes=nodes)
