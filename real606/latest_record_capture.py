# SPDX-License-Identifier: MIT
"""Fresh complete four selected raw DB leaf captures within one fixed MiB."""
import base64,hashlib,os,stat
from pathlib import Path
import latest_restoration as R
LIMIT=1024**2

def capture(root,graph,read):
 root=Path(root);R.plan.need(root==Path('/'),'fixed original native root only');out={};spent=0
 for _,name,version in R.SELECTED:
  record='var/lib/pacman/local/'+name+'-'+version;directory=graph['nodes'][record];R.plan.need(directory['kind']=='directory'and directory['children']==['desc','files','mtree']and dict(mode=stat.S_IMODE(directory['identity'][2]),uid=directory['identity'][3],gid=directory['identity'][4],capability=directory['capability'],children=directory['children'])==R.DIRECTORY,'complete original selected ALPM record shape');leaves={}
  for leaf in('desc','files','mtree'):
   relative=record+'/'+leaf;node=graph['nodes'][relative];R.plan.need(node['kind']=='file','ordinary selected raw DB leaf');identity=node['identity'];path=root/relative;before=path.lstat();raw=read(path,LIMIT);after=path.lstat();key=lambda s:[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns];spent+=len(raw)
   R.plan.need(spent<=LIMIT and key(before)==key(after)==identity and stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==before.st_gid==0 and hashlib.sha256(raw).hexdigest()==node['sha256'],'fresh complete captured leaf equals independent full graph identity/hash')
   leaves[leaf]=dict(body_base64=base64.b64encode(raw).decode(),mode=stat.S_IMODE(before.st_mode),uid=before.st_uid,gid=before.st_gid,nlink=before.st_nlink)
  out[name]=dict(version=version,directory=dict(R.DIRECTORY),leaves=leaves)
 return out
