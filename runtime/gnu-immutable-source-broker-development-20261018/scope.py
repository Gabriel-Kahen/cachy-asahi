"""Explicit separate-device source scope; never impersonates legacy Scope.start."""
import os,stat
from pathlib import Path
import client,context as C,protocol as P

class Scope:
 def __init__(self,sock,nonce):
  self.client=client.Client(sock,nonce);self.api,self.modules=C.source_api()
 def source(self,root,limits):
  P.need(Path(root)==Path('/held'),'fixed immutable source only');return self.client.source(limits)
 def mutable(self,root,limits):
  # No FS-state caching or shortcut for /work or any copied target.
  client.restricted();root=Path(root);P.need(root.is_absolute()and(root==Path('/work')or Path('/work')in root.parents)and not any(p.is_symlink()for p in(root,*root.parents)),'owned ordinary mutable work scope')
  s=root.lstat();P.need(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not os.statvfs(root).f_flag&os.ST_RDONLY,'actual owned writable work directory')
  P.need(self.client.pinned is not None and s.st_dev!=self.client.pinned['root_identity'][0],'explicit distinct immutable source/mutable work devices')
  value=self.api['observe'](self.modules,root,limits);value['auxiliary']=self.modules['aux_checkpoint'].checkpoint(root,value['observation'],limits);return value
 def close(self):self.client.close()
