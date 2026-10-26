"""Exact baseline plus registered PID1 proc/dev-null rows; no general ignore."""
from pathlib import PurePosixPath

def need(ok,why):
 if not ok:raise ValueError(why)
def rows(raw):
 need(type(raw)is bytes and 0<len(raw)<=4*1024**2,'bounded complete mount inventory');out={}
 for line in raw.splitlines():
  f=line.split();need(len(f)>=10 and len(line)<=16384 and f.count(b'-')==1 and f[0].isdigit()and int(f[0])>0,'canonical mount row');i=int(f[0]);need(i not in out,'duplicate mount ID');out[i]=line
 need(len(out)<=32768,'bounded mount count');return out

def transition(before,after,registered):
 a,b=rows(before),rows(after);need([line for line in after.splitlines()if int(line.split()[0])in a]==before.splitlines(),'all baseline mount rows and their order held');need(type(registered)is dict and len(registered)<=2,'at most one two-mount lease')
 need(not(set(a)&set(registered))and b==dict(a,**{})|registered,'only exact registered lease rows added; all baseline rows whole held')
 for ident,line in registered.items():need(rows(line+b'\n')=={ident:line},'registered actual whole mount row')
 return True

def lease_rows(before,after,targets):
 a,b=rows(before),rows(after);added={k:v for k,v in b.items()if k not in a};need(len(added)==len(targets),'exact newly mounted row count')
 need(sorted(v.split()[4].decode()for v in added.values())==sorted(targets),'exact lease target paths');transition(before,after,added);return added
