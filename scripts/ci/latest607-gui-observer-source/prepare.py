# SPDX-License-Identifier: MIT
"""Portable exact682 factory from the complete public676 source; no actor authority."""
import argparse,ast,base64,copy,hashlib,importlib.util,json,os,stat
from pathlib import Path
D=Path(__file__).resolve().parent
PROFILE='b92d394b86e5d0f2bcb5ca732d3591cb8ad2aac3725614248e3071774b466141'
def need(v,s):
 if not v:raise ValueError(s)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def canonical(p):
 p=Path(p);need(p.is_absolute()and p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'canonical absolute ordinary path');return p
def identity(s):
 return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p):
 p=canonical(p);a=p.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<=256*1024**2,'bounded singlelink source input')
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb')as stream:
  need(identity(os.fstat(stream.fileno()))==identity(a),'opened source identity')
  b=stream.read(a.st_size+1)
  need(len(b)==a.st_size and identity(a)==identity(os.fstat(stream.fileno()))==identity(p.lstat()),'stable source input')
 return b
def files(root,admin=False):
 root=canonical(root);need(root.is_dir(),'source directory');out={}
 def walk(p):
  for q in sorted(p.iterdir()):
   if admin and p==root and q.name=='.git':
    need(q.is_dir()and not q.is_symlink(),'top Git administration directory');continue
   need(q.name!='.git'and not q.is_symlink(),'foreign Git or symlink source member');s=q.lstat()
   if stat.S_ISDIR(s.st_mode):walk(q)
   else:out[q.relative_to(root).as_posix()]=read(q)
 walk(root);return out
def table(values):return{n:pin(b)for n,b in values.items()}
def inputs():
 b=read(D/'profile.json');need(pin(b)['sha256']==PROFILE,'fixed profile identity');q=json.loads(b)
 for n,w in q['operands'].items():need(pin(read(D/n))==w,'fixed operand '+n)
 return q
def change(value,p):
 old=copy.deepcopy(value);kind=p['kind']
 if kind in('object','array'):
  for k,op in p['items'].items():i=int(k)if kind=='array'else k;value[i]=change(value[i],op)
 elif kind=='base64':value=base64.b64encode(patch_bytes(base64.b64decode(value,validate=True),p['body'])).decode()
 else:need(kind=='value'and pin(enc(value))==p['before'],'typed unbinding leaf');value=p['after']
 # The inverse retains the exact removed typed value, never a nearby historical context.
 undo=copy.deepcopy(value)
 if kind in('object','array'):
  for k in p['items']:i=int(k)if kind=='array'else k;undo[i]=old[i]
 else:undo=old
 need(undo==old,'complete typed unbinding inverse');return value
def patch_bytes(raw,p):
 if p['kind']=='json':return enc(change(json.loads(raw),p['body']))
 need(p['kind']=='text','finite unbinding codec');s=raw.decode();out=s
 for e in reversed(p['edits']):need(s[e['start']:e['end']]==e['before'],'counted unbinding seam');out=out[:e['start']]+e['after']+out[e['end']:]
 inverse=out
 shift=0
 for e in p['edits']:
  start=e['start']+shift;need(inverse[start:start+len(e['after'])]==e['after'],'inverse unbinding seam');inverse=inverse[:start]+e['before']+inverse[start+len(e['after']):]
 need(inverse==s,'whole text unbinding inverse');return out.encode()
def unbind(values,q):
 need(table(values)==q['before']['known'],'exact public676 before unbinding');values=dict(values)
 for n,row in json.loads(read(D/'unbound.json')).items():
  need(pin(values[n])==row['before'],'whole unbinding before body');values[n]=patch_bytes(values[n],row['patch']);need(pin(values[n])==row['after'],'whole unbinding after body')
 need(table(values)==q['before']['null'],'whole NULL676 source');return values
def compose(values,variant,q):
 need(table(values)==q['before'][variant],'complete676 source context')
 spec=importlib.util.spec_from_file_location('_fixed_gui682_apply',D/'payload/observer_apply.py');O=importlib.util.module_from_spec(spec);spec.loader.exec_module(O)
 values={n:values[n]for n in q['before'][variant]};lex=values['implementation/factory/support/alpm_reader.py'];need(pin(lex)==O.BEFORE,'held observer input')
 for a,b in q['edits']:need(lex.count(a.encode())==1,'three finite lexical seams');lex=lex.replace(a.encode(),b.encode(),1)
 need(pin(lex)==O.AFTER,'exact observer product');values['implementation/factory/support/alpm_reader.py']=lex
 values['implementation/native.py']=O.edited(values['implementation/native.py'],[(O.NATIVE_BEFORE,O.NATIVE_AFTER)])
 profile=json.loads(values['implementation/factory/profile.json']);profile['support']['alpm_reader.py']=O.AFTER;values['implementation/factory/profile.json']=enc(profile)
 values['implementation/source_guard.py']+=O.SUFFIX
 inverses=json.loads(values['implementation/body-inverses.json']);next(x for x in inverses if x['after_path']=='implementation/native.py')['seams'].append(dict(before=O.NATIVE_BEFORE,after=O.NATIVE_AFTER,count=1));values['implementation/body-inverses.json']=enc(inverses)
 values['implementation/test_source.py']=O.edited(values['implementation/test_source.py'],[(O.BEFORE['sha256'],O.AFTER['sha256']),('self.assertEqual(new,C.read(ROOT/','self.assertEqual(__import__(\'observer_apply\').workflow(new),C.read(ROOT/')])
 for n in('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-welcome8-gui.yml'):values[n]=O.workflow(values[n])
 for n in('observer_apply.py','observer_stage.py','test_observer.py','presecret_control.py'):values['implementation/'+n]=read(D/'payload'/n)
 values['implementation/observer-parent.json']=enc(dict(variant=variant,source=q['source']if variant=='known'else None,ref=q['ref']if variant=='known'else None,files=q['before'][variant],actual=None))
 t=read(D/'payload/observer_guard.in').decode().replace('@PARENTS@',repr({v:pin(enc(q['before'][v]))for v in('known','null')})).replace('@PRODUCTS@',repr({n:pin(b)for n,b in values.items()if n!='source-manifest.json'})).replace('@EDITS@',repr(q['edits']));need(t.count("\nSELF_SHA='@SELF@'\n")==1,'one guard seal');t=t.replace("\nSELF_SHA='@SELF@'\n",'\nSELF_SHA='+repr(hashlib.sha256(t.encode()).hexdigest())+'\n',1);values['implementation/observer_guard.py']=t.encode()
 m=json.loads(values['source-manifest.json']);m['status']='SOURCE_ONLY_LATEST607_LEXICAL_OBSERVER_DATA_NO_GUI_AUTHORITY';m['files']={n:pin(b)for n,b in values.items()if n!='source-manifest.json'};values['source-manifest.json']=enc(m)
 for n,b in values.items():
  if n.endswith('.py'):ast.parse(b,filename=n)
 need(table(values)==q['after'][variant],'whole exact682 emission');return values
def emit(parent,output,variant):
 q=inputs();need(variant in('known','null'),'finite known/NULL context');parent=canonical(parent);out=canonical(output)
 need(not os.path.lexists(out)and out.parent.is_dir(),'fresh output with existing parent')
 for r in(parent,D):need(not out.is_relative_to(r)and not r.is_relative_to(out),'disjoint input/output')
 need(not any(('native-actual'in x.name or 'trial-root'in x.name) for x in(out,*out.parents)),'constructor cannot write actual roots')
 original=files(parent,admin=True);need(table(original)==q['before']['known'],'exact public676 input')
 values=compose(original if variant=='known'else unbind(original,q),variant,q)
 need(table(files(parent,admin=True))==q['before']['known']and inputs()==q,'late complete input and operand join')
 out.mkdir(mode=0o700)
 for n,b in values.items():p=out/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
 need(table(files(out))==q['after'][variant],'complete emitted map');return dict(files=len(values),context=variant,actual_source=None,actual_ref=None,actual_run=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--context',choices=('known','null'),required=True);a=p.parse_args();print(json.dumps(emit(a.parent,a.output,a.context),sort_keys=True))
