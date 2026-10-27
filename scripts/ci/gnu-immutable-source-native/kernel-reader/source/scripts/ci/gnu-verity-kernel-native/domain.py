"""Finite Kconfig visibility-frontier audit, not a configuration evaluator/build."""
import re
ROOTS=('drivers/md/Kconfig','crypto/Kconfig')

def need(ok,why):
 if not ok:raise ValueError(why)
def symbols(raw):
 values={}
 for line in raw.decode().splitlines():
  m=re.fullmatch(r'(CONFIG_[A-Z0-9_]+)=(.*)',line);n=re.fullmatch(r'# (CONFIG_[A-Z0-9_]+) is not set',line)
  if m or n:
   k,v=(m[1],m[2])if m else(n[1],'n');need(k not in values,'duplicate baseline symbol');values[k]=v
 return values

def expression(text,values,used):
 tokens=re.findall(r'&&|\|\||!=|=|!|\(|\)|[A-Za-z0-9_]+',text);need(''.join(tokens)==re.sub(r'\s+','',text),'finite pinned dependency expression');at=0
 def atom():
  nonlocal at
  need(at<len(tokens),'dependency operand');token=tokens[at];at+=1
  if token=='!':return 2-atom()
  if token=='(':
   v=disjunction();need(at<len(tokens)and tokens[at]==')','dependency closing parenthesis');at+=1;return v
  need(re.fullmatch('[A-Za-z0-9_]+',token)is not None,'dependency symbol')
  if token in('y','m','n'):return {'n':0,'m':1,'y':2}[token]
  used.add('CONFIG_'+token);v=values.get('CONFIG_'+token,'n');need(v in('n','m','y'),'boolean dependency only');return {'n':0,'m':1,'y':2}[v]
 def comparison():
  nonlocal at
  a=atom()
  if at<len(tokens)and tokens[at]in('=','!='):
   op=tokens[at];at+=1;b=atom();return 2*int((a==b)if op=='='else(a!=b))
  return a
 def conjunction():
  nonlocal at
  v=comparison()
  while at<len(tokens)and tokens[at]=='&&':at+=1;v=min(v,comparison())
  return v
 def disjunction():
  nonlocal at
  v=conjunction()
  while at<len(tokens)and tokens[at]=='||':at+=1;v=max(v,conjunction())
  return v
 result=disjunction();need(at==len(tokens),'complete finite dependency expression');return result

def scan(text):
 """Retain explicit if/menu/choice dependencies and prompted bool/tristates."""
 scopes=[];configs=[];sources=[];current=None;helping=False
 for line in text.splitlines():
  s=line.strip()
  if not s or s.startswith('#'):continue
  structural=not line[0].isspace()
  if helping and not structural:continue
  if structural:helping=False
  if s.startswith(('help','---help---')):helping=True;continue
  m=re.fullmatch(r'(?:menu)?config ([A-Z0-9_]+)',s)
  if m:
   current=dict(symbol='CONFIG_'+m[1],type=None,prompt=False,dependencies=[d for x in scopes for d in x['dependencies']]);configs.append(current);continue
  if s.startswith('if '):scopes.append(dict(kind='if',dependencies=[s[3:].split('#',1)[0].strip()]));current=None;continue
  if s in('endif','endmenu','endchoice')or re.match(r'endif(?:\s|$)',s):
   kind='if'if s.startswith('endif')else('menu'if s=='endmenu'else'choice');need(scopes and scopes[-1]['kind']==kind,'finite pinned Kconfig scopes: '+s+' '+repr(scopes));scopes.pop();current=None;continue
  if s.startswith('menu ')or s=='choice'or s.startswith('choice '):scopes.append(dict(kind='menu'if s.startswith('menu ')else'choice',dependencies=[]));current=None;continue
  m=re.fullmatch(r'source "([A-Za-z0-9_./-]+)"',s)
  if m:sources.append(dict(path=m[1],dependencies=[d for x in scopes for d in x['dependencies']]));current=None;continue
  if s.startswith('depends on '):
   target=current if current is not None else(scopes[-1]if scopes else None);need(target is not None,'dependency has explicit owner');target['dependencies'].append(s[len('depends on '):].split('#',1)[0].strip());continue
  m=re.match(r'(bool|tristate)(?:\s|$)',s)
  if current is not None and m:
   current['type']=m[1];current['prompt']='"'in s
   if '" if 'in s:current['dependencies'].append(s.rsplit('" if ',1)[1])
  if current is not None and s.startswith('prompt '):current['prompt']=True
 need(not scopes,'closed pinned Kconfig scopes');return configs,sources

def derive(primary,children,baseline,expected):
 before=symbols(baseline);after=dict(before)
 for n,row in expected.items():need(row==dict(before='n',proposed='y')and before.get(n,'n')=='n','held fourteen select closure');after[n]='y'
 used=set();domain=set();routes={};frontier={}
 for path in ROOTS:
  text=primary[path]
  for m in re.finditer(r'^(?:menu)?config ([A-Z0-9_]+)\n(.*?)(?=^(?:menu)?config |\Z)',text,re.M|re.S):
   if re.search(r'^\s*(?:bool|tristate)(?:\s|$)',m[2],re.M):domain.add('CONFIG_'+m[1])
  _,sources=scan(text)
  for row in sources:
   deps=row['dependencies'];changed=any(expression(x,before,used)==0 and expression(x,after,used)>0 for x in deps)
   if changed and all(expression(x,after,used)>0 for x in deps):routes[row['path']]=dict(parent=path,dependencies=deps)
 need(set(children)==set(routes),'all and only direct source paths exposed by held active closure')
 for path,route in routes.items():
  configs,_=scan(children[path])
  for row in configs:
   if row['type']not in('bool','tristate')or not row['prompt']:continue
   deps=route['dependencies']+row['dependencies']
   if all(expression(x,after,used)>0 for x in deps):frontier[row['symbol']]=dict(path=path,type=row['type'],dependencies=deps)
 return dict(domain=sorted(domain|set(frontier)),original_domain=sorted(domain),frontier=frontier,routes=routes,reference_values={n:before.get(n,'n')for n in sorted(used)},method='EXPLICIT_DIRECT_SOURCE_PROMPT_VISIBILITY_FRONTIER_ONLY_NOT_KCONFIG_SOLVER_OR_CANDIDATE_CONFIG')

def validate(rules,proof,baseline,pin):
 """Validate only pinned source-derived n-domain DATA; never build a config."""
 need(pin(baseline)==proof['baseline_config'],'whole original held baseline audit')
 primary=proof['inactive_domain_sources'];extra=proof['inactive_visibility_frontier'];children=extra['sources']
 need(set(primary)==set(ROOTS)and all(pin(text.encode())==proof['files'][name]for name,text in {**primary,**children}.items()),'whole pinned root and directly sourced Kconfig text')
 result=derive(primary,children,baseline,rules['expected_changes']);need(result==extra['derivation']and rules['inactive_bool_tristate_domain']==result['domain'],'exact source-derived189 inactive domain; no actual-list widening')
 need(len(result['original_domain'])==173 and len(result['frontier'])==16 and len(result['domain'])==189,'finite original173 plus16 visibility frontier')
 return result
