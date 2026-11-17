# SPDX-License-Identifier: MIT
"""Separate build-only metadata closure using existing bounded ALPM resolver."""
import argparse,base64,copy,hashlib,importlib.util,json,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
NAMES=('base-devel','cmake','ninja','pkgconf','python','openssl','libssh2','pcre2','zlib','glibc')
REPOS=('core','extra','alarm')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def encoded(v):return(json.dumps(v,indent=2,sort_keys=True)+'\n').encode()
def resolver():
 p=ROOT/'scripts/port/platform-residual-closure/resolve.py';expected=json.loads((HERE/'profile.DATA.json').read_bytes())['engines'][str(p.relative_to(ROOT))];need(pin(p.read_bytes())==expected,'whole maintained resolver pin');s=importlib.util.spec_from_file_location('maintained_minimal_builder_resolver',p);r=importlib.util.module_from_spec(s);s.loader.exec_module(r);return r

def plan(cache):
 R=resolver();catalog=[];database=[];signatures={};descriptors={};diagnostics=[]
 for repo in REPOS:
  path=cache/(repo+'.db');raw=path.read_bytes();need(0<len(raw)<=20*1024**2,'bounded fresh catalog')
  ref=dict(repo=repo,url='https://ca.us.mirror.archlinuxarm.org/aarch64/'+repo+'/'+repo+'.db',**pin(raw),signed=False)
  database.append(ref);groups,unavailable=R.read_catalog(raw,repo,time.monotonic()+60)
  diagnostics.extend(dict(repo=repo,directory=n,reason='sparse-unavailable')for n in unavailable)
  for directory,group in groups.items():
   try:rows=R.catalog_packages({directory:group},repo,ref)
   except R.Refused as e:diagnostics.append(dict(repo=repo,directory=directory,reason=str(e)));continue
   row=rows[0]
   try:R.record(row)
   except R.Refused as e:diagnostics.append(dict(repo=repo,directory=directory,reason='unselectable '+str(e)));continue
   catalog.append(row);fields={k:v for member in group.values()for k,v in member['fields'].items()};descriptors[(repo,row['name'])]=fields
   if fields.get('PGPSIG'):signatures[row['archive']['filename']+'.sig']=base64.b64decode(fields['PGPSIG'][0],validate=True)
 byname={}
 for row in catalog:byname.setdefault(row['name'],[]).append(row)
 roots=[]
 for n in NAMES:
  need(n in byname and len(byname[n])==1,'one exact official recipe/build root '+n);roots.append(R.identity(byname[n][0]))
 # The regular official rootfs is the maintained bootstrap operand. Its entire
 # installed inventory is reconciled to this one new catalog, never mixed with349.
 bootstrap=json.loads((HERE/'profile.DATA.json').read_bytes())['bootstrap_manifest'];bootstrap_raw=(ROOT/bootstrap['path']).read_bytes();need(pin(bootstrap_raw)=={k:bootstrap[k]for k in('bytes','sha256')},'whole maintained rootfs/trust manifest');old=json.loads(bootstrap_raw);base=[];missing=[]
 for row in old['rootfs_packages']:
  name=row['name'][0];candidates=byname.get(name,[])
  if len(candidates)!=1:missing.append(dict(name=name,old_version=row['version'][0],candidates=[R.identity(r)for r in candidates]))
  else:base.append(candidates[0])
 # The maintained resolver intentionally refuses multiple simultaneous witnesses.
 # Constrain only these explicit normal dependency edges to a literal versioned
 # package witness. Retain original package metadata and original requirements.
 bindings=json.loads((HERE/'profile.DATA.json').read_bytes())['provider_bindings']
 originals={(r['repo'],r['name']):r for r in catalog};view=copy.deepcopy(catalog);applied=[]
 for binding in bindings:
  consumer=[r for r in view if R.identity(r)==binding['consumer']];provider=[r for r in catalog if R.identity(r)==binding['provider']]
  need(len(consumer)==len(provider)==1 and consumer[0]['depends'].count(binding['requirement'])==1,'exact finite provider binding identities')
  need(R.witnesses(provider[0],binding['requirement']),'explicit provider satisfies ORIGINAL normal dependency')
  constrained=provider[0]['name']+'='+provider[0]['version'];need([R.identity(r)for r in catalog if R.witnesses(r,constrained)]==[binding['provider']],'one exact versioned provider witness')
  consumer[0]['depends']=[constrained if x==binding['requirement']else x for x in consumer[0]['depends']];applied.append(dict(binding,solver_constraint=constrained))
 viewbase=[next(v for v in view if R.identity(v)==R.identity(r))for r in base]
 closure=R.resolve(viewbase,view,roots,{},limits=R.Limits(max_packages=256,max_edges=4096,max_depth=128,max_seconds=60,max_report_bytes=16*1024**2))
 for edge in closure['edges']:
  for binding in applied:
   if edge['consumer']==binding['consumer']and edge['requirement']==binding['solver_constraint']:
    edge['constrained_solver_requirement']=edge['requirement'];edge['requirement']=binding['requirement'];edge['explicit_provider_binding']=binding['provider']
 selected=[originals[(r['repo'],r['name'])]for r in closure['selected']];packages=[]
 for row in selected:
  a=dict(row['archive']);a['signature_b64']=base64.b64encode(signatures[a['filename']+'.sig']).decode('ascii');row=dict(row,archive=a);need(a['signature_bytes']and a['signature_sha256'],'every selected official package has detached-signature bytes')
  f=descriptors[(row['repo'],row['name'])];packages.append(dict(**row,url='https://ca.us.mirror.archlinuxarm.org/aarch64/'+row['repo']+'/'+a['filename'],installed_bytes=int(f['ISIZE'][0]),signature_source='embedded PGPSIG in exact catalog descriptor',signature_authentication=None))
 # Read the original recipes as metadata; never source or execute PKGBUILD.
 check_path=ROOT/'scripts/checks/package_checks.py';check_pin=json.loads((HERE/'profile.DATA.json').read_bytes())['engines'][str(check_path.relative_to(ROOT))];need(pin(check_path.read_bytes())==check_pin,'whole maintained SRCINFO parser');spec=importlib.util.spec_from_file_location('minimal_recipe_metadata',check_path);check=importlib.util.module_from_spec(spec);spec.loader.exec_module(check)
 recipe_inputs={};sources=[];recipe_edges=[]
 for name in('llhttp','libgit2'):
  recipe=ROOT/('packages/libraries/cachy-asahi-'+name+'-reference');fields=check.metadata((recipe/'.SRCINFO').read_text());need(fields['arch']==['aarch64'],'original aarch64 recipe metadata')
  leaves={p.relative_to(recipe).as_posix():dict(pin(p.read_bytes()),mode=p.stat().st_mode&0o777)for p in recipe.rglob('*')if p.is_file()};need(not any(p.is_symlink()for p in recipe.rglob('*')),'ordinary complete original recipe family')
  info=json.loads((recipe/'source.json').read_bytes());source=info['source'];sources.append(dict(filename=source['filename'],size=source['bytes'],sha256=source['sha256'],url=source['url'],upstream_commit=info['upstream_commit'],upstream_detached_signature=None))
  requirements=sum((fields.get(k,[])for k in('depends','makedepends','checkdepends')),[])
  for requirement in requirements:
   if requirement=='llhttp=9.3.1':recipe_edges.append(dict(recipe=name,requirement=requirement,status='SEPARATE_PROJECT_SIGNED_PROVIDER_REQUIRED_BEFORE_LIBGIT2'));continue
   matches=[r for r in selected if R.witnesses(r,requirement)];need(len(matches)==1,'exact normal recipe dependency witness '+requirement);recipe_edges.append(dict(recipe=name,requirement=requirement,provider=R.identity(matches[0]),status='METADATA_SATISFIED'))
  recipe_inputs[name]=dict(path=str(recipe.relative_to(ROOT)),files=leaves,depends=fields.get('depends',[]),makedepends=fields.get('makedepends',[]),checkdepends=fields.get('checkdepends',[]),source=source,provides=fields.get('provides',[]),conflicts=fields.get('conflicts',[]),build_check_package_commands='original unchanged PKGBUILD functions; no network in build')
 rootfs=old['rootfs'];result=dict(schema=1,kind='SEPARATE_MINIMAL_NATIVE_LIBRARY_BUILDER_INPUTS_V1',scope='BUILDER_ONLY_NOT_FROZEN349_OR_FULL_PORT_OR_RUNTIME_OR_M2',recipe_inputs=recipe_inputs,upstream_sources=sources,recipe_dependency_edges=recipe_edges,catalogs=database,bootstrap_manifest=bootstrap,keyring_files=old['keyring_files'],signer_fingerprint=old['signer_fingerprint'],catalog_unselectable=diagnostics,explicit_provider_bindings=applied,rootfs=rootfs,rootfs_original_inventory=old['rootfs_packages'],rootfs_reconciliation=dict(installed=len(old['rootfs_packages']),selected=len(base),missing=missing),roots=roots,packages=packages,edges=closure['edges'],metadata_graph_status=closure['metadata_graph_status'],graph_blockers=[b for b in closure['blockers']if b['scope']=='graph'],resolver_remaining_review_holds=[b for b in closure['blockers']if b['scope']!='graph'],budgets=dict(packages=len(packages),compressed_bytes=sum(r['archive']['bytes']for r in packages),signature_bytes=sum(r['archive']['signature_bytes']for r in packages),declared_installed_bytes=sum(r['installed_bytes']for r in packages),rootfs_bytes=rootfs['size'],owner_memory_limit=2*1024**3,daemon_memory_limit=6*1024**3,storage_limit=12*1024**3,live_storage_reserve=2*1024**3,actual_fit=None),project_llhttp_dependency=dict(requirement='llhttp=9.3.1',intended_provider='cachy-asahi-llhttp-reference',actual_project_archive=None,actual_project_signature=None,stage='REQUIRED_SEPARATE_SIGNED_PROVIDER_BEFORE_LIBGIT2_BUILD_ONLY'),all_inputs_retrieved=None,signature_authentication=None,Root_selection=None,native=None,M2=None,distribution_release=None)
 return result,{n:signatures[n]for n in [r['archive']['filename']+'.sig'for r in packages]}

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cache',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();need(not a.output.exists(),'new immutable plan only');d,sigs=plan(a.cache);a.output.mkdir(mode=0o700);(a.output/'builder.lock.json').write_bytes(encoded(d));(a.output/'signatures').mkdir()
 for name,b in sigs.items():(a.output/'signatures'/name).write_bytes(b)
 print(json.dumps(dict(metadata=d['metadata_graph_status'],missing_base=d['rootfs_reconciliation']['missing'],budgets=d['budgets'],graph_blockers=d['graph_blockers']),indent=2))
