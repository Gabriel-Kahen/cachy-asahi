# SPDX-License-Identifier: MIT
"""Exact Apps5→6 selection over one authenticated, source-pinned auxiliary runtime."""
import ast
import hashlib
import inspect
INPUT={'bytes':6925,'sha256':'91d34f6decab6262f36dfe71cc27714139bc906d7b89fb8b89d7c143eca4ca5f'}
BEFORE='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5'
AFTER='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3'
ARCHIVE='1ce4a540a5ec2fa26353847b93fed953e084cf65e872836f670ac721446cd3d7'
FILES={'usr/bin/cachy-asahi-apps','usr/lib/cachy-asahi-apps/apps.py','usr/lib/cachy-asahi-apps/helper-pins.json','usr/lib/cachy-asahi-apps/inventory.py','usr/share/doc/cachy-asahi-apps/README.md','usr/share/doc/cachy-asahi-apps/source-provenance.json','usr/share/licenses/cachy-asahi-apps/LICENSE','usr/share/licenses/cachy-asahi-apps/NOTICE'}
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def need(ok,why):
 if not ok:raise ValueError(why)

def apps6_selection_guard(snapshot,before,desired,config,*,need,inventory_sha):
    # bound_update calls selection only inside snapshot.authenticated's context.
    need(type(before) is dict and len(before)==604 and inventory_sha(before)=='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5','exact-apps604-before-lock')
    need(config['before_lock_sha256']=='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5' and config['after_lock_sha256']=='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3','exact-apps604-scale-locks')
    need(before.get('cachy-asahi-apps')=='0.1.0-5' and desired=={'cachy-asahi-apps':'0.1.0-6'} and before.get('cachy-asahi-setup')=='0.1.0-5','exact-apps5-to6-transition')
    after=dict(before,**desired)
    other=lambda rows:{n:v for n,v in rows.items() if n!='cachy-asahi-apps'}
    need(len(other(before))==603 and other(before)==other(after) and inventory_sha(after)=='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3','exact-apps604-after-lock-and-other603')
    rows=snapshot['release']['packages']
    need(type(rows) is list and len(rows)==1 and rows[0]['name']=='cachy-asahi-apps' and rows[0]['version']=='0.1.0-6' and rows[0]['sha256']=='1ce4a540a5ec2fa26353847b93fed953e084cf65e872836f670ac721446cd3d7','exact-apps6-authenticated-archive')

def apps6_postcommit_compare(before,after,comparator,*,committed,selected,config,need,compare):
    # The exact selected Apps files are below this one non-recursive ldconfig
    # scan entry. Keep inode, mode, owner, links, size and all other rows exact;
    # only this directory's mtime/ctime may reflect those selected replacements.
    if not committed:return compare(before,after,comparator,committed=False)
    need(selected is True and config['before_lock_sha256']=='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5' and config['after_lock_sha256']=='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3','apps604-selected-postcommit-only')
    name='usr/lib/cachy-asahi-apps';old,new=before['scan'].get(name),after['scan'].get(name)
    need(type(old) is dict and type(new) is dict and set(old)==set(new)=={'node','identity'},'apps-directory-scan-row')
    need(old['node']==new['node'] and set(old['node'])=={'type','mode','uid','gid'} and old['node']['type']=='directory' and old['node']['mode']==0o755,'apps-directory-node-metadata')
    a,b=old['identity'],new['identity'];need(type(a) is tuple and type(b) is tuple and len(a)==len(b)==9 and all(type(v) is int for v in (*a,*b)) and a[:7]==b[:7],'apps-directory-inode-links-size-metadata')
    left=dict(before,scan=dict(before['scan']));right=dict(after,scan=dict(after['scan']))
    left['scan'][name]=dict(old,identity=a[:7]);right['scan'][name]=dict(new,identity=b[:7])
    result=compare(left,right,comparator,committed=True)
    return dict(result,selected_scan_directory=dict(path=name,projection='DIRECTORY_MTIME_CTIME_ONLY',inode_links_size_metadata='UNCHANGED',before_times=a[7:],after_times=b[7:]))

def derive(raw):
    need(pin(raw)==INPUT,'exact previously derived Setup3-to5 auxiliary source required')
    text=raw.decode();tree=ast.parse(text);edits=[]
    assignments={'SETUP':"SETUP = 'cachy-asahi-apps'",'SETUP_ARCHIVE':"SETUP_ARCHIVE = '"+ARCHIVE+"'",'FILES':'FILES = {'+', '.join(repr(n) for n in sorted(FILES))+'}'}
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in assignments:edits.append((node.lineno-1,node.end_lineno,assignments[node.targets[0].id]+'\n'))
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Runtime');method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='selection')
    edits.append((method.lineno-1,method.end_lineno,"    def selection(self,snapshot,before,desired):\n        apps6_selection_guard(snapshot,before,desired,self.config,need=aux.need,inventory_sha=scale.inventory_sha)\n        super().selection(snapshot,before,desired)\n        self.apps6_auxiliary_selected = True\n"))
    need(len(edits)==4,'only three identity assignments and one selection method')
    lines=text.splitlines(keepends=True)
    for a,b,v in sorted(edits,reverse=True):lines[a:b]=[v]
    result=''.join(lines);anchor='class Runtime(strict.Runtime):';need(result.count(anchor)==1,'one inherited auxiliary class');result=result.replace(anchor,inspect.getsource(apps6_selection_guard)+'\n\n'+anchor)
    before="'exact-six-setup-files'";need(result.count(before)==1,'one exact auxiliary payload diagnostic');result=result.replace(before,"'exact-eight-apps6-files'")
    before='check = aux.compare(previous,state,self.comparator,committed=committed)';after='check = apps6_postcommit_compare(previous,state,self.comparator,committed=committed,selected=getattr(self,\"apps6_auxiliary_selected\",False),config=self.config,need=aux.need,compare=aux.compare)';need(result.count(before)==1,'one selected postcommit comparator call');result=result.replace(before,after);result=result.replace('class Runtime(strict.Runtime):',inspect.getsource(apps6_postcommit_compare)+'\n\nclass Runtime(strict.Runtime):')
    generated=ast.parse(result);changed_cls=next(n for n in generated.body if isinstance(n,ast.ClassDef) and n.name=='Runtime')
    original_methods={n.name:n for n in cls.body if isinstance(n,ast.FunctionDef)};new_methods={n.name:n for n in changed_cls.body if isinstance(n,ast.FunctionDef)}
    need(set(original_methods)==set(new_methods),'no auxiliary method added/removed')
    for name,node in original_methods.items():
        if name=='selection':continue
        expected=ast.parse(ast.get_source_segment(text,node).replace("'exact-six-setup-files'","'exact-eight-apps6-files'").replace('check = aux.compare(previous,state,self.comparator,committed=committed)','check = apps6_postcommit_compare(previous,state,self.comparator,committed=committed,selected=getattr(self,\"apps6_auxiliary_selected\",False),config=self.config,need=aux.need,compare=aux.compare)'))
        need(ast.dump(expected.body[0],include_attributes=False)==ast.dump(new_methods[name],include_attributes=False),'auxiliary/cache/capability body changed: '+name)
    old_apply=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='apply');new_apply=next(n for n in generated.body if isinstance(n,ast.FunctionDef) and n.name=='apply')
    need(ast.dump(old_apply,include_attributes=False)==ast.dump(new_apply,include_attributes=False),'original auxiliary apply changed')
    return result.encode(),dict(status='EXACT_APPS5_TO6_AUXILIARY_SELECTION_ONLY',before=pin(raw),after=pin(result.encode()),before604_sha256=BEFORE,after604_sha256=AFTER,package_sha256=ARCHIVE,payload_files=sorted(FILES),other_packages=603,setup='UNCHANGED0.1.0-5',auxiliary_cache_capability_comparisons='UNCHANGED_EXCEPT_EXACT_SELECTED_APPS_PARENT_DIRECTORY_TIMES',scope='SOURCE_ONLY_NO_TRANSACTION_OR_CACHE_ACCEPTANCE')


def apps_scan_difference(before,after,raw_before,raw_after):
    import hashlib,json
    def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    def summary(mapping,name):
        if name not in mapping:return {'present':False}
        row=mapping[name];data=encoded(row)
        if len(data)>16384:raise ValueError('bounded scan row')
        out={'present':True,'row_type':type(row).__name__,'row_bytes':len(data),'row_sha256':hashlib.sha256(data).hexdigest()}
        if type(row) is not dict:
            if row is None or type(row) in (bool,int) or type(row) is str and len(row)<=128:out['scalar']=row
            return out
        out['row_keys']=sorted(str(k)[:128] for k in row)[:16];node=row.get('node')
        if type(node) is dict:
            out['node']={k:v for k,v in node.items() if k in ('type','mode','uid','gid','bytes','sha256') and (type(v) in (int,bool) or type(v) is str and len(v)<=128)}
            if type(node.get('target')) is str:out['node']['target_sha256']=hashlib.sha256(node['target'].encode()).hexdigest()
        identity=row.get('identity')
        if type(identity) in (list,tuple) and len(identity)<=9 and all(type(v)is int for v in identity):out['identity']=list(identity)
        return out
    old,new=before['scan'],after['scan']
    if type(old)is not dict or type(new)is not dict or len(old)>8192 or len(new)>8192:raise ValueError('bounded scan maps')
    names=sorted(set(old)|set(new));path=next((n for n in names if n not in old or n not in new or old[n]!=new[n]),None)
    if path is None:raise ValueError('no original scan difference')
    if type(path)is not str or not 0<len(path)<=1024 or not path.isprintable() or path.startswith('/') or any(p in ('','.','..') for p in path.split('/')):raise ValueError('bounded scan path')
    category,field='ROW_SHAPE_OR_SCALAR','row'
    if path not in new:category,field='MISSING_NODE','row.presence'
    elif path not in old:category,field='EXTRA_NODE','row.presence'
    elif type(old[path])is dict and type(new[path])is dict:
        a,b=old[path],new[path]
        if set(a)!=set(b):category,field='ROW_FIELDS','row.keys'
        elif a.get('node')!=b.get('node'):
            category,field='NODE_METADATA_OR_SHAPE','node'
            if type(a.get('node'))is dict and type(b.get('node'))is dict:
                key=next(k for k in sorted(set(a['node'])|set(b['node'])) if k not in a['node'] or k not in b['node'] or a['node'][k]!=b['node'][k]);field='node.'+str(key)[:128];category='NODE_HASH_OR_LINK' if key in ('sha256','target') else 'NODE_METADATA_OR_SHAPE'
        elif a.get('identity')!=b.get('identity'):
            category,field='INODE_IDENTITY','identity'
            aa,bb=a.get('identity'),b.get('identity');labels=('device','inode','mode','uid','gid','nlink','size','mtime_ns','ctime_ns')
            if type(aa)in(list,tuple) and type(bb)in(list,tuple) and len(aa)==len(bb)<=9:field='identity.'+labels[next(i for i in range(len(aa)) if aa[i]!=bb[i])]
    value={'schema_version':1,'status':'BOUNDED_SCAN_DIFFERENCE_DIAGNOSTIC_ONLY','acceptance_authority':False,'path':path,'category':category,'field':field,'before_scan_entries':len(old),'after_scan_entries':len(new),'before':summary(raw_before['scan'],path),'after':summary(raw_after['scan'],path),'comparison_view':'EXISTING_EXACT_APPS_PARENT_TIME_PROJECTION','original_failure':'aux-checkpoint-scan-changed'}
    if len(encoded(value))>8192:raise ValueError('bounded scan diagnostic')
    return value

def apps6_linked_compare(runtime,before,after,*,committed):
    def compare(left,right,comparator,*,committed):
        try:return aux.compare(left,right,comparator,committed=committed)
        except ValueError as error:
            if str(error)=='aux-checkpoint-scan-changed':
                try:
                    try:value=apps_scan_difference(left,right,before,after)
                    except Exception as diagnostic_error:value={'status':'SCAN_DIAGNOSTIC_UNAVAILABLE','error_type':type(diagnostic_error).__name__,'acceptance_authority':False}
                    runtime.auxiliary_checks.append({'checkpoint':'scan-comparison-failure','diagnostic':value})
                except Exception:pass # Original refusal always wins over diagnostic failure.
            raise
    return aux_runtime.apps6_postcommit_compare(before,after,runtime.comparator,committed=committed,selected=getattr(runtime,'apps6_auxiliary_selected',False),config=runtime.config,need=aux.need,compare=compare)

LINKED_INPUT={'bytes':3539,'sha256':'aabc95cee161d705dbb8fda79a4f0d937afc10ab2bd8a4714deff35470e92ad5'}
def derive_linked(raw):
    need(pin(raw)==LINKED_INPUT,'exact original linked Runtime override required')
    text=raw.decode();before='check=aux.compare(previous,state,self.comparator,committed=committed)';after='check=apps6_linked_compare(self,previous,state,committed=committed)';need(text.count(before)==1,'one exact active linked comparator call');result=text.replace(before,after);anchor='class Runtime(aux_runtime.Runtime):';need(result.count(anchor)==1,'one exact linked Runtime class');result=result.replace(anchor,inspect.getsource(apps_scan_difference)+'\n\n'+inspect.getsource(apps6_linked_compare)+'\n\n'+anchor)
    old=ast.parse(text);new=ast.parse(result);classes=lambda tree:next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Runtime');a,b=classes(old),classes(new);methods=lambda cls:{n.name:n for n in cls.body if isinstance(n,ast.FunctionDef)};aa,bb=methods(a),methods(b);need(set(aa)==set(bb),'no linked runtime method added/removed')
    for name,node in aa.items():
        expected=ast.parse(ast.get_source_segment(text,node).replace(before,after)).body[0];need(ast.dump(expected,include_attributes=False)==ast.dump(bb[name],include_attributes=False),'linked runtime body changed beyond active comparator: '+name)
    oa=next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name=='apply');na=next(n for n in new.body if isinstance(n,ast.FunctionDef) and n.name=='apply');need(ast.dump(oa,include_attributes=False)==ast.dump(na,include_attributes=False),'linked apply/truth/error status changed')
    return result.encode(),dict(status='EXACT_LINKED_OVERRIDE_ROUTES_EXISTING_APPS_PARENT_TIMES_PLUS_FAILURE_DIAGNOSTIC',before=pin(raw),after=pin(result.encode()),new_allowances='NONE',original_compare='UNCHANGED',failure_status='UNCHANGED',diagnostic_bytes=8192,scope='SOURCE_ONLY_NOT_ACTUAL_ACCEPTANCE')


def apps6_selection_identity(verifier,spec):
    need(verifier.config['before_lock_sha256']==BEFORE and verifier.config['after_lock_sha256']==AFTER,'apps604-parent-selection-locks')
    need(identity(verifier.root)==spec['root_identity'] and Path(spec['args']['root'])==verifier.root,'apps604-parent-selection-root')
    need(spec['worker_sha256']==sha(Path(__file__)),'apps604-parent-selection-worker')
    raw=read(Path(verifier.args.data)/'failure-worker.json',128*1024)
    need(hashlib.sha256(raw).hexdigest()==spec['spec_sha256'] and json.loads(raw)=={k:v for k,v in spec.items() if k!='spec_sha256'},'apps604-parent-selection-spec')
    return dict(nonce=spec['nonce'],spec_sha256=spec['spec_sha256'],worker_sha256=spec['worker_sha256'],root_identity=spec['root_identity'],before_lock_sha256=BEFORE,after_lock_sha256=AFTER,archive_sha256=PACKAGE)


def apps6_reserve_selection(verifier,spec):
    need(getattr(verifier,'apps6_auxiliary_selected',False) is False and not hasattr(verifier,'apps6_selection_reservation') and not hasattr(verifier,'apps6_selection_consumed'),'apps604-fresh-parent-selection')
    verifier.apps6_selection_reservation=apps6_selection_identity(verifier,spec)


def apps6_bind_selection(verifier,witness,spec):
    # boundary still proves real commit87/nonce/source/root/locks/checkpoint.
    boundary(witness,spec)
    expected=apps6_selection_identity(verifier,spec)
    need(getattr(verifier,'apps6_auxiliary_selected',False) is False and getattr(verifier,'apps6_selection_reservation',None)==expected and not hasattr(verifier,'apps6_selection_consumed'),'apps604-reserved-parent-selection')
    del verifier.apps6_selection_reservation
    verifier.apps6_selection_consumed=True
    verifier.apps6_auxiliary_selected=True

POSTCOMMIT_INPUT={'bytes':26466,'sha256':'c8e876dd407cdd2b8882a34b20f64ec93db98fb9ffa9a6b28dd067a82ec97178'}
def derive_postcommit(raw):
    need(pin(raw)==POSTCOMMIT_INPUT,'exact composed Apps6 postcommit driver required')
    text=raw.decode()
    def replace(before,after):
        nonlocal text
        need(text.count(before)==1,'one exact Apps6 postcommit selection seam');text=text.replace(before,after)
    # The Apps source transform rewrites exact package names and versions,
    # but this concatenated Setup DB prefix escaped it. Match the authenticated
    # child's existing exact Apps5/6 exclusions; all later readbacks stay held.
    replace("    verifier.database_changes=tuple('var/lib/pacman/local/cachy-asahi-setup-'+v for v in ('0.1.0-5','0.1.0-6'))","    verifier.database_changes=tuple('var/lib/pacman/local/cachy-asahi-apps-'+v for v in ('0.1.0-5','0.1.0-6'))")
    replace("    need(runtime.commit_ready is True and runtime.commit_calls==1", "    need(getattr(runtime,'apps6_auxiliary_selected',False) is True and runtime.config['before_lock_sha256']==BEFORE and runtime.config['after_lock_sha256']==AFTER,'apps604-authenticated-child-selection')\n    need(runtime.commit_ready is True and runtime.commit_calls==1")
    receipt="dict(status='AUTHENTICATED_APPS5_TO6_CHILD_SELECTION',before_lock_sha256=BEFORE,after_lock_sha256=AFTER,archive_sha256=PACKAGE)"
    replace("worker_sha256=spec['worker_sha256'],prepared_add=", "worker_sha256=spec['worker_sha256'],apps6_selection="+receipt+",prepared_add=")
    replace("'worker_sha256','prepared_add','prepared_remove'", "'worker_sha256','apps6_selection','prepared_add','prepared_remove'")
    replace("marker['worker_sha256']==spec['worker_sha256'] and", "marker['worker_sha256']==spec['worker_sha256'] and marker['apps6_selection']=="+receipt+" and")
    replace("        witness_spec=dict(spec,spec_sha256=spec_pin)\n", "        witness_spec=dict(spec,spec_sha256=spec_pin)\n        apps6_reserve_selection(verifier,witness_spec)\n")
    replace("            after,proof=verify_after(api,child_args,scale,verifier,records,payload)", "            apps6_bind_selection(verifier,witness,witness_spec)\n            after,proof=verify_after(api,child_args,scale,verifier,records,payload)")
    anchor='def execute_case(args,api):';replace(anchor,inspect.getsource(apps6_selection_identity)+'\n\n'+inspect.getsource(apps6_reserve_selection)+'\n\n'+inspect.getsource(apps6_bind_selection)+'\n\n'+anchor)
    before,after=ast.parse(raw),ast.parse(text);functions=lambda tree:{n.name:ast.dump(n,include_attributes=False) for n in tree.body if isinstance(n,ast.FunctionDef)};old,new=functions(before),functions(after)
    need(set(new)==set(old)|{'apps6_selection_identity','apps6_reserve_selection','apps6_bind_selection'},'only three parent selection helpers added')
    need({n for n in old if old[n]!=new[n]}=={'prepare_verifier','arm','boundary','execute_case'},'only exact selected DB prefix plus child witness boundary and parent bridge may change')
    expected=next(n for n in before.body if isinstance(n,ast.FunctionDef) and n.name=='prepare_verifier')
    expected=ast.parse(ast.get_source_segment(raw.decode(),expected).replace("'var/lib/pacman/local/cachy-asahi-setup-'","'var/lib/pacman/local/cachy-asahi-apps-'")).body[0]
    need(ast.dump(expected,include_attributes=False)==new['prepare_verifier'],'parent preparer changed beyond exact Apps DB prefix')
    for tree in (before,after):tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef)]
    need(ast.dump(before,include_attributes=False)==ast.dump(after,include_attributes=False),'postcommit imports/constants/classes held')
    return text.encode(),dict(status='SOURCE_BOUND_AUTHENTICATED_CHILD_TO_DISTINCT_PARENT_SELECTION',before=pin(raw),after=pin(text.encode()),changed_functions=['prepare_verifier','arm','boundary','execute_case'],parent_database_selection='EXACT_APPS5_AND_APPS6_PREFIXES_MATCH_AUTHENTICATED_CHILD',unchanged_readbacks=['verify_after','database_after','assess'],selected_guard='REQUIRES_TRUE_AFTER_EXACT_NONCE_SPEC_WORKER_ROOT_ARCHIVE_LOCK_WITNESS',budgets='UNCHANGED',scope='POSTCOMMIT_EXIT87_ONLY_NO_ACCEPTANCE')
