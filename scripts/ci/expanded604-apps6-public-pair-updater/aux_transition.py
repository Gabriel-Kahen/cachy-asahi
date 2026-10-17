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
