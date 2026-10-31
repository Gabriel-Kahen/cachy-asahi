# SPDX-License-Identifier: MIT
"""Finite hooks in the original traversal; no second scan or public path names."""
import ast
import hashlib
import inspect
import time
import types
import threading

SOURCE_SHA256='cece1c597b2e2eb98b0e3087cc7e7c148b54332f8a1c4f18e04e4552a71fb51d'
COUNTERS=('ticks','nodes','declared_bytes','hashed_bytes','reads','hashes','mount_queries')
OPERATIONS=('start','open-root','root-component','mount-id','file-hash','file-read','walk','walk-scandir','hardlinks','links','final','final-rebind','done')

def need(ok,why):
    if not ok:raise ValueError(why)

def validate(value):
    need(type(value) is dict and set(value)=={'operation','edge','elapsed_ms',*COUNTERS},'closed observer counters')
    need(value['operation'] in OPERATIONS and value['edge'] in ('enter','leave','sample'),'finite observer operation')
    need(all(type(value[k]) is int and 0<=value[k]<=2**63-1 for k in ('elapsed_ms',*COUNTERS)),'finite observer totals')
    return value

class Probe:
    def __init__(self,callback,clock=time.monotonic):
        self.callback=callback;self.clock=clock;self.started=clock();self.next=self.started
        self.counts=dict.fromkeys(COUNTERS,0);self.seen=set();self.disabled=False
        self.active=[];self.lock=threading.Lock();self.stop=threading.Event()
    def emit(self,operation,edge,now):
        self.next=now+5
        self.callback(validate(dict(operation=operation,edge=edge,elapsed_ms=int((now-self.started)*1000),**self.counts)))
    def __call__(self,operation,edge='sample',count=0):
        if self.disabled:return
        try:
            with self.lock:
                now=self.clock()
                if operation in COUNTERS:
                    self.counts[operation]+=count
                    operation,edge=self.active[-1] if self.active else ('start','sample')
                else:
                    if edge=='enter':self.active.append((operation,edge))
                    elif edge=='leave' and self.active and self.active[-1][0]==operation:self.active.pop()
                key=(operation,edge)
                if key not in self.seen or now>=self.next:
                    self.seen.add(key);self.emit(operation,edge,now)
        except Exception:self.disabled=True # Diagnostic IO cannot change original observation/refusals.
    def start(self):
        def sample():
            while not self.stop.wait(5):
                if self.disabled:return
                try:
                    with self.lock:
                        operation,edge=self.active[-1] if self.active else ('start','sample')
                        self.emit(operation,edge,self.clock())
                except Exception:self.disabled=True
        self.thread=None
        try:
            self.thread=threading.Thread(target=sample,name='bounded-original-observer',daemon=True);self.thread.start()
        except Exception:self.disabled=True
    def close(self):
        self.stop.set()
        if self.thread is not None and self.thread.ident is not None:self.thread.join(timeout=1)

# These insertions only expose values already computed by the original code.
RULES=(
    ("                footprint['nodes'] += 1","                footprint['nodes'] += 1\n                _probe('nodes',count=1)"),
    ("                    footprint['bytes'] += before.st_size","                    footprint['bytes'] += before.st_size\n                    _probe('declared_bytes',count=before.st_size)"),
    ('        walk(descriptor)\n        if internal:\n            validate_groups()',"        _probe('walk','enter')\n        walk(descriptor)\n        _probe('walk','leave')\n        if internal:\n            _probe('hardlinks','enter')\n            validate_groups()\n            _probe('hardlinks','leave')\n        _probe('links','enter')"),
    ('        with os.scandir(directory) as entries:',"        _probe('walk-scandir','enter')\n        with os.scandir(directory) as entries:\n            _probe('walk-scandir','leave')"),
    ("        rebound = _open_root(root)\n        try:","        _probe('final-rebind','enter')\n        rebound = _open_root(root)\n        try:"),
    ("            os.close(rebound)\n        report['complete']","            os.close(rebound)\n            _probe('final-rebind','leave')\n        report['complete']"),
    ('        for auxiliary in (',"        _probe('links','leave')\n        _probe('final','enter')\n        for auxiliary in ("),
    ("        report['complete'] = True","        report['complete'] = True\n        _probe('final','leave')"),
)

def facade(roots,callback,*,mount_query=None):
    """Compile only exact original function definitions with counted hook insertions."""
    raw=inspect.getsource(roots)
    need(hashlib.sha256(raw.encode()).hexdigest()==SOURCE_SHA256,'exact original full-root observer required')
    tree=ast.parse(raw);wanted={'observe','_open_root','_file_hash','_mount_id'}
    functions={n.name:ast.get_source_segment(raw,n) for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in wanted}
    need(set(functions)==wanted,'exact observer definitions')
    originals=dict(functions);probe=None;namespace=dict(vars(roots))
    original=functions['observe'];adapted=original
    for before,after in RULES:
        need(adapted.count(before)==1,'counted observer hook anchor');adapted=adapted.replace(before,after)
    reverse=adapted
    for before,after in reversed(RULES):reverse=reverse.replace(after,before)
    need(reverse==original,'observer checks and return body unchanged')
    functions['observe']=adapted
    # The original hash loop/read size/identity/limits remain intact.
    for name,operation,counter in (('_file_hash','file-hash','hashes'),('_mount_id','mount-id','mount_queries'),('_open_root','open-root',None)):
        original=functions[name];text=original
        if name=='_open_root':
            anchor='            child = os.open(part, flags, dir_fd=descriptor)'
            need(text.count(anchor)==1,'original root component seam')
            text=text.replace(anchor,"            _probe('root-component','enter')\n"+anchor+"\n            _probe('root-component','leave')")
            functions[name]=text
        if name=='_file_hash':
            text=original
            anchor='        data = os.read(descriptor, min(1024**2, expected.st_size - hashed + 1))'
            need(text.count(anchor)==1,'original bounded read seam')
            text=text.replace(anchor,"        _probe('file-read','enter')\n"+anchor+"\n        _probe('reads',count=1)\n        _probe('hashed_bytes',count=len(data))\n        _probe('file-read','leave')")
            functions[name]=text
        elif name=='_mount_id':functions[name]=original
    for name,text in functions.items():
        stripped='\n'.join(line for line in text.splitlines() if not line.lstrip().startswith("_probe("))
        need(stripped==originals[name],'removing diagnostic hooks restores exact original body')
        definition=ast.parse(text);exec(compile(definition,'<exact-observer-progress>','exec'),namespace)
    def wrap(function,operation,counter=None):
        def call(*args,**kwargs):
            probe(operation,'enter')
            if counter:probe(counter,count=1)
            try:return function(*args,**kwargs)
            finally:probe(operation,'leave')
        return call
    if mount_query is not None:namespace['_mount_id']=mount_query(roots._mount_id)
    for name,operation,counter in (('_file_hash','file-hash','hashes'),('_mount_id','mount-id','mount_queries'),('_open_root','open-root',None)):
        namespace[name]=wrap(namespace[name],operation,counter)
    original_observe=namespace['observe']
    class Limits:
        def __init__(self,base):self.base=base
        def __getattr__(self,key):return getattr(self.base,key)
        def tick(self):
            self.base.tick();probe('ticks',count=1)
    def observe(root,*,limits,**kwargs):
        nonlocal probe
        probe=Probe(callback);namespace['_probe']=probe
        probe.start();probe('start','enter')
        try:return original_observe(root,limits=Limits(limits),**kwargs)
        finally:probe('done','leave');probe.close()
    return types.SimpleNamespace(**dict(vars(roots),observe=observe))
