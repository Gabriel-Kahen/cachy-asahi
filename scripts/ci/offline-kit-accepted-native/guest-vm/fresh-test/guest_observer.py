# SPDX-License-Identifier: MIT
"""Original full-root/capability providers with one explicit guest kit77 boundary."""
import ast,sys,time,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import guest_phase as G
VIRTUAL={'proc','sys','dev','run','tmp'};OMITTED=VIRTUAL|{'kit77'}
PROVIDERS=Path('/kit77/source/scripts/ci/offline-kit-accepted-native/guest-vm/fresh-test/providers')
need=G.need

def capability_text(raw):
 text=raw.decode();rules=[("   need(actual==set(children[prefix]),'actual node graph differs')","   if not prefix:actual-=OMITTED\n   need(actual==set(children[prefix]),'actual node graph differs')"),("need(_identity(os.fstat(fd))==identity and _mount(fd,limits)==mount,'node identity/mount drift')","need(_identity(os.fstat(fd))==identity and (_mount(fd,limits)==mount or relative in MOUNT_FILES),'node identity/mount drift')")]
 for before,after in rules:need(text.count(before)==1,'exact original capability scope anchor');text=text.replace(before,after)
 ast.parse(text);return text

def policy(rows):
 need(type(rows)is list and len(rows)<=4096,'bounded guest mount table');roots=[r for r in rows if r['path']=='/'];need(len(roots)==1 and roots[0]['fs']=='ext4','one real guest root');observed=[]
 for row in rows:
  n=row['path'].lstrip('/')
  if not n:continue
  need(n.split('/')[0]in VIRTUAL or n in('kit77','kit77/source','kit77/accepted','kit77/runtime'),'only virtual mounts and one explicit kit77 data boundary');observed.append(n)
 need(observed.count('kit77')==1,'one owned data role mount');return dict(source_mount=roots[0]['id'],target_mount=next(r['id']for r in rows if r['path']=='/kit77'),observed_mounts=sorted(observed))

def observe(selection,media):
 a=media.apis();scope=a.scope;scope.RUNTIME=frozenset(OMITTED);scope.INFRASTRUCTURE=frozenset();scope.MOUNT_FILES=frozenset(('etc/hosts','etc/hostname','etc/resolv.conf'))
 rows=scope.mounts(scope._mount_table());p=policy(rows)
 def limits():return a.roots.Limits(deadline=time.monotonic()+600,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3,max_package_files=100000)
 baseline=G.SC.decode(G.read('/kit77/baseline-nodes.json',256*1024**2));overlay=G.SC.decode(G.read('/kit77/overlay.json',1024**2));expected=media.overlay_model(baseline,overlay)
 nodes,_=scope.source_manifest(Path('/'),limits(),a.roots,p);need(nodes==expected,'complete original574 guest boot-root nodes plus exact VM overlay')
 raw=G.read(PROVIDERS/'media-source/scripts/apps/file_capabilities.py',256*1024);text=capability_text(raw);caps=types.ModuleType('_kit77_guest_cap_scope');caps.OMITTED=set(OMITTED);caps.MOUNT_FILES={'etc/hosts','etc/hostname','etc/resolv.conf'};exec(compile(text,'source-pinned-filecaps-kit77-only','exec'),caps.__dict__)
 persistent={n:r for n,r in nodes.items()if n.split('/')[0]not in OMITTED};mapping=caps.observe(Path('/'),persistent,limits());held=G.SC.decode(G.read('/kit77/capabilities.json',16*1024**2));need(mapping==held,'all original file capability bytes and no unknown xattrs/ACLs')
 inventory=media.inventory(Path('/'),nodes);need(G.sha(inventory)=='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac','actual original574 inventory')
 return dict(status='PASS_FULL_ORIGINAL574_NODE_HARDLINK_XATTR_CAPABILITY_INVENTORY_OBSERVATION',nodes=len(nodes),source_nodes_sha256=G.sha(G.encoded(nodes)),baseline_nodes_sha256=G.sha(G.encoded(baseline)),overlay_sha256=G.sha(G.encoded(overlay)),source_capabilities_sha256=G.sha(G.encoded(mapping)),inventory_sha256=G.sha(inventory),observer_source_sha256=G.sha(raw),omitted_roots=sorted(OMITTED),original_bounds=dict(nodes=500000,bytes=8*1024**3,file_bytes=1024**3,package_files=100000,seconds=600),acceptance=False)
