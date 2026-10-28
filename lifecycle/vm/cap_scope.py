# SPDX-License-Identifier: MIT
"""Source-pinned capability observer over original persistent_scope boundaries."""
import ast,types
from pathlib import Path
import contract as C

def runtime_boundaries(omitted):
 """Only exact runtime-root descendants collapse to their already omitted root."""
 runtime={'proc','sys','dev','run','tmp'};result=set()
 for name in omitted:
  C.need(type(name) is str and name and not name.startswith('/') and '\\' not in name and '\0' not in name and all(p not in ('','.','..') for p in name.split('/')),'safe relative persistent-scope boundary required')
  first=name.split('/')[0];result.add(first if first in runtime else name)
 return result

def derive(raw,omitted):
 omitted=runtime_boundaries(omitted)
 C.need(set(omitted)<={'proc','sys','dev','run','tmp','inputs','out','source','workspace','measurement','measurement-source','footprint.py','runner.py','lifecycle.py','setup4.py','upgrade-code','upgrade-config.json','upgrade-pair','upgrade-hook.py','persistent_scope.py','upgrade-signing','etc/hosts','etc/hostname','etc/resolv.conf'},'only existing persistent-scope boundaries')
 text=raw.decode();rules=[("   need(actual==set(children[prefix]),'actual node graph differs')","   if not prefix:actual-=OMITTED\n   need(actual==set(children[prefix]),'actual node graph differs')"),("need(_identity(os.fstat(fd))==identity and _mount(fd,limits)==mount,'node identity/mount drift')","need(_identity(os.fstat(fd))==identity and (_mount(fd,limits)==mount or relative in MOUNT_FILES),'node identity/mount drift')")]
 for a,b in rules:C.need(text.count(a)==1,'exact scoped capability source anchor');text=text.replace(a,b)
 ast.parse(text);m=types.ModuleType('_apps6_persistent_caps');m.OMITTED=set(omitted)-{'etc/hosts','etc/hostname','etc/resolv.conf'};m.MOUNT_FILES={'etc/hosts','etc/hostname','etc/resolv.conf'};exec(compile(text,'file_capabilities-scoped.py','exec'),m.__dict__);return m

def nodes(value):return {n:r for n,r in value.items() if n.split('/')[0] not in {'proc','sys','dev','run','tmp'}}

def audit(raw,omitted,root,reader):
 """Same complete ELF parser/bounds over original persistent directories only."""
 text=raw.decode();a='        children.sort()';b="        if Path(directory)==Path(root):children[:]=[n for n in children if n not in OMITTED]\n        children.sort()"
 C.need(text.count(a)==1,'one root-only ELF infrastructure boundary');text=text.replace(a,b);ast.parse(text)
 m=types.ModuleType('_apps6_persistent_elf');m.OMITTED=set(omitted);exec(compile(text,'elf-audit-persistent.py','exec'),m.__dict__);return m.audit(root,reader)
