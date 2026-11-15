# SPDX-License-Identifier: MIT
"""Passive full-namespace and all-111 ALPM ownership DATA, never guest execution."""
import hashlib
import os
from pathlib import Path
import posixpath
import re
import stat


def need(ok,why):
    if not ok:raise ValueError(why)


def safe(name):
    need(re.fullmatch('[A-Za-z0-9._+/@:~-]+',name) and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')), 'literal normalized guest path required');return name


def passive_key(name):
    r"""Bound a literal POSIX inventory key; never quote, decode or execute it.

    This DATA validator is deliberately separate from ``safe`` command paths.
    Backslashes (including the literal spelling \\x2d), brackets, commas and
    spaces remain ordinary filename characters, not escape syntax.
    """
    need(type(name) is str and 0<len(name)<=4095 and all(c.isprintable() for c in name), 'printable bounded passive ownership key required')
    parts=name.split('/')
    need(not name.startswith('/') and all(p not in ('','.','..') for p in parts), 'normalized relative passive ownership key required')
    need(len(name.encode('utf-8'))<=4095 and all(len(p.encode('utf-8'))<=255 for p in parts), 'bounded passive ownership key required')
    return name


def files_text(text):
    """Parse bounded local ALPM files DATA, including a byteempty record.

    A nonempty record must explicitly declare FILES. BACKUP, when present,
    contains owned paths and literal MD5 values, not additional owned entries.
    """
    need(type(text) is str, 'literal ALPM files text required')
    if text=='':return []
    need(len(text)<=4*1024**2 and all(c.isprintable() or c in '\n\t' for c in text) and len(text.encode('utf-8'))<=4*1024**2, 'bounded literal ALPM files text required')
    sections={};section=None
    lines=text.split('\n');need(len(lines)<=150004, 'bounded ALPM files lines required')
    for line in lines:
        if not line:continue
        if line.startswith('%'):
            need(line in ('%FILES%','%BACKUP%'), 'unknown or malformed ALPM files field')
            section=line[1:-1]
            need(section not in sections and (section=='FILES' and not sections or section=='BACKUP' and list(sections)==['FILES']), 'ordered unique ALPM files fields required')
            sections[section]=[]
        else:
            need(section is not None, 'ALPM files value without field');sections[section].append(line)
    need('FILES' in sections, 'nonempty ALPM files record requires FILES field')
    paths=[];seen=set()
    for line in sections['FILES']:
        path=passive_key(line[:-1] if line.endswith('/') else line)
        need(path not in seen, 'duplicate ALPM owned path');seen.add(path);paths.append(path)
    backups=set()
    for line in sections.get('BACKUP',[]):
        pair=line.split('\t');need(len(pair)==2 and re.fullmatch('[0-9a-f]{32}',pair[1]), 'literal ALPM backup path and MD5 required')
        path=passive_key(pair[0]);need(path in seen and path not in backups, 'unique owned ALPM backup path required');backups.add(path)
    return paths


def pin(path):
    with path.open('rb') as stream:return dict(bytes=path.stat().st_size,sha256=hashlib.file_digest(stream,'sha256').hexdigest())


def namespace(root):
    rows = {};size = 0
    for current,dirs,files in os.walk(root,followlinks=False):
        dirs.sort()
        for name in sorted(dirs+files):
            p = Path(current)/name;relative = p.relative_to(root).as_posix();passive_key(relative);mode = p.lstat().st_mode
            if stat.S_ISLNK(mode):
                target=os.readlink(p);need(not any(c in target for c in '\n\r\t'),'literal single-line guest symlink target required')
                row = dict(kind='link',mode=stat.S_IMODE(mode),target=target)
            elif stat.S_ISDIR(mode):row = dict(kind='dir',mode=stat.S_IMODE(mode))
            else:
                need(stat.S_ISREG(mode), 'special dumped guest node refused')
                row = dict(kind='file',mode=stat.S_IMODE(mode),**pin(p));size += row['bytes']
            rows[relative] = row;need(len(rows) <= 150000 and size <= 3*1024**3, 'bounded guest namespace required')
    return rows


def fields(path):
    return fields_text(path.read_text())


def fields_text(text):
    need(type(text) is str and '\0' not in text,'literal ALPM text required')
    result = {};key = None
    for line in text.splitlines():
        if line.startswith('%') and line.endswith('%'):key = line.strip('%');need(key not in result,'duplicate ALPM field');result[key] = []
        elif line:
            need(key is not None,'ALPM value without key');result[key].append(line)
    return result


def all_owned(root,expected,nodes):
    db = root/'var/lib/pacman/local';packages = {};owners = {}
    for directory in sorted(db.iterdir()):
        if directory.name == 'ALPM_DB_VERSION':continue
        need(directory.is_dir() and not directory.is_symlink(),'ordinary local package directory')
        desc = fields(directory/'desc');name,version = desc['NAME'],desc['VERSION']
        need(len(name) == len(version) == 1 and name[0] not in packages,'unique actual ALPM package')
        packages[name[0]] = version[0]
        for path in files_text((directory/'files').read_bytes().decode('utf-8')):
            need(path in nodes,'owned node missing in complete dump')
            owners.setdefault(path,[]).append(name[0])
    need(packages == expected and len(packages) == 111,'exact complete original111 ALPM inventory')
    return {name:dict(owners=sorted(group),**nodes[name]) for name,group in sorted(owners.items())}


def all_owned_records(records,expected,nodes):
    """Join captured raw ALPM text to the complete independently hashed tree."""
    db='var/lib/pacman/local';packages={};owners={}
    need(nodes.get(db,{}).get('kind')=='dir','actual local ALPM directory required')
    directories={name[len(db)+1:] for name in nodes if name.startswith(db+'/') and '/' not in name[len(db)+1:] and name!=db+'/ALPM_DB_VERSION'}
    need(type(records) is dict and set(records)==directories,'complete captured ALPM directories required')
    for directory,record in sorted(records.items()):
        safe(directory);need('/' not in directory and nodes[db+'/'+directory]['kind']=='dir' and type(record) is dict and set(record)=={'desc','files'},'ordinary complete ALPM package record')
        for kind,text in record.items():
            need(type(text) is str,'literal ALPM text required');body=text.encode('utf-8');node=nodes.get(db+'/'+directory+'/'+kind,{})
            need(node.get('kind')=='file' and node['bytes']==len(body) and node['sha256']==hashlib.sha256(body).hexdigest(),'captured ALPM text differs from namespace')
        desc=fields_text(record['desc']);name,version=desc['NAME'],desc['VERSION']
        need(len(name)==len(version)==1 and name[0] not in packages,'unique actual ALPM package');packages[name[0]]=version[0]
        for path in files_text(record['files']):
            need(path in nodes,'owned node missing in complete image')
            owners.setdefault(path,[]).append(name[0])
    need(packages==expected and len(packages)==111,'exact complete original111 ALPM inventory')
    return {name:dict(owners=sorted(group),**nodes[name]) for name,group in sorted(owners.items())}


def resolve(root,guest):
    current = guest;seen = set()
    for _ in range(32):
        need(current.startswith('/') and current not in seen,'guest link cycle/absolute namespace');seen.add(current)
        parts = current.lstrip('/').split('/');prefix = '/';changed = False
        for index,part in enumerate(parts):
            prefix = posixpath.join(prefix,part);p = root/prefix.lstrip('/')
            if p.is_symlink():
                target = os.readlink(p)
                prefix = target if target.startswith('/') else posixpath.join(posixpath.dirname(prefix),target)
                current = posixpath.normpath(posixpath.join(prefix,*parts[index+1:]));changed = True;break
        if not changed:
            p = root/current.lstrip('/');need(p.is_file() and not p.is_symlink(),'qualified guest path is not a regular file');return current,p
    raise ValueError('guest link bound')


def qualify(root,certificate,owned):
    result = {}
    for name,row in certificate['files'].items():
        resolved,file = resolve(root,name)
        need(resolved == row['resolved'] and pin(file) == {k:row[k] for k in ('bytes','sha256')}, 'actual guest input bytes/link resolution differ')
        key = name.lstrip('/');final = resolved.lstrip('/')
        need(row['owner'] in owned.get(key,owned.get(final,{})).get('owners',[]), 'actual ALPM file ownership differs')
        result[name] = row
    for name,path in certificate['link_inputs'].items():
        candidates = ['/usr/lib/lib'+name+'.so','/usr/lib/lib'+name+'.a']
        chosen = next((n for n in candidates if os.path.lexists(root/n.lstrip('/'))),None)
        need(chosen == path,'actual direct GNU ld search choice differs')
    return result


def resolve_nodes(nodes,guest):
    """Resolve guest links inside the captured namespace, never the host tree."""
    current=guest;seen=set()
    for _ in range(32):
        need(type(current) is str and current.startswith('/') and current not in seen and not any(c in current for c in '\0\n\r\t'),'guest link cycle/absolute namespace');seen.add(current)
        parts=current.lstrip('/').split('/');prefix='/';changed=False
        need(all(part not in ('','.','..') for part in parts),'normalized absolute guest path required')
        for index,part in enumerate(parts):
            prefix=posixpath.join(prefix,part);node=nodes.get(prefix.lstrip('/'))
            need(node is not None,'guest path missing from image namespace')
            if node['kind']=='link':
                target=node['target'];prefix=target if target.startswith('/') else posixpath.join(posixpath.dirname(prefix),target)
                current=posixpath.normpath(posixpath.join(prefix,*parts[index+1:]));changed=True;break
            need(node['kind']==('file' if index==len(parts)-1 else 'dir'),'qualified guest path is not a regular file')
        if not changed:return current,node
    raise ValueError('guest link bound')


def qualify_nodes(certificate,owned,nodes):
    result={}
    for name,row in certificate['files'].items():
        resolved,node=resolve_nodes(nodes,name)
        need(resolved==row['resolved'] and {key:node[key] for key in ('bytes','sha256')}=={key:row[key] for key in ('bytes','sha256')},'actual guest input bytes/link resolution differ')
        key=name.lstrip('/');final=resolved.lstrip('/')
        need(row['owner'] in owned.get(key,owned.get(final,{})).get('owners',[]),'actual ALPM file ownership differs');result[name]=row
    for name,path in certificate['link_inputs'].items():
        chosen=next((n for n in ('/usr/lib/lib'+name+'.so','/usr/lib/lib'+name+'.a') if n.lstrip('/') in nodes),None)
        need(chosen==path,'actual direct GNU ld search choice differs')
    return result


PROTECTED = ('etc/passwd','etc/group','etc/shadow','etc/hostname','etc/hosts',
             'etc/resolv.conf','etc/machine-id','etc/locale.conf','etc/fstab',
             'etc/arm16k-systemd-nonce','home/builder/.bash_profile',
             'usr/local/libexec/arm16k-login-proof','etc/systemd/system/default.target',
             'etc/systemd/system/getty.target.wants/serial-getty@ttyAMA0.service',
             'etc/systemd/system/sockets.target.wants/dbus.socket')


def readable(owned,nodes):
    """Conservative other-read/search subset, requiring no privileged guest access."""
    result = {}
    for name,row in owned.items():
        parents = list(Path(name).parents)[:-1]
        if not all(nodes.get(p.as_posix(),{}).get('kind')=='dir' and nodes[p.as_posix()]['mode'] & 0o001 for p in parents):continue
        if row['kind']=='link' or row['kind']=='file' and row['mode'] & 0o004:result[name]=row
    need(any(r['kind']=='file' for r in result.values()) and any(r['kind']=='link' for r in result.values()),'nonempty readable ownership subsets required')
    return result


def preservation(root,baseline,payload,prefix):
    """Complete post-QMP on-disk ownership, fixed PAM/boot and prefix comparison."""
    current = namespace(root)
    need(all_owned(root,baseline['packages'],current)==baseline['owned'], 'postboot all111 owned content/type/mode differs')
    need(all(current.get(name)==row for name,row in baseline['protected'].items()), 'postboot PAM/boot/reference identity differs')
    private = prefix.lstrip('/')+'/'
    actual = {name[len(private):]:row for name,row in current.items() if name.startswith(private)}
    need(actual==payload,'postboot complete private prefix differs')
    return dict(scope='ALL111_OWNED_CONTENT_TYPE_MODE_PLUS_PROTECTED_PAM_BOOT_AND_PRIVATE_PREFIX',
                packages=111,owned_paths=len(baseline['owned']),protected_paths=len(baseline['protected']),
                prefix_nodes=len(payload),all111_unchanged=True,PAM_boot_unchanged=True,prefix_unchanged=True)


def preservation_nodes(nodes,records,baseline,payload,prefix):
    """The same complete ownership/protected/prefix gates over raw observations."""
    need(all_owned_records(records,baseline['packages'],nodes)==baseline['owned'],'postboot all111 owned content/type/mode differs')
    need(all(nodes.get(name)==row for name,row in baseline['protected'].items()),'postboot PAM/boot/reference identity differs')
    private=prefix.lstrip('/')+'/'
    actual={name[len(private):]:row for name,row in nodes.items() if name.startswith(private)}
    need(actual==payload,'postboot complete private prefix differs')
    return dict(scope='ALL111_OWNED_CONTENT_TYPE_MODE_PLUS_PROTECTED_PAM_BOOT_AND_PRIVATE_PREFIX',packages=111,owned_paths=len(baseline['owned']),protected_paths=len(baseline['protected']),prefix_nodes=len(payload),all111_unchanged=True,PAM_boot_unchanged=True,prefix_unchanged=True)
