def archive(path):
    nodes={};data={};hardlinks={};total=0
    with tarfile.open(path,mode='r:*') as stream:
        for m in stream:
            n=relative(m.name.rstrip('/'));need(n not in nodes and len(nodes)<60000 and m.uid==m.gid==0 and not m.mode&0o7000,'package member identity/mode')
            need(m.isfile() or m.isdir() or m.issym() or m.islnk(),'ordinary package member')
            need(set(m.pax_headers)<={'path','linkpath','mtime','atime','ctime'},'provider/held package xattrs or unknown PAX refused')
            row=dict(type='directory' if m.isdir() else 'symlink' if m.issym() else 'file',mode=m.mode,uid=m.uid,gid=m.gid)
            if m.issym():
                need(not m.linkname.startswith('/') and '\x00' not in m.linkname,'relative package link');row['target']=m.linkname
            elif m.islnk():
                target=relative(m.linkname)
                need('\0' not in n+target and not n.startswith('.') and not target.startswith('.') and m.size==0,
                     'ordinary payload hardlink header')
                need(len(hardlinks)<16384,'package hardlink alias bound');hardlinks[n]=target
            elif m.isfile():
                total+=m.size;need(m.size<=64*1024**2 and total<=512*1024**2,'package byte bound')
                raw=stream.extractfile(m).read(m.size+1);need(len(raw)==m.size,'package byte count')
                row.update(bytes=m.size,sha256=sha(raw));data[n]=raw
            nodes[n]=row
    # Resolve only archive-owned regular bytes; never ask tarfile or the host to follow a link.
    resolved={n:n for n in data};groups={}
    for name in hardlinks:
        trail=[];seen=set();target=name
        while target not in resolved:
            need(target in hardlinks and target not in seen,'missing/special/cyclic package hardlink target')
            seen.add(target);trail.append(target);target=hardlinks[target]
        origin=resolved[target];source=nodes[origin]
        for alias in trail:
            need(all(nodes[alias][k]==source[k] for k in ('mode','uid','gid')),'package hardlink metadata differs')
            for member in (alias,origin):
                parts=member.split('/')
                need(all('/'.join(parts[:i]) not in nodes or nodes['/'.join(parts[:i])]['type']=='directory'
                         for i in range(1,len(parts))),'package hardlink ancestor is not directory')
            total+=source['bytes'];need(total<=512*1024**2,'package byte bound')
            nodes[alias].update(bytes=source['bytes'],sha256=source['sha256']);data[alias]=data[origin];resolved[alias]=origin
            members=groups.setdefault(origin,{origin});members.add(alias)
            need(len(groups)<=4096 and len(members)<=4096,'package hardlink group bound')
    for members in groups.values():
        key=min(members)
        for name in members:nodes[name]['hardlink_group']=key
    need({'.PKGINFO','.BUILDINFO','.MTREE'}<=set(data),'complete package metadata')
    return dict(nodes={n:r for n,r in nodes.items() if not n.startswith('.')},data=data,metadata=fields(data['.PKGINFO']),buildinfo=fields(data['.BUILDINFO']))
