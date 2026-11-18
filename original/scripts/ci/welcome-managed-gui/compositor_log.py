# SPDX-License-Identifier: MIT
"""Finite stdout budget for the longer, seven-view compositor exercise only."""
STDOUT_LIMIT=2*1024*1024


def logged_type(base):
    class CompositorLogged(base.Logged):
        def __init__(self,*args,**kwargs):
            self.counts=[0,0]
            self.limits=[STDOUT_LIMIT,base.MAX_LOG]
            super().__init__(*args,**kwargs)

        def drain(self,pipe,path):
            index=self.paths.index(path);limit=self.limits[index]
            try:
                with path.open('xb') as output,pipe:
                    read=getattr(pipe,'read1',pipe.read)
                    while raw:=read(65536):
                        output.write(raw[:max(0,limit-self.counts[index])])
                        self.counts[index]+=len(raw)
                        if self.counts[index]>limit:self.overflow=True
            except BaseException as error:self.errors.append(error)

        def reason(self):
            detail=', '.join(path.name+': '+str(count)+'/'+str(limit)+' bytes'
                for path,count,limit in zip(self.paths,self.counts,self.limits))
            return 'compositor process log overflow/failure ('+detail+'; drain_errors='+str(len(self.errors))+')'

        def healthy(self):
            base.need(not self.overflow and not self.errors,self.reason())
            super().healthy()

        def finish(self):
            first=None
            try:super().finish()
            except BaseException as error:first=error
            try:
                base.emit('compositor_log_summary',stage=self.paths[0].name.removesuffix('.stdout'),
                    pid=self.process.pid,returncode=self.process.returncode,
                    drains_complete=all(not thread.is_alive() for thread in self.threads),
                    streams=[dict(path=str(path),observed_bytes=count,limit_bytes=limit)
                             for path,count,limit in zip(self.paths,self.counts,self.limits)],
                    overflow=self.overflow,drain_errors=len(self.errors))
            except BaseException as error:
                if first is None:first=error
            if first is not None:
                if self.overflow or self.errors:raise ValueError(self.reason()) from first
                raise first
    return CompositorLogged


def launch(base,stage,config,logs,env):
    base.need(stage in ('minimal','overlay'),'fixed compositor profile required')
    return logged_type(base)(['/usr/bin/Hyprland','--config',str(config)],stage,logs,env)
