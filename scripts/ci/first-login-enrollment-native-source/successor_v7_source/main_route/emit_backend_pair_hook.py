# SPDX-License-Identifier: MIT
"""Emit two proposed Source207 successor leaves, without editing any Source map."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backend_successor_adapter import C, H, S, T, write_body

FAMILY = "scripts/ci/first-login-enrollment-native-source/payload/native/"
EXECUTOR = FAMILY + "owned_executor_current_v3.py"
EXECUTOR_PIN = {"bytes":53735,"sha256":"aee41c0956f3249eef2e9c8974238b214622cb385e2d8f736109d9650ce7120a"}

EXECUTOR_CHANGES = (
    ("    def retain(self):", "    def retain(self, *, retain_backend_pairs=False):"),
    ("    def cleanup(self):\n        if not self.output_created:",
     "    def cleanup(self, *, retain_backend_pairs=False):\n        if not self.output_created:"),
    ("            try:self.retain()",
     """            try:
                if retain_backend_pairs:self.retain(retain_backend_pairs=True)
                else:self.retain()"""),
    ("        try:report['cleanup']=controller.cleanup()",
     """        retain_pairs=(getattr(args,'private_backend_pairs',False) is True and context['stage']=='backend'
                      and report['status']=='DELEGATED_STAGE_RETURNED_PENDING_RETIREMENT')
        try:report['cleanup']=controller.cleanup(retain_backend_pairs=True) if retain_pairs else controller.cleanup()"""),
    ("        for path in [*target.rglob('*'),target]:\n"
     "            os.chown(path,self.uid,self.gid);path.chmod(0o700 if path.is_dir()else 0o600)\n",
     """
        if retain_backend_pairs:
            self.retain_backend_pairs(target)
        for path in [*target.rglob('*'),target]:
            os.chown(path,self.uid,self.gid);path.chmod(0o700 if path.is_dir()else 0o600)

    def retain_backend_pairs(self, target):
        need(self.c['stage']=='backend','backend pair custody only')
        manifest_path=target/'public/delegated-backend-public-v4/retention-manifest.json'
        manifest=json.loads(read_data(manifest_path))
        need(manifest['binding']==self.c['binding'] and manifest['nonce']==self.nonce
             and manifest['stage']=='backend' and manifest['evidence_state']=='COMPLETE','exact complete backend retention')
        pairs={}
        for kind in ('enrollment','first-login'):
            src=self.out/'volume/work/stage/stage'/(kind+'-pair.json')
            raw=read_data(src,1024**2)
            wanted=manifest['origins'][kind+'-pair.public.json']
            need(wanted['projection'] is True and pin(raw)==wanted['pin'],'exact original backend pair')
            pairs[kind]=raw
        private=self.out/'private-backend-pairs'
        private.mkdir(mode=0o700)
        for kind,raw in pairs.items():
            dest=private/(kind+'.json')
            fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:
                stream.write(raw);os.fchown(stream.fileno(),self.uid,self.gid)
        os.chown(private,self.uid,self.gid)
"""),
)
LAUNCHER_CHANGES = (
    ("        '--uid',str(os.getuid()),'--gid',str(os.getgid())]+timing_args(plan)",
     """        '--uid',str(os.getuid()),'--gid',str(os.getgid())]+timing_args(plan)+(
            ['--private-backend-pairs'] if getattr(plan,'private_backend_pairs',False) else [])"""),
    ("    available=os.statvfs(plan.control.parent);",
     """    plan.private_backend_pairs=getattr(args,'private_backend_pairs',False)
    if plan.private_backend_pairs:
        need(plan.d['stage']=='backend' and plan.S is not None,'explicit private custody for held backend only')
    available=os.statvfs(plan.control.parent);"""),
    ("        output=Path('/var/lib/cachy-current-'+d['nonce']),uid=args.uid,gid=args.gid))",
     """        output=Path('/var/lib/cachy-current-'+d['nonce']),uid=args.uid,gid=args.gid,
        private_backend_pairs=getattr(args,'private_backend_pairs',False)))"""),
    ("    for key in ('main-root','control-root'):launch.add_argument('--'+key,type=Path,required=True)",
     """    for key in ('main-root','control-root'):launch.add_argument('--'+key,type=Path,required=True)
    for parser in (launch,control):parser.add_argument('--private-backend-pairs',action='store_true')"""),
)


def project(raw, expected, changes, member):
    C.need(C.pin(raw)==expected,"HOLD_SOURCE207_HOOK_PREDECESSOR")
    source=raw.decode()
    for before,after in changes:
        C.need(source.count(before)==1,"HOLD_SOURCE207_HOOK_EXACT_INSERTION")
        source=source.replace(before,after,1)
    compile(source,member,"exec")
    return source.encode()


def proposed(source, launcher):
    raw=T.read_local(str(source/EXECUTOR),EXECUTOR_PIN["bytes"])
    return {EXECUTOR:project(raw,EXECUTOR_PIN,EXECUTOR_CHANGES,EXECUTOR),
            C.LAUNCHER:project(launcher,S.CORE,LAUNCHER_CHANGES,C.LAUNCHER)}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--launcher",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    options=parser.parse_args()
    sys.addaudithook(H.review.fence)
    C.need(sys.flags.isolated and sys.dont_write_bytecode and options.output.is_absolute(),"HOLD_SOURCE207_HOOK_INVOCATION")
    bodies=proposed(options.source,T.read_local(str(options.launcher),S.CORE["bytes"]))
    C.need(options.output.parent.resolve(strict=True) == options.output.parent and
           H.disjoint(options.output,options.source) and H.disjoint(options.output,options.launcher.parent),
           "HOLD_SOURCE207_HOOK_OUTPUT")
    options.output.mkdir(mode=0o700)
    for member,raw in bodies.items():
        file=options.output/member
        file.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        write_body(file,raw)
    print(C.encoded(dict(status="SOURCE207_PAIR_HOOK_LEAVES_PROPOSED_ONLY",
                         files={member:C.pin(raw) for member,raw in bodies.items()},
                         source_map=None, **C.FINAL)).decode(),end="")
