#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Ordinary hosted payload; waits for actual kernel-domain admission before seed."""
import importlib.util
import json
import os
from pathlib import Path
import resource
import sys
import time

HERE = Path(__file__).resolve().parent
s = importlib.util.spec_from_file_location('llhttp-reference_v2_data',HERE/'data.py');D=importlib.util.module_from_spec(s);s.loader.exec_module(D)
s = importlib.util.spec_from_file_location('llhttp_payload_diagnostic_v3',HERE/'payload_diagnostic.py');X=importlib.util.module_from_spec(s);s.loader.exec_module(X)
s = importlib.util.spec_from_file_location('llhttp_mount_accounting_v4',HERE/'mount_accounting.py');M=importlib.util.module_from_spec(s);s.loader.exec_module(M)


def main():
    X.phase('entry')
    D.need(sys.flags.isolated and __debug__ and os.getuid() == os.geteuid() > 0, 'ordinary isolated payload')
    X.phase('launch-data')
    config_path = Path(sys.argv[1]); config = D.decode(D.read(config_path)); config_path.unlink()
    X.phase('environment')
    os.environ.clear(); os.environ.update(config['environment'])
    root = Path(config['source_root']); map_sha = config['source_map_sha256']
    X.phase('admission')
    a,r = D.admission(root,map_sha,config['admission_raw'].encode(),config['runtime_raw'].encode(),
                      config['admission_sha256'],config['runtime_sha256'],os.environ,int(time.time()))
    X.phase('owner-AS')
    policy = D.decode(D.read(HERE/'policy.json'))
    resource.setrlimit(resource.RLIMIT_AS,(policy['owner']['AS_bytes'],policy['owner']['AS_bytes']))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    X.phase('marker-wait')
    end = time.monotonic()+30; marker = Path(config['marker'])
    while not marker.exists():
        D.need(time.monotonic() < end,'no actual external owner observation before seed');time.sleep(.05)
    X.phase('marker-read')
    raw = D.read(marker); observed = D.decode(raw)
    fields = Path('/proc/self/stat').read_text().rpartition(')')[2].split()
    group = Path('/proc/self/cgroup').read_text().strip();D.need(group.startswith('0::/'),'unified owner cgroup')
    X.phase('owner-observation')
    D.observation(observed,a,map_sha,policy,os.getpid(),int(fields[19]),group[3:])
    X.phase('owner-kernel')
    own = Path('/sys/fs/cgroup'+group[3:])
    D.domain({k:(own/k).read_text().strip() for k in ('memory.max','memory.swap.max','pids.max','cpu.max')},policy['owner'])
    X.phase('dispatch-context')
    D.need(observed['run'] == os.environ['GITHUB_RUN_ID'] and observed['attempt'] == 1
           and observed['job'] == os.environ['GITHUB_JOB'], 'actual hosted run/attempt/job')
    os.environ['CACHY_LLHTTP_MINIMAL_BUILDER_OWNED_DOCKER_HOST'] = observed['endpoint']
    os.environ['CACHY_LLHTTP_MINIMAL_BUILDER_OWNED_TMPDIR'] = os.environ['TMPDIR']
    X.phase('daemon-identity')
    daemon=observed['daemon']; daemon_fields=Path('/proc/'+str(daemon['pid'])+'/stat').read_text().rpartition(')')[2].split()
    D.need(int(daemon_fields[19])==daemon['starttime'] and Path('/proc/'+str(daemon['pid'])+'/cgroup').read_text().strip()=='0::'+daemon['cgroup']+'/daemon','same actual daemon PID/start/domain before seed')
    X.phase('daemon-kernel')
    parent=Path('/sys/fs/cgroup'+daemon['cgroup'])
    D.domain({k:(parent/k).read_text().strip() for k in ('memory.max','memory.swap.max','pids.max','cpu.max')},policy['daemon'])
    X.phase('socket-identity')
    socket=Path(observed['endpoint'][7:]).stat()
    import stat
    D.need(stat.S_ISSOCK(socket.st_mode) and socket.st_uid==0 and socket.st_gid==os.getgid() and stat.S_IMODE(socket.st_mode)==0o660,'same scoped root-owned daemon socket')
    X.phase('readonly-filesystem')
    print(M.record(M.observe(root,Path(config['output']).parent)),file=sys.stderr)
    D.need(not os.access('/tmp',os.W_OK) and not os.access('/var/tmp',os.W_OK) and not os.access(root,os.W_OK),'actual owner writable filesystem restricted to quota work domain')
    X.phase('held-entry')
    base = root/'held-source'; entry_path = base/D.BASE_PREFIX/'entry.py'
    # Exact finite environment seam; restoring it gives every original entry byte.
    namespace = dict(__name__='llhttp-reference_v2_held_entry',__file__=str(entry_path),PINNED_STORAGE=D)
    exec(compile(D.projected_entry(D.read(entry_path)),str(entry_path),'exec'),namespace)
    C = namespace['C']; original_verify = C.verify_source
    def closed_source(held,expected):
        D.need(held == base and expected == map_sha,'exact outer/held Source delegation')
        D.source(root,map_sha)
        return original_verify(held,D.base_binding(root)['map']['sha256'])
    C.verify_source = closed_source
    X.phase('inner-pair')
    report = namespace['execute'](base,Path(config['output']),map_sha,a,r)
    print(json.dumps(dict(status=report['status'],actual_observation=D.pin(raw),Root_acceptance=None)),flush=True)
    return 0 if report['status'] == 'PASS_CURRENT_LLHTTP_MINIMAL206_BUILD_ONLY_NATIVE_PAIR_ONLY' else 1


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error:
        print(X.record(error),file=sys.stderr);raise SystemExit(2)
