# SPDX-License-Identifier: MIT
"""Independent local v5 producer evidence predicates; never imports Source code."""
import hashlib,re,stat,importlib.util
from pathlib import PurePosixPath as Path
from pathlib import Path as LocalPath
spec=importlib.util.spec_from_file_location('xs_v5_producer_base',LocalPath(__file__).parent/'base.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
legacy=B.load('bootstrap.py','v5_producer_ancestor')
DOCKER=legacy.DOCKER;OPERATION=legacy.OPERATION;PAIR=legacy.PAIR;INVENTORY=legacy.INVENTORY;RUNNER_SHA=legacy.RUNNER_SHA;DECISION=legacy.DECISION;TMPFS=legacy.TMPFS;MIB=legacy.MIB;Sequence=legacy.Sequence;image_data=legacy.image_data;stopped=legacy.stopped
NATIVE_SHA='1db474ed81295c3604212998617bb44c1ed0339c224d63f61b06768cef6bde4f'
def preentry(exported,op,io):
    io.need('work-preentry-v5.json' in exported,'mandatory v5 preentry receipt')
    raw,mode=exported['work-preentry-v5.json'];io.need(mode==0o600 and len(raw)<=16384,'bounded private0600 v5 preentry receipt')
    r=io.decode(raw);io.need(type(r)is dict and set(r)=={'schema','kind','phase','operation_sha256','source','run','job','image','native_adapter_sha256','work_root','native_acceptance','XS_acceptance','runtime_observation','actor_result'},'exact v5 preentry schema')
    w=r['work_root'];io.need(type(w)is dict and set(w)=={'device','inode','uid','gid','mode','empty','writable'} and all(type(w[k])is int and w[k]>=0 for k in ('device','inode','uid','gid','mode')) and w['inode']>0 and w['uid']==w['gid']==1001 and w['mode']in(0o700,0o755) and w['empty']is w['writable']is True,'actual empty safe owned writable work root')
    io.need(r['schema']==1 and r['kind']=='XS_WORK_VOLUME_PREENTRY_V5' and r['phase']=='OBSERVED_BEFORE_ANY_WORK_WRITE' and all(r[k]==op[k]for k in ('source','run','job','image')) and r['native_adapter_sha256']==op['runtime_identity_generator_sha256']==NATIVE_SHA and r['operation_sha256']==io.pin(exported['operation.json'][0])['sha256'] and r['runtime_observation']==io.pin(exported['runtime-observation.json'][0]) and r['actor_result']==io.pin(exported['actor-result.json'][0]) and r['native_acceptance']is r['XS_acceptance']is False,'preentry raw operation/runtime/actor byte joins')
    return r

def policy(row, image, name, mounts, tmpfs, io, *, initializer=False):
    h, x = row['HostConfig'], row['Config']
    io.need(row['Name'] == '/' + name and row['Image'] == image and row['State']['Running'] is False and
            x['User'] == ('0:0' if initializer else '1001:1001'), 'actual stopped container image/name/user')
    io.need(h['NanoCpus'] == 2000000000 and h['Memory'] == h['MemorySwap'] == 4294967296 and
            h['PidsLimit'] == 256 and h['ReadonlyRootfs'] is True and h['NetworkMode'] == 'none' and
            h['CapDrop'] == ['ALL'] and (h.get('CapAdd') in (['CHOWN'], ['CAP_CHOWN']) if initializer else not h.get('CapAdd')) and
            h['SecurityOpt'] == ['no-new-privileges'] and not h['Privileged'] and
            not h.get('Devices') and not h.get('DeviceRequests'), 'actual CPU/memory/swap/PID/capability/isolation policy')
    if not initializer:
        io.need(h['Init'] is True and h['CgroupnsMode'] == 'private' and h['Tmpfs'] == tmpfs and
                x['Hostname'] == 'perl5423-native', 'actual private init/cgroup/tmpfs/hostname policy')
    actual = {m['Destination']: m for m in row['Mounts']}
    io.need(len(row['Mounts']) == len(mounts) and set(actual) == set(mounts), 'exact container mounts')
    for destination, (kind, value, rw) in mounts.items():
        m = actual[destination]
        io.need(m['Type'] == kind and m['RW'] is rw and m['Name' if kind == 'volume' else 'Source'] == value,
                'actual mount type/source/write policy')
    if '/work' in mounts:
        declared=[m for m in h['Mounts'] if m['Target']=='/work']
        io.need(len(declared)==1 and declared[0]['Type']=='volume' and declared[0]['Source']==mounts['/work'][1]
                and declared[0]['VolumeOptions']['NoCopy'] is True,'explicit v5 owned volume-nocopy')


def actor_argv(name, volume, image, bundle, sha):
    return DOCKER + ['create', '--name', name, '--label', 'cachy-asahi.operation=' + OPERATION,
        '--label', 'cachy-asahi.admission=' + sha, '--cpus=2', '--memory=4g', '--memory-swap=4g', '--pids-limit=256',
        '--init', '--read-only', '--network=none', '--cgroupns=private', '--hostname=perl5423-native', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--user=1001:1001', '--ulimit=nofile=1024:1024', '--ulimit=core=0:0',
        *['--tmpfs=' + k + ':' + v for k, v in TMPFS.items()],
        '--mount', f'type=bind,src={bundle},dst=/inputs,readonly', '--mount', f'type=volume,src={volume},dst=/work,volume-nocopy',
        '--workdir=/work', '--entrypoint=/usr/bin/python3', image, '-I', '-B',
        '/inputs/consumer/native_adapter/native.py', 'actor', '--admission-sha256', sha]

def producer(get, image, work, h, b, daemon, io):
    op_raw = get('xs/operation.json')
    io.need(op_raw == get('bundle/operation.json') and io.pin(op_raw)['sha256'] == h['operation_sha256'], 'actual Root operation copies/pin')
    op = io.decode(op_raw)
    sha = io.pin(op_raw)['sha256']
    io.need(op['schema'] == 1 and op['operation'] == OPERATION and
            op['authorization'] == 'ROOT_ACCEPTED_PAIR_AND_ADMITTED_NATIVE_XS' and
            op['source'] == dict(sha=b['source'], ref=b['ref'].removeprefix('refs/heads/')) and
            all(op[k] == b[k] for k in ('run', 'job', 'approval')) and op['pair'] == PAIR and op['image'] == image and
            op['source_readback_sha256'] == h['source_readback_sha256'] and
            op['native_daemon_identity_sha256'] == h['daemon_identity_sha256'] and
            op['input_signature_audit_sha256'] == h['bootstrap']['signatures_sha256'] and op['expected349_sha256'] == INVENTORY and
            op['runner_sha256'] == RUNNER_SHA and op['runtime_identity_generator_sha256'] == NATIVE_SHA and
            op['authorize_runtime_observation_only'] is True and
            op['accepted_reader_receipt'] == dict(path='/inputs/accepted-reader.json', **DECISION) and
            op['nested_invocation'] == 'NOT_INVOKED' and op['nested_qualification'] == 'NOT_QUALIFIED', 'exact delegated XS operation bindings')
    for name, key in [('xs-admission.json', 'xs_admission_sha256'), ('xs-inputs.json', 'inputs_sha256'),
                      ('xs-plan.json', 'plan_sha256'), ('bundle-map.json', 'bundle_map_sha256')]:
        io.need(io.pin(get('bundle/' + name))['sha256'] == op[key], 'prepared whole operand to Root operation join')
    report = io.decode(get('xs/producer-receipt.json'))
    io.need(report['schema'] == 1 and report['status'] == 'SMOKE_EVIDENCE_EXPORTED_PENDING_INDEPENDENT_READER' and
            report['operation_sha256'] == sha and report['native_acceptance'] is report['XS_acceptance'] is False and
            report['qualification'] == 'NOT_GRANTED' and report['owned_resources_absent'] is True and
            not any(k in report for k in ('error', 'actor_error', 'cleanup_error')), 'actual XS producer completion without acceptance')
    planned = report['planned']
    name, init, volume = (planned[k] for k in ('actor', 'init', 'volume'))
    io.need(re.fullmatch('perl-xs-' + re.escape(b['run']) + '-[0-9a-f]{12}', name) and
            init == name + '-init' and volume == name + '-work', 'exact unique owned XS resource names')
    rows = report['operations']
    io.need(type(rows) is list and len(rows) == 23, 'exact successful native XS operation count')
    captures, seconds = [], 0
    for index, row in enumerate(rows):
        io.tick()
        io.need(set(row) == {'argv', 'lifecycle', 'log', 'returncode', 'launched'} | ({'stdout'} if index == 14 else set()) and
                row['log'] == f'command-{index:03d}.log' and row['launched'] is True and
                type(row['returncode']) is int and row['returncode'] == 0 and
                io.natural(row['lifecycle'], max_seconds=300 if index == 12 else 120) == 0, 'natural bounded exact XS CLI row')
        captures.append((get('xs/' + row['log'], 8 * MIB), b''))
        seconds += row['lifecycle']['elapsed_seconds']
    io.need(seconds <= 600, 'complete XS producer actor budget')
    seq = Sequence(rows, captures, io)
    out, _ = seq.take(DOCKER + ['image', 'inspect', image], data=get('xs/image-inspect.json'))
    token = hashlib.sha256((b['source'] + ':' + b['ref'] + ':' + b['run']).encode()).hexdigest()[:24]
    image_data(out, image, token, b, io)
    actual = io.decode(get('xs/actual-daemon.json'))
    for command, key in [('info', 'info'), ('version', 'version')]:
        out, _ = seq.take(DOCKER + [command, '--format', '{{json .}}'])
        io.need(io.decode(out) == actual[key], 'actual XS daemon raw metadata join')
    io.need(get('xs/root-daemon-proof.json') == get('daemon.json'), 'unchanged Root daemon proof copy')
    for key in ('ID', 'OSType', 'Architecture', 'SecurityOptions', 'CgroupVersion', 'CpuCfsQuota',
                'MemoryLimit', 'SwapLimit', 'PidsLimit', 'DockerRootDir'):
        io.need(actual['info'][key] == daemon['info'][key], 'actual same Rootful unremapped daemon identity')
    socket = actual['socket_before']
    io.need(type(socket) is list and socket == actual['socket_after'] and len(socket) == 5 and
            all(type(v) is int and v >= 0 for v in socket) and socket[1] > 0 and socket[3] == 0 and
            stat.S_ISSOCK(socket[2]) and actual['version']['Server'] == daemon['version']['Server'], 'actual stable root-owned socket/native daemon version')
    out, _ = seq.take(DOCKER + ['container', 'ls', '--all', '--format', '{{.Names}}'])
    io.need(not {name, init} & set(out.decode().splitlines()), 'owned XS containers initially absent')
    out, _ = seq.take(DOCKER + ['volume', 'ls', '--quiet'])
    io.need(volume not in out.decode().splitlines(), 'owned XS volume initially absent')
    label = 'cachy-asahi.admission=' + sha
    seq.take(DOCKER + ['volume', 'create', '--label', label, volume])
    init_argv = DOCKER + ['create', '--name', init, '--label', label, '--cpus=2', '--memory=4g', '--memory-swap=4g',
        '--pids-limit=256', '--network=none', '--read-only', '--user=0:0', '--cap-drop=ALL', '--cap-add=CHOWN',
        '--security-opt=no-new-privileges', '--mount', f'type=volume,src={volume},dst=/work,volume-nocopy',
        '--entrypoint=/usr/bin/chown', image, '1001:1001', '/work']
    seq.take(init_argv)
    out, _ = seq.take(DOCKER + ['inspect', init], data=get('xs/init-before.json'))
    init_row = io.decode(out)[0]
    io.need(init_row['State']['Status']=='created' and init_row['State']['Pid']==0,'initializer created and unstarted')
    policy(init_row, image, init, {'/work': ('volume', volume, True)}, None, io, initializer=True)
    io.need(init_row['Config']['Entrypoint'] == ['/usr/bin/chown'] and init_row['Config']['Cmd'] == ['1001:1001', '/work'],
            'fixed CHOWN-only initializer argv')
    bundle = work / 'bundle'
    seq.take(actor_argv(name, volume, image, bundle, sha))
    out, _ = seq.take(DOCKER + ['inspect', name], data=get('xs/actor-before.json'))
    before = io.decode(out)[0]
    policy(before, image, name, {'/inputs': ('bind', str(bundle), False), '/work': ('volume', volume, True)}, TMPFS, io)
    io.need(before['Config']['Entrypoint'] == ['/usr/bin/python3'] and before['Config']['WorkingDir'] == '/work' and
            before['Config']['Cmd'] == ['-I', '-B', '/inputs/consumer/native_adapter/native.py', 'actor', '--admission-sha256', sha],
            'actual fixed native XS entry argv')
    io.need(init_row['Config']['Labels'].get('cachy-asahi.admission')==sha and before['Config']['Labels'].get('cachy-asahi.admission')==sha,'same admission ownership before initializer start')
    seq.take(DOCKER + ['start', '--attach', init])
    out,_=seq.take(DOCKER + ['inspect',init],data=get('xs/init-after.json'))
    final_init=io.decode(out)[0]
    policy(final_init,image,init,{'/work':('volume',volume,True)},None,io,initializer=True)
    stopped(final_init,image,io)
    io.need(final_init['State']['Status']=='exited','initializer actual naturally exited state')
    io.need(final_init['Id']==init_row['Id'] and final_init['Config']==init_row['Config'],'same naturally retired initializer before consumer start')
    seq.take(DOCKER + ['start', '--attach', name])
    out, _ = seq.take(DOCKER + ['inspect', name], data=get('xs/actor-after.json'))
    after = io.decode(out)[0]
    stopped(after, image, io)
    io.need(after['Id'] == before['Id'], 'same retired XS actor')
    seq.take(DOCKER + ['cp', name + ':/work/output', '-'])
    io.need(rows[14]['stdout'] == 'output.tar', 'captured bounded DATA tar path')
    exported = io.export(get('xs/output.tar', 256 * MIB))
    io.need(io.names('xs/exported') == set(exported), 'complete actual tar/exported namespace')
    for filename, (body, mode) in exported.items():
        io.tick()
        io.need(get('xs/exported/' + filename, 64 * MIB) == body, 'raw tar joins every exported file')
    evidence_map = io.decode(exported['evidence-map.json'][0])
    io.need(type(evidence_map) is dict and 1 <= len(evidence_map) <= 50, 'complete finite flattened runner map')
    membership = {'evidence-map.json', 'actor-result.json', 'runtime-observation.json',
                  'actual-packages.txt', 'operation.json', 'accepted-reader.json', 'work-preentry-v5.json'}
    for relative, row in evidence_map.items():
        io.need(re.fullmatch('[A-Za-z0-9._+/-]+', relative) and all(x not in ('', '.', '..') for x in relative.split('/')) and
                re.fullmatch(r'evidence-[0-9]{3}\.data', row['file']) and row['file'] not in membership and
                io.pin(exported[row['file']][0]) == {k: row[k] for k in ('bytes', 'sha256')}, 'unique complete runner evidence map/raw pin')
        membership.add(row['file'])
    io.need(membership == set(exported), 'no missing or unaccounted exported DATA')
    io.need(exported['operation.json'][0] == op_raw and io.pin(exported['accepted-reader.json'][0]) == DECISION and
            io.pin(exported['actual-packages.txt'][0])['sha256'] == INVENTORY, 'actual actor operation/accepted decision/signed349 inventory')
    for kind, resource, expected_id in [('container', name, before['Id']), ('container', init, init_row['Id']), ('volume', volume, volume)]:
        out, _ = seq.take(DOCKER + [kind, 'inspect', resource])
        observed = io.decode(out)[0]
        labels = observed.get('Labels') if kind == 'volume' else observed['Config']['Labels']
        io.need(labels.get('cachy-asahi.admission') == sha, 'actual exact owned cleanup label')
        if kind == 'container':
            stopped(observed, image, io)
            io.need(observed['Id'] == expected_id, 'cleanup same stopped owned container')
        else:
            io.need(observed['Name'] == volume, 'cleanup same owned volume')
        seq.take(DOCKER + [kind, 'rm', *([] if kind == 'volume' else ['--force']), expected_id])
    out, _ = seq.take(DOCKER + ['container', 'ls', '--all', '--format', '{{.Names}}'])
    outv, _ = seq.take(DOCKER + ['volume', 'ls', '--quiet'])
    io.need(not {name, init} & set(out.decode().splitlines()) and volume not in outv.decode().splitlines(),
            'raw final XS container/volume absence')
    seq.end()
    io.need(report['cleanup'] == [dict(kind=k, name=n, removed=True) for k, n in
            [('container', name), ('container', init), ('volume', volume)]], 'exact owned cleanup receipt')
    result, observation = (io.decode(exported[n][0]) for n in ('actor-result.json', 'runtime-observation.json'))
    io.need(result['schema'] == 1 and result['status'] == 'RUNNER_COMPLETED' and result['failure'] is None and
            result['runner_status'] == 'FOUR_SMOKE_COMMANDS_COMPLETED' and result['operation_sha256'] == sha and
            result['native_acceptance'] is result['XS_acceptance'] is False and result['qualification'] == 'NOT_GRANTED' and
            result['nested_invocation'] == 'NOT_INVOKED' and result['nested_qualification'] == 'NOT_QUALIFIED', 'actual four-command actor receipt without acceptance')
    io.need(observation['schema'] == 1 and observation['operation_sha256'] == sha and
            observation['generator_sha256'] == NATIVE_SHA and
            observation['native_acceptance'] is observation['XS_acceptance'] is False,
            'runtime observation is bound delegated DATA, without acceptance')
    preentry(exported,op,io)
    return op, report, result, observation
