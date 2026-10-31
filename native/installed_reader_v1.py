# SPDX-License-Identifier: MIT
from reader import *
from installed_tools_v1 import SDK,policy
def retained_public_projection(view, files, binding, map_sha256):
    """Require a closed finite DATA projection, preserving every reader-required leaf."""
    name = 'public-projection.json'
    need(name in files and files[name]['kind'] == 'file', 'source-owned finite projection receipt required')
    value = view.load(name)
    producers = {
        'native/python_backend.py': 'ef300afa53a9480dd2605ee58d0bd18df6569acb6483d55494c6b9c696a96a31',
        'scripts/workflows/python_development.py': '3587267a38e77e9ca93301accf7fe0c6d73f5664320ee11635b0c17734e3004b',
        'scripts/workflows/python_extension.py': 'cdb46ca82ec8d45923361cb190cf2cc426b1bf3587eb4c9fd4cef76d91dd5b36',
        'scripts/workflows/developer_build_systems.py': '8c5025f3d748fb2e5aebb304310852158ebaac0bcaf9ef44cad8676ed5963fbc',
        'scripts/workflows/developer_workflow.py': '531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba',
        'native/uv-inputs.json': 'b61aaff24cc354fc5946af07afc7a088587d52987081ea993e847270cfda94d3'}
    host = {'transport-diagnostic.json','transport-proof.json','receipt.json', 'cleanup.json', 'source-proof.json', 'consumer-inspect.json', 'consumer-after.json',
            'consumer-diagnostic.json', 'image-ledger.json', 'image-retirement.json', 'bootstrap-failure-retention.json', 'provision-diagnostic.json', 'build-summary.json'}
    bootstrap = {phase + '-' + leaf for phase in ('bootstrap', 'overlay') for leaf in
                 ('packages.lock', 'signatures.json', 'bootstrap.json', 'cache-checksums.json', 'Dockerfile', 'runner.json')}
    bootstrap |= {'bootstrap-acquisition.json', 'bootstrap-key-import.log', 'bootstrap-bootstrap.log'}
    reports = {'python': {'result.json', 'project.json', 'commands.json'},
               'extension': {'result.json', 'project.json', 'commands.json'},
               'build-systems': {'result.json', 'project-cmake.json', 'project-meson.json', 'installed-cmake.json', 'installed-meson.json', 'commands.json'}}
    private = {'python': {'home', 'tmp', 'project', 'venv', 'cache', 'dist', 'snapshots'},
               'extension': {'home', 'tmp', 'extension-project', 'snapshots'},
               'build-systems': {'home', 'tmp', 'cmake-project', 'meson-project', 'sources'}}
    reports={'python': set(['commands.json', 'project.json', 'result.json']), 'build-systems': set(['commands.json', 'installed-cmake.json', 'installed-meson.json', 'project-cmake.json', 'project-meson.json', 'result.json']), 'workflow': set(['builds.json', 'commands.json', 'result.json']), 'debugger': set(['c-edited-debug.gdb', 'c-initial-debug.gdb', 'c-recovery-debug.gdb', 'commands.json', 'cpp-edited-debug.gdb', 'cpp-initial-debug.gdb', 'cpp-recovery-debug.gdb', 'project-c.json', 'project-cpp.json', 'result.json']), 'control': set(['commands.json', 'result.json']), 'backend-v1': set(['commands.json', 'result.json']), 'alpm-v1': set(['commands.json', 'result.json'])}
    private={'python': set(['cache', 'dist', 'home', 'project', 'snapshots', 'tmp', 'venv']), 'build-systems': set(['cmake-project', 'home', 'meson-project', 'sources', 'tmp']), 'workflow': set(['checkout', 'empty-template', 'home', 'make-project', 'ninja-project', 'origin', 'project-sources', 'venv']), 'debugger': set(['c-project', 'cpp-project', 'home', 'snapshots', 'source-c-00.c', 'source-c-01.c', 'source-c-02.c', 'source-c-03.c', 'source-c-04.c', 'source-c-05.c', 'source-c-06.c', 'source-c-07.c', 'source-c-08.c', 'source-c-09.c', 'source-cpp-00.cpp', 'source-cpp-01.cpp', 'source-cpp-02.cpp', 'source-cpp-03.cpp', 'source-cpp-04.cpp', 'source-cpp-05.cpp', 'source-cpp-06.cpp', 'source-cpp-07.cpp', 'source-cpp-08.cpp', 'source-cpp-09.cpp', 'tmp']), 'control': set(['home']), 'backend-v1': set(['home']), 'alpm-v1': set(['home'])}
    producers.update({'native/installed_tools_v1.py': '9335bbb76a726917a00b0b2807c7097c3d7cf4fd264cd77f43a91044bbc8c032', 'native/installed_guest_v1.py': 'dae919edd4f031330e973fdcb8d521aaf55fe23df053404af3d0975e2c8a36f6', 'native/installed_uv_v1.py': '590780db7b5e64ba861d85973df03497fd01af2069333398d9964c7504007c67', 'native/installed-contract-v1.json': '6cb07ef8dfa7e9e8be892ad7a491055fe3d83c28a194c4971f9a09d841ae0fdc'})
    for alias in ('workflow','build-systems','debugger','python','control','backend-v1'):
        reports['usr-'+alias]=set(reports[alias]);private['usr-'+alias]=set(private[alias])
    reports['pair-v1']={'result.json','commands.json'};private['pair-v1']={'home'}
    producers.update({'native/installed_alpm_v1.py': 'bec0296e21d85ab405b20118d046e8bf2c6f3627d99b0799886ca6142d5ce6cb', 'native/alpm-contract-v1.json': 'd695f7924938a3bd750d47d2923183b1345e34060fd9950c8e859d49969a7841'})
    site = 'lib/python3.14/site-packages/'; dist = 'uv_build-0.11.28.dist-info/'
    backend = {'bin/uv-build'} | {site + 'uv_build/' + leaf for leaf in ('__init__.py', '__main__.py', 'py.typed')}
    backend |= {site + dist + leaf for leaf in ('METADATA', 'WHEEL', 'RECORD', 'INSTALLER', 'REQUESTED', 'direct_url.json',
                'uv_cache.json', 'licenses/LICENSE-APACHE', 'licenses/LICENSE-MIT', 'sboms/uv-build.cyclonedx.json')}
    log_pattern = r'[0-9]{3}-[A-Za-z0-9][A-Za-z0-9_+.-]{0,127}\.log'
    private_marker = re.compile(br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|BEGIN PGP PRIVATE|ssh-(?:rsa|ed25519)|ecdsa-sha2-|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)|(?:access[_-]?token|password|secret)\s*[=:]|CACHY_(?:OLD_FOUR|RETAINED_BUBBLEWRAP)|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b', re.I)
    need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
         and value.get('status') == 'PASS_FINITE_SOURCE_PUBLIC_DATA_PROJECTION'
         and value.get('binding') == binding and value.get('source_map_sha256') == map_sha256
         and value.get('source_producers') == producers
         and value.get('omitted_private_scopes') == sorted('journey/' + feature + '/' + part for feature, parts in private.items() for part in parts)
         and value.get('original_output_unchanged') is True and value.get('omitted_private_trees_walked') is False
         and value.get('privacy') == 'Selected text/JSON/log ASCII private-key,SSH,token,secret-env marker refusal; exact source-pinned backend executable exempt from text scanning'
         and value.get('scope') == 'Fixed reports, raw referenced command logs and exact backend files only; raw snapshots and remaining private project/build/home/tmp/venv/cache trees not retained',
         'same-source exact finite projection and explicit omission scope required')
    need(pin(view.read(name)) == {key: files[name][key] for key in ('bytes', 'sha256')}, 'projection receipt actual bytes differ')
    selected = value.get('selected')
    need(type(selected) is dict and 0 < len(selected) <= 2998 and set(files) == set(selected) | {name}
         and ('receipt.json' in selected) != ('provision-diagnostic.json' in selected),
         'closed finite projection leaf set and sole authority required')
    for target, row in selected.items():
        parts = target.split('/'); allowed = target in host or target in {'journey/result.json', 'journey/build-summary.json', 'journey/package.json','journey/usr-result.json','journey/usr-package.json','journey/usr-build-summary.json'}
        if len(parts) == 2:
            allowed |= (parts[0] == 'actor-logs' and re.fullmatch(r'[0-9]{4}\.log', parts[1]) is not None
                        or parts[0] == 'provision-logs' and re.fullmatch(r'(?:proof\.json|input-transport-owner\.json|input-cache-owner\.json)-[0-9]{3}\.log', parts[1]) is not None
                        or parts[0] == 'bootstrap-proof' and parts[1] in bootstrap
                        or parts[0] == 'transport-proof' and (parts[1]=='receipt.json' or re.fullmatch(r'[0-9]{4}\.(stdout|stderr)',parts[1]) is not None))
        if len(parts) == 3 and parts[0] == 'journey' and parts[1] in reports:
            allowed |= parts[2] in reports[parts[1]] or re.fullmatch(log_pattern, parts[2]) is not None
        for alias in ('','usr-'):
            if target.startswith('journey/'+alias+'python/venv/'):
                allowed |= target.removeprefix('journey/'+alias+'python/venv/') in backend
        need(allowed and type(row) is dict and set(row) == {'kind', 'mode', 'source_mode', 'bytes', 'sha256'}
             and row['kind'] == 'file' and type(row['mode']) is int and row['mode'] == 0o600
             and type(row['source_mode']) is int and 0 <= row['source_mode'] <= 0o777
             and type(row['bytes']) is int and 0 <= row['bytes'] <= 16*1024**2
             and re.fullmatch('[0-9a-f]{64}', row['sha256'] or ''), 'finite ordinary projected evidence leaf required')
        need(files[target] == {key: row[key] for key in ('kind', 'mode', 'bytes', 'sha256')}
             and pin(view.read(target)) == {key: row[key] for key in ('bytes', 'sha256')},
             'projection selected pin and modes must match manifest and actual DATA')
        if target in {'journey/python/venv/bin/uv-build','journey/usr-python/venv/bin/uv-build'}:
            need(pin(view.read(target)) == dict(bytes=3310128, sha256='82cf8b50be166cf5aab7eddddd0c27535b59cf9b34c4abc9443acacb1256f10c'),
                 'only exact source-pinned backend executable may bypass text scanning')
        else:
            need(not private_marker.search(view.read(target)), 'private marker in projected public DATA refused')
    guest = view.load('journey/result.json') if 'journey/result.json' in selected else None
    for feature in reports:
        prefix = 'journey/' + feature + '/'; report_name = prefix + 'result.json'
        actual_logs = {target for target in selected if target.startswith(prefix) and re.fullmatch(log_pattern, target[len(prefix):])}
        if report_name not in selected:
            need(not actual_logs, 'projected feature logs require original feature result')
            continue
        report = view.load(report_name); commands = report.get('commands', [])
        need(type(commands) is list and len(commands) <= 1000, 'finite projected original feature command list required')
        wanted = set()
        for command in commands:
            leaf = command.get('log')
            need(type(leaf) is str and re.fullmatch(log_pattern, leaf) and prefix + leaf not in wanted,
                 'finite unique projected feature log names required')
            target = prefix + leaf; wanted.add(target)
            need(target in selected and {key: selected[target][key] for key in ('bytes', 'sha256')} == command.get('log_pin'),
                 'all original feature raw command logs must be projected')
        need(actual_logs == wanted, 'closed original feature log projection required')
        command_file = prefix + 'commands.json'
        need(not commands or command_file in selected, 'actual feature command list receipt must be projected')
        if command_file in selected:
            need(view.load(command_file) == commands, 'projected standalone and feature command lists differ')
        if type(guest) is dict and guest.get('status') == 'PASS_NATIVE_DEVELOPER_COMPONENTS_ONLY':
            need(guest.get('build_systems' if feature == 'build-systems' else feature) == report,
                 'positive guest and separately retained feature results differ')
        if feature in ('python','usr-python'):
            installed = report.get('installed_backend', {}).get('files', {})
            adapter_name='journey/'+('usr-' if feature=='usr-python' else '')+'backend-v1/result.json'
            if adapter_name in selected:
                adapter=view.load(adapter_name)
                if adapter.get('status')=='PASS_PINNED_INSTALLED_PEP517_ADAPTER_V1':
                    need(not installed or installed==adapter.get('members'),'original and adapter backend maps differ')
                    installed=adapter.get('members')
            need(type(installed) is dict and len(installed) <= len(backend), 'finite projected installed backend map required')
            wanted_backend = set()
            for path, expected_file in installed.items():
                need(type(path) is str and path.startswith('/out/journey/python/venv/')
                     and path.removeprefix('/out/journey/python/venv/') in backend, 'source wheel layout backend leaf required')
                target = path.removeprefix('/out/').replace('journey/python/','journey/'+feature+'/',1); wanted_backend.add(target)
                need(target in selected and {key: selected[target][key] for key in ('bytes', 'sha256')} == expected_file,
                     'every original installed backend file must be projected')
            need({target for target in selected if target.startswith('journey/'+feature+'/venv/')} == wanted_backend,
                 'exact installed backend evidence projection required')
    return dict(status='VALIDATED_FINITE_PUBLIC_DATA_PROJECTION_ONLY', selected=len(selected))


def installed_result(view, files, guest, binding, alias="", expected_prefix=SDK):
    """An incomplete installed operation never upgrades to native acceptance."""
    need(guest.get('operation') == 'installed-v1'
         and guest.get('installed_prefix') == str(expected_prefix)
         and guest.get('missing') == ({} if guest.get('alpm_installed') else {'workflow':['git']}), 'explicit installed operation/missing Git required')
    contract = policy(Path(__file__).resolve().parents[1])
    package = view.load('journey/'+alias+'package.json')
    need(guest.get('installed_package') == package
         and package.get('stage') == 'OWNED_IMAGE_NATIVE_PACKAGE_PRIVATE_PREFIX_INSTALL'
         and package.get('source_archive') == contract['source_archive']
         and package.get('package') == 'cachy-asahi-developer-tools'
         and package.get('version') == '0.1.0-1', 'actual installed package/source join required')
    expected = {r['path']:r for r in contract['payload_files']}
    need(set(package.get('files',{})) == set(expected), 'complete installed payload map required')
    for name,row in expected.items():
        actual=package['files'][name]
        need(actual == dict(installed=str(SDK.parent/'package-root/usr'/name),moved=str(SDK/name),mode=row['mode'],
             **{k:row[k] for k in ('bytes','sha256')}), 'installed and moved payload pins differ')
    statuses={'workflow':('PASS_LOCAL_DEVELOPER_COMPONENT' if guest.get('alpm_installed') else 'MISSING_TOOLS'),'debugger':'PASS_LOCAL_DEBUGGER_COMPONENT',
              'build-systems':'PASS_AVAILABLE_LOCAL_WORKFLOWS','python':'PASS_LOCAL_PYTHON_WORKFLOW'}
    for feature,status in statuses.items():
        report=view.load('journey/'+alias+feature+'/result.json')
        need(guest['commands'][feature] == report and report.get('status') == status,
             'installed guest and original command result differ')
        if feature=='workflow' and not guest.get('alpm_installed'):need(report.get('missing_required') == ['git'], 'missing Git must remain explicit NOT_RUN')
        if feature=='workflow' and guest.get('alpm_installed'):
            need(set(report['project_workflows'])=={'make','ninja'} and {r['status'] for r in report['project_workflows'].values()}=={'PASS_REAL_PROJECT_WORKFLOW'},'actual Git/Make/Ninja workflow required')
        if feature=='debugger':need(set(report['projects'])=={'c','cpp'} and {r['status'] for r in report['projects'].values()}=={'PASS_REAL_GDB_WORKFLOW'},'both actual GDB languages required')
        if feature=='build-systems':
            need(set(report['project_workflows']) == {'cmake','meson'}
                 and {r['status'] for r in report['project_workflows'].values()} == {'PASS_REAL_PROJECT_WORKFLOW'},
                 'both actual installed build-system outcomes required')
        source=report.get('sources',{}).get('runner')
        relative={'workflow':'developer_workflow.py','build-systems':'developer_build_systems.py',
                  'debugger':'developer_debugger.py','python':'python_development.py'}[feature]
        wanted=expected['lib/cachy-asahi-developer-tools/0.1.0/scripts/workflows/'+relative]
        need(source == {k:wanted[k] for k in ('bytes','sha256')}, 'actual installed runner source pin required')
    backend=view.load('journey/'+alias+'backend-v1/result.json')
    need(guest.get('backend') == backend and backend.get('status') == 'PASS_PINNED_INSTALLED_PEP517_ADAPTER_V1'
         and backend.get('protocol') == 'FORCE_PEP517_PRIVATE_PINNED_UV_BUILD_NO_BUILD_ISOLATION_NO_INDEX',
         'versioned installed Python protocol evidence required')
    wheel=next(r for r in uv_policy(Path(__file__).resolve().parents[1])['artifacts'] if r['role']=='backend')
    need(backend.get('wheel') == wheel and backend.get('identity',{}).get('version') == '0.11.28'
         and backend['identity'].get('builtin_frontend') is False, 'held separate backend identity required')
    for member in wheel['verified_members']:
        name='journey/'+alias+'python/venv/bin/uv-build' if member['name'].endswith('.data/scripts/uv-build') else 'journey/'+alias+'python/venv/lib/python3.14/site-packages/'+member['name']
        need(name in files and pin(view.read(name)) == {k:member[k] for k in ('bytes','sha256')}, 'actual installed backend payload bytes required')
    for feature in (*statuses,'control','backend-v1'):
        report=view.load('journey/'+alias+feature+'/result.json')
        need(report.get('commands'), 'actual installed command records required')
        for row in report['commands']:
            log='journey/'+alias+feature+'/'+row['log']; state=row['supervision']
            need(log in files and pin(view.read(log)) == row['log_pin'] and row['success'] is True
                 and state['reaped'] is True and state['ownership'] == 'REAPED' and state['group_census'] == 'EMPTY_TWICE'
                 and state['output_complete'] is True and state['error'] is None and not state['timeout'] and not state['signals'],
                 'actual raw installed command log and owned retirement required')
    launches=view.load('journey/'+alias+'control/result.json')['commands']
    need(len(launches)==5 and all(row['argv'][0] == str(expected_prefix/'bin/cachy-asahi-developer-tools') for row in launches),
         'all requested commands must actually invoke installed moved launcher')
    forced=[r['argv'] for r in backend['commands'] if r['step']=='force-pep517-build']
    need(forced and all('--offline' in a and '--force-pep517' in a and '--no-build-isolation' in a and '--no-index' in a for a in forced),
         'actual forced offline PEP517 argv required')
    return dict(status=('VALIDATED_INSTALLED_COMPONENT_DATA_ONLY' if guest.get('alpm_installed') else 'VALIDATED_INCOMPLETE_INSTALLED_DEVELOPER_DATA_ONLY'),binding=binding,
        available_components=['debugger','CMake','Meson','Python_PEP517'],missing=({} if guest.get('alpm_installed') else {'workflow':['git']}),
        native='NOT_ADMITTED',native_16K='NOT_QUALIFIED',physical_M2='NOT_RUN',release='NOT_ADMITTED')


def validate(capsule_path, expected):
    need(type(expected) is dict and set(expected) == {'source', 'ref', 'run', 'map_sha256'}
         and re.fullmatch('[0-9a-f]{40}', expected.get('source') or '')
         and isinstance(expected.get('ref'), str) and expected['ref'].startswith('refs/heads/codex/')
         and re.fullmatch('[1-9][0-9]*', expected.get('run') or '')
         and re.fullmatch('[0-9a-f]{64}', expected.get('map_sha256') or ''), 'NULL/unbound actual native evidence refused before reading')
    view = open_capsule(capsule_path)
    binding = {k: expected[k] for k in ('source', 'ref', 'run')}
    binding.update(attempt=1, token=hashlib.sha256((binding['source'] + ':' + binding['ref'] + ':' + binding['run']).encode()).hexdigest()[:24])
    manifest = view.load('artifacts.json')
    need(manifest['schema'] == 1 and manifest['binding'] == binding
         and manifest['source_map_sha256'] == expected['map_sha256'], 'actual binding differs')
    files = manifest['files']
    need(type(files) is dict and all(type(row.get('bytes')) is int and row['bytes'] >= 0
         and re.fullmatch('[0-9a-f]{64}', row.get('sha256') or '') for row in files.values()), 'typed artifact pins')
    need(0 < len(files) <= 3000 and sum(row['bytes'] for row in files.values()) <= 32*1024**2, 'bounded artifact namespace')
    view.verify_manifest(manifest)
    if 'safe-diagnostic.json' in files:
        return retained_safe_diagnostic(view, files, binding, expected['map_sha256'])
    retained_public_projection(view, files, binding, expected['map_sha256'])
    if 'provision-diagnostic.json' in files:
        transport_phase=view.load('provision-diagnostic.json').get('phases',{}).get('input-transport-owner.json')
        if transport_phase is not None:retained_transport_diagnostic(view,files,transport_phase,binding,expected['map_sha256'])
    if 'provision-diagnostic.json' in files:
        diagnostic = view.load('provision-diagnostic.json')
        need(diagnostic['binding'] == binding and diagnostic['source_map_sha256'] == expected['map_sha256']
             and diagnostic['status'] == 'DIAGNOSTIC_HOSTED_INPUT_PROVISIONING_ONLY'
             and diagnostic['native'] == diagnostic['GPG'] == diagnostic['ALPM'] == 'NOT_RUN', 'actual DATA diagnostic only')
        return dict(status='VALIDATED_INPUT_PROVISIONING_DIAGNOSTIC_NOT_NATIVE', binding=binding, native='NOT_RUN', physical_M2='NOT_RUN')
    receipt = view.load('receipt.json'); cleanup = view.load('cleanup.json')
    need(receipt.get('binding') == binding and receipt.get('source_map_sha256') == expected['map_sha256']
         and type(receipt.get('status')) is str and type(cleanup.get('status')) is str,
         'same-source owner and explicit cleanup outcome required')
    selected_status='PASS_INSTALLED_TEST_ALPM_COMPONENTS_V1' if receipt.get('operation')=='installed-alpm-v1' else 'INCOMPLETE_NATIVE_INSTALLED_DEVELOPER_TOOLS_V1'
    consumer_diagnostic = retained_consumer_diagnostic(view, files, receipt, binding, expected['map_sha256'])
    build_summary = retained_build_summary(view, files, binding, expected['map_sha256'])
    failed = (receipt['status'] != selected_status
              or cleanup['status'] != 'PASS_EXACT_OWNED_RESOURCES_RETIRED')
    need(failed or consumer_diagnostic['status'] != 'ABSENT_CONSUMER_DIAGNOSTIC_DATA_ONLY',
         'successful owner cannot omit original consumer diagnostic')
    need(failed or build_summary['status'] != 'ABSENT_BUILD_SUMMARY_DATA_ONLY',
         'successful owner cannot omit original build summary')
    if failed or not build_summary['positive_candidate']:
        return dict(status='VALIDATED_NATIVE_FAILURE_DATA_ONLY', binding=binding,
                    owner_status=receipt['status'], cleanup_status=cleanup['status'],
                    consumer_diagnostic=consumer_diagnostic, build_summary=build_summary, native='NOT_ADMITTED', physical_M2='NOT_RUN')
    if failed or not consumer_diagnostic['positive_candidate']:
        return dict(status='VALIDATED_NATIVE_FAILURE_DATA_ONLY', binding=binding,
                    owner_status=receipt['status'], cleanup_status=cleanup['status'],
                    consumer_diagnostic=consumer_diagnostic, native='NOT_ADMITTED', physical_M2='NOT_RUN')
    retained_consumer_diagnostic(view, files, receipt, binding, expected['map_sha256'], positive=True)
    retained_build_summary(view, files, binding, expected['map_sha256'], positive=True)
    retained_failure_data(view, files, receipt.get('bootstrap_failure_data'), binding, expected['map_sha256'])
    retained_image_lifecycle(view, files, receipt, cleanup, binding, expected['map_sha256'])
    need(receipt['binding'] == binding and receipt['source_map_sha256'] == expected['map_sha256']
         and receipt['status'] == selected_status
         and cleanup['status'] == 'PASS_EXACT_OWNED_RESOURCES_RETIRED', 'all native components plus actual resource retirement required')
    runner = view.load('bootstrap-proof/bootstrap-runner.json')
    need(runner['kernel']['machine'] in ('aarch64', 'arm64') and runner['docker_server_arch'] in ('aarch64', 'arm64')
         and runner['commit'] == binding['source'] and runner['run_id'] == binding['run']
         and runner['docker_endpoint'] in ('unix:///var/run/docker.sock', 'unix:///run/docker.sock')
         and type(runner['page_size']) is int and runner['page_size'] > 0, 'actual native host/local daemon provenance')
    before = view.load('consumer-inspect.json'); after = view.load('consumer-after.json')
    for row in (before, after):
        need(row['Id'] == receipt['consumer']['container'], 'retained exact consumer ID')
        consumer_contract(row, binding, receipt['consumer']['image'], receipt['source_root'], receipt['output_root'], runner['uid'], runner['gid'])
    need(after['State'] == receipt['consumer']['state'] and after['State']['Running'] is False
         and after['State']['ExitCode'] == 0 and after['State']['Status'] == 'exited', 'actual completed consumer daemon state')
    phases = receipt['provisioning']
    retained_transport_proof(view,files,phases['transport'],binding,expected['map_sha256'])
    need(phases['proof']['status'] == 'PASS_EXACT_PUBLISHED_SOURCE_PROOF_ONLY'
         and phases['transport']['status'] == 'PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY'
         and phases['cache']['status'] == 'PASS_EIGHT_INPUT_CACHE_DATA_ONLY', 'complete hosted source and input DATA provisioning')
    for phase in phases.values():
        need(phase['binding'] == binding and phase['source_map_sha256'] == expected['map_sha256'], 'all provisioning same exact source and run')
    for row in phases['proof']['actors'] + phases['transport']['actors'] + receipt['actors'] + cleanup['actors']:
        need(row.get('public_log') in files and files[row['public_log']]['kind'] == 'file', 'actor log must be a retained ordinary artifact')
        need(row['status'] == 'PASS' and row['exit'] == 0 and row['natural_exit'] is True
             and row['group_absent'] is True and row['retirement'] == 'REAPED'
             and row['exit_observed_via_waitpid'] is True and row['ownership_lost'] is False
             and row['forced_cleanup'] is False and row['leader_held_until_group_inspection'] is True
             and pin(view.read(row['public_log'])) == row['log_pin'], 'direct owned wait and retained actor output required')
    guest = view.load('journey/result.json')
    need(guest['status'] == receipt['status'] and guest['architecture'] == 'aarch64'
         and guest['packages'] == receipt['input_inventory'] and guest['physical_M2'] == 'NOT_RUN'
         and guest['native_16K'] == 'NOT_QUALIFIED', 'actual guest identity and non-hardware boundary')
    return installed_result(view,files,guest,binding)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--capsule',type=Path,required=True);parser.add_argument('--binding',type=Path,required=True);args=parser.parse_args();print(json.dumps(validate(args.capsule,load(args.binding)),sort_keys=True))
