# Compact Fish r11 raw check-log retention inverse begins here.
def inverse_source_r11_retention(bodies):
    source_map = 'source-map.json'
    data_name, export_name = PREFIX+'data.py', PREFIX+'public_evidence.py'
    policy_name, program_name = PREFIX+'policy.json', PREFIX+'owner-program.json'
    restored = dict(bodies)
    marker = b'\n\n# Compact Fish r11 raw check-log retention inverse begins here.\n'
    need(restored[data_name].count(marker) == 1, 'one exact Fish r12 inverse seam')
    restored[data_name] = restored[data_name].split(marker, 1)[0]
    for name, edits in ((data_name, ((b"    need(value['kind']=='FISH02_EXACT_PACMAN_CONFIG_MODE_SOURCE_V11' and len(rows)==69 and\n", b"    need(value['kind']=='FISH02_EXACT_CHECK_LOG_RETENTION_SOURCE_V12' and len(rows)==69 and\n"), (b'    prior10 = inverse_source_r10_pacman_mode(bodies)\n', b'    prior10 = inverse_source_r10_pacman_mode(inverse_source_r11_retention(bodies))\n'))), (export_name, ((b"PACKAGE = 'cachy-asahi-fish-config-0.1.0-2-any'\n", b"PACKAGE = 'cachy-asahi-fish-config-0.1.0-2-any'\nCHECK_LOG = 'cachy-asahi-fish-config-0.1.0-2-aarch64-check.log'\n"), (b"*(PACKAGE+'-'+phase+'.log' for phase", b"*(CHECK_LOG if phase == 'check' else PACKAGE+'-'+phase+'.log' for phase"), (b"PACKAGE+'.pkg.tar.xz', PACKAGE+'-check.log'", b"PACKAGE+'.pkg.tar.xz', CHECK_LOG")))):
        for old, new in reversed(edits):
            need(restored[name].count(new) == 1, 'one exact Fish r12 source inverse')
            restored[name] = restored[name].replace(new, old, 1)

    policy = decode(restored[policy_name])
    retention = policy['inner_public_retention']
    for field in ('public_leaves', 'success_required'):
        paths = retention[field]
        for build in (1, 2):
            stem = f'build-{build}/artifacts/'
            current, prior = stem+'cachy-asahi-fish-config-0.1.0-2-aarch64-check.log', stem+'cachy-asahi-fish-config-0.1.0-2-any-check.log'
            need(paths.count(current) == 1 and prior not in paths, 'one exact Fish check path inverse')
            paths[paths.index(current)] = prior

    def row(raw):
        return dict(pin(raw), mode=0o644)

    def encoded(value):
        return (json.dumps(value, indent=2, sort_keys=True)+'\n').encode()

    restored[policy_name] = encoded(policy)
    program = decode(restored[program_name])
    program['files'] = {name: row(raw) for name, raw in restored.items()
                        if name not in (source_map, program_name) and not name.startswith('held-source32/')}
    restored[program_name] = encoded(program)
    prior = decode(restored[source_map])
    prior['kind'] = 'FISH02_EXACT_PACMAN_CONFIG_MODE_SOURCE_V11'
    prior['files'] = {name: row(raw) for name, raw in restored.items() if name != source_map}
    restored[source_map] = encoded(prior)
    need(len(restored) == 70 and sum(map(len, restored.values())) == 2090583
         and pin(restored[source_map]) == dict(bytes=14996, sha256='69315946d019b810ff4b4d14f01c6730e4f416b5836eff4b8f05bf7f0735c1c5')
         and git_tree(restored) == '502a3c8d89050fde5c03ca19d617fc5c2d067687',
         'whole exact published Fish r11 Source inverse')
    return restored
