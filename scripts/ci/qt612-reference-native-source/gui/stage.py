# SPDX-License-Identifier: MIT
"""GUI18 receipt checks. All observations concern bytes, never M2/runtime proof."""
import re


def need(value, why):
    if not value:
        raise ValueError(why)


def enrich_elf(elf):
    providers = {}
    for name, info in elf.items():
        if info['soname'] is not None:
            providers.setdefault(info['soname'], []).append(name)
    for info in elf.values():
        info['version_provider_observations'] = []
        for requirement in info['version_needs'] or []:
            observations = []
            for provider in sorted(providers.get(requirement['file'], [])):
                definitions = elf[provider]['version_definitions']
                names = None if definitions is None else sorted({n for row in definitions for n in row['names']})
                observations.append(dict(staged_path=provider, observed_definition_names=names))
            info['version_provider_observations'].append(dict(file=requirement['file'],
                required_names=[row['name'] for row in requirement['versions']],
                staged_providers=observations, runtime_resolution=None))
        info['needed_providers'] = {name: dict(staged_paths=sorted(providers.get(name, [])),
            availability='STAGED_BYTES_ONLY' if name in providers else 'UNAVAILABLE_IN_STAGE',
            runtime_resolution=None) for name in info['needed']}
    return elf


def validate_stage(stage, contract):
    files, links, elf = stage['files'], stage['symlinks'], stage['elf']
    profile = contract['expected_stage']
    modules = profile['public_modules'] + profile['private_modules']
    need(len(modules) == len(set(modules)) == 18, 'GUI_EXACT18_MODULE_PROFILE')
    for name, info in elf.items():
        need(info['machine'] == 183 and info['geometry_16k'] is True
             and info['metadata_scope'] == 'ELF_BYTES_ONLY_NO_NATIVE_OR_PROVIDER_ACCEPTANCE', 'GUI_AARCH64_16K_BYTES')
        module = re.fullmatch(r'libQt6(.+)\.so\.6', info['soname'] or '')
        need(module is None or module[1] in modules, 'GUI_NO_EXTRA_QT_MODULE')
        need(1 <= len(info['load_segments']) <= 4096 and all(s['alignment'] >= 16384 and
                 (s['virtual_address'] - s['offset']) % 16384 == 0 for s in info['load_segments']), 'GUI_ALL_LOAD_GEOMETRY')
    for module in modules:
        base = 'usr/lib/libQt6' + module
        info = elf.get(base + '.so.6.12.0', {})
        need(info.get('type') == 3 and info.get('soname') == 'libQt6' + module + '.so.6', 'GUI_REQUIRED_MODULE_ELF')
        for suffix, target in (('.so.6', 'libQt6' + module + '.so.6.12.0'), ('.so', 'libQt6' + module + '.so.6')):
            need(links.get(base + suffix, {}).get('target') == target, 'GUI_MODULE_SONAME_LINKS')
        if module in profile['public_modules']:
            names = ('usr/include/qt6/Qt'+module+'/Qt'+module,
                     'usr/lib/pkgconfig/Qt6'+module+'.pc',
                     'usr/lib/cmake/Qt6'+module+'/Qt6'+module+'Config.cmake')
            need(all(n in files for n in names), 'GUI_PUBLIC_DEVELOPMENT_FILES')
        elif module in profile['private_headers']:
            names = ('usr/include/qt6/Qt'+module+'/6.12.0/Qt'+module+'/private/'+profile['private_headers'][module],
                     'usr/lib/cmake/Qt6'+module+'Private/Qt6'+module+'PrivateConfig.cmake')
            need(all(n in files for n in names), 'GUI_PRIVATE_DEVELOPMENT_FILES')
    plugins = {'usr/lib/qt6/plugins/'+p for p in profile['plugins_required']}
    for name in set(profile['tools_required']) | plugins:
        need(name in elf and files[name]['mode'] & 0o111, 'GUI_REQUIRED_TOOL_PLUGIN')
        need(name not in plugins or elf[name]['type'] == 3, 'GUI_PLUGIN_SHARED_OBJECT')
    for name in set(files) | set(links):
        if name.startswith(tuple('usr/lib/qt6/plugins/'+p+'/' for p in (
                'egldeviceintegrations', 'wayland-shell-integration', 'wayland-graphics-integration-client',
                'wayland-decoration-client'))):
            need(name in plugins, 'GUI_DISABLED_PLUGIN_ABSENT')
        if name.startswith('usr/lib/qt6/plugins/sqldrivers/'):
            need(name == 'usr/lib/qt6/plugins/sqldrivers/libqsqlite.so', 'GUI_SQLITE_ONLY')
        need(not name.startswith(tuple('usr/lib/qt6/plugins/'+p for p in (
            'platforms/libqlinuxfb', 'platforms/libqvkkhrdisplay', 'platforms/libqdirectfb',
            'platforms/libqvnc', 'platformthemes/libqgtk3'))), 'GUI_DISABLED_PLATFORM_ABSENT')
    def owned(name):
        trees = ('usr/include/qt6', 'usr/lib/qt6', 'usr/share/qt6', 'usr/share/doc/qt6',
                 'usr/share/licenses/'+contract['package']['name'])
        return (name in ('usr', 'usr/bin', 'usr/include', 'usr/lib', 'usr/lib/cmake', 'usr/lib/pkgconfig',
                         'usr/share', 'usr/share/doc', 'usr/share/licenses', 'usr/bin/qmake6', 'usr/bin/qtpaths6')
                or any(name == t or name.startswith(t+'/') for t in trees)
                or name.startswith(('usr/lib/cmake/Qt6', 'usr/lib/pkgconfig/Qt6'))
                or (name.startswith('usr/lib/libQt6') and '/' not in name[len('usr/lib/'):]))
    need(all(owned(n) for n in set(files) | set(links) | set(stage['directories'])), 'GUI_QT_OWNED_NAMESPACE')


def validate_stage_receipt(stage, contract):
    need(set(stage) == {'status', 'architecture', 'evidence_scope', 'files', 'symlinks', 'directories', 'elf',
        'payload_bytes', 'license_policy_pin', 'native_execution', 'installation', 'hardware', 'provider_transaction',
        'native_acceptance'}, 'GUI_EXACT_STAGE_RECEIPT_KEYS')
    need(stage['status'] == 'PASS_QT612_GUI_DESTDIR_CONTRACT_ONLY' and stage['architecture'] == 'aarch64'
         and stage['evidence_scope'] == 'STAGED_AARCH64_ELF_16K_GEOMETRY_ONLY'
         and stage['native_execution'] == stage['installation'] == stage['hardware'] == 'NOT_ESTABLISHED'
         and stage['provider_transaction'] is None and stage['native_acceptance'] is None
         and stage['license_policy_pin'] == contract['source_notices']['policy'], 'GUI_PASSIVE_STAGE_SCOPE')
    validate_stage(stage, contract)
