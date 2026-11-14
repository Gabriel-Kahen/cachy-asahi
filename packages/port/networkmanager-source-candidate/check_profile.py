#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned feature declarations/configuration checks; never start networking."""
import argparse
import json
from pathlib import Path
import re
import sys


def profile(path):
    value = json.loads(path.read_text())
    assert value['schema_version'] == 1 and value['package_version'] == '1.58.1-2.1'
    options = value['options']
    for name in ('wifi','iwd','ppp','modem_manager','concheck','teamdctl','ovs','nmcli','nmtui','nm_cloud_setup','nbft','clat','introspection','docs','man','polkit'):
        assert options[name] is True, name
    assert options['config_wifi_backend_default'] == 'wpa_supplicant'
    assert options['config_dhcp_default'] == 'internal'
    assert options['config_dns_rc_manager_default'] == 'symlink'
    assert options['config_plugins_default'] == 'keyfile'
    assert options['polkit_noauth_group'] == '' and options['tests'] == 'yes'
    assert options['ebpf'] == options['vapi'] == 'true' and options['bpf-compiler'] == 'clang'
    return value


def check_source(value, source):
    text = (source/'meson_options.txt').read_text()
    declared = set(re.findall(r"^option\('([^']+)'", text, re.M)) | {'b_lto'}
    assert set(value['options']) <= declared, set(value['options']) - declared
    assert "version: '1.58.1'" in (source/'meson.build').read_text()
    return {'declared_options_checked': len(value['options']), 'network': 'NOT RUN'}


def configured(value, build):
    rows = json.loads((build/'meson-info/intro-buildoptions.json').read_text())
    actual = {row['name']: row['value'] for row in rows}
    expected = {key:value[key] for key in ('prefix','bindir','sbindir','libdir','libexecdir','sysconfdir','localstatedir','buildtype')}
    expected.update(value['options'])
    for key, wanted in expected.items():
        assert actual.get(key) == wanted, (key, actual.get(key), wanted)
    # Prevent optional-dependency auto-disabling after an apparently valid setup.
    config = (build/'config.h').read_text()
    required = ['WITH_WIFI','WITH_IWD','WITH_PPP','WITH_WWAN','WITH_CONCHECK','WITH_TEAMDCTL','WITH_OPENVSWITCH','WITH_NBFT','HAVE_CLAT','HAVE_LIBAUDIT','WITH_JANSSON','WITH_LIBPSL','WITH_FIREWALLD_ZONE','SYSTEMD_JOURNAL']
    observed = {name: bool(re.search(r'^#define '+name+r' 1$',config,re.M)) for name in required}
    assert all(observed.values()), observed
    return {'options_checked': len(expected), 'feature_macros': observed,
            'scope': 'configured source metadata; no daemon/bus/network execution'}


if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--profile',type=Path,default=Path(__file__).with_name('feature-options.json'))
    p.add_argument('--flags',action='store_true');p.add_argument('--source',type=Path);p.add_argument('--build',type=Path)
    args=p.parse_args();value=profile(args.profile)
    if args.flags:
        flags=['--'+key+'='+value[key] for key in ('prefix','bindir','sbindir','libdir','libexecdir','sysconfdir','localstatedir','buildtype')]
        flags+=['-D'+key+'='+str(v).lower() if type(v)is bool else '-D'+key+'='+v for key,v in value['options'].items()]
        sys.stdout.buffer.write(b''.join(f.encode()+b'\0' for f in flags))
    else:
        result={}
        if args.source:result['source']=check_source(value,args.source)
        if args.build:result['configured']=configured(value,args.build)
        print(json.dumps(result,sort_keys=True))
