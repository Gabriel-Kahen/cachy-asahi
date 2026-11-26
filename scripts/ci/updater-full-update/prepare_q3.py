# SPDX-License-Identifier: MIT
"""Prepare the updater boot and available offline inputs without issuing a VM."""

import argparse
import gzip
import json
from pathlib import Path
import re
import runpy
import secrets
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PINNED_IMAGES = {
    'boot.raw': (1611661312, '951bdc40ec6d3c4735d688acda30f153a22019862bc255059b874d9c27e0a858'),
    'scratch.raw': (17179869184, '70ca6c345fcf5e5d29d0bb90993d54c17a54164f23b2a6fe839e061b51edca45'),
    'Image': (9019400, '36066ded2f5721fd9bb257cebb2e4cb32084f45c3717f4d7a45430fe3cdcc494'),
}
TOOLS = {
    'debugfs': (218712, '41d0fc883db19d89f65503ce3cd1c016bd7a33ad750f28a349c050742de0e9b1'),
    'e2fsck': (405720, '3287fdce1c7f9ffadc760e24fbae88a0ecd9abe7536f2f60725c9bfbd480333d'),
    'mke2fs': (145768, '0b645e158b060a7ff22bff543b20c6aeba043f7ebca24e7a2f63a20bd3e46130'),
}
HOOKS = (1001, 'd31e16267b226b46367696f662825642762d34699724525abeaeaa57bad8fe2e')
PRIOR_PLAN = '22ee97c1d5e023db28572b03ec3ecf7650a3f14b568161b0f71754454b63f10c'
PRIOR_BOOT = (1611661312, 'aef2b0c4df60f794f7a4f34180e99ff1dba44447bd14b3e0502fbbc3c5d3cd99')
BOOT_PAYLOAD = '/updater-q3-v2'


def file_pin(size, digest):
    return {'bytes': size, 'sha256': digest}


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def prepare(args):
    p = SimpleNamespace(**runpy.run_path(str(REPO / 'scripts/integration/qt612_md4c_compile/prepare.py')))
    qt = REPO / 'scripts/integration/qt612_gui_16k_link_checkpoint'
    q = SimpleNamespace(**runpy.run_path(str(qt / 'prepare.py')))
    capsule = SimpleNamespace(**runpy.run_path(str(qt / 'gui_capsule.py')))
    guest = runpy.run_path(str(HERE / 'guest.py'))
    runtime = runpy.run_path(str(REPO / 'scripts/port/updater-native-stage/runtime_intake.py'))
    setup = runpy.run_path(str(HERE / 'q3-setup.py'))
    dest = args.output
    parent = dest.parent
    p.need(dest.is_absolute() and dest.resolve() == dest and not dest.exists()
           and re.fullmatch(r'/[A-Za-z0-9_./-]+', str(dest)) and not parent.stat().st_mode & 0o022,
           'fresh output under an ordinary private parent required')
    base_path = args.capsule if args.prior_packet is None else args.prior_packet
    originals = dict(PINNED_IMAGES)
    if args.prior_packet is not None:
        prior = p.strict_json(p.read(base_path / 'PLAN.UNISSUED.json', PRIOR_PLAN))
        p.need(prior['inputs'] == {name: file_pin(*pin) for name, pin in
                                  (originals | {'boot.raw': PRIOR_BOOT}).items()}
               and prior['authority'] is None,
               'exact prior isolated updater preparation required')
        originals['boot.raw'] = PRIOR_BOOT
    image_sources = {name: base_path / 'inputs' / name for name in originals}
    for source in (base_path, args.q3_lock, args.hooks, args.vendor, args.official):
        p.need(not dest.is_relative_to(source) and not source.is_relative_to(dest), 'distinct output required')
    expected = {'q3.lock': (6925, guest['Q3_LOCK']), 'hooks.list': HOOKS}
    read = lambda path, pin: p.observe(path, pin[0], collect=True)
    q3 = {}
    for name, path in (('q3.lock', args.q3_lock), ('hooks.list', args.hooks)):
        data, observed = read(path, expected[name])
        p.need(observed == file_pin(*expected[name]), 'Q3 lock or hook pin differs')
        q3[name] = data
    base = guest['inventory'](q3['q3.lock'])
    p.need(len(base) == 356 and base.get('sudo') == '1.9.17.p2-6' and base.get('xdg-utils') == '1.2.1-2',
           'exact Q3 sudo and xdg versions required')
    before = base | guest['SUPPLEMENTS']
    q3['before.lock'] = ''.join(f'{name} {before[name]}\n' for name in sorted(before)).encode()
    p.need(len(before) == 362 and p.sha(q3['before.lock']) == setup['BEFORE_SHA'], 'exact 362-package lock required')
    guest['expected_inventories'](q3['q3.lock'], q3['before.lock'])
    vendor_pins = {name: pin for name, _url, pin in runtime['runtime_files']() if not name.startswith('xdg-utils-')}
    keyring = runtime['KEYRING']
    vendor_pins[keyring] = runtime['KEYRING_PIN']
    vendor = {}
    for name, pin in vendor_pins.items():
        path = args.official if name == keyring else args.vendor / name
        body, observed = read(path, pin)
        p.need(observed == file_pin(*pin), 'vendor pin differs')
        vendor[name] = body

    format_tools = q.Formatting(capsule, {name: {'path': f'/usr/bin/{name}', **file_pin(*pin)}
                                          for name, pin in TOOLS.items()})
    nonce = secrets.token_hex(16)
    input_uuid = p.result_uuid(nonce)
    payload = {
        'guest-init.sh': (HERE / 'q3-guest-init.sh').read_bytes(),
        'q3-setup.py': (HERE / 'q3-setup.py').read_bytes(),
        'guest.py': (HERE / 'guest.py').read_bytes(),
        'rtc-clock.sh': (REPO / 'scripts/integration/arm16k_c01_workflow_rtc/rtc-clock.sh').read_bytes(),
        'client.py': (REPO / 'scripts/client/client.py').read_bytes(),
        'boot-identity': f'{nonce} {input_uuid}\n'.encode(),
        'vendor.json': json_bytes({name: file_pin(*pin) for name, pin in vendor_pins.items()}),
    }
    p.need(p.sha(payload['client.py']) == guest['CLIENT_SHA'], 'pinned detached verifier required')
    with TemporaryDirectory(prefix='.updater-q3-', dir=parent) as temporary:
        stage = Path(temporary) / 'packet'
        stage.mkdir(mode=0o700)
        inputs, media = stage / 'inputs', stage / 'unsigned-media'
        for folder in (inputs, media, media / 'vendor', media / 'repo'):
            folder.mkdir(mode=0o700)
        for name, body in q3.items():
            p.new(media / name, body)
        for name, body in vendor.items():
            p.new(media / 'vendor' / name, body)
        fixture = runpy.run_path(str(REPO / 'scripts/ci/updater-optional-check/historical/real-check/real-check.py'))
        for path, version in ((media / guest['OLD_ARCHIVE'], guest['OLD']), (media / 'repo' / guest['REPO'][2], guest['NEW'])):
            fixture['write_package'](path, version)
            body = gzip.compress(gzip.decompress(path.read_bytes()), mtime=0)
            guest['verify_fixture_archive'](body, version)
            path.write_bytes(body)
            path.chmod(0o444)
        for name, source in image_sources.items():
            info = source.lstat()
            p.need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o444 and info.st_nlink == 1
                   and info.st_size == originals[name][0],
                   'sealed original image required')
            if name == 'scratch.raw' and args.prior_packet is not None:
                continue  # Mount one verified owned clone per admitted attempt.
            clone = inputs / name
            p.clone(source, clone)
            p.match(clone, file_pin(*originals[name]))
            if name != 'boot.raw':
                clone.chmod(0o444)
        q.patch_boot(SimpleNamespace(P=p, PAYLOAD=BOOT_PAYLOAD, BOOT_BYTES=PINNED_IMAGES['boot.raw'][0]),
                     format_tools, inputs / 'boot.raw', nonce, payload)
        (inputs / 'boot.raw').chmod(0o444)
        append = p.boot_cmdline(nonce, BOOT_PAYLOAD + '/guest-init.sh')
        append += (f' cachy_updater16k_nonce={nonce} cachy_updater16k_case={args.case}'
                   ' cachy_updater16k={PLAN_SHA256} arm16k_rtc_host_epoch={HOST_UTC}')
        argv = p.vm_argv('/inputs/Image', append, 'updater-q3-' + nonce,
                         (('boot', 'file=/inputs/boot.raw,format=raw,readonly=on'),
                          ('scratch', 'file=/out/overlay.qcow2,format=qcow2,readonly=off,discard=ignore'),
                          ('input', 'file=/inputs/media.raw,format=raw,readonly=on')))
        plan = {'kind': 'UPDATER_Q3_PREPARATION_UNISSUED', 'authority': None, 'nonce': nonce, 'case': args.case,
                'input_ext4': {'bytes': 128 << 20, 'label': 'UPDATER16K', 'uuid': input_uuid},
                'base_inventory': 356, 'target_inventory': 362,
                'originals': {name: {'path': str(source), **file_pin(*originals[name])}
                              for name, source in image_sources.items()},
                'inputs': {name: file_pin(*PINNED_IMAGES[name]) for name in ('scratch.raw', 'Image')},
                'boot_payload': {name: file_pin(len(body), p.sha(body)) for name, body in payload.items()},
                'qemu_argv_template': argv}
        plan['inputs']['boot.raw'] = p.observe(inputs / 'boot.raw', PINNED_IMAGES['boot.raw'][0])[1]
        plan['unsigned_media'] = {path.relative_to(media).as_posix(): p.observe(path, 1 << 20)[1]
                                  for path in sorted(media.rglob('*')) if path.is_file()}
        p.new(stage / 'PLAN.UNISSUED.json', json_bytes(plan))
        stage.rename(dest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    origin = parser.add_mutually_exclusive_group(required=True)
    origin.add_argument('--capsule', type=Path)
    origin.add_argument('--prior-packet', type=Path)
    for name in ('q3-lock', 'hooks', 'vendor', 'official', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--case', choices=('update', 'signature-refusal'), default='update')
    prepare(parser.parse_args())


if __name__ == '__main__':
    main()
