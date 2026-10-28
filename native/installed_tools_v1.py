# SPDX-License-Identifier: MIT
"""Finite installed-v1 overlay extension; default184 actors/policies stay held."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys

OPERATION = 'installed-v1'
BASE_OPERATION = 'source184'
PREFIX = Path('/opt/native-developer-installed-v1')
SDK = PREFIX / 'moved-sdk'
PACKAGE = 'cachy-asahi-developer-tools'


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def policy(root):
    return json.loads((Path(root) / 'native/installed-contract-v1.json').read_text())


def prepare_context(root, context):
    contract = policy(root)
    target = context / 'installed-v1'; target.mkdir()
    for name, row in contract['context_inputs'].items():
        source = root / name
        need(not source.is_symlink() and pin(source) == {k: row[k] for k in ('bytes', 'sha256')},
             'installed overlay input differs')
        output = target / row['destination']; output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output); output.chmod(row.get('mode', 0o644))
    shutil.copyfile(root / 'native/installed-contract-v1.json', target / 'installed-contract-v1.json')


def dockerfile(original):
    ending = 'USER alarm\nWORKDIR /tmp\n'
    need(original.endswith(ending) and original.count(ending) == 1,
         'exact184 overlay suffix required')
    # Dependency transaction and image labels/FROM are unchanged. Only the new
    # project package is built/installed into this already-owned disposable image.
    return original[:-len(ending)] + '''COPY installed-v1/ /opt/native-developer-installed-v1/
RUN cp /builder-packages.lock /builder-dependency-packages.lock && mkdir /tmp/installed-package-build && chown alarm:alarm /tmp/installed-package-build && cp /opt/native-developer-installed-v1/recipe/* /tmp/installed-package-build/ && chown alarm:alarm /tmp/installed-package-build/*
USER alarm
RUN cd /tmp/installed-package-build && PKGDEST=/tmp/installed-package-build SRCDEST=/tmp/installed-package-build BUILDDIR=/tmp/installed-package-build makepkg --nodeps --nocheck --nosign --noconfirm --config /opt/native-developer-installed-v1/makepkg.conf
USER root
RUN mkdir /opt/native-developer-installed-v1/package-root && bsdtar -xf /tmp/installed-package-build/cachy-asahi-developer-tools-0.1.0-1-any.pkg.tar.zst -C /opt/native-developer-installed-v1/package-root && /usr/bin/python3 -I -B /opt/native-developer-installed-v1/installed_tools_v1.py image-receipt && rm -rf /tmp/installed-package-build
USER alarm
WORKDIR /tmp
'''


def load_packaged_workflow():
    path = SDK / 'lib/cachy-asahi-developer-tools/0.1.0/scripts/workflows/developer_workflow.py'
    body = path.read_bytes()
    need(hashlib.sha256(body).hexdigest() == '531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba',
         'exact installed workflow/helper required')
    spec = importlib.util.spec_from_file_location('_installed_workflow_v1', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(body, str(path), 'exec'), module.__dict__)
    return module


def image_receipt():
    need(os.getuid() == os.geteuid() == 0, 'only owned image build root may stage package payload')
    contract = json.loads((PREFIX / 'installed-contract-v1.json').read_text())
    installed_root = PREFIX / 'package-root/usr'
    need(not SDK.exists(), 'fresh moved installed prefix required')
    installed_root.rename(SDK)
    expected = {row['path'] for row in contract['payload_files']}
    need({str(p.relative_to(SDK)) for p in SDK.rglob('*') if p.is_file()} == expected, 'exact package archive payload set required')
    files = {}
    for row in contract['payload_files']:
        name = row['path']; source = SDK / name
        need(not source.is_symlink() and pin(source) == {k: row[k] for k in ('bytes', 'sha256')},
             'actual package archive prefix payload differs')
        need(source.stat().st_mode & 0o777 == row['mode'], 'actual archive payload mode differs')
        files[name] = dict(installed=str(installed_root / name), moved=str(source), mode=row['mode'], **pin(source))
    archive = Path('/tmp/installed-package-build/cachy-asahi-developer-tools-0.1.0-1-any.pkg.tar.zst')
    receipt = dict(schema=1, stage='OWNED_IMAGE_NATIVE_PACKAGE_PRIVATE_PREFIX_INSTALL',
        package=PACKAGE, version='0.1.0-1', archive=pin(archive), files=files,
        source_archive=contract['source_archive'], dependency_inventory=pin(Path('/builder-dependency-packages.lock')),
        build_check='NOT_RUN_EXPLICIT_NOCHECK; focused v1 controls already held',
        ALPM='NOT_RUN_FOR_PROJECT_PACKAGE; held Required signature policy unchanged',
        original_prefix='REAL_PACKAGE_ARCHIVE_EXTRACTED_THEN_USR_PREFIX_MOVED', native='NOT_ADMITTED')
    (PREFIX / 'image-package.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    need(sys.argv[1:] == ['image-receipt'], 'fixed image receipt operation only')
    image_receipt()
