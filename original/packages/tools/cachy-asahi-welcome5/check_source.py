#!/usr/bin/env python3
"""Read-only recipe, desktop-entry and installed-payload contract checks."""
import configparser
import argparse
import hashlib
from pathlib import Path
import re
import shlex
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
EXPECTED={
    '/bin/cachy-asahi-welcome':'755',
    '/share/applications/io.github.GabrielKahen.CachyAsahiWelcome.desktop':'644',
    '/share/icons/hicolor/scalable/apps/cachy-asahi-welcome.svg':'644',
    '/share/doc/cachy-asahi-welcome/first-run.txt':'644',
    '/share/doc/cachy-asahi-welcome/updates.txt':'644',
    '/share/doc/cachy-asahi-welcome/recovery.txt':'644',
    '/share/doc/cachy-asahi-welcome/README.md':'644',
    '/share/licenses/cachy-asahi-welcome/LICENSE':'644',
    '/share/licenses/cachy-asahi-welcome/NOTICE':'644',
}


def check(root=HERE):
    recipe=(root/'PKGBUILD').read_text()
    sources=shlex.split(re.search(r'^source=\((.*?)\)',recipe,re.M|re.S)[1])
    pins=shlex.split(re.search(r'^sha256sums=\((.*?)\)',recipe,re.M|re.S)[1])
    assert len(sources)==len(pins)==len(set(sources))
    for name,pin in zip(sources,pins):
        assert '/' not in name and name not in ('.','..')
        path=root/name
        assert path.is_file() and not path.is_symlink()
        assert re.fullmatch('[0-9a-f]{64}',pin) and hashlib.sha256(path.read_bytes()).hexdigest()==pin,name
    assert "license=('MIT')" in recipe and "arch=('aarch64')" in recipe
    assert re.search(r'^pkgrel=5$', recipe, re.M)
    assert "'cachy-asahi-doctor: optional local observation report'" in recipe
    assert "'cachy-asahi-orphans: optional installed metadata assessment'" in recipe
    assert "'cachy-asahi-dns>=0.1.0-2: optional read-only stored profile discovery'" in recipe
    assert {'management.c','management.h','management-report.c','management-report.h',
            'test_management.c','test_management_report.c','test_report_work.c'} <= set(sources)
    makefile=(root/'Makefile').read_text()
    assert re.search(r'^check:.*\btest-report-work\b',makefile,re.M)
    assert '\t./test-report-work\n' in makefile
    assert 'Permission is hereby granted' in (root/'LICENSE').read_text()
    payload={}
    for line in (root/'Makefile').read_text().splitlines():
        if line.startswith('\tinstall '):
            command=shlex.split(line.strip())
            assert len(command)==4 and command[1] in ('-Dm755','-Dm644')
            destination=command[3]
            assert destination.startswith('$(DESTDIR)$(PREFIX)/')
            target=destination.removeprefix('$(DESTDIR)$(PREFIX)')
            assert target not in payload
            payload[target]=command[1][-3:]
    assert payload==EXPECTED
    desktop=configparser.ConfigParser(interpolation=None)
    desktop.optionxform=str
    desktop.read(root/'io.github.GabrielKahen.CachyAsahiWelcome.desktop')
    app=desktop['Desktop Entry']
    assert app['Type']=='Application' and app['Exec']==app['TryExec']=='cachy-asahi-welcome'
    assert app['Icon']=='cachy-asahi-welcome' and app['Terminal']=='false'
    assert 'Autostart' not in desktop and not any(root.glob('*.install'))
    icon=ET.parse(root/'cachy-asahi-welcome.svg').getroot()
    for node in icon.iter():
        assert node.tag.rsplit('}',1)[-1] in ('svg','title','rect','circle','path')
        assert not any('href' in key or key.startswith('on') for key in node.attrib)
    for name in ('first-run.txt','updates.txt','recovery.txt'):
        data=(root/name).read_bytes()
        assert 1<=len(data)<=65536 and b'\0' not in data
        data.decode('utf-8')
    return {'status':'PASS_SOURCE_PAYLOAD_CONTRACT','pinned_sources':len(sources),
            'installed_files':len(payload),'native_build':'NOT RUN','GUI':'NOT RUN'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=HERE)
    print(check(parser.parse_args().root.resolve()))
