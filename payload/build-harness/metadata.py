#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare actual makepkg metadata to the reviewed literal recipe expectation."""
import argparse
from pathlib import Path
import re

NAME='cachy-asahi-glibc-gnu-provider'
VERSION='2.43.caa1-1'
DEPENDS=('linux-api-headers>=4.10','filesystem','tzdata')


def need(ok,why):
    if not ok:raise ValueError(why)


def fields(text):
    need(len(text.encode())<=65536,'bounded package metadata required')
    result={}
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        match=re.fullmatch(r'([a-zA-Z0-9_]+) = (.{1,4096})',line)
        need(match is not None,'literal package metadata field required')
        key,value=match.groups();result.setdefault(key,[]).append(value)
        need(len(result)<=64 and len(result[key])<=1024,'metadata field count bound')
    return result


def srcinfo(actual,expected):
    want=fields(expected);got=fields(actual)
    need(want.get('pkgname')==want.get('pkgbase')==[NAME] and
         want.get('pkgver')==['2.43.caa1'] and want.get('pkgrel')==['1'] and
         want.get('arch')==['aarch64'] and want.get('provides')==['glibc=2.43'] and
         want.get('conflicts')==['glibc'] and want.get('backup')==['etc/gai.conf'] and
         want.get('depends')==list(DEPENDS) and 'replaces' not in want and 'install' not in want,
         'reviewed provider SRCINFO expectation required')
    need(got==want,'actual makepkg SRCINFO differs from reviewed recipe metadata')


def package_identity(info,buildinfo,recipe_sha256):
    need(re.fullmatch('[0-9a-f]{64}',recipe_sha256),'concrete recipe hash required')
    info=fields(info);build=fields(buildinfo)
    need(info.get('pkgname')==[NAME] and info.get('pkgver')==[VERSION] and
         info.get('arch')==['aarch64'] and info.get('provides')==['glibc=2.43'] and
         info.get('conflict')==['glibc'] and 'replaces' not in info and
         sorted(info.get('depend',[]))==sorted(DEPENDS) and
         info.get('backup')==['etc/gai.conf'], 'exact unselected provider PKGINFO required')
    need(build.get('format')==['2'] and build.get('pkgname')==[NAME] and
         build.get('pkgver')==[VERSION] and build.get('pkgarch')==['aarch64'] and
         build.get('pkgbuild_sha256sum')==[recipe_sha256],
         'BUILDINFO concrete provider recipe binding required')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--actual',type=Path,required=True)
    parser.add_argument('--expected',type=Path,required=True)
    args=parser.parse_args()
    srcinfo(args.actual.read_text(),args.expected.read_text())
    print('PASS_ACTUAL_PROVIDER_SRCINFO')
