#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""One exact public-input carrier; private credential exists only in fetch()."""
import argparse
import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import resource
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import threading
import time

HERE = Path(__file__).resolve().parent
EXPECTED = {'all501_required': True, 'files': {'packages/aquamarine-0.15.1-1-aarch64.pkg.tar.xz': {'bytes': 396652, 'mode': 420, 'sha256': '49dc8acbad78f97698bcefaba742c231eb108db41e6afaa3b89bac078eb22b7d'}, 'packages/aquamarine-0.15.1-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'a9b3653f4ef9080f6104b4a1f9b079d6c1198df107b12b3b15dce181e1de05dd'}, 'packages/automake-1.19-1-any.pkg.tar.xz': {'bytes': 653408, 'mode': 420, 'sha256': '8617b421ac17d0a8c35aa5a788a1bf36f0a9f934016a57b542b3efb45064d57d'}, 'packages/automake-1.19-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '92845534d0412ad4160e7d79b0a2bf8aaee95cc7b1a04fc44efcdb0f178d5693'}, 'packages/avahi-1:0.9rc5-1-aarch64.pkg.tar.xz': {'bytes': 413888, 'mode': 420, 'sha256': 'cc5397663792b8a6aeeb8879d44020e21f7dc8f3889e4bcab25cb976b0033481'}, 'packages/avahi-1:0.9rc5-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '764a6b9ba1ac7ea6c72b6515645115e60b27b1029ac8205cfebfaeeb135f2612'}, 'packages/benchmark-1.9.5-2-aarch64.pkg.tar.xz': {'bytes': 222384, 'mode': 420, 'sha256': '710ab192abd501f2783bfb665377d0c3324a7619763a8b2afda0d69bc8798b96'}, 'packages/benchmark-1.9.5-2-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '19836d4c54a9eba85ba1dfccfb843b218b93d7b92a1d5f189e5aa2272965aecb'}, 'packages/boost-libs-1.92.0-1-aarch64.pkg.tar.xz': {'bytes': 5800604, 'mode': 420, 'sha256': '0a0e6f37821cfd34b077658e6e5ba6a73c648e2094ccd74eb489180ba455fead'}, 'packages/boost-libs-1.92.0-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '5d66f5656f6eb76bc8ddbdcb28c28562d854cb6297d14f5fae01c508a850b0b4'}, 'packages/ca-certificates-mozilla-3.131-1-aarch64.pkg.tar.xz': {'bytes': 380492, 'mode': 420, 'sha256': '9703baef3672ee4c44edca301c4e2524414bef82e81ac30345e2f1751ae5672d'}, 'packages/ca-certificates-mozilla-3.131-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '9f751d2b54b949b270fc2d3e41d0f5423df2ff81f23da3724da2d52b313425bd'}, 'packages/coreutils-9.12-2-aarch64.pkg.tar.xz': {'bytes': 2854560, 'mode': 420, 'sha256': '855b6439cc94fe5d0a3b1428e63ca785c0fa83135e0c0d59277d704d8f4dd647'}, 'packages/coreutils-9.12-2-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'f1e348bfb3c5dfc01681ecfc43df3c2a984bc9cd33cc0ea5d83e4b32ea05ee61'}, 'packages/cryptsetup-2.8.8-1-aarch64.pkg.tar.xz': {'bytes': 806768, 'mode': 420, 'sha256': 'e335839706dfc90e99bec38d104382f06ae82bc32b6a098b00b67e535ccf0e95'}, 'packages/cryptsetup-2.8.8-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '215c83fc37dfd22fd86af5875da34e4a0ab9cdc9f0f77c0bb4255e06d8064397'}, 'packages/curl-8.22.0-1-aarch64.pkg.tar.xz': {'bytes': 1281188, 'mode': 420, 'sha256': '5461bb97fca88b237d17db833622789eedca390634a6d2fb2e3b71287e52acb2'}, 'packages/curl-8.22.0-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '2523ff1b88dfc1ed910ad90d44c04387a86c397bf8043b518cad1c33dd9524e8'}, 'packages/debugedit-5.3-2-aarch64.pkg.tar.xz': {'bytes': 50624, 'mode': 420, 'sha256': 'c7c2d3c8231c388c882fc27cf93c6c1d34a698b01a282f648cae65216fdeba59'}, 'packages/debugedit-5.3-2-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '0f0c73fa12ba0c58ea3108f7a2ce66c082199851eb135a9ca5fc159870da46aa'}, 'packages/desktop-file-utils-0.28-1-aarch64.pkg.tar.xz': {'bytes': 44376, 'mode': 420, 'sha256': '89d97b1e9e0c265da1bf9120f39fb78122f4eb221dd1e5956b8d64326cf72eca'}, 'packages/desktop-file-utils-0.28-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'ad0f0d679412d445172d1fb2b023ba6e8aa8670f284378a88307790c5d5732e9'}, 'packages/device-mapper-2.03.43-2-aarch64.pkg.tar.xz': {'bytes': 283800, 'mode': 420, 'sha256': '8f61e0fbd02a36f73380e1429fe1f33ef5090645ab2c85d16dfa17f0c084226f'}, 'packages/device-mapper-2.03.43-2-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '90c6efc81d37cfe3070e37d7868bddd6ddcc8d41012d98ed5ddcb38c74751088'}, 'packages/dhcpcd-10.5.2-1-aarch64.pkg.tar.xz': {'bytes': 194608, 'mode': 420, 'sha256': '8ebc266d7b3798d92fc4f0924384aa793baaa567178761d4229b4c42cdad34b2'}, 'packages/dhcpcd-10.5.2-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'b8e3b2347fbef1bade019679da7f7f38f0f4e8d5e18f780eb41b5ed5d0ee8ff7'}, 'packages/elfutils-0.196-1-aarch64.pkg.tar.xz': {'bytes': 671272, 'mode': 420, 'sha256': '83951aac632b10ae3f814c9b0bc51e4b10045e40c7e89664fce2f9176299204c'}, 'packages/elfutils-0.196-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '9f0c26ec5759118517f889bc6f8d73f08d3c3e160afec9929442bd0225e30c70'}, 'packages/expat-2.9.0-1-aarch64.pkg.tar.xz': {'bytes': 119344, 'mode': 420, 'sha256': 'c2bc1dd56d595b24f561e9514f0e82eaee1da5e7b1e0d46126868b9defe4e06a'}, 'packages/expat-2.9.0-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '002126e43e5583ed1773868eb7ad8054299c630c6db079df76c8619382bc2bed'}, 'packages/fakeroot-1:1.37.2-3-aarch64.pkg.tar.xz': {'bytes': 77456, 'mode': 420, 'sha256': 'ae7a1e0df8abd196f5d54f8206db363e3f9ad0b7157fca026729698ccf866ad0'}, 'packages/fakeroot-1:1.37.2-3-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'dab0e61acff72e3db0e7fcf6d5678ecd9d99683b61d5299c501fa025838df71e'}, 'packages/flex-2.6.4-6-aarch64.pkg.tar.xz': {'bytes': 293964, 'mode': 420, 'sha256': 'b640fd86f5334e1e56e102a4ae4ad1080e8971d12caf46fef5279a35fc3a9d76'}, 'packages/flex-2.6.4-6-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'dc49266e45aa699b79e73e282d235e4511c4020337c47919fd4b7c1d06b48792'}, 'packages/freetype2-2.14.3-1-aarch64.pkg.tar.xz': {'bytes': 487400, 'mode': 420, 'sha256': '080b6aa7827298e5b92800229d76689e0dbff08cd96690ae75e8feedf6a9ae5d'}, 'packages/freetype2-2.14.3-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '2b7e1428b25300e635cfa8d6a58695f1c4c3f36feb2ddebd7e27a912aab2d7f2'}, 'packages/fribidi-1.0.17-1-aarch64.pkg.tar.xz': {'bytes': 73788, 'mode': 420, 'sha256': '44f00133167fba3debb1afae29ccb23e9abbada84c32b3580dbc33b2e3b53f09'}, 'packages/fribidi-1.0.17-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '6a0f2b697d770031edafc5a4be9697dcad528d947cef6a0f02df292e11ac24a4'}, 'packages/glib-networking-1:2.90.0-1-aarch64.pkg.tar.xz': {'bytes': 141660, 'mode': 420, 'sha256': '601d60c1be70361d70cd7d6e700b996c0593fd0a66b77fbec4afd991a9946dec'}, 'packages/glib-networking-1:2.90.0-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'b57b244a776005b58db7867b52e53a7e1c2793722a1b391c3973d4033e75f618'}, 'packages/glycin-2.2.2-1-aarch64.pkg.tar.xz': {'bytes': 3718772, 'mode': 420, 'sha256': '6d8739db5a24a0319b170912ff04b5e000ff5b7e9cf3561c4fcee977c6362dc2'}, 'packages/glycin-2.2.2-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '66f23d924d7d88f195dd0accab839efada2cd9d5512da5da5582f61fa4fc71e2'}, 'packages/gnupg-2.4.9-3-aarch64.pkg.tar.xz': {'bytes': 2763600, 'mode': 420, 'sha256': '3f26513fb04d1670ca202551988f5766ef5713533b27846831e834243f52cbfa'}, 'packages/gnupg-2.4.9-3-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '0cf4a712716a4e6ad2c5c63be6222d8a7e4a22ef5217495a2892b32504a023fc'}, 'packages/gperftools-2.18.1-1-aarch64.pkg.tar.xz': {'bytes': 469944, 'mode': 420, 'sha256': '3cc5b9b683c6c783694759b2de1c618d7c20c3a36e9d8cb29eeeb0ca20fe8bbc'}, 'packages/gperftools-2.18.1-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'b1a8632353e0e38e13b052a129d2861fa0bb68fdc7e51a90f649a5f41e16791c'}, 'packages/harfbuzz-14.6.0-1-aarch64.pkg.tar.xz': {'bytes': 1346752, 'mode': 420, 'sha256': 'b3103d1da7a997ac0592ae4d689dc627cb07c8fa050f29dddec567661482c507'}, 'packages/harfbuzz-14.6.0-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '1b7578067c5e43621a28908ac6d9904ddff727073446b4e03c4975927d2cdeba'}, 'packages/hyprcursor-0.1.13-7-aarch64.pkg.tar.xz': {'bytes': 204804, 'mode': 420, 'sha256': 'c30d748c7942abb8f20c212c7e17f86199007f6ef4e20f07d95c3e47db6f63de'}, 'packages/hyprcursor-0.1.13-7-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '5d040fbf9087b3627f773b2f52185e30d9627f3382a4862fa56386c1a9f421d2'}, 'packages/hyprgraphics-0.5.1-4-aarch64.pkg.tar.xz': {'bytes': 79400, 'mode': 420, 'sha256': 'f084a115374a913909f1a95db9f7e028a2b6a6b4ac3ac6da3e836ef5a0947a3c'}, 'packages/hyprgraphics-0.5.1-4-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'bcb17461d68e4c8708da2869dd165b5ca6900cf01783ffdb8a8e82d5e90316ec'}, 'packages/hyprland-0.56.2-4-aarch64.pkg.tar.xz': {'bytes': 49886060, 'mode': 420, 'sha256': '4183f5212200625c278eefbbf70c912f1e8803df7ed99a8a2988beb4f4c74e04'}, 'packages/hyprland-0.56.2-4-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '29f404a67bed43b44a4209c4eac07e72b51034cad4a925d124ba19704c830f34'}, 'packages/hyprland-guiutils-0.2.2-4-aarch64.pkg.tar.xz': {'bytes': 134444, 'mode': 420, 'sha256': 'cd0aae46488b7948d7d4fb10adca67b00987f93279a0fad3131de01e3c550362'}, 'packages/hyprland-guiutils-0.2.2-4-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '6e021d6aacdef9cbd1aa1789ad4b47f9d0f34cbf75e10794ecbbeffa92de777e'}, 'packages/hyprtoolkit-0.6.0-1-aarch64.pkg.tar.xz': {'bytes': 480708, 'mode': 420, 'sha256': '5f947de83b1f8d1ca5a19c6a5eace0b0e943f19d4c488282fc1f270cde8f1964'}, 'packages/hyprtoolkit-0.6.0-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '485192d4d13b0279a2f7833ecef76c95301078c1eb58cf0e9e5d40ca82de2f70'}, 'packages/hyprutils-0.14.2-1-aarch64.pkg.tar.xz': {'bytes': 197828, 'mode': 420, 'sha256': 'a48f017818b0b6900d6bc0d2de890477e9d8abef3d416089f36635d168b12280'}, 'packages/hyprutils-0.14.2-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'd2176dd44b150f651e515584650a285b05154141dd820598267b7d644ffc1b06'}, 'packages/iproute2-7.2.0-1-aarch64.pkg.tar.xz': {'bytes': 1149324, 'mode': 420, 'sha256': '37a789f1b62f329e17868f7a2e8e232ed12700e93fbe1504d9f59de5aec80e8a'}, 'packages/iproute2-7.2.0-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '4dde21af54cf09473058c57bbd39b2349bd30a3bedabd48218add503e4979cc8'}, 'packages/lcms2-2.19.1-1-aarch64.pkg.tar.xz': {'bytes': 205460, 'mode': 420, 'sha256': '5f93d01820b4e1a463f3cb11e19916bb3761b4faca20d4e1f0854329ba3f46f8'}, 'packages/lcms2-2.19.1-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '3e35d43d7cd15dc360e2c250b32610f97330b239ba30d2917d6998c1d337dd5c'}, 'packages/libcloudproviders-0.4.1-1-aarch64.pkg.tar.xz': {'bytes': 44368, 'mode': 420, 'sha256': '83dfe6750ccad57d0e453cd6df7dd4263ec3cd3362ae26db126a820ff829fd3f'}, 'packages/libcloudproviders-0.4.1-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '82dc44da6ccc2370f23f6d50425baa58816a099b3ddce67ac67b286548c99369'}, 'packages/libcolord-1.4.8-1-aarch64.pkg.tar.xz': {'bytes': 169748, 'mode': 420, 'sha256': '79b5775b226ec0974454621e527094f0d59e7e5017b2c31c07871354de8fda0f'}, 'packages/libcolord-1.4.8-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'db3ec2b86c8727ed215866e3ca4a5c1f0de2257fb76fa4a7f0758930c4c841d6'}, 'packages/libei-1.6.0-1-aarch64.pkg.tar.xz': {'bytes': 107216, 'mode': 420, 'sha256': 'a09e6322764d03ed4dd9bc968d8fd22f9833ab859ce9316eeb496522ac0edb45'}, 'packages/libei-1.6.0-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'dfd60023ab72534f1f4b423c3fc9c7c5ae7435ed37dcdf7e112c48a7bda2abe4'}, 'packages/libelf-0.196-1-aarch64.pkg.tar.xz': {'bytes': 577236, 'mode': 420, 'sha256': 'a8f417d24a297384b27935381a0a4f892b121956066c09a3c9cd1e3a47c6d214'}, 'packages/libelf-0.196-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'c8f2b924f3156afdb845ef83bfab9176b883b475c17f199e66deac8064acfafe'}, 'packages/libgudev-238-3-aarch64.pkg.tar.xz': {'bytes': 42040, 'mode': 420, 'sha256': '54ad35f53e669683ef336aec62c9173b343b51efd4b6a7d3eb022708c1dc3c7e'}, 'packages/libgudev-238-3-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '0f296e7194ed47ed9c48fa9836417792984beb97a20a9ce3853fcd4b074846f5'}, 'packages/libjpeg-turbo-3.2.0-2-aarch64.pkg.tar.xz': {'bytes': 503296, 'mode': 420, 'sha256': 'fd1cd460ef3a4bbeb1a660f9f4bbacd09d6dd817a10f0300891a6a552fddb5ec'}, 'packages/libjpeg-turbo-3.2.0-2-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '98fc688c700aabea1a1cf125d0bfa221e195324bb2ca5e60a8dc8a0841fcad78'}, 'packages/libldap-2.7.1-1-aarch64.pkg.tar.xz': {'bytes': 263796, 'mode': 420, 'sha256': '09423337d9311f65e2cdd298ff7a2bbfbfdd7f5cbccfc21e42d8b82de669c737'}, 'packages/libldap-2.7.1-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '24a5a0bb5f5ce2a47f13ecdd676c5c6935c2fe3a7a39557acf9ce994b8eca823'}, 'packages/libp11-kit-0.26.5-1-aarch64.pkg.tar.xz': {'bytes': 416988, 'mode': 420, 'sha256': '0d8da62f6e0fb213858619d928b4b25afb9e783b8285dfdfbef54339584b35ef'}, 'packages/libp11-kit-0.26.5-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '615bb78eeac92f3526cebb5626fb6954abb109330acd0cd11569a7e1d109f1fc'}, 'packages/libpipewire-1:1.6.9-1-aarch64.pkg.tar.xz': {'bytes': 1366556, 'mode': 420, 'sha256': '21e81a38ea0217e0b0675b00c1c98bb547098f00d689201a27c34824e442d66e'}, 'packages/libpipewire-1:1.6.9-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'b3e6293de37f24955bf5a1ac0dd140a4356252e28068a31a876753cdf3e43328'}, 'packages/librsvg-2:2.63.2-1-aarch64.pkg.tar.xz': {'bytes': 2020292, 'mode': 420, 'sha256': '4081d59650b742c5eb370561c6619ac1de1179be4be5c5e6d894549f3f4f84c8'}, 'packages/librsvg-2:2.63.2-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'd71c40d60ce7e9609baec246d8b1a098fbf12e51d390aa07ddebed0ea2c4965c'}, 'packages/libsoup3-3.8.0-1-aarch64.pkg.tar.xz': {'bytes': 392992, 'mode': 420, 'sha256': '64de7da632474a9b45e473731c9098e11379c5dc441e7ca1af91546dc0eabe7b'}, 'packages/libsoup3-3.8.0-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'c7cb940a538e22bffe3f3c32479417ae57570d0861355f21414b75b45e00f678'}, 'packages/libstemmer-3.1.1-1-aarch64.pkg.tar.xz': {'bytes': 125172, 'mode': 420, 'sha256': 'c5ab5687f090d94c15b7a4b7288a58e5bf826921ad9cffa8d85bad1ce31284ba'}, 'packages/libstemmer-3.1.1-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '6819029f59f619a44144c6c10868f5039c6469db3c7a907d05d184e024f40445'}, 'packages/libwireplumber-0.5.18-1-aarch64.pkg.tar.xz': {'bytes': 284324, 'mode': 420, 'sha256': '9fc7aedc4079fadbef1fd7079076b781bee45431d9e534b7c45b82c39ad17d9c'}, 'packages/libwireplumber-0.5.18-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '1844ceaeee6846d6e6661025421159c6461b88252134f3e51b1d55205ba4d35e'}, 'packages/libx11-1.8.13-2-aarch64.pkg.tar.xz': {'bytes': 2009768, 'mode': 420, 'sha256': 'b391fdf1927ec6f8de2f3e5998c927df5fe1b13d9338e56ade48154af460a234'}, 'packages/libx11-1.8.13-2-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '7ac4bf3d7fcac7160797bdcf23a2cd7904c96ee938089dd40164aecb7fb5936f'}, 'packages/libxi-1.8.3-1-aarch64.pkg.tar.xz': {'bytes': 151764, 'mode': 420, 'sha256': '379cea947498145d31decca7a1beacec268cb24fb622a59f6dc49c23be793a22'}, 'packages/libxi-1.8.3-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'a9222bebc44be41ba8f0504459d4a009f353b2254db897e8962eb753c5cefd79'}, 'packages/libxrender-0.9.12-1-aarch64.pkg.tar.xz': {'bytes': 27784, 'mode': 420, 'sha256': 'f5f344d116ff42b379c50ef595e7e9a3a6f7ed09357f8cd3acab90a3d11c9960'}, 'packages/libxrender-0.9.12-1-aarch64.pkg.tar.xz.sig': {'bytes': 565, 'mode': 420, 'sha256': '5964f40f20cc60188d1e14e89363d68c57500b03cb0d08c991aa6feb68dd321d'}, 'packages/libxtst-1.2.5-1-aarch64.pkg.tar.xz': {'bytes': 28736, 'mode': 420, 'sha256': '3ca6270ff04330650205339e2726c23616b31468a493642ba3df74af050ae888'}, 'packages/libxtst-1.2.5-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '2f26dbe9d2a4aa42639e97e4f11b0270c2ba2247c6513890a2d517bd6d0465c2'}, 'packages/libzip-1.11.4-1-aarch64.pkg.tar.xz': {'bytes': 258420, 'mode': 420, 'sha256': '6f108f41399e25a1c20c4deb0b4c89d41d568f810c78104d20628fb7eb241f83'}, 'packages/libzip-1.11.4-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '97736ba70622baaedbb47b53cadd40e33b9110c188da69ac901f0e568b5e84ff'}, 'packages/linux-aarch64-7.2.10-1-aarch64.pkg.tar.xz': {'bytes': 68687880, 'mode': 420, 'sha256': '9172d7677d3c1c4b4b72b50b7931b5ccc19a4552d68e4a029ca7e9663e1ebcb7'}, 'packages/linux-aarch64-7.2.10-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '9e258a5301a67e61bb46f6714287dd077d216ab583529fb80b4e90daaddedd6f'}, 'packages/linux-api-headers-7.2-1-aarch64.pkg.tar.xz': {'bytes': 1509724, 'mode': 420, 'sha256': 'e03baabe6bbf49b65b394eb24629978bbb2094cd17b3fecd892a011041f9c24a'}, 'packages/linux-api-headers-7.2-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '9c6974b7625ed33396a3f896af1689449614573c86496b914af67fa476984fad'}, 'packages/linux-firmware-20260916-1-any.pkg.tar.xz': {'bytes': 2588, 'mode': 420, 'sha256': '117147a72bb15e20c94d1e3c9af0ed3fb77b7caf2448f99e95390b8aa6808c83'}, 'packages/linux-firmware-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '29d87540f6f88e7602c6ffb4f83923b49b0db051963dfe7cfd01ebda5dc72957'}, 'packages/linux-firmware-amd-20260916-1-any.pkg.tar.xz': {'bytes': 490596, 'mode': 420, 'sha256': 'a00e7a18744c40580fdbb781fcf2f51b84c57af1ca27cf05b5a28f8e068586a3'}, 'packages/linux-firmware-amd-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'edb15673fb5c306e57de409507d03873f8bcc39e5cfffb2aa3577f125080cab6'}, 'packages/linux-firmware-amdgpu-20260916-1-any.pkg.tar.xz': {'bytes': 15995644, 'mode': 420, 'sha256': 'a16035a7fedcb0dedd2b41d45a38ef9002f0857c802f6f1d7b8f253121ccf88d'}, 'packages/linux-firmware-amdgpu-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '63b9c206d65899f4917587bed074e283ae81d96e56f12e868a50c92c7b0ebece'}, 'packages/linux-firmware-atheros-20260916-1-any.pkg.tar.xz': {'bytes': 43599864, 'mode': 420, 'sha256': '3585438c34b7014dd156d814104c8d2f60ea11d642a4a31354239e8602418708'}, 'packages/linux-firmware-atheros-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'ba58830b5e352d715e57373e3da3723ba10a3e084070d9fcc9d53ac0b36aa0fe'}, 'packages/linux-firmware-broadcom-20260916-1-any.pkg.tar.xz': {'bytes': 7790268, 'mode': 420, 'sha256': '92986151fa0765edf364d9536aa6b76210445c60c808e852aa586085891fe0d9'}, 'packages/linux-firmware-broadcom-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'ba2b090ee025adbf258fdc45e66ffa204359c6aa02f3bc92fdf30151e7ef8ce0'}, 'packages/linux-firmware-cirrus-20260916-1-any.pkg.tar.xz': {'bytes': 465188, 'mode': 420, 'sha256': '7ff462e21e34239c4d1add91ddd38f8537f79b79acc23aa976b6d1ddc040553e'}, 'packages/linux-firmware-cirrus-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '93fb9e99d024fedb870ff129310a0090022f9f2f5c3c66f6c96c965d0bceb6c1'}, 'packages/linux-firmware-intel-20260916-1-any.pkg.tar.xz': {'bytes': 56053544, 'mode': 420, 'sha256': '5bb579c535c44d9dc3bd4a0d3bb9fa675776e03488a78e3ae09c60c8de7181b7'}, 'packages/linux-firmware-intel-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'e442d87a34d24c9a4160cd3e0f13cc48c381baf1842022653a776c642505a2b8'}, 'packages/linux-firmware-mediatek-20260916-1-any.pkg.tar.xz': {'bytes': 34714404, 'mode': 420, 'sha256': '0b9a3876db35b50f0cdc898a4e5570ef1d6e153a7ec6ae6216ee03eaa9305b73'}, 'packages/linux-firmware-mediatek-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'a2613a694171607d8b754360bfff199b0ffbcd7a8c85c2eb9c8322344dbb9705'}, 'packages/linux-firmware-nvidia-20260916-1-any.pkg.tar.xz': {'bytes': 104330276, 'mode': 420, 'sha256': '9a88f0af44ff0d0c9894935ef3ddd018337392584fb927da4e620121106562f2'}, 'packages/linux-firmware-nvidia-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '20567f0621f1ff7e708bbd3a749dac00d951683f7784ffec599d0cf5703b1959'}, 'packages/linux-firmware-other-20260916-1-any.pkg.tar.xz': {'bytes': 12566012, 'mode': 420, 'sha256': '047e55539d830123a0e86d4d5be3f7f1cdb18b41822dbe06ec6562020c50beb3'}, 'packages/linux-firmware-other-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'b17669753694815c7e77af24f797740a68a83a8d34890f69ce59d81d1dd8c1c2'}, 'packages/linux-firmware-radeon-20260916-1-any.pkg.tar.xz': {'bytes': 841780, 'mode': 420, 'sha256': '3f7788bcba04df8917e5549d1c00c82e32d96a7e0b8032df9198df1b2331ca8e'}, 'packages/linux-firmware-radeon-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'f202a78bdaa083b02fecc1e4fc24d7d49c2ec46f69676b7453d73f12fd70ca5a'}, 'packages/linux-firmware-realtek-20260916-1-any.pkg.tar.xz': {'bytes': 3940848, 'mode': 420, 'sha256': '5f7f940945e7b6e8a968435d7eba4e61a75f606fd680f95efc4fd0c433f1c15f'}, 'packages/linux-firmware-realtek-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '2f9dcb95b9a0038372ef433d44d9e30a2f948bba880e9215ad050536afe106e5'}, 'packages/linux-firmware-ti-20260916-1-any.pkg.tar.xz': {'bytes': 2201060, 'mode': 420, 'sha256': '71ae3063e56ec52fd45b2c117443b250bd754a989412a7b42ffe319712b5900d'}, 'packages/linux-firmware-ti-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '7d0b0090232d583da7f6b5fe3e6d9226cdcc5adfe883bd861601db66806eb3f6'}, 'packages/linux-firmware-whence-20260916-1-any.pkg.tar.xz': {'bytes': 43144, 'mode': 420, 'sha256': '52671ff7275c0a62029150ef700778da7e448f36b381e73da964751e8862bdbc'}, 'packages/linux-firmware-whence-20260916-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'e1f33d9f53b4c27910d7ca43cb5c4d9722e6b09f92f8acbf8e4140efb65bd2e5'}, 'packages/llvm-libs-23.1.1-1-aarch64.pkg.tar.xz': {'bytes': 37588856, 'mode': 420, 'sha256': 'd890dc562274f6e2ec59d5b2ceb21ddeabee89c0563ead27a550ee11810cdff4'}, 'packages/llvm-libs-23.1.1-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'b06b35cb4e524be09461b4ae825c2a00d92733c59d4a4364c2a59d3060c4ece8'}, 'packages/mesa-1:26.2.4-1-aarch64.pkg.tar.xz': {'bytes': 12639708, 'mode': 420, 'sha256': 'b03b498ba04ef5217299a81a1ef4c1c3582a250fab74848a443b85ba4a352fbd'}, 'packages/mesa-1:26.2.4-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '70b68b0ad743f13cb4e1a3d53e8c7a041a13ab3f387ef830d0735c0883e0cb03'}, 'packages/nano-9.2-1-aarch64.pkg.tar.xz': {'bytes': 620456, 'mode': 420, 'sha256': 'b7de7c6cf2e4859c141f978bd7f1e9467118266c1ea83fcae07c2921dae3f3d3'}, 'packages/nano-9.2-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '2fda31bc521a43e3e65941fcc80f1baa423d770797b86a4cfd7c2934fa0832cd'}, 'packages/openssh-10.6p1-1-aarch64.pkg.tar.xz': {'bytes': 1228712, 'mode': 420, 'sha256': '28522c0cb098994889b8186315f7629bf1d75931487f16a237dd3e93bbdbaa10'}, 'packages/openssh-10.6p1-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '2b6ebf8553f7b10ba22f768adc7dbcbd00ce983364a0000f85ed13d11cb44ac1'}, 'packages/openssl-3.6.5-1-aarch64.pkg.tar.xz': {'bytes': 5895660, 'mode': 420, 'sha256': 'f60b3c69329784d1218ba098a46b092bb42ecc68f0424f01ce2873353a667c20'}, 'packages/openssl-3.6.5-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'de6c9c6fc49a0f8d1ef87baab5ccc3acd481652b4b8244119f54a818e80c6354'}, 'packages/p11-kit-0.26.5-1-aarch64.pkg.tar.xz': {'bytes': 249124, 'mode': 420, 'sha256': '7e5c2facac3abd9b51709e081e8720dc7ccc0f27d6c9b49bcb3d188fa91e75f1'}, 'packages/p11-kit-0.26.5-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '1cb5b9640a044a32be18c730033bd50f9922374e7c27101471549765676c5b8b'}, 'packages/patch-2.8-1-aarch64.pkg.tar.xz': {'bytes': 83988, 'mode': 420, 'sha256': 'a62862b3dc3c82c3f8892707ec118a56fb0230480c017445d795fc0989e32f67'}, 'packages/patch-2.8-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'bd57f9d4db65366308ce84e59f761d2b5857f9e74507dc2f273236ef118f4c59'}, 'packages/perl-5.42.3-1-aarch64.pkg.tar.xz': {'bytes': 16017184, 'mode': 420, 'sha256': 'f0e47c42ec91985898af2ce7355ef4eead50457108706add1f8c1650bca19b8f'}, 'packages/perl-5.42.3-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'f40e70ac18f61c8b706c7642bac2cfef7b4fcb9d96bd30da3fc41c48a6667dca'}, 'packages/pipewire-1:1.6.9-1-aarch64.pkg.tar.xz': {'bytes': 264148, 'mode': 420, 'sha256': 'd711f2ba44cf9be3800b168f1d68d7791e2838c2bbefde26deff56a26eaccae2'}, 'packages/pipewire-1:1.6.9-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '128286cc9966ac4fb0152d53af7e5b304b693c097d4becb3cef76ccd58c640b1'}, 'packages/pkgconf-3.0.7-1-aarch64.pkg.tar.xz': {'bytes': 114348, 'mode': 420, 'sha256': '92275199f2f7b8907032e96a40187fef60a30dc7aaaeba1e4c5a03177365858a'}, 'packages/pkgconf-3.0.7-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'bc72c375df7b8b20f6f43562b447d0dcb0e91343428c3341ac8b59db2a733981'}, 'packages/python-3.14.8-1-aarch64.pkg.tar.xz': {'bytes': 13588352, 'mode': 420, 'sha256': '5e00dbb30ab55fd160d64205e1f3418c8bcf5b295ff07bf9af7ad4ab85bc6984'}, 'packages/python-3.14.8-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'ee28ca566685118f6048b859691802ddc6a1c0772581371a7d9cab2d3405c2f0'}, 'packages/sudo-1.9.17.p2-6-aarch64.pkg.tar.xz': {'bytes': 1774712, 'mode': 420, 'sha256': '3e90ee7aa3b5526a155396f3baa6305e37eed317db674cc077312cc386d5b0bd'}, 'packages/sudo-1.9.17.p2-6-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '24f1c52f52ccd28105a25fd5a6d10d8fe9dba3e57200e655240ac10d783f7b05'}, 'packages/systemd-262-1-aarch64.pkg.tar.xz': {'bytes': 9737940, 'mode': 420, 'sha256': 'dd26469e35547b68793f5ef3e9ba343179704652425349a36d231f34ec6e0546'}, 'packages/systemd-262-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'de5b2b5b2c485613e7c854d049578c6c0a9bf9c680132c9e3c4076fffb5dc89b'}, 'packages/systemd-libs-262-1-aarch64.pkg.tar.xz': {'bytes': 1303288, 'mode': 420, 'sha256': '8e697c8f2db7c82dfcdcdc63540f7ad265d8e10fc7aab656c60229d858fca901'}, 'packages/systemd-libs-262-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '1188b1b93ba1f79069a36c8d33555713b41746c981d246f5e3ffc726c4633de7'}, 'packages/systemd-resolvconf-262-1-aarch64.pkg.tar.xz': {'bytes': 3420, 'mode': 420, 'sha256': '2c65f94c06ecca704afe9a95b7eed2de11a82447fecc3fac26e6d46da424fba3'}, 'packages/systemd-resolvconf-262-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'ed7bbb6e5123ea5874853fa56745cfc9256be96d82a5026f5c8115e366825c27'}, 'packages/systemd-sysvcompat-262-1-aarch64.pkg.tar.xz': {'bytes': 6692, 'mode': 420, 'sha256': '17ad08c06f3d759bb9d6eabc8881481b5b5dae02ef1ab591b6571bf4d675cc79'}, 'packages/systemd-sysvcompat-262-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'a4196339ef70bec487b46ce875122bc7d1acecf9560b49f06110215f9d19f359'}, 'packages/texinfo-7.3-1-aarch64.pkg.tar.xz': {'bytes': 2070900, 'mode': 420, 'sha256': '796e5577b93b495b953473af8eb5f27dd7fe7ddb07ccf8a49720449e5a194067'}, 'packages/texinfo-7.3-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '3a536c65fb5f3ad39c5e9c1013f89d29bf2891df07d76d9f4956b98a6ff6da76'}, 'packages/tomlplusplus-3.4.0-1-aarch64.pkg.tar.xz': {'bytes': 164828, 'mode': 420, 'sha256': '79fb3aaffdb83b811096032183d34960ec7ae136a28217bf626c9a45ad750422'}, 'packages/tomlplusplus-3.4.0-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '67854ceaa2dfc82ae4c1b9585c5983b231d495f8017e568492bc2ab3fe84202f'}, 'packages/tpm2-tss-4.2.0-2-aarch64.pkg.tar.xz': {'bytes': 877720, 'mode': 420, 'sha256': '90f527d90d490e1436c696a81df7b0c6da5fa18dfdb87fb92813f35ac86c7c1b'}, 'packages/tpm2-tss-4.2.0-2-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'cc50e53810afe468d2e351b5d8bbe20485fe9c8853fd4a8e41c765cecc5d5705'}, 'packages/tzdata-2026e-1-aarch64.pkg.tar.xz': {'bytes': 293780, 'mode': 420, 'sha256': 'd7d3c754efda7194c0b931c457436f5215e1ca51835cbfac228e70c46112f22f'}, 'packages/tzdata-2026e-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': '6625904c3bccff17143fa2c978582fd2cc1175629517c8cd0f635ab30e5ff2b5'}, 'packages/wayland-protocols-1.49-1-any.pkg.tar.xz': {'bytes': 139436, 'mode': 420, 'sha256': '9678c0d371ecfb5041b1b1d8a7986977bd82b7233984dbe25b33a54da0dbee27'}, 'packages/wayland-protocols-1.49-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'd731754509b526be5f65900e4d645641bec9ac3b7ad6f7c59d821b8690bb920e'}, 'packages/wireplumber-0.5.18-1-aarch64.pkg.tar.xz': {'bytes': 289536, 'mode': 420, 'sha256': '2410813c8b3eba26598b90b260171ac884af59f8dc1441112eee80f1873b628b'}, 'packages/wireplumber-0.5.18-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'f061b3156e88502e0fcca2b1742c9d4e6687a23a2b92d804a664abecbd52cd04'}, 'packages/xkeyboard-config-2.48-1-any.pkg.tar.xz': {'bytes': 843224, 'mode': 420, 'sha256': '6ee5de46d25850dee96be9c28f9870ea2ae0b19ac8fb3c2194d31b9649b03ecd'}, 'packages/xkeyboard-config-2.48-1-any.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'aaeeab21217c1f307f1c75165443c2274f215df788c456b21276bc670e41e95c'}, 'packages/xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz': {'bytes': 27344, 'mode': 420, 'sha256': '6cc9149138662041aa13c6ec027c074c67ee411848e38c349232acd9d97fca98'}, 'packages/xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'cb12e8a377cd9a8f4718faa270f7b5ca0834e7b72b70c073338f57bfea31b4d3'}, 'packages/xorg-xwayland-24.1.14-1-aarch64.pkg.tar.xz': {'bytes': 851344, 'mode': 420, 'sha256': '6affc1b822583d80040e1be9598dfdb7bedc235d2c29283af7a878100fc069c1'}, 'packages/xorg-xwayland-24.1.14-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'mode': 420, 'sha256': 'e1fe05949dd62873ac7a197a146d9fab4b7693727d8d8a07a2c2a353a16d4559'}}, 'input_lock_sha256': 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f', 'package_provenance': {'aquamarine': {'arch': 'aarch64', 'filename': 'aquamarine-0.15.1-1-aarch64.pkg.tar.xz', 'license': ['BSD-3-Clause'], 'source_url': ['https://github.com/hyprwm/aquamarine'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/aquamarine-0.15.1-1-aarch64.pkg.tar.xz', 'version': '0.15.1-1'}, 'automake': {'arch': 'any', 'filename': 'automake-1.19-1-any.pkg.tar.xz', 'license': ['GPL'], 'source_url': ['https://www.gnu.org/software/automake'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/automake-1.19-1-any.pkg.tar.xz', 'version': '1.19-1'}, 'avahi': {'arch': 'aarch64', 'filename': 'avahi-1:0.9rc5-1-aarch64.pkg.tar.xz', 'license': ['LGPL-2.1-or-later'], 'source_url': ['https://github.com/avahi/avahi'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/avahi-1:0.9rc5-1-aarch64.pkg.tar.xz', 'version': '1:0.9rc5-1'}, 'benchmark': {'arch': 'aarch64', 'filename': 'benchmark-1.9.5-2-aarch64.pkg.tar.xz', 'license': ['Apache-2.0'], 'source_url': ['https://github.com/google/benchmark'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/benchmark-1.9.5-2-aarch64.pkg.tar.xz', 'version': '1.9.5-2'}, 'boost-libs': {'arch': 'aarch64', 'filename': 'boost-libs-1.92.0-1-aarch64.pkg.tar.xz', 'license': ['BSL-1.0'], 'source_url': ['https://www.boost.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/boost-libs-1.92.0-1-aarch64.pkg.tar.xz', 'version': '1.92.0-1'}, 'ca-certificates-mozilla': {'arch': 'aarch64', 'filename': 'ca-certificates-mozilla-3.131-1-aarch64.pkg.tar.xz', 'license': ['MPL-2.0'], 'source_url': ['https://firefox-source-docs.mozilla.org/security/nss/index.html'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/ca-certificates-mozilla-3.131-1-aarch64.pkg.tar.xz', 'version': '3.131-1'}, 'coreutils': {'arch': 'aarch64', 'filename': 'coreutils-9.12-2-aarch64.pkg.tar.xz', 'license': ['GPL-3.0-or-later', 'GFDL-1.3-or-later'], 'source_url': ['https://www.gnu.org/software/coreutils/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/coreutils-9.12-2-aarch64.pkg.tar.xz', 'version': '9.12-2'}, 'cryptsetup': {'arch': 'aarch64', 'filename': 'cryptsetup-2.8.8-1-aarch64.pkg.tar.xz', 'license': ['GPL-2.0-or-later'], 'source_url': ['https://gitlab.com/cryptsetup/cryptsetup/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/cryptsetup-2.8.8-1-aarch64.pkg.tar.xz', 'version': '2.8.8-1'}, 'curl': {'arch': 'aarch64', 'filename': 'curl-8.22.0-1-aarch64.pkg.tar.xz', 'license': ['curl'], 'source_url': ['https://curl.se/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/curl-8.22.0-1-aarch64.pkg.tar.xz', 'version': '8.22.0-1'}, 'debugedit': {'arch': 'aarch64', 'filename': 'debugedit-5.3-2-aarch64.pkg.tar.xz', 'license': ['GPL-3.0-or-later', 'GPL-2.0-or-later', 'LGPL-2.0-or-later'], 'source_url': ['https://sourceware.org/debugedit/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/debugedit-5.3-2-aarch64.pkg.tar.xz', 'version': '5.3-2'}, 'desktop-file-utils': {'arch': 'aarch64', 'filename': 'desktop-file-utils-0.28-1-aarch64.pkg.tar.xz', 'license': ['GPL-2.0-or-later'], 'source_url': ['https://www.freedesktop.org/wiki/Software/desktop-file-utils'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/desktop-file-utils-0.28-1-aarch64.pkg.tar.xz', 'version': '0.28-1'}, 'device-mapper': {'arch': 'aarch64', 'filename': 'device-mapper-2.03.43-2-aarch64.pkg.tar.xz', 'license': ['GPL-2.0-only', 'LGPL-2.1-only'], 'source_url': ['http://sourceware.org/dm/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/device-mapper-2.03.43-2-aarch64.pkg.tar.xz', 'version': '2.03.43-2'}, 'dhcpcd': {'arch': 'aarch64', 'filename': 'dhcpcd-10.5.2-1-aarch64.pkg.tar.xz', 'license': ['BSD-2-Clause'], 'source_url': ['https://roy.marples.name/projects/dhcpcd/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/dhcpcd-10.5.2-1-aarch64.pkg.tar.xz', 'version': '10.5.2-1'}, 'elfutils': {'arch': 'aarch64', 'filename': 'elfutils-0.196-1-aarch64.pkg.tar.xz', 'license': ['GPL-3.0-or-later'], 'source_url': ['https://sourceware.org/elfutils/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/elfutils-0.196-1-aarch64.pkg.tar.xz', 'version': '0.196-1'}, 'expat': {'arch': 'aarch64', 'filename': 'expat-2.9.0-1-aarch64.pkg.tar.xz', 'license': ['MIT'], 'source_url': ['https://libexpat.github.io/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/expat-2.9.0-1-aarch64.pkg.tar.xz', 'version': '2.9.0-1'}, 'fakeroot': {'arch': 'aarch64', 'filename': 'fakeroot-1:1.37.2-3-aarch64.pkg.tar.xz', 'license': ['GPL-3.0-or-later'], 'source_url': ['https://tracker.debian.org/pkg/fakeroot'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/fakeroot-1:1.37.2-3-aarch64.pkg.tar.xz', 'version': '1:1.37.2-3'}, 'flex': {'arch': 'aarch64', 'filename': 'flex-2.6.4-6-aarch64.pkg.tar.xz', 'license': ['custom:flex'], 'source_url': ['https://github.com/westes/flex'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/flex-2.6.4-6-aarch64.pkg.tar.xz', 'version': '2.6.4-6'}, 'freetype2': {'arch': 'aarch64', 'filename': 'freetype2-2.14.3-1-aarch64.pkg.tar.xz', 'license': ['FTL OR GPL-2.0-or-later'], 'source_url': ['https://www.freetype.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/freetype2-2.14.3-1-aarch64.pkg.tar.xz', 'version': '2.14.3-1'}, 'fribidi': {'arch': 'aarch64', 'filename': 'fribidi-1.0.17-1-aarch64.pkg.tar.xz', 'license': ['LGPL-2.1-or-later'], 'source_url': ['https://github.com/fribidi/fribidi'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/fribidi-1.0.17-1-aarch64.pkg.tar.xz', 'version': '1.0.17-1'}, 'glib-networking': {'arch': 'aarch64', 'filename': 'glib-networking-1:2.90.0-1-aarch64.pkg.tar.xz', 'license': ['LGPL-2.1-or-later'], 'source_url': ['https://gitlab.gnome.org/GNOME/glib-networking'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/glib-networking-1:2.90.0-1-aarch64.pkg.tar.xz', 'version': '1:2.90.0-1'}, 'glycin': {'arch': 'aarch64', 'filename': 'glycin-2.2.2-1-aarch64.pkg.tar.xz', 'license': ['MPL-2.0 OR LGPL-2.1-or-later'], 'source_url': ['https://gnome.pages.gitlab.gnome.org/glycin/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/glycin-2.2.2-1-aarch64.pkg.tar.xz', 'version': '2.2.2-1'}, 'gnupg': {'arch': 'aarch64', 'filename': 'gnupg-2.4.9-3-aarch64.pkg.tar.xz', 'license': ['BSD-2-Clause', 'BSD-3-Clause', 'BSD-4-Clause', 'CC0-1.0', 'GPL-2.0-or-later', 'GPL-3.0-or-later', 'LGPL-2.1-or-later', 'LGPL-3.0-or-later OR GPL-2.0-or-later', 'MIT', 'Unicode-TOU'], 'source_url': ['https://www.gnupg.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/gnupg-2.4.9-3-aarch64.pkg.tar.xz', 'version': '2.4.9-3'}, 'gperftools': {'arch': 'aarch64', 'filename': 'gperftools-2.18.1-1-aarch64.pkg.tar.xz', 'license': ['BSD-3-Clause'], 'source_url': ['https://github.com/gperftools/gperftools'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/gperftools-2.18.1-1-aarch64.pkg.tar.xz', 'version': '2.18.1-1'}, 'harfbuzz': {'arch': 'aarch64', 'filename': 'harfbuzz-14.6.0-1-aarch64.pkg.tar.xz', 'license': ['MIT'], 'source_url': ['https://harfbuzz.github.io/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/harfbuzz-14.6.0-1-aarch64.pkg.tar.xz', 'version': '14.6.0-1'}, 'hyprcursor': {'arch': 'aarch64', 'filename': 'hyprcursor-0.1.13-7-aarch64.pkg.tar.xz', 'license': ['BSD-3-Clause'], 'source_url': ['https://github.com/hyprwm/hyprcursor'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/hyprcursor-0.1.13-7-aarch64.pkg.tar.xz', 'version': '0.1.13-7'}, 'hyprgraphics': {'arch': 'aarch64', 'filename': 'hyprgraphics-0.5.1-4-aarch64.pkg.tar.xz', 'license': ['BSD-3-Clause'], 'source_url': ['https://github.com/hyprwm/hyprgraphics'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/hyprgraphics-0.5.1-4-aarch64.pkg.tar.xz', 'version': '0.5.1-4'}, 'hyprland': {'arch': 'aarch64', 'filename': 'hyprland-0.56.2-4-aarch64.pkg.tar.xz', 'license': ['BSD-3-Clause'], 'source_url': ['https://github.com/hyprwm/Hyprland'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/hyprland-0.56.2-4-aarch64.pkg.tar.xz', 'version': '0.56.2-4'}, 'hyprland-guiutils': {'arch': 'aarch64', 'filename': 'hyprland-guiutils-0.2.2-4-aarch64.pkg.tar.xz', 'license': ['BSD-3-Clause'], 'source_url': ['https://github.com/hyprwm/hyprland-guiutils'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/hyprland-guiutils-0.2.2-4-aarch64.pkg.tar.xz', 'version': '0.2.2-4'}, 'hyprtoolkit': {'arch': 'aarch64', 'filename': 'hyprtoolkit-0.6.0-1-aarch64.pkg.tar.xz', 'license': ['BSD-3-Clause'], 'source_url': ['https://github.com/hyprwm/hyprtoolkit'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/hyprtoolkit-0.6.0-1-aarch64.pkg.tar.xz', 'version': '0.6.0-1'}, 'hyprutils': {'arch': 'aarch64', 'filename': 'hyprutils-0.14.2-1-aarch64.pkg.tar.xz', 'license': ['BSD-3-Clause'], 'source_url': ['https://github.com/hyprwm/hyprutils'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/hyprutils-0.14.2-1-aarch64.pkg.tar.xz', 'version': '0.14.2-1'}, 'iproute2': {'arch': 'aarch64', 'filename': 'iproute2-7.2.0-1-aarch64.pkg.tar.xz', 'license': ['GPL-2.0-or-later'], 'source_url': ['https://git.kernel.org/pub/scm/network/iproute2/iproute2.git'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/iproute2-7.2.0-1-aarch64.pkg.tar.xz', 'version': '7.2.0-1'}, 'lcms2': {'arch': 'aarch64', 'filename': 'lcms2-2.19.1-1-aarch64.pkg.tar.xz', 'license': ['MIT'], 'source_url': ['http://www.littlecms.com/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/lcms2-2.19.1-1-aarch64.pkg.tar.xz', 'version': '2.19.1-1'}, 'libcloudproviders': {'arch': 'aarch64', 'filename': 'libcloudproviders-0.4.1-1-aarch64.pkg.tar.xz', 'license': ['LGPL-3.0-or-later'], 'source_url': ['https://gitlab.gnome.org/GNOME/libcloudproviders'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libcloudproviders-0.4.1-1-aarch64.pkg.tar.xz', 'version': '0.4.1-1'}, 'libcolord': {'arch': 'aarch64', 'filename': 'libcolord-1.4.8-1-aarch64.pkg.tar.xz', 'license': ['GPL-2.0-or-later'], 'source_url': ['https://www.freedesktop.org/software/colord/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libcolord-1.4.8-1-aarch64.pkg.tar.xz', 'version': '1.4.8-1'}, 'libei': {'arch': 'aarch64', 'filename': 'libei-1.6.0-1-aarch64.pkg.tar.xz', 'license': ['MIT'], 'source_url': ['https://libinput.pages.freedesktop.org/libei/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libei-1.6.0-1-aarch64.pkg.tar.xz', 'version': '1.6.0-1'}, 'libelf': {'arch': 'aarch64', 'filename': 'libelf-0.196-1-aarch64.pkg.tar.xz', 'license': ['GPL-2.0-or-later OR LGPL-3.0-or-later'], 'source_url': ['https://sourceware.org/elfutils/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/libelf-0.196-1-aarch64.pkg.tar.xz', 'version': '0.196-1'}, 'libgudev': {'arch': 'aarch64', 'filename': 'libgudev-238-3-aarch64.pkg.tar.xz', 'license': ['LGPL-2.1-or-later'], 'source_url': ['https://gitlab.gnome.org/GNOME/libgudev'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libgudev-238-3-aarch64.pkg.tar.xz', 'version': '238-3'}, 'libjpeg-turbo': {'arch': 'aarch64', 'filename': 'libjpeg-turbo-3.2.0-2-aarch64.pkg.tar.xz', 'license': ['BSD-3-Clause', 'IJG'], 'source_url': ['https://libjpeg-turbo.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libjpeg-turbo-3.2.0-2-aarch64.pkg.tar.xz', 'version': '3.2.0-2'}, 'libldap': {'arch': 'aarch64', 'filename': 'libldap-2.7.1-1-aarch64.pkg.tar.xz', 'license': ['custom'], 'source_url': ['https://www.openldap.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/libldap-2.7.1-1-aarch64.pkg.tar.xz', 'version': '2.7.1-1'}, 'libp11-kit': {'arch': 'aarch64', 'filename': 'libp11-kit-0.26.5-1-aarch64.pkg.tar.xz', 'license': ['BSD-3-Clause'], 'source_url': ['https://p11-glue.freedesktop.org'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/libp11-kit-0.26.5-1-aarch64.pkg.tar.xz', 'version': '0.26.5-1'}, 'libpipewire': {'arch': 'aarch64', 'filename': 'libpipewire-1:1.6.9-1-aarch64.pkg.tar.xz', 'license': ['MIT'], 'source_url': ['https://pipewire.org'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libpipewire-1:1.6.9-1-aarch64.pkg.tar.xz', 'version': '1:1.6.9-1'}, 'librsvg': {'arch': 'aarch64', 'filename': 'librsvg-2:2.63.2-1-aarch64.pkg.tar.xz', 'license': ['LGPL-2.1-or-later'], 'source_url': ['https://gitlab.gnome.org/GNOME/librsvg'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/librsvg-2:2.63.2-1-aarch64.pkg.tar.xz', 'version': '2:2.63.2-1'}, 'libsoup3': {'arch': 'aarch64', 'filename': 'libsoup3-3.8.0-1-aarch64.pkg.tar.xz', 'license': ['LGPL-2.0-or-later'], 'source_url': ['https://libsoup.gnome.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libsoup3-3.8.0-1-aarch64.pkg.tar.xz', 'version': '3.8.0-1'}, 'libstemmer': {'arch': 'aarch64', 'filename': 'libstemmer-3.1.1-1-aarch64.pkg.tar.xz', 'license': ['BSD-3-Clause'], 'source_url': ['https://snowballstem.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libstemmer-3.1.1-1-aarch64.pkg.tar.xz', 'version': '3.1.1-1'}, 'libwireplumber': {'arch': 'aarch64', 'filename': 'libwireplumber-0.5.18-1-aarch64.pkg.tar.xz', 'license': ['MIT'], 'source_url': ['https://pipewire.pages.freedesktop.org/wireplumber/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libwireplumber-0.5.18-1-aarch64.pkg.tar.xz', 'version': '0.5.18-1'}, 'libx11': {'arch': 'aarch64', 'filename': 'libx11-1.8.13-2-aarch64.pkg.tar.xz', 'license': ['MIT AND X11'], 'source_url': ['https://gitlab.freedesktop.org/xorg/lib/libx11'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libx11-1.8.13-2-aarch64.pkg.tar.xz', 'version': '1.8.13-2'}, 'libxi': {'arch': 'aarch64', 'filename': 'libxi-1.8.3-1-aarch64.pkg.tar.xz', 'license': ['MIT-open-group', 'SMLNJ', 'MIT'], 'source_url': ['https://xorg.freedesktop.org'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libxi-1.8.3-1-aarch64.pkg.tar.xz', 'version': '1.8.3-1'}, 'libxrender': {'arch': 'aarch64', 'filename': 'libxrender-0.9.12-1-aarch64.pkg.tar.xz', 'license': ['HPND-sell-variant'], 'source_url': ['https://xorg.freedesktop.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libxrender-0.9.12-1-aarch64.pkg.tar.xz', 'version': '0.9.12-1'}, 'libxtst': {'arch': 'aarch64', 'filename': 'libxtst-1.2.5-1-aarch64.pkg.tar.xz', 'license': ['MIT-open-group', 'HPND-sell-variant', 'X11', 'HPND-doc', 'HPND-doc-sell'], 'source_url': ['https://gitlab.freedesktop.org/xorg/lib/libxtst'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libxtst-1.2.5-1-aarch64.pkg.tar.xz', 'version': '1.2.5-1'}, 'libzip': {'arch': 'aarch64', 'filename': 'libzip-1.11.4-1-aarch64.pkg.tar.xz', 'license': ['BSD'], 'source_url': ['https://libzip.org'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/libzip-1.11.4-1-aarch64.pkg.tar.xz', 'version': '1.11.4-1'}, 'linux-aarch64': {'arch': 'aarch64', 'filename': 'linux-aarch64-7.2.10-1-aarch64.pkg.tar.xz', 'license': ['GPL-2.0-only'], 'source_url': ['http://www.kernel.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-aarch64-7.2.10-1-aarch64.pkg.tar.xz', 'version': '7.2.10-1'}, 'linux-api-headers': {'arch': 'aarch64', 'filename': 'linux-api-headers-7.2-1-aarch64.pkg.tar.xz', 'license': ['GPL-2.0-only'], 'source_url': ['https://www.gnu.org/software/libc'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-api-headers-7.2-1-aarch64.pkg.tar.xz', 'version': '7.2-1'}, 'linux-firmware': {'arch': 'any', 'filename': 'linux-firmware-20260916-1-any.pkg.tar.xz', 'license': ['CC0-1.0'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'linux-firmware-amd': {'arch': 'any', 'filename': 'linux-firmware-amd-20260916-1-any.pkg.tar.xz', 'license': ['LicenseRef-WHENCE', 'LicenseRef-amd'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-amd-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'linux-firmware-amdgpu': {'arch': 'any', 'filename': 'linux-firmware-amdgpu-20260916-1-any.pkg.tar.xz', 'license': ['LicenseRef-WHENCE', 'LicenseRef-amdgpu', 'MIT'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-amdgpu-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'linux-firmware-atheros': {'arch': 'any', 'filename': 'linux-firmware-atheros-20260916-1-any.pkg.tar.xz', 'license': ['LicenseRef-WHENCE', 'GPL-2.0-only', 'LicenseRef-atheros'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-atheros-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'linux-firmware-broadcom': {'arch': 'any', 'filename': 'linux-firmware-broadcom-20260916-1-any.pkg.tar.xz', 'license': ['LicenseRef-WHENCE', 'LicenseRef-broadcom'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-broadcom-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'linux-firmware-cirrus': {'arch': 'any', 'filename': 'linux-firmware-cirrus-20260916-1-any.pkg.tar.xz', 'license': ['LicenseRef-WHENCE', 'LicenseRef-cirrus'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-cirrus-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'linux-firmware-intel': {'arch': 'any', 'filename': 'linux-firmware-intel-20260916-1-any.pkg.tar.xz', 'license': ['LicenseRef-WHENCE', 'Apache-2.0', 'GPL-2.0-only', 'LicenseRef-intel'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-intel-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'linux-firmware-mediatek': {'arch': 'any', 'filename': 'linux-firmware-mediatek-20260916-1-any.pkg.tar.xz', 'license': ['LicenseRef-WHENCE', 'LicenseRef-mediatek'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-mediatek-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'linux-firmware-nvidia': {'arch': 'any', 'filename': 'linux-firmware-nvidia-20260916-1-any.pkg.tar.xz', 'license': ['LicenseRef-WHENCE', 'LicenseRef-nvidia'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-nvidia-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'linux-firmware-other': {'arch': 'any', 'filename': 'linux-firmware-other-20260916-1-any.pkg.tar.xz', 'license': ['LicenseRef-WHENCE'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-other-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'linux-firmware-radeon': {'arch': 'any', 'filename': 'linux-firmware-radeon-20260916-1-any.pkg.tar.xz', 'license': ['LicenseRef-WHENCE', 'LicenseRef-radeon'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-radeon-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'linux-firmware-realtek': {'arch': 'any', 'filename': 'linux-firmware-realtek-20260916-1-any.pkg.tar.xz', 'license': ['LicenseRef-WHENCE', 'LicenseRef-realtek'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-realtek-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'linux-firmware-ti': {'arch': 'any', 'filename': 'linux-firmware-ti-20260916-1-any.pkg.tar.xz', 'license': ['LicenseRef-WHENCE', 'GPL-2.0-or-later', 'LicenseRef-ti'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-ti-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'linux-firmware-whence': {'arch': 'any', 'filename': 'linux-firmware-whence-20260916-1-any.pkg.tar.xz', 'license': ['LicenseRef-WHENCE'], 'source_url': ['https://gitlab.com/kernel-firmware/linux-firmware'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/linux-firmware-whence-20260916-1-any.pkg.tar.xz', 'version': '20260916-1'}, 'llvm-libs': {'arch': 'aarch64', 'filename': 'llvm-libs-23.1.1-1-aarch64.pkg.tar.xz', 'license': ['Apache-2.0 WITH LLVM-exception'], 'source_url': ['https://llvm.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/llvm-libs-23.1.1-1-aarch64.pkg.tar.xz', 'version': '23.1.1-1'}, 'mesa': {'arch': 'aarch64', 'filename': 'mesa-1:26.2.4-1-aarch64.pkg.tar.xz', 'license': ['MIT AND BSD-3-Clause AND SGI-B-2.0'], 'source_url': ['https://www.mesa3d.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/mesa-1:26.2.4-1-aarch64.pkg.tar.xz', 'version': '1:26.2.4-1'}, 'nano': {'arch': 'aarch64', 'filename': 'nano-9.2-1-aarch64.pkg.tar.xz', 'license': ['GPL-3.0-or-later'], 'source_url': ['https://www.nano-editor.org'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/nano-9.2-1-aarch64.pkg.tar.xz', 'version': '9.2-1'}, 'openssh': {'arch': 'aarch64', 'filename': 'openssh-10.6p1-1-aarch64.pkg.tar.xz', 'license': ['0BSD', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'LicenseRef-Public-Domain', 'MIT'], 'source_url': ['https://www.openssh.com/portable.html'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/openssh-10.6p1-1-aarch64.pkg.tar.xz', 'version': '10.6p1-1'}, 'openssl': {'arch': 'aarch64', 'filename': 'openssl-3.6.5-1-aarch64.pkg.tar.xz', 'license': ['Apache-2.0'], 'source_url': ['https://www.openssl.org'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/openssl-3.6.5-1-aarch64.pkg.tar.xz', 'version': '3.6.5-1'}, 'p11-kit': {'arch': 'aarch64', 'filename': 'p11-kit-0.26.5-1-aarch64.pkg.tar.xz', 'license': ['BSD-3-Clause'], 'source_url': ['https://p11-glue.freedesktop.org'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/p11-kit-0.26.5-1-aarch64.pkg.tar.xz', 'version': '0.26.5-1'}, 'patch': {'arch': 'aarch64', 'filename': 'patch-2.8-1-aarch64.pkg.tar.xz', 'license': ['GPL'], 'source_url': ['https://www.gnu.org/software/patch/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/patch-2.8-1-aarch64.pkg.tar.xz', 'version': '2.8-1'}, 'perl': {'arch': 'aarch64', 'filename': 'perl-5.42.3-1-aarch64.pkg.tar.xz', 'license': ['Artistic-1.0-Perl', 'GPL-1.0-or-later'], 'source_url': ['https://www.perl.org'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/perl-5.42.3-1-aarch64.pkg.tar.xz', 'version': '5.42.3-1'}, 'pipewire': {'arch': 'aarch64', 'filename': 'pipewire-1:1.6.9-1-aarch64.pkg.tar.xz', 'license': ['MIT', 'LGPL-2.1-or-later'], 'source_url': ['https://pipewire.org'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/pipewire-1:1.6.9-1-aarch64.pkg.tar.xz', 'version': '1:1.6.9-1'}, 'pkgconf': {'arch': 'aarch64', 'filename': 'pkgconf-3.0.7-1-aarch64.pkg.tar.xz', 'license': ['ISC'], 'source_url': ['https://github.com/pkgconf/pkgconf'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/pkgconf-3.0.7-1-aarch64.pkg.tar.xz', 'version': '3.0.7-1'}, 'python': {'arch': 'aarch64', 'filename': 'python-3.14.8-1-aarch64.pkg.tar.xz', 'license': ['PSF-2.0'], 'source_url': ['https://www.python.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/python-3.14.8-1-aarch64.pkg.tar.xz', 'version': '3.14.8-1'}, 'sudo': {'arch': 'aarch64', 'filename': 'sudo-1.9.17.p2-6-aarch64.pkg.tar.xz', 'license': ['custom'], 'source_url': ['https://www.sudo.ws/sudo/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/sudo-1.9.17.p2-6-aarch64.pkg.tar.xz', 'version': '1.9.17.p2-6'}, 'systemd': {'arch': 'aarch64', 'filename': 'systemd-262-1-aarch64.pkg.tar.xz', 'license': ['LGPL-2.1-or-later', 'CC0-1.0', 'GPL-2.0-or-later', 'MIT-0'], 'source_url': ['https://www.github.com/systemd/systemd'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/systemd-262-1-aarch64.pkg.tar.xz', 'version': '262-1'}, 'systemd-libs': {'arch': 'aarch64', 'filename': 'systemd-libs-262-1-aarch64.pkg.tar.xz', 'license': ['LGPL-2.1-or-later', 'CC0-1.0', 'GPL-2.0-or-later WITH Linux-syscall-note'], 'source_url': ['https://www.github.com/systemd/systemd'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/systemd-libs-262-1-aarch64.pkg.tar.xz', 'version': '262-1'}, 'systemd-resolvconf': {'arch': 'aarch64', 'filename': 'systemd-resolvconf-262-1-aarch64.pkg.tar.xz', 'license': ['LGPL-2.1-or-later'], 'source_url': ['https://www.github.com/systemd/systemd'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/systemd-resolvconf-262-1-aarch64.pkg.tar.xz', 'version': '262-1'}, 'systemd-sysvcompat': {'arch': 'aarch64', 'filename': 'systemd-sysvcompat-262-1-aarch64.pkg.tar.xz', 'license': ['LGPL-2.1-or-later'], 'source_url': ['https://www.github.com/systemd/systemd'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/systemd-sysvcompat-262-1-aarch64.pkg.tar.xz', 'version': '262-1'}, 'texinfo': {'arch': 'aarch64', 'filename': 'texinfo-7.3-1-aarch64.pkg.tar.xz', 'license': ['GPL3'], 'source_url': ['https://www.gnu.org/software/texinfo/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/texinfo-7.3-1-aarch64.pkg.tar.xz', 'version': '7.3-1'}, 'tomlplusplus': {'arch': 'aarch64', 'filename': 'tomlplusplus-3.4.0-1-aarch64.pkg.tar.xz', 'license': ['MIT'], 'source_url': ['https://marzer.github.io/tomlplusplus/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/tomlplusplus-3.4.0-1-aarch64.pkg.tar.xz', 'version': '3.4.0-1'}, 'tpm2-tss': {'arch': 'aarch64', 'filename': 'tpm2-tss-4.2.0-2-aarch64.pkg.tar.xz', 'license': ['BSD-2-Clause'], 'source_url': ['https://github.com/tpm2-software/tpm2-tss'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/tpm2-tss-4.2.0-2-aarch64.pkg.tar.xz', 'version': '4.2.0-2'}, 'tzdata': {'arch': 'aarch64', 'filename': 'tzdata-2026e-1-aarch64.pkg.tar.xz', 'license': ['LicenseRef-tz'], 'source_url': ['https://www.iana.org/time-zones'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/tzdata-2026e-1-aarch64.pkg.tar.xz', 'version': '2026e-1'}, 'wayland-protocols': {'arch': 'any', 'filename': 'wayland-protocols-1.49-1-any.pkg.tar.xz', 'license': ['MIT'], 'source_url': ['https://wayland.freedesktop.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/wayland-protocols-1.49-1-any.pkg.tar.xz', 'version': '1.49-1'}, 'wireplumber': {'arch': 'aarch64', 'filename': 'wireplumber-0.5.18-1-aarch64.pkg.tar.xz', 'license': ['MIT'], 'source_url': ['https://pipewire.pages.freedesktop.org/wireplumber/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/wireplumber-0.5.18-1-aarch64.pkg.tar.xz', 'version': '0.5.18-1'}, 'xkeyboard-config': {'arch': 'any', 'filename': 'xkeyboard-config-2.48-1-any.pkg.tar.xz', 'license': ['LicenseRef-xkeyboard-config'], 'source_url': ['https://gitlab.freedesktop.org/xkeyboard-config/xkeyboard-config'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/xkeyboard-config-2.48-1-any.pkg.tar.xz', 'version': '2.48-1'}, 'xorg-server-common': {'arch': 'aarch64', 'filename': 'xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz', 'license': ['LicenseRef-Adobe-Display-PostScript', 'BSD-3-Clause', 'LicenseRef-DEC-3-Clause', 'HPND', 'LicenseRef-HPND-sell-MIT-disclaimer-xserver', 'HPND-sell-variant', 'ICU', 'ISC', 'MIT', 'MIT-open-group', 'NTP', 'SGI-B-2.0', 'SMLNJ', 'X11', 'X11-distribute-modifications-variant'], 'source_url': ['https://xorg.freedesktop.org'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz', 'version': '21.1.25-1'}, 'xorg-xwayland': {'arch': 'aarch64', 'filename': 'xorg-xwayland-24.1.14-1-aarch64.pkg.tar.xz', 'license': ['LicenseRef-Adobe-Display-PostScript', 'BSD-3-Clause', 'LicenseRef-DEC-3-Clause', 'HPND', 'LicenseRef-HPND-sell-MIT-disclaimer-xserver', 'HPND-sell-variant', 'ICU', 'ISC', 'MIT', 'MIT-open-group', 'NTP', 'SGI-B-2.0', 'SMLNJ', 'X11', 'X11-distribute-modifications-variant'], 'source_url': ['https://xorg.freedesktop.org'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/xorg-xwayland-24.1.14-1-aarch64.pkg.tar.xz', 'version': '24.1.14-1'}}, 'schema': 1, 'signer_fingerprint': '68B3537F39A313B3E574D06777193F152BDBE6A6'}
BINDING = {'Root_receipt': {'bytes': 1545, 'sha256': '8fc5e5af70725a9e58db957885cdcbbb0a7694edb55694d059d882c0a41e41ac'}, 'branch': 'native349-r1', 'commit': '9d9e1ab7ce694e33238ec1152bef72270d4bf91f', 'deploy_key_fingerprint': 'SHA256:6gnCZBWA+I9mccJV/YzywHoefkGrpuKBHU0dVcgqn7k', 'manifest': {'bytes': 99724, 'sha256': 'd831cf894377deb4a90f6b8fd69eca08263318273a58061936f00b7ad82ba18e'}, 'readonly_repository_scope': 'Gabriel-Kahen/cachy-asahi-ci-inputs', 'repository': 'Gabriel-Kahen/cachy-asahi-ci-inputs', 'ssh_host_keys': ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'], 'tree': 'cc6298d8dbbb5b0dd522de76b7140306d83bfe7a'}
HOST_REFERENCE = {'HTTP_status': 200, 'Root_host_pin_binding': None, 'documentation': 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints', 'fingerprint': 'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU', 'key': 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl', 'kind': 'OFFICIAL_GITHUB_ED25519_REFERENCE_NOT_ROOT_BINDING', 'response_bytes': 204557, 'response_sha256': '5bb0a36de4e8415759d8016d8ad5356ccb3346a4bcbb9bf29de592ee290ed652', 'source': 'https://api.github.com/meta'}
SECRET = 'CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY'
REPOSITORY = 'Gabriel-Kahen/cachy-asahi-ci-inputs'
FORBIDDEN = {'fa96de743c6806092284a2069f2aa4c01234d200', '15d272e7a4647495ecf98c1afc36e62477b0eb74',
             'e1c763a74f7db48aba5e2c57757abc79233c8543', 'fd2755ce0d8972b69f32b2412d80180b36aac377'}
TOTAL = 544634853
LARGEST = 104330276
LIBFFI_NAME = 'libffi-3.8.0-1-aarch64.pkg.tar.xz'
LIBFFI_PRIMARY = 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/'
LIBFFI_ARCHIVE = 'https://pkgmirror.sametimetomorrow.net/aarch64/packages/l/libffi/'
LIBFFI_PINS = {
    LIBFFI_NAME: (51464, 'dfece459e053d53a5a7fdfbb2caf1b0fa662470220f86615a7789eba8571c0ff'),
    LIBFFI_NAME+'.sig': (566, '3772033208e24a494fa9602f66d063978ecbccd4f4f99132048e2213f91355b8'),
}
GIT = ['/usr/bin/git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null', '-c', 'maintenance.auto=false',
       '-c', 'gc.auto=0', '-c', 'core.preloadIndex=false', '-c', 'index.threads=1', '-c', 'pack.threads=1',
       '-c', 'core.autocrlf=false', '-c', 'core.attributesFile=/dev/null', '-c', 'submodule.recurse=false',
       '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never', '-c', 'credential.helper=']


PUBLIC_STAGES = frozenset({
    'binding', 'fetch-paths', 'ordinary-arm', 'source-admission', 'fetch-output',
    'disk-budget', 'fetch-tools', 'child-supervisor', 'credential-home',
    'key-input', 'key-write', 'host-pin-write', 'key-derivation', 'key-fingerprint',
    'git-init', 'git-origin', 'git-fetch', 'credential-retirement', 'git-ref',
    'git-object-metadata', 'git-commit-metadata', 'git-tree-metadata', 'git-checkout',
    'public-material', 'git-retirement', 'fetch-receipt', 'final-credential-cleanup',
})
PUBLIC_GUARDS = frozenset({
    'binding-schema', 'Root-carrier-CID-tree-unissued', 'Root-carrier-receipt-unissued',
    'Root-host-key-deploy-scope-unissued', 'exact182-original501', 'ordinary-path',
    'genuine-ordinary-ARM-fetch', 'explicit-Root-source-map', 'Root-source-map-pin',
    'pinned-source-admission-code', 'ordinary-bounded-file', 'stable-file',
    'fresh-fetch-output', 'original-controller-disk-reserve-plus-finite-fetch',
    'observed-existing-fetch-tool', 'ordinary-public-input', 'same-open-input',
    'public-input-budget', 'unchanged-input', 'whole-public-input',
    'Root-deploy-key-required', 'deploy-public-key', 'exact-Root-deploy-key-fingerprint',
    'finite-fetch-commands-deadline', 'same-qualified-fetch-tools', 'natural-fetch-child-required',
    'late-fetch-child-retirement',
    'same-temporary-key-before-delete', 'same-credential-home', 'only-own-host-pin-in-keyhome',
    'same-own-host-pin', 'key-and-home-absent-before-checkout-controller', 'same-key-final-cleanup',
    'private-key-not-retained', 'private-key-home-not-retained',
    'forbidden-stored-or-reachable-OID', 'only-complete-reachable-carrier-objects',
    'actual-parentless-pinned-tree', 'carrier-tree-modes-types',
    'carrier-precheckout-exact-blob-size', 'carrier-tree-only183', 'carrier-symlink',
    'carrier-extra-directory', 'carrier-special-file', 'complete183-public-namespace',
    'manifest-pin-mode', 'canonical-manifest-schema', 'exact182-lock-no-rebaseline',
    'exact91-provenance', 'original-provenance', 'official-signature-provenance',
    'signature-receipt-pin', 'exact-public-input-pin-mode', 'duplicate-json',
    'nonfinite-json', 'same-owned-fetch-store',
})
PUBLIC_ERROR_CLASSES = {
    cls: cls.__name__ for cls in (ValueError, OSError, FileNotFoundError, FileExistsError,
                                 PermissionError, TimeoutError, UnicodeDecodeError,
                                 json.JSONDecodeError, subprocess.SubprocessError,
                                 KeyError, TypeError, ImportError, IndexError, KeyboardInterrupt)
}


def need(value, guard):
    if not value:
        error = ValueError(guard)
        error._carrier_guard_id = guard
        raise error


def public_failure(stage, error):
    guard = getattr(error, '_carrier_guard_id', None) if type(error) is ValueError else None
    if type(guard) is not str or guard not in PUBLIC_GUARDS:
        guard = 'stage-exception'
    return dict(stage=stage if type(stage) is str and stage in PUBLIC_STAGES else 'unclassified', guard_id=guard,
                error_class=PUBLIC_ERROR_CLASSES.get(type(error), 'OtherError'))


class FetchDiagnostic:
    def __init__(self):
        self.stage = 'unclassified'
        self.primary = None
        self.cleanup = None

    def hold(self, error):
        failure = self.primary or self.cleanup or public_failure(self.stage, error)
        return dict(status='HOLD_PINNED_INPUT_CARRIER', **failure,
                    cleanup_failure=self.cleanup if self.primary else None,
                    private_key_value_logged=False)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def decode(raw):
    def pairs(rows):
        result = {}
        for name, value in rows:
            need(name not in result, 'duplicate-json')
            result[name] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite-json'))


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def key_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid)


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary-path')
    return path


def whole(path, maximum=1024**2):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum
             and not before.st_mode & 0o022, 'ordinary-bounded-file')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum+1)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'stable-file')
        return raw
    finally:
        os.close(fd)


def file_pin(path, maximum=LARGEST, *, release_cache=False):
    path = ordinary(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum
         and not before.st_mode & 0o022, 'ordinary-public-input')
    digest = hashlib.sha256(); size = 0
    with path.open('rb') as stream:
        need(identity(before) == identity(os.fstat(stream.fileno())), 'same-open-input')
        while raw := stream.read(1024**2):
            size += len(raw); need(size <= maximum, 'public-input-budget'); digest.update(raw)
        if release_cache:
            os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
        need(identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()), 'unchanged-input')
    need(size == before.st_size, 'whole-public-input')
    return dict(bytes=size, sha256=digest.hexdigest())


def binding():
    b = BINDING
    need(set(b) == {'repository', 'branch', 'commit', 'tree', 'manifest', 'ssh_host_keys', 'deploy_key_fingerprint', 'Root_receipt', 'readonly_repository_scope'}, 'binding-schema')
    need(b['repository'] == REPOSITORY and b['branch'] == 'native349-r1'
         and re.fullmatch('[0-9a-f]{40}', b['commit'] or '') and re.fullmatch('[0-9a-f]{40}', b['tree'] or ''), 'Root-carrier-CID-tree-unissued')
    for name in ('manifest', 'Root_receipt'):
        row = b[name]
        need(type(row) is dict and set(row) == {'bytes', 'sha256'} and type(row['bytes']) is int and 0 < row['bytes'] <= 1024**2
             and re.fullmatch('[0-9a-f]{64}', row['sha256'] or ''), 'Root-carrier-receipt-unissued')
    need(b['ssh_host_keys'] == [HOST_REFERENCE['key']] and b['readonly_repository_scope'] == REPOSITORY
         and re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', b['deploy_key_fingerprint'] or ''), 'Root-host-key-deploy-scope-unissued')
    need(EXPECTED['all501_required'] is True and len(EXPECTED['files']) == 182
         and sum(r['bytes'] for r in EXPECTED['files'].values()) == TOTAL
         and max(r['bytes'] for r in EXPECTED['files'].values()) == LARGEST < 100*1024**2, 'exact182-original501')
    return b


def manifest(raw):
    value = decode(raw)
    need(raw == encode(value) and set(value) == {'schema', 'kind', 'input_lock_sha256', 'all501_required', 'files', 'package_provenance', 'native_build', 'installation', 'Root_acceptance'}, 'canonical-manifest-schema')
    need(value['schema'] == 1 and value['kind'] == 'NATIVE349_EXACT_MISSING_PUBLIC_INPUTS_V1'
         and value['input_lock_sha256'] == EXPECTED['input_lock_sha256'] and value['all501_required'] is True
         and value['files'] == EXPECTED['files'] and value['native_build'] == value['installation'] == 'NOT RUN'
         and value['Root_acceptance'] is None, 'exact182-lock-no-rebaseline')
    need(set(value['package_provenance']) == set(EXPECTED['package_provenance']), 'exact91-provenance')
    for name, before in EXPECTED['package_provenance'].items():
        row = value['package_provenance'][name]
        need(set(row) == set(before) | {'signature_verification'} and all(row[k] == v for k, v in before.items()), 'original-provenance')
        proof = row['signature_verification']
        need(set(proof) == {'status', 'primary_fingerprint', 'receipt'} and proof['status'] == 'PASS_EXACT_OFFICIAL_SIGNATURE'
             and proof['primary_fingerprint'] == EXPECTED['signer_fingerprint'], 'official-signature-provenance')
        receipt = proof['receipt']
        need(set(receipt) == {'bytes', 'sha256'} and type(receipt['bytes']) is int and 0 < receipt['bytes'] <= 4*1024**2
             and re.fullmatch('[0-9a-f]{64}', receipt['sha256'] or ''), 'signature-receipt-pin')
    return value


def material(root, expected_manifest=None, *, release_cache=False):
    root = ordinary(root)
    names = set()
    for path in root.rglob('*'):
        need(not path.is_symlink(), 'carrier-symlink')
        if path.is_file(): names.add(str(path.relative_to(root)))
        elif path.is_dir(): need(path == root/'packages', 'carrier-extra-directory')
        else: need(False, 'carrier-special-file')
    need(names == set(EXPECTED['files']) | {'manifest.json'}, 'complete183-public-namespace')
    raw = whole(root/'manifest.json')
    need((expected_manifest is None or pin(raw) == expected_manifest)
         and stat.S_IMODE((root/'manifest.json').stat().st_mode) == 0o644, 'manifest-pin-mode')
    value = manifest(raw)
    for name, row in EXPECTED['files'].items():
        need(stat.S_IMODE((root/name).stat().st_mode) == row['mode']
             and file_pin(root/name, release_cache=release_cache) == {k: row[k] for k in ('bytes', 'sha256')}, 'exact-public-input-pin-mode')
    return value


def copy_public(source, destination, uid=None, gid=None, *, release_cache=False):
    """Copy only the already pinned finite public namespace; no key/config path."""
    source, destination = ordinary(source), ordinary(destination)
    need(not destination.exists() and not destination.is_relative_to(source) and not source.is_relative_to(destination), 'fresh-disjoint-material')
    value = material(source, BINDING['manifest'], release_cache=release_cache)
    destination.mkdir(mode=0o700)
    for name in ('manifest.json', *EXPECTED['files']):
        target = destination/name; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (source/name).open('rb') as src, target.open('xb') as dst:
            os.fchmod(dst.fileno(), 0o644)
            shutil.copyfileobj(src, dst, 1024**2)
            if release_cache:
                # Finish per-file writeback before asking the kernel to release
                # clean pages. The controller's bound includes file cache.
                dst.flush()
                os.fdatasync(dst.fileno())
                for stream in (src, dst):
                    os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
        if uid is not None: os.chown(target, uid, gid)
    if uid is not None:
        os.chown(destination/'packages', uid, gid); os.chown(destination, uid, gid)
    material(destination, BINDING['manifest'], release_cache=release_cache)
    return dict(kind='EXACT_PUBLIC_182_CARRIER_STAGE', files=182, bytes=TOTAL, manifest=pin(encode(value)), private_key_present=False, accepting=False)


def stage(source, destination, uid, gid):
    binding(); need(SECRET not in os.environ and 'SSH_AUTH_SOCK' not in os.environ, 'no-fetch-credential-in-controller')
    source, destination = ordinary(source), ordinary(destination)
    need(destination.name == 'native349-pinned-inputs' and destination.parent.name == 'work' and destination.parent.parent.name == 'volume', 'owned-quota-only-stage')
    run = os.environ.get('GITHUB_RUN_ID', '')
    need(re.fullmatch('[1-9][0-9]{1,19}', run) and source.name == 'public'
         and source.parent.name == 'native349-carrier-'+run+'-1' and source.parent.parent == destination.parents[3], 'same-run-exact-public-fetch-output')
    return copy_public(source, destination, uid, gid, release_cache=True)


def owned_leaf(path, size):
    info = ordinary(path).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
         and info.st_nlink == 1 and info.st_size == size and not info.st_mode & 0o022,
         'exact owned single-link input leaf')
    return info


def owned_handoff(source, destination, size):
    """Transfer one single-link input inode to a fresh name on the same quota."""
    before = owned_leaf(source, size)
    parent = ordinary(destination.parent).lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and not parent.st_mode & 0o022
         and parent.st_dev == before.st_dev, 'same owned input quota and destination directory')
    os.link(source, destination, follow_symlinks=False)
    def file_id(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns)
    linked = destination.lstat()
    need(linked.st_nlink == 2 and file_id(before) == file_id(linked)
         and identity(source.lstat()) == identity(linked), 'exact two-name handoff before retiring original')
    source.unlink()
    need(file_id(owned_leaf(destination, size)) == file_id(before), 'single original inode at its fresh destination')


def seed(source, cache):
    binding(); need(SECRET not in os.environ and 'SSH_AUTH_SOCK' not in os.environ, 'no-fetch-credential-in-payload')
    source, cache = ordinary(source), ordinary(cache)
    need(source.name == 'native349-pinned-inputs' and cache.name == 'cache'
         and cache.parent.name == 'llhttp-reference-native' and source.parent == cache.parent.parent, 'same-owned-work-cache')
    material(source, BINDING['manifest']); need(cache.is_dir() and not cache.is_symlink(), 'canonical-existing-cache-required')
    manifest_file = source/'manifest.json'
    manifest_info = owned_leaf(manifest_file, BINDING['manifest']['bytes'])
    for relative, row in EXPECTED['files'].items():
        name = relative.removeprefix('packages/'); target = cache/name; staged = source/relative
        expected = {k: row[k] for k in ('bytes', 'sha256')}
        if target.exists():
            before = owned_leaf(staged, row['bytes'])
            need(file_pin(target) == expected and identity(staged.lstat()) == identity(before),
                 'retire owned duplicate only after exact cache body rejoin')
            staged.unlink()
        else:
            owned_handoff(staged, target, row['bytes'])
            target.chmod(0o600)
            need(file_pin(target) == expected, 'whole-seeded-cache-input')
    need(identity(manifest_file.lstat()) == identity(manifest_info), 'same exact owned stage manifest')
    manifest_file.unlink()
    (source/'packages').rmdir()
    source.rmdir()
    return dict(kind='ONLY_EXACT_MISSING182_SEEDED_BEFORE_ALL501_ACQUIRE', files=182, bytes=TOTAL,
                all501_required=True, URL_overrides=False, staged_copy_retired=True,
                signature_authentication='MANDATORY_EXISTING_CANONICAL_AUDIT_NOT_BYPASSED')


def install_libffi_recovery(native):
    """Keep the original fetch and allow one pinned libffi archive route on a 404."""
    original = native.fetch
    archive_lock = threading.Lock()

    def fetch(item, cache):
        try:
            return original(item, cache)
        except native.AcquisitionError as error:
            name = item['filename']
            if (LIBFFI_PINS.get(name) != (item['size'], item['sha256']) or item['url'] != LIBFFI_PRIMARY+name
                    or error.filename != name or error.category != 'HTTP failure' or error.http_status != 404):
                raise
        with archive_lock:
            row = dict(kind='LLHTTP_LIBFFI_ALAA_RECOVERY_V1', filename=name, primary_http_status=404)
            print(json.dumps(dict(row, status='ATTEMPTED')), flush=True)
            target = original(dict(item, url=LIBFFI_ARCHIVE+name), cache)
            print(json.dumps(dict(row, status='PASS_PINNED_BODY')), flush=True)
            return target

    native.fetch = fetch


ROOTFS_BYTES = 829367415
ROOTFS_SHA256 = '42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319'
ROOTFS_DIFF_ID = 'sha256:44409090c83feba37bfaf8e897d84804331f1412f9f4665cacc95688c6e9b0fb'
ROOTFS_MEMBERS = 49104
ROOTFS_SCRATCH = b'FROM scratch\nADD rootfs.tar.gz /\n'
HELD_NATIVE_BUILD = '238f8a8a14af23e2f02ad0fd5d1522f984ef38f7114edd9b1b27c45f98789e4e'
EXPECTED_INVENTORY = '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
DESKTOP574_LOCK = 'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'
INVENTORY_ADDITIONS = {
    'cmake':'4.4.4-1', 'cppdap':'1.58.0-3', 'jsoncpp':'1.9.8-1', 'libuv':'1.52.1-2',
    'meson':'1.12.1-2', 'ninja':'1.13.2-3', 'python-tqdm':'4.70.1-1', 'rhash':'1.4.6-1',
}


def extend_bootstrap_inputs(original, retained_lock, expected_inventory):
    """Join the untouched 501-input lock and only its missing inventory entries."""
    base_raw=whole(retained_lock)
    need(pin(base_raw)['sha256']==EXPECTED['input_lock_sha256'] and decode(base_raw)==original
         and len(original['packages'])==248 and pin(expected_inventory)['sha256']==EXPECTED_INVENTORY,
         'original pinned 501 lock and exact expected349 inventory')
    raw=whole(HERE/'inventory349-extra-inputs.json',32*1024)
    extension=decode(raw)
    need(set(extension)=={'kind','base_lock_sha256','desktop574_lock_sha256','packages','acquisition_urls'}
         and extension['kind']=='LLHTTP_INVENTORY349_EXACT_EIGHT_V1'
         and extension['base_lock_sha256']==EXPECTED['input_lock_sha256']
         and extension['desktop574_lock_sha256']==DESKTOP574_LOCK
         and type(extension['packages']) is list and len(extension['packages'])==8
         and type(extension['acquisition_urls']) is dict, 'exact additive inventory input declaration')
    additional=extension['packages']
    routes=extension['acquisition_urls']
    need({row['name']:row['version'] for row in additional}==INVENTORY_ADDITIONS
         and set(routes)=={row['filename'] for row in additional}, 'only exact eight additional package rows')
    packages=[]
    for row in additional:
        name=row['filename']
        archive=('https://pkgmirror.sametimetomorrow.net/aarch64/packages/'
                 +row['name'][0]+'/'+row['name']+'/'+name)
        need(name==f"{row['name']}-{row['version']}-{row['arch']}.pkg.tar.xz"
             and row['arch'] in ('aarch64','any')
             and row['url']=='https://ca.us.mirror.archlinuxarm.org/aarch64/extra/'+name
             and routes[name]==archive
             and all(type(row[key]) is int and 0<row[key]<=32*1024**2 for key in ('size','signature_size'))
             and all(re.fullmatch('[0-9a-f]{64}',row[key]) for key in ('sha256','signature_sha256')),
             'exact original package, detached signature and ALARM repository')
        packages.append(dict(row,url=routes[name]))
    projected={row['name'][0]:row['version'][0] for row in original['rootfs_packages']}
    projected.update({row['name']:row['version'] for row in original['packages']})
    need(len(projected)==341 and not projected.keys()&INVENTORY_ADDITIONS.keys(),'only additive missing packages')
    projected.update(INVENTORY_ADDITIONS)
    need(''.join(f'{name} {version}\n' for name,version in sorted(projected.items())).encode()==expected_inventory,
         'exact published expected349 lock after the eight additive inputs')
    return dict(original,packages=[*original['packages'],*packages]),pin(raw)


def install_inventory_transport(native, inputs):
    """Keep normal acquisition and pace only the reviewed archive's 16 requests."""
    archive_inputs=inputs['packages'][-8:]
    need({row['name']:row['version'] for row in archive_inputs}==INVENTORY_ADDITIONS,
         'exact added inventory transport scope')
    pairs=[item for row in archive_inputs for item in (row,native.signature_item(row))]
    keys=('filename','url','sha256','size')
    pinned={item['filename']:tuple(item[key] for key in keys) for item in pairs}
    need(len(pinned)==16,'exact eight package and signature pairs')
    original=native.fetch
    gate=threading.Lock()
    next_request=0.0

    def fetch(item,cache):
        nonlocal next_request
        expected=pinned.get(item['filename'])
        if expected is None:
            return original(item,cache)
        need(tuple(item[key] for key in keys)==expected,'same reviewed additional acquisition route and pin')
        with gate:
            delay=next_request-time.monotonic()
            if delay>0:
                time.sleep(delay)
            try:
                return original(item,cache)
            finally:
                next_request=time.monotonic()+1.25

    native.fetch=fetch


def rootfs_need(value, guard):
    if not value:
        raise ValueError(guard)


def rootfs_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def install_context_handoff(native, inputs, cache, out):
    """Project only the three copies in the authenticated legacy build handoff."""
    cache,out=ordinary(cache),ordinary(out)
    need(cache.name=='cache' and out.name=='bootstrap' and cache.parent==out.parent
         and cache.parent.name=='llhttp-reference-native','exact owned bootstrap staging roots')
    text=whole(Path(native.__file__)).decode()
    node,=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='build']
    original=ast.get_source_segment(text,node)
    need(hashlib.sha256(original.encode()).hexdigest()==HELD_NATIVE_BUILD
         and original.count('shutil.copyfile(')==3
         and 'PINNED_CONTEXT_TRANSFER' not in native.__dict__, 'exact held three-copy bootstrap')
    projected=original.replace('shutil.copyfile(', 'PINNED_CONTEXT_TRANSFER(')
    need(projected.replace('PINNED_CONTEXT_TRANSFER(', 'shutil.copyfile(')==original,
         'whole unchanged authenticated build inverse')
    handoff=ContextHandoff(inputs,cache,out)
    native.PINNED_CONTEXT_TRANSFER=handoff.transfer
    exec(compile(projected,native.__file__,'exec'),native.__dict__)
    return handoff


class ContextHandoff:
    """Keep one owned ext4 inode per already authenticated build operand."""
    def __init__(self, inputs, cache, out):
        self.cache=cache
        self.context=out/'context'
        self.pending={}
        self.verified={}
        self.total=0
        self.allocated=0
        checks={}
        root=inputs['rootfs']
        self.rootfs=self.context/'rootfs.tar.gz'
        self.plan(root,self.rootfs,checks)
        checks[root['filename']+'.sig']=root['signature_sha256']
        for item in inputs['packages']:
            name=item['filename']
            self.plan(item,self.context/'deps'/name,checks)
            sig=dict(filename=name+'.sig',size=item['signature_size'],sha256=item['signature_sha256'])
            self.plan(sig,self.context/'deps'/sig['filename'],checks)
        for item in inputs['keyring_files']:
            self.plan(item,self.context/'keys'/item['filename'],checks)
        need(len(self.pending)==516 and len(checks)==517 and decode(whole(out/'cache-checksums.json'))==checks,
             'complete original 501 and 16 additional audit checksum joins before owned cache handoff')

    def plan(self, item, destination, checks):
        name=item['filename']
        size=item['size']
        empty_revocations=(size==0 and name=='archlinuxarm-revoked'
                           and destination==self.context/'keys'/name
                           and item['sha256']==hashlib.sha256(b'').hexdigest())
        need(re.fullmatch(r'[A-Za-z0-9_+:.@-]+',name) and name not in ('.','..') and name not in checks
             and type(size) is int and (size>0 or empty_revocations), 'unique exact bounded authenticated operand')
        self.pending[self.cache/name]=(destination,size)
        checks[name]=item['sha256']

    def transfer(self, source, destination):
        planned=self.pending.get(source)
        need(planned is not None and planned[0]==destination,'only exact authenticated context copy operand')
        owned_handoff(source,destination,planned[1])
        # The held entry sets umask 077, so its former copy created mode 0600.
        destination.chmod(0o600)
        info=owned_leaf(destination,planned[1])
        self.verified[destination]=identity(info)
        self.total+=info.st_size
        self.allocated+=info.st_blocks*512
        del self.pending[source]

    def retire_context(self):
        # The completed build has already uploaded the context and checked the image inventory.
        need(not self.pending and not self.rootfs.exists() and not self.rootfs.is_symlink(),
             'complete original build and inspected rootfs context retired after import')
        for item, before in self.verified.items():
            if item!=self.rootfs:
                need(identity(item.lstat())==before,'same exact uploaded context input before retirement')
                item.unlink()
        (self.context/'deps').rmdir()
        (self.context/'keys').rmdir()
        print(json.dumps(dict(kind='EXACT_AUDITED_CONTEXT_HANDOFF_V1',files=len(self.verified),
                              bytes=self.total,allocated_bytes=self.allocated,accepting=False)),flush=True)


def signed_rootfs_layout(path):
    """Read only the pinned archive and the executable headers used for bootstrap."""
    rootfs_need(path.is_absolute() and path == path.resolve(), 'ordinary signed rootfs context path')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        rootfs_need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
                    and not before.st_mode & 0o022 and before.st_size == ROOTFS_BYTES
                    and hashlib.file_digest(stream, 'sha256').hexdigest() == ROOTFS_SHA256, 'exact pinned signed rootfs context bytes')
        stream.seek(0)
        links = {'bin':'usr/bin', 'lib':'usr/lib', 'usr/bin/sh':'bash'}
        directories = {'usr','usr/bin','usr/lib'}
        elf = {'usr/bin/bash','usr/lib/ld-linux-aarch64.so.1'}
        required = set(links) | directories | elf
        seen = set()
        count = 0
        with tarfile.open(fileobj=stream, mode='r|gz') as archive:
            for count,info in enumerate(archive,1):
                rootfs_need(count <= ROOTFS_MEMBERS, 'finite signed rootfs member census')
                name = info.name.removeprefix('./')
                if name not in required:
                    continue
                rootfs_need(name not in seen and info.uid == info.gid == 0, 'unique root-owned bootstrap entry')
                seen.add(name)
                if name in links:
                    rootfs_need(info.issym() and info.linkname == links[name], 'literal signed rootfs shell or loader alias')
                elif name in directories:
                    rootfs_need(info.isdir() and info.mode == 0o755, 'literal signed rootfs directory')
                else:
                    rootfs_need(info.isfile() and info.mode == 0o755 and info.size >= 64, 'regular executable in signed rootfs')
                    with archive.extractfile(info) as member:
                        data = member.read(min(info.size,4096))
                    rootfs_need(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01' and data[18:20] == b'\xb7\x00', 'AArch64 ELF in signed rootfs')
                    if name == 'usr/bin/bash':
                        phoff = struct.unpack_from('<Q',data,32)[0]
                        entsize, entries = struct.unpack_from('<HH',data,54)
                        rootfs_need(entsize == 56 and 0 < entries <= 32 and 64 <= phoff <= len(data)-entries*entsize,
                                    'bounded signed shell program headers')
                        targets = []
                        for offset in range(phoff,phoff+entries*entsize,entsize):
                            kind,_,start,_,_,length,_,_ = struct.unpack_from('<IIQQQQQQ',data,offset)
                            if kind == 3:
                                targets.append(data[start:start+length])
                        rootfs_need(targets == [b'/lib/ld-linux-aarch64.so.1\x00'], 'literal signed shell interpreter')
        rootfs_need(seen == required and count == ROOTFS_MEMBERS, 'complete finite signed rootfs entrypoints')
        identity = rootfs_identity(before)
        rootfs_need(rootfs_identity(os.fstat(stream.fileno())) == rootfs_identity(path.lstat()) == identity, 'same signed rootfs during read')
        return identity


def stage_packaging_config(context):
    body = (b'[options]\nArchitecture = aarch64\nSigLevel = Required\n'
            b'LocalFileSigLevel = Required\nHookDir = /builder-disabled-hooks\n')
    config = context / 'pacman.conf'
    fd = os.open(config, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        current = os.fstat(stream.fileno())
        rootfs_need(stat.S_ISREG(current.st_mode) and current.st_nlink == 1
                    and current.st_uid == os.geteuid()
                    and stat.S_IMODE(current.st_mode) in (0o600, 0o644),
                    'ordinary generated offline packaging config')
        rootfs_need(stream.read(len(body) + 1) == body
                    and identity(current) == identity(config.lstat()),
                    'exact generated offline packaging config bytes')
        # Docker COPY retains the context mode. The image builder runs as alarm.
        os.fchmod(stream.fileno(), 0o644)


class SignedRootfsBootstrap:
    """Install after the original audit and run cleanup after derived-image retirement."""
    def __init__(self,native,runner,out,nonce,operation='llhttp-reference',probe=None):
        rootfs_need(re.fullmatch('[0-9a-f]{32}',nonce) and re.fullmatch('[a-z][a-z0-9-]{3,28}',operation), 'fixed owned signed-rootfs scope')
        self.run_existing, self.runner, self.out, self.probe = native.run, runner, out, probe
        self.labels = {'org.cachy-asahi.'+operation+'.signed-rootfs':nonce}
        self.label = next(iter(self.labels))+'='+nonce
        self.tag = 'cachy-'+operation+'-rootfs:'+nonce
        self.submitted = False
        self.image = None
        native.run = self.call

    def _images(self,selector):
        raw = self.runner(['/usr/bin/docker','image','ls','--all','--quiet','--no-trunc','--filter',selector],15).stdout
        rows = raw.decode('ascii').splitlines()
        rootfs_need(len(rows) <= 1 and all(re.fullmatch(r'sha256:[0-9a-f]{64}',x) for x in rows), 'unambiguous signed-rootfs image census')
        return rows

    def _inspect(self,image,allow_untagged=False):
        rows = json.loads(self.runner(['/usr/bin/docker','image','inspect',image],15).stdout)
        rootfs_need(type(rows) is list and len(rows) == 1, 'one signed-rootfs image inspection')
        row = rows[0]
        tags = row.get('RepoTags') or []
        rootfs_need(row.get('Id') == image and row.get('Os') == 'linux' and row.get('Architecture') == 'arm64'
                    and (tags == [self.tag] or allow_untagged and not tags) and not row.get('RepoDigests')
                    and row['Config'].get('Labels') == self.labels
                    and row['RootFS'].get('Layers') == [ROOTFS_DIFF_ID], 'exact owned ARM signed-rootfs ID, tag, label and layer')

    def call(self,argv,log=None,timeout=1800):
        if argv[:2] != ['docker','build']:
            return self.run_existing(argv,log,timeout)
        context = self.out/'context'
        expected = ['docker','build','--network=none','--pull=false','--platform=linux/arm64',
                    '--iidfile',str(self.out/'image-id'),str(context)]
        rootfs_need(argv == expected and not self.submitted, 'one original owned offline bootstrap command')
        archive, dockerfile = context/'rootfs.tar.gz',context/'Dockerfile'
        rootfs_need(dockerfile == dockerfile.resolve() and dockerfile.is_file(), 'ordinary original Dockerfile')
        with dockerfile.open('rb') as stream:
            raw = stream.read(16*1024+1)
        rootfs_need(len(raw) <= 16*1024 and raw.startswith(ROOTFS_SCRATCH) and raw.count(ROOTFS_SCRATCH) == 1,
                    'single original scratch ADD projection seam')
        stage_packaging_config(context)
        identity = signed_rootfs_layout(archive)
        rootfs_need(not self._images('label='+self.label) and not self._images('reference='+self.tag), 'fresh signed-rootfs label and tag')
        self.submitted = True
        imported = self.runner(['/usr/bin/docker','image','import','--platform=linux/arm64','--change','LABEL '+self.label,
                                str(archive),self.tag],180).stdout.decode('ascii').strip()
        rootfs_need(re.fullmatch(r'sha256:[0-9a-f]{64}',imported), 'complete immutable signed-rootfs import ID')
        self.image = imported
        self._inspect(imported)
        rootfs_need(rootfs_identity(archive.lstat()) == identity, 'same archive through signed-rootfs import')
        if self.probe is not None:
            self.probe(imported,dict(self.labels))
        # A bare full ID is resolvable locally by the legacy builder and is
        # invalid as a registry repository. Clear the inherited base label
        # before any derived image is made to keep the cleanup census exact.
        replacement = ('FROM '+imported.removeprefix('sha256:')+'\nLABEL '+next(iter(self.labels))+'=""\n').encode('ascii')
        projected = raw.replace(ROOTFS_SCRATCH,replacement,1)
        rootfs_need(projected.count(replacement) == 1 and projected.replace(replacement,ROOTFS_SCRATCH,1) == raw,
                    'whole Dockerfile inverse outside signed base image')
        temporary = context/'Dockerfile.rootfs-import'
        with temporary.open('xb') as stream:
            stream.write(projected)
        temporary.replace(dockerfile)
        archive.unlink()
        print(json.dumps(dict(kind='EXACT_SIGNED_ARM_ROOTFS_IMPORT_V1',image=imported,
                              layer=ROOTFS_DIFF_ID,accepting=False)),flush=True)
        return self.run_existing(argv,log,timeout)

    def cleanup(self):
        if not self.submitted:
            return dict(submitted=False)
        labelled = self._images('label='+self.label)
        tagged = self._images('reference='+self.tag)
        rootfs_need(not tagged or tagged == labelled, 'same owned signed-rootfs label and tag before retirement')
        if labelled:
            image = labelled[0]
            rootfs_need(self.image is None or self.image == image, 'same originally observed signed-rootfs image ID')
            self._inspect(image,allow_untagged=True)
            self.runner(['/usr/bin/docker','image','rm','--no-prune',image],30)
        rootfs_need(not self._images('label='+self.label) and not self._images('reference='+self.tag), 'owned signed-rootfs tag and image absent')
        return dict(submitted=True,image_id=self.image,owned_image_absence_verified=True)


PACKAGE_COMMANDS = {
    'build': ('build_llhttp-reference.py',
              '7f22ecf8198af5955062dd76c5dcac8e90621e9c54a6fef96481fd19a060fb0f',
              "bind_artifact(report['metadata'], result, report['input_sha256']['PKGBUILD'])",
              "bind_llhttp_artifact(report['metadata'], result, report['input_sha256']['PKGBUILD'], paths[0])"),
    'compare': ('compare_llhttp.py',
                '0d4a2c31e2d001848f20cb21ef22e8fb8ca157d291a749ded09b7beaeee0d534',
                "bind_artifact(record['recipe_metadata'], report, record['recipe_inputs']['PKGBUILD'])",
                "bind_llhttp_artifact(record['recipe_metadata'], report, record['recipe_inputs']['PKGBUILD'], item)"),
}
PAIR_FINISHER_SHA = '9c050c418e3fdb2b1bb168d3c8f535a885a3714a68844988b3a2f93d1d9566a0'


def package_commands(here, builds, compare):
    interpreter = ['/usr/bin/python3', '-I', '-B']
    carrier = str(Path(__file__).resolve())

    def project(kind, command):
        script = here / 'runtime/scripts/build' / PACKAGE_COMMANDS[kind][0]
        need(command[:4] == [*interpreter, str(script)], 'exact held package command')
        return [*interpreter, carrier, '--held-package-command', kind, *command[4:]]

    need(len(builds) == 2, 'exact held package pair')
    return [project('build', command) for command in builds], project('compare', compare)


def package_command(kind):
    """Project only the binding call in each immutable package-validation entry."""
    need(sys.flags.isolated and __debug__ and kind in PACKAGE_COMMANDS, 'isolated held package command')
    root = Path(__file__).resolve().parents[4]
    held = root / 'held-source/scripts/ci/llhttp-reference-native-source/base'
    name, sha, before, after = PACKAGE_COMMANDS[kind]
    script = held / 'runtime/scripts/build' / name
    raw = whole(script)
    need(pin(raw)['sha256'] == sha and raw.count(before.encode()) == 1 and after.encode() not in raw,
         'exact held package body and binding seam')
    projected = raw.replace(before.encode(), after.encode())
    need(projected.replace(after.encode(), before.encode()) == raw, 'whole package command inverse')
    finisher_file = held / 'finish_pair.py'
    finisher_raw = whole(finisher_file)
    need(pin(finisher_raw)['sha256'] == PAIR_FINISHER_SHA, 'exact held llhttp archive and ELF inspector')
    finisher = dict(__file__=str(finisher_file))
    exec(compile(finisher_raw, str(finisher_file), 'exec'), finisher)
    namespace = dict(__name__='llhttp_held_package', __file__=str(script))
    exec(compile(projected, str(script), 'exec'), namespace)
    original_bind = namespace['bind_artifact']
    namespace['bind_llhttp_artifact'] = lambda reviewed, report, recipe_hash, archive: bind_llhttp_artifact(
        reviewed, report, recipe_hash, archive, finisher, original_bind)
    return script, namespace


def bind_llhttp_artifact(reviewed, report, recipe_hash, archive, finisher, original_bind):
    """Bind the recipe's lone makepkg-generated provider to the actual library."""
    if sorted(reviewed.get('provides', [])) != ['libllhttp.so', 'llhttp=9.3.1'] or reviewed.get('provides_aarch64'):
        return ['unexpected reviewed llhttp providers']
    library = 'usr/lib/libllhttp.so.9.3.1'
    if set(report['elf']) != {library} or report['elf'][library]['errors']:
        return ['expected one structurally valid AArch64 llhttp library']
    try:
        raw, bodies = finisher['archive_members'](archive, (library,))
        if (pin(raw)['sha256'] != report['sha256']
                or pin(bodies[library])['sha256'] != report['members'][library]['sha256']):
            return ['llhttp provider archive or ELF changed during inspection']
        soname = finisher['elf'](bodies[library])['soname']
    except (ValueError, OSError, tarfile.TarError) as error:
        return [f'llhttp provider ELF validation failed: {error}']
    version = soname.removeprefix('libllhttp.so.')
    expected = dict(reviewed, provides=['llhttp=9.3.1', f'libllhttp.so={version}-64'])
    return original_bind(expected, report, recipe_hash)


def project_entry(raw):
    before = "seed.seed_current_build_cache(output/'cache',profile['inputs_sha256'])"
    after = before+"\n        PINNED_CARRIER.seed(PINNED_INPUTS,output/'cache')"
    text = raw.decode(); need(text.count(before) == 1 and after not in text, 'one-seed-before-audit-seam')
    new = text.replace(before, after)
    need(new.replace(after, before).encode() == raw, 'whole-unchanged-held-entry-inverse')
    count_before = 'len(self.rows)<160'; count_after = 'len(self.rows)<512'
    need(new.count(count_before) == 1 and count_after not in new, 'one finite inner command budget seam')
    bounded = new.replace(count_before, count_after)
    need(bounded.replace(count_after, count_before) == new, 'whole original inner command guard inverse')
    native_before = "native=C.module(HERE/'runtime/scripts/ci/native_arm.py','llhttp-reference_native');"
    native_after = native_before+'PINNED_CARRIER.install_libffi_recovery(native);'
    need(bounded.count(native_before) == 1 and native_after not in bounded, 'one native acquisition recovery seam')
    recovered = bounded.replace(native_before, native_after)
    need(recovered.replace(native_after, native_before) == bounded, 'whole libffi recovery inverse')
    init = 'scopes=[];tag=None;report=dict('
    build = "native.audit(inputs,output/'cache',output/'bootstrap');image=native.build("
    handoff = (
        "inputs,inventory_extension=PINNED_CARRIER.extend_bootstrap_inputs(inputs,output/'bootstrap/inputs.lock.json',C.read(HERE/'expected349.lock'));"
        "PINNED_CARRIER.install_inventory_transport(native,inputs);"
        "native.audit(inputs,output/'cache',output/'bootstrap');"
        "cache_handoff=PINNED_CARRIER.install_context_handoff(native,inputs,output/'cache',output/'bootstrap');"
    )
    inventory = "        C.need((output/'bootstrap/packages.lock').read_bytes()==C.read(HERE/'expected349.lock'),'genuine exact freshly provisioned349 inventory')"
    bootstrap_receipt = "bootstrap['legacy_command']=bootstrap['command'];"
    commands = '        builds,compare=C.plans(HERE,output,image)'
    cleanup = "        clean=not cleanup['errors']"
    edits = (
        (init, init.replace('report=dict(', 'rootfs_base=None;report=dict(')),
        (build, handoff+"rootfs_base=PINNED_CARRIER.SignedRootfsBootstrap(native,runner,output/'bootstrap',nonce);image=native.build("),
        (inventory, inventory+"\n        cache_handoff.retire_context()"),
        (bootstrap_receipt, bootstrap_receipt+"bootstrap['inventory349_extra_inputs']=inventory_extension;"),
        (commands, commands+"\n        builds,compare=PINNED_CARRIER.package_commands(HERE,builds,compare)"),
        (cleanup, "        if rootfs_base is not None:\n"
         "            try:cleanup['signed_rootfs']=rootfs_base.cleanup()\n"
         "            except BaseException as error:cleanup['errors'].append(dict(step='signed-rootfs',type=type(error).__name__))\n"+cleanup),
    )
    result = recovered
    for old, new in edits:
        need(result.count(old) == 1 and new not in result, 'unique held execution seam')
        result = result.replace(old,new)
    inverse = result
    for old, new in reversed(edits):
        need(inverse.count(new) == 1, 'unique held execution inverse seam')
        inverse = inverse.replace(new,old)
    need(inverse == recovered, 'whole held execution inverse')
    return result.encode()


def metadata_guard(stored, reachable):
    s = {n.split(b' ', 1)[0].decode() for n in stored.splitlines()}
    r = {n.split(b' ', 1)[0].decode() for n in reachable.splitlines()}
    need(all(re.fullmatch('[0-9a-f]{40}', n) for n in s | r) and not (s | r) & FORBIDDEN, 'forbidden-stored-or-reachable-OID')
    need(s == r and BINDING['commit'] in s, 'only-complete-reachable-carrier-objects')
    return dict(stored=len(s), reachable=len(r), forbidden_body_reads=False)


def tree_metadata(raw):
    found = {}
    for item in raw.split(b'\0'):
        if not item: continue
        header, name = item.split(b'\t', 1); mode, kind, oid, size = header.decode().split()
        name = name.decode('ascii'); need(name not in found and mode == '100644' and kind == 'blob', 'carrier-tree-modes-types')
        expected = BINDING['manifest']['bytes'] if name == 'manifest.json' else EXPECTED['files'].get(name, {}).get('bytes')
        need(size.isdecimal() and int(size) == expected and re.fullmatch('[0-9a-f]{40}', oid), 'carrier-precheckout-exact-blob-size')
        found[name] = oid
    need(set(found) == set(EXPECTED['files']) | {'manifest.json'} and not set(found.values()) & FORBIDDEN, 'carrier-tree-only183')
    return found


def tool(name):
    path = Path('/usr/bin')/name; info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and os.access(path, os.X_OK), 'observed-existing-fetch-tool')
    return dict(path=str(path), identity=identity(info), sha256=file_pin(path, 16*1024**2)['sha256'])


def admitted_source(root, env):
    """Independently repeat five-input/source admission before credential access."""
    digest = env.get('SOURCE_MAP_SHA256', '')
    need(re.fullmatch('[0-9a-f]{64}', digest), 'explicit-Root-source-map')
    raw = whole(root/'source-map.json', 2*1024**2)
    need(pin(raw)['sha256'] == digest, 'Root-source-map-pin')
    rows = decode(raw)['files']; name = 'scripts/ci/llhttp-reference-native-source/owner/data.py'
    body = whole(root/name, 2*1024**2)
    need(pin(body) == {k:rows[name][k] for k in ('bytes','sha256')}, 'pinned-source-admission-code')
    spec = importlib.util.spec_from_file_location('carrier_exact_source_admission', root/name)
    data = importlib.util.module_from_spec(spec); spec.loader.exec_module(data)
    data.admission(root, digest, env.get('ROOT_LLHTTP_REFERENCE_ADMISSION_JSON','').encode(),
        env.get('ROOT_LLHTTP_REFERENCE_RUNTIME_JSON','').encode(), env.get('ADMISSION_SHA256',''), env.get('RUNTIME_SHA256',''), env, int(time.time()))


def fetch(root, output, runner=None, environment=None, diagnostic=None):
    """No call path may read the deploy-key environment before all Root pins exist."""
    diagnostic = FetchDiagnostic() if diagnostic is None else diagnostic
    diagnostic.stage = 'binding'
    b = binding()
    diagnostic.stage = 'fetch-paths'
    root, output = ordinary(root), ordinary(output)
    diagnostic.stage = 'ordinary-arm'
    need(sys.flags.isolated and __debug__ and platform.machine() in ('aarch64', 'arm64') and os.getuid() > 0, 'genuine-ordinary-ARM-fetch')
    env = os.environ if environment is None else environment
    diagnostic.stage = 'source-admission'
    admitted_source(root, env)
    diagnostic.stage = 'fetch-output'
    need(not output.exists() and not output.is_relative_to(root) and re.fullmatch('/[A-Za-z0-9_./-]+', str(output)), 'fresh-fetch-output')
    diagnostic.stage = 'disk-budget'
    need(shutil.disk_usage(output.parent).free >= 14*1024**3+2*TOTAL+64*1024**2, 'original-controller-disk-reserve-plus-finite-fetch')
    diagnostic.stage = 'fetch-tools'
    observed = {n: tool(n) for n in ('git', 'ssh', 'ssh-keygen')}
    command_rows = []; deadline = time.monotonic()+180; private_identity = None; secret = None
    diagnostic.stage = 'child-supervisor'
    if runner is None:
        spec = importlib.util.spec_from_file_location('pinned_carrier_owned', root/'held-source/scripts/ci/llhttp-reference-native-source/base/runtime/owned_process.py')
        owned = importlib.util.module_from_spec(spec); spec.loader.exec_module(owned); owned.prepare()
    diagnostic.stage = 'credential-home'
    output.mkdir(mode=0o700); keyhome = output/'credential-home'; keyhome.mkdir(mode=0o700)
    keyhome_identity = key_identity(keyhome.lstat()); private = keyhome/'identity'; known = keyhome/'known_hosts'; store = output/'git'; public = output/'public'
    clean = dict(PATH='/usr/bin:/bin', HOME=str(keyhome), LC_ALL='C', TZ='UTC', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                 GIT_TERMINAL_PROMPT='0', GIT_ASKPASS='/bin/false', SSH_ASKPASS='/bin/false')
    def run(argv, seconds=45):
        need(len(command_rows) < 24 and time.monotonic() < deadline, 'finite-fetch-commands-deadline')
        for n, row in observed.items():
            need(tool(n) == row, 'same-qualified-fetch-tools')
        need(deadline-time.monotonic() > 1, 'finite-fetch-commands-deadline')
        if runner is not None: return runner(argv, clean)
        def limits():
            resource.setrlimit(resource.RLIMIT_AS, (2*1024**3, 2*1024**3)); resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
            resource.setrlimit(resource.RLIMIT_FSIZE, (2*TOTAL+64*1024**2, 2*TOTAL+64*1024**2)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); os.umask(0o022)
        # Metadata parsers consume stdout alone. SSH/Git diagnostic text is not
        # public evidence; status/retirement still fail closed without retaining it.
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=store if store.exists() else output,
                                 env=clean, start_new_session=True, preexec_fn=limits)
        cap = min(seconds, deadline-time.monotonic())
        late = cap <= 1
        # A launch can cross the budget boundary. Transfer even a late child
        # to the supervisor for bounded retirement before returning HOLD.
        row = owned.supervise(child, cap=1.01 if late else cap, retirement=1, grace=.1, max_output=1024**2)
        raw = row.pop('output'); command_rows.append(dict(command=(argv[len(GIT):] if argv[:len(GIT)] == GIT else argv[:3]), retirement=row, output=pin(raw)))
        retired = row['reaped'] and row['ownership'] == 'REAPED' and row['group_census'] == 'EMPTY_TWICE'
        need(not late or retired, 'late-fetch-child-retirement')
        need(not late and time.monotonic() < deadline, 'finite-fetch-commands-deadline')
        need(row['exit'] == 0 and retired and not row['signals'] and not row['timeout']
             and row['error'] is None and row['output_complete'], 'natural-fetch-child-required')
        return raw
    def remove_keyhome():
        if not keyhome.exists(): return
        need(key_identity(keyhome.lstat()) == keyhome_identity and not keyhome.is_symlink(), 'same-credential-home')
        need(set(p.name for p in keyhome.iterdir()) <= {'known_hosts'}, 'only-own-host-pin-in-keyhome')
        if known.exists():
            need(whole(known) == ('github.com '+HOST_REFERENCE['key']+'\n').encode() and stat.S_IMODE(known.stat().st_mode) == 0o600, 'same-own-host-pin')
            known.unlink()
        keyhome.rmdir()
    try:
        diagnostic.stage = 'key-input'
        secret = env.pop(SECRET, None)
        need(type(secret) is str and 64 <= len(secret) <= 32768 and secret.startswith('-----BEGIN OPENSSH PRIVATE KEY-----\n')
             and secret.rstrip().endswith('-----END OPENSSH PRIVATE KEY-----'), 'Root-deploy-key-required')
        # An otherwise valid Actions secret can arrive without its trailing LF.
        secret = secret.rstrip()+'\n'
        need(len(secret) <= 32768, 'Root-deploy-key-required')
        diagnostic.stage = 'key-write'
        fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        private_identity = key_identity(os.fstat(fd))
        with os.fdopen(fd, 'w') as stream:
            stream.write(secret); stream.flush(); os.fsync(stream.fileno())
        secret = None
        diagnostic.stage = 'host-pin-write'
        known.write_text('github.com '+HOST_REFERENCE['key']+'\n'); known.chmod(0o600)
        diagnostic.stage = 'key-derivation'
        public_key = run(['/usr/bin/ssh-keygen', '-y', '-P', '', '-f', str(private)]).decode().strip().split()
        need(len(public_key) >= 2, 'deploy-public-key')
        diagnostic.stage = 'key-fingerprint'
        fingerprint = 'SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(public_key[1], validate=True)).digest()).decode().rstrip('=')
        need(fingerprint == b['deploy_key_fingerprint'], 'exact-Root-deploy-key-fingerprint')
        ssh = ['/usr/bin/ssh', '-F', '/dev/null', '-q', '-i', str(private), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(known), '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'HostKeyAlgorithms=ssh-ed25519',
               '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
               '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', '-o', 'ConnectionAttempts=1', '-o', 'ConnectTimeout=15', '-o', 'VerifyHostKeyDNS=no']
        clean['GIT_SSH_COMMAND'] = shlex.join(ssh)
        diagnostic.stage = 'git-init'
        run(GIT+['init', '-q', str(store)])
        diagnostic.stage = 'git-origin'
        run(GIT+['remote', 'add', 'origin', 'git@github.com:'+REPOSITORY+'.git'])
        diagnostic.stage = 'git-fetch'
        run(GIT+['fetch', '--quiet', '--no-tags', '--depth=1', 'origin', b['commit']], 150)
        diagnostic.stage = 'credential-retirement'
        need(key_identity(private.lstat()) == private_identity, 'same-temporary-key-before-delete'); private.unlink(); private_identity = None
        clean.pop('GIT_SSH_COMMAND'); remove_keyhome(); clean['HOME'] = str(output)
        need(SECRET not in env and not private.exists() and not keyhome.exists(), 'key-and-home-absent-before-checkout-controller')
        diagnostic.stage = 'git-ref'
        run(GIT+['update-ref', 'refs/heads/carrier', b['commit']])
        diagnostic.stage = 'git-object-metadata'
        guard = metadata_guard(run(GIT+['cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype)']), run(GIT+['rev-list', '--objects', '--all']))
        diagnostic.stage = 'git-commit-metadata'
        commit = run(GIT+['cat-file', '-p', b['commit']]); header = commit.split(b'\n\n', 1)[0].splitlines()
        need(header[0] == ('tree '+b['tree']).encode() and not any(n.startswith(b'parent ') for n in header), 'actual-parentless-pinned-tree')
        diagnostic.stage = 'git-tree-metadata'
        tree_metadata(run(GIT+['ls-tree', '-r', '-l', '-z', '--full-tree', b['commit']]))
        diagnostic.stage = 'git-checkout'
        run(GIT+['checkout', '--quiet', '--detach', b['commit']])
        # No private/unlisted tracked file was eligible for checkout.
        diagnostic.stage = 'public-material'
        material_root = output/'material'; material_root.mkdir(mode=0o700)
        (store/'manifest.json').rename(material_root/'manifest.json'); (store/'packages').rename(material_root/'packages')
        material(material_root, b['manifest']); material_root.rename(public)
        # Only this invocation's freshly-created Git store; no external mount or path.
        diagnostic.stage = 'git-retirement'
        need(store.parent == output and not store.is_symlink(), 'same-owned-fetch-store'); shutil.rmtree(store)
        diagnostic.stage = 'fetch-receipt'
        receipt = dict(status='EXACT_PRIVATE_GIT_PUBLIC_INPUTS_FETCHED', repository=REPOSITORY, commit=b['commit'], tree=b['tree'],
                       files=182, bytes=TOTAL, manifest=b['manifest'], object_metadata_guard=guard, private_key_absent=True, private_key_home_absent=True,
                       agent_used=False, credentials_forwarded=False, accepting=False, commands=command_rows)
        (output/'fetch-receipt.json').write_bytes(encode(receipt)); return receipt
    except BaseException as error:
        diagnostic.primary = public_failure(diagnostic.stage, error)
        raise
    finally:
        secret = None
        try:
            env.pop(SECRET, None)
            if private_identity is not None:
                need(private.exists() and key_identity(private.lstat()) == private_identity, 'same-key-final-cleanup'); private.unlink()
            need(not private.exists(), 'private-key-not-retained'); remove_keyhome()
            need(not keyhome.exists(), 'private-key-home-not-retained')
        except BaseException as error:
            diagnostic.cleanup = public_failure('final-credential-cleanup', error)
            raise


if __name__ == '__main__':
    if sys.argv[1:2] == ['--held-package-command']:
        script, namespace = package_command(sys.argv[2])
        sys.argv[:] = [str(script), *sys.argv[3:]]
        raise SystemExit(namespace['main']())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    diagnostic = FetchDiagnostic()
    try:
        result = fetch(args.root, args.output, diagnostic=diagnostic)
        print(json.dumps({k: result[k] for k in ('status', 'files', 'bytes', 'private_key_absent', 'accepting')}))
    except BaseException as error:
        print(json.dumps(diagnostic.hold(error)))
        raise SystemExit(2)
