# SPDX-License-Identifier: MIT
"""Private offline DocBook catalogs inside the existing unprivileged builder only."""
import base64,hashlib,json,math,os,re,stat,subprocess,time,xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote,urlparse
ENC=lambda v:(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
PIN=lambda b:dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
NS='urn:oasis:names:tc:entity:xmlns:xml:catalog'
PROFILE='RUN_OWNED_PRIVATE_DOCBOOK_CATALOG_V1'
ENTRY_BEFORE={'bytes': 2800, 'sha256': 'daf610fe828ea57ccae0ac23479c613d0c8a7e8df0a285501195f0909e337462'}
INPUTS={'docbook-xml': {'archive': {'bytes': 84244, 'sha256': 'bcfe760c01b18cc8725509c3ed6b862df8db42eb3bdf2812a91054edb5b44c7f'}, 'signature': {'bytes': 566, 'sha256': 'a9a7ec7a4e4e4c4467577189a5ede53f115c576361f873d24a673a1183ba9006'}, 'install': {'bytes': 1169, 'sha256': 'efd4a96cad68bba4cc1c783595e4a8b4094341dd6926e34ba19152d47973ef82'}, 'pkginfo': {'bytes': 409, 'sha256': '834109ee87d8699ebded952c5c1518dd50fa1148191bc091a04ef709b77a5f57'}}, 'docbook-xsl': {'archive': {'bytes': 1455900, 'sha256': '08b37365fb00e8db4662b20beb91fa11ce6bf4913729dae9582a3ca30b63856f'}, 'signature': {'bytes': 566, 'sha256': 'bb7667d726460d0fea89694522e3e3a767bf9aafccf33ae9eb6b6a75fc1f2c27'}, 'install': {'bytes': 1072, 'sha256': 'f3ff287da8c1c0d2214c81e2d498f45a771b0e57c758407069b3e88cae878a17'}, 'pkginfo': {'bytes': 438, 'sha256': 'b7925ac0b15450c5ff2cd8751bda6539ef82f3a9e33308a8a1364f78cb7a97e5'}}}
PAYLOAD=json.loads(r'''{
  "etc/xml/docbook-xml": {
    "bytes": 6714,
    "gid": 0,
    "mode": 420,
    "sha256": "b7c1465242f2250a833e736b94bacdbcdcf226837072746b5a8ce43bb75afed2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/calstblx.dtd": {
    "bytes": 8352,
    "gid": 0,
    "mode": 420,
    "sha256": "3eff227b388b7cc5cda3a9cb20d9ec9da690288c5e4cf704925e7620174ef3e6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/dbcentx.mod": {
    "bytes": 6268,
    "gid": 0,
    "mode": 420,
    "sha256": "ada8b7a8d850d80d15f4702b25e2ff3304f5056966c840893a6176c00dab07fc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/dbgenent.mod": {
    "bytes": 1605,
    "gid": 0,
    "mode": 420,
    "sha256": "947b43e0f753e88a62281ac4992ef32ca95eabc5c40e4ed07403a10310a59c45",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/dbhierx.mod": {
    "bytes": 59188,
    "gid": 0,
    "mode": 420,
    "sha256": "0b9dbcd169f976a09a042449736672f768025220bd6258ae5dc9458c6b7f8487",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/dbnotnx.mod": {
    "bytes": 4316,
    "gid": 0,
    "mode": 420,
    "sha256": "94a79ab38e110364e83c80bd61828e00f27e66f821556254d53341c0e6c62775",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/dbpoolx.mod": {
    "bytes": 203338,
    "gid": 0,
    "mode": 420,
    "sha256": "614ad1dbafce05adf5bfe208a5667bcc7a0c31217e95b4fde4e93e6ba87972ef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/docbook.cat": {
    "bytes": 3681,
    "gid": 0,
    "mode": 420,
    "sha256": "c78152b12696a33ed68ebc8491f1b98f9d5c936d068a8d045857301050011b10",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/docbookx.dtd": {
    "bytes": 4658,
    "gid": 0,
    "mode": 420,
    "sha256": "b3a7f55e2785cc74dd26179397b56d83af530b1f883bc99f54652fb03df79ca6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-amsa.ent": {
    "bytes": 3866,
    "gid": 0,
    "mode": 420,
    "sha256": "0e6d3bdd09b5e500068de46cd39312c396297ac452e7bb7d6b496da41c8aa560",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-amsb.ent": {
    "bytes": 2548,
    "gid": 0,
    "mode": 420,
    "sha256": "a2a89e73e98113699b0024be64c662a2c013f908f402847806e8e12bbdf88644",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-amsc.ent": {
    "bytes": 718,
    "gid": 0,
    "mode": 420,
    "sha256": "43720a397420a2ad4d5efe9ba9af7d911d6c121aee1a81e83f2e1a831f56db18",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-amsn.ent": {
    "bytes": 3227,
    "gid": 0,
    "mode": 420,
    "sha256": "9bdbecc40f4e99cd788f518eac7ef23f13db289478453884bd0aad87732540d7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-amso.ent": {
    "bytes": 1313,
    "gid": 0,
    "mode": 420,
    "sha256": "8e2b99e2d8452b7ffb17e28c6b3d7d3a54ba33dafb0b9db34f707071a17d949c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-amsr.ent": {
    "bytes": 3709,
    "gid": 0,
    "mode": 420,
    "sha256": "19fcebf9da7aa02496de944259c054e2a95d4fae8c9fdcaec84ae15aa5405766",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-box.ent": {
    "bytes": 3220,
    "gid": 0,
    "mode": 420,
    "sha256": "b474674256c9148a2737cd38a248ea5fede558e03509bfb7b2c7c129e5797c48",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-cyr1.ent": {
    "bytes": 4311,
    "gid": 0,
    "mode": 420,
    "sha256": "4e52a8f9f0a1fac61c1e2d513b933173e2163144e3659e84f0401f6a2cc21716",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-cyr2.ent": {
    "bytes": 1910,
    "gid": 0,
    "mode": 420,
    "sha256": "f29690919fda98a533fd70bdf8f267ea01779eff41287eb2ea2d574ccac69165",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-dia.ent": {
    "bytes": 834,
    "gid": 0,
    "mode": 420,
    "sha256": "197408c6b31170d357dfea4538404d37367c39dc59dd7d34012bb0dbb01d3078",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-grk1.ent": {
    "bytes": 3002,
    "gid": 0,
    "mode": 420,
    "sha256": "587daa40b879356c2607316fc72fbdb9dbde6396fa38522a57382ec0f879960e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-grk2.ent": {
    "bytes": 1735,
    "gid": 0,
    "mode": 420,
    "sha256": "3aa9791e184341fecb3229d4fd7943688fc2cbbb3bb023afdea176d791de9278",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-grk3.ent": {
    "bytes": 2563,
    "gid": 0,
    "mode": 420,
    "sha256": "6e7794a18e56d00bb9b6ffb86766b7ef7f590283f55d8a26903b695b38167146",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-grk4.ent": {
    "bytes": 2649,
    "gid": 0,
    "mode": 420,
    "sha256": "048897adc21f179f240f6556000109cf383eeac55aea8ed5340eb36b2d6eef15",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-lat1.ent": {
    "bytes": 4554,
    "gid": 0,
    "mode": 420,
    "sha256": "82e8588eae820695977bd1a7158714b3c09ebf9d8228e875fe90fd9f0b8b59c5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-lat2.ent": {
    "bytes": 8759,
    "gid": 0,
    "mode": 420,
    "sha256": "1afcf75a44a52bef0843327edf35f900e738054487656cf60a3f930d7214ba34",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-num.ent": {
    "bytes": 4085,
    "gid": 0,
    "mode": 420,
    "sha256": "3cd12debf4067ce81435970f9c9e8326354bbd901ecaa0cc3daf7a2087b64af5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-pub.ent": {
    "bytes": 4590,
    "gid": 0,
    "mode": 420,
    "sha256": "941de8044ca8224ea3ad89cbc8d0f44301a2650106a683d9e028a7704eace91f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/ent/iso-tech.ent": {
    "bytes": 3002,
    "gid": 0,
    "mode": 420,
    "sha256": "b7fdc6792471446cc619f44debcda84f091d1939939279318d822fbe90c61be2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.1.2/soextblx.dtd": {
    "bytes": 12587,
    "gid": 0,
    "mode": 420,
    "sha256": "68caa8ae83b2b5a7e78ef36c0678f075bf268fed52b875557f44340b3da44330",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/calstblx.dtd": {
    "bytes": 8418,
    "gid": 0,
    "mode": 420,
    "sha256": "f72315fd572e095a2f75dae3e934517d528c66741ef0a003ffa50312cab79581",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/dbcentx.mod": {
    "bytes": 10179,
    "gid": 0,
    "mode": 420,
    "sha256": "8156e5d411bc369cad6f8e8d837f128727a9ac08ffee0dab2a65e7a433871b18",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/dbgenent.mod": {
    "bytes": 1565,
    "gid": 0,
    "mode": 420,
    "sha256": "1f13c10d9518b80c6e48e46b9df8623f70d7896bf8fcc2925ed3325990df5f88",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/dbhierx.mod": {
    "bytes": 59636,
    "gid": 0,
    "mode": 420,
    "sha256": "cfd281c71ba03082882c0bdeed87dd641f7800bbe109042d9306abf0bad058db",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/dbnotnx.mod": {
    "bytes": 4397,
    "gid": 0,
    "mode": 420,
    "sha256": "5b3efde118e74816ccccce86ad6b8b744dd11bcca3af9b1d3cb4e988921b5cb4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/dbpoolx.mod": {
    "bytes": 216346,
    "gid": 0,
    "mode": 420,
    "sha256": "fbf5d613c3e9c8633ec22073636ed5495a0d40cab5a40989e69c29aec0bb8305",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/docbook.cat": {
    "bytes": 3945,
    "gid": 0,
    "mode": 420,
    "sha256": "ecd83c989733d61e397dbfbee0a5428f9243835131a850b4fe5ca54f6a5be34d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/docbookx.dtd": {
    "bytes": 5705,
    "gid": 0,
    "mode": 420,
    "sha256": "e25f062fe27ae290f3c51bbea7d2067d1d4bae24dd28f139f49f600e5a548f6f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-amsa.ent": {
    "bytes": 3866,
    "gid": 0,
    "mode": 420,
    "sha256": "0e6d3bdd09b5e500068de46cd39312c396297ac452e7bb7d6b496da41c8aa560",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-amsb.ent": {
    "bytes": 2548,
    "gid": 0,
    "mode": 420,
    "sha256": "a2a89e73e98113699b0024be64c662a2c013f908f402847806e8e12bbdf88644",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-amsc.ent": {
    "bytes": 718,
    "gid": 0,
    "mode": 420,
    "sha256": "43720a397420a2ad4d5efe9ba9af7d911d6c121aee1a81e83f2e1a831f56db18",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-amsn.ent": {
    "bytes": 3227,
    "gid": 0,
    "mode": 420,
    "sha256": "9bdbecc40f4e99cd788f518eac7ef23f13db289478453884bd0aad87732540d7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-amso.ent": {
    "bytes": 1313,
    "gid": 0,
    "mode": 420,
    "sha256": "8e2b99e2d8452b7ffb17e28c6b3d7d3a54ba33dafb0b9db34f707071a17d949c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-amsr.ent": {
    "bytes": 3709,
    "gid": 0,
    "mode": 420,
    "sha256": "19fcebf9da7aa02496de944259c054e2a95d4fae8c9fdcaec84ae15aa5405766",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-box.ent": {
    "bytes": 3220,
    "gid": 0,
    "mode": 420,
    "sha256": "b474674256c9148a2737cd38a248ea5fede558e03509bfb7b2c7c129e5797c48",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-cyr1.ent": {
    "bytes": 4311,
    "gid": 0,
    "mode": 420,
    "sha256": "4e52a8f9f0a1fac61c1e2d513b933173e2163144e3659e84f0401f6a2cc21716",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-cyr2.ent": {
    "bytes": 1910,
    "gid": 0,
    "mode": 420,
    "sha256": "f29690919fda98a533fd70bdf8f267ea01779eff41287eb2ea2d574ccac69165",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-dia.ent": {
    "bytes": 834,
    "gid": 0,
    "mode": 420,
    "sha256": "197408c6b31170d357dfea4538404d37367c39dc59dd7d34012bb0dbb01d3078",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-grk1.ent": {
    "bytes": 3002,
    "gid": 0,
    "mode": 420,
    "sha256": "587daa40b879356c2607316fc72fbdb9dbde6396fa38522a57382ec0f879960e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-grk2.ent": {
    "bytes": 1735,
    "gid": 0,
    "mode": 420,
    "sha256": "3aa9791e184341fecb3229d4fd7943688fc2cbbb3bb023afdea176d791de9278",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-grk3.ent": {
    "bytes": 2563,
    "gid": 0,
    "mode": 420,
    "sha256": "6e7794a18e56d00bb9b6ffb86766b7ef7f590283f55d8a26903b695b38167146",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-grk4.ent": {
    "bytes": 2649,
    "gid": 0,
    "mode": 420,
    "sha256": "048897adc21f179f240f6556000109cf383eeac55aea8ed5340eb36b2d6eef15",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-lat1.ent": {
    "bytes": 4554,
    "gid": 0,
    "mode": 420,
    "sha256": "82e8588eae820695977bd1a7158714b3c09ebf9d8228e875fe90fd9f0b8b59c5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-lat2.ent": {
    "bytes": 8759,
    "gid": 0,
    "mode": 420,
    "sha256": "1afcf75a44a52bef0843327edf35f900e738054487656cf60a3f930d7214ba34",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-num.ent": {
    "bytes": 4085,
    "gid": 0,
    "mode": 420,
    "sha256": "3cd12debf4067ce81435970f9c9e8326354bbd901ecaa0cc3daf7a2087b64af5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-pub.ent": {
    "bytes": 4590,
    "gid": 0,
    "mode": 420,
    "sha256": "941de8044ca8224ea3ad89cbc8d0f44301a2650106a683d9e028a7704eace91f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/ent/iso-tech.ent": {
    "bytes": 3002,
    "gid": 0,
    "mode": 420,
    "sha256": "b7fdc6792471446cc619f44debcda84f091d1939939279318d822fbe90c61be2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.2/soextblx.dtd": {
    "bytes": 12587,
    "gid": 0,
    "mode": 420,
    "sha256": "68caa8ae83b2b5a7e78ef36c0678f075bf268fed52b875557f44340b3da44330",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/calstblx.dtd": {
    "bytes": 8642,
    "gid": 0,
    "mode": 420,
    "sha256": "8d1c4018df1436719a89c1cf0eefddb0ac9c3c95e984ecda96719c03b100a196",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/dbcentx.mod": {
    "bytes": 10179,
    "gid": 0,
    "mode": 420,
    "sha256": "a75e0e3862d8a0476526489636e35619032e88a75c330cd1d61d2f2700f05681",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/dbgenent.mod": {
    "bytes": 1565,
    "gid": 0,
    "mode": 420,
    "sha256": "86e62a6eaea163dc1caa764b8d45ee78a6ec400c43231f04ca3f4359712baa92",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/dbhierx.mod": {
    "bytes": 59665,
    "gid": 0,
    "mode": 420,
    "sha256": "e53aa3fc2549894f47ee0d4c0a809d0970ec3ab7f32fcf78091d3a6ba54a494a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/dbnotnx.mod": {
    "bytes": 4526,
    "gid": 0,
    "mode": 420,
    "sha256": "96bb35c78f70457af5cf5517839f79d051527f4e02e377747d2364eaa8d7d042",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/dbpoolx.mod": {
    "bytes": 225442,
    "gid": 0,
    "mode": 420,
    "sha256": "ae241d524e33453256cdce627c76458c5cc2d061124f22fa2e5a8bd19c41f646",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/docbook.cat": {
    "bytes": 3945,
    "gid": 0,
    "mode": 420,
    "sha256": "4ff3347f4ca6e25cd976d6e1b3d91fe88778dd08559f11e8fd27bc276567624b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/docbookx.dtd": {
    "bytes": 5703,
    "gid": 0,
    "mode": 420,
    "sha256": "84a1f9ac03ea923f27d4fff15fd436bc9b6ae2838d1c4817c6ee7430aeb0fc98",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-amsa.ent": {
    "bytes": 3866,
    "gid": 0,
    "mode": 420,
    "sha256": "0e6d3bdd09b5e500068de46cd39312c396297ac452e7bb7d6b496da41c8aa560",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-amsb.ent": {
    "bytes": 2548,
    "gid": 0,
    "mode": 420,
    "sha256": "a2a89e73e98113699b0024be64c662a2c013f908f402847806e8e12bbdf88644",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-amsc.ent": {
    "bytes": 718,
    "gid": 0,
    "mode": 420,
    "sha256": "43720a397420a2ad4d5efe9ba9af7d911d6c121aee1a81e83f2e1a831f56db18",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-amsn.ent": {
    "bytes": 3227,
    "gid": 0,
    "mode": 420,
    "sha256": "9bdbecc40f4e99cd788f518eac7ef23f13db289478453884bd0aad87732540d7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-amso.ent": {
    "bytes": 1313,
    "gid": 0,
    "mode": 420,
    "sha256": "8e2b99e2d8452b7ffb17e28c6b3d7d3a54ba33dafb0b9db34f707071a17d949c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-amsr.ent": {
    "bytes": 3709,
    "gid": 0,
    "mode": 420,
    "sha256": "19fcebf9da7aa02496de944259c054e2a95d4fae8c9fdcaec84ae15aa5405766",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-box.ent": {
    "bytes": 3220,
    "gid": 0,
    "mode": 420,
    "sha256": "b474674256c9148a2737cd38a248ea5fede558e03509bfb7b2c7c129e5797c48",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-cyr1.ent": {
    "bytes": 4311,
    "gid": 0,
    "mode": 420,
    "sha256": "4e52a8f9f0a1fac61c1e2d513b933173e2163144e3659e84f0401f6a2cc21716",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-cyr2.ent": {
    "bytes": 1910,
    "gid": 0,
    "mode": 420,
    "sha256": "f29690919fda98a533fd70bdf8f267ea01779eff41287eb2ea2d574ccac69165",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-dia.ent": {
    "bytes": 834,
    "gid": 0,
    "mode": 420,
    "sha256": "197408c6b31170d357dfea4538404d37367c39dc59dd7d34012bb0dbb01d3078",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-grk1.ent": {
    "bytes": 3002,
    "gid": 0,
    "mode": 420,
    "sha256": "587daa40b879356c2607316fc72fbdb9dbde6396fa38522a57382ec0f879960e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-grk2.ent": {
    "bytes": 1735,
    "gid": 0,
    "mode": 420,
    "sha256": "3aa9791e184341fecb3229d4fd7943688fc2cbbb3bb023afdea176d791de9278",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-grk3.ent": {
    "bytes": 2563,
    "gid": 0,
    "mode": 420,
    "sha256": "6e7794a18e56d00bb9b6ffb86766b7ef7f590283f55d8a26903b695b38167146",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-grk4.ent": {
    "bytes": 2649,
    "gid": 0,
    "mode": 420,
    "sha256": "048897adc21f179f240f6556000109cf383eeac55aea8ed5340eb36b2d6eef15",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-lat1.ent": {
    "bytes": 4554,
    "gid": 0,
    "mode": 420,
    "sha256": "82e8588eae820695977bd1a7158714b3c09ebf9d8228e875fe90fd9f0b8b59c5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-lat2.ent": {
    "bytes": 8759,
    "gid": 0,
    "mode": 420,
    "sha256": "1afcf75a44a52bef0843327edf35f900e738054487656cf60a3f930d7214ba34",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-num.ent": {
    "bytes": 4085,
    "gid": 0,
    "mode": 420,
    "sha256": "3cd12debf4067ce81435970f9c9e8326354bbd901ecaa0cc3daf7a2087b64af5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-pub.ent": {
    "bytes": 4590,
    "gid": 0,
    "mode": 420,
    "sha256": "941de8044ca8224ea3ad89cbc8d0f44301a2650106a683d9e028a7704eace91f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/ent/iso-tech.ent": {
    "bytes": 3002,
    "gid": 0,
    "mode": 420,
    "sha256": "b7fdc6792471446cc619f44debcda84f091d1939939279318d822fbe90c61be2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/htmltblx.mod": {
    "bytes": 7514,
    "gid": 0,
    "mode": 420,
    "sha256": "7b79137b290623f72c8cdf77b269901672830cd96759dc7f823de0cf700ccb2c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.3/soextblx.dtd": {
    "bytes": 12819,
    "gid": 0,
    "mode": 420,
    "sha256": "7e29308cc0965ef342505ea099ed765afcaa2f4f4f84243302f53a04e04f5edf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/calstblx.dtd": {
    "bytes": 8642,
    "gid": 0,
    "mode": 420,
    "sha256": "e0baa7c95213501ab01b1640f8876f4cddc212eeb0652b2ee7c3845dd4ccab0b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/dbcentx.mod": {
    "bytes": 10160,
    "gid": 0,
    "mode": 420,
    "sha256": "b267aec0e7e304b94052bdadf749af675de3187371c8d0420646cf2b170f268a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/dbgenent.mod": {
    "bytes": 1565,
    "gid": 0,
    "mode": 420,
    "sha256": "dc442adc09a4cab8a7d88e15b591d32753707c663b501650b4d4d3c35d2c80bd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/dbhierx.mod": {
    "bytes": 59516,
    "gid": 0,
    "mode": 420,
    "sha256": "36f21cd3a63dcf60c65952dc9a070370c60ad8106c072163639b9cdef485ae79",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/dbnotnx.mod": {
    "bytes": 4526,
    "gid": 0,
    "mode": 420,
    "sha256": "97e76498630d0a9535252db143e7c89218625f0909350c65720bb62f8e512c55",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/dbpoolx.mod": {
    "bytes": 228414,
    "gid": 0,
    "mode": 420,
    "sha256": "8cafc5a7d76268c7207a201c035f95c38da477692973c7a207708db32297e36d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/docbook.cat": {
    "bytes": 4010,
    "gid": 0,
    "mode": 420,
    "sha256": "05dad464319c10b2b002b392ebd4004579079fbaad2f9e95265b000b52ef54c4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/docbookx.dtd": {
    "bytes": 5796,
    "gid": 0,
    "mode": 420,
    "sha256": "ec3c8dc9ee9c1c0e830ede3f05b2d8d46b11909dbc10d3d1deeea6f61ab526f3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/README": {
    "bytes": 554,
    "gid": 0,
    "mode": 420,
    "sha256": "2abb0d5858d65a080a36165d00235edf647e095301f31a145ae184cf69e94b37",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isoamsa.ent": {
    "bytes": 5486,
    "gid": 0,
    "mode": 420,
    "sha256": "39d89fb51100e2871d950fdcaad25ba33afe5a46d642b05f6897ca88f9539680",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isoamsb.ent": {
    "bytes": 3981,
    "gid": 0,
    "mode": 420,
    "sha256": "ba39036d9defeb3385da89c277ebe982200a59310a8f4ae2857cae6f896b465c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isoamsc.ent": {
    "bytes": 1919,
    "gid": 0,
    "mode": 420,
    "sha256": "c3375ed0ca6dce766fec04963030c9b41702c5b03f79248a51815f8b6f7f9df5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isoamsn.ent": {
    "bytes": 6268,
    "gid": 0,
    "mode": 420,
    "sha256": "4dfb6c7db68a4ef8972c926fe3aa535aeb40af9a82c8f65a6cf0489569ddad1b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isoamso.ent": {
    "bytes": 2416,
    "gid": 0,
    "mode": 420,
    "sha256": "36f90b16fe5f3a92a241a37c6dea9b30959c49cbaa4c664ffa3cd8700ad9dccc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isoamsr.ent": {
    "bytes": 7024,
    "gid": 0,
    "mode": 420,
    "sha256": "d0dfc0bd33a3bee4261921c259649c6b88f8e881f25e416e8cb6400b68c8b0ce",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isobox.ent": {
    "bytes": 4688,
    "gid": 0,
    "mode": 420,
    "sha256": "5ef1f06c301ac75177483a674d019d1af76417cbe8f4c3ab7aed85b3f1b758f8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isocyr1.ent": {
    "bytes": 6164,
    "gid": 0,
    "mode": 420,
    "sha256": "c348b2218ff0c670e54ecf7f7a3c04b8a492f4e5ed17bc2f9fb88c9c3dae6452",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isocyr2.ent": {
    "bytes": 3239,
    "gid": 0,
    "mode": 420,
    "sha256": "d33314c2d4c87b9ea1277cf216113e3a0e8421b07d25a3992ed2f41a7d71ad83",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isodia.ent": {
    "bytes": 2060,
    "gid": 0,
    "mode": 420,
    "sha256": "0af038be94b0fea755893d845a4ca4da29377cc8b9247cd6663c64058f1e0801",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isogrk1.ent": {
    "bytes": 4773,
    "gid": 0,
    "mode": 420,
    "sha256": "7583c437580362f59d23bf6ae43493371fbe7f8e52bf4cac3099170dad1a6211",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isogrk2.ent": {
    "bytes": 2970,
    "gid": 0,
    "mode": 420,
    "sha256": "5b188ed0b2366e6df2a2609d3ac0edf4072c4516c789d1745c90216cefad220c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isogrk3.ent": {
    "bytes": 4299,
    "gid": 0,
    "mode": 420,
    "sha256": "74384f258fe2b340bdd94089f4de78a3651a5d6efe16ca562dd6483ca0ded476",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isogrk4.ent": {
    "bytes": 4554,
    "gid": 0,
    "mode": 420,
    "sha256": "f4c4f4f284604000d7800178c596b8c510ab1786decc9078c0a8831348061732",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isolat1.ent": {
    "bytes": 6244,
    "gid": 0,
    "mode": 420,
    "sha256": "2b64df2e72d297f43172615fbd225da5ea75ea6271e5f7596fb31754eba5948b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isolat2.ent": {
    "bytes": 11072,
    "gid": 0,
    "mode": 420,
    "sha256": "8196b10e425b18c542a86bc83398a7ee0331f5c58052bfbd1dce3c9a5ba682ff",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isonum.ent": {
    "bytes": 6131,
    "gid": 0,
    "mode": 420,
    "sha256": "43e7b5f80ac3cf992da80d252c63add7a14fb3cebe27bb494c928d2778136611",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isopub.ent": {
    "bytes": 6756,
    "gid": 0,
    "mode": 420,
    "sha256": "e7644fe32c0465d23bfc8a091dc669b0fc77bad6e78adc14830c9c2f4522741c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/ent/isotech.ent": {
    "bytes": 5135,
    "gid": 0,
    "mode": 420,
    "sha256": "69361e13c3482bfbdb71f7f67662d94dbf3da19db1253b765bd1aa0f61bbe25c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/htmltblx.mod": {
    "bytes": 7929,
    "gid": 0,
    "mode": 420,
    "sha256": "c7d6e4d5a7507495826d01dcecf4c6e50a715f2de7f380514f4570eea086ff11",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.4/soextblx.dtd": {
    "bytes": 12829,
    "gid": 0,
    "mode": 420,
    "sha256": "e8d8af21fb93ee3f59eae9f628ebc268421fa4bfcfd76af617359498b48a142d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/calstblx.dtd": {
    "bytes": 9174,
    "gid": 0,
    "mode": 420,
    "sha256": "54c96c2aa55e2a95b4d0f9ac30df90cfdd717fa1c52f6d3547f1cbd3c8ad4b85",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/dbcentx.mod": {
    "bytes": 10155,
    "gid": 0,
    "mode": 420,
    "sha256": "29c6dd8cd6572596c33bee2db8e3918db157c378e32caaf4c6626b4aa4546b49",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/dbgenent.mod": {
    "bytes": 1565,
    "gid": 0,
    "mode": 420,
    "sha256": "2b0eb74552c24f57c64539a76dad22b78f7511cc23168c7506595f998f8a1ff1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/dbhierx.mod": {
    "bytes": 63686,
    "gid": 0,
    "mode": 420,
    "sha256": "0591ef42802588d22c5a3cdc19345262ed689263f187f574f7ecc341dea574ef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/dbnotnx.mod": {
    "bytes": 4521,
    "gid": 0,
    "mode": 420,
    "sha256": "1ced6b81e62743360b907f837535c1731d07a22a95ff2719c1dee64918ae4f20",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/dbpoolx.mod": {
    "bytes": 247056,
    "gid": 0,
    "mode": 420,
    "sha256": "07cfbc12ed12e448e88663c4c93b6e66dc8d31a4d15ddad69f7843318b4e1ae3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/docbook.cat": {
    "bytes": 4010,
    "gid": 0,
    "mode": 420,
    "sha256": "83abde159a039fd9dd3967db815558dc43f12acfae81e969f2696c57558b5247",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/docbookx.dtd": {
    "bytes": 5791,
    "gid": 0,
    "mode": 420,
    "sha256": "e5616d42877c0630779143a6cada440b189538b87d07ad33c72c422af70aef78",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/README": {
    "bytes": 554,
    "gid": 0,
    "mode": 420,
    "sha256": "2abb0d5858d65a080a36165d00235edf647e095301f31a145ae184cf69e94b37",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isoamsa.ent": {
    "bytes": 5486,
    "gid": 0,
    "mode": 420,
    "sha256": "39d89fb51100e2871d950fdcaad25ba33afe5a46d642b05f6897ca88f9539680",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isoamsb.ent": {
    "bytes": 3981,
    "gid": 0,
    "mode": 420,
    "sha256": "ba39036d9defeb3385da89c277ebe982200a59310a8f4ae2857cae6f896b465c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isoamsc.ent": {
    "bytes": 1919,
    "gid": 0,
    "mode": 420,
    "sha256": "c3375ed0ca6dce766fec04963030c9b41702c5b03f79248a51815f8b6f7f9df5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isoamsn.ent": {
    "bytes": 6268,
    "gid": 0,
    "mode": 420,
    "sha256": "4dfb6c7db68a4ef8972c926fe3aa535aeb40af9a82c8f65a6cf0489569ddad1b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isoamso.ent": {
    "bytes": 2416,
    "gid": 0,
    "mode": 420,
    "sha256": "36f90b16fe5f3a92a241a37c6dea9b30959c49cbaa4c664ffa3cd8700ad9dccc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isoamsr.ent": {
    "bytes": 7024,
    "gid": 0,
    "mode": 420,
    "sha256": "d0dfc0bd33a3bee4261921c259649c6b88f8e881f25e416e8cb6400b68c8b0ce",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isobox.ent": {
    "bytes": 4688,
    "gid": 0,
    "mode": 420,
    "sha256": "5ef1f06c301ac75177483a674d019d1af76417cbe8f4c3ab7aed85b3f1b758f8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isocyr1.ent": {
    "bytes": 6164,
    "gid": 0,
    "mode": 420,
    "sha256": "c348b2218ff0c670e54ecf7f7a3c04b8a492f4e5ed17bc2f9fb88c9c3dae6452",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isocyr2.ent": {
    "bytes": 3239,
    "gid": 0,
    "mode": 420,
    "sha256": "d33314c2d4c87b9ea1277cf216113e3a0e8421b07d25a3992ed2f41a7d71ad83",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isodia.ent": {
    "bytes": 2060,
    "gid": 0,
    "mode": 420,
    "sha256": "0af038be94b0fea755893d845a4ca4da29377cc8b9247cd6663c64058f1e0801",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isogrk1.ent": {
    "bytes": 4773,
    "gid": 0,
    "mode": 420,
    "sha256": "7583c437580362f59d23bf6ae43493371fbe7f8e52bf4cac3099170dad1a6211",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isogrk2.ent": {
    "bytes": 2970,
    "gid": 0,
    "mode": 420,
    "sha256": "5b188ed0b2366e6df2a2609d3ac0edf4072c4516c789d1745c90216cefad220c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isogrk3.ent": {
    "bytes": 4299,
    "gid": 0,
    "mode": 420,
    "sha256": "74384f258fe2b340bdd94089f4de78a3651a5d6efe16ca562dd6483ca0ded476",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isogrk4.ent": {
    "bytes": 4554,
    "gid": 0,
    "mode": 420,
    "sha256": "f4c4f4f284604000d7800178c596b8c510ab1786decc9078c0a8831348061732",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isolat1.ent": {
    "bytes": 6244,
    "gid": 0,
    "mode": 420,
    "sha256": "2b64df2e72d297f43172615fbd225da5ea75ea6271e5f7596fb31754eba5948b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isolat2.ent": {
    "bytes": 11072,
    "gid": 0,
    "mode": 420,
    "sha256": "8196b10e425b18c542a86bc83398a7ee0331f5c58052bfbd1dce3c9a5ba682ff",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isonum.ent": {
    "bytes": 6131,
    "gid": 0,
    "mode": 420,
    "sha256": "43e7b5f80ac3cf992da80d252c63add7a14fb3cebe27bb494c928d2778136611",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isopub.ent": {
    "bytes": 6756,
    "gid": 0,
    "mode": 420,
    "sha256": "e7644fe32c0465d23bfc8a091dc669b0fc77bad6e78adc14830c9c2f4522741c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/ent/isotech.ent": {
    "bytes": 5135,
    "gid": 0,
    "mode": 420,
    "sha256": "69361e13c3482bfbdb71f7f67662d94dbf3da19db1253b765bd1aa0f61bbe25c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/htmltblx.mod": {
    "bytes": 8184,
    "gid": 0,
    "mode": 420,
    "sha256": "2ffb78a2c5b26fa60b77588a463840688a5a4381c4e8e2cda25604e45523f0f6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xml-dtd-4.5/soextblx.dtd": {
    "bytes": 13150,
    "gid": 0,
    "mode": 420,
    "sha256": "cb040773b6b30fd7a7cc3d5e666e12decf8f9e6435a951c17ce432d3bfccc92a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets": {
    "gid": 0,
    "mode": 511,
    "target": "xsl-stylesheets-1.79.2",
    "type": "symlink",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/VERSION": {
    "bytes": 4577,
    "gid": 0,
    "mode": 420,
    "sha256": "a29841372eef306516afc52de28e861ce3972f51b0800b863416e352132e0665",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/VERSION.xsl": {
    "bytes": 4569,
    "gid": 0,
    "mode": 420,
    "sha256": "86855687ccab1902d609614604a5cdd1c7c0304f369e22b232d6e310f52e160e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/assembly": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/assembly/assemble.xsl": {
    "bytes": 25707,
    "gid": 0,
    "mode": 420,
    "sha256": "0375d652e7b53da3f667503e0fbd46b0f6ccf2811429e72f7c465308c7557cfb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/assembly/topic-maker-chunk.xsl": {
    "bytes": 6504,
    "gid": 0,
    "mode": 420,
    "sha256": "2587678359a4d794f87964c94845b6e1a76d6230c92f5f1c840709ba8387c69b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/assembly/topic-maker.xsl": {
    "bytes": 2743,
    "gid": 0,
    "mode": 420,
    "sha256": "dc24e6e45be5c166f2634b1892f7e7443648337cfa257f2ee81f362167186224",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/addns.xsl": {
    "bytes": 4895,
    "gid": 0,
    "mode": 420,
    "sha256": "5564946fa72718e46eaed71e3955a239e2f2f49362d3fe7b2acbfc5c275a3794",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/af.xml": {
    "bytes": 47951,
    "gid": 0,
    "mode": 420,
    "sha256": "0f48b714f4b99b9db59051346f61cd9470b2734386cf80ebc1d01dbccfafb973",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/am.xml": {
    "bytes": 48652,
    "gid": 0,
    "mode": 420,
    "sha256": "843123dab908a7776655a76224f529225700d9493460a1538c2d205775abdcf2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/ar.xml": {
    "bytes": 48296,
    "gid": 0,
    "mode": 420,
    "sha256": "70e587d9e250fa4b98bff9da06d416c5d74d50edb005d835fcd49c909318f74f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/as.xml": {
    "bytes": 37581,
    "gid": 0,
    "mode": 420,
    "sha256": "0fd21e915698f86be9feb55b48b46944eadbb2233188c12b0b4f19ecae6d74cc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/ast.xml": {
    "bytes": 33853,
    "gid": 0,
    "mode": 420,
    "sha256": "a4b4de170aa3194e632c078a132bf47e9435616fbd503253d820e932f38ded07",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/autoidx-kimber.xsl": {
    "bytes": 1483,
    "gid": 0,
    "mode": 420,
    "sha256": "b80c7e5a7c1128823e2fb2ab46e20bd1f734a18ba29878f76fe23844107985ef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/autoidx-kosek.xsl": {
    "bytes": 5014,
    "gid": 0,
    "mode": 420,
    "sha256": "bd2c5f4480145aa9f0cd98c86e3d69e6fb7fc52be630760fc0b0b85762166b29",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/az.xml": {
    "bytes": 34324,
    "gid": 0,
    "mode": 420,
    "sha256": "af4b081ed122bebd17ae244bce18e95175ed74262c6a3911151c553595aed23c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/bg.xml": {
    "bytes": 38142,
    "gid": 0,
    "mode": 420,
    "sha256": "d9ad227e003f953ed7623d1fb323ead8ac2533b67b6117a3e83e7e8bd52a9cbe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/bn.xml": {
    "bytes": 51040,
    "gid": 0,
    "mode": 420,
    "sha256": "899776193708c763fbb372cc2118261af8747350e8b8b0864ceba836c67ee24f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/bn_in.xml": {
    "bytes": 38396,
    "gid": 0,
    "mode": 420,
    "sha256": "a37e6b92058cd49331ef4a2421ef8f317ade3798e388b4f53f9cce88d35f2785",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/bs.xml": {
    "bytes": 33637,
    "gid": 0,
    "mode": 420,
    "sha256": "70a22016ff0103bff6209e4b8a392dc3bff54309f8cd2b88d59706fcea1eb078",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/build.xml": {
    "bytes": 935,
    "gid": 0,
    "mode": 420,
    "sha256": "82a7576432836a13359f92e09b107e8231b747631f891ae2e61367d562b3863d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/ca.xml": {
    "bytes": 33663,
    "gid": 0,
    "mode": 420,
    "sha256": "089d289b2fe93594ba80e07ac3ecc49075f1b7cb1043550309407a3fff1d0d49",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/charmap.xml": {
    "bytes": 6625,
    "gid": 0,
    "mode": 420,
    "sha256": "7485c379fcbe10cdcc08d6c69f6230f951f50df15092fde3e2090b09b01c1902",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/charmap.xsl": {
    "bytes": 9345,
    "gid": 0,
    "mode": 420,
    "sha256": "e4a9fc4dc1947846bd978e0a4eb12179513c6434203b22349cd5717ac2789def",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/common.xml": {
    "bytes": 18407,
    "gid": 0,
    "mode": 420,
    "sha256": "ee226de064cad44e4951849a574b6fb23fa6587775ce1e55335a7d8e720480a3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/common.xsl": {
    "bytes": 77768,
    "gid": 0,
    "mode": 420,
    "sha256": "7593e1fe9edfb581ef86939076bd1af424dd0592de6ae0b245e4d885d8c6c46a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/cs.xml": {
    "bytes": 31896,
    "gid": 0,
    "mode": 420,
    "sha256": "542954933db2c2597991d543dc7e48ab46f1f30593ad1af1cdc9c195eac85013",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/cy.xml": {
    "bytes": 47150,
    "gid": 0,
    "mode": 420,
    "sha256": "32fb4b9eb2c8567c67610038c7ded872a9d459cd72c85f6fbd9a6532ad035ab0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/da.xml": {
    "bytes": 33548,
    "gid": 0,
    "mode": 420,
    "sha256": "596edebaea8e13996537da366b0484ba85e97d4d9f9a9d85584b5ca46450b4fd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/de.xml": {
    "bytes": 34188,
    "gid": 0,
    "mode": 420,
    "sha256": "87432c35cfab28cd4c06c08d8d9a3ef8ddb264640fee4fb7dcda21dbdc35f518",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/el.xml": {
    "bytes": 35869,
    "gid": 0,
    "mode": 420,
    "sha256": "9b9a158ef54abcdffcec0d24761f93769d30e431f4fcfb0fc13a57cf8c3ef8e8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/en.xml": {
    "bytes": 45396,
    "gid": 0,
    "mode": 420,
    "sha256": "aafbaa3422e5d78b71d3fc6d668976752043207abfad197aa05920bc055dba12",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/entities.ent": {
    "bytes": 8297,
    "gid": 0,
    "mode": 420,
    "sha256": "e73deaef4bd0ddd3124a90f7a525ac67eaf7c60676cae64f5135eeb983737718",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/eo.xml": {
    "bytes": 46196,
    "gid": 0,
    "mode": 420,
    "sha256": "f4309952470cc75259c0b4293b425f606e735bcaedd4ee39c1cd53d2755edb45",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/es.xml": {
    "bytes": 34486,
    "gid": 0,
    "mode": 420,
    "sha256": "c02b664955f35386bc28a23a48c71794697779fd14d766fe0ab30fd12997cd77",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/et.xml": {
    "bytes": 47122,
    "gid": 0,
    "mode": 420,
    "sha256": "48e853f51e57dc20847cfb883acc9c64e1d2b0acff2c7204aee37b0344bc3090",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/eu.xml": {
    "bytes": 47552,
    "gid": 0,
    "mode": 420,
    "sha256": "1c8db56e9988c6c99c5546d7e82021445875aff3e131f07969d6c4db4e09b198",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/fa.xml": {
    "bytes": 36552,
    "gid": 0,
    "mode": 420,
    "sha256": "97136dde8c381ec22713be04e88a4ff30f1b9124f61d01bf016d09e8de50f554",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/fi.xml": {
    "bytes": 34127,
    "gid": 0,
    "mode": 420,
    "sha256": "4e1d348f481641cafe5f7cf4882671ead9645e9c9cdbbc3381cde12e85015e7d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/fr.xml": {
    "bytes": 34240,
    "gid": 0,
    "mode": 420,
    "sha256": "fe5489a57fdaac07f9815e27939aa155696a9b1ae300f21e61c7034a6aa4faee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/ga.xml": {
    "bytes": 47134,
    "gid": 0,
    "mode": 420,
    "sha256": "5f714c658cbd4e6af01721bab79ce25bc14b2786019c2a9d23e569301c430352",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/gentext.xsl": {
    "bytes": 30947,
    "gid": 0,
    "mode": 420,
    "sha256": "205ddac514f3ee0211188fbf9efef80b221c2edfd31a68a50574f2034a3dd7e5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/gl.xml": {
    "bytes": 47041,
    "gid": 0,
    "mode": 420,
    "sha256": "c7dc73bcff97c09a2991b28cd4923ce23fa2dbfa3b150ff8e351a30997b680ed",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/gu.xml": {
    "bytes": 37586,
    "gid": 0,
    "mode": 420,
    "sha256": "2eee5fb18920a1621eb9bdb61fea2e9d005df122902e7331ef9025cea81942b2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/he.xml": {
    "bytes": 48308,
    "gid": 0,
    "mode": 420,
    "sha256": "3fffde7e254d5f867f078a10a7c75336dfa41d0d0d4cf0e400118f8b277c38cd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/hi.xml": {
    "bytes": 37118,
    "gid": 0,
    "mode": 420,
    "sha256": "e505277ff69878b7e4a4c31e77a6ac5006f17c2d9bbc1b397582b23b92a21d83",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/hr.xml": {
    "bytes": 33741,
    "gid": 0,
    "mode": 420,
    "sha256": "03f58c984c4427f4e1f9a33fb76a09541456dcb847505d5c6b1320ff6c7c18cd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/hu.xml": {
    "bytes": 34186,
    "gid": 0,
    "mode": 420,
    "sha256": "2b1cbd18831e3f2675c92ad7711957bf47ff32d72318a50445e7a03a8e157218",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/id.xml": {
    "bytes": 46626,
    "gid": 0,
    "mode": 420,
    "sha256": "311815983b6a92afbf0c920d68274464ccbdc7b4e71db81e3973afd5855a96d7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/insertfile.xsl": {
    "bytes": 3823,
    "gid": 0,
    "mode": 420,
    "sha256": "4059f535335565c0c5ba0a3bfdebf27cf56a8a428783320e49dd32cc5555e04a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/is.xml": {
    "bytes": 31866,
    "gid": 0,
    "mode": 420,
    "sha256": "9945937e07459a3c28de01fc85db6b8512f478c69d6a2096a69715a6511c87f8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/it.xml": {
    "bytes": 46292,
    "gid": 0,
    "mode": 420,
    "sha256": "73772a328208498e385a45fcdfea7da1148f49400f1d0e89919669ad6f4b8576",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/ja.xml": {
    "bytes": 33426,
    "gid": 0,
    "mode": 420,
    "sha256": "e38f107de73238f5943c3337588824175495a6912f5e026b545b18d5b9424702",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/ka.xml": {
    "bytes": 39234,
    "gid": 0,
    "mode": 420,
    "sha256": "fb12ab0504ef8d6fa040466d76ea0a2c1bf105bbdca579eb6f6dc77ab425c5ef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/kn.xml": {
    "bytes": 51201,
    "gid": 0,
    "mode": 420,
    "sha256": "8845326ecaa1bf21cba8807b407da942d7f13f9911eaf0819b74088773df6c00",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/ko.xml": {
    "bytes": 47141,
    "gid": 0,
    "mode": 420,
    "sha256": "37b3b99d28563fecc2ab1cfdc39b014d29325e42a8f3d40e62a9a8d6769f7bd0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/ky.xml": {
    "bytes": 37492,
    "gid": 0,
    "mode": 420,
    "sha256": "3179c2004d65c2f8d1da5a58a719f94cf9b08969a86a1be0436ce836cd75a11f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/l10n.dtd": {
    "bytes": 1320,
    "gid": 0,
    "mode": 420,
    "sha256": "adfc7e18ad538026f3344dde3e309a386f434bc51e6a71832c8d2b66797ed882",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/l10n.xml": {
    "bytes": 2983,
    "gid": 0,
    "mode": 420,
    "sha256": "265172a990f1a41d488210ac3120b033ff539ff6fa88751843ea9275722f2d91",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/l10n.xsl": {
    "bytes": 20721,
    "gid": 0,
    "mode": 420,
    "sha256": "d5e1448223d516644979725850d11dc9b69fe6257bc6e7697647207c059edf14",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/la.xml": {
    "bytes": 46991,
    "gid": 0,
    "mode": 420,
    "sha256": "bf5d637621e5d59a34b492f981c7b8f604e512e36539830a7bef383478205d27",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/labels.xsl": {
    "bytes": 32633,
    "gid": 0,
    "mode": 420,
    "sha256": "f2a9ddcc462878223139ea22a5721b1e3309a4312b8495c56c898d7cc9a8ef8e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/lt.xml": {
    "bytes": 34893,
    "gid": 0,
    "mode": 420,
    "sha256": "60717f668f4f142380a3f13ef2c97ba2bc3d49368e48e5887841853b8707de34",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/lv.xml": {
    "bytes": 46512,
    "gid": 0,
    "mode": 420,
    "sha256": "5fac413cf63bb6bf9839e2db958a157d8b0f752c72a079d62a60d3b69b5040e9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/ml.xml": {
    "bytes": 38522,
    "gid": 0,
    "mode": 420,
    "sha256": "fcd992008294909ec0e60d18b1c662b989c114e6c2003fb39ae37c8e4c224797",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/mn.xml": {
    "bytes": 37776,
    "gid": 0,
    "mode": 420,
    "sha256": "5b7a50bdecbd1c39417b0db328c2c06b3351c7c4e0313210a73999de5cc0ae49",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/mr.xml": {
    "bytes": 37000,
    "gid": 0,
    "mode": 420,
    "sha256": "0f4cd55d67014bf3736bb01e751231279418e2fdb7398c9e5a255e23ccae054d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/nb.xml": {
    "bytes": 47188,
    "gid": 0,
    "mode": 420,
    "sha256": "c3e37f78f876f1093c276b11bcf4f6915db41d9278de41da7280a24b44b62926",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/nds.xml": {
    "bytes": 33647,
    "gid": 0,
    "mode": 420,
    "sha256": "b46926ea576b75bfbe892515970fc97ebde6748344ff5d229115e7916121ecc1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/nl.xml": {
    "bytes": 34237,
    "gid": 0,
    "mode": 420,
    "sha256": "f978a6aa29efd13fdb606087595e232f6125bd35d2a6e98a07064e7ec9cf1808",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/nn.xml": {
    "bytes": 47072,
    "gid": 0,
    "mode": 420,
    "sha256": "9b7830200c5a6a68ee8ffac97b39af4df9a1855bd9b398e9d294fc872f37d5d1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/olink.xsl": {
    "bytes": 51993,
    "gid": 0,
    "mode": 420,
    "sha256": "cd844e6e7775ae0ca635c4738beb9f6d8278260372f2d183bb83dd2749b3fe80",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/or.xml": {
    "bytes": 51020,
    "gid": 0,
    "mode": 420,
    "sha256": "bb59210f4dc3c84d31343660aab2496d263aa329776345bd5c94bad16c1acf87",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/pa.xml": {
    "bytes": 36324,
    "gid": 0,
    "mode": 420,
    "sha256": "bb759ed5711402ded7ebb06b974dd0559d1079595b156ee9339e11bc14ce124d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/pi.xml": {
    "bytes": 5002,
    "gid": 0,
    "mode": 420,
    "sha256": "bc18888c84afa9f91c104cb3e698420b17da8f415b65a9ce48564d7a7bda9aef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/pi.xsl": {
    "bytes": 13722,
    "gid": 0,
    "mode": 420,
    "sha256": "9f1858bb2c3fbf61f332f15575495ccdf2ffebe043170babbfd93801c656c0c1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/pl.xml": {
    "bytes": 34259,
    "gid": 0,
    "mode": 420,
    "sha256": "cf29cb4b084cc0ed6843d3c3424a7db09ade304b35286b1bb62736543c9faece",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/pt.xml": {
    "bytes": 46887,
    "gid": 0,
    "mode": 420,
    "sha256": "24dcb48691662108143a8eda3af4fd44e439437ee15c60d653cd2b4937dbb735",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/pt_br.xml": {
    "bytes": 46379,
    "gid": 0,
    "mode": 420,
    "sha256": "fac830c06564cc98fab0f8c7e7e9bd4418ee8e8d6489ed0acf8f87472d8fcd38",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/refentry.xml": {
    "bytes": 22185,
    "gid": 0,
    "mode": 420,
    "sha256": "77f5ef4e2691b7040b481021e7f742501a42e7213ab1b1b3f6febc7bafd545ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/refentry.xsl": {
    "bytes": 55928,
    "gid": 0,
    "mode": 420,
    "sha256": "a91ecf2c6df577884a9a524c967e01b66df214e4706674894c31352beb775b2d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/ro.xml": {
    "bytes": 47334,
    "gid": 0,
    "mode": 420,
    "sha256": "6e4c07977f87312c7c911d260a59328c4107d1e01487fd60007857cb7e4aa942",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/ru.xml": {
    "bytes": 38086,
    "gid": 0,
    "mode": 420,
    "sha256": "4bd7d33e8ecae845c691577d4e30b4a2f9562448bc5a69b3c5beb5f7f8b6a0a9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/sk.xml": {
    "bytes": 46955,
    "gid": 0,
    "mode": 420,
    "sha256": "3a0177a23a2ec11ada11cbed6dcaf2a2edc0f4e4d1704f75b824903bf743c013",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/sl.xml": {
    "bytes": 47203,
    "gid": 0,
    "mode": 420,
    "sha256": "0733f65c1e19868adc5bab0babff006b3026a83925e7519896a45425969f79a9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/sq.xml": {
    "bytes": 47093,
    "gid": 0,
    "mode": 420,
    "sha256": "934aa2386bf53bdd317a8cb15c23dc992224ba2a933e6577a7ddd904c645cacf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/sr.xml": {
    "bytes": 37457,
    "gid": 0,
    "mode": 420,
    "sha256": "fc967b207e9f7a7687ad9a84569689bc9aa4f45921e2c70db99e983d4a59cd37",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/sr_Latn.xml": {
    "bytes": 34502,
    "gid": 0,
    "mode": 420,
    "sha256": "970ba576dc1c8a8c3ea5d5884efc0885ef2b1596bac543cb9cc496aaf18e4a73",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/stripns.xsl": {
    "bytes": 13230,
    "gid": 0,
    "mode": 420,
    "sha256": "b5755ca372b73f478aba0b0f78ff3d7e1d68211e529828214b26cb34fdb4266c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/subtitles.xsl": {
    "bytes": 7192,
    "gid": 0,
    "mode": 420,
    "sha256": "4697568b3258b4aa3b3f94e26d6dc0b3a7da0e25558407dde5c26e7a28ce4448",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/sv.xml": {
    "bytes": 34406,
    "gid": 0,
    "mode": 420,
    "sha256": "d41507de6954f4b44778a6a477928dbfa04ca0d5a8807b51a4e24d060cd42e11",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/ta.xml": {
    "bytes": 38858,
    "gid": 0,
    "mode": 420,
    "sha256": "3ae18a6099508903bdd014d8fc36c22ecb846efd8f23ae065f797de3fae5ee30",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/table.xsl": {
    "bytes": 18126,
    "gid": 0,
    "mode": 420,
    "sha256": "34c8b2731b9da5bfc4a9967402894afce82d3df18896d8557eea693eff8d7d28",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/targetdatabase.dtd": {
    "bytes": 1231,
    "gid": 0,
    "mode": 420,
    "sha256": "4daad7fda6dbb9fe02a3e16bad35df8933bf356f7f877abde21e4e768d6121c3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/targets.xsl": {
    "bytes": 10693,
    "gid": 0,
    "mode": 420,
    "sha256": "b0b3317ff3d2f74a892d9e31e2fc8400f233c682e9a5be8800d9bc8bc5f15610",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/te.xml": {
    "bytes": 39169,
    "gid": 0,
    "mode": 420,
    "sha256": "3fefa781b21d2d2e0df963dc6009c103c469e9f147f11c4863080731469e2a89",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/th.xml": {
    "bytes": 50022,
    "gid": 0,
    "mode": 420,
    "sha256": "8f023471d0718e66a48a541b99ecd31590e014cc0d7238ba043bd720ca89d3f1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/titles.xsl": {
    "bytes": 30536,
    "gid": 0,
    "mode": 420,
    "sha256": "069cdd588bc407abb433ede959ea6a8471c8404f08a2acd82cbb95f849a7d967",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/tl.xml": {
    "bytes": 47209,
    "gid": 0,
    "mode": 420,
    "sha256": "9e9801a68c75d8711aa6a3a8877a1b9b47b9d332c727adb4ab0ea6cfc06ecf05",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/tr.xml": {
    "bytes": 34085,
    "gid": 0,
    "mode": 420,
    "sha256": "243c922872d9a287a9679ea76d530b2b016474d7e3b94c5b227d15a0c7d647e4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/uk.xml": {
    "bytes": 37870,
    "gid": 0,
    "mode": 420,
    "sha256": "7374c6ef1bf9771d7e3f4486bd38c00742a925001c445a01a485eb9aa525bca6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/ur.xml": {
    "bytes": 34082,
    "gid": 0,
    "mode": 420,
    "sha256": "19fa2690e6803c8b960568552ae9c358eab10589a60e00b5a95a276e8e20775a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/utility.xml": {
    "bytes": 9695,
    "gid": 0,
    "mode": 420,
    "sha256": "f69eca679a4a1637c5bdd464f06bef1db18cbea6445f3c5ef3890cbeda1a8113",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/utility.xsl": {
    "bytes": 12101,
    "gid": 0,
    "mode": 420,
    "sha256": "607928df84e52deeddced09df410805977862cc1246c327e69046478505ee347",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/vi.xml": {
    "bytes": 47646,
    "gid": 0,
    "mode": 420,
    "sha256": "65bd0e934f7e33d398aa403f63d6786603db5218cfa446647c2fa06fe5ef9f52",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/xh.xml": {
    "bytes": 47994,
    "gid": 0,
    "mode": 420,
    "sha256": "a48dba9f86169766035dae52aecfc50a90283be5baf53c4430ee9d6e5ce08de2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/zh.xml": {
    "bytes": 30414,
    "gid": 0,
    "mode": 420,
    "sha256": "f9b024d15bc34bb2c02196d1897c3d1cbbe5ad38907899f158b666c74d7f5943",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/zh_cn.xml": {
    "bytes": 30434,
    "gid": 0,
    "mode": 420,
    "sha256": "46ba4be5b23379a73bec96d42df5b59eaf4313b820c7923b576d6fd713f2752e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/common/zh_tw.xml": {
    "bytes": 33310,
    "gid": 0,
    "mode": 420,
    "sha256": "1888e905cca19448afc7c3eeb774edb5cb7c3b5bc0220ecab817e71709d0477c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/eclipse": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/eclipse/build.xml": {
    "bytes": 763,
    "gid": 0,
    "mode": 420,
    "sha256": "ef58cd553623d6c2e168c56e22bce75ecaf826a3eeb1f7fa370e16b0726c3948",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/eclipse/eclipse.xsl": {
    "bytes": 12568,
    "gid": 0,
    "mode": 420,
    "sha256": "fb5824e598c795708bba04ab992a6e2ab11c1738e82bdbfdefef7e3c07d4fa99",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/eclipse/eclipse3.xsl": {
    "bytes": 3923,
    "gid": 0,
    "mode": 420,
    "sha256": "b79a2e67fa04bd127a3a63e1651b76d26cd6a790ef0bcf878cc80d4a5544718b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/eclipse/profile-eclipse.xsl": {
    "bytes": 12775,
    "gid": 0,
    "mode": 420,
    "sha256": "37bc1d0e80222ce1b44e3f0b0f47d6b9af1f2f07cb58412c7dee11d01ce8a9f6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub/docbook.xsl": {
    "bytes": 78684,
    "gid": 0,
    "mode": 420,
    "sha256": "a1a6fa6657fad05f23e9497f90a9bd66a8ca85ae39d456f7d56fcdf0bc1081f8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub3": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub3/build.xml": {
    "bytes": 758,
    "gid": 0,
    "mode": 420,
    "sha256": "d50e94d3083c274d292957c6ffca312031d058da5b2b716992ecbd8dd2a3f87e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub3/chunk.xsl": {
    "bytes": 934,
    "gid": 0,
    "mode": 420,
    "sha256": "668ba7cda6c4704d6239b57ff44e95a0f0708d3032299c3e5ceac195214da29b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub3/chunkfast.xsl": {
    "bytes": 2754,
    "gid": 0,
    "mode": 420,
    "sha256": "b25579b473d9585a868565b09c68927687e2aa6315e4242ddddda845756b5d13",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub3/docbook-epub.css.xml": {
    "bytes": 2059,
    "gid": 0,
    "mode": 420,
    "sha256": "bf4addc9ab516ec832c1117bd55c0e9cf8b264200ade9a0b16f8acfb97ab270e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub3/docbook.xsl": {
    "bytes": 445,
    "gid": 0,
    "mode": 420,
    "sha256": "982bcb182157e90c5b8d73da2ecf99d601fe693ba13e5ef2d325ca004f3debd5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub3/epub3-chunk-mods.xsl": {
    "bytes": 1997,
    "gid": 0,
    "mode": 420,
    "sha256": "53ff044bcb4407a4fb1b9339f553077c4f40c78c0fc83868db6bd4645005d36b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub3/epub3-element-mods.xsl": {
    "bytes": 96487,
    "gid": 0,
    "mode": 420,
    "sha256": "226e6342e44dd4f5d4d196e0ee291a4db065975407ec0a03ef0709b6dbc66ae8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub3/profile-chunk.xsl": {
    "bytes": 2455,
    "gid": 0,
    "mode": 420,
    "sha256": "6456281cdb97203f3c47de32fc3834970af0e632f8b0196ecab5da5d2c1d22dc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub3/profile-docbook.xsl": {
    "bytes": 17739,
    "gid": 0,
    "mode": 420,
    "sha256": "ae638160d590f7ff3e1b62aa912733103bfa662a7b56dda1cbaa31d2f6484922",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub3/titlepage.templates.xml": {
    "bytes": 16422,
    "gid": 0,
    "mode": 420,
    "sha256": "ca3dc628baeb710b8d25abd3163d217b58b5fe5a9e0580c07b3362cce5a6766b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/epub3/titlepage.templates.xsl": {
    "bytes": 177035,
    "gid": 0,
    "mode": 420,
    "sha256": "beb4d6c06b7c62350d64520c7edd038af950448728a9f24bf621bb98edff4a59",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/admon.xsl": {
    "bytes": 4567,
    "gid": 0,
    "mode": 420,
    "sha256": "f82affcf380ad3e3d22995bb6384e6b606e3dfb605aa2773f71606c82632a93b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/annotations.xsl": {
    "bytes": 566,
    "gid": 0,
    "mode": 420,
    "sha256": "456aa33de115f345b872c6e3a2c4cf12562ad090b565f709d2a48189f91f048d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/autoidx-kimber.xsl": {
    "bytes": 6266,
    "gid": 0,
    "mode": 420,
    "sha256": "7c0611a9de9d143ae07821a5522b52858c11d81b3de6ba1278686b136194d23c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/autoidx-kosek.xsl": {
    "bytes": 5169,
    "gid": 0,
    "mode": 420,
    "sha256": "fba2e40df0a0a6d04479412523f67d13c930e3ac4b6894c09c45fab7d3f9b335",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/autoidx-ng.xsl": {
    "bytes": 694,
    "gid": 0,
    "mode": 420,
    "sha256": "53e019988467526792439583c14d993b4f3a3a9e783cf729ed63dc09df7430bd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/autoidx.xsl": {
    "bytes": 55972,
    "gid": 0,
    "mode": 420,
    "sha256": "b61d1b5089c294d20721bacfe9d44aa4a3db4a82d0976d3e35822d9a9cc7e2f6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/autotoc.xsl": {
    "bytes": 32036,
    "gid": 0,
    "mode": 420,
    "sha256": "21c7bddd9a6e927dd48249ad7549805470d6ba67357b394c5a968010fe2d339c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/axf.xsl": {
    "bytes": 3951,
    "gid": 0,
    "mode": 420,
    "sha256": "922a78721e990952198f494df722e4ec0e11b874d4598e4a57fea39961f950f3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/biblio-iso690.xsl": {
    "bytes": 56543,
    "gid": 0,
    "mode": 420,
    "sha256": "fb0d5e24f922162f7f2fe339156693936594aa5115343bd6762f400230cfba5f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/biblio.xsl": {
    "bytes": 36214,
    "gid": 0,
    "mode": 420,
    "sha256": "d521b105436c28002293dc8af9ea28ec7e47c89c51dfc2ade5797415cc57ece9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/block.xsl": {
    "bytes": 22858,
    "gid": 0,
    "mode": 420,
    "sha256": "02429862a7dee1dd9a0ebd534e1b9d9877bb712fb3433641d09171702031a145",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/build.xml": {
    "bytes": 1345,
    "gid": 0,
    "mode": 420,
    "sha256": "5eb40820a3f5bd59066af49d15752e2ae4894d5b1d113fa71bb86ac9ea023298",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/callout.xsl": {
    "bytes": 12081,
    "gid": 0,
    "mode": 420,
    "sha256": "4002368a9d919a9b31da833959555752806d8af0852f15ecbbc10b81952bf011",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/component.xsl": {
    "bytes": 35212,
    "gid": 0,
    "mode": 420,
    "sha256": "e5228813fda6af60ee191ea57ab5f173fcc69d5c54152ddd7516492e9a2179ad",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/division.xsl": {
    "bytes": 23167,
    "gid": 0,
    "mode": 420,
    "sha256": "9a02c97929e808a1efc8d13deead4b772830fafbc0c673fb8d00110140946281",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/docbook.xsl": {
    "bytes": 16524,
    "gid": 0,
    "mode": 420,
    "sha256": "ffbf375682e778d6058a3fe32b70b0a65ec81bb830f28094fdd438797ef1bec0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/ebnf.xsl": {
    "bytes": 10574,
    "gid": 0,
    "mode": 420,
    "sha256": "b5db450ffa79a90bb97344b2fa8601a072ebcd4ec43d3d7500746c2d1248679c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/fo-rtf.xsl": {
    "bytes": 5128,
    "gid": 0,
    "mode": 420,
    "sha256": "b127a61f65697acb7fde45c7e4830cc053fa758c9013e27f5a191326ba7244db",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/fo.xsl": {
    "bytes": 4521,
    "gid": 0,
    "mode": 420,
    "sha256": "f37444404b5d86c56930cae5d93de88ff6c96980b29492d792fb5a9c9923487d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/footnote.xsl": {
    "bytes": 8642,
    "gid": 0,
    "mode": 420,
    "sha256": "7dd8a5c388fef5aa3713cfac8b9f0edf4f53e857f2a948d96e5cae4ecb287bdf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/fop.xsl": {
    "bytes": 4186,
    "gid": 0,
    "mode": 420,
    "sha256": "ffb3c7911f39b2ab1e14e149ad9b7ac78dc609496eb0243a91375231d0136c52",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/fop1.xsl": {
    "bytes": 7562,
    "gid": 0,
    "mode": 420,
    "sha256": "e4bcd9509052c90f78b4fdac34ccfbc7fc6de8da283369fe2c693e7d260fb06a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/formal.xsl": {
    "bytes": 22480,
    "gid": 0,
    "mode": 420,
    "sha256": "9fb01347d67010ef9e3f0185284f361fd65846f15b1baaadb94e539e1c2fa27b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/glossary.xsl": {
    "bytes": 44729,
    "gid": 0,
    "mode": 420,
    "sha256": "576c44b68fedf34680f3db7c909555733b34a552a1bb3775eefd6136ef6d1807",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/graphics.xsl": {
    "bytes": 26524,
    "gid": 0,
    "mode": 420,
    "sha256": "d7226da7bb14fc276f12147d62fea711809326c30c82fe5d44171d2b419954fe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/highlight.xsl": {
    "bytes": 2560,
    "gid": 0,
    "mode": 420,
    "sha256": "b89b6e062b328adc8654adb8a70de88dfd7dfb30e920afe17d8a47597c4183e5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/htmltbl.xsl": {
    "bytes": 16212,
    "gid": 0,
    "mode": 420,
    "sha256": "6a7bf9bc5cf4b8670ea9b03d954ddce92fea3d19a9b365497b6d3264828b5ac2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/index.xsl": {
    "bytes": 17651,
    "gid": 0,
    "mode": 420,
    "sha256": "be399ed71f3e5870e6020edae3cae627b16645eb84a2b670d1f53b3361b42b0d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/info.xsl": {
    "bytes": 1189,
    "gid": 0,
    "mode": 420,
    "sha256": "e2b33bed4a40d69639a60f3320d884b395b945306d1123554a2d65b10a475b8c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/inline.xsl": {
    "bytes": 42982,
    "gid": 0,
    "mode": 420,
    "sha256": "001f72865b0ab79ed124c82a1e78d00eca5489fb9cca29414a8c07424290bab9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/keywords.xsl": {
    "bytes": 708,
    "gid": 0,
    "mode": 420,
    "sha256": "464a57d1d3eea048c9f126171427a5859ce3250dba0859191289c50f66503800",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/lists.xsl": {
    "bytes": 48526,
    "gid": 0,
    "mode": 420,
    "sha256": "1991b9f9329175e3cda88a321df2afa869bd82ddab79144806c9ac87733738b9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/math.xsl": {
    "bytes": 2738,
    "gid": 0,
    "mode": 420,
    "sha256": "8156ca65d456c9c348ae30e175c50dfb68ef32624a56d58298082b9f860df21f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/pagesetup.xsl": {
    "bytes": 160788,
    "gid": 0,
    "mode": 420,
    "sha256": "470cd29e616cd66c7c4a0fc0eacfe78d9d1c49366b2a414c411ff5695832036b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/param.xml": {
    "bytes": 497725,
    "gid": 0,
    "mode": 420,
    "sha256": "2365111873537ba52e8387f7bdf9ab20823048f6f378c3bef4d16d355096d864",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/param.xsl": {
    "bytes": 51459,
    "gid": 0,
    "mode": 420,
    "sha256": "c14edb0f20a0353d7c4a57c45c7ed7f91f5ff31e7a7c7fa2cc65b4333d5a0bc5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/passivetex.xsl": {
    "bytes": 1226,
    "gid": 0,
    "mode": 420,
    "sha256": "6167bb0fcf93514e4c97f39fbdf50982eb2bb0e87c70913419302135b9da53a1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/pi.xml": {
    "bytes": 33756,
    "gid": 0,
    "mode": 420,
    "sha256": "4bc7fa05b14712c77cb2e9bc87ea3dec8ccf11a6837045af4dbeba260f600750",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/pi.xsl": {
    "bytes": 42974,
    "gid": 0,
    "mode": 420,
    "sha256": "c129390c605d34fb83a87d2922b5debeec6a15146a3a9538d73c3c22e129d9a2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/profile-docbook.xsl": {
    "bytes": 16134,
    "gid": 0,
    "mode": 420,
    "sha256": "dcc73e7430c8e1662fd3231ed1674efb12f9792c04a9e4b13ba41f53d5d3f0d2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/ptc.xsl": {
    "bytes": 3843,
    "gid": 0,
    "mode": 420,
    "sha256": "a36800fefe16134c34f69be20e794326ffa79ee275f482c4ac8faa23a0ed810e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/publishers.xsl": {
    "bytes": 3687,
    "gid": 0,
    "mode": 420,
    "sha256": "f76c710d58aeb3933901cb12fd28e78d599515e603619a5eef553a66c989a26d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/qandaset.xsl": {
    "bytes": 14273,
    "gid": 0,
    "mode": 420,
    "sha256": "23a1f025d9b81777c69586aef72c7a276d27c172a1fc7f13336a3f2b876ab93e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/refentry.xsl": {
    "bytes": 25278,
    "gid": 0,
    "mode": 420,
    "sha256": "4d895561ecdb7861af2c1fe0a54980703ba45479b7192b9d6ea07527dde3d80a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/sections.xsl": {
    "bytes": 27978,
    "gid": 0,
    "mode": 420,
    "sha256": "8dcea37c99460344a7236c4c9ce7f1f2af25d1f7f6a1b501b4e9e76d45067699",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/spaces.xsl": {
    "bytes": 9767,
    "gid": 0,
    "mode": 420,
    "sha256": "87fafc2964bec1917a5a33d7c35dfb87c26d380d95ecaa001c60e2904a8a8df0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/synop.xsl": {
    "bytes": 31928,
    "gid": 0,
    "mode": 420,
    "sha256": "97efab714e4181254c0f102d0d513bce675e2016226f959b48c5e0aec97d2fbd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/table.xml": {
    "bytes": 2851,
    "gid": 0,
    "mode": 420,
    "sha256": "36757648b1972e80ce2fefe8197c071fffa12ff012f5c75bb30a9020e046fd9d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/table.xsl": {
    "bytes": 61012,
    "gid": 0,
    "mode": 420,
    "sha256": "31a20cd4458d25e3329f0f232e5dbbfea6b7389321e82e41163900d568e3a38d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/task.xsl": {
    "bytes": 2676,
    "gid": 0,
    "mode": 420,
    "sha256": "0fd0c53073f0a95a5ea1b856ad85ff9a3fecbd047daac06aa65c8ed0c58a40e6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/titlepage.templates.xml": {
    "bytes": 43202,
    "gid": 0,
    "mode": 420,
    "sha256": "88a2b63e7daa410191ed61c42989adbe4a9392c66a750aefe1d6ee7706e36af1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/titlepage.templates.xsl": {
    "bytes": 314470,
    "gid": 0,
    "mode": 420,
    "sha256": "b79187b5b115df6156547d92ec6477bf014a61e3b51d52e47c2977026e9c4165",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/titlepage.xsl": {
    "bytes": 28421,
    "gid": 0,
    "mode": 420,
    "sha256": "a9030dbaed7ea98c89e9b1a5a9d5b106cc700cf7214e54857b1a23bbdc494779",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/toc.xsl": {
    "bytes": 11508,
    "gid": 0,
    "mode": 420,
    "sha256": "2403b76c3fa85c4b59b96c6cd9261ea988737481600af393df4c87b7a01dc808",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/verbatim.xsl": {
    "bytes": 18090,
    "gid": 0,
    "mode": 420,
    "sha256": "569758a9d0936ee43efaf03d45d6949fcf9ca9f8091cabd4d1bd8336f88e6702",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/xep.xsl": {
    "bytes": 7232,
    "gid": 0,
    "mode": 420,
    "sha256": "8d65dda8685cfabd517c687497a511356365a91ee90160270e3496ecb3f12081",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/fo/xref.xsl": {
    "bytes": 59196,
    "gid": 0,
    "mode": 420,
    "sha256": "ecfdf626e27421f5ff737f8de949e7aa42cea598992e42d73bd6ec937b414512",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/bourne-hl.xml": {
    "bytes": 2691,
    "gid": 0,
    "mode": 420,
    "sha256": "a7c0b63f6bf539842047a84eb9c96464230a7de9c8f8c5ede43385c5396ea02d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/c-hl.xml": {
    "bytes": 3595,
    "gid": 0,
    "mode": 420,
    "sha256": "60aed026c6a11fa6ffa1d371b2e0d33c7aab9803bfb5d2e3ff964d5dd89cb468",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/cmake-hl.xml": {
    "bytes": 5998,
    "gid": 0,
    "mode": 420,
    "sha256": "be5b5cd967e90b0aa52e3ec1366472c3674b44e7b9fed2772eaa4498aaca3fb6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/common.xsl": {
    "bytes": 4014,
    "gid": 0,
    "mode": 420,
    "sha256": "d06ae790aee6ede9c9dc914f3e3dd75945c3cf08b398e0c2c1d996903bbaf7a4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/cpp-hl.xml": {
    "bytes": 4539,
    "gid": 0,
    "mode": 420,
    "sha256": "1f18f6e80a0981883e66f1314d8da3f64dc726266acb0bc1ffc3ecc8a65fb43c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/csharp-hl.xml": {
    "bytes": 5702,
    "gid": 0,
    "mode": 420,
    "sha256": "417af260d4126bf388eb2fc8a3302f67a40d7873fb6bc781a32f51fb39da0acb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/css21-hl.xml": {
    "bytes": 6637,
    "gid": 0,
    "mode": 420,
    "sha256": "8e597363f8723873e0f3002db5eb65495c2907cc909de3ac0505e627283fd820",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/delphi-hl.xml": {
    "bytes": 8948,
    "gid": 0,
    "mode": 420,
    "sha256": "e3d83b96b3622cb7ea48ef443bafc4b2742cad964b45fe61cacf6cb1cc601bf2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/ini-hl.xml": {
    "bytes": 1662,
    "gid": 0,
    "mode": 420,
    "sha256": "b485127b70950ecbf714fe9231700e9f74d0c3096afe311ff51d8bebe776ac7f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/java-hl.xml": {
    "bytes": 3553,
    "gid": 0,
    "mode": 420,
    "sha256": "cb269d3fe5234adb5f2eee1833fa5d6eeb81924487eca032a6bb0d66dd262a61",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/javascript-hl.xml": {
    "bytes": 4529,
    "gid": 0,
    "mode": 420,
    "sha256": "5dc3bee14f80800a2c727ddb4823c4337c52c305fe6f82b5d93f080b482614f3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/lua-hl.xml": {
    "bytes": 3897,
    "gid": 0,
    "mode": 420,
    "sha256": "c7102514756cfb7552ba67ff22c26d43742239a2331ef3f09b2950f913d5b31d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/m2-hl.xml": {
    "bytes": 2795,
    "gid": 0,
    "mode": 420,
    "sha256": "58914242f3b91f5f199744e11a883a514892adae648f8c6fa535eed1c51ea33e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/myxml-hl.xml": {
    "bytes": 3161,
    "gid": 0,
    "mode": 420,
    "sha256": "a837eefaa2c3ab1d301df52c2a10c9dacaad3879f6a6adef763a644d3312e06e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/perl-hl.xml": {
    "bytes": 3676,
    "gid": 0,
    "mode": 420,
    "sha256": "7068e1744af6995720c9a4d82da92e8a313ea76c541d52191588129f821dcf80",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/php-hl.xml": {
    "bytes": 4687,
    "gid": 0,
    "mode": 420,
    "sha256": "61cbbdae563613467e64ec3d18239e36e2e3adc21e8e77fb0c075619b5e91be8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/python-hl.xml": {
    "bytes": 3023,
    "gid": 0,
    "mode": 420,
    "sha256": "13647a808273a4a4172b5a3030b3529ee5b1309990d997d869385e76c5f0e0fe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/ruby-hl.xml": {
    "bytes": 3247,
    "gid": 0,
    "mode": 420,
    "sha256": "a2e0d217886e7da909a2725ba393c52d2554959e7d32f57696a5580d91c0abbe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/sql1999-hl.xml": {
    "bytes": 14719,
    "gid": 0,
    "mode": 420,
    "sha256": "8b94ad27a9402726c48fb8a85619fea3c70baf8a63187716f9bedc9fb7a4ecf6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/sql2003-hl.xml": {
    "bytes": 16882,
    "gid": 0,
    "mode": 420,
    "sha256": "e40f16b054d47ade708be9a9440c773ef118c715e3899b0835ef0f5c3ac646d9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/sql92-hl.xml": {
    "bytes": 9960,
    "gid": 0,
    "mode": 420,
    "sha256": "a6f798d03c0be17d5796f3577efaca0b2851159d0e7944e75d8f73b1e565b193",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/tcl-hl.xml": {
    "bytes": 5173,
    "gid": 0,
    "mode": 420,
    "sha256": "d7120452655592be473be6695fdbfb9019d9b0f3d01ec7a23326881ce4e07c8f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/upc-hl.xml": {
    "bytes": 4211,
    "gid": 0,
    "mode": 420,
    "sha256": "2326c31c608d4323ef52968974d1e07a4b3f95950504d81c99b9c303ff7bdfa5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/highlighting/xslthl-config.xml": {
    "bytes": 2494,
    "gid": 0,
    "mode": 420,
    "sha256": "5df66ed6c36bc308b4a71b08bbd37ffecac0e2568321766a933ca501148309e5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/admon.xsl": {
    "bytes": 4681,
    "gid": 0,
    "mode": 420,
    "sha256": "759f4fb2ea8515146f18fbc3e1b800a00e029d3968b75cf4ab87dc6b1f930a2a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/annotations.xsl": {
    "bytes": 5659,
    "gid": 0,
    "mode": 420,
    "sha256": "ac96bf7faf85fda51fe0b28bc33cf7309e5d2c6bac2aed5ac67a835547bea224",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/autoidx-kimber.xsl": {
    "bytes": 5965,
    "gid": 0,
    "mode": 420,
    "sha256": "a78315943f99dcfe9c298f72f83fb26796ef5a34c808720bef8073b6265957ff",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/autoidx-kosek.xsl": {
    "bytes": 4419,
    "gid": 0,
    "mode": 420,
    "sha256": "df1497727323a52c2a00c5f857ba37e15dde26bd6edc0897543e38a702d84550",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/autoidx-ng.xsl": {
    "bytes": 682,
    "gid": 0,
    "mode": 420,
    "sha256": "29305c1813db20ef4e2099749aead2ddc6f44a732cad4f3cc800701170c7a2f6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/autoidx.xsl": {
    "bytes": 34642,
    "gid": 0,
    "mode": 420,
    "sha256": "b40932e59b247e35b105b24c7d834600382007c628d3d38e9f67258f3d606bd0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/autotoc.xsl": {
    "bytes": 28447,
    "gid": 0,
    "mode": 420,
    "sha256": "9a49bb694b2a6a2dc8665f204c6a1b96e70815687e2e0e745de43c31c75686d6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/biblio-iso690.xsl": {
    "bytes": 56401,
    "gid": 0,
    "mode": 420,
    "sha256": "0e7264818695f67fb39274797edfc8bdd234ddf29fc404819d28f4257f3ecf3c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/biblio.xsl": {
    "bytes": 44935,
    "gid": 0,
    "mode": 420,
    "sha256": "c3523da70ce56afa89c45243a7eec89d1fca4d9a460a74d4a740b4f8c146fe41",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/block.xsl": {
    "bytes": 16866,
    "gid": 0,
    "mode": 420,
    "sha256": "fa69a43ca3fb6750f00a86282d1809ecc9a1d95c4cdaacd86ef0b7e2e7f90d11",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/build.xml": {
    "bytes": 1355,
    "gid": 0,
    "mode": 420,
    "sha256": "2440a685e78216ae76ce3d15175fd3c292bad284c615e3d3956c05d46ca37194",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/callout.xsl": {
    "bytes": 7931,
    "gid": 0,
    "mode": 420,
    "sha256": "80b5886daeae3122bb12605bdabfb1fad45c4108d88de4a2a611137130accfa5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/changebars.xsl": {
    "bytes": 3961,
    "gid": 0,
    "mode": 420,
    "sha256": "56bc933ca0acc950794b6bfcc08d57b1a94f35f68d4582f3a9641f424992b22f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/chunk-changebars.xsl": {
    "bytes": 3801,
    "gid": 0,
    "mode": 420,
    "sha256": "0ae0c36be6bf125fb732841eb75935e1b22bd1e7028407d0cd60c60e4b742040",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/chunk-code.xsl": {
    "bytes": 25191,
    "gid": 0,
    "mode": 420,
    "sha256": "4d54a0e7660e2f90d9209e5c1ae1f21425b6fc3fccb3ae258935bc39a07b7d0e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/chunk-common.xsl": {
    "bytes": 85182,
    "gid": 0,
    "mode": 420,
    "sha256": "2352defb99c5505812a3745d96ead263d9568a2cbd2e197e2ad04a296769b73a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/chunk.xsl": {
    "bytes": 2245,
    "gid": 0,
    "mode": 420,
    "sha256": "07d1a09bedf522ffedb4ab386833499692767bfe2dfdf91416065440b2c319da",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/chunker.xsl": {
    "bytes": 21472,
    "gid": 0,
    "mode": 420,
    "sha256": "203ed44bcde57af2e921101d257abf77507b76c567420471476ea0b2b87df285",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/chunkfast.xsl": {
    "bytes": 2667,
    "gid": 0,
    "mode": 420,
    "sha256": "f176034f426aac4027e87f45f3a434b97789d867d2333c3108761fa874f9beb2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/chunktoc.xsl": {
    "bytes": 18976,
    "gid": 0,
    "mode": 420,
    "sha256": "6eaf19f2e0017a8ab50e0cc7a4bf54c65d8cc736aba924d017c12deda2aa9775",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/component.xsl": {
    "bytes": 16951,
    "gid": 0,
    "mode": 420,
    "sha256": "c7e141d92cc78ba316975434fe7f6cbe8c9f90beaf7a0ebfa54d37f873a68c3a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/division.xsl": {
    "bytes": 6992,
    "gid": 0,
    "mode": 420,
    "sha256": "a598fff4ae40ffd8f8a78fb3c66c8bdbe59fbb2b0463dcd67d65c6c3fb2c7acd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/docbook.css.xml": {
    "bytes": 1623,
    "gid": 0,
    "mode": 420,
    "sha256": "653067889f6a4a8f427cd4fb72176776da4124e76aa79b448b2b8fecaa065497",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/docbook.xsl": {
    "bytes": 20259,
    "gid": 0,
    "mode": 420,
    "sha256": "c8c3474bbd9ca3fb11a848d333298ff849cb81fd4e62b767dcfa547d0d86445f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/ebnf.xsl": {
    "bytes": 10245,
    "gid": 0,
    "mode": 420,
    "sha256": "b159f8647e3c819e51c2a42c4dcc0fdc966f67855010ea25b6cebee6736caf80",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/footnote.xsl": {
    "bytes": 12361,
    "gid": 0,
    "mode": 420,
    "sha256": "e97d12380153c594bba7250c44d515772e66dde758097b42684e2ec68aa265d8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/formal.xsl": {
    "bytes": 16403,
    "gid": 0,
    "mode": 420,
    "sha256": "e1df1cfd18ea0f4cb3a755c30ff09ff4b4e3278c1ed6554a2bbd7f35f7e17e00",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/glossary.xsl": {
    "bytes": 18327,
    "gid": 0,
    "mode": 420,
    "sha256": "77b35d54140156bda621f849e04358a803e68865c481f42084d1cfe3b154a467",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/graphics.xsl": {
    "bytes": 60247,
    "gid": 0,
    "mode": 420,
    "sha256": "751538438caf8e8bbe3b3ef49a11b8081bd44f7711ffca7d78fd177937b171f4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/highlight.xsl": {
    "bytes": 2979,
    "gid": 0,
    "mode": 420,
    "sha256": "ef294b764e31a5a150d7f027a76859db6203a31f860edd9820d0889a9d765cf0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/html-rtf.xsl": {
    "bytes": 11370,
    "gid": 0,
    "mode": 420,
    "sha256": "e8437f7b7898ccddfabfeb38f7be4490c7fd3c286290028dab2fd52cd4e537a0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/html.xsl": {
    "bytes": 24017,
    "gid": 0,
    "mode": 420,
    "sha256": "54b7717cda3f1bd9026bdd6c30e03cca41b6dd2df9a6913c9d33d5868b90ccf3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/htmltbl.xsl": {
    "bytes": 4500,
    "gid": 0,
    "mode": 420,
    "sha256": "b6136e2030de801bdee89593526191fa354e8f831a1608d893b058f51a19d018",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/index.xsl": {
    "bytes": 10162,
    "gid": 0,
    "mode": 420,
    "sha256": "810e29b67ba22ac05545af0da41952edf06c0930f69f06e307fe7589e3ef46d3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/info.xsl": {
    "bytes": 1518,
    "gid": 0,
    "mode": 420,
    "sha256": "e578989d94344f85920977402a3e65e81d2e8e244b843d68843d371281635a37",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/inline.xsl": {
    "bytes": 50440,
    "gid": 0,
    "mode": 420,
    "sha256": "8acba49f2ae6bf3ca10b0261a96dea523bfa2ad3067d429acb0271d9cbd98206",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/its.xsl": {
    "bytes": 4476,
    "gid": 0,
    "mode": 420,
    "sha256": "4016e9f11ce2b3a27387c2d3ab825bfca7bc3e0a490b5346884e18bc9514e951",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/keywords.xsl": {
    "bytes": 1100,
    "gid": 0,
    "mode": 420,
    "sha256": "6626880d78d5b817864315a0890003d3a5c521b53f3e935511f27766538c6c0e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/lists.xsl": {
    "bytes": 41894,
    "gid": 0,
    "mode": 420,
    "sha256": "b3d660e42e0b80737151d77b868cc95ffc0266b590532f2e9f9347a7eeadd5ab",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/maketoc.xsl": {
    "bytes": 2619,
    "gid": 0,
    "mode": 420,
    "sha256": "362034904d41bab891423a5a74da079f1f80726fbe5f2c918eafbab4632cd36e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/manifest.xsl": {
    "bytes": 875,
    "gid": 0,
    "mode": 420,
    "sha256": "42a97bbf7598e6ed9ded0e18544c313650264b8281795d50e61894f144907584",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/math.xsl": {
    "bytes": 9045,
    "gid": 0,
    "mode": 420,
    "sha256": "03d3454be409aeaba4c3fb65bb990dc8aabfd5498833530f3e37b2ee7c73d6dc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/oldchunker.xsl": {
    "bytes": 7393,
    "gid": 0,
    "mode": 420,
    "sha256": "be40dfcf6f9f240dc26b1a91e0b60338bfecdd8b7e4e62e5cc4c603d6edfed2a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/onechunk.xsl": {
    "bytes": 1327,
    "gid": 0,
    "mode": 420,
    "sha256": "bcfaf9d448e88adf853a0d3bef2eb95ab145aee38dd352f19c9b5b3f83950864",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/param.xml": {
    "bytes": 401480,
    "gid": 0,
    "mode": 420,
    "sha256": "56d6f67c32e68170ddc396ad354c3fcce71cde62f57bfcf86b76088e561f2058",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/param.xsl": {
    "bytes": 20389,
    "gid": 0,
    "mode": 420,
    "sha256": "02d291720f4265c17f82d4f6fa5911819559338c72fb39fd6c36d45a85c26d21",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/pi.xml": {
    "bytes": 39440,
    "gid": 0,
    "mode": 420,
    "sha256": "5ca494b4c7d90bfee46b456c1b6e653b0c3453241b4dd7eb29ed6b9c9266200f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/pi.xsl": {
    "bytes": 48956,
    "gid": 0,
    "mode": 420,
    "sha256": "34b04ae24ea924c7b5606db3ede1f61bad45a53351383d17d8a7086af71a61dc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/profile-chunk-code.xsl": {
    "bytes": 25708,
    "gid": 0,
    "mode": 420,
    "sha256": "1a3fb73e405be1e2e88139c8a4ad2dddcc185514cb237bb02bb4365b4aaab70a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/profile-chunk.xsl": {
    "bytes": 2252,
    "gid": 0,
    "mode": 420,
    "sha256": "9d5609963f9181167312765e3b05c9b07d69357144e98a3530726138d24a7f5b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/profile-docbook.xsl": {
    "bytes": 20356,
    "gid": 0,
    "mode": 420,
    "sha256": "a9ec16c313cf154dc81452922696181479f8246cc0f4560df630a50ccb7e385b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/profile-onechunk.xsl": {
    "bytes": 1335,
    "gid": 0,
    "mode": 420,
    "sha256": "0b8038fcf1263435037e1fefcca33f08dde9973c8c7046712fe6e7fc4266544f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/publishers.xsl": {
    "bytes": 3302,
    "gid": 0,
    "mode": 420,
    "sha256": "71942d534459bf0f2b75bf3a7f6e3b826f91eaadd1e53fe1616668d1f000e30f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/qandaset.xsl": {
    "bytes": 15513,
    "gid": 0,
    "mode": 420,
    "sha256": "177aab699f6bcf9f6e2dff00876fc53687967e3130c0508f0ba30b524ff57bc9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/refentry.xsl": {
    "bytes": 9787,
    "gid": 0,
    "mode": 420,
    "sha256": "b021c9146af8044c8f3d977b5d16d5fae9d586a9c25a78292b01d1e4530afb26",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/sections.xsl": {
    "bytes": 23223,
    "gid": 0,
    "mode": 420,
    "sha256": "84d3f612e3f512ec2f06f7c63b0149e0dd2e478f0277edb156b1fbe003daad85",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/synop.xsl": {
    "bytes": 51693,
    "gid": 0,
    "mode": 420,
    "sha256": "f3a996b1b47276fd94ac8b079fcf44a1d326643b21263376c6d77b8c94b8b089",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/table.xsl": {
    "bytes": 43802,
    "gid": 0,
    "mode": 420,
    "sha256": "d396dc4f08219983e474e45a5cb371cc2b15dddf6df383bd5e36c69ae658d2d8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/task.xsl": {
    "bytes": 2312,
    "gid": 0,
    "mode": 420,
    "sha256": "acd4508de3360aacd1ad948eb07009626bf7197b0a6b21ed54f91de85c277dc2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/titlepage.templates.xml": {
    "bytes": 19289,
    "gid": 0,
    "mode": 420,
    "sha256": "f811acac4681bcaf66b9c30a8b5c970a0e72d037646371bda8d687578a366c04",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/titlepage.templates.xsl": {
    "bytes": 196434,
    "gid": 0,
    "mode": 420,
    "sha256": "9873feae22c90004c18312681e7ffdd0b87d06ec9cb17aadd39f3b1023da37a0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/titlepage.xsl": {
    "bytes": 38275,
    "gid": 0,
    "mode": 420,
    "sha256": "08e1c284907493e858497bb1486dd4b8cc6175a426e89e9b222d364817d0a28a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/toc.xsl": {
    "bytes": 12577,
    "gid": 0,
    "mode": 420,
    "sha256": "661c231274ae6f10bcd1ce322c028c0109981717ae331726d87edb166bc06d6b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/verbatim.xsl": {
    "bytes": 14066,
    "gid": 0,
    "mode": 420,
    "sha256": "320705101a25ecc2e4cb9914fcc67803eacd8ef6799ae3a91b9cb9af1bb31e0e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/html/xref.xsl": {
    "bytes": 47476,
    "gid": 0,
    "mode": 420,
    "sha256": "327a67cd0bcd6df4c7ab8a677f539f7bd3b7d76d550bc6f4a597569fc78eacf5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/htmlhelp": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/htmlhelp/build.xml": {
    "bytes": 791,
    "gid": 0,
    "mode": 420,
    "sha256": "8ca27118357b22e4b86f0bd323460759b4cabe72bbce85fa4375c9767c90eacc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/htmlhelp/htmlhelp-common.xsl": {
    "bytes": 39242,
    "gid": 0,
    "mode": 420,
    "sha256": "6db5055df9b585b5b9396831342c42ee0da4bb1ec8f04e2251a2ea55f47e8ead",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/htmlhelp/htmlhelp.xsl": {
    "bytes": 794,
    "gid": 0,
    "mode": 420,
    "sha256": "11f81e5511e1f6163beadc491d3e2296e059387cc0e0fbb76cd8d077709cccf1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/htmlhelp/profile-htmlhelp-common.xsl": {
    "bytes": 40064,
    "gid": 0,
    "mode": 420,
    "sha256": "0f47acc9c3c087e3c1ae6d80426a325b117228ca3271ca635b7771cd4f6be395",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/htmlhelp/profile-htmlhelp.xsl": {
    "bytes": 802,
    "gid": 0,
    "mode": 420,
    "sha256": "b733b6c007147461708b27211327d5c88809d1ec3752aedf7a888b86778c5b41",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/javahelp": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/javahelp/build.xml": {
    "bytes": 768,
    "gid": 0,
    "mode": 420,
    "sha256": "8222ac2522cc59c811502f9582a447213aa1cbc178189746caf3dcb36e7e9c14",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/javahelp/javahelp.xsl": {
    "bytes": 21525,
    "gid": 0,
    "mode": 420,
    "sha256": "80128424faf108595bb77795e9696b42d170cebcdae2b41d8f172e7108a92666",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/javahelp/profile-javahelp.xsl": {
    "bytes": 21546,
    "gid": 0,
    "mode": 420,
    "sha256": "21864b86ed48b49f1241e854d02590770df537a17f46897ad2f4e95004bf6fe4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/lib": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/lib/build.xml": {
    "bytes": 633,
    "gid": 0,
    "mode": 420,
    "sha256": "f196e8a11686406461a6b2e9b76c5b57d156f795105f1633c14de05cbf9eb967",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/lib/lib.xsl": {
    "bytes": 20863,
    "gid": 0,
    "mode": 420,
    "sha256": "7f3770de157446446e079644824ba99c8fab1db6beee85b46a824c7025adc502",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/block.xsl": {
    "bytes": 15978,
    "gid": 0,
    "mode": 420,
    "sha256": "b0ce6e0a1d04c80ef25df83a2a976b8a8bf6611c4fdc9ae310510d4d684da598",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/build.xml": {
    "bytes": 1352,
    "gid": 0,
    "mode": 420,
    "sha256": "f05f271d64b2f99938b7fbec7e88d38ba5894039cfecf10a7140f4e4a21f6f41",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/charmap.groff.xsl": {
    "bytes": 153719,
    "gid": 0,
    "mode": 420,
    "sha256": "48bbe73bc5c966f00b81f26c2213e448f8a36f574ba7a80c5fd592670c11b033",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/docbook.xsl": {
    "bytes": 15182,
    "gid": 0,
    "mode": 420,
    "sha256": "6fe069de0511e027399c716fcf0549ab1569e2cd64a2ccae359a75063f4cd0bb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/endnotes.xsl": {
    "bytes": 26434,
    "gid": 0,
    "mode": 420,
    "sha256": "ad7329639a6e2627050aac0100f1a439ccf2ba1f16922c44137436b266f03370",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/html-synop.xsl": {
    "bytes": 52033,
    "gid": 0,
    "mode": 420,
    "sha256": "070bd2a6524c2a36024acf77c617e33e2b1736d82dbbe359d808b15c326f646c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/info.xsl": {
    "bytes": 35179,
    "gid": 0,
    "mode": 420,
    "sha256": "5f12da5476c3a9d11f8cb3e6383facbb000b5a05130d7afef2d1e313d883bbbb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/inline.xsl": {
    "bytes": 7184,
    "gid": 0,
    "mode": 420,
    "sha256": "62fb0fbba68f5ac1b423ad7b856ffc88ec29a653a208efee8867cc4c16ec70b1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/lists.xsl": {
    "bytes": 23570,
    "gid": 0,
    "mode": 420,
    "sha256": "a7cfa466007f521cff70c76239627b52209c155bdd42ae1c7f49f7e33b827a78",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/other.xsl": {
    "bytes": 34529,
    "gid": 0,
    "mode": 420,
    "sha256": "bb7692474a4b404faf8f5c704d353fb0a13b96e523df29116434749b23976c3b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/param.xml": {
    "bytes": 131220,
    "gid": 0,
    "mode": 420,
    "sha256": "e496fc692e7e6e214a70938bf4eb325a28241cd94357c3074db352a0e1e385fa",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/param.xsl": {
    "bytes": 8932,
    "gid": 0,
    "mode": 420,
    "sha256": "1534e3a82f86ad6a771e4b4ceb1ed0f9fe661af8ffeb6c02bb843a5125f87e60",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/pi.xml": {
    "bytes": 2171,
    "gid": 0,
    "mode": 420,
    "sha256": "05cce675ed4a1b7e2a49f2cc4625ca7dd5f8077584aee8a17cc948769bd8bcff",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/pi.xsl": {
    "bytes": 3000,
    "gid": 0,
    "mode": 420,
    "sha256": "f54c4dd8792e368aae92fbf5597e93609468e7a4d45eb469bab2aa45d334204b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/profile-docbook.xsl": {
    "bytes": 15097,
    "gid": 0,
    "mode": 420,
    "sha256": "bf77d5bf58bd07bba221d9f0b85c9d631b22c8e100beeddb1e87931efca91252",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/refentry.xsl": {
    "bytes": 12232,
    "gid": 0,
    "mode": 420,
    "sha256": "aa6294a40f38c7e967c7629b8840bbf81a1b86c567da72fac7d871086e69807d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/synop.xsl": {
    "bytes": 16434,
    "gid": 0,
    "mode": 420,
    "sha256": "0d8cef3f43fe75dbac16bd667355305bb499cbb928e6213a114c403a566c67b0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/table.xsl": {
    "bytes": 5764,
    "gid": 0,
    "mode": 420,
    "sha256": "f003a5283800613f41f75104f00259b9b64db3da69a4a1113c04674c94a0e5e5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/tbl.xsl": {
    "bytes": 24014,
    "gid": 0,
    "mode": 420,
    "sha256": "ef3c8f03872ab1de592da5b01de56a0c7304c11f8e73c0845d969a2d27d3377d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/manpages/utility.xsl": {
    "bytes": 23192,
    "gid": 0,
    "mode": 420,
    "sha256": "e7e0e71ed08c368534e689bc05daadff23b0fa20d73a59604d020b8f1b9a7ff8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/abstract.notitle.enabled.xml": {
    "bytes": 986,
    "gid": 0,
    "mode": 420,
    "sha256": "6c45fba7cb57f176b5dae05afc5d50782937eca440e26c75221a93282abfa667",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/abstract.properties.xml": {
    "bytes": 1122,
    "gid": 0,
    "mode": 420,
    "sha256": "6637954bc4785a96dd87d2e7aa0e478433a5ade3917b1bd8129cb8a744ecd0f7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/abstract.title.properties.xml": {
    "bytes": 1778,
    "gid": 0,
    "mode": 420,
    "sha256": "d7e074b563e4e8882c0d8aeaf8918ceb3ca9520d32ca8267ef949c67eaf44529",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/activate.external.olinks.xml": {
    "bytes": 2906,
    "gid": 0,
    "mode": 420,
    "sha256": "a971d114a800903f0a98c834f32b8254747e7df62c10f1df5ce0108d2a2603a3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/active.toc.xml": {
    "bytes": 958,
    "gid": 0,
    "mode": 420,
    "sha256": "ee860ee1d00847be488bb64b746868794f817a52792ddca29fac6a9979c1f0ed",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/ade.extensions.xml": {
    "bytes": 1280,
    "gid": 0,
    "mode": 420,
    "sha256": "caaf6e3e0b865203fe5391f9892f60530f5ea675b57c1d78db94aff9c0fa6b0d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/admon.graphics.extension.xml": {
    "bytes": 1460,
    "gid": 0,
    "mode": 420,
    "sha256": "985984b305e2c0bc3d75e032937e62d4c8aba222b8543a83e57e57ed27f329a9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/admon.graphics.path.xml": {
    "bytes": 1043,
    "gid": 0,
    "mode": 420,
    "sha256": "fbbc759260f66fe9e4a60f3afde3fea06250a0fe56ff02b050fd1b4cba8c1b76",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/admon.graphics.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "a24947619e1e9831574712d940fa47f6e861709e9c7da24477121c09052712f0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/admon.style.xml": {
    "bytes": 1087,
    "gid": 0,
    "mode": 420,
    "sha256": "2b26688b8c3d42c4ad137f7d82928b3005dad9c754b32138b39f013151bd47b8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/admon.textlabel.xml": {
    "bytes": 1074,
    "gid": 0,
    "mode": 420,
    "sha256": "93a29a3af103f129d2f07990e9db87d1415ed688abf0b1491ee620b19883e825",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/admonition.properties.xml": {
    "bytes": 964,
    "gid": 0,
    "mode": 420,
    "sha256": "398b8564f82f2614026efeede55eb9a42e29cdae955efd3a175b4411e313de35",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/admonition.title.properties.xml": {
    "bytes": 1271,
    "gid": 0,
    "mode": 420,
    "sha256": "f6940a3a972c99fa34d755fd91e3f733e192d591851b76a56fbc181fa0262245",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/alignment.xml": {
    "bytes": 1559,
    "gid": 0,
    "mode": 420,
    "sha256": "b0ec9d1769d4dd4aba3ab79593972e1326e8008798d39fcff8857283efca836d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/annotate.toc.xml": {
    "bytes": 952,
    "gid": 0,
    "mode": 420,
    "sha256": "1305d44e4fc51ac38483dbd8d5a8a2b281c46af67b2ef9a7d9f2cf6d94d08e70",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/annotation.css.xml": {
    "bytes": 2190,
    "gid": 0,
    "mode": 420,
    "sha256": "9a8ad6d923a6f74d26c9354becfdf37d31f52598d6bcd43d352edc2ff08fd589",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/annotation.graphic.close.xml": {
    "bytes": 1259,
    "gid": 0,
    "mode": 420,
    "sha256": "431c3ad5858668c40231589e264af2e635714ae95e2dac55776516f42b90e336",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/annotation.graphic.open.xml": {
    "bytes": 1103,
    "gid": 0,
    "mode": 420,
    "sha256": "d98f0284f53fc1ed24fb4ac570a9f693d58787db62c12c3b49d334a128a5212a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/annotation.js.xml": {
    "bytes": 1215,
    "gid": 0,
    "mode": 420,
    "sha256": "a0ec839b6847e40d209bb4ef4d6ba996362f4bab120edca21ed03ea2bd9006a5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/annotation.support.xml": {
    "bytes": 979,
    "gid": 0,
    "mode": 420,
    "sha256": "adee7d2bb7771766e91c59cd059209d92722e465c7fd7ae6664f781c5758884f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/appendix.autolabel.xml": {
    "bytes": 2421,
    "gid": 0,
    "mode": 420,
    "sha256": "589eb103d741402ee76a4e75413d400375adda6e96f7f420e3ca69e4b210cc6f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/arbortext.extensions.xml": {
    "bytes": 1029,
    "gid": 0,
    "mode": 420,
    "sha256": "a021af7e7c49f2c338f12e715d4e2f853f4f53327dadb73b11d089fb43bf6a85",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/article.appendix.title.properties.xml": {
    "bytes": 1194,
    "gid": 0,
    "mode": 420,
    "sha256": "a5f104833e80b226c2c73151a34c6e91bfb4476386bc351e614ee3bcd369825c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/author.othername.in.middle.xml": {
    "bytes": 1080,
    "gid": 0,
    "mode": 420,
    "sha256": "b2dfd9fbddc8c041ff3243770174620c3c4716e2993f7ac4d2ca84474933b848",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/autolayout-file.xml": {
    "bytes": 1123,
    "gid": 0,
    "mode": 420,
    "sha256": "dd9ce81c0a201360eefed7a9daa5dd2dd64dc91912a9e8fbe7ab86a17e0bdbaf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/autolink.index.see.xml": {
    "bytes": 2196,
    "gid": 0,
    "mode": 420,
    "sha256": "299611f9f1a2a73e4a1106ee8dda6ae68d9a74d69dff952309df6a96465fd6f0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/autotoc.label.in.hyperlink.xml": {
    "bytes": 1150,
    "gid": 0,
    "mode": 420,
    "sha256": "3c31ac4e8c6f292fdd7768b8b3b2e9b143297a1149186cbb79e38f7e31b43441",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/autotoc.label.separator.xml": {
    "bytes": 944,
    "gid": 0,
    "mode": 420,
    "sha256": "605c26d80174c8bf32450adfcdefd9f7a6630dd954308b8c79a09ea8a21502ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/axf.extensions.xml": {
    "bytes": 1114,
    "gid": 0,
    "mode": 420,
    "sha256": "7a28d8ac66543a242f64890404d706d649224b6b43fd4f8f0c20455052b7dc41",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/banner.before.navigation.xml": {
    "bytes": 869,
    "gid": 0,
    "mode": 420,
    "sha256": "798c6e0488e78404973e9173910a687540bab8f285680d11ca33f75e5d7de860",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/base.dir.xml": {
    "bytes": 1295,
    "gid": 0,
    "mode": 420,
    "sha256": "a38d7032fd0de8b9e8cb94a72663ab5975a4cd54c3bb8ead7192339aca2cfca8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/biblioentry.item.separator.xml": {
    "bytes": 921,
    "gid": 0,
    "mode": 420,
    "sha256": "b91715aaf83e2b9229d2f12d558415b8a67127746b64d5d29c5110803e5753b3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/biblioentry.properties.xml": {
    "bytes": 1184,
    "gid": 0,
    "mode": 420,
    "sha256": "a7b2077a33ff4c5158cb6ab15f88754a226181f335a8f89ccd6636d0a4a784e6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/bibliography.collection.xml": {
    "bytes": 4873,
    "gid": 0,
    "mode": 420,
    "sha256": "2931519ed3f01d35b3c7acd5fa66be225a3daf0a0bca6c8715d6b59a96ab1bf4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/bibliography.numbered.xml": {
    "bytes": 911,
    "gid": 0,
    "mode": 420,
    "sha256": "a340c62b234faeaee7011e435cfca4ccbb7021aad1dd4d77e89240d8da503e3d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/bibliography.style.xml": {
    "bytes": 1329,
    "gid": 0,
    "mode": 420,
    "sha256": "db087ce0d7062bc69952a05ed931a7566396bfc5b291140da78ca79249759bc5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/blockquote.properties.xml": {
    "bytes": 1345,
    "gid": 0,
    "mode": 420,
    "sha256": "d9f6c4fbbbd234bc476183ebdda29ac7bcb9828e6c24ba486fa51010f09f9d0d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/blurb.on.titlepage.enabled.xml": {
    "bytes": 1190,
    "gid": 0,
    "mode": 420,
    "sha256": "07eefccf7c826d8decb85ae62e9b2795ae09854e92e4b9ec9f60731943faad46",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/body.attributes.xml": {
    "bytes": 1099,
    "gid": 0,
    "mode": 420,
    "sha256": "e9eff2b4883758862b1b5ccbbe8fc4f05a46ab5a62302a904466eac325e5e6ff",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/body.bg.color.xml": {
    "bytes": 891,
    "gid": 0,
    "mode": 420,
    "sha256": "5e78efc7d4505f63d57951859a336551904a546f55a1f7564e12494012fdef83",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/body.end.indent.xml": {
    "bytes": 1234,
    "gid": 0,
    "mode": 420,
    "sha256": "2fd2206f1e7db86d4bc0e25982b12ac3a769c261b2791802c544201a9dc73666",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/body.font.family.xml": {
    "bytes": 1391,
    "gid": 0,
    "mode": 420,
    "sha256": "29c71b7af5b965a6bf04d67831ad14925492a8033943d4e7b5d0ea87a1cdf0d6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/body.font.master.xml": {
    "bytes": 1036,
    "gid": 0,
    "mode": 420,
    "sha256": "b9aaaf7c331d9eab50a41789a65cac92942b5452cb583a048012cbb4defa777d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/body.font.size.xml": {
    "bytes": 1088,
    "gid": 0,
    "mode": 420,
    "sha256": "a0ea8067714e9566c585fcb0cfd3bc5839d93dc2bc5bc21e25e440d07ce8d10f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/body.margin.bottom.xml": {
    "bytes": 963,
    "gid": 0,
    "mode": 420,
    "sha256": "2d93ecae471a7047050ffc5cc5b95c7145ff51a2b7870eebc60537aea6e3c023",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/body.margin.inner.xml": {
    "bytes": 1772,
    "gid": 0,
    "mode": 420,
    "sha256": "f78427a53ec8fbb1cb5851fbbb140a67f5af427c117a86d1bdede9120d21b286",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/body.margin.outer.xml": {
    "bytes": 1783,
    "gid": 0,
    "mode": 420,
    "sha256": "4ed6bc3c368f49c3313d2d267916317da36ff1dd4e7bffe58e7dcd6ad6053437",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/body.margin.top.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "b18ea1c788a98c5ebda4cef7a5a2f54b8a675d49d547bc7dfd896269e0e7c1df",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/body.start.indent.xml": {
    "bytes": 2232,
    "gid": 0,
    "mode": 420,
    "sha256": "648a60a9ee85ade9fa07c38ca90a8629e833d7b8d5f25b6edbbad8c931f57ff8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/bookmarks.collapse.xml": {
    "bytes": 1088,
    "gid": 0,
    "mode": 420,
    "sha256": "17f9f9eba3a2332e4e4e64cdbb06896b72a54434439e2e1e6af500ba3c41aea3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/bridgehead.in.toc.xml": {
    "bytes": 1004,
    "gid": 0,
    "mode": 420,
    "sha256": "7808de9b4c36f737a88e309454101d3655597393323cafcf87d42e4411baa7b0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/bullet.image.xml": {
    "bytes": 880,
    "gid": 0,
    "mode": 420,
    "sha256": "38c20596790ecc579705df81e41bd8c60912f019bfd5d4e60b34e77a43f312cd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/callout.defaultcolumn.xml": {
    "bytes": 1047,
    "gid": 0,
    "mode": 420,
    "sha256": "aa13e63315e57c028949e118f0f763b2cf15a296243e834a0943952992d82216",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/callout.graphics.extension.xml": {
    "bytes": 1448,
    "gid": 0,
    "mode": 420,
    "sha256": "12dc463b0f54b1cdb258334f1df74094d6bf3caae9d4d0ea10d37c4ad8913e3c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/callout.graphics.number.limit.xml": {
    "bytes": 1356,
    "gid": 0,
    "mode": 420,
    "sha256": "752af987a3e523d667aa08f906fa786a3208ed1cce1de839bf2d4aa202bfdbea",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/callout.graphics.path.xml": {
    "bytes": 1116,
    "gid": 0,
    "mode": 420,
    "sha256": "cb90fe1a8e945119b64dae6a0f8a698bfd580f97366dae670a07d76278b8c688",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/callout.graphics.xml": {
    "bytes": 993,
    "gid": 0,
    "mode": 420,
    "sha256": "000e761b0bdaf092ef845bb91a352cd432ee257163851d4c251db448c7e6748a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/callout.icon.size.xml": {
    "bytes": 923,
    "gid": 0,
    "mode": 420,
    "sha256": "f6993201c3af85c8461426c311c099894d2a0f70632f4e51e96b60b544dffb41",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/callout.list.table.xml": {
    "bytes": 1211,
    "gid": 0,
    "mode": 420,
    "sha256": "85c350f206f60a4995621208b8b82c271deeb0f7a58f3366b62d010e1886bcad",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/callout.properties.xml": {
    "bytes": 1042,
    "gid": 0,
    "mode": 420,
    "sha256": "6888f0baa6974fe6bb45c4d0a4b6faf15cefc222c3fe795e20f33457f6ee2748",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/callout.unicode.font.xml": {
    "bytes": 979,
    "gid": 0,
    "mode": 420,
    "sha256": "c42f8351d10822915b5f47b194fa7f09569092c6e9c56c936ce3b483c35d756a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/callout.unicode.number.limit.xml": {
    "bytes": 1240,
    "gid": 0,
    "mode": 420,
    "sha256": "67947c05dcb97251e2ffee842b26a6e4f5a13dab54c0a68902bc51f578f438f4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/callout.unicode.start.character.xml": {
    "bytes": 1307,
    "gid": 0,
    "mode": 420,
    "sha256": "d344f97cf7f8005d999828af3a92aac15e25f1aaf597cdd9e86f48346d825636",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/callout.unicode.xml": {
    "bytes": 1055,
    "gid": 0,
    "mode": 420,
    "sha256": "b8571cfb9419e98cc3f2efa4306a6c4110a137a31e8a79e025836522decde04e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/calloutlist.properties.xml": {
    "bytes": 1552,
    "gid": 0,
    "mode": 420,
    "sha256": "cdb2e5395494b50c3a63f1ab700d44867e9a5e9460e6f09799727f5a66f4ab56",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/callouts.extension.xml": {
    "bytes": 1049,
    "gid": 0,
    "mode": 420,
    "sha256": "8e64033b198e3d2ee5b8b597b5933e007f87a932851725aa1284dc69034e6a40",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chapter.autolabel.xml": {
    "bytes": 2407,
    "gid": 0,
    "mode": 420,
    "sha256": "4e5e5197a7baa85df15b2ab86932f8c90c24e4a1896f84e44c263f1af46bde43",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunk.append.xml": {
    "bytes": 1168,
    "gid": 0,
    "mode": 420,
    "sha256": "df422c553c0f3b79de144e93378df06be39685217a1b8ba45743ae8769ae88a7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunk.first.sections.xml": {
    "bytes": 1045,
    "gid": 0,
    "mode": 420,
    "sha256": "ae9e559e8d55c8c98f48481ca6352353ab87b86128d915bc0919cf36c24bac05",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunk.quietly.xml": {
    "bytes": 979,
    "gid": 0,
    "mode": 420,
    "sha256": "06917c5451d4dc22fb383d50cd59ce141a4243294dbb0e9693a26993e0303286",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunk.section.depth.xml": {
    "bytes": 903,
    "gid": 0,
    "mode": 420,
    "sha256": "166275d3a2b540cf5d80d58c4d3b92be7ed81a4feeca17ba25f660dadd8e8239",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunk.sections.xml": {
    "bytes": 960,
    "gid": 0,
    "mode": 420,
    "sha256": "1271cb8f19f8d7c04937271a2037db928de5f4eb2ffa4067ae96816ba4c75a09",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunk.separate.lots.xml": {
    "bytes": 1165,
    "gid": 0,
    "mode": 420,
    "sha256": "05558ad26fcbe549241744b5e2bde92b94eef27267cfff794ca6587738f55689",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunk.toc.xml": {
    "bytes": 1017,
    "gid": 0,
    "mode": 420,
    "sha256": "8c2b119b31c6ab582ef93f9f3788f149fdb59a56ba428bbaec05f9640de5b43c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunk.tocs.and.lots.has.title.xml": {
    "bytes": 986,
    "gid": 0,
    "mode": 420,
    "sha256": "3e6fc6f5bb824d6bccef73a5b92a37e86ffc283c6b63547fb2cd915b0d4ff5bd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunk.tocs.and.lots.xml": {
    "bytes": 1166,
    "gid": 0,
    "mode": 420,
    "sha256": "bb2d48ce207a4e56215cc40e9703155b1e80738dbf1171bafe4eba8b632540af",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunked.filename.prefix.xml": {
    "bytes": 1597,
    "gid": 0,
    "mode": 420,
    "sha256": "b64b14228d5e4133e36fcd77df1655e65e2695f657a760d0a115ea52e7c98c2f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunker.output.cdata-section-elements.xml": {
    "bytes": 1273,
    "gid": 0,
    "mode": 420,
    "sha256": "0685bf4e553d287c15bdd74edf569c35256dd8dc97988c149b1402c473b250ed",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunker.output.doctype-public.xml": {
    "bytes": 1279,
    "gid": 0,
    "mode": 420,
    "sha256": "54dd8b9b95b3f4a8b980ea4b6d729031d265b955d28e177f06b9c03f3f19a68a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunker.output.doctype-system.xml": {
    "bytes": 1278,
    "gid": 0,
    "mode": 420,
    "sha256": "2f3ce5515bead08015d327ba391060bd70614aea8b8c4325470723f824d51a21",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunker.output.encoding.xml": {
    "bytes": 1261,
    "gid": 0,
    "mode": 420,
    "sha256": "30f2682207ef4b0df2c5419e0712a15960b5dcf9948151accbd0b3bd825f7ccb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunker.output.indent.xml": {
    "bytes": 1164,
    "gid": 0,
    "mode": 420,
    "sha256": "de01f6b82723db2b995bd31ce510d27f55c699404330989b923662281e726e9e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunker.output.media-type.xml": {
    "bytes": 1519,
    "gid": 0,
    "mode": 420,
    "sha256": "fe5c24f9a9cf30f6c034f5950e40177a4cbda17610920bea773cd175de91a53a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunker.output.method.xml": {
    "bytes": 1312,
    "gid": 0,
    "mode": 420,
    "sha256": "d7eebd9fddfe4283b129fa18c55783e5cc758bd2b6c9dc41f1924fe16a4a6561",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunker.output.omit-xml-declaration.xml": {
    "bytes": 1241,
    "gid": 0,
    "mode": 420,
    "sha256": "aa1b32f8d79f6d286aa99cbe6c248856b03603f2db926fca00e1967c0eccd7c5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/chunker.output.standalone.xml": {
    "bytes": 1256,
    "gid": 0,
    "mode": 420,
    "sha256": "81fe7675fc2ed75785d3969134ecdc162c7db64dcbc0a867fb58b99701afd7f7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/citerefentry.link.xml": {
    "bytes": 1039,
    "gid": 0,
    "mode": 420,
    "sha256": "e0f55229bebe71a2b94cdfb33060a28347ca69ee7480fb42bec2f2edfa464e1f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/collect.xref.targets.xml": {
    "bytes": 1754,
    "gid": 0,
    "mode": 420,
    "sha256": "575d396d6995c2f4c9cfe493c76847df2d468a49d2a379139521bd00fa1c1abf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/column.count.back.xml": {
    "bytes": 906,
    "gid": 0,
    "mode": 420,
    "sha256": "7de90bb993782ca9ff21e0d45dbea4df31425525353b3fc4fc1523a2700068fb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/column.count.body.xml": {
    "bytes": 865,
    "gid": 0,
    "mode": 420,
    "sha256": "2b6bade1a464494d124d02557f1ed3cd5419665744862117271f1d224f5e9a33",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/column.count.front.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "da1309cf6acddb85d3cda67eea0284ccc20487a85fddaaaba062064e19c52d59",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/column.count.index.xml": {
    "bytes": 873,
    "gid": 0,
    "mode": 420,
    "sha256": "1d7295b88c7d37f8c59c7002281f8f3a5060852b2fadacb826b7066bbefe2284",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/column.count.lot.xml": {
    "bytes": 933,
    "gid": 0,
    "mode": 420,
    "sha256": "993de6599504d183c0801caf86ba59d1d9b570f9737d4e08cbfec8bda66ab1f5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/column.count.titlepage.xml": {
    "bytes": 893,
    "gid": 0,
    "mode": 420,
    "sha256": "c3b4d092156fc9faf15c74cdeee18df6b3a56e4a79a764a0bb9397a3e43ca5ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/column.gap.back.xml": {
    "bytes": 944,
    "gid": 0,
    "mode": 420,
    "sha256": "dc1a854522613dffadfe7b1a81881a436ba49d3a05c075a12bf68e01b258f143",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/column.gap.body.xml": {
    "bytes": 941,
    "gid": 0,
    "mode": 420,
    "sha256": "abbf9ebf5f0d007384143e6820ddb3be0754a6f512c424fd8c29be39b53da3d3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/column.gap.front.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "e1973a32a2a0b16dda8a813c1d1096ac0e91224fbe25d16667ee93e8b76f8c6e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/column.gap.index.xml": {
    "bytes": 944,
    "gid": 0,
    "mode": 420,
    "sha256": "e3e96442aa3ae62bf94679c38ec8c647b272c1aec7f0df8d4e22281367fc021c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/column.gap.lot.xml": {
    "bytes": 961,
    "gid": 0,
    "mode": 420,
    "sha256": "22dd1ef2654262014d359f4d5463a973054e564472d30d23ea7fee7a46f58de6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/column.gap.titlepage.xml": {
    "bytes": 975,
    "gid": 0,
    "mode": 420,
    "sha256": "93b81684fa5434e54783d6664ac0d4c44ec09e7f458993d95a213c09d995e1bf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/compact.list.item.spacing.xml": {
    "bytes": 1266,
    "gid": 0,
    "mode": 420,
    "sha256": "c49d10ccada76693da2aeadadfff385359732ff5ef4f01bc662150564c892ff3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/component.label.includes.part.label.xml": {
    "bytes": 1607,
    "gid": 0,
    "mode": 420,
    "sha256": "94122f4fa60f0c0a794c1f48ba7739bfbbba944fb2465b1c37bcd00bad358907",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/component.title.properties.xml": {
    "bytes": 1890,
    "gid": 0,
    "mode": 420,
    "sha256": "626e9b34c4e837eac7524f40525770cbd5c5c8606937a51211bc48599c7bf2de",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/component.titlepage.properties.xml": {
    "bytes": 1233,
    "gid": 0,
    "mode": 420,
    "sha256": "5337e7b6d0cc7311007f3fe9570a3b03af596b8c68153e4bdcdfa1bce6effe58",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/contrib.inline.enabled.xml": {
    "bytes": 984,
    "gid": 0,
    "mode": 420,
    "sha256": "cbed3b95a88011e277636d1f4507edf5fe894c782935e7e28269e1ce0bfbdc3c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/crop.mark.bleed.xml": {
    "bytes": 946,
    "gid": 0,
    "mode": 420,
    "sha256": "f5907f5e0a5ba15fa9a0878143f71ef4962f0a3a20eea324a526b0cac31b2b01",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/crop.mark.offset.xml": {
    "bytes": 916,
    "gid": 0,
    "mode": 420,
    "sha256": "2c70df725a10bdc5d9d0ed1ba3f271ee93a1167030f3720ec78ba8825cab61b9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/crop.mark.width.xml": {
    "bytes": 910,
    "gid": 0,
    "mode": 420,
    "sha256": "128da320ecdbc95c3033bae005a4fab4dbc3132ccfe7fff171d4156af9eaa886",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/crop.marks.xml": {
    "bytes": 926,
    "gid": 0,
    "mode": 420,
    "sha256": "b0aea0cf41b3b65f77a68c9b063c7f5c77e0b8f083fc9ab00428f9a658bf7e7f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/css.decoration.xml": {
    "bytes": 1127,
    "gid": 0,
    "mode": 420,
    "sha256": "9e30eb260b5898a3d3c31f00496e006fedd64af29f23e42b5f8cd926b3a99100",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/css.stylesheet.dir.xml": {
    "bytes": 1136,
    "gid": 0,
    "mode": 420,
    "sha256": "045323cff6bd1afd75cd8fdb8c7f65569370fcbf6dcbbbc0e24f4c6d5754c45b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/css.stylesheet.xml": {
    "bytes": 998,
    "gid": 0,
    "mode": 420,
    "sha256": "a4db7ffac669e9ac65caf2376e6a84da54736423f581c6df937b6f90158eee18",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/current.docid.xml": {
    "bytes": 1744,
    "gid": 0,
    "mode": 420,
    "sha256": "47466d3066418122e25eeba2c9512b02494b86f1ce563c4aa969f18ef0a06087",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/currentpage.marker.xml": {
    "bytes": 902,
    "gid": 0,
    "mode": 420,
    "sha256": "da4330f03ae6719924bd9f930e4c4108a99ba07f609ab57bce4cc39113273e38",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/custom.css.source.xml": {
    "bytes": 4255,
    "gid": 0,
    "mode": 420,
    "sha256": "b07c68e2d0b1f66537ac92116ccdb51450c5bf7753db407b34c3b42953b42fdd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/default.float.class.xml": {
    "bytes": 1164,
    "gid": 0,
    "mode": 420,
    "sha256": "30706e8862e205dcc1c9fe349e77ce8cd18b63dffbf8f0c6dbd1f041851c53ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/default.image.width.xml": {
    "bytes": 1128,
    "gid": 0,
    "mode": 420,
    "sha256": "5352b8b44dbf098d9bb41544029b493c34020280fdf59e9c3fdd9139c0150f38",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/default.table.frame.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "a92ea20dce28d0175239282b5d2c440a778c98956d08bce52cb3e4fc15cab16b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/default.table.rules.xml": {
    "bytes": 2212,
    "gid": 0,
    "mode": 420,
    "sha256": "ecf51b92b572b36f3cb20182dac0076f9cfe701f2bd77e55e450beddebb108d6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/default.table.width.xml": {
    "bytes": 1098,
    "gid": 0,
    "mode": 420,
    "sha256": "6f416e382f2ceceefd33a8291f68b242e6224a20b32080d7462950fcc0286410",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/default.units.xml": {
    "bytes": 1477,
    "gid": 0,
    "mode": 420,
    "sha256": "6d062d16f310fbdebbac7ad2f6611d56aef033f2f7eabea42dcfe52df7e0198a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/dialogue.properties.xml": {
    "bytes": 1146,
    "gid": 0,
    "mode": 420,
    "sha256": "eb63ba403adfa4d1bd283ba2e417115ca112d40df12fcf3d11276819e9f47f31",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/dingbat.font.family.xml": {
    "bytes": 1274,
    "gid": 0,
    "mode": 420,
    "sha256": "7e1958d6db091553d31366647375ddf1b9a3a747dfbbeb067b51d3b04be97f6f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/disable.collapsible.xml": {
    "bytes": 982,
    "gid": 0,
    "mode": 420,
    "sha256": "a43d3f2fd20cb69db3dd435f8422657689e4c298cbc2a3304115ad66178619f6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/disable.incremental.xml": {
    "bytes": 982,
    "gid": 0,
    "mode": 420,
    "sha256": "05caa015a8b8fcafd61b73eec4b80d2c354fdd015cf59656260e6d18988244b4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/docbook.css.link.xml": {
    "bytes": 1520,
    "gid": 0,
    "mode": 420,
    "sha256": "8074e36fe27a8e7e77fbd38768821d2f80b6f27eae4c4276bd3ec2a92eccefcc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/docbook.css.source.xml": {
    "bytes": 3541,
    "gid": 0,
    "mode": 420,
    "sha256": "026f88c3a675c104d4bbfa716ce8547513dca4654a84c3209aad9c602aa8c8ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/double.sided.xml": {
    "bytes": 1436,
    "gid": 0,
    "mode": 420,
    "sha256": "76431e128c8f51458d66367e696c856c782b3f713321042a3f0f2fbe0b298a5f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/draft.mode.xml": {
    "bytes": 1410,
    "gid": 0,
    "mode": 420,
    "sha256": "cd453a2fad9269280e8504edf6f3d907079e56b6ec23bbcaab66cdefc055b417",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/draft.watermark.image.xml": {
    "bytes": 928,
    "gid": 0,
    "mode": 420,
    "sha256": "1d5a7ef2bd15931a3a5b4ea4bf858475743e94eed4027358d0db97c9b8e4929c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/drama.properties.xml": {
    "bytes": 1125,
    "gid": 0,
    "mode": 420,
    "sha256": "4e97d7ce4cf8b5baa0bc5eebf21e2cf5af0cf1fa75a5ec53957d98987b84de7c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/dry-run.xml": {
    "bytes": 1126,
    "gid": 0,
    "mode": 420,
    "sha256": "ad344c4a338e6410447ce4fd0f0bb8796f918117c9cdd01c6943de5b3e2b001a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/dynamic.toc.xml": {
    "bytes": 972,
    "gid": 0,
    "mode": 420,
    "sha256": "8b4167909f78b9239adb70a5791808fb8ef85a94eb5f3594c423274297fa5b73",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/ebnf.assignment.xml": {
    "bytes": 1397,
    "gid": 0,
    "mode": 420,
    "sha256": "8a9e05783bf1b0ee2754c67725a239b0fec17391c018833824d9bfd15095db6f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/ebnf.statement.terminator.xml": {
    "bytes": 1168,
    "gid": 0,
    "mode": 420,
    "sha256": "ddd9a56a8e9ff95f5a4dfa91a655182d3504ebd7993f40281b500baa552aa4eb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/ebnf.table.bgcolor.xml": {
    "bytes": 1018,
    "gid": 0,
    "mode": 420,
    "sha256": "312b177703aa68129cef64b50aeee5cd1bda946937bcff763f14c1d70b1a6fa1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/ebnf.table.border.xml": {
    "bytes": 923,
    "gid": 0,
    "mode": 420,
    "sha256": "29d2af960264d29e569469dfb4b46353c064c0d573477f895be0168097013e23",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/eclipse.autolabel.xml": {
    "bytes": 952,
    "gid": 0,
    "mode": 420,
    "sha256": "362d8efc2b18b4eadd65be44ce7bf25d28e2e17b58f109bb724c2c68517e33c9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/eclipse.plugin.id.xml": {
    "bytes": 923,
    "gid": 0,
    "mode": 420,
    "sha256": "9e141273b32ca0a68eb89e42f09873d993bdfd1fc8747174d5f2cd47bd7e56f3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/eclipse.plugin.name.xml": {
    "bytes": 886,
    "gid": 0,
    "mode": 420,
    "sha256": "c569d097200493b59f0f62b00f80139b3725f1615cbfd43ce313abb901abfb40",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/eclipse.plugin.provider.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "19c79b8b4731e5a4f1bff40db16c6bae24fc7d299243a45ccd8998290247413d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/editedby.enabled.xml": {
    "bytes": 997,
    "gid": 0,
    "mode": 420,
    "sha256": "e9353ba0a80412d1b657809f1193c6b11bbe49865a254d3002bb28c4a604084d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/email.delimiters.enabled.xml": {
    "bytes": 1107,
    "gid": 0,
    "mode": 420,
    "sha256": "d2ed1dcdcb6ca44faf5542b3722129d13f0f08ceeee9822a6745f962d6b789df",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/email.mailto.enabled.xml": {
    "bytes": 1012,
    "gid": 0,
    "mode": 420,
    "sha256": "e3cb99162c94217f05f416303cab7cf1e1b98daa0c159d9aa2e12a4d09852063",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/emphasis.propagates.style.xml": {
    "bytes": 1079,
    "gid": 0,
    "mode": 420,
    "sha256": "14dcde80b73461aef532d23033422ce9f28f3ae626f673b541a1ed2d51c02d81",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/entry.propagates.style.xml": {
    "bytes": 1049,
    "gid": 0,
    "mode": 420,
    "sha256": "49351a2c60f3367f7af95935d979cc644a86c3b16253ca0f5c0cdcd3edd97bb5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/epub.autolabel.xml": {
    "bytes": 923,
    "gid": 0,
    "mode": 420,
    "sha256": "6552284f49c1009222a638b7f5cf95d8ff5e1b1eacae0c14bbd44195d2e51116",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/equation.number.properties.xml": {
    "bytes": 1324,
    "gid": 0,
    "mode": 420,
    "sha256": "2d2cf9e3736370f3ddb9cd6898376a230a9b29d42243b08dfc76d1e2ee39c7d1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/equation.properties.xml": {
    "bytes": 924,
    "gid": 0,
    "mode": 420,
    "sha256": "2ba5643ac455b5b4a83b52bdfc126cd8c63b8b56d082a3b2b4776972faf346fc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/example.properties.xml": {
    "bytes": 1012,
    "gid": 0,
    "mode": 420,
    "sha256": "fab0baee94bb7d652f3be601c03c0c9e2ae7895b9e19293e1fd2b1ab8af71bf0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/exsl.node.set.available.xml": {
    "bytes": 1643,
    "gid": 0,
    "mode": 420,
    "sha256": "83af83872069d50c0ccf28ea695dfc1b66da57bdb58cd921d3de15b5ca515a56",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/feedback.href.xml": {
    "bytes": 1007,
    "gid": 0,
    "mode": 420,
    "sha256": "e698929c84e114b23a98533026c264ab9be513545c058cfe41fe60ac6d825634",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/feedback.link.text.xml": {
    "bytes": 1038,
    "gid": 0,
    "mode": 420,
    "sha256": "dce39beb0fa38c782e99c97a2accc4a0bf0f241854a0d7a0c9cd2d2500075d8b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/feedback.with.ids.xml": {
    "bytes": 1032,
    "gid": 0,
    "mode": 420,
    "sha256": "758bf26e0e33ab206a047f997e71ac83f063674cfdad52698e750c7d1557fad7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/figure.properties.xml": {
    "bytes": 912,
    "gid": 0,
    "mode": 420,
    "sha256": "55618438832b35086532ac70c82361619861ced1a42317a2fd8d38c112c556ab",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/filename-prefix.xml": {
    "bytes": 1080,
    "gid": 0,
    "mode": 420,
    "sha256": "1a69e5650275cefbb8d93b2d0c02128d851de7e36ddca730a8e444b6fce467c4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/firstterm.only.link.xml": {
    "bytes": 1021,
    "gid": 0,
    "mode": 420,
    "sha256": "d3f2d6cb0f606954c4989fd42441ca872d1feb73218e4b5d5cc138c463dd4523",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foil.footer.properties.xml": {
    "bytes": 932,
    "gid": 0,
    "mode": 420,
    "sha256": "102558df7f692b525e4c0b6035ee4ce7b52ec0a63ef9d779e05ba966176bfc80",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foil.header.properties.xml": {
    "bytes": 1393,
    "gid": 0,
    "mode": 420,
    "sha256": "72a29ff452108b1a598f88352c30596dcca1754eed468858c3043324ce77d46a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foil.master.properties.xml": {
    "bytes": 1637,
    "gid": 0,
    "mode": 420,
    "sha256": "8f39672e9776a60b6f44cf5e4e02794d249fef6ab4f02ceede3ab9cbffba27eb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foil.page-sequence.properties.xml": {
    "bytes": 1105,
    "gid": 0,
    "mode": 420,
    "sha256": "e60d156a6d7aafab6113e51e918afdb44b40ddbdbca5401f09d81d48710582b4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foil.properties.xml": {
    "bytes": 1312,
    "gid": 0,
    "mode": 420,
    "sha256": "7bac6f8eae0b66fab6ba0cce7a4e79e14495fcd6a39a85515ff37ac2f826925b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foil.region-after.properties.xml": {
    "bytes": 1173,
    "gid": 0,
    "mode": 420,
    "sha256": "023dc900c29b6b83912f46268a3eb317653f7946df1a8b59db0ff4d414016811",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foil.region-before.properties.xml": {
    "bytes": 1225,
    "gid": 0,
    "mode": 420,
    "sha256": "13d5b88b41dd887b852877ca2a22abcac03b9e56a548c44c6f514c13b2ec98a4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foil.region-body.properties.xml": {
    "bytes": 1338,
    "gid": 0,
    "mode": 420,
    "sha256": "9f5e4e915af93cadab767b3dca2a41ead2500fb6ee43ea22c39a49b201cf7fc4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foil.subtitle.properties.xml": {
    "bytes": 1378,
    "gid": 0,
    "mode": 420,
    "sha256": "88493583c17e7d60892dc4b9d994d0eb2db18f74c1b5a07079010032f8df356b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foil.title.master.xml": {
    "bytes": 1027,
    "gid": 0,
    "mode": 420,
    "sha256": "b3b473318ee3c46d18595bc00ba052de982db2cfaab784dd8e75ef93bb23a719",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foil.title.properties.xml": {
    "bytes": 1059,
    "gid": 0,
    "mode": 420,
    "sha256": "8754ce2ee16ec936e366d1fa29dd83b6ea7f95f2459aa5bd5d99ce91bd89d92d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foil.title.size.xml": {
    "bytes": 1106,
    "gid": 0,
    "mode": 420,
    "sha256": "e9ad28ee50d8b7804d575e9bc048dfce1d8054fe47f2068eeabc33d7150a95a5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foilgroup.properties.xml": {
    "bytes": 1080,
    "gid": 0,
    "mode": 420,
    "sha256": "c0b2abc81fc18684e2c075d3a8fdf257ddb7930c7ee8f9a8c09658f58fd71707",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/foilgroup.toc.xml": {
    "bytes": 889,
    "gid": 0,
    "mode": 420,
    "sha256": "c97e5c635b7e9cd308817248e57e5803048be9904b7b3ef6c0e875c8b5f503f5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/footer.column.widths.xml": {
    "bytes": 2987,
    "gid": 0,
    "mode": 420,
    "sha256": "63e39aecde889723764da7e8a3a33be5447132354c182f9ac5b410bc06e25a40",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/footer.content.properties.xml": {
    "bytes": 1135,
    "gid": 0,
    "mode": 420,
    "sha256": "c917d9c6d6d94fa06484296e24c02661373dc934cf0ae8a6d4b5a239839d0252",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/footer.hr.xml": {
    "bytes": 881,
    "gid": 0,
    "mode": 420,
    "sha256": "4fb548b7299ec5169152b442f494e458298e3897c98f29a48145768b40d07bb9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/footer.rule.xml": {
    "bytes": 847,
    "gid": 0,
    "mode": 420,
    "sha256": "570e75164f172f1a5c4751657d8f0611fd4e5ba80288d53b215f0018e605742a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/footer.table.height.xml": {
    "bytes": 1242,
    "gid": 0,
    "mode": 420,
    "sha256": "79d816100aa2073e8a1db5738533514e8b05d90ef5869382fd27ae62a418dcef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/footer.table.properties.xml": {
    "bytes": 1070,
    "gid": 0,
    "mode": 420,
    "sha256": "783deb3f90d033c6e0ced3ec8300691ad10e29de0d91f290fb866973bd34798c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/footers.on.blank.pages.xml": {
    "bytes": 905,
    "gid": 0,
    "mode": 420,
    "sha256": "86d70d3142806aba8e61f726d08f753175628a5205a7347845f80f47dd55015b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/footnote.font.size.xml": {
    "bytes": 953,
    "gid": 0,
    "mode": 420,
    "sha256": "8c2a91d19314cda7ee1811fe85394f2c511077b86edec595685ccbdda3800d69",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/footnote.mark.properties.xml": {
    "bytes": 1466,
    "gid": 0,
    "mode": 420,
    "sha256": "c117b2b0b0667cac6ff8e7266c17561c2d9ac9f021fb040ef71df7878f3ed24a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/footnote.number.format.xml": {
    "bytes": 1406,
    "gid": 0,
    "mode": 420,
    "sha256": "32a2e62e8ec74d8c3fbde218c78c6862694eda28546ff49f8a21955ad743cc1f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/footnote.number.symbols.xml": {
    "bytes": 1735,
    "gid": 0,
    "mode": 420,
    "sha256": "d9a2d81acecf502957e906fb8926364cb1ea56aa8de48039ba9355e299fd87a5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/footnote.properties.xml": {
    "bytes": 1846,
    "gid": 0,
    "mode": 420,
    "sha256": "6643dc062ec310a051a9405b07f889d18ee0e8f2f32012c62521e5876fdba46a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/footnote.sep.leader.properties.xml": {
    "bytes": 1461,
    "gid": 0,
    "mode": 420,
    "sha256": "eb11901fd08ae4307fc97b4d861a14cafcce9282428dab114afc3a6a247380ec",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/fop.extensions.xml": {
    "bytes": 1246,
    "gid": 0,
    "mode": 420,
    "sha256": "b899d0f9f37df51d30bdd192083419b5be1e42a3d26236e79d63334e109da236",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/fop1.extensions.xml": {
    "bytes": 1181,
    "gid": 0,
    "mode": 420,
    "sha256": "f98bbba57a235e6e3f82cab884677dd22c0cd593b1fc1a5d8a66dc597d9549c6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/force.blank.pages.xml": {
    "bytes": 1657,
    "gid": 0,
    "mode": 420,
    "sha256": "2d64a342c29485f2601c5f165c65bd889c28eff2cb8fea3fcedd49539d6d3348",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/formal.object.properties.xml": {
    "bytes": 1513,
    "gid": 0,
    "mode": 420,
    "sha256": "77ce6bd5a30454e48f216d504f592f84d18fe59d0b52cd89787b4cdb06420be8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/formal.procedures.xml": {
    "bytes": 895,
    "gid": 0,
    "mode": 420,
    "sha256": "48a0287a42d50bd3cfdc340bf285b1413f943887158397654b88a55eb2e02c76",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/formal.title.placement.xml": {
    "bytes": 1265,
    "gid": 0,
    "mode": 420,
    "sha256": "5061086d28c056e1538057539cac735b7ede0ceaa14d76a5bfebb100d454ff43",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/formal.title.properties.xml": {
    "bytes": 1504,
    "gid": 0,
    "mode": 420,
    "sha256": "d1582e15517addb3714e2db73868b145a76a7c129d16b51bf26645bfd9bea79d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/funcsynopsis.decoration.xml": {
    "bytes": 1080,
    "gid": 0,
    "mode": 420,
    "sha256": "9ed63b1c6413361ff4480517fd2dd13deaad9134a09bcf486ec38a77196c02ac",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/funcsynopsis.style.xml": {
    "bytes": 1194,
    "gid": 0,
    "mode": 420,
    "sha256": "c2ee8d9b9d235e2f4eef199729eeed5f740a98c82b852978752a6ce2e4718e5e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/function.parens.xml": {
    "bytes": 922,
    "gid": 0,
    "mode": 420,
    "sha256": "4acce89219d39f8e1f024bd6e90f93936afc4899821cf0674548f96a80815fb9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.consistent.ids.xml": {
    "bytes": 1953,
    "gid": 0,
    "mode": 420,
    "sha256": "4e5aa0d9f44cb61945756090b9853cef97dd628c145792f488aab8b722c58cf9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.copyright.xml": {
    "bytes": 942,
    "gid": 0,
    "mode": 420,
    "sha256": "d912aa3efc3586eabab405720ecdf32672a0e885a37cd4fcd13ca6c5ba20ebba",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.css.header.xml": {
    "bytes": 1489,
    "gid": 0,
    "mode": 420,
    "sha256": "2f6d25ec9f6c5cbe26653a2e6662ed48006c3e69c39e2643edd49fd765ac1647",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.foilgroup.numbered.toc.xml": {
    "bytes": 1084,
    "gid": 0,
    "mode": 420,
    "sha256": "adbcd93537602ed6a88a9842eb3c4c7891df0a8ebe2682b76a7eb9d69b89433e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.foilgroup.toc.xml": {
    "bytes": 976,
    "gid": 0,
    "mode": 420,
    "sha256": "34dc2167ca22e97c02fe7982370117751265da1e69e07fee1e8c4305a56540b0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.handoutnotes.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "a4261165509d145d4fc495c112cba419318fe0168060d0969b34d8feaf13b084",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.id.attributes.xml": {
    "bytes": 2069,
    "gid": 0,
    "mode": 420,
    "sha256": "3c33893b88336ee1a3b8371c05ce32b51010b5ec73f67af002d53ca66174534c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.index.xml": {
    "bytes": 847,
    "gid": 0,
    "mode": 420,
    "sha256": "8c4591b205a866468afe6779ac4af70e54e37a105361671fd448895a06c351a7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.legalnotice.link.xml": {
    "bytes": 2698,
    "gid": 0,
    "mode": 420,
    "sha256": "aa3ac7cac80b2ca31c6d03903ceb611a7c4cc180cfabff6b06bcffe4449a1845",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.manifest.xml": {
    "bytes": 1032,
    "gid": 0,
    "mode": 420,
    "sha256": "b0e3a172379ec18cba17f7c1e1a8eeb9bc93fe97edb00dfbc4925f5b5a3979e9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.meta.abstract.xml": {
    "bytes": 1041,
    "gid": 0,
    "mode": 420,
    "sha256": "f58413b52a5e58096496a0be07a26c0515b18b6bc07d7568ab97a04d326ea4ff",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.page.number.xml": {
    "bytes": 1783,
    "gid": 0,
    "mode": 420,
    "sha256": "1855aaa99af57b742819e213aac246a8cf5e194a14bdec0c45d89b285ed0cb08",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.pubdate.xml": {
    "bytes": 936,
    "gid": 0,
    "mode": 420,
    "sha256": "fdd61e22494ef1bb30f7cda85d08b53334d1821422c4221e6890aeb408b484e2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.revhistory.link.xml": {
    "bytes": 1982,
    "gid": 0,
    "mode": 420,
    "sha256": "35daec79a472980decb4876a27a65f47cdefb9f108c08c9c5bec46adc891064d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.section.toc.level.xml": {
    "bytes": 1406,
    "gid": 0,
    "mode": 420,
    "sha256": "aebbf7076b60c077fdca77deb28a6ffb8524b8fedcae93d3b155f54dee9289d2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.speakernotes.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "a45670c626bd3ef9a397c904e0c2051cea84746c21ba2199f4bb8eb55fc608d1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.titlepage.xml": {
    "bytes": 935,
    "gid": 0,
    "mode": 420,
    "sha256": "aca7805035180be1ec8847daf9df6e285293af5e8be0dcaf4b1878afcb68fc22",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/generate.toc.xml": {
    "bytes": 3652,
    "gid": 0,
    "mode": 420,
    "sha256": "255e2052a1946fd83121d825cb918ebad2e517667deeafd9c3917249e263ea77",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/glossary.as.blocks.xml": {
    "bytes": 1377,
    "gid": 0,
    "mode": 420,
    "sha256": "41259358bd3fc6b9b2b6e2d2d3b416d0c49454de16348c5a4fd223bc0fba0fbb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/glossary.collection.xml": {
    "bytes": 11119,
    "gid": 0,
    "mode": 420,
    "sha256": "dc104b1de303518797b90504e58cef2a9aece8405a891f8a9c51c06d40403fcf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/glossary.sort.xml": {
    "bytes": 1053,
    "gid": 0,
    "mode": 420,
    "sha256": "b49e1ce4101bafdb1ffd908fc326189e0341ab68052be00176271736e0ee631e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/glossdef.block.properties.xml": {
    "bytes": 1278,
    "gid": 0,
    "mode": 420,
    "sha256": "8a3a0aac4b5a5a33899ef1f56ab60d959972c40b9faf4eabb6ff2962b5e157ef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/glossdef.list.properties.xml": {
    "bytes": 1129,
    "gid": 0,
    "mode": 420,
    "sha256": "6625fc3cd0e6d7833129b94feedb004217f56245f16a2d4af262394f5ce8b0d5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/glossentry.list.item.properties.xml": {
    "bytes": 1360,
    "gid": 0,
    "mode": 420,
    "sha256": "b1f7a81a42215ce0998731ac6f0c66a1504f88e33635cfb713109f8537a13f52",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/glossentry.show.acronym.xml": {
    "bytes": 1395,
    "gid": 0,
    "mode": 420,
    "sha256": "8ff96e8547967e398ed4e521ae671928f1b53b9acb55ae970e99b41cb04ef7c7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/glosslist.as.blocks.xml": {
    "bytes": 884,
    "gid": 0,
    "mode": 420,
    "sha256": "21c4265aa36440f739221a33e5568554994177a72709eb545cefcdebce0ce64b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/glossterm.auto.link.xml": {
    "bytes": 1309,
    "gid": 0,
    "mode": 420,
    "sha256": "ca43ac52dec0ed1083c006678f4e1e0b7e6c2882e8bcc66e76bc776b7340bfe8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/glossterm.block.properties.xml": {
    "bytes": 1542,
    "gid": 0,
    "mode": 420,
    "sha256": "7a02e18afff7f35a524b7ad438d53bcb7e4bdd808ba62c1c5e52123464c3aa32",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/glossterm.list.properties.xml": {
    "bytes": 1118,
    "gid": 0,
    "mode": 420,
    "sha256": "225b2f4d5432f9e32a696a4c42f60c163be2e2c740d31ff6ac1c87695f36028c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/glossterm.separation.xml": {
    "bytes": 1078,
    "gid": 0,
    "mode": 420,
    "sha256": "852fbda68d828523bda639156438509ceef2c30bd89f9a56befd9c9229fcf785",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/glossterm.width.xml": {
    "bytes": 935,
    "gid": 0,
    "mode": 420,
    "sha256": "97d211335166feb17988fbb57c81d265cd31a6e0c1274b287441a4f0c8975e3a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/graphic.default.extension.xml": {
    "bytes": 1115,
    "gid": 0,
    "mode": 420,
    "sha256": "a3d8ad61f0a626d863b656593638891211e68e94eee5b606f5445f7d8673799a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/graphical.admonition.properties.xml": {
    "bytes": 1914,
    "gid": 0,
    "mode": 420,
    "sha256": "2bb3ea90ac6dcc887c92b0d494dcf6e4947d5f587aa94d8ea770e2b7429ac05e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/graphics.dir.xml": {
    "bytes": 1096,
    "gid": 0,
    "mode": 420,
    "sha256": "b5e6f1557adeb3ee1dff288b0a64d5378c19c29bdae7386254d4169612f7897f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/graphicsize.extension.xml": {
    "bytes": 1277,
    "gid": 0,
    "mode": 420,
    "sha256": "aadec4ba906772a99538224d715f8f20c37a5f20eda9bd5a8f70a27da9cfcec6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/graphicsize.use.img.src.path.xml": {
    "bytes": 1100,
    "gid": 0,
    "mode": 420,
    "sha256": "ba5f15471ee3647a15822de1563f2eba7be330342e832c4616fbecea42884a10",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/handoutnotes.properties.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "6c547075da57b1c59e1cd1634c749f8696c27498340c1ca20552ea61dd34ee75",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/header.column.widths.xml": {
    "bytes": 2987,
    "gid": 0,
    "mode": 420,
    "sha256": "d804a70756e0298ac7170dc6832b1a40c3fce7e20f80ba70ac3067554c6ad150",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/header.content.properties.xml": {
    "bytes": 1135,
    "gid": 0,
    "mode": 420,
    "sha256": "2537a7de3f40526981e96dcc732aea1458e39c8e5ebe3e59d98ff8d4124f92b2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/header.hr.xml": {
    "bytes": 880,
    "gid": 0,
    "mode": 420,
    "sha256": "a1576b8fd66ae9ea30f55fad2fea3204ba96e06e5085bc28bcb32c76cb8e667c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/header.rule.xml": {
    "bytes": 848,
    "gid": 0,
    "mode": 420,
    "sha256": "342d4ec2b332eded8b8e597a4d91cdf0a46c42fa91c0edc3db721ec25f7f4b48",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/header.table.height.xml": {
    "bytes": 1241,
    "gid": 0,
    "mode": 420,
    "sha256": "6761fc3f289eb6f46f826828496b6d7eb3af99c7d7614b969006322c35e12b5d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/header.table.properties.xml": {
    "bytes": 1070,
    "gid": 0,
    "mode": 420,
    "sha256": "f224e6990dc864621d5bf2d1800cd1856f4230064f03ef761ae66e7da37017b4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/headers.on.blank.pages.xml": {
    "bytes": 905,
    "gid": 0,
    "mode": 420,
    "sha256": "2d68168e5ffb3b21ca7d720dce6700b5fc4fef588834017798380f0d927fcc46",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/hidetoc.image.xml": {
    "bytes": 963,
    "gid": 0,
    "mode": 420,
    "sha256": "913f24455c397cf548e5c7dce0c7c31c7d3677cc5d5429b132752ab88a315558",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/highlight.default.language.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "5d8633acd2b082afaa301a8ee451b8389986364aea0a3e93e2a99c1c0e1bea13",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/highlight.source.xml": {
    "bytes": 3433,
    "gid": 0,
    "mode": 420,
    "sha256": "f688fa8f42c1799e66d6306392448cc350402c489f222667c6ea70042f9336d3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/highlight.xslthl.config.xml": {
    "bytes": 1132,
    "gid": 0,
    "mode": 420,
    "sha256": "fc35396579ed870e2e062d3e62fedff51080bfce79ba7295c1dad49618aa2c66",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/home.image.xml": {
    "bytes": 848,
    "gid": 0,
    "mode": 420,
    "sha256": "3d4b45f327012cfadb1a4ec8acee8fbf68077e352f1e704a0b39ec80bfab4cb0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.append.xml": {
    "bytes": 1157,
    "gid": 0,
    "mode": 420,
    "sha256": "b7ad3157089ad15733376bd44004f418cf4b868b71470683194ca4fe44c20ba0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.base.xml": {
    "bytes": 1032,
    "gid": 0,
    "mode": 420,
    "sha256": "6865db30d5cb882a56f188b525a738a0a824a6c12d0fc6a5c420859a2231a651",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.cellpadding.xml": {
    "bytes": 983,
    "gid": 0,
    "mode": 420,
    "sha256": "4156be6502ba6daa517e5cff65e2792dd12e98f9ddcb439eda287080c461892c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.cellspacing.xml": {
    "bytes": 983,
    "gid": 0,
    "mode": 420,
    "sha256": "690fef3712002f2fdf56096bd9650b830dcba0686f347cd7c552c1542e9f277d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.cleanup.xml": {
    "bytes": 1268,
    "gid": 0,
    "mode": 420,
    "sha256": "65c00580ec905fe1fb62ad342026f1f35b53f8d27507efd385b5ecd67d246920",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.ext.xml": {
    "bytes": 947,
    "gid": 0,
    "mode": 420,
    "sha256": "a155fdd0616a6acefe8b99dd1f238862c05fea0924cba447298ed2e95807c2c3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.extra.head.links.xml": {
    "bytes": 1126,
    "gid": 0,
    "mode": 420,
    "sha256": "2c6c23129d61005a5ec6ccdb0c1462144c0ca1188fc2e9cf12081e0a60c5ae29",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.head.legalnotice.link.multiple.xml": {
    "bytes": 1798,
    "gid": 0,
    "mode": 420,
    "sha256": "8dcc88bf500ce654a35b6e78c9ebf48efce7608280d7d8327ef064cb481e06b1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.head.legalnotice.link.types.xml": {
    "bytes": 3149,
    "gid": 0,
    "mode": 420,
    "sha256": "ca7d0fa5a206f094d5ecb6580c5912add95f6f34ad654a1f54f2ff03c092fef8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.longdesc.link.xml": {
    "bytes": 1293,
    "gid": 0,
    "mode": 420,
    "sha256": "9ef192398d58297a52cafb685b948501e572b8f064744a644c756c46531aac21",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.longdesc.xml": {
    "bytes": 1014,
    "gid": 0,
    "mode": 420,
    "sha256": "8763fba6464b964d9de515ef7d92066c072caed8c8ce411d485ba61317d3ccaf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.script.type.xml": {
    "bytes": 1194,
    "gid": 0,
    "mode": 420,
    "sha256": "3c7b8314761d3c0591b1b2d32713e1d24b40e45213f9e07b5a14debf8eede09b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.script.xml": {
    "bytes": 1323,
    "gid": 0,
    "mode": 420,
    "sha256": "9f5340e8480ef14ed5319737913591e41346f624f8a1ca045d7ac9d4089f4787",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.stylesheet.type.xml": {
    "bytes": 944,
    "gid": 0,
    "mode": 420,
    "sha256": "022cecbc759e9fe7aa261b87fb81d5ce7e467cbc6761bd1c9b99120750a2dcee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/html.stylesheet.xml": {
    "bytes": 1347,
    "gid": 0,
    "mode": 420,
    "sha256": "7f5f8ea26130b8979d7f1dee36147489149ab364dd9547983290f60dab7f1581",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.alias.file.xml": {
    "bytes": 916,
    "gid": 0,
    "mode": 420,
    "sha256": "b39c9ddb900839750856dd40f9ff9c009b068dc9dc8107046bfff9789da3bbd9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.autolabel.xml": {
    "bytes": 941,
    "gid": 0,
    "mode": 420,
    "sha256": "b0e371f066211bc64ae8cf2bb7af04b20e3d650d3e0dd259c9d6a2f7c2830285",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.back.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "623718082c5b87404d5c6bd9df12b90a051884eca384f1ee5cdcf609d05f55df",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.forward.xml": {
    "bytes": 930,
    "gid": 0,
    "mode": 420,
    "sha256": "7d8203562e60fcdd95df7bbdc8f3a0b5c7c61feb5baf892c4cedb9f046437de9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.hideshow.xml": {
    "bytes": 939,
    "gid": 0,
    "mode": 420,
    "sha256": "0962142b371a2b69df3aacf128b0bf456cdc997ac062128a447fc4ef588b2647",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.home.url.xml": {
    "bytes": 916,
    "gid": 0,
    "mode": 420,
    "sha256": "6e06affb26693b347c28ef60dc8615bea8dc49a24b8bd73be01f57a7e6c60e74",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.home.xml": {
    "bytes": 908,
    "gid": 0,
    "mode": 420,
    "sha256": "e65175258b55ebffd841d569885d22059ae5150e634a7e4d3269f147145dd56a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.jump1.title.xml": {
    "bytes": 899,
    "gid": 0,
    "mode": 420,
    "sha256": "a56032e0a5ab7e1e2a9809da30a37f896b80381422160d87f2d4b793cd01cbdc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.jump1.url.xml": {
    "bytes": 923,
    "gid": 0,
    "mode": 420,
    "sha256": "39508d4c6565ca3dd484904d0fa2f6160279080a2b99a51654c5b240aa14b6c5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.jump1.xml": {
    "bytes": 931,
    "gid": 0,
    "mode": 420,
    "sha256": "8d507582aeb225c227ce58932cc1956fd612032163c8407d9318bd76fd57d8ce",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.jump2.title.xml": {
    "bytes": 899,
    "gid": 0,
    "mode": 420,
    "sha256": "633542b97001c05a38492c8c5dc94756f269ab20a5357232f0cc24c393bd47b4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.jump2.url.xml": {
    "bytes": 934,
    "gid": 0,
    "mode": 420,
    "sha256": "0e45119ce84359299d1ea689499b7fff460a49c630d3fd8ddf352752eb5a5fdb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.jump2.xml": {
    "bytes": 915,
    "gid": 0,
    "mode": 420,
    "sha256": "f1611380c7873ea80af233d259e946c50b2a1195a1dae627828da90d56b1b43d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.locate.xml": {
    "bytes": 930,
    "gid": 0,
    "mode": 420,
    "sha256": "105422655b5039a773fa0192bb9ff57cabf14ac65bbb1cef0678c542741e5857",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.next.xml": {
    "bytes": 908,
    "gid": 0,
    "mode": 420,
    "sha256": "b005947cfa3d3d2181d053e3b97c090474637b2ed9c3adcd5a60a3471c2771c3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.options.xml": {
    "bytes": 937,
    "gid": 0,
    "mode": 420,
    "sha256": "5f28f85eee11581f66c32d213ef2abf959b4f76e9baea6f239ed4b7c8c5fd971",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.prev.xml": {
    "bytes": 909,
    "gid": 0,
    "mode": 420,
    "sha256": "821b4589ea6258f6f30f92940ae6818729e9fe444d047bf2bcb671b2c1ab9d42",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.print.xml": {
    "bytes": 916,
    "gid": 0,
    "mode": 420,
    "sha256": "abc1424b0dc43dc976d733f420aaadacbe8be8b3cbea18115c35b4f06cf26f69",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.refresh.xml": {
    "bytes": 926,
    "gid": 0,
    "mode": 420,
    "sha256": "0e168223c837f4d99772aef28291e031d4d70d8c02a578c3dd08bf4a9c9aaf07",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.stop.xml": {
    "bytes": 916,
    "gid": 0,
    "mode": 420,
    "sha256": "9b6a10ee333750050ed50bd121386e37b9a7ce13c96d213b5d66aee039a2d726",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.button.zoom.xml": {
    "bytes": 909,
    "gid": 0,
    "mode": 420,
    "sha256": "9f6513bd66dfbaa94e9f11f8df052403060bc42cacbf7697cb4456b360706001",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.chm.xml": {
    "bytes": 857,
    "gid": 0,
    "mode": 420,
    "sha256": "31d060eaf218ddec71bfdbb100238b8938e11b84844286d7e0fb5d837dab535b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.default.topic.xml": {
    "bytes": 1369,
    "gid": 0,
    "mode": 420,
    "sha256": "af650f7c833a33488f7ee9884bdc996b2089d47c3525eac7c1ca911aca4c5dcb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.display.progress.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "0d23689a288d1b05d1e230d90a38d8865f9f2909b1251c5827ec0c9b8ca6a2ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.encoding.xml": {
    "bytes": 1075,
    "gid": 0,
    "mode": 420,
    "sha256": "6594cbf59a03b08b0b13e484b379e58b01e43c1e6ca7047f6641c9cc124d842e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.enhanced.decompilation.xml": {
    "bytes": 975,
    "gid": 0,
    "mode": 420,
    "sha256": "a2d4f0b1326062d551afaecde60a1e62a0d23c5e61017658daee0e5931a2b194",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.enumerate.images.xml": {
    "bytes": 1033,
    "gid": 0,
    "mode": 420,
    "sha256": "4d3cf8761263a177ff5d0ff76cf0463a145ffa5d092fe38373341b860e25722d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.force.map.and.alias.xml": {
    "bytes": 1112,
    "gid": 0,
    "mode": 420,
    "sha256": "23097c94d418e34ffdd6654573b2814946a36aba8c1d9910e2cec442d5634315",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.hhc.binary.xml": {
    "bytes": 1019,
    "gid": 0,
    "mode": 420,
    "sha256": "be26907693176426efb4aebe9af95c421158a2d678eabc784729bafccd3f4183",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.hhc.folders.instead.books.xml": {
    "bytes": 1139,
    "gid": 0,
    "mode": 420,
    "sha256": "70743019c941d23dfd49c096916cfac28d026ea3e4a44d6f14e0d60f8b3976ba",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.hhc.section.depth.xml": {
    "bytes": 949,
    "gid": 0,
    "mode": 420,
    "sha256": "305a805ee6a98d59f779d8a2415df00fe6f623a16abff56a115aa5685a0f91ab",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.hhc.show.root.xml": {
    "bytes": 1040,
    "gid": 0,
    "mode": 420,
    "sha256": "045ecd91ff4de625274513b556f8ee5860edece3c96f67cf05f383591a0b9407",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.hhc.width.xml": {
    "bytes": 931,
    "gid": 0,
    "mode": 420,
    "sha256": "02e9e7f00c4c70f358a5ef3edfccc13bcc9ed1bd4cdbf8f2005b04cca93eba45",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.hhc.xml": {
    "bytes": 878,
    "gid": 0,
    "mode": 420,
    "sha256": "af3864808e3830a466af227e20960849b1555e9fe959e93b2be1a811a4be5915",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.hhk.xml": {
    "bytes": 886,
    "gid": 0,
    "mode": 420,
    "sha256": "f02bb90fddf10d702292ea2593e8d3c0905f9b40677ee133280ebc7ce3771432",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.hhp.tail.xml": {
    "bytes": 954,
    "gid": 0,
    "mode": 420,
    "sha256": "d08506fdb3996a2236c3c8cff4fea10be79ce03e4209cfa602901fd409fd7c1f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.hhp.window.xml": {
    "bytes": 922,
    "gid": 0,
    "mode": 420,
    "sha256": "92293f708ae80bc4447e1d81d62fc0b403063c1d56d938c7a599117dc17c4e6b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.hhp.windows.xml": {
    "bytes": 977,
    "gid": 0,
    "mode": 420,
    "sha256": "5d22f7db40309df79bd60d4464bf4ba12dec1e6a12f1eb021bf78ea92f5fee81",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.hhp.xml": {
    "bytes": 896,
    "gid": 0,
    "mode": 420,
    "sha256": "d5e8186fc5dad12bbe8e5e8e6a9597629a5fd86d657a6efeb11f65eef1184b7e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.map.file.xml": {
    "bytes": 938,
    "gid": 0,
    "mode": 420,
    "sha256": "148258326902d6e05742d94d06b9b3390e0bd03b15f942b92101c38a6296ac96",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.only.xml": {
    "bytes": 1045,
    "gid": 0,
    "mode": 420,
    "sha256": "a61c70bc2e6b2476be2dc4c49e898af79d14e2f089bf4bcc30759e5326897f97",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.remember.window.position.xml": {
    "bytes": 976,
    "gid": 0,
    "mode": 420,
    "sha256": "ee670dbbbbff83743fec16ceae4ba0b0e4f38820d7c396917b2d6e3349da4136",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.show.advanced.search.xml": {
    "bytes": 983,
    "gid": 0,
    "mode": 420,
    "sha256": "cb7f0fb5efc93997e307bc291472f2691c13f383a679baa361d03d07e2870e6e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.show.favorities.xml": {
    "bytes": 957,
    "gid": 0,
    "mode": 420,
    "sha256": "b5e108143bfd72385cbed9045035f679bdd6122a411c7c14236d0fb352d4041a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.show.menu.xml": {
    "bytes": 910,
    "gid": 0,
    "mode": 420,
    "sha256": "165f8ea74633a43953d840c2841432f6b53b7fd03deeb6d32f2155984624a8ce",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.show.toolbar.text.xml": {
    "bytes": 963,
    "gid": 0,
    "mode": 420,
    "sha256": "c877ff4ca2bec490f04bc6f84ddec4141b633354738c023ddd951b3a819bfb3d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.title.xml": {
    "bytes": 937,
    "gid": 0,
    "mode": 420,
    "sha256": "56f0bd0419454ac218d7dfee67ebd9abf96495d95785ea1dd0d925a847c6134f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.use.hhk.xml": {
    "bytes": 1080,
    "gid": 0,
    "mode": 420,
    "sha256": "8f38b404a14d0d0c4420f8af95cc70466495c0ce867da0408261fc266bc7e0d0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/htmlhelp.window.geometry.xml": {
    "bytes": 1040,
    "gid": 0,
    "mode": 420,
    "sha256": "293348efa836537fa544cce468d8fad261d347b428acc18c1def39a9039e0933",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/hyphenate.verbatim.characters.xml": {
    "bytes": 1171,
    "gid": 0,
    "mode": 420,
    "sha256": "9220724020f809e6bd0f8807d2d1a57e0775a88293735fe500bc639cba66a866",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/hyphenate.verbatim.xml": {
    "bytes": 2172,
    "gid": 0,
    "mode": 420,
    "sha256": "af41dc3309e7301db95f7ae675599a96c7a35528fc577e8b9ff3a915cce69f54",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/hyphenate.xml": {
    "bytes": 1117,
    "gid": 0,
    "mode": 420,
    "sha256": "aa2fc0c1adc0d38daa2a0419203af6541f34a0b515b60133bf523658e6fbeebf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/id.warnings.xml": {
    "bytes": 977,
    "gid": 0,
    "mode": 420,
    "sha256": "b59c1f5ea5406f818e7ed0acc8daa2f4687ad0fb1a25de26730b5417cca5b9af",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/ignore.image.scaling.xml": {
    "bytes": 963,
    "gid": 0,
    "mode": 420,
    "sha256": "3771d62a87b19adc693704b20c27cf4dec41f422c595d6ba4cf00bae3388d9ec",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/img.src.path.xml": {
    "bytes": 1510,
    "gid": 0,
    "mode": 420,
    "sha256": "42b646e06870c31d356221bb4fc47c05e36a37fdba249a285904c6badcc50267",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/index.div.title.properties.xml": {
    "bytes": 1796,
    "gid": 0,
    "mode": 420,
    "sha256": "f2aeec600f6eec7a9262a8cf49cdb04cdde016b8f12e9c76ab7421eb7d4bce49",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/index.entry.properties.xml": {
    "bytes": 1188,
    "gid": 0,
    "mode": 420,
    "sha256": "b4cc0844884012d6e58989d55bad9c8439d0a8c5baab7e80db5900dafef77c1f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/index.links.to.section.xml": {
    "bytes": 2715,
    "gid": 0,
    "mode": 420,
    "sha256": "b732f2fd7cf786d88027167db8c8ff9297e7f4a32efa1d0b47245ce57e75d1ed",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/index.method.xml": {
    "bytes": 5764,
    "gid": 0,
    "mode": 420,
    "sha256": "42ccf4ee095df93b8782d5485b4bf87d911b54d2781161d3bd13271a6a4cde27",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/index.number.separator.xml": {
    "bytes": 1945,
    "gid": 0,
    "mode": 420,
    "sha256": "b070a525c397bbf5b9c2cc071d81913741bc3d238def9a55ed9324ede9d1c58b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/index.on.role.xml": {
    "bytes": 1655,
    "gid": 0,
    "mode": 420,
    "sha256": "80c331f71df9086d5fe9e59a7d3ed7ebe117d7eed463afa72dae6591f9cec5b5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/index.on.type.xml": {
    "bytes": 1824,
    "gid": 0,
    "mode": 420,
    "sha256": "ce4262529066dc1e79bbb08b02a7a73955dbf369bbec233c340fd59018660ce2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/index.page.number.properties.xml": {
    "bytes": 1051,
    "gid": 0,
    "mode": 420,
    "sha256": "17e51ae89e05a39a146a302cd7aa30e5323e857c7efd259147051cb6f8a0aba8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/index.prefer.titleabbrev.xml": {
    "bytes": 1028,
    "gid": 0,
    "mode": 420,
    "sha256": "91cdb64f80e3b619e6952dba0230d1332082aadb3e5a9bb1b385cc6440a19bab",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/index.preferred.page.properties.xml": {
    "bytes": 1224,
    "gid": 0,
    "mode": 420,
    "sha256": "b95939ff8c8f72a03dcb1820dd76fb5ea83143237b802d04ead03bb41cd08b37",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/index.range.separator.xml": {
    "bytes": 2029,
    "gid": 0,
    "mode": 420,
    "sha256": "fac8eaad64028f8fe6ddaa80d1717354d1ef9d5e9422bd30e68cb4347f3ea280",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/index.term.separator.xml": {
    "bytes": 1928,
    "gid": 0,
    "mode": 420,
    "sha256": "e9fdedd11168d680987e156897e5fc4067e6dc92244ed4b0c017209f4bcb3708",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/informal.object.properties.xml": {
    "bytes": 1432,
    "gid": 0,
    "mode": 420,
    "sha256": "b91c2c4a8d66c2dc907b05352e02f2ad0db203bb24b1336ebb4194c7370b5b1b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/informalequation.properties.xml": {
    "bytes": 983,
    "gid": 0,
    "mode": 420,
    "sha256": "c9c30c16fa028f3d7de3db69beaae5cae6683d4c754db52961402cc86893ca8e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/informalexample.properties.xml": {
    "bytes": 976,
    "gid": 0,
    "mode": 420,
    "sha256": "dffdd3b4ba85b3b67332c1d98ea8f191b76c91da5206728583e3762f624290cd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/informalfigure.properties.xml": {
    "bytes": 969,
    "gid": 0,
    "mode": 420,
    "sha256": "9e7e3a9291d3d326fc8b6fd111bf3f16f36709bb3b128ddb4e9fa7421781995c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/informaltable.properties.xml": {
    "bytes": 1253,
    "gid": 0,
    "mode": 420,
    "sha256": "ce9bed53033c7a8253037c26682a1bc71b4dbeae187eab5e9f7830245477f463",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/inherit.keywords.xml": {
    "bytes": 1099,
    "gid": 0,
    "mode": 420,
    "sha256": "1341107f01c9df5b6604ecacf3c607161a061ab5d4ebcd8bf8fb2e380114ec69",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/inlinestagedir.properties.xml": {
    "bytes": 1333,
    "gid": 0,
    "mode": 420,
    "sha256": "4d3dd60ab6da5739da0d8ccb6f5a9b574031fc6e29611f6e14d5bef9d6f9b1ad",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/inner.region.content.properties.xml": {
    "bytes": 1748,
    "gid": 0,
    "mode": 420,
    "sha256": "df68f57bc2ec0d5819ced1bb6ff84b6d1658dcdd371bed7646621ab4071a8ee5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/insert.link.page.number.xml": {
    "bytes": 2334,
    "gid": 0,
    "mode": 420,
    "sha256": "d0523eadd49c9909356690116bb433fefb402a489545ebffbb9efe4a5205f56b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/insert.olink.page.number.xml": {
    "bytes": 2859,
    "gid": 0,
    "mode": 420,
    "sha256": "cfe3ec172cf0b7d1dfc70c32ba92fa5e9b19b0b6c641a4c1a4523f491662fc05",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/insert.olink.pdf.frag.xml": {
    "bytes": 2587,
    "gid": 0,
    "mode": 420,
    "sha256": "e8ca22ef1780ab9ae22b47253dc9946caae9c3dea992a62830f32ab052a38836",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/insert.xref.page.number.para.xml": {
    "bytes": 1800,
    "gid": 0,
    "mode": 420,
    "sha256": "a9fc4356fe6a9d4d2d5d0a013d2d2e82da6da40d3dae8ac9f49610cbeef9ad60",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/insert.xref.page.number.xml": {
    "bytes": 1916,
    "gid": 0,
    "mode": 420,
    "sha256": "2597f55c0cdfa36a803591af93d05c312ba460e8b32173ed19bad76537b6c2bf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/itemizedlist.label.properties.xml": {
    "bytes": 1192,
    "gid": 0,
    "mode": 420,
    "sha256": "dc531d6ab197a367489b1f83274a727cb161ad71e00dca8ed984a04b7cdf8141",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/itemizedlist.label.width.xml": {
    "bytes": 1151,
    "gid": 0,
    "mode": 420,
    "sha256": "b4471db3f918e2a1001ed3788709388430536e3a55a492a46281779c80178bab",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/itemizedlist.properties.xml": {
    "bytes": 1030,
    "gid": 0,
    "mode": 420,
    "sha256": "b515a1b4f21354daa641ca0794cffa1007731ac8a08df5ff39171d180373d000",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/javahelp.encoding.xml": {
    "bytes": 1015,
    "gid": 0,
    "mode": 420,
    "sha256": "06abb8974ab2499e4f669b111bf7681e4faed0ac300fd6a5676dde99ee0cb1c9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/keep.relative.image.uris.xml": {
    "bytes": 1304,
    "gid": 0,
    "mode": 420,
    "sha256": "be558d6fca5b6f1adcc3f50d26c5a041d09f97ba0a0d8f62a2820c206f1d22b5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/keyboard.nav.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "38efb8673c6e0eee4a14f69cb9e8da407f2e6608be82ebf4a1d06521605ee9d6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/l10n.gentext.default.language.xml": {
    "bytes": 1109,
    "gid": 0,
    "mode": 420,
    "sha256": "25c4b485845487fc74ae76f8d2839a680ba173606c98f2e0f1ff7ff5ff035174",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/l10n.gentext.language.xml": {
    "bytes": 1231,
    "gid": 0,
    "mode": 420,
    "sha256": "979f75ed9a55270f1395cb254beac44d0808ed7e4ed2823b37a337d2a67a4c82",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/l10n.gentext.use.xref.language.xml": {
    "bytes": 1866,
    "gid": 0,
    "mode": 420,
    "sha256": "ccb4deef7c72470b87bfc1c7a7bf262cb388eb8916ee3a7ae51a6163c6ae07e5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/l10n.lang.value.rfc.compliant.xml": {
    "bytes": 2408,
    "gid": 0,
    "mode": 420,
    "sha256": "eea373050541ac84b54a0f4ebfa4c421966be1d62579e4d65caac8eb925b6deb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/label.from.part.xml": {
    "bytes": 1446,
    "gid": 0,
    "mode": 420,
    "sha256": "7018d3f899e629b0796b9849e8ba010b3cf74dfd6f83b715fc405a441806fcb3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/line-height.xml": {
    "bytes": 839,
    "gid": 0,
    "mode": 420,
    "sha256": "58394c07e15e176ca4db304df706898b28ea7433da2a1aa259b877968a555c81",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/line.properties.xml": {
    "bytes": 1007,
    "gid": 0,
    "mode": 420,
    "sha256": "aa241e377e7811602ce401e35c7a9583e514d6319be5f9889e5dd54046bbe89a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/linegroup.properties.xml": {
    "bytes": 1277,
    "gid": 0,
    "mode": 420,
    "sha256": "660b597a19f9dc9fc81e2ecfefe94dc9e4eb0ac844a8c8823537fe192b33dabe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/linenumbering.everyNth.xml": {
    "bytes": 1182,
    "gid": 0,
    "mode": 420,
    "sha256": "d0df0444e0da07163c56c1f53725461e7369943f66ca1e0681d4794847f11003",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/linenumbering.extension.xml": {
    "bytes": 1068,
    "gid": 0,
    "mode": 420,
    "sha256": "85d8503a1c9e6a4bc36ac82c66c9dd5329ff4b5df10797798683336c8a64d410",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/linenumbering.separator.xml": {
    "bytes": 1102,
    "gid": 0,
    "mode": 420,
    "sha256": "5878ae666c7a18bfcd43f06d736edd705d37a20dc700b8217bab0ddb54ab27db",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/linenumbering.width.xml": {
    "bytes": 955,
    "gid": 0,
    "mode": 420,
    "sha256": "208ca6f2d76a8b511ccc9bdbfba62d37d5819c3fb55bf6e1983d1686692893e2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/link.mailto.url.xml": {
    "bytes": 977,
    "gid": 0,
    "mode": 420,
    "sha256": "ca1defb67cbd1f4bd7a4a1e769e1055337aca3d12dc7e3981c593cf057f6abcb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/link.to.self.for.mediaobject.xml": {
    "bytes": 1760,
    "gid": 0,
    "mode": 420,
    "sha256": "d342745c2a69d8efb826c5d239ecbcbaffa69c7ec806fb69c36c1a7852dd9e22",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/list.block.properties.xml": {
    "bytes": 1138,
    "gid": 0,
    "mode": 420,
    "sha256": "14d1f81d3dfc4f8a96e8ec5cf4b8230a3f649fe7c851b78b68c99695a146b85b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/list.block.spacing.xml": {
    "bytes": 1600,
    "gid": 0,
    "mode": 420,
    "sha256": "dbd44da1d3a7298fe429c96400eab6858d2cc7fae1c7d98f3fd737b70d2e4672",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/list.item.spacing.xml": {
    "bytes": 1257,
    "gid": 0,
    "mode": 420,
    "sha256": "26bf5870963dcbfa1c58c1a75e274e2221710ce8c712515c8fe4eaac279d9348",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/make.clean.html.xml": {
    "bytes": 2045,
    "gid": 0,
    "mode": 420,
    "sha256": "f8abff698ae823f783eb867aaa562c3ae29df96575efbc0dbfc2aa7d19db5d8d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/make.graphic.viewport.xml": {
    "bytes": 1349,
    "gid": 0,
    "mode": 420,
    "sha256": "8d03e04307e8a3b123cb286e8a38150fe90087a8ab2b91f81a50d4799a6ff2f6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/make.index.markup.xml": {
    "bytes": 2817,
    "gid": 0,
    "mode": 420,
    "sha256": "bd424fca9a7745cf3cda0203503e6563b7fcf8bf8cfb53ea6caf02f97686f1b8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/make.single.year.ranges.xml": {
    "bytes": 1010,
    "gid": 0,
    "mode": 420,
    "sha256": "2403139322ec3c0bffb3113a47663deeff0d1a08577a510f38037ba48e481750",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/make.valid.html.xml": {
    "bytes": 1338,
    "gid": 0,
    "mode": 420,
    "sha256": "959f7032b5d8f33c65839e966f62783ce204424742517e524910bc2663faf51c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/make.year.ranges.xml": {
    "bytes": 1150,
    "gid": 0,
    "mode": 420,
    "sha256": "21222c08237e40cf62d2c2a03e9306ea4be00cf107c2609822ad3accaac6f3b6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.authors.section.enabled.xml": {
    "bytes": 1970,
    "gid": 0,
    "mode": 420,
    "sha256": "cbe532f9ba9fc26fde80953b4e1e7c9c256d282fbbcc07cbe413cd605ef954df",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.base.url.for.relative.links.xml": {
    "bytes": 3183,
    "gid": 0,
    "mode": 420,
    "sha256": "707d532f14a6d4467e5694f21b9aad5514f41f5bfa2522f86e417509fda1e57f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.break.after.slash.xml": {
    "bytes": 1918,
    "gid": 0,
    "mode": 420,
    "sha256": "a222a8a64e48b6ba2fc6aed2590bd291986a72e2a69f2f2ac0a2e1e2b1131624",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.charmap.enabled.xml": {
    "bytes": 2413,
    "gid": 0,
    "mode": 420,
    "sha256": "9e7d93c282c0749a86809b78a68960dcd975f726fc730a33b538f7a532124ed7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.charmap.subset.profile.english.xml": {
    "bytes": 3455,
    "gid": 0,
    "mode": 420,
    "sha256": "7bf748615ff7de7a113b89a0edf66551ccae8ac5a8bc674fdb2314fcb9febb16",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.charmap.subset.profile.xml": {
    "bytes": 14006,
    "gid": 0,
    "mode": 420,
    "sha256": "ca7c5e8ce2f571dbbd03a1fed38c61ffcf88b0363fba67d9518c54125c3c4706",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.charmap.uri.xml": {
    "bytes": 1678,
    "gid": 0,
    "mode": 420,
    "sha256": "abbf101cba9b7ed7bc456f634170c0a8732286969d6895fa2e35914bbc814715",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.charmap.use.subset.xml": {
    "bytes": 3595,
    "gid": 0,
    "mode": 420,
    "sha256": "b5b47469f4c4176630b6c7f7a0bfd620e0609f433f3e5b45027a83d288a55f80",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.copyright.section.enabled.xml": {
    "bytes": 1963,
    "gid": 0,
    "mode": 420,
    "sha256": "758f43281c31e0b7741537c06fdf386f09ec1d75d3ffc8f066bbf96a38037032",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.endnotes.are.numbered.xml": {
    "bytes": 4886,
    "gid": 0,
    "mode": 420,
    "sha256": "1ccb78a88e5cf36c74d09515d2011ea07c38c934f48956e806b7457e0bbb21fc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.endnotes.list.enabled.xml": {
    "bytes": 5156,
    "gid": 0,
    "mode": 420,
    "sha256": "e710304e09d5b03d789bbc4ba804242ba7cf0c1f2f1a5bf4f447d2bd8b20aa60",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.endnotes.list.heading.xml": {
    "bytes": 1470,
    "gid": 0,
    "mode": 420,
    "sha256": "61ac9ea8c6259c189de9b89cbacad18e960370137349e9bc71ee886d513c56e1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.font.funcprototype.xml": {
    "bytes": 1076,
    "gid": 0,
    "mode": 420,
    "sha256": "3993ebafd6d45d1b0eb784dbb459fd106291ebfa4810be2c20ee97eddd376774",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.font.funcsynopsisinfo.xml": {
    "bytes": 1098,
    "gid": 0,
    "mode": 420,
    "sha256": "7d9444b1bfe13b23851367361d83b8f5927097525bc1549d8d16d2fdeccb0403",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.font.links.xml": {
    "bytes": 2773,
    "gid": 0,
    "mode": 420,
    "sha256": "5602367aa4d862f2aa3cc8f991915fbe0a72ac57d103ac6ef06768b299c5c37d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.font.table.headings.xml": {
    "bytes": 1063,
    "gid": 0,
    "mode": 420,
    "sha256": "9f457f24a8df575d6973ece92655e66c0bdb5d6ead6902fdd28aeb780ae86254",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.font.table.title.xml": {
    "bytes": 1043,
    "gid": 0,
    "mode": 420,
    "sha256": "3748cdd94d5cb35b1a0cb8347bcc1f1e7c322a378ef7a8df614738d6948eedfb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.funcsynopsis.style.xml": {
    "bytes": 1215,
    "gid": 0,
    "mode": 420,
    "sha256": "53a5611234abff1a5ffe987c25a8150077f2ba0fe9f4c357838c3996f1c1badd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.hyphenate.computer.inlines.xml": {
    "bytes": 1918,
    "gid": 0,
    "mode": 420,
    "sha256": "a769d33aad1b9725fe05e91acd7f670c5a89ce37857572f6111c33256057a045",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.hyphenate.filenames.xml": {
    "bytes": 1704,
    "gid": 0,
    "mode": 420,
    "sha256": "63cbd0d833697c177fcaf41da7ae4a7d78918f577ecaada5fb64f6773bb04b39",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.hyphenate.urls.xml": {
    "bytes": 1679,
    "gid": 0,
    "mode": 420,
    "sha256": "abe5f9944f6338bc2bddba3db7a346679cf2e79ac6607d5d463ef0b2ae40cbc2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.hyphenate.xml": {
    "bytes": 2374,
    "gid": 0,
    "mode": 420,
    "sha256": "71f39ee8faafb7e1520c827cbc50eb2bfd5195494bdfcb000d2fdea590675454",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.indent.blurbs.xml": {
    "bytes": 1264,
    "gid": 0,
    "mode": 420,
    "sha256": "8bfda865be39ad456d19eb7683db632325b951d6b6f2db3d98299dd95f67f000",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.indent.lists.xml": {
    "bytes": 1305,
    "gid": 0,
    "mode": 420,
    "sha256": "488aabd218ebb09f847782f401a2810f329ef338b41a7436b884718a3f1ff289",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.indent.refsect.xml": {
    "bytes": 2702,
    "gid": 0,
    "mode": 420,
    "sha256": "138d7216c3223b78a04727d61ec434bbdb9a8a8bd338e7bd50acf7c4e14cf52c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.indent.verbatims.xml": {
    "bytes": 1300,
    "gid": 0,
    "mode": 420,
    "sha256": "a97b796d5ccbc564c2387b819291aead913f21efb86524a3450c87bf0e9904c0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.indent.width.xml": {
    "bytes": 1588,
    "gid": 0,
    "mode": 420,
    "sha256": "5afd02e56f19f11d73635b280f4c20d6c4d563184309cb4d583bb229fa789457",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.justify.xml": {
    "bytes": 2197,
    "gid": 0,
    "mode": 420,
    "sha256": "cf2ffc50cc676aadec65f95f8fe268fa51cf9a2b4cb451b12d1e2d6bfe698f2a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.output.base.dir.xml": {
    "bytes": 1521,
    "gid": 0,
    "mode": 420,
    "sha256": "f808da08ad1b8e5ab75bcc7d8d2dcaf2fa51cdf47e693b212d2a893fe301d31c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.output.better.ps.enabled.xml": {
    "bytes": 2654,
    "gid": 0,
    "mode": 420,
    "sha256": "1e8ba817771eec26b212cb98435922bc8914993d33ce80be2105b2bf7d26dc19",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.output.encoding.xml": {
    "bytes": 2185,
    "gid": 0,
    "mode": 420,
    "sha256": "3200832449b44f1ef347d83387e30fa42878fb2840a0812f77b72dcfa8f0fef7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.output.in.separate.dir.xml": {
    "bytes": 1241,
    "gid": 0,
    "mode": 420,
    "sha256": "f2ef53958cba90d2e216cfbb68166c4ca6f6bc5bf9cc8546c1a9efdc477e1a7d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.output.lang.in.name.enabled.xml": {
    "bytes": 1828,
    "gid": 0,
    "mode": 420,
    "sha256": "c733dc5a794f8273d72e437396b3deda095570c108f8c5160876739757f220dc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.output.manifest.enabled.xml": {
    "bytes": 1111,
    "gid": 0,
    "mode": 420,
    "sha256": "67bbb7166d05ff96cf392c7bb4e9b1969d67d13d3b19534676859e10f7c8b5e5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.output.manifest.filename.xml": {
    "bytes": 1182,
    "gid": 0,
    "mode": 420,
    "sha256": "00b6d0a4842895541a24cc1fcb11b9e9678b4257657510f42f44b3e9c5966b4e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.output.quietly.xml": {
    "bytes": 1293,
    "gid": 0,
    "mode": 420,
    "sha256": "00df60e714d86ed9a0afcdb78a23a78cbffaf334e8f729f675ac27ff17acd6ee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.output.subdirs.enabled.xml": {
    "bytes": 1571,
    "gid": 0,
    "mode": 420,
    "sha256": "ffd611fe5522e6873b8e3d4bd0302c91e3f7c23bbe147957970a9da493b58632",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.segtitle.suppress.xml": {
    "bytes": 1002,
    "gid": 0,
    "mode": 420,
    "sha256": "f2a82075931b0eb16b2c4dae31c41f336c38985c35458f72fb5dcb37b99c9d23",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.string.subst.map.local.post.xml": {
    "bytes": 1361,
    "gid": 0,
    "mode": 420,
    "sha256": "a8238339c76869164d44fc48c4715741f3cb86c85510b5905fb368e8c0d09f3b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.string.subst.map.local.pre.xml": {
    "bytes": 1358,
    "gid": 0,
    "mode": 420,
    "sha256": "da8419e7f77718cb465fc4fd9e3600bd194cb5cbb0eb22699fe9f9021907b0d4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.string.subst.map.xml": {
    "bytes": 6861,
    "gid": 0,
    "mode": 420,
    "sha256": "3748e493b731620413ce2fde27013daf95f172f44b03512200627dddd96885de",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.subheading.divider.enabled.xml": {
    "bytes": 1499,
    "gid": 0,
    "mode": 420,
    "sha256": "db9dd3d3b1a5a046d7ef2cc002aef7df5297703f36015b6c9be70924130a2b60",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.subheading.divider.xml": {
    "bytes": 1536,
    "gid": 0,
    "mode": 420,
    "sha256": "d7eb4f232c85b989838b832a6a118002ed524b0793fb98b425de0bd01d17eca2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.table.footnotes.divider.xml": {
    "bytes": 1097,
    "gid": 0,
    "mode": 420,
    "sha256": "c28016a89b4e34eb1956c565ba065365a34ba0df5af4c280425fce1a72f946cd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.th.extra1.suppress.xml": {
    "bytes": 1203,
    "gid": 0,
    "mode": 420,
    "sha256": "44b23da2858879a22ec0e6605b374dde5f9a69e17f49e2fbed4600b31a647eae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.th.extra2.max.length.xml": {
    "bytes": 1819,
    "gid": 0,
    "mode": 420,
    "sha256": "d5a04a909aca3f3fe1fa6a3df8d18d99c57ef97d703a2c9b7dd52b66ad9a8f65",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.th.extra2.suppress.xml": {
    "bytes": 1685,
    "gid": 0,
    "mode": 420,
    "sha256": "a8ccf7d26019933de3fb1b73daa3f81144397aedeeb1d60bf8585cdf1ebcd69a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.th.extra3.max.length.xml": {
    "bytes": 1789,
    "gid": 0,
    "mode": 420,
    "sha256": "85f6a185ed1ac7bfc07764be2cabf3f7838b165f8bbf8a0eb1974ea8a3c8c78b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.th.extra3.suppress.xml": {
    "bytes": 1291,
    "gid": 0,
    "mode": 420,
    "sha256": "d5ebe8c7616f2f820d3250890830c38472ca75c353c447cf70b46a7fae9dba6e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/man.th.title.max.length.xml": {
    "bytes": 2647,
    "gid": 0,
    "mode": 420,
    "sha256": "84a3f0f8917d6e1b8a461e586ffdc6360dab99ff176b4137115f9ac429478164",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/manifest.in.base.dir.xml": {
    "bytes": 1059,
    "gid": 0,
    "mode": 420,
    "sha256": "72ef5e1fef34ed947a6538262ecac4a5c1793f49de1ea72a8c980eab4aad94b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/manifest.xml": {
    "bytes": 988,
    "gid": 0,
    "mode": 420,
    "sha256": "20f49e604c474b22df60237e9ca35ff4841f3da254df1c8063b1608a890d7dc5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/manual.toc.xml": {
    "bytes": 917,
    "gid": 0,
    "mode": 420,
    "sha256": "775077442cbce7569da6262b94d0d6cc4bec4a436359dfefa18c46a235dce201",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/margin.note.float.type.xml": {
    "bytes": 2758,
    "gid": 0,
    "mode": 420,
    "sha256": "6a70d1e981d0446ef5a70e0d566e16b2f92ce6145ebf93337e783dfdf34e7ab3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/margin.note.properties.xml": {
    "bytes": 1934,
    "gid": 0,
    "mode": 420,
    "sha256": "912479764efe2df4de0e6903657b5860225045ace6b45abd4c2d9970c265e973",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/margin.note.title.properties.xml": {
    "bytes": 1197,
    "gid": 0,
    "mode": 420,
    "sha256": "e2752b005afd450a6771a399168fd1436774c0ba03aa6f7eaa808173d3943247",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/margin.note.width.xml": {
    "bytes": 1187,
    "gid": 0,
    "mode": 420,
    "sha256": "82fef982bad1b039f8c7b9addfcc0998e53960377962d6ccb32d95ce38c3e769",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/mark.optional.procedure.steps.xml": {
    "bytes": 1301,
    "gid": 0,
    "mode": 420,
    "sha256": "9ef8df68d36fd1d8e460230ef064f974b17d0a004492f4e305e39d9aa629178e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/marker.section.level.xml": {
    "bytes": 1839,
    "gid": 0,
    "mode": 420,
    "sha256": "36af951a498674caf17d206f017e11c6d51ab58ee1e4b46b21a79b513d0ae151",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/menuchoice.menu.separator.xml": {
    "bytes": 1517,
    "gid": 0,
    "mode": 420,
    "sha256": "05475b809ab53665b8c796cadbc132209f709034c051889e84376b29ed19d19d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/menuchoice.separator.xml": {
    "bytes": 1133,
    "gid": 0,
    "mode": 420,
    "sha256": "c9fcf87d13e5d7dd5d5a1347d86585a75beadf9ee38191910408d5080c24f897",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/minus.image.xml": {
    "bytes": 965,
    "gid": 0,
    "mode": 420,
    "sha256": "bbff36bfa5b86a096dae4d4db33c5255e37121b4a96aeed168cebf695fffd81d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/mml.embedding.mode.fo.xml": {
    "bytes": 1838,
    "gid": 0,
    "mode": 420,
    "sha256": "c0f8068af7cfa12c204eb942fc858895e53fa41d4e81f628d71c914368a095de",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/mml.embedding.mode.xml": {
    "bytes": 2596,
    "gid": 0,
    "mode": 420,
    "sha256": "f98902627aa25a021373cfab6f65f7b8c802fb5a36a639d0afff700a8d75eca3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/monospace.font.family.xml": {
    "bytes": 1181,
    "gid": 0,
    "mode": 420,
    "sha256": "da8d891d7e9f4fa983e3e64530dfc77913b0366b6287aeff1b15f9f6a6550bbe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/monospace.properties.xml": {
    "bytes": 1366,
    "gid": 0,
    "mode": 420,
    "sha256": "3656cc4cb5f0f24be2e40f6d1c6c84fe125769c30282f38fce0c5bbd4da165e2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/monospace.verbatim.font.width.xml": {
    "bytes": 1541,
    "gid": 0,
    "mode": 420,
    "sha256": "fc33bb28875a8ce91683a1812208dd2ae57c1626acb0b8c14c9439f87d2b2440",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/monospace.verbatim.properties.xml": {
    "bytes": 1176,
    "gid": 0,
    "mode": 420,
    "sha256": "5202c9fbd31f562c9d2a4865c7bf765458ae3f966a7c1022d106ee5bc28073a9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/multiframe.bottom.bgcolor.xml": {
    "bytes": 1012,
    "gid": 0,
    "mode": 420,
    "sha256": "78ac76f5dd929604dd938dd06bfea5cd5922eab3f4dad38d0dc3ac147c4ba2cd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/multiframe.navigation.height.xml": {
    "bytes": 1002,
    "gid": 0,
    "mode": 420,
    "sha256": "9cbc405de7fee5dc9347be1983ba56c03a37566e6aa0a1b4f8f45bca1c306058",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/multiframe.top.bgcolor.xml": {
    "bytes": 992,
    "gid": 0,
    "mode": 420,
    "sha256": "9382dbb961d928567ac15da748cd55cd48816d59e5fcb0c701dd8c21fa3d2651",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/multiframe.xml": {
    "bytes": 1161,
    "gid": 0,
    "mode": 420,
    "sha256": "c25003a9220409afdb6c48ca0c8f837fd9deedf996c938f7af2ff28d8ebb81e0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/nav.separator.xml": {
    "bytes": 952,
    "gid": 0,
    "mode": 420,
    "sha256": "33373bd96ad3df00418ce310695e06146fd22e872dfcca7ddc903e59902d2d70",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/nav.table.summary.xml": {
    "bytes": 1041,
    "gid": 0,
    "mode": 420,
    "sha256": "7cdeb6bb3dfbd7a4315ff4f258a724649051e05ffc3c08040eb96447e0aa2b65",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/navbgcolor.xml": {
    "bytes": 926,
    "gid": 0,
    "mode": 420,
    "sha256": "12e1c68880c5a028c242f7457c774883f3e2bd4eb51ee4cd626e662e25f7bb1c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/navbodywidth.xml": {
    "bytes": 911,
    "gid": 0,
    "mode": 420,
    "sha256": "d2ea29dbc9a45192eabd199117089770c744eb9fe1d13fb6e37835066c0f5be9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/navig.graphics.extension.xml": {
    "bytes": 983,
    "gid": 0,
    "mode": 420,
    "sha256": "323fb4b2d49c8458f3cb8391c7d4828e0cb5d9caa3ea483a2f3949313e50e592",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/navig.graphics.path.xml": {
    "bytes": 1009,
    "gid": 0,
    "mode": 420,
    "sha256": "491040ad5c9e3cc1220af89da59706ea4c107702fa3c90a5414024a89b865069",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/navig.graphics.xml": {
    "bytes": 1093,
    "gid": 0,
    "mode": 420,
    "sha256": "b35579990e511591e836a646a6016cc8ea16820225cbd68300376f295be3c9f7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/navig.showtitles.xml": {
    "bytes": 1139,
    "gid": 0,
    "mode": 420,
    "sha256": "cc1cb32012ed234f1d03982f2fbe28c7687bd080aee9403bec377237d4ba4ea0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/navtocwidth.xml": {
    "bytes": 937,
    "gid": 0,
    "mode": 420,
    "sha256": "c55a9ac21dc1c7d9f75e26e89a460c28bc52749a0f54d505e1a03d5b6463ed70",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/next.image.xml": {
    "bytes": 867,
    "gid": 0,
    "mode": 420,
    "sha256": "8fd9c38bb6275682d12f5ef29ac8977bb2e7fc176a7170f1832a58acdd384ab9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/no.home.image.xml": {
    "bytes": 883,
    "gid": 0,
    "mode": 420,
    "sha256": "6e5b8266a5ae25809a765efa463306e273f7e1e880517d0029e628c93bc8e148",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/no.next.image.xml": {
    "bytes": 901,
    "gid": 0,
    "mode": 420,
    "sha256": "50af1f6c515ba759e7ccd92c9bd7bd3e6535003a09024b3d5053df40600e7c27",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/no.prev.image.xml": {
    "bytes": 900,
    "gid": 0,
    "mode": 420,
    "sha256": "1027dd328899723dd9908774437e8095b83c1c9b26e004d2a6cdbfa84bc03168",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/no.toc.image.xml": {
    "bytes": 875,
    "gid": 0,
    "mode": 420,
    "sha256": "654362640dbb4b72ab479135f0c0298a348c4df2a9f9c0cb646a594500bb1e8c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/no.up.image.xml": {
    "bytes": 888,
    "gid": 0,
    "mode": 420,
    "sha256": "b7eafc50d42d9f79f1950ccdf8207882d4cc501a06178f4ece1828c50213caaf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/nominal.image.depth.xml": {
    "bytes": 896,
    "gid": 0,
    "mode": 420,
    "sha256": "21a450501968f2c41c8c1d1daa55fc327d8890ef0f51fa13aa88c144dc8a290d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/nominal.image.width.xml": {
    "bytes": 1702,
    "gid": 0,
    "mode": 420,
    "sha256": "eb3ba8338960b380fc432e0ede5ee63350bf12b9cd2be255f584e046c9de6ace",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/nominal.table.width.xml": {
    "bytes": 1092,
    "gid": 0,
    "mode": 420,
    "sha256": "dea35e4a964cdd82ea21ca731c84fd7f90a75f2fc4ff292f5b0dfc6cd2c8305a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/nongraphical.admonition.properties.xml": {
    "bytes": 1887,
    "gid": 0,
    "mode": 420,
    "sha256": "dc41428b6312afbc328f7bf28b4fb0f0435603a49ae5d21e98faecc5747fc74e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/normal.para.spacing.xml": {
    "bytes": 1550,
    "gid": 0,
    "mode": 420,
    "sha256": "75f25b2039f63f034411b483c05baa6b735ad6d2db0c1392a491c0903784713a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/olink.base.uri.xml": {
    "bytes": 1595,
    "gid": 0,
    "mode": 420,
    "sha256": "b3d45d2dcd8def1ff617c3442df6f26e32be1b3568d038c46743b68d06ca62f3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/olink.debug.xml": {
    "bytes": 1173,
    "gid": 0,
    "mode": 420,
    "sha256": "18eaa6d28f7236cc1b2ace1376c0cf05ab423d04ac00bfb4a780781a1fe064fb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/olink.doctitle.xml": {
    "bytes": 4729,
    "gid": 0,
    "mode": 420,
    "sha256": "3e258b40d3dfbfd227fa4ce0f30c70d285db3ddf169e243a3472fdd7b72db83b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/olink.fragid.xml": {
    "bytes": 905,
    "gid": 0,
    "mode": 420,
    "sha256": "e63d2bd7a8e482475776b1431a292e1f8b894ff018ea6f1eaf844cf9d19f7d4a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/olink.lang.fallback.sequence.xml": {
    "bytes": 3225,
    "gid": 0,
    "mode": 420,
    "sha256": "b83b1ee4a1a47958eb630b285d379b712af80216697e355c61648d4d2797d682",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/olink.outline.ext.xml": {
    "bytes": 958,
    "gid": 0,
    "mode": 420,
    "sha256": "9de6e4fafbdf45981db89e20c6830222a8ed452b4db4fa60d57105636acbdb00",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/olink.properties.xml": {
    "bytes": 1149,
    "gid": 0,
    "mode": 420,
    "sha256": "76064d166157730f9a96f3c71412b6edf4a4db4eda4bb265785e5636f97e0f6f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/olink.pubid.xml": {
    "bytes": 838,
    "gid": 0,
    "mode": 420,
    "sha256": "506532901c3d5ba3b081cf5f79b47fcef6ce8188f7c687c475663f2de7a6a15f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/olink.resolver.xml": {
    "bytes": 859,
    "gid": 0,
    "mode": 420,
    "sha256": "2f1308d4a9115ef672b155122072e65b0e313e94502ecf590cd910e06eab74bb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/olink.sysid.xml": {
    "bytes": 843,
    "gid": 0,
    "mode": 420,
    "sha256": "cdde8c3dc6918591375aa5c3c32edbc09fba3d8b633e226543883a61c5ae41b4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/orderedlist.label.properties.xml": {
    "bytes": 1184,
    "gid": 0,
    "mode": 420,
    "sha256": "64f6c2875b40aa66c0fcccda790cc08f0191e4ba4d0826212d727227e2c42c5e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/orderedlist.label.width.xml": {
    "bytes": 1141,
    "gid": 0,
    "mode": 420,
    "sha256": "ac31e5f47180acc6b938d44d1d41623db1d0363d575706fb2af8c7a052a2c044",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/orderedlist.properties.xml": {
    "bytes": 1103,
    "gid": 0,
    "mode": 420,
    "sha256": "1f52343a8d8c8ca81ad1f08ebe591985056a327ac3536e3784749ecc18bfad52",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/othercredit.like.author.enabled.xml": {
    "bytes": 1202,
    "gid": 0,
    "mode": 420,
    "sha256": "c4f0a06bdbb9f9b9524b9dc074415fec0445921ad5fc25870d6a43c3d6fb3a84",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/outer.region.content.properties.xml": {
    "bytes": 1760,
    "gid": 0,
    "mode": 420,
    "sha256": "650db404964232880607604dbf213118463aedd2d35d93ff41568db265051719",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/output-root.xml": {
    "bytes": 1056,
    "gid": 0,
    "mode": 420,
    "sha256": "cd5f4410747e5895da8379f814329eaae76486a67c2d28c72921b60386797c30",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/output.indent.xml": {
    "bytes": 1190,
    "gid": 0,
    "mode": 420,
    "sha256": "278aa910bb21642d569727f65eb58878f0ef9fad81a865f4876b749d17c94f4a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/overlay.js.xml": {
    "bytes": 919,
    "gid": 0,
    "mode": 420,
    "sha256": "17d8621c77e51a7aa94ede49cdeed85a1104de57d013bb33b168b8f76eeca90b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/overlay.logo.xml": {
    "bytes": 949,
    "gid": 0,
    "mode": 420,
    "sha256": "296d6cb555004862a251d377a7a53ac3bbce3fa00b32d2c7e1b9233a44d62a17",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/overlay.xml": {
    "bytes": 1085,
    "gid": 0,
    "mode": 420,
    "sha256": "a8c7d9437b549058305a0ee014659aff8b90cdc33523fa78a4d87de32f425a81",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/page.height.portrait.xml": {
    "bytes": 3341,
    "gid": 0,
    "mode": 420,
    "sha256": "060c85ead7365a880d5ac530c01a5c7a7316548aaaa309dc69e05abb149428b3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/page.height.xml": {
    "bytes": 1186,
    "gid": 0,
    "mode": 420,
    "sha256": "018f5cd6e22d474585a5ebc1022d97a1070aa5096a3c193f5261b3182e4b2477",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/page.margin.bottom.xml": {
    "bytes": 951,
    "gid": 0,
    "mode": 420,
    "sha256": "e051f3c7e701a8d509601f5f3d5d229d10201b117cbb2d79585dc3cc349b4ce3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/page.margin.inner.xml": {
    "bytes": 1993,
    "gid": 0,
    "mode": 420,
    "sha256": "aa4fee6f2eb23d6184806c525198544486f2521d0c100346c86d01bbd47436e5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/page.margin.outer.xml": {
    "bytes": 1886,
    "gid": 0,
    "mode": 420,
    "sha256": "4d1992529a7355d629219991b857df08605f5280242b3dcc8238d18018b2404a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/page.margin.top.xml": {
    "bytes": 924,
    "gid": 0,
    "mode": 420,
    "sha256": "a237c7fff741c26131a72cfe04ac0e9c4c4cd06b95ef4ae8c132044e2605c878",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/page.orientation.xml": {
    "bytes": 1105,
    "gid": 0,
    "mode": 420,
    "sha256": "716461ea73d78d3e4cf6fe49348365f5a2846a6995232c498697f9b11ecb8791",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/page.width.portrait.xml": {
    "bytes": 3266,
    "gid": 0,
    "mode": 420,
    "sha256": "a635ecbf95cec7aa23f297b912fa749584b53b23301110e2aa36553131b3f1e2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/page.width.xml": {
    "bytes": 1179,
    "gid": 0,
    "mode": 420,
    "sha256": "a5d7e99658f9ee81da1a1c6386c1a9df1a2b5a73fa0eac3490e4b2d07a38857f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/pages.template.xml": {
    "bytes": 1399,
    "gid": 0,
    "mode": 420,
    "sha256": "2bff9142eaed581ddff7dbb9e2944660b81de2b1bf745dc4d64cb260b2510737",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/paper.type.xml": {
    "bytes": 4403,
    "gid": 0,
    "mode": 420,
    "sha256": "54fe08fefca20e6c226a99f5d22bf07680bb8e1d3ab04cb000d4602208896735",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/para.propagates.style.xml": {
    "bytes": 1023,
    "gid": 0,
    "mode": 420,
    "sha256": "b53658987e50a0badab2386ffc9c20542372e1f3d5e26fe0672e118d9a8141bb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/para.properties.xml": {
    "bytes": 1339,
    "gid": 0,
    "mode": 420,
    "sha256": "5a5d81a1696ddde04cd4cc19bbb85f441ded16c458e9814626d47c8959e83c47",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/part.autolabel.xml": {
    "bytes": 2393,
    "gid": 0,
    "mode": 420,
    "sha256": "e30215e765414eeefb852fd37a4fded8b68c38a674a42eacf1bf034538c9085b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/passivetex.extensions.xml": {
    "bytes": 1129,
    "gid": 0,
    "mode": 420,
    "sha256": "966619cb4b13613563f1f5806e85a5002a7327128c6be7060ceb6bc9ad38f778",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/pgwide.properties.xml": {
    "bytes": 1760,
    "gid": 0,
    "mode": 420,
    "sha256": "0f5679b86de4a7e91217f6f06ea21062028dd9f8928e8d7d07b05e3c5cab960d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/phrase.propagates.style.xml": {
    "bytes": 1066,
    "gid": 0,
    "mode": 420,
    "sha256": "d32842470f6edf83c09fd781645ad3e56bd03415e9f65989c80ee22ed5ee347e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/pixels.per.inch.xml": {
    "bytes": 1047,
    "gid": 0,
    "mode": 420,
    "sha256": "30d7b2abb02ebbfce97124dcdbfef0da8b6031cc87cbe41f2d0c9bbafe5a6a70",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/plus.image.xml": {
    "bytes": 959,
    "gid": 0,
    "mode": 420,
    "sha256": "2c3d335ae99d16abd53ad6e9b190c2f4624ceda1c757c3d27e6bc3611a99b432",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/poetry.properties.xml": {
    "bytes": 1131,
    "gid": 0,
    "mode": 420,
    "sha256": "a7e659df6b1388f489b3b2584806a646cbee0096c22f0922831b6e8d40de3c0e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/points.per.em.xml": {
    "bytes": 993,
    "gid": 0,
    "mode": 420,
    "sha256": "a6d3d554e9bd9cc01e2ffa5ac0c60c2d9b484ac394f48706e9bf2c1a7bd50fab",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/preface.autolabel.xml": {
    "bytes": 2407,
    "gid": 0,
    "mode": 420,
    "sha256": "af9bfbab843e2cc2859a297a17a4f0003c9648719ec57dffc4861006e1c29da0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/prefer.internal.olink.xml": {
    "bytes": 2968,
    "gid": 0,
    "mode": 420,
    "sha256": "51bf0366133fb96b5c25d99860ad6480d0fde73de652caa27563bd983ea53af6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/preferred.mediaobject.role.xml": {
    "bytes": 1603,
    "gid": 0,
    "mode": 420,
    "sha256": "cee9698a00d2a3002a764794fb96351f49bd04b06271f992315e3b588d38e9bc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/prev.image.xml": {
    "bytes": 864,
    "gid": 0,
    "mode": 420,
    "sha256": "a6293da39f996a57e7e6bbcd7073fa36430ccf8bc92c7610ef5e9919c0f27e8b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/procedure.properties.xml": {
    "bytes": 1024,
    "gid": 0,
    "mode": 420,
    "sha256": "42e3014e412d3235e0d00cb705622f20c5345f1c23b5be124e6027b531244183",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/process.empty.source.toc.xml": {
    "bytes": 1566,
    "gid": 0,
    "mode": 420,
    "sha256": "334c1547242353cf3988697f3bf3aa610e72b063ba8be7b92c3b5910124fac49",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/process.source.toc.xml": {
    "bytes": 1546,
    "gid": 0,
    "mode": 420,
    "sha256": "6a759558d117a269a4c07271ad14a44cad6c49691dde01ce93c9a8f619246c69",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.arch.xml": {
    "bytes": 1352,
    "gid": 0,
    "mode": 420,
    "sha256": "e83c0e428dffd6785b80bef0ae5ff1c603cc54d34414950e6ac3b4c64a0cf3bf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.attribute.xml": {
    "bytes": 1192,
    "gid": 0,
    "mode": 420,
    "sha256": "1f129e8913550399872c508fa39e844715148704cb1f2b16966e944970fd5f2b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.audience.xml": {
    "bytes": 1371,
    "gid": 0,
    "mode": 420,
    "sha256": "b9d3ebfea3267040f0a03953ac6e58d669499f0e868ebd86fd58c75813331083",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.condition.xml": {
    "bytes": 1381,
    "gid": 0,
    "mode": 420,
    "sha256": "5bd7d3a61d9107c4a7051c9a9a74915c1fb918c88f52e349e65a6b58d7807214",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.conformance.xml": {
    "bytes": 1393,
    "gid": 0,
    "mode": 420,
    "sha256": "4241fb6922d683c9d8dbcaa65cbcf81f61bef560fd97aa25802a9898c441ed96",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.lang.xml": {
    "bytes": 1351,
    "gid": 0,
    "mode": 420,
    "sha256": "dc697949f72a04878cb1975864b4167efc69f2989f158548f52351f276db63f4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.os.xml": {
    "bytes": 1339,
    "gid": 0,
    "mode": 420,
    "sha256": "ad63ea6f92a36f647c6a157c8c2b3910ebd419898976007f59b8ae34a70a6c38",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.outputformat.xml": {
    "bytes": 1418,
    "gid": 0,
    "mode": 420,
    "sha256": "a9335b12fc42ded02521125a3706253f4224ca76de2d01045f99c77a3449bd32",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.revision.xml": {
    "bytes": 1376,
    "gid": 0,
    "mode": 420,
    "sha256": "bdb8bc837a2c6519a8f1529b0b1290ad305ad56604a804396db64abd63143449",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.revisionflag.xml": {
    "bytes": 1399,
    "gid": 0,
    "mode": 420,
    "sha256": "983d8546ef7aa775c375e26a131937b9e86578a3eef38d519113c1a9c4e755dc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.role.xml": {
    "bytes": 2225,
    "gid": 0,
    "mode": 420,
    "sha256": "b4cf9006e1a679c9cbfbdab09ed80c60f232fbc52f93df99362fd32727ef755a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.security.xml": {
    "bytes": 1375,
    "gid": 0,
    "mode": 420,
    "sha256": "c6891fe9dc163dd0718c5b017c747ed04488e626189386cc043ff08f4e076522",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.separator.xml": {
    "bytes": 942,
    "gid": 0,
    "mode": 420,
    "sha256": "f478643020f021ef9421df9737a14d25d637f05a5f3e3d70de23dc1ecd1604f4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.status.xml": {
    "bytes": 1363,
    "gid": 0,
    "mode": 420,
    "sha256": "a9955992374ea920a89a5f290f74211dac884386365530902312933d32341a01",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.userlevel.xml": {
    "bytes": 1381,
    "gid": 0,
    "mode": 420,
    "sha256": "ad28d67f1d5df7a2b597ab0e833b0014a48f21bc4b7a4070aa6c86077ccd26f7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.value.xml": {
    "bytes": 1492,
    "gid": 0,
    "mode": 420,
    "sha256": "199d7a414f0b02237890bae6cb6f89c4d636382d6bea61bb4ffd3d4e6fa1b646",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.vendor.xml": {
    "bytes": 1363,
    "gid": 0,
    "mode": 420,
    "sha256": "9b64fa9d7aa9fc7324202ef5fabdf18cd5f17180bd36b34901aa3120fc4eb31d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/profile.wordsize.xml": {
    "bytes": 1375,
    "gid": 0,
    "mode": 420,
    "sha256": "6f60c0556eb7f0f466032bcec39ba3de13082af0c22b76f51b8cf6cdf49333dc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/publishers.properties.xml": {
    "bytes": 1366,
    "gid": 0,
    "mode": 420,
    "sha256": "da3a444993969621d53188d43faf9627dc4fbd6553e522b620d28374c276875d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/punct.honorific.xml": {
    "bytes": 942,
    "gid": 0,
    "mode": 420,
    "sha256": "e120a48be89dfcab296865873a42313e8b82ea6bed89843db55cb9cd7b28e6b1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/qanda.defaultlabel.xml": {
    "bytes": 2922,
    "gid": 0,
    "mode": 420,
    "sha256": "663abcf606d61c9efb45926c59fc3f5a9492f6d93b7ba0b3835988e138264dfd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/qanda.in.toc.xml": {
    "bytes": 1196,
    "gid": 0,
    "mode": 420,
    "sha256": "d5165df24680bed8ccbbf345f4119ca92c17a0212ffee3a81aa8d26516eb6e95",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/qanda.inherit.numeration.xml": {
    "bytes": 1085,
    "gid": 0,
    "mode": 420,
    "sha256": "8795855973c9f5f7da22ff0335e7c4af1c26da11cdf13031d97d123a7568cbb0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/qanda.nested.in.toc.xml": {
    "bytes": 985,
    "gid": 0,
    "mode": 420,
    "sha256": "f033eb4bfedfaddecef88246bb8b7df5d296e2f4c5f0395c2901000d2483b83b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/qanda.title.level1.properties.xml": {
    "bytes": 1105,
    "gid": 0,
    "mode": 420,
    "sha256": "b244a1c96f6eeeda7b9da30e2d19021e95d0acea78d082e1923d15acebe33968",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/qanda.title.level2.properties.xml": {
    "bytes": 1104,
    "gid": 0,
    "mode": 420,
    "sha256": "8f79032a7554d1042b03749dc6cf949b1a5d5ee6794bb9131e0bd345faf42e2f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/qanda.title.level3.properties.xml": {
    "bytes": 1103,
    "gid": 0,
    "mode": 420,
    "sha256": "eae13222d4ec9dee48885b2d5f317fcb035eb1b7bc4657e8accd1b6c311f7287",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/qanda.title.level4.properties.xml": {
    "bytes": 1102,
    "gid": 0,
    "mode": 420,
    "sha256": "826f91ff7fe043f6a989ca965d36e9f78ebad86acd50c17b0ccd519bcdc13e62",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/qanda.title.level5.properties.xml": {
    "bytes": 1096,
    "gid": 0,
    "mode": 420,
    "sha256": "cb17ac4bf7e6a6086797181d37bcad939377cae6d4a1be5d1a77ce6e5f0c4fc4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/qanda.title.level6.properties.xml": {
    "bytes": 1161,
    "gid": 0,
    "mode": 420,
    "sha256": "6806262d611738e48abfdfb7cb55da191a4afaef8f90ab10a9e78ee39c789773",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/qanda.title.properties.xml": {
    "bytes": 1434,
    "gid": 0,
    "mode": 420,
    "sha256": "4a9bb61e18c94a0ce32278ca1364365053356fb080ea5c023e84b26ab92c6de3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/qandadiv.autolabel.xml": {
    "bytes": 896,
    "gid": 0,
    "mode": 420,
    "sha256": "19d8ed7bf2bd1e370bd371ce50185cab24bb0ec64967f0b2d4b6a41eb4a7aad5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/rebuild-all.xml": {
    "bytes": 1320,
    "gid": 0,
    "mode": 420,
    "sha256": "b32444df5bc6eab6675da4abaead2823e79b7cd557f5352806441e7268277ddb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refclass.suppress.xml": {
    "bytes": 978,
    "gid": 0,
    "mode": 420,
    "sha256": "6e279b8c8c9a80dfd71819fe16b19daf954ceec59c70cf296282cc242ba4d0f9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.date.profile.enabled.xml": {
    "bytes": 1917,
    "gid": 0,
    "mode": 420,
    "sha256": "bbb3b19668d9a9c7299de751de026c39294a59a4df8253ddc10e125425a4ff70",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.date.profile.xml": {
    "bytes": 1453,
    "gid": 0,
    "mode": 420,
    "sha256": "de83b85efe1d17f9830511f6c885e23d42bd348c644acfdce62d156d03b0c3ea",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.generate.name.xml": {
    "bytes": 1219,
    "gid": 0,
    "mode": 420,
    "sha256": "169612731b1e8ec5d2ec3cc549d9fddef45af18b2c1f89a3b23ed08f23012ba0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.generate.title.xml": {
    "bytes": 1232,
    "gid": 0,
    "mode": 420,
    "sha256": "05685a45bc550a82a6512be55bb34d43cb2dbb4ab66cc5a7511b6821297ae3c5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.manual.fallback.profile.xml": {
    "bytes": 2003,
    "gid": 0,
    "mode": 420,
    "sha256": "fc62cddd7fd0dc3612a1205a21b263c1a8e881a83c60c9afd74ababe7e99c36d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.manual.profile.enabled.xml": {
    "bytes": 1934,
    "gid": 0,
    "mode": 420,
    "sha256": "f5c49cef0232ab04e00d9cddbf41239530520723d4b56a468a6ecb54c9445baf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.manual.profile.xml": {
    "bytes": 2430,
    "gid": 0,
    "mode": 420,
    "sha256": "61948e01c912bf8359b6ebaa0508e9e66bd8fd363c79c24e9ba58958d0efe0ad",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.meta.get.quietly.xml": {
    "bytes": 1366,
    "gid": 0,
    "mode": 420,
    "sha256": "9d75936552b1063766c8629f9fb92097820cd986937318c69fcf32b9815d5079",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.pagebreak.xml": {
    "bytes": 1313,
    "gid": 0,
    "mode": 420,
    "sha256": "b77982b23ccadd626d8e203ecefd7640caa1f24cefbad97440882f2285540163",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.separator.xml": {
    "bytes": 942,
    "gid": 0,
    "mode": 420,
    "sha256": "efd53017d472ec0550417fbba9f2b714d1a8e8c53da0e842d5b0f9ce000d2f45",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.source.fallback.profile.xml": {
    "bytes": 2079,
    "gid": 0,
    "mode": 420,
    "sha256": "6e108bd47c29cd370c870f0f45090e47056a75a09f576e5347902462b55ca4b2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.source.name.profile.enabled.xml": {
    "bytes": 2022,
    "gid": 0,
    "mode": 420,
    "sha256": "40d05b5209a17ffb3aba2e2dd13c3342b44b7a1b5c5c2562309a716040594c14",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.source.name.profile.xml": {
    "bytes": 3458,
    "gid": 0,
    "mode": 420,
    "sha256": "c7d4c7c6f7a95a6bc06327327e7594a0ec0e38aca49c8ca23de4372d8e598861",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.source.name.suppress.xml": {
    "bytes": 1804,
    "gid": 0,
    "mode": 420,
    "sha256": "79af6d4cc6861254c96a2d0b3723becf813e1f6c4d2e9de9333d4df38b11b6da",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.title.properties.xml": {
    "bytes": 2626,
    "gid": 0,
    "mode": 420,
    "sha256": "700444c2a07665514c9d455449ea492aee05196bf25618ab4f7e59d5f6446a6c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.version.profile.enabled.xml": {
    "bytes": 1962,
    "gid": 0,
    "mode": 420,
    "sha256": "7b35af7fc4116d8e1d5d0aafdf7241febe5aaeadac05fc6abc3169f17eb2d4c1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.version.profile.xml": {
    "bytes": 1618,
    "gid": 0,
    "mode": 420,
    "sha256": "2f61fa2163c53e8e5aef305fd25fb4d464671c78d89aa060b0c5d6994f485bc9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.version.suppress.xml": {
    "bytes": 1779,
    "gid": 0,
    "mode": 420,
    "sha256": "bcdab526cc116b072f92420fe3c1d66d5eba16ff0510e95fde29ca4dd1bcc577",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/refentry.xref.manvolnum.xml": {
    "bytes": 1055,
    "gid": 0,
    "mode": 420,
    "sha256": "f1941eaae65e7b135e2884bbdcf24af8bef6cb0e8bd02f57f3de3bb21d4f9e20",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/reference.autolabel.xml": {
    "bytes": 2423,
    "gid": 0,
    "mode": 420,
    "sha256": "5e981d211cee173a894440811079836154f3640acb8ed442bb2e89e6c55896a0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/region.after.extent.xml": {
    "bytes": 928,
    "gid": 0,
    "mode": 420,
    "sha256": "65e0f473e7b118d92a436db8c66123e19dbfd77f52d908778764f36bff692a4a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/region.before.extent.xml": {
    "bytes": 933,
    "gid": 0,
    "mode": 420,
    "sha256": "0450514598b5bf36b034dac82d682b1b659797878f6ab01592dd5c99ad99cff1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/region.inner.extent.xml": {
    "bytes": 1849,
    "gid": 0,
    "mode": 420,
    "sha256": "70d093d0e8fc6d0e126f8927335e6cd35f0b31f8ebfd089ef8c69c06fca31f6b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/region.inner.properties.xml": {
    "bytes": 1910,
    "gid": 0,
    "mode": 420,
    "sha256": "0debe1ffac888ba8fb00c68a507bb470f03abef20f92f56f9047ec1424610647",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/region.outer.extent.xml": {
    "bytes": 1859,
    "gid": 0,
    "mode": 420,
    "sha256": "98a0b6f28b37d656beb170916b0353fea50b4b1688034e0466116baa7fb84caa",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/region.outer.properties.xml": {
    "bytes": 1923,
    "gid": 0,
    "mode": 420,
    "sha256": "cb1fe83438f55a5a199fbd20d1ec8786263327b6d889f725f7ba674b8cfdd808",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/revhistory.table.cell.properties.xml": {
    "bytes": 1037,
    "gid": 0,
    "mode": 420,
    "sha256": "f999fb1857eea3d4a6ffc9e070753afe4626661da52828ca9d5b38cec8f834b9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/revhistory.table.properties.xml": {
    "bytes": 986,
    "gid": 0,
    "mode": 420,
    "sha256": "26198bf04b5eec7f7016b7736370f93ce9b9a001424d303c52629ff774ca76b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/revhistory.title.properties.xml": {
    "bytes": 966,
    "gid": 0,
    "mode": 420,
    "sha256": "1b8834dd553520822fb6449b095f983a6b7b58c60cef64a74629126dedcc43b1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/root.filename.xml": {
    "bytes": 963,
    "gid": 0,
    "mode": 420,
    "sha256": "80ab242d60df263f914a4c25c5e86daa58798750d7077fba12cf7e0effa85b9b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/root.properties.xml": {
    "bytes": 1640,
    "gid": 0,
    "mode": 420,
    "sha256": "8f630944991fa6f5ef473fb922bf8478f454da639a339aca464aec744953ec2f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/rootid.xml": {
    "bytes": 1272,
    "gid": 0,
    "mode": 420,
    "sha256": "f8ddc11c1b53dbb09dbb0ada2f128ed157f685f03f4d32bed60a5bce915bb2e9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/runinhead.default.title.end.punct.xml": {
    "bytes": 1081,
    "gid": 0,
    "mode": 420,
    "sha256": "eb94e31587cb77f42a871b99bb716786b4ed4d50d9a0156b89cdedec7a6125a3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/runinhead.title.end.punct.xml": {
    "bytes": 1197,
    "gid": 0,
    "mode": 420,
    "sha256": "8ac1bf818c2d445bc2f61fb242f1ccab311d92fdebc7d4044924608e9e2bdf35",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/running.foot.properties.xml": {
    "bytes": 1243,
    "gid": 0,
    "mode": 420,
    "sha256": "1adbc234db2f8538b75ea056ce596c830fa54f329b3756526e777839b89464ef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/s5.controls.xml": {
    "bytes": 903,
    "gid": 0,
    "mode": 420,
    "sha256": "5fcccad1e7b1e8c2bcc0f1e3bb50b0231cbcd704fa7727fc8f8a9544ad8828d9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/s5.defaultview.xml": {
    "bytes": 1055,
    "gid": 0,
    "mode": 420,
    "sha256": "d4d55aa2028fe80ed63dde49032ed58dfe0c6c663c989c458f94f8893d6b0bfb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/s5.opera.css.xml": {
    "bytes": 917,
    "gid": 0,
    "mode": 420,
    "sha256": "154f679792dc16e6fcb5bf119446ddd597081edd8c2c4dff54a5feb7f3d83a4a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/s5.outline.css.xml": {
    "bytes": 913,
    "gid": 0,
    "mode": 420,
    "sha256": "01d837270b01a8675f49c06d01e0179c4576f0724f035eb6e62fa9fdbe786b14",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/s5.path.prefix.xml": {
    "bytes": 999,
    "gid": 0,
    "mode": 420,
    "sha256": "c7ef83e4d918ca42cdeaccbc698d3b1c32f9f7ac085d3c21cf20727e911e35ca",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/s5.print.css.xml": {
    "bytes": 897,
    "gid": 0,
    "mode": 420,
    "sha256": "4d5a17b8534f6da3f6366f85ed63bbc35b27611c8f5d145b7ffdae7b13382e9e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/s5.slides.css.xml": {
    "bytes": 905,
    "gid": 0,
    "mode": 420,
    "sha256": "0dcec14e563628329810f30c3d5a5e59a8a6cf5f0f868947c4b594dcc4a7cfa9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/s5.slides.js.xml": {
    "bytes": 915,
    "gid": 0,
    "mode": 420,
    "sha256": "be4b1f1ef01d8b3852aff55f9a51da540f6e8cdd8b6724303ec806981f1a40b3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/sans.font.family.xml": {
    "bytes": 938,
    "gid": 0,
    "mode": 420,
    "sha256": "909aff0911b96622e8e4755313edbd205a8c1ed3165547e681aef8a82c7fb191",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/saxon.callouts.xml": {
    "bytes": 946,
    "gid": 0,
    "mode": 420,
    "sha256": "ecdadf3808400f4acd20bd11272356619a5e089ee2aedc761e9a5bfc111185d5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/saxon.character.representation.xml": {
    "bytes": 1606,
    "gid": 0,
    "mode": 420,
    "sha256": "92d9bc942ffd361dc7d8f29129897f6382f45017e1bbb2337dd7e919fb666cfc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/saxon.linenumbering.xml": {
    "bytes": 1113,
    "gid": 0,
    "mode": 420,
    "sha256": "3a61ea86de97d173af45483269bb711812adc74b01b7a0547257c8fe86e66a7d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/saxon.tablecolumns.xml": {
    "bytes": 1007,
    "gid": 0,
    "mode": 420,
    "sha256": "4e8d822b89bdea60ecc23ceffbc4afa89b0d4b75a74037e8a2a3d16584e60a3f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/script.dir.xml": {
    "bytes": 1046,
    "gid": 0,
    "mode": 420,
    "sha256": "0ee59d35fb45815a474171062cb003acb32f74e66477b91f94b336077aa0b27c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.autolabel.max.depth.xml": {
    "bytes": 1156,
    "gid": 0,
    "mode": 420,
    "sha256": "0dc307f83849283ce4db457d401ef7fd5f152409979c7e3ea6a630f94fa284d0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.autolabel.xml": {
    "bytes": 883,
    "gid": 0,
    "mode": 420,
    "sha256": "7be04bf6341c7a4f71036585e950eef371a3fa670db56b80eb9eff4a121b7f8c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.container.element.xml": {
    "bytes": 2337,
    "gid": 0,
    "mode": 420,
    "sha256": "41ca25552bc0821d7facf43a48d30a3df5fd25a69ce923f6c7acebf71c4d59f5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.label.includes.component.label.xml": {
    "bytes": 1044,
    "gid": 0,
    "mode": 420,
    "sha256": "20d38975a288144d3a108a10cfdf8b15aaf497b2db887fb0d44c5cd6a5fce405",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.level1.properties.xml": {
    "bytes": 1529,
    "gid": 0,
    "mode": 420,
    "sha256": "ac04ebbcf36cadb95202bb21911e5c519b54ccfd731cc063908e518539984b15",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.level2.properties.xml": {
    "bytes": 1529,
    "gid": 0,
    "mode": 420,
    "sha256": "b38cbbc83571a53f892aee13edc6da2c2379252640e203ad0098f2219fad103c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.level3.properties.xml": {
    "bytes": 1529,
    "gid": 0,
    "mode": 420,
    "sha256": "abdb86d27a7a847a60baf3aafe0d540b0817bfe604ba56c9b26e22b565220e3e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.level4.properties.xml": {
    "bytes": 1529,
    "gid": 0,
    "mode": 420,
    "sha256": "c78a42d20a397857e97d7b91f6b53b83b688c9d76101e5f84cd455df460c2868",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.level5.properties.xml": {
    "bytes": 1529,
    "gid": 0,
    "mode": 420,
    "sha256": "cf82dc366666688a65e93f05379f7e48620f71537eae0d963ae8c04f835d47ee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.level6.properties.xml": {
    "bytes": 1519,
    "gid": 0,
    "mode": 420,
    "sha256": "16bfdd2e915eee1125dc204e9e8372d57e34a597e96cd5991874bae08d08adf9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.properties.xml": {
    "bytes": 1116,
    "gid": 0,
    "mode": 420,
    "sha256": "183ea02f1681fece4750dab07efe113a92276475ede4bcba348a5eb8868f6c75",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.title.level1.properties.xml": {
    "bytes": 1111,
    "gid": 0,
    "mode": 420,
    "sha256": "1b348f642e12843441363c3b7399260c6619b4798e09db2807cf7d9c823e53af",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.title.level2.properties.xml": {
    "bytes": 1111,
    "gid": 0,
    "mode": 420,
    "sha256": "574205d6486514306bbc9effb9a8568bacded42233813142ac1cb13adeef6dac",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.title.level3.properties.xml": {
    "bytes": 1109,
    "gid": 0,
    "mode": 420,
    "sha256": "0413129d0e8568bdd27fe87cf1d31b9ef4f2f1550e976375a6c05e0302dd62e7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.title.level4.properties.xml": {
    "bytes": 1108,
    "gid": 0,
    "mode": 420,
    "sha256": "7e10ccdd638376dafb0dfc7c4320b3753954befa03a5a376b6b856bd212a31e5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.title.level5.properties.xml": {
    "bytes": 1102,
    "gid": 0,
    "mode": 420,
    "sha256": "c4515dee47128ba1e799ad2c878ef35146d2f102c79e82139036d55180e3ce2a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.title.level6.properties.xml": {
    "bytes": 1167,
    "gid": 0,
    "mode": 420,
    "sha256": "16a46bd9e6893430e4b4e2a53a3670e0b78d30d37e20749b80b2dee273cf7e7d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/section.title.properties.xml": {
    "bytes": 1596,
    "gid": 0,
    "mode": 420,
    "sha256": "196dec7b8b58e06aeb77c0d29aafa549753ae98e00c5119b5b17cc47e9817a1b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/segmentedlist.as.table.xml": {
    "bytes": 927,
    "gid": 0,
    "mode": 420,
    "sha256": "21f2d19319e991c846b846a0a4c4012dc150d779201171def745131789733e6f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/sequential.links.xml": {
    "bytes": 824,
    "gid": 0,
    "mode": 420,
    "sha256": "64016fb66288223e5536390673125cdbbb4548dc8ae933925737318e3217b081",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/shade.verbatim.style.xml": {
    "bytes": 1492,
    "gid": 0,
    "mode": 420,
    "sha256": "faeb9aa184a57fe8ef3d01fe2dd1c84639a4f3112002217af9653da00e78aa7b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/shade.verbatim.xml": {
    "bytes": 1068,
    "gid": 0,
    "mode": 420,
    "sha256": "3fcb7d5bdb012d95b868db32dcb5a9aad1e7b88037b8b0249309bc1d6c95be19",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/show.bookmarks.xml": {
    "bytes": 991,
    "gid": 0,
    "mode": 420,
    "sha256": "0b356dc3add2057542d74f4b1e89ae84f38a93fc8f906d131f1aaf9c64ffcb19",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/show.comments.xml": {
    "bytes": 1078,
    "gid": 0,
    "mode": 420,
    "sha256": "a8e1e3b74d06476a0ac35c67b576944ce90da6364ac78523b0b6a7f03b77e976",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/show.foil.number.xml": {
    "bytes": 926,
    "gid": 0,
    "mode": 420,
    "sha256": "8d589adca9b57f340ed0065c744f96f0c96a999e9ad2c70f7d3657b5d4f24063",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/show.revisionflag.xml": {
    "bytes": 1748,
    "gid": 0,
    "mode": 420,
    "sha256": "56fa7982c0a8d8a6afdc8e21adc9ce07cd4df6500d1a9f2b16a24b0506fdcd03",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/showtoc.image.xml": {
    "bytes": 963,
    "gid": 0,
    "mode": 420,
    "sha256": "ca6366ac7dd4dfd95a351e197b259c9644eb0f6c1035ffef08c33123477395c1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/side.float.properties.xml": {
    "bytes": 2008,
    "gid": 0,
    "mode": 420,
    "sha256": "7798a7d874ef614b192506d1fef68f0c8b908fe9977ad45e27b5ab57b9e838c8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/side.region.precedence.xml": {
    "bytes": 2291,
    "gid": 0,
    "mode": 420,
    "sha256": "7181b092be57ae0229850550c3b37bcd296aa4f24bedda70599a64719fb133d6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/sidebar.float.type.xml": {
    "bytes": 2984,
    "gid": 0,
    "mode": 420,
    "sha256": "e5cade98ad26b4424037ba31768e3cbbe04a1d6718cb64c925cd2b0fc860b9c3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/sidebar.float.width.xml": {
    "bytes": 1179,
    "gid": 0,
    "mode": 420,
    "sha256": "eb9e4797232f9ba33467cececd4953cd754dc3625dc48e800a23f7bbdd14691c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/sidebar.properties.xml": {
    "bytes": 1680,
    "gid": 0,
    "mode": 420,
    "sha256": "29083197e5c971bc6286766b76c575b0270a30d4031682050e80e887bed7061a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/sidebar.title.properties.xml": {
    "bytes": 1170,
    "gid": 0,
    "mode": 420,
    "sha256": "fe73823a3681b3cc9b2ac998f57a8a594f253a2f8e7ba042a288393c1fb6d66b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/simplesect.in.toc.xml": {
    "bytes": 921,
    "gid": 0,
    "mode": 420,
    "sha256": "6130fc93ca0da6c9d64b01f01451f6c8cb151edd07594392fc8599a6af44ccd5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slide.font.family.xml": {
    "bytes": 1181,
    "gid": 0,
    "mode": 420,
    "sha256": "c605f03bc8e40dff2b58c276e1aac492330190911256c7d36c247b711a80da33",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slide.title.font.family.xml": {
    "bytes": 1210,
    "gid": 0,
    "mode": 420,
    "sha256": "2bb558a8701b10c0c4c957323448ee83e2235908d78e2fdd7a57c22008f6d98f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slides.js.xml": {
    "bytes": 909,
    "gid": 0,
    "mode": 420,
    "sha256": "9fa47376c44773778bd680b93f77bfdd1095701185bd2603741c517188acf07e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slides.properties.xml": {
    "bytes": 1055,
    "gid": 0,
    "mode": 420,
    "sha256": "f8aed9ff513eaeb5f77f0f9d0ea164f0053506ebe6759a0eeeccbb1b3f41094a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slides.titlepage.author.properties.xml": {
    "bytes": 1232,
    "gid": 0,
    "mode": 420,
    "sha256": "a99e9538fe78e3113afa3909a1bf55a424ba326d74bc701bcfa1c41e9c8a91db",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slides.titlepage.authorgroup.properties.xml": {
    "bytes": 1053,
    "gid": 0,
    "mode": 420,
    "sha256": "49cfbf0beb22187847939d3393a43cf94caa4ddaa86efadcdd14cb2c8304ef55",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slides.titlepage.corpauthor.properties.xml": {
    "bytes": 1256,
    "gid": 0,
    "mode": 420,
    "sha256": "01c672db95b1e8720b141b28f4f8e9dcb86899d04b466775c1ab7df653c1d7c6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slides.titlepage.master.properties.xml": {
    "bytes": 1721,
    "gid": 0,
    "mode": 420,
    "sha256": "700ce9489214dfc3f04a2cae7f6e189afb424361d70324bd8620357a7ba1581b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slides.titlepage.pubdate.properties.xml": {
    "bytes": 1237,
    "gid": 0,
    "mode": 420,
    "sha256": "b113d909b7ad42b723dc6f59f529546cdc2d4071f320bfef4e58a68b94bb2274",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slides.titlepage.region-body.properties.xml": {
    "bytes": 1311,
    "gid": 0,
    "mode": 420,
    "sha256": "c7c8e03d5e123fb584eb024b1d3ed07a4c6fe73db48f1d32eade87977d221890",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slides.titlepage.subtitle.properties.xml": {
    "bytes": 1296,
    "gid": 0,
    "mode": 420,
    "sha256": "50720d782fa804de6c4b474f2a241f011b161b583a2068746717a2070cd00514",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slides.titlepage.title.properties.xml": {
    "bytes": 1572,
    "gid": 0,
    "mode": 420,
    "sha256": "36c1d1aee2979bc6f894adaf8bc608f77ff302bf6123ff38c01ffdca198afc02",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slidy.duration.xml": {
    "bytes": 1023,
    "gid": 0,
    "mode": 420,
    "sha256": "c331755519af8e5e2791c56890f2fa6895e80f2c23fe87130d4e4e1c0f346dd4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slidy.path.prefix.xml": {
    "bytes": 1012,
    "gid": 0,
    "mode": 420,
    "sha256": "1a587f8f7d574ab4663e9bb1f9840d6614f92a97ad0feb3b92cf43673b022b9d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slidy.slidy.css.xml": {
    "bytes": 923,
    "gid": 0,
    "mode": 420,
    "sha256": "c05c28488aed5a0120133ffc9a29b4850d75b3b96ea1f111561ba5a5d7cc0ec4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slidy.slidy.js.xml": {
    "bytes": 922,
    "gid": 0,
    "mode": 420,
    "sha256": "0a1cabd8f5d80059df602ddf20c5ebe6f2a2ee9e877459878807cd686bd3e2ea",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/slidy.user.css.xml": {
    "bytes": 921,
    "gid": 0,
    "mode": 420,
    "sha256": "75340ebfbd0590ee624e3e84fdae357d10c16cf46f7c32c3535da6fa58886fee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/spacing.paras.xml": {
    "bytes": 1010,
    "gid": 0,
    "mode": 420,
    "sha256": "c9a0147cb59c3721e33b6dbbbe4441990aa3dba57038ff00027d69889b86612a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/speaker.properties.xml": {
    "bytes": 1026,
    "gid": 0,
    "mode": 420,
    "sha256": "6319879036cb662c8b6cb1e3391caa877dc6d42a6deee36e81d91bc79e1080d0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/speakernote.properties.xml": {
    "bytes": 1228,
    "gid": 0,
    "mode": 420,
    "sha256": "ef8df15b6ef136a2a4a315b13298775f4f7a98c4d02a5a5f3b3562dd5844c049",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/speakernotes.properties.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "6729747a18efe20c02eb8203b175b13b95af1ae62da880aa571b2105a3c52d68",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/stagedir.properties.xml": {
    "bytes": 1292,
    "gid": 0,
    "mode": 420,
    "sha256": "5037c53a27a693ec4a013eda36c00b52d09ba72ef7a272baa627a19ba4e5c7bc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/subscript.properties.xml": {
    "bytes": 975,
    "gid": 0,
    "mode": 420,
    "sha256": "9328322068c5d001fd3f6b46575e0d89809a42c57c28cf7ab800520e52907076",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/superscript.properties.xml": {
    "bytes": 989,
    "gid": 0,
    "mode": 420,
    "sha256": "0406c85d0bbdd9db5c1a65bd17f24bb51c452e1d47c4c02086265a42c5e9be8a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/suppress.footer.navigation.xml": {
    "bytes": 922,
    "gid": 0,
    "mode": 420,
    "sha256": "eb3f10bc7d98ba65909c1d2dfccacfa37c5be88fcf7eaee168ae217586a50143",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/suppress.header.navigation.xml": {
    "bytes": 922,
    "gid": 0,
    "mode": 420,
    "sha256": "7f5f67d74e1e11bf26383824be1198222aa46fe80862712803d85fe90eb7e0bf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/suppress.homepage.title.xml": {
    "bytes": 916,
    "gid": 0,
    "mode": 420,
    "sha256": "11debb4874643ce1263bf9467be40abac0fb0c4a8473f50e52de858826e69d82",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/suppress.navigation.xml": {
    "bytes": 910,
    "gid": 0,
    "mode": 420,
    "sha256": "0d2783fcbc03b2c07a0b31493fc46a16ba516a6c9ef8b5b03a3446596a7e2fa1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/svg.embedding.mode.fo.xml": {
    "bytes": 1786,
    "gid": 0,
    "mode": 420,
    "sha256": "aba56b5b9b7bf401adcd26512790f220d49a4c221ece6f813daf925a2959fa43",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/svg.embedding.mode.xml": {
    "bytes": 2590,
    "gid": 0,
    "mode": 420,
    "sha256": "d04c50105f0348337a26ef51f0c0d8a5c23389d2a35922b6f33a26f095d05a36",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/symbol.font.family.xml": {
    "bytes": 1711,
    "gid": 0,
    "mode": 420,
    "sha256": "2801694195be0238b7971a332d4a94d7cfec0ad379d436b72bf412ebadab1b3b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.borders.with.css.xml": {
    "bytes": 928,
    "gid": 0,
    "mode": 420,
    "sha256": "bd74262b185b8653a43b00d077cf023c00f93ca8653546829e1871a4b1be04a6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.caption.properties.xml": {
    "bytes": 1101,
    "gid": 0,
    "mode": 420,
    "sha256": "5c5188ed3bf1401a656f012070f9a6b906dfa13b099e03c70958c7cc6d03618f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.cell.border.color.xml": {
    "bytes": 1535,
    "gid": 0,
    "mode": 420,
    "sha256": "3f2eabda0dbbf9fe876bbbf14bbd40e2ff59997f59866657a8a98dae9b106369",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.cell.border.style.xml": {
    "bytes": 1786,
    "gid": 0,
    "mode": 420,
    "sha256": "36879cc5e24cd9a40108386d678b2b5b6bf6f32e1ea913ce956b33f2768746e9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.cell.border.thickness.xml": {
    "bytes": 1375,
    "gid": 0,
    "mode": 420,
    "sha256": "eb3f4acf5c1c74af407f351348c0bdd1a83897eb230f9997721679a70acb0a80",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.cell.padding.xml": {
    "bytes": 1132,
    "gid": 0,
    "mode": 420,
    "sha256": "43fafdda26cc5918472ff832729ed65d126b778c2f160e5e6422017e055a6e5b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.entry.padding.xml": {
    "bytes": 808,
    "gid": 0,
    "mode": 420,
    "sha256": "e4e032bdaf1ba57b696440eb7e54a9177e1427599740177b3988aea0e6bbe514",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.footnote.number.format.xml": {
    "bytes": 1461,
    "gid": 0,
    "mode": 420,
    "sha256": "8e6ffb75da9c9e679d9767b61e25b577652433af43248a77f6dd89e38ef12068",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.footnote.number.symbols.xml": {
    "bytes": 1811,
    "gid": 0,
    "mode": 420,
    "sha256": "53ce67b8d750dd6d0e772e37989e8fe6533e5a40812e27c06e968175a33124ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.footnote.properties.xml": {
    "bytes": 1564,
    "gid": 0,
    "mode": 420,
    "sha256": "d910fb6821b020a13e3a236bd891754d2b2f5f3b547afced7cb96a04e9d3b4f4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.frame.border.color.xml": {
    "bytes": 1013,
    "gid": 0,
    "mode": 420,
    "sha256": "e0a8559dabb09adcb4bdda27ef908e8abfc4f1f161065857a13d96dbe1db57b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.frame.border.style.xml": {
    "bytes": 1622,
    "gid": 0,
    "mode": 420,
    "sha256": "a38afb096071bac7300d28c6e7d86cdd36c9d7164e902bc5c9948891b9a1b831",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.frame.border.thickness.xml": {
    "bytes": 1108,
    "gid": 0,
    "mode": 420,
    "sha256": "045848bd1b40548d828eb1eb6afdd2749d1aa61f864ffff1ed2df38791400caf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.properties.xml": {
    "bytes": 1279,
    "gid": 0,
    "mode": 420,
    "sha256": "450663d58784159b13ae5760d08b7c6a37e46849734a1a768da73aab8c027743",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.spacer.image.xml": {
    "bytes": 1104,
    "gid": 0,
    "mode": 420,
    "sha256": "abb395016a0e07acd680570aa5ec037702c1092cf491b73540837bdd512974cc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/table.table.properties.xml": {
    "bytes": 1312,
    "gid": 0,
    "mode": 420,
    "sha256": "9ca7d12b43ab525d80cdd77d970d718afd782b023ee78ec2ca3ceb9bd2194fb6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/tablecolumns.extension.xml": {
    "bytes": 1027,
    "gid": 0,
    "mode": 420,
    "sha256": "6fc1e8ced0f8c468c881afcf2878552d4be5f99b7f3ab2e437647da1e64e485f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/target.database.document.xml": {
    "bytes": 1653,
    "gid": 0,
    "mode": 420,
    "sha256": "ac4d6981ab2cec3580336d05993f300d987bc7ab45b03dbbe0b225a8e9744819",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/targets.filename.xml": {
    "bytes": 1307,
    "gid": 0,
    "mode": 420,
    "sha256": "d48f00d8c4cbc73236b30955f1d9d44a01a8d58ee37fdb801dba8807f62d6ca7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/task.properties.xml": {
    "bytes": 1032,
    "gid": 0,
    "mode": 420,
    "sha256": "668b04c784f28c5ce4a55189547951e94efe07d41df5103257834803802984a9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/template.xml": {
    "bytes": 730,
    "gid": 0,
    "mode": 420,
    "sha256": "4fcab5ca777797a885e3129b31ac7d660d1b9b375814af278da757809eeb75fe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/tex.math.delims.xml": {
    "bytes": 1529,
    "gid": 0,
    "mode": 420,
    "sha256": "e3c31ec08f185d929f87c9a30b7e44813a77099c8558719953dfdcfe59607202",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/tex.math.file.xml": {
    "bytes": 1435,
    "gid": 0,
    "mode": 420,
    "sha256": "a0b4d156100eaeca910c77993aa76dd81fe34071ccf6468c356ff9683fd44218",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/tex.math.in.alt.xml": {
    "bytes": 2793,
    "gid": 0,
    "mode": 420,
    "sha256": "709b08b2de5297091656826d132e650a3f3b98d4cda19245e82a22a4365ca1f3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/text.home.xml": {
    "bytes": 775,
    "gid": 0,
    "mode": 420,
    "sha256": "4682998b3cb9355234e24b447c8a6ecc24f58385e5ebfb8edd0ef28713fcf2b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/text.next.xml": {
    "bytes": 777,
    "gid": 0,
    "mode": 420,
    "sha256": "37d1b273929a34345dce6d441aa8f2ef57344371b37f147bb9701af17fc9e5d7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/text.prev.xml": {
    "bytes": 777,
    "gid": 0,
    "mode": 420,
    "sha256": "8052d67b033bcb142f1f6f705cc91097aba4910318538c16c7b4e931d04cdae0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/text.toc.xml": {
    "bytes": 771,
    "gid": 0,
    "mode": 420,
    "sha256": "79f74495efdbb3a0cd2d9d040699bcc8f9983e44565f44f89aba36e999273217",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/text.up.xml": {
    "bytes": 766,
    "gid": 0,
    "mode": 420,
    "sha256": "a636806a7b3c32358f33a0923f9d800ee1a817fd41da90b238d6e2d18bdbf9f4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/textbgcolor.xml": {
    "bytes": 921,
    "gid": 0,
    "mode": 420,
    "sha256": "f4761614e664eec9319826c76bda5ddb9675dd48dcfeceb93397e29b1793203a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/textdata.default.encoding.xml": {
    "bytes": 1210,
    "gid": 0,
    "mode": 420,
    "sha256": "e008fc6888b2e72927f95e52d7c2176a390bca308c222e2ff6402d1ad1f05a86",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/textinsert.extension.xml": {
    "bytes": 2875,
    "gid": 0,
    "mode": 420,
    "sha256": "4c19746c7ed47bcceeb50831fa95cab8dd3c8bd5fb958d167581484f09230728",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/title.font.family.xml": {
    "bytes": 1399,
    "gid": 0,
    "mode": 420,
    "sha256": "48805929e7761b7f097d86504f51f4d88ec34bc0d444c3b4b37a4a82c76c7cb2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/title.margin.left.xml": {
    "bytes": 2184,
    "gid": 0,
    "mode": 420,
    "sha256": "c2539a49f913d8f891d172bfb790f567c771be03d9e38ed29e9abcfa82cd733c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/titlefoil.html.xml": {
    "bytes": 889,
    "gid": 0,
    "mode": 420,
    "sha256": "fbbfc55bad6c86a001f0820697402dcf03f334b984691c47b4416e54db08bea4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.bg.color.xml": {
    "bytes": 865,
    "gid": 0,
    "mode": 420,
    "sha256": "dffcea7c53b4a42aab67ed3908cc9eadc690903176b98188ce4fec73cef04677",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.blank.graphic.xml": {
    "bytes": 1029,
    "gid": 0,
    "mode": 420,
    "sha256": "587017709980e41bb833dae7fd149a833660c29e96d8ac484d7aae777148e399",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.blank.image.xml": {
    "bytes": 1017,
    "gid": 0,
    "mode": 420,
    "sha256": "239b4275c7ce43127826e34eb3a1fd33f39f61cc82b9a812e816112d29f06d66",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.blank.text.xml": {
    "bytes": 1008,
    "gid": 0,
    "mode": 420,
    "sha256": "a56732905345941d99530f8071773defc49b613a763035ede722ce268aa78cec",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.hide.show.xml": {
    "bytes": 1221,
    "gid": 0,
    "mode": 420,
    "sha256": "09e985969d57f22d0cf113058e7cc9af700ecfa4cbfec32f71b77339e6baff24",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.html.xml": {
    "bytes": 856,
    "gid": 0,
    "mode": 420,
    "sha256": "93c5a21289b93a908ed5c9e8bde10ecd280934af0223884bc11d0503f659e9c4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.image.xml": {
    "bytes": 840,
    "gid": 0,
    "mode": 420,
    "sha256": "88daf147ddfa10c575fea260c5a0dea140edb703135506d6828c50c9ec2e78b1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.indent.width.xml": {
    "bytes": 1250,
    "gid": 0,
    "mode": 420,
    "sha256": "199ab1d16a7ccf2beb47f84e992a3ed4bfb86118442bd0659032d46c7cb5ea02",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.leader.properties.xml": {
    "bytes": 1240,
    "gid": 0,
    "mode": 420,
    "sha256": "be5ea77706a73c978be214e4293aaeba7555afd220a66d7098586dccae9f7e64",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.line.properties.xml": {
    "bytes": 1797,
    "gid": 0,
    "mode": 420,
    "sha256": "7b6df9e390ccb628fdb3c320b1f1ef5df9ee44f5fd82184627d89f1f8c3a64b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.list.type.xml": {
    "bytes": 1155,
    "gid": 0,
    "mode": 420,
    "sha256": "4f3c3fc0a2068738157310aa0deb51bec8740a7ae90bcd79fff7795fbd3e6594",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.margin.properties.xml": {
    "bytes": 1427,
    "gid": 0,
    "mode": 420,
    "sha256": "f2f56f80a557241cccb40bf6774a85b6b231cff56385a79453d74dcedf937cf2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.max.depth.xml": {
    "bytes": 877,
    "gid": 0,
    "mode": 420,
    "sha256": "65036f97fea9c25a5f08b715e3ebfc9db11a2018657e405b9ca221a38e2c2646",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.pointer.graphic.xml": {
    "bytes": 1034,
    "gid": 0,
    "mode": 420,
    "sha256": "2a76973674b56fc038b472b6dc40be3741e91595ba54129f912539ff669467e6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.pointer.image.xml": {
    "bytes": 1036,
    "gid": 0,
    "mode": 420,
    "sha256": "39dabd73be3ae1bbb963d0e023945f17d940b92d372a6cb8c7f06ccd049e8123",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.pointer.text.xml": {
    "bytes": 1035,
    "gid": 0,
    "mode": 420,
    "sha256": "f602e2e74296fd109cd7a6b5c0aceb7f3faad4e24e3c9f2a22fca7d9ddb70b21",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.row.height.xml": {
    "bytes": 1210,
    "gid": 0,
    "mode": 420,
    "sha256": "5baf34dd2fcb16e581b7a910a18c7242b0ab8b54cb036a1706f543f4aeb73865",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.section.depth.xml": {
    "bytes": 939,
    "gid": 0,
    "mode": 420,
    "sha256": "4397a1d57e5b94400c1eeb4f55bcc1ada780ac1b7ba04cabd65382a5b2026aae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.spacer.graphic.xml": {
    "bytes": 1032,
    "gid": 0,
    "mode": 420,
    "sha256": "16bc2e0be482a61e23cd91f65f50376adda4c75e92efaafb9fc52541c3515b91",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.spacer.image.xml": {
    "bytes": 1010,
    "gid": 0,
    "mode": 420,
    "sha256": "37cc71564d0c21005d4cbdbe091bc88b091d3e55a68c0d87cdbe3d4b7e451de0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.spacer.text.xml": {
    "bytes": 1004,
    "gid": 0,
    "mode": 420,
    "sha256": "e1c951d530917cb65c622aa1c695828e92b6dfdf6fa9b10e65ec90641aa552e4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/toc.width.xml": {
    "bytes": 861,
    "gid": 0,
    "mode": 420,
    "sha256": "1d17ab416badf1482025eecfd2fea5981f193bcc4000ef758ef8de49fdcc1ee7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/ua.js.xml": {
    "bytes": 879,
    "gid": 0,
    "mode": 420,
    "sha256": "80d81370b8468ca5f43f5162f0cb3e6235ab4e339924b7bbe6758169df9e6865",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/ulink.footnotes.xml": {
    "bytes": 1265,
    "gid": 0,
    "mode": 420,
    "sha256": "d6a3d1a2706dcf0da0cf6f223a20e0b01116e5d3cf01baef61ab6a7c3a5759c1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/ulink.hyphenate.chars.xml": {
    "bytes": 1476,
    "gid": 0,
    "mode": 420,
    "sha256": "a6ae96c44d96dff47053701e9494c4bc176e6cde0a33aa9b41d7cc6622e6cd2d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/ulink.hyphenate.xml": {
    "bytes": 1563,
    "gid": 0,
    "mode": 420,
    "sha256": "27fbea60f3709770e82e5d19b6877742f4800c6fc6d8991c610f616fb4870305",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/ulink.show.xml": {
    "bytes": 1323,
    "gid": 0,
    "mode": 420,
    "sha256": "272778e479d90d8fd516628d88a42dc12219722bb624571d34b9824e2e86c0ca",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/ulink.target.xml": {
    "bytes": 975,
    "gid": 0,
    "mode": 420,
    "sha256": "27344f26da1fb1e879ad8520ea1e8b305576833809455cc0b73bdac33a43a08e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/up.image.xml": {
    "bytes": 852,
    "gid": 0,
    "mode": 420,
    "sha256": "f737b3ef3fa0be9dd09842ea29143ae8a26aa4c40fade4186e76cbdfe3ecd028",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/use.embed.for.svg.xml": {
    "bytes": 1217,
    "gid": 0,
    "mode": 420,
    "sha256": "5ff18c5b6fd863b8f548c8b343930f1bff2e52662078b08b7fcafdb83f0929c6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/use.extensions.xml": {
    "bytes": 982,
    "gid": 0,
    "mode": 420,
    "sha256": "4f5625b0f90bac05f572d95a6bc2d9d44d9fa28d5037328154d5156ff063d5e6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/use.id.as.filename.xml": {
    "bytes": 992,
    "gid": 0,
    "mode": 420,
    "sha256": "d47d6b8a47a45b84474c4fa42448d16bf3eae5a212795aedc56e69e0d48ce09d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/use.id.function.xml": {
    "bytes": 1195,
    "gid": 0,
    "mode": 420,
    "sha256": "fd88221629f3769b903e50173f48645c801736fee7f4636515b0aee87b4f7b5e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/use.local.olink.style.xml": {
    "bytes": 1740,
    "gid": 0,
    "mode": 420,
    "sha256": "f64c51da1962902b88c0f9faa1c3957197142e6831ca5673c7a2b22ac6e9e384",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/use.role.as.xrefstyle.xml": {
    "bytes": 3308,
    "gid": 0,
    "mode": 420,
    "sha256": "b8b1a7636310b25663d2aa408f39135e4de44be018c80b9261152c6319afd262",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/use.role.for.mediaobject.xml": {
    "bytes": 1940,
    "gid": 0,
    "mode": 420,
    "sha256": "dc450e296ed37d9c659b77b32d5f8c012636fe766d26294d2194b359e4de6059",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/use.svg.xml": {
    "bytes": 1043,
    "gid": 0,
    "mode": 420,
    "sha256": "7e6a7f22669ad63c9bc7d33c4b70da438a9e5ad2d768a7d770b86b433c95bfb0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/user.css.xml": {
    "bytes": 950,
    "gid": 0,
    "mode": 420,
    "sha256": "1bb5c4be788b2e3734d567ae4182cbcae215436b90156cd6fe6ce14d7fb96454",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/variablelist.as.blocks.xml": {
    "bytes": 2385,
    "gid": 0,
    "mode": 420,
    "sha256": "956faa7fb9e47b19d2e503bd854529b48eada32651290996c12a7b107965b856",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/variablelist.as.table.xml": {
    "bytes": 2097,
    "gid": 0,
    "mode": 420,
    "sha256": "38501f815da50256e2e050b895cacb802e8379cc1ab4a47df71c5a98574a34aa",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/variablelist.max.termlength.xml": {
    "bytes": 1689,
    "gid": 0,
    "mode": 420,
    "sha256": "d93b3cd7955eb161d7e7532f9278dca8845628a929fe76fe2b69e60d77e64433",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/variablelist.term.break.after.xml": {
    "bytes": 1455,
    "gid": 0,
    "mode": 420,
    "sha256": "4ddc191eb685231bc105e62cbec52c8dcd7c1a029a9caa2dd3e6290d97af4bdb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/variablelist.term.properties.xml": {
    "bytes": 1084,
    "gid": 0,
    "mode": 420,
    "sha256": "b42b7dd7242d44d011994ed727560c722df9f4c2c7876d9eda4aadda199ffa3f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/variablelist.term.separator.xml": {
    "bytes": 1603,
    "gid": 0,
    "mode": 420,
    "sha256": "dc01784f6c0bde80cac01aee2969877c2961e16c7a4fcc7dc82d72db38cfea37",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/verbatim.properties.xml": {
    "bytes": 1703,
    "gid": 0,
    "mode": 420,
    "sha256": "a3345b62d02813384e14ca073a9fb909aad39686ab00b60a4764088d446832d1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/webhelp.autolabel.xml": {
    "bytes": 939,
    "gid": 0,
    "mode": 420,
    "sha256": "8cc73c2745af1a39d0ac1789740c711f9a6e7c79f5fc7c66f39fa3bd951bee72",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/webhelp.base.dir.xml": {
    "bytes": 1075,
    "gid": 0,
    "mode": 420,
    "sha256": "3d74668e39a8fd21837fcb267e0546973cc72d528277639649a7fe74a295a0c2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/webhelp.common.dir.xml": {
    "bytes": 1380,
    "gid": 0,
    "mode": 420,
    "sha256": "12c80eb5d56f23d655ce974e09f3bf71fcbea4c02746119c6dd09ca8f7b1e088",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/webhelp.default.topic.xml": {
    "bytes": 1428,
    "gid": 0,
    "mode": 420,
    "sha256": "1e7bae6fc416aa5458e4783a1f8b784c6845922a9c65e0ee81c6683ca21e1af2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/webhelp.include.search.tab.xml": {
    "bytes": 964,
    "gid": 0,
    "mode": 420,
    "sha256": "ce05282cccc08d38451c566c0ed9366b95d25a1028b239d726f934adeb2a9af2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/webhelp.indexer.language.xml": {
    "bytes": 1564,
    "gid": 0,
    "mode": 420,
    "sha256": "ebd7e94fedf630c7a3d1d4d1c1382dab877ed1a373824b8bd389437fe7b8325d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/webhelp.start.filename.xml": {
    "bytes": 1394,
    "gid": 0,
    "mode": 420,
    "sha256": "99e0575eaa612f550afd15bd95d66ed83f3375e6c4f05d52af65c800809b06c3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/webhelp.tree.cookie.id.xml": {
    "bytes": 2247,
    "gid": 0,
    "mode": 420,
    "sha256": "b95a023ea0aaa9d6ce9907cbf84dd4543f985ece15ddef33c5e16182fb6ab2de",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/wordml.template.xml": {
    "bytes": 1366,
    "gid": 0,
    "mode": 420,
    "sha256": "5e7f150136d02c2478c47d2d8da5c44171203a73f517e4a266b2ea4b90ed29a9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/wrap.slidecontent.xml": {
    "bytes": 983,
    "gid": 0,
    "mode": 420,
    "sha256": "8c954d3271fd4d089288755e55e9d027f1321918e24de95a5b1f902c9ded60c7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/writing.mode.xml": {
    "bytes": 2494,
    "gid": 0,
    "mode": 420,
    "sha256": "7b7481c518faf09a08ec53866cc7348774cd3e2f4a25d0c73da27ca34d160e51",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/xbCollapsibleLists.js.xml": {
    "bytes": 1007,
    "gid": 0,
    "mode": 420,
    "sha256": "a5b54f23f1c07df0ff2d85f2198e7c8569d382479d9499dea5994f91a8dd325f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/xbDOM.js.xml": {
    "bytes": 903,
    "gid": 0,
    "mode": 420,
    "sha256": "4197dbe4b7a60e1e4ad767f32b1984439b41d9b0ff488f0c53888d6cc91efdd4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/xbLibrary.js.xml": {
    "bytes": 935,
    "gid": 0,
    "mode": 420,
    "sha256": "d1595558434dc3c197897266204843d9c9ad1e104548074dd90862a336c547b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/xbStyle.js.xml": {
    "bytes": 919,
    "gid": 0,
    "mode": 420,
    "sha256": "f258f4bdaa57aaa230ef443124f4917dde629415990a31e89e0b26427b36f62e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/xep.extensions.xml": {
    "bytes": 1077,
    "gid": 0,
    "mode": 420,
    "sha256": "033e781cd959f809284106ded7a7505774200336b87647c548acb257c3bdc2a6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/xep.index.item.properties.xml": {
    "bytes": 1516,
    "gid": 0,
    "mode": 420,
    "sha256": "600790bfacdee8618d16b35a1a284e1908fd4fdc056c7f6fe872f45e0e5ad7a1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/xref.label-page.separator.xml": {
    "bytes": 1487,
    "gid": 0,
    "mode": 420,
    "sha256": "03b43dd85d7d59c171af0b0165b049f3052fe14215e9f5b010e5b5dacfcda0d5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/xref.label-title.separator.xml": {
    "bytes": 1392,
    "gid": 0,
    "mode": 420,
    "sha256": "e02ee1996116bae43b746a7e05d64232dcbc7796a32846645099eaa0d3597f59",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/xref.properties.xml": {
    "bytes": 931,
    "gid": 0,
    "mode": 420,
    "sha256": "c627b9674643b83af5fac1a6a94f83d067d3e20dd17a3cffd0c5a737293373fd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/xref.title-page.separator.xml": {
    "bytes": 1425,
    "gid": 0,
    "mode": 420,
    "sha256": "fcc03dc62aa6c819b2383df1f71f20bc691735a27789a69c02bc36405c2114f1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/xref.with.number.and.title.xml": {
    "bytes": 1130,
    "gid": 0,
    "mode": 420,
    "sha256": "4917f4a57f7c00e4a26a1596b584d2f400b2192b80d1d31d1506485b1c1b8bf5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/params/xsl1.1.bookmarks.xml": {
    "bytes": 1365,
    "gid": 0,
    "mode": 420,
    "sha256": "12ac694b3cf839effc753aa07f4adf43e3d3d232d0a32e0d1b4b51985264590c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/profiling": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/profiling/profile-mode.xsl": {
    "bytes": 10432,
    "gid": 0,
    "mode": 420,
    "sha256": "61effafb44307acdd1d832d17b02bd6940d820828ddc4bab6443db73b8bfea7c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/profiling/profile.xsl": {
    "bytes": 2284,
    "gid": 0,
    "mode": 420,
    "sha256": "423e40c1003ab5525986fa7e3783643f223627a41a40d655aa5f9f847303c014",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/profiling/strip-attributes.xsl": {
    "bytes": 798,
    "gid": 0,
    "mode": 420,
    "sha256": "2cc835ebca57dae2828b4cb2d24af43f82d79db9a77756123b50b1e8001c5724",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/profiling/xsl2profile.xsl": {
    "bytes": 6728,
    "gid": 0,
    "mode": 420,
    "sha256": "0f1886be5dc508741fb583aa69ee368d49ecf8ef0790d6266619ff42bf2b438c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/blocks-spec.xml": {
    "bytes": 422,
    "gid": 0,
    "mode": 420,
    "sha256": "eaaa2c05d479000f17f39b51bab14db3e5cd624d5f06f5b7a9f625b4eb931ee8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/blocks2dbk.dtd": {
    "bytes": 2396,
    "gid": 0,
    "mode": 420,
    "sha256": "1e2333b01209da29895e2f51fc836996bd61f42a61c00a613d663c628e173e19",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/blocks2dbk.xsl": {
    "bytes": 68906,
    "gid": 0,
    "mode": 420,
    "sha256": "c4b82d272318dd9fccedeeb27c97a3b596edf984e71c3ed3f6d2740abad62ac3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/dbk2ooo.xsl": {
    "bytes": 5946,
    "gid": 0,
    "mode": 420,
    "sha256": "e936613d782587b27324fbc379802121a731f6f23355afb8c67e07f92416a99e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/dbk2pages.xsl": {
    "bytes": 15980,
    "gid": 0,
    "mode": 420,
    "sha256": "75832f3ec817183ff12386010558be24f32e69e1644de07106d527a4299d6fb9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/dbk2wordml.xsl": {
    "bytes": 12518,
    "gid": 0,
    "mode": 420,
    "sha256": "92b0180efb0282685a64fa8e8d2f60aab49ca1ba8538347ea1e2eeb4fb63a04a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/dbk2wp.xsl": {
    "bytes": 55181,
    "gid": 0,
    "mode": 420,
    "sha256": "2804f546a7295a54b24cca8c702f35382ba434f2f4262d2657fc6926ffc0e2a0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/normalise-common.xsl": {
    "bytes": 1314,
    "gid": 0,
    "mode": 420,
    "sha256": "bc1d66ff9c373e04b98d6b9c9696e349ce2d0e8bdf1372973ba4a3386a7114f8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/normalise2sections.xsl": {
    "bytes": 74892,
    "gid": 0,
    "mode": 420,
    "sha256": "f769f63c5f491ab478dab163d5eacfad4fcc0e4e6072fa5a5fb2a2940b12884a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/pages2normalise.xsl": {
    "bytes": 14182,
    "gid": 0,
    "mode": 420,
    "sha256": "fabcc94bfcbd30d4ef8ffeecb53fe8bfa7c293a4ecee9e45837b32e62a1fd57f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/param.xml": {
    "bytes": 3928,
    "gid": 0,
    "mode": 420,
    "sha256": "7cacd203ef37691e64675b9e4cd96be5cde59843d596027d0a12f847a0f348bf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/param.xsl": {
    "bytes": 587,
    "gid": 0,
    "mode": 420,
    "sha256": "1a91ae11ecc94d04bb61583bdefaed1e2a7c100054bae464a25ce10b8beeacb2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/sections-spec.xml": {
    "bytes": 1394,
    "gid": 0,
    "mode": 420,
    "sha256": "11936674f7be394f9044fdfe22e5227a2988362f0eea5dab238f7a0182918e0a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/sections2blocks.xsl": {
    "bytes": 15547,
    "gid": 0,
    "mode": 420,
    "sha256": "5617983282b56f9e9916d69905f3bc8bf110f0cfb8da9dc23832f3762fc9cddd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/specifications.xml": {
    "bytes": 67086,
    "gid": 0,
    "mode": 420,
    "sha256": "6a3733774f838820d4e2fd799202735d655686c4a92082bd243c5245536dce78",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/template-pages.xml": {
    "bytes": 427500,
    "gid": 0,
    "mode": 420,
    "sha256": "8e1e0c555229680ecc946be216f71cb1745f1b7ccf8ed923658b3619b997d615",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/template.xml": {
    "bytes": 86584,
    "gid": 0,
    "mode": 420,
    "sha256": "77c167c4de9d8737a326f77dfbff0a2be1bdfbd137312d64c299d43cc4975cd4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/roundtrip/wordml2normalise.xsl": {
    "bytes": 16790,
    "gid": 0,
    "mode": 420,
    "sha256": "747117c8f05d6b24d34e4708eba98d82ae0612227a75bc28ddbe4493ac75ef3c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/template": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/template/titlepage.xml": {
    "bytes": 16594,
    "gid": 0,
    "mode": 420,
    "sha256": "0705ec3d3f6bd8f20675805e4b15b6feb95dafcdce8f9a2360377c409b765da7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/template/titlepage.xsl": {
    "bytes": 54530,
    "gid": 0,
    "mode": 420,
    "sha256": "3ebf345b42f44f6cce8e375e18c2d6e40177081d84587bac39595fb3b9d9fb75",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/autolayout.xsl": {
    "bytes": 6933,
    "gid": 0,
    "mode": 420,
    "sha256": "817642f20b82572066d94f0af406673923eaaf920799c78d08169db927b2036f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/build.xml": {
    "bytes": 555,
    "gid": 0,
    "mode": 420,
    "sha256": "3d3a25d695ad04b0b9ec8eb14e36986492c542141c1e17c5b4532b0fae065e89",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/chunk-common.xsl": {
    "bytes": 7230,
    "gid": 0,
    "mode": 420,
    "sha256": "1fc3efb0991c0364bd990a80ff32e590648df2dbddc6cea655d0c34d918669f0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/chunk-tabular.xsl": {
    "bytes": 446,
    "gid": 0,
    "mode": 420,
    "sha256": "1730c3bb2f1bc5ad42ae1a51c1b34cca724ee3be63442b0a52b1a5e5de3ebe9e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/chunk-website.xsl": {
    "bytes": 446,
    "gid": 0,
    "mode": 420,
    "sha256": "8bbc34db90afa7eb5353d62d74bf025fde1371b5afb99f057ca23ae94a3e037c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/head.xsl": {
    "bytes": 9242,
    "gid": 0,
    "mode": 420,
    "sha256": "d26e8dc3a6172a78f14b1dae2da3483a3992f806e722cf2ec056e9d41c77bebf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/makefile-dep.xsl": {
    "bytes": 4200,
    "gid": 0,
    "mode": 420,
    "sha256": "b40333d93f4ea5a567de649ae21ea7a9ca922b81caa7c3d0f75396c2435d33ef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/olink.xsl": {
    "bytes": 10949,
    "gid": 0,
    "mode": 420,
    "sha256": "a4b6845777365803a17cfe567ddc97b5b8608e83ab7e5323bd2e31d0bba8494e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/param.xml": {
    "bytes": 26659,
    "gid": 0,
    "mode": 420,
    "sha256": "f9aba2e5160c6225684ef0bd936e35e731c5567aaf36dd4df1ab9397586f3bf3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/param.xsl": {
    "bytes": 2322,
    "gid": 0,
    "mode": 420,
    "sha256": "0f620afab0a00ec58d22ac189d0685503108116620da2931f33edda9abab08c6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/rss.xsl": {
    "bytes": 4589,
    "gid": 0,
    "mode": 420,
    "sha256": "e427f86766d1b9b180a33c830f0bece8f5ec1cb153a2546ce36bd3845fe5d704",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/tabular.xsl": {
    "bytes": 7647,
    "gid": 0,
    "mode": 420,
    "sha256": "8d1be0cb3131644fdf31d5c0e283900e90c1242b0db97e9c402586da61ed1f04",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/toc-tabular.xsl": {
    "bytes": 15849,
    "gid": 0,
    "mode": 420,
    "sha256": "27455b08fb3a486471acab6c4af3c2d8059f0ac12ae051aa87244cfb2c0847b4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/toc.xsl": {
    "bytes": 9227,
    "gid": 0,
    "mode": 420,
    "sha256": "43c826f90f2704cee715af1a471d1c7466aa3236b2cc69476a07cccc6b5a7a7a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/website-common.xsl": {
    "bytes": 27558,
    "gid": 0,
    "mode": 420,
    "sha256": "93d78d027fac2aeb7346b89925a2e7f9a10008f224f82a5e176e70d51c8c48e4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/website-targets.xsl": {
    "bytes": 730,
    "gid": 0,
    "mode": 420,
    "sha256": "8ec94bb151a0fdf371b0343f9d94ccb292811969b8e23d7698e473f5917df76b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/website.xsl": {
    "bytes": 4130,
    "gid": 0,
    "mode": 420,
    "sha256": "5a65d28e618f9990394d80ace644038926ae919b5bc53cfe6024233e593f62c4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/website/xbel.xsl": {
    "bytes": 2880,
    "gid": 0,
    "mode": 420,
    "sha256": "8491d875b7c8920dcd7402f5a8bc2e707d59c8f86882e19d23aa355105c32ec7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/admon.xsl": {
    "bytes": 4607,
    "gid": 0,
    "mode": 420,
    "sha256": "f51d743610f60caa5b029a1c7425789b7f037cfb236c497b975843e74c650a3c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/annotations.xsl": {
    "bytes": 5559,
    "gid": 0,
    "mode": 420,
    "sha256": "bee466d5703c71dec5c44c30d71b7abfd79531c225deca59d45bc20f771aa9c0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/autoidx-kimber.xsl": {
    "bytes": 7100,
    "gid": 0,
    "mode": 420,
    "sha256": "52f53563dd0c7a61104564d7b979885b26dd4caf3139633d9f155a1d9ae8eab8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/autoidx-kosek.xsl": {
    "bytes": 5297,
    "gid": 0,
    "mode": 420,
    "sha256": "3338315530bdf7d434d59aadec9237dda08c40d9d480ef4ca272e563aa619646",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/autoidx-ng.xsl": {
    "bytes": 806,
    "gid": 0,
    "mode": 420,
    "sha256": "4a7be2fd615a8474cdbc4fbfe4e18181facfef604962f15d3665a6eca7414232",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/autoidx.xsl": {
    "bytes": 148171,
    "gid": 0,
    "mode": 420,
    "sha256": "3498303ba129d19959a22e0f48b61008269dc874eb2a5758a47f4eadc1206bb4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/autotoc.xsl": {
    "bytes": 28994,
    "gid": 0,
    "mode": 420,
    "sha256": "2a0f2bc29795ac37bd4b738825c33393bfbef7e4d7d265df3cc17ad5eb238609",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/biblio-iso690.xsl": {
    "bytes": 56488,
    "gid": 0,
    "mode": 420,
    "sha256": "e2aa02b8652cae08e2d812bf39c0af57ad875b3bf140422397cd81a51ad3ca4b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/biblio.xsl": {
    "bytes": 44893,
    "gid": 0,
    "mode": 420,
    "sha256": "1cd7eaf64cfc127305a47a30284c96a99e8d6fad278559dba1d4c2d2e10bd149",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/block.xsl": {
    "bytes": 17039,
    "gid": 0,
    "mode": 420,
    "sha256": "22eb6b48f149161237123c4c9743cacc9e51c198a3fd2a91ccde5c84eabb5dc6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/build.xml": {
    "bytes": 1245,
    "gid": 0,
    "mode": 420,
    "sha256": "c892326b4aaa1aee4febf5ba29c4cbde703ef4826514a3ed3f30c8917a4c71fb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/callout.xsl": {
    "bytes": 7866,
    "gid": 0,
    "mode": 420,
    "sha256": "16c5f083b97549884b2806ca700ee66ab48a2810b1598c870c79d05da2ac1f96",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/changebars.xsl": {
    "bytes": 4085,
    "gid": 0,
    "mode": 420,
    "sha256": "d5d4fc1ec88c63b769e4be5be45bae7fd3bc06b6a7a428909cd4e95040d15bc7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/chunk-changebars.xsl": {
    "bytes": 3872,
    "gid": 0,
    "mode": 420,
    "sha256": "f282c0b36433be4747bfeec41e652cfd841e6c2dc104f2d970e9e39705b76c11",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/chunk-code.xsl": {
    "bytes": 25060,
    "gid": 0,
    "mode": 420,
    "sha256": "6f791122e224b9a8ebc0ab1143c575c8bfe5d8dd1eecbb4241eea0c101dfa863",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/chunk-common.xsl": {
    "bytes": 83853,
    "gid": 0,
    "mode": 420,
    "sha256": "2ab2c3ae65f2ed3acc45039d37bce2668ab7d2dcce93586915f651daa4d97606",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/chunk.xsl": {
    "bytes": 2373,
    "gid": 0,
    "mode": 420,
    "sha256": "4c6aeabcca176259da5ad1dbe2f9a24065f8e4cbd4b735173d956c40ea5e9bf7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/chunker.xsl": {
    "bytes": 17877,
    "gid": 0,
    "mode": 420,
    "sha256": "da4afd16d5d1969d6712d627d0004a3a1b836169811cbab6ac25d7e6bbdaaafb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/chunkfast.xsl": {
    "bytes": 2739,
    "gid": 0,
    "mode": 420,
    "sha256": "fc56bb4ca12fab527b4656436d5c7b3549ed7d87070d3cfe28fedad948c6ce83",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/chunktoc.xsl": {
    "bytes": 18962,
    "gid": 0,
    "mode": 420,
    "sha256": "35ab6b5739b314a93fc2ac085ed01c55b9e201b3af0cd5a3f8ac3b49d24582f8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/component.xsl": {
    "bytes": 16676,
    "gid": 0,
    "mode": 420,
    "sha256": "4bf4f597dae631bab89ff186e6f2be4c2852fc060c1b15ae76336d6689396db8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/division.xsl": {
    "bytes": 6910,
    "gid": 0,
    "mode": 420,
    "sha256": "1e694e89f003d7c434df8f1f3ecb7bc9a41502ba1ee6313dfabb6a97090dccee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/docbook.css.xml": {
    "bytes": 1623,
    "gid": 0,
    "mode": 420,
    "sha256": "653067889f6a4a8f427cd4fb72176776da4124e76aa79b448b2b8fecaa065497",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/docbook.xsl": {
    "bytes": 19958,
    "gid": 0,
    "mode": 420,
    "sha256": "b66312fd023b76f81bb3b90ac3d18497236bb1d4d6ceae8790ee31c0d4f69298",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/ebnf.xsl": {
    "bytes": 10477,
    "gid": 0,
    "mode": 420,
    "sha256": "772291952268d1a90e98a36e54d4b07547a4938f2e31fd45aacf43c3a7a60f18",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/footnote.xsl": {
    "bytes": 11562,
    "gid": 0,
    "mode": 420,
    "sha256": "089fcf46310438bee6be165dbaa78e349d21eecaa5f172badc1b8895a85eeaae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/formal.xsl": {
    "bytes": 16312,
    "gid": 0,
    "mode": 420,
    "sha256": "d10e43bc5dac390874632ce1016680a673c235ce57d206088748d37cd8ea2453",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/glossary.xsl": {
    "bytes": 37651,
    "gid": 0,
    "mode": 420,
    "sha256": "5ce1e39446ee7bc4cc17db86a9fa5549489d7323d958669fefe41d6b3a27cd40",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/graphics.xsl": {
    "bytes": 59950,
    "gid": 0,
    "mode": 420,
    "sha256": "18c32d9f4628cb999254ea66b1ff1132d5b6ee769729778f463c5e64ce443c07",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/highlight.xsl": {
    "bytes": 3113,
    "gid": 0,
    "mode": 420,
    "sha256": "1dc083a640be9e17b914326ab6262f0fb4407522ca70fcac8d2bd84f0d6880d4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/html-rtf.xsl": {
    "bytes": 11312,
    "gid": 0,
    "mode": 420,
    "sha256": "7eb5df2d3a43f4273128465cb12bbdeb8755f2cadcc59c22d822fc09c171ad9c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/html.xsl": {
    "bytes": 24072,
    "gid": 0,
    "mode": 420,
    "sha256": "c9851cae93395abf197b8f4f3ebbe6ea5d28752a7784b8731b3582ddc2136901",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/htmltbl.xsl": {
    "bytes": 4776,
    "gid": 0,
    "mode": 420,
    "sha256": "c0316bbf6606b598d271353ae643a4772c27cbf51d4f2502a2d1758bfaf86891",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/index.xsl": {
    "bytes": 9809,
    "gid": 0,
    "mode": 420,
    "sha256": "8585c8b40d3195e2cddce75537f27485ad60a93b5dd435224a8fc918189518a4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/info.xsl": {
    "bytes": 1642,
    "gid": 0,
    "mode": 420,
    "sha256": "bb7d1313ee78a81a330f05e53ddcbd836dac43edc106af8ea3b4ce0ff0b9b56c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/inline.xsl": {
    "bytes": 52406,
    "gid": 0,
    "mode": 420,
    "sha256": "10c429ef2be3d4330672ac3704ea363c3da2c758ee16c1b7068b67e75904608b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/its.xsl": {
    "bytes": 4596,
    "gid": 0,
    "mode": 420,
    "sha256": "0aa132bdf6c49e5ba1a27397ef31c2e78ac9e0b5aa7db9441faf3e7caf6f3889",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/keywords.xsl": {
    "bytes": 1196,
    "gid": 0,
    "mode": 420,
    "sha256": "0630ad225189d60d306adb6f57aee8950184892fedfe3509471a772975183952",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/lists.xsl": {
    "bytes": 41358,
    "gid": 0,
    "mode": 420,
    "sha256": "e9224b5ff970fe94f2aa12735d6ce5117417d371361d949523254d50c23ed822",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/maketoc.xsl": {
    "bytes": 2832,
    "gid": 0,
    "mode": 420,
    "sha256": "3fbbf4dff11f89fd62ae40af09d53dc6000e1993be3d8a12a064ab59e83aa003",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/manifest.xsl": {
    "bytes": 989,
    "gid": 0,
    "mode": 420,
    "sha256": "a55c0d5c7b043161832de7f16c684c047ca415622b98150dd4251f32e008a981",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/math.xsl": {
    "bytes": 8983,
    "gid": 0,
    "mode": 420,
    "sha256": "31b37fb3de18bb843e5f009d5fda85191d356342108f5215df66eac410fc8da8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/oldchunker.xsl": {
    "bytes": 7165,
    "gid": 0,
    "mode": 420,
    "sha256": "f2452f03b2aa6a4ff400112f6971fa80f51221286f721a24442e3afd4e72493c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/onechunk.xsl": {
    "bytes": 1419,
    "gid": 0,
    "mode": 420,
    "sha256": "7d9f102ba03e90da841f36b13b1113e3c3565e1850e23a5de11f8b07fd94ae64",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/param.xsl": {
    "bytes": 20540,
    "gid": 0,
    "mode": 420,
    "sha256": "96f6e7e03b5e46c705ac5ecdf4ea261de25256f4dfbda8ce90e16586923844fa",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/pi.xsl": {
    "bytes": 54261,
    "gid": 0,
    "mode": 420,
    "sha256": "084cc4797c3b5ae87aa29d60d528e2925203c4640382861747873aac4dd25f67",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/profile-chunk-code.xsl": {
    "bytes": 25831,
    "gid": 0,
    "mode": 420,
    "sha256": "cd3ca56fef0518c2569365d79a7ddf5a7d0267edd67270c5a11aff8228bedc3a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/profile-chunk.xsl": {
    "bytes": 2696,
    "gid": 0,
    "mode": 420,
    "sha256": "5f37ca8db6cbafa35715396b9316d33f9075128f30d5c2a66081ee66002de629",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/profile-docbook.xsl": {
    "bytes": 20246,
    "gid": 0,
    "mode": 420,
    "sha256": "88d7fad739e9e582f23615c002446d44bc6345ebc1e143faa070b5dbd8ca0ac0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/profile-onechunk.xsl": {
    "bytes": 1734,
    "gid": 0,
    "mode": 420,
    "sha256": "a043d47df909d5f1fb4068de695840977c5c46b29fe93acecb07f353a4bdd747",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/publishers.xsl": {
    "bytes": 3415,
    "gid": 0,
    "mode": 420,
    "sha256": "2415daa1f6b2daeedd6e46d8d866c5dcdbe659b3064f6d03ebed695342e74e9e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/qandaset.xsl": {
    "bytes": 15717,
    "gid": 0,
    "mode": 420,
    "sha256": "e7b20ee00dc19a05b071fed34d96c522335c109eb0206c23806a9b595721ab0e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/refentry.xsl": {
    "bytes": 9748,
    "gid": 0,
    "mode": 420,
    "sha256": "93f287ca705ece60b1a56dc165cad63a1042fb7e06d753b089c174dc4d093fe7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/sections.xsl": {
    "bytes": 23125,
    "gid": 0,
    "mode": 420,
    "sha256": "81907bafb6024683ac95c2ebe44ca20373f0f31d1b62ef8ee1dcc4af197e8955",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/synop.xsl": {
    "bytes": 51741,
    "gid": 0,
    "mode": 420,
    "sha256": "c9195be06a2d3f9edddcdb26ffba9ebc5d0724ad9bd761f43fc5146a200d7cee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/table.xsl": {
    "bytes": 44080,
    "gid": 0,
    "mode": 420,
    "sha256": "353445e29fd5e76b73e4f80b31b2c627592b61160e10d6768915111b0b9fdeae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/task.xsl": {
    "bytes": 2404,
    "gid": 0,
    "mode": 420,
    "sha256": "6539aa137b0fd5fa91572d90456ea57582cb9df8580d977b3ca20e2114e21534",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/titlepage.templates.xsl": {
    "bytes": 196558,
    "gid": 0,
    "mode": 420,
    "sha256": "8fc6d1dfc51776a558a56ccb3e938ab69cb411feaea54fc20bd28e3342b47e3d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/titlepage.xsl": {
    "bytes": 38083,
    "gid": 0,
    "mode": 420,
    "sha256": "609b0092ae758099dbd900deaf84654861843b0fa72cf6293ca41dd301e6b999",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/toc.xsl": {
    "bytes": 12617,
    "gid": 0,
    "mode": 420,
    "sha256": "a790af112a9324150b58300a9a525459f7310410aaba726cfe989c985cfdd1f2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/verbatim.xsl": {
    "bytes": 14022,
    "gid": 0,
    "mode": 420,
    "sha256": "77eb46596af87f663ce9e406f4bdde5418f9841e5260393b215c71a1e5d0efbc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml-1_1/xref.xsl": {
    "bytes": 47386,
    "gid": 0,
    "mode": 420,
    "sha256": "7ad2477bdcbf0fb8d1eecd988e3bda2a14be4d94a63a5e97327a78b3af69c140",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/admon.xsl": {
    "bytes": 4735,
    "gid": 0,
    "mode": 420,
    "sha256": "d16e39618d8d771267cc03252e3a597ad5a469d03f2ab7d3a27c098c287329bf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/annotations.xsl": {
    "bytes": 5581,
    "gid": 0,
    "mode": 420,
    "sha256": "42357ae7946ee4c049380655f3073c38a2a5fa5f80b8597759406d3f7d134fe8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/autoidx-kimber.xsl": {
    "bytes": 7100,
    "gid": 0,
    "mode": 420,
    "sha256": "52f53563dd0c7a61104564d7b979885b26dd4caf3139633d9f155a1d9ae8eab8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/autoidx-kosek.xsl": {
    "bytes": 5297,
    "gid": 0,
    "mode": 420,
    "sha256": "3338315530bdf7d434d59aadec9237dda08c40d9d480ef4ca272e563aa619646",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/autoidx-ng.xsl": {
    "bytes": 806,
    "gid": 0,
    "mode": 420,
    "sha256": "4a7be2fd615a8474cdbc4fbfe4e18181facfef604962f15d3665a6eca7414232",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/autoidx.xsl": {
    "bytes": 148171,
    "gid": 0,
    "mode": 420,
    "sha256": "3498303ba129d19959a22e0f48b61008269dc874eb2a5758a47f4eadc1206bb4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/autotoc.xsl": {
    "bytes": 28994,
    "gid": 0,
    "mode": 420,
    "sha256": "2a0f2bc29795ac37bd4b738825c33393bfbef7e4d7d265df3cc17ad5eb238609",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/biblio-iso690.xsl": {
    "bytes": 56488,
    "gid": 0,
    "mode": 420,
    "sha256": "e2aa02b8652cae08e2d812bf39c0af57ad875b3bf140422397cd81a51ad3ca4b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/biblio.xsl": {
    "bytes": 44893,
    "gid": 0,
    "mode": 420,
    "sha256": "1cd7eaf64cfc127305a47a30284c96a99e8d6fad278559dba1d4c2d2e10bd149",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/block.xsl": {
    "bytes": 17087,
    "gid": 0,
    "mode": 420,
    "sha256": "5436aff3206cca2955d02cefd1552a9cbefe39da6c972c49455c1e5537703165",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/build.xml": {
    "bytes": 1241,
    "gid": 0,
    "mode": 420,
    "sha256": "f07bbcd081ad082c82a50f671d7bbfd139c547ebf7df3cf02c134826f73cfa7d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/callout.xsl": {
    "bytes": 7877,
    "gid": 0,
    "mode": 420,
    "sha256": "449bbc82535134ee917c480660f723a161adabdb78e014609cfe828fba643b6d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/changebars.xsl": {
    "bytes": 4096,
    "gid": 0,
    "mode": 420,
    "sha256": "25d2ff445f09e3a8157b99f2a914a61e6bb4a93725c912e64ebb52050c38a796",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/chunk-changebars.xsl": {
    "bytes": 3872,
    "gid": 0,
    "mode": 420,
    "sha256": "f282c0b36433be4747bfeec41e652cfd841e6c2dc104f2d970e9e39705b76c11",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/chunk-code.xsl": {
    "bytes": 25060,
    "gid": 0,
    "mode": 420,
    "sha256": "6f791122e224b9a8ebc0ab1143c575c8bfe5d8dd1eecbb4241eea0c101dfa863",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/chunk-common.xsl": {
    "bytes": 84741,
    "gid": 0,
    "mode": 420,
    "sha256": "75ef9d28ed590249f505672d3308fc743494e27c44c3d15c7ff498e890a096b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/chunk.xsl": {
    "bytes": 2384,
    "gid": 0,
    "mode": 420,
    "sha256": "de8b9d3359f89be07b3e99d7021aadb365a37719685810d7f59a18fcbcda0774",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/chunker.xsl": {
    "bytes": 17901,
    "gid": 0,
    "mode": 420,
    "sha256": "0e3d76b22d106b2b75f5cdd8183d3ee74397a53b8f5735017c82a76c3f3054ff",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/chunkfast.xsl": {
    "bytes": 2739,
    "gid": 0,
    "mode": 420,
    "sha256": "fc56bb4ca12fab527b4656436d5c7b3549ed7d87070d3cfe28fedad948c6ce83",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/chunktoc.xsl": {
    "bytes": 18973,
    "gid": 0,
    "mode": 420,
    "sha256": "fe55a03b1a1cbaa03cb7094c311516781389d152982bada7baa2a2fc899355a6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/component.xsl": {
    "bytes": 16676,
    "gid": 0,
    "mode": 420,
    "sha256": "4bf4f597dae631bab89ff186e6f2be4c2852fc060c1b15ae76336d6689396db8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/division.xsl": {
    "bytes": 6906,
    "gid": 0,
    "mode": 420,
    "sha256": "0987c46e62275423f6f7380bd392e8c15c3b20faddae983bcad8cbc0edcda9b0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/docbook-no-doctype.xsl": {
    "bytes": 20031,
    "gid": 0,
    "mode": 420,
    "sha256": "55e11a8d6de511ff3cb2cd616fec53e0612cfa6eaa9f9a926de9e8dc156445f4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/docbook.css.xml": {
    "bytes": 1623,
    "gid": 0,
    "mode": 420,
    "sha256": "653067889f6a4a8f427cd4fb72176776da4124e76aa79b448b2b8fecaa065497",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/docbook.xsl": {
    "bytes": 20160,
    "gid": 0,
    "mode": 420,
    "sha256": "9cc8a33face2ef202edd7001a7572347294253001ec43b27d166df6f80eafffe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/ebnf.xsl": {
    "bytes": 10461,
    "gid": 0,
    "mode": 420,
    "sha256": "c33f1ee7463d741b8b0fe4d008df19aad2ecf478877d969dd6d275e63bec5e27",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/footnote.xsl": {
    "bytes": 12354,
    "gid": 0,
    "mode": 420,
    "sha256": "adefe18aaa76a0f902a6ef1a3ead66d8ddc3ecbcfe27e3ed73186e75ce58a331",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/formal.xsl": {
    "bytes": 16312,
    "gid": 0,
    "mode": 420,
    "sha256": "d10e43bc5dac390874632ce1016680a673c235ce57d206088748d37cd8ea2453",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/glossary.xsl": {
    "bytes": 37651,
    "gid": 0,
    "mode": 420,
    "sha256": "5ce1e39446ee7bc4cc17db86a9fa5549489d7323d958669fefe41d6b3a27cd40",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/graphics.xsl": {
    "bytes": 59906,
    "gid": 0,
    "mode": 420,
    "sha256": "4ea517df7e5bbd484d84df6d8bce797723c0c3fe3619282487be2dfc5cdc94d2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/highlight.xsl": {
    "bytes": 3113,
    "gid": 0,
    "mode": 420,
    "sha256": "1dc083a640be9e17b914326ab6262f0fb4407522ca70fcac8d2bd84f0d6880d4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/html-rtf.xsl": {
    "bytes": 11312,
    "gid": 0,
    "mode": 420,
    "sha256": "7eb5df2d3a43f4273128465cb12bbdeb8755f2cadcc59c22d822fc09c171ad9c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/html.xsl": {
    "bytes": 24072,
    "gid": 0,
    "mode": 420,
    "sha256": "c9851cae93395abf197b8f4f3ebbe6ea5d28752a7784b8731b3582ddc2136901",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/htmltbl.xsl": {
    "bytes": 4776,
    "gid": 0,
    "mode": 420,
    "sha256": "c0316bbf6606b598d271353ae643a4772c27cbf51d4f2502a2d1758bfaf86891",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/index.xsl": {
    "bytes": 9809,
    "gid": 0,
    "mode": 420,
    "sha256": "8585c8b40d3195e2cddce75537f27485ad60a93b5dd435224a8fc918189518a4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/info.xsl": {
    "bytes": 1642,
    "gid": 0,
    "mode": 420,
    "sha256": "bb7d1313ee78a81a330f05e53ddcbd836dac43edc106af8ea3b4ce0ff0b9b56c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/inline.xsl": {
    "bytes": 52406,
    "gid": 0,
    "mode": 420,
    "sha256": "10c429ef2be3d4330672ac3704ea363c3da2c758ee16c1b7068b67e75904608b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/its.xsl": {
    "bytes": 4596,
    "gid": 0,
    "mode": 420,
    "sha256": "0aa132bdf6c49e5ba1a27397ef31c2e78ac9e0b5aa7db9441faf3e7caf6f3889",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/keywords.xsl": {
    "bytes": 1196,
    "gid": 0,
    "mode": 420,
    "sha256": "0630ad225189d60d306adb6f57aee8950184892fedfe3509471a772975183952",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/lists.xsl": {
    "bytes": 41689,
    "gid": 0,
    "mode": 420,
    "sha256": "68a4303547390f4d52732d402c993fe8f2ff446254f8460bd131d18227bf6a07",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/maketoc.xsl": {
    "bytes": 2867,
    "gid": 0,
    "mode": 420,
    "sha256": "9f2798445d251f9394506d54534db013498aac6521234695e8abbd78dbf20599",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/manifest.xsl": {
    "bytes": 989,
    "gid": 0,
    "mode": 420,
    "sha256": "a55c0d5c7b043161832de7f16c684c047ca415622b98150dd4251f32e008a981",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/math.xsl": {
    "bytes": 8983,
    "gid": 0,
    "mode": 420,
    "sha256": "31b37fb3de18bb843e5f009d5fda85191d356342108f5215df66eac410fc8da8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/oldchunker.xsl": {
    "bytes": 7165,
    "gid": 0,
    "mode": 420,
    "sha256": "f2452f03b2aa6a4ff400112f6971fa80f51221286f721a24442e3afd4e72493c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/onechunk.xsl": {
    "bytes": 1419,
    "gid": 0,
    "mode": 420,
    "sha256": "7d9f102ba03e90da841f36b13b1113e3c3565e1850e23a5de11f8b07fd94ae64",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/param.xsl": {
    "bytes": 20518,
    "gid": 0,
    "mode": 420,
    "sha256": "e817a70c9152c2f518f029b0d7ed1fe60fc509b0c062fc46ea6995ef3bafc76f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/pi.xsl": {
    "bytes": 54261,
    "gid": 0,
    "mode": 420,
    "sha256": "084cc4797c3b5ae87aa29d60d528e2925203c4640382861747873aac4dd25f67",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/profile-chunk-code.xsl": {
    "bytes": 25831,
    "gid": 0,
    "mode": 420,
    "sha256": "cd3ca56fef0518c2569365d79a7ddf5a7d0267edd67270c5a11aff8228bedc3a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/profile-chunk.xsl": {
    "bytes": 2707,
    "gid": 0,
    "mode": 420,
    "sha256": "031e064ffdd619d086842c7c7d9fbe7ad0ff6a99084a88f9a8128703b4695248",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/profile-docbook.xsl": {
    "bytes": 20448,
    "gid": 0,
    "mode": 420,
    "sha256": "233bf4c119d17280259d3f48612239e688ccae99b6d3c93ef2cca9b4692712b6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/profile-onechunk.xsl": {
    "bytes": 1734,
    "gid": 0,
    "mode": 420,
    "sha256": "a043d47df909d5f1fb4068de695840977c5c46b29fe93acecb07f353a4bdd747",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/publishers.xsl": {
    "bytes": 3415,
    "gid": 0,
    "mode": 420,
    "sha256": "2415daa1f6b2daeedd6e46d8d866c5dcdbe659b3064f6d03ebed695342e74e9e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/qandaset.xsl": {
    "bytes": 15717,
    "gid": 0,
    "mode": 420,
    "sha256": "e7b20ee00dc19a05b071fed34d96c522335c109eb0206c23806a9b595721ab0e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/refentry.xsl": {
    "bytes": 9748,
    "gid": 0,
    "mode": 420,
    "sha256": "93f287ca705ece60b1a56dc165cad63a1042fb7e06d753b089c174dc4d093fe7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/sections.xsl": {
    "bytes": 23125,
    "gid": 0,
    "mode": 420,
    "sha256": "81907bafb6024683ac95c2ebe44ca20373f0f31d1b62ef8ee1dcc4af197e8955",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/synop.xsl": {
    "bytes": 51741,
    "gid": 0,
    "mode": 420,
    "sha256": "c9195be06a2d3f9edddcdb26ffba9ebc5d0724ad9bd761f43fc5146a200d7cee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/table.xsl": {
    "bytes": 43808,
    "gid": 0,
    "mode": 420,
    "sha256": "749a6757a0d6156de812287cc577e25ce883650db4008bd30e038302385ab557",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/task.xsl": {
    "bytes": 2404,
    "gid": 0,
    "mode": 420,
    "sha256": "6539aa137b0fd5fa91572d90456ea57582cb9df8580d977b3ca20e2114e21534",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/titlepage.templates.xml": {
    "bytes": 16992,
    "gid": 0,
    "mode": 420,
    "sha256": "bc639f5cba2b4e3c5843b0184b3123c9bdae72b8f84f7303e842d1e68b7c635a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/titlepage.templates.xsl": {
    "bytes": 196558,
    "gid": 0,
    "mode": 420,
    "sha256": "8fc6d1dfc51776a558a56ccb3e938ab69cb411feaea54fc20bd28e3342b47e3d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/titlepage.xsl": {
    "bytes": 38083,
    "gid": 0,
    "mode": 420,
    "sha256": "609b0092ae758099dbd900deaf84654861843b0fa72cf6293ca41dd301e6b999",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/toc.xsl": {
    "bytes": 12617,
    "gid": 0,
    "mode": 420,
    "sha256": "a790af112a9324150b58300a9a525459f7310410aaba726cfe989c985cfdd1f2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/verbatim.xsl": {
    "bytes": 14022,
    "gid": 0,
    "mode": 420,
    "sha256": "77eb46596af87f663ce9e406f4bdde5418f9841e5260393b215c71a1e5d0efbc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml/xref.xsl": {
    "bytes": 47386,
    "gid": 0,
    "mode": 420,
    "sha256": "7ad2477bdcbf0fb8d1eecd988e3bda2a14be4d94a63a5e97327a78b3af69c140",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5/build.xml": {
    "bytes": 727,
    "gid": 0,
    "mode": 420,
    "sha256": "c151b95c8a012c2ba017bbb6ef35d1be4d77af5d240096aad5e58d64ad1f803c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5/chunk.xsl": {
    "bytes": 929,
    "gid": 0,
    "mode": 420,
    "sha256": "8181ac4610bc7224fcfe9fe585ae475c0345de2a85155edf7a152982c641040b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5/chunkfast.xsl": {
    "bytes": 2742,
    "gid": 0,
    "mode": 420,
    "sha256": "ab4df1d520692844823e3336d163b70f94073c9137a8da5fc494735846583da7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5/docbook.css.xml": {
    "bytes": 1568,
    "gid": 0,
    "mode": 420,
    "sha256": "ea3920dce5dd749a4adfcfd1fc1a224c260319833faf4178c2657df9daffeecf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5/docbook.xsl": {
    "bytes": 655,
    "gid": 0,
    "mode": 420,
    "sha256": "e59e28259dd2ba782f9fdf127ae8b3d0dad2a3e4a0d1b3260c568bd2dbfbd395",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5/html5-chunk-mods.xsl": {
    "bytes": 3603,
    "gid": 0,
    "mode": 420,
    "sha256": "3e20e147c71461acec146dbda54098357d3aa5105dca9d43ab91aac81e8c171c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5/html5-element-mods.xsl": {
    "bytes": 32233,
    "gid": 0,
    "mode": 420,
    "sha256": "74f50f5a4a49fb42f28eb92e6103abaf34d83692de655f6dbf7c0c6efe4698c1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5/onechunk.xsl": {
    "bytes": 1432,
    "gid": 0,
    "mode": 420,
    "sha256": "88a779a84b799ce54f00dc4dfa8112a1b28360b8b860f7942583aef45609d5ba",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5/profile-chunk.xsl": {
    "bytes": 2364,
    "gid": 0,
    "mode": 420,
    "sha256": "7b883da46bb51c371b58703b1dd53fcb8f5936e5ad1e377bbfbd59e6f9fc1930",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5/profile-docbook.xsl": {
    "bytes": 1055,
    "gid": 0,
    "mode": 420,
    "sha256": "2be133e77828710c79e45c1c515bc8b82ca103631c2ee52733a37df4229abbd6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5/xhtml-docbook.xsl": {
    "bytes": 20554,
    "gid": 0,
    "mode": 420,
    "sha256": "9a3f677430befabcb9e4555148fe67d0614f1cb85edbef4d8836c2b359e03a84",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5/xhtml-profile-docbook.xsl": {
    "bytes": 17739,
    "gid": 0,
    "mode": 420,
    "sha256": "ae638160d590f7ff3e1b62aa912733103bfa662a7b56dda1cbaa31d2f6484922",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2-nons/xhtml5/xhtml2xhtml5.xsl": {
    "bytes": 1550,
    "gid": 0,
    "mode": 420,
    "sha256": "88c7b861d8363f6b469d11542f162f77a6be712377d73a45a4d25bf8ce754fb8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/VERSION": {
    "bytes": 4569,
    "gid": 0,
    "mode": 420,
    "sha256": "86855687ccab1902d609614604a5cdd1c7c0304f369e22b232d6e310f52e160e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/VERSION.xsl": {
    "bytes": 4567,
    "gid": 0,
    "mode": 420,
    "sha256": "e23804541271819b96e74fb704e3dcaedb9e2223a8f863759a67a02ed19da596",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/assembly": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/assembly/assemble.xsl": {
    "bytes": 25917,
    "gid": 0,
    "mode": 420,
    "sha256": "bd54a80fac2ded13d2cda7ae40864839402f021f248c172d024215b834bc2a4c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/assembly/topic-maker-chunk.xsl": {
    "bytes": 6552,
    "gid": 0,
    "mode": 420,
    "sha256": "6b4c11ce0687f009d6f8980d00a81e8c96fd9a2fbc276c14be915d5485173b37",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/assembly/topic-maker.xsl": {
    "bytes": 2795,
    "gid": 0,
    "mode": 420,
    "sha256": "8f9fb3f3ecdef6f4f12afd7d157635a25e2256094cd0e37c0de8122aa77b60ca",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/addns.xsl": {
    "bytes": 4895,
    "gid": 0,
    "mode": 420,
    "sha256": "5564946fa72718e46eaed71e3955a239e2f2f49362d3fe7b2acbfc5c275a3794",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/af.xml": {
    "bytes": 47951,
    "gid": 0,
    "mode": 420,
    "sha256": "0f48b714f4b99b9db59051346f61cd9470b2734386cf80ebc1d01dbccfafb973",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/am.xml": {
    "bytes": 48652,
    "gid": 0,
    "mode": 420,
    "sha256": "843123dab908a7776655a76224f529225700d9493460a1538c2d205775abdcf2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/ar.xml": {
    "bytes": 48296,
    "gid": 0,
    "mode": 420,
    "sha256": "70e587d9e250fa4b98bff9da06d416c5d74d50edb005d835fcd49c909318f74f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/as.xml": {
    "bytes": 37581,
    "gid": 0,
    "mode": 420,
    "sha256": "0fd21e915698f86be9feb55b48b46944eadbb2233188c12b0b4f19ecae6d74cc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/ast.xml": {
    "bytes": 33853,
    "gid": 0,
    "mode": 420,
    "sha256": "a4b4de170aa3194e632c078a132bf47e9435616fbd503253d820e932f38ded07",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/autoidx-kimber.xsl": {
    "bytes": 1527,
    "gid": 0,
    "mode": 420,
    "sha256": "8e2b89c92172dd751da9dda93f2373e83ec9bb82d0a3b7dddcdb61db4a94416d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/autoidx-kosek.xsl": {
    "bytes": 5058,
    "gid": 0,
    "mode": 420,
    "sha256": "df8cb4eddd5e12459bde363c11549d7ec4d89fcdd819382f10ba2008536f187d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/az.xml": {
    "bytes": 34324,
    "gid": 0,
    "mode": 420,
    "sha256": "af4b081ed122bebd17ae244bce18e95175ed74262c6a3911151c553595aed23c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/bg.xml": {
    "bytes": 38142,
    "gid": 0,
    "mode": 420,
    "sha256": "d9ad227e003f953ed7623d1fb323ead8ac2533b67b6117a3e83e7e8bd52a9cbe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/bn.xml": {
    "bytes": 51040,
    "gid": 0,
    "mode": 420,
    "sha256": "899776193708c763fbb372cc2118261af8747350e8b8b0864ceba836c67ee24f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/bn_in.xml": {
    "bytes": 38396,
    "gid": 0,
    "mode": 420,
    "sha256": "a37e6b92058cd49331ef4a2421ef8f317ade3798e388b4f53f9cce88d35f2785",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/bs.xml": {
    "bytes": 33637,
    "gid": 0,
    "mode": 420,
    "sha256": "70a22016ff0103bff6209e4b8a392dc3bff54309f8cd2b88d59706fcea1eb078",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/build.xml": {
    "bytes": 935,
    "gid": 0,
    "mode": 420,
    "sha256": "82a7576432836a13359f92e09b107e8231b747631f891ae2e61367d562b3863d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/ca.xml": {
    "bytes": 33663,
    "gid": 0,
    "mode": 420,
    "sha256": "089d289b2fe93594ba80e07ac3ecc49075f1b7cb1043550309407a3fff1d0d49",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/charmap.xml": {
    "bytes": 6625,
    "gid": 0,
    "mode": 420,
    "sha256": "7485c379fcbe10cdcc08d6c69f6230f951f50df15092fde3e2090b09b01c1902",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/charmap.xsl": {
    "bytes": 9387,
    "gid": 0,
    "mode": 420,
    "sha256": "5036b8e1cd89f2d47f2d4de46f3d8dfc296f42edb975a472e429f5b234836bb2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/common.xml": {
    "bytes": 18407,
    "gid": 0,
    "mode": 420,
    "sha256": "ee226de064cad44e4951849a574b6fb23fa6587775ce1e55335a7d8e720480a3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/common.xsl": {
    "bytes": 78454,
    "gid": 0,
    "mode": 420,
    "sha256": "85d526ae424d05ad45bb5afdd8ad395c2cf43d3a71ca94b4176588b393dd6df6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/cs.xml": {
    "bytes": 31896,
    "gid": 0,
    "mode": 420,
    "sha256": "542954933db2c2597991d543dc7e48ab46f1f30593ad1af1cdc9c195eac85013",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/cy.xml": {
    "bytes": 47150,
    "gid": 0,
    "mode": 420,
    "sha256": "32fb4b9eb2c8567c67610038c7ded872a9d459cd72c85f6fbd9a6532ad035ab0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/da.xml": {
    "bytes": 33548,
    "gid": 0,
    "mode": 420,
    "sha256": "596edebaea8e13996537da366b0484ba85e97d4d9f9a9d85584b5ca46450b4fd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/de.xml": {
    "bytes": 34188,
    "gid": 0,
    "mode": 420,
    "sha256": "87432c35cfab28cd4c06c08d8d9a3ef8ddb264640fee4fb7dcda21dbdc35f518",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/el.xml": {
    "bytes": 35869,
    "gid": 0,
    "mode": 420,
    "sha256": "9b9a158ef54abcdffcec0d24761f93769d30e431f4fcfb0fc13a57cf8c3ef8e8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/en.xml": {
    "bytes": 45396,
    "gid": 0,
    "mode": 420,
    "sha256": "aafbaa3422e5d78b71d3fc6d668976752043207abfad197aa05920bc055dba12",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/entities.ent": {
    "bytes": 8445,
    "gid": 0,
    "mode": 420,
    "sha256": "2aa3067591c32c0260d3f1b592fc98f654db9e573ab99299a3b5428339589c91",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/eo.xml": {
    "bytes": 46196,
    "gid": 0,
    "mode": 420,
    "sha256": "f4309952470cc75259c0b4293b425f606e735bcaedd4ee39c1cd53d2755edb45",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/es.xml": {
    "bytes": 34486,
    "gid": 0,
    "mode": 420,
    "sha256": "c02b664955f35386bc28a23a48c71794697779fd14d766fe0ab30fd12997cd77",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/et.xml": {
    "bytes": 47122,
    "gid": 0,
    "mode": 420,
    "sha256": "48e853f51e57dc20847cfb883acc9c64e1d2b0acff2c7204aee37b0344bc3090",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/eu.xml": {
    "bytes": 47552,
    "gid": 0,
    "mode": 420,
    "sha256": "1c8db56e9988c6c99c5546d7e82021445875aff3e131f07969d6c4db4e09b198",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/fa.xml": {
    "bytes": 36552,
    "gid": 0,
    "mode": 420,
    "sha256": "97136dde8c381ec22713be04e88a4ff30f1b9124f61d01bf016d09e8de50f554",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/fi.xml": {
    "bytes": 34127,
    "gid": 0,
    "mode": 420,
    "sha256": "4e1d348f481641cafe5f7cf4882671ead9645e9c9cdbbc3381cde12e85015e7d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/fr.xml": {
    "bytes": 34240,
    "gid": 0,
    "mode": 420,
    "sha256": "fe5489a57fdaac07f9815e27939aa155696a9b1ae300f21e61c7034a6aa4faee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/ga.xml": {
    "bytes": 47134,
    "gid": 0,
    "mode": 420,
    "sha256": "5f714c658cbd4e6af01721bab79ce25bc14b2786019c2a9d23e569301c430352",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/gentext.xsl": {
    "bytes": 31083,
    "gid": 0,
    "mode": 420,
    "sha256": "5ca01e84715bf7567f05670bcd0053c13da12197ac765ec6345887af8032fd72",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/gl.xml": {
    "bytes": 47041,
    "gid": 0,
    "mode": 420,
    "sha256": "c7dc73bcff97c09a2991b28cd4923ce23fa2dbfa3b150ff8e351a30997b680ed",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/gu.xml": {
    "bytes": 37586,
    "gid": 0,
    "mode": 420,
    "sha256": "2eee5fb18920a1621eb9bdb61fea2e9d005df122902e7331ef9025cea81942b2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/he.xml": {
    "bytes": 48308,
    "gid": 0,
    "mode": 420,
    "sha256": "3fffde7e254d5f867f078a10a7c75336dfa41d0d0d4cf0e400118f8b277c38cd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/hi.xml": {
    "bytes": 37118,
    "gid": 0,
    "mode": 420,
    "sha256": "e505277ff69878b7e4a4c31e77a6ac5006f17c2d9bbc1b397582b23b92a21d83",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/hr.xml": {
    "bytes": 33741,
    "gid": 0,
    "mode": 420,
    "sha256": "03f58c984c4427f4e1f9a33fb76a09541456dcb847505d5c6b1320ff6c7c18cd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/hu.xml": {
    "bytes": 34186,
    "gid": 0,
    "mode": 420,
    "sha256": "2b1cbd18831e3f2675c92ad7711957bf47ff32d72318a50445e7a03a8e157218",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/id.xml": {
    "bytes": 46626,
    "gid": 0,
    "mode": 420,
    "sha256": "311815983b6a92afbf0c920d68274464ccbdc7b4e71db81e3973afd5855a96d7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/insertfile.xsl": {
    "bytes": 3929,
    "gid": 0,
    "mode": 420,
    "sha256": "ccef326fa469e70fd11d78ed0421a11c4ef4ee5868872a39bdf47116f4f1b4ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/is.xml": {
    "bytes": 31866,
    "gid": 0,
    "mode": 420,
    "sha256": "9945937e07459a3c28de01fc85db6b8512f478c69d6a2096a69715a6511c87f8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/it.xml": {
    "bytes": 46292,
    "gid": 0,
    "mode": 420,
    "sha256": "73772a328208498e385a45fcdfea7da1148f49400f1d0e89919669ad6f4b8576",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/ja.xml": {
    "bytes": 33426,
    "gid": 0,
    "mode": 420,
    "sha256": "e38f107de73238f5943c3337588824175495a6912f5e026b545b18d5b9424702",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/ka.xml": {
    "bytes": 39234,
    "gid": 0,
    "mode": 420,
    "sha256": "fb12ab0504ef8d6fa040466d76ea0a2c1bf105bbdca579eb6f6dc77ab425c5ef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/kn.xml": {
    "bytes": 51201,
    "gid": 0,
    "mode": 420,
    "sha256": "8845326ecaa1bf21cba8807b407da942d7f13f9911eaf0819b74088773df6c00",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/ko.xml": {
    "bytes": 47141,
    "gid": 0,
    "mode": 420,
    "sha256": "37b3b99d28563fecc2ab1cfdc39b014d29325e42a8f3d40e62a9a8d6769f7bd0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/ky.xml": {
    "bytes": 37492,
    "gid": 0,
    "mode": 420,
    "sha256": "3179c2004d65c2f8d1da5a58a719f94cf9b08969a86a1be0436ce836cd75a11f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/l10n.dtd": {
    "bytes": 1320,
    "gid": 0,
    "mode": 420,
    "sha256": "adfc7e18ad538026f3344dde3e309a386f434bc51e6a71832c8d2b66797ed882",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/l10n.xml": {
    "bytes": 2983,
    "gid": 0,
    "mode": 420,
    "sha256": "265172a990f1a41d488210ac3120b033ff539ff6fa88751843ea9275722f2d91",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/l10n.xsl": {
    "bytes": 20763,
    "gid": 0,
    "mode": 420,
    "sha256": "722105eedeb89ebf5504666480496560fb797b7f77621113c50bec7c472c8613",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/la.xml": {
    "bytes": 46991,
    "gid": 0,
    "mode": 420,
    "sha256": "bf5d637621e5d59a34b492f981c7b8f604e512e36539830a7bef383478205d27",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/labels.xsl": {
    "bytes": 33025,
    "gid": 0,
    "mode": 420,
    "sha256": "bf635f954437a2c6fbcec64bd5298a78f76a94de8ba3b007a2f441cdc8077f49",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/lt.xml": {
    "bytes": 34893,
    "gid": 0,
    "mode": 420,
    "sha256": "60717f668f4f142380a3f13ef2c97ba2bc3d49368e48e5887841853b8707de34",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/lv.xml": {
    "bytes": 46512,
    "gid": 0,
    "mode": 420,
    "sha256": "5fac413cf63bb6bf9839e2db958a157d8b0f752c72a079d62a60d3b69b5040e9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/ml.xml": {
    "bytes": 38522,
    "gid": 0,
    "mode": 420,
    "sha256": "fcd992008294909ec0e60d18b1c662b989c114e6c2003fb39ae37c8e4c224797",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/mn.xml": {
    "bytes": 37776,
    "gid": 0,
    "mode": 420,
    "sha256": "5b7a50bdecbd1c39417b0db328c2c06b3351c7c4e0313210a73999de5cc0ae49",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/mr.xml": {
    "bytes": 37000,
    "gid": 0,
    "mode": 420,
    "sha256": "0f4cd55d67014bf3736bb01e751231279418e2fdb7398c9e5a255e23ccae054d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/nb.xml": {
    "bytes": 47188,
    "gid": 0,
    "mode": 420,
    "sha256": "c3e37f78f876f1093c276b11bcf4f6915db41d9278de41da7280a24b44b62926",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/nds.xml": {
    "bytes": 33647,
    "gid": 0,
    "mode": 420,
    "sha256": "b46926ea576b75bfbe892515970fc97ebde6748344ff5d229115e7916121ecc1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/nl.xml": {
    "bytes": 34237,
    "gid": 0,
    "mode": 420,
    "sha256": "f978a6aa29efd13fdb606087595e232f6125bd35d2a6e98a07064e7ec9cf1808",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/nn.xml": {
    "bytes": 47072,
    "gid": 0,
    "mode": 420,
    "sha256": "9b7830200c5a6a68ee8ffac97b39af4df9a1855bd9b398e9d294fc872f37d5d1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/olink.xsl": {
    "bytes": 51993,
    "gid": 0,
    "mode": 420,
    "sha256": "cd844e6e7775ae0ca635c4738beb9f6d8278260372f2d183bb83dd2749b3fe80",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/or.xml": {
    "bytes": 51020,
    "gid": 0,
    "mode": 420,
    "sha256": "bb59210f4dc3c84d31343660aab2496d263aa329776345bd5c94bad16c1acf87",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/pa.xml": {
    "bytes": 36324,
    "gid": 0,
    "mode": 420,
    "sha256": "bb759ed5711402ded7ebb06b974dd0559d1079595b156ee9339e11bc14ce124d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/pi.xml": {
    "bytes": 5002,
    "gid": 0,
    "mode": 420,
    "sha256": "bc18888c84afa9f91c104cb3e698420b17da8f415b65a9ce48564d7a7bda9aef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/pi.xsl": {
    "bytes": 13764,
    "gid": 0,
    "mode": 420,
    "sha256": "feb07210157ea08a4ed82104374f53ffbb7e8d5346a3820b4177ebb30c6756cd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/pl.xml": {
    "bytes": 34259,
    "gid": 0,
    "mode": 420,
    "sha256": "cf29cb4b084cc0ed6843d3c3424a7db09ade304b35286b1bb62736543c9faece",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/pt.xml": {
    "bytes": 46887,
    "gid": 0,
    "mode": 420,
    "sha256": "24dcb48691662108143a8eda3af4fd44e439437ee15c60d653cd2b4937dbb735",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/pt_br.xml": {
    "bytes": 46379,
    "gid": 0,
    "mode": 420,
    "sha256": "fac830c06564cc98fab0f8c7e7e9bd4418ee8e8d6489ed0acf8f87472d8fcd38",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/refentry.xml": {
    "bytes": 22185,
    "gid": 0,
    "mode": 420,
    "sha256": "77f5ef4e2691b7040b481021e7f742501a42e7213ab1b1b3f6febc7bafd545ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/refentry.xsl": {
    "bytes": 56112,
    "gid": 0,
    "mode": 420,
    "sha256": "188a680af0e0685b22b601de397f300e4508c14dc5a68010976158f732e96866",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/ro.xml": {
    "bytes": 47334,
    "gid": 0,
    "mode": 420,
    "sha256": "6e4c07977f87312c7c911d260a59328c4107d1e01487fd60007857cb7e4aa942",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/ru.xml": {
    "bytes": 38086,
    "gid": 0,
    "mode": 420,
    "sha256": "4bd7d33e8ecae845c691577d4e30b4a2f9562448bc5a69b3c5beb5f7f8b6a0a9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/sk.xml": {
    "bytes": 46955,
    "gid": 0,
    "mode": 420,
    "sha256": "3a0177a23a2ec11ada11cbed6dcaf2a2edc0f4e4d1704f75b824903bf743c013",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/sl.xml": {
    "bytes": 47203,
    "gid": 0,
    "mode": 420,
    "sha256": "0733f65c1e19868adc5bab0babff006b3026a83925e7519896a45425969f79a9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/sq.xml": {
    "bytes": 47093,
    "gid": 0,
    "mode": 420,
    "sha256": "934aa2386bf53bdd317a8cb15c23dc992224ba2a933e6577a7ddd904c645cacf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/sr.xml": {
    "bytes": 37457,
    "gid": 0,
    "mode": 420,
    "sha256": "fc967b207e9f7a7687ad9a84569689bc9aa4f45921e2c70db99e983d4a59cd37",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/sr_Latn.xml": {
    "bytes": 34502,
    "gid": 0,
    "mode": 420,
    "sha256": "970ba576dc1c8a8c3ea5d5884efc0885ef2b1596bac543cb9cc496aaf18e4a73",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/stripns.xsl": {
    "bytes": 13230,
    "gid": 0,
    "mode": 420,
    "sha256": "b5755ca372b73f478aba0b0f78ff3d7e1d68211e529828214b26cb34fdb4266c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/subtitles.xsl": {
    "bytes": 7434,
    "gid": 0,
    "mode": 420,
    "sha256": "8c176a8251d213ec018cbf1430d0fa0491dbb0633355bff692780939af10a60e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/sv.xml": {
    "bytes": 34406,
    "gid": 0,
    "mode": 420,
    "sha256": "d41507de6954f4b44778a6a477928dbfa04ca0d5a8807b51a4e24d060cd42e11",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/ta.xml": {
    "bytes": 38858,
    "gid": 0,
    "mode": 420,
    "sha256": "3ae18a6099508903bdd014d8fc36c22ecb846efd8f23ae065f797de3fae5ee30",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/table.xsl": {
    "bytes": 18258,
    "gid": 0,
    "mode": 420,
    "sha256": "17eac7cfeb4c80c1c52a1fb7fd64f2a9fb67fe83a557f4e46e7a796411cea3d2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/targetdatabase.dtd": {
    "bytes": 1231,
    "gid": 0,
    "mode": 420,
    "sha256": "4daad7fda6dbb9fe02a3e16bad35df8933bf356f7f877abde21e4e768d6121c3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/targets.xsl": {
    "bytes": 10817,
    "gid": 0,
    "mode": 420,
    "sha256": "7af72ae67a1f1acd84528bf9b4730a984ab4d3bd739095b7af8936fd2414d9fa",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/te.xml": {
    "bytes": 39169,
    "gid": 0,
    "mode": 420,
    "sha256": "3fefa781b21d2d2e0df963dc6009c103c469e9f147f11c4863080731469e2a89",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/th.xml": {
    "bytes": 50022,
    "gid": 0,
    "mode": 420,
    "sha256": "8f023471d0718e66a48a541b99ecd31590e014cc0d7238ba043bd720ca89d3f1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/titles.xsl": {
    "bytes": 31204,
    "gid": 0,
    "mode": 420,
    "sha256": "eb0c79e96cb4fb6717c9421374c236185617af00b327422411985cc156713955",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/tl.xml": {
    "bytes": 47209,
    "gid": 0,
    "mode": 420,
    "sha256": "9e9801a68c75d8711aa6a3a8877a1b9b47b9d332c727adb4ab0ea6cfc06ecf05",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/tr.xml": {
    "bytes": 34085,
    "gid": 0,
    "mode": 420,
    "sha256": "243c922872d9a287a9679ea76d530b2b016474d7e3b94c5b227d15a0c7d647e4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/uk.xml": {
    "bytes": 37870,
    "gid": 0,
    "mode": 420,
    "sha256": "7374c6ef1bf9771d7e3f4486bd38c00742a925001c445a01a485eb9aa525bca6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/ur.xml": {
    "bytes": 34082,
    "gid": 0,
    "mode": 420,
    "sha256": "19fa2690e6803c8b960568552ae9c358eab10589a60e00b5a95a276e8e20775a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/utility.xml": {
    "bytes": 9695,
    "gid": 0,
    "mode": 420,
    "sha256": "f69eca679a4a1637c5bdd464f06bef1db18cbea6445f3c5ef3890cbeda1a8113",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/utility.xsl": {
    "bytes": 12143,
    "gid": 0,
    "mode": 420,
    "sha256": "75d7d39fa2559aa436313464bb2b0d43692805bce2cf1cb5b106a5e4b1e80285",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/vi.xml": {
    "bytes": 47646,
    "gid": 0,
    "mode": 420,
    "sha256": "65bd0e934f7e33d398aa403f63d6786603db5218cfa446647c2fa06fe5ef9f52",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/xh.xml": {
    "bytes": 47994,
    "gid": 0,
    "mode": 420,
    "sha256": "a48dba9f86169766035dae52aecfc50a90283be5baf53c4430ee9d6e5ce08de2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/zh.xml": {
    "bytes": 30414,
    "gid": 0,
    "mode": 420,
    "sha256": "f9b024d15bc34bb2c02196d1897c3d1cbbe5ad38907899f158b666c74d7f5943",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/zh_cn.xml": {
    "bytes": 30434,
    "gid": 0,
    "mode": 420,
    "sha256": "46ba4be5b23379a73bec96d42df5b59eaf4313b820c7923b576d6fd713f2752e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/common/zh_tw.xml": {
    "bytes": 33310,
    "gid": 0,
    "mode": 420,
    "sha256": "1888e905cca19448afc7c3eeb774edb5cb7c3b5bc0220ecab817e71709d0477c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/eclipse": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/eclipse/build.xml": {
    "bytes": 763,
    "gid": 0,
    "mode": 420,
    "sha256": "ef58cd553623d6c2e168c56e22bce75ecaf826a3eeb1f7fa370e16b0726c3948",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/eclipse/eclipse.xsl": {
    "bytes": 12738,
    "gid": 0,
    "mode": 420,
    "sha256": "c0b7d50f782246c47317e4859fdbb87b90f6f60a5b5bdb37f56c84d600e157f5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/eclipse/eclipse3.xsl": {
    "bytes": 3965,
    "gid": 0,
    "mode": 420,
    "sha256": "8fe6aac62d6af92adf9307048ca905491bcb286807f292dd8994d84ad6341e83",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/eclipse/profile-eclipse.xsl": {
    "bytes": 12943,
    "gid": 0,
    "mode": 420,
    "sha256": "e6a62e75c8a91831b1c86a37ce8369cb1240d2ae9d0a342b7d54e15cbd640f9c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub/docbook.xsl": {
    "bytes": 79395,
    "gid": 0,
    "mode": 420,
    "sha256": "b33fb7396b2408b056da05a2057479bf3a3d72a9a1dbb2db297403781e3dccf5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub3": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub3/build.xml": {
    "bytes": 758,
    "gid": 0,
    "mode": 420,
    "sha256": "d50e94d3083c274d292957c6ffca312031d058da5b2b716992ecbd8dd2a3f87e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub3/chunk.xsl": {
    "bytes": 976,
    "gid": 0,
    "mode": 420,
    "sha256": "2d3e10c6f483982039469f19df56faa8122459cb0d44c40479028f80daecd9d7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub3/chunkfast.xsl": {
    "bytes": 2796,
    "gid": 0,
    "mode": 420,
    "sha256": "f4169d3c19afc3591de347adc69aca15b65172fa8a0700ce14c6fb52e3773045",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub3/docbook-epub.css.xml": {
    "bytes": 2059,
    "gid": 0,
    "mode": 420,
    "sha256": "bf4addc9ab516ec832c1117bd55c0e9cf8b264200ade9a0b16f8acfb97ab270e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub3/docbook.xsl": {
    "bytes": 487,
    "gid": 0,
    "mode": 420,
    "sha256": "a9c8a02634fe81d41b3e52ecb7e6ffca8eb8100b37c520fca381d0e8ea3076c1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub3/epub3-chunk-mods.xsl": {
    "bytes": 2039,
    "gid": 0,
    "mode": 420,
    "sha256": "e5fc7950e8570c7698bb7b2b69f456230cc263ffd126419b41d71764fe0c02ad",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub3/epub3-element-mods.xsl": {
    "bytes": 97107,
    "gid": 0,
    "mode": 420,
    "sha256": "5589ab031c7707b7766ece2c45adbb1813fb28f2138e307cdcf671cbe42cfbdb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub3/profile-chunk.xsl": {
    "bytes": 2497,
    "gid": 0,
    "mode": 420,
    "sha256": "b2795cfa0b2189ecbda744869ccd1e2732d1b1b26310896533573dd484b8b0c0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub3/profile-docbook.xsl": {
    "bytes": 17910,
    "gid": 0,
    "mode": 420,
    "sha256": "43af0f500ec71411acfee37bfa2b672a8b73d952c8c5811fba0c257671052b3d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub3/titlepage.templates.xml": {
    "bytes": 16422,
    "gid": 0,
    "mode": 420,
    "sha256": "ca3dc628baeb710b8d25abd3163d217b58b5fe5a9e0580c07b3362cce5a6766b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/epub3/titlepage.templates.xsl": {
    "bytes": 180274,
    "gid": 0,
    "mode": 420,
    "sha256": "7de1bd1e265f5970ad9fb4197e1d5d6734a3efb4d7ef7f600654dc1f0bbacb01",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/admon.xsl": {
    "bytes": 4693,
    "gid": 0,
    "mode": 420,
    "sha256": "058eca7c3b1d864d06a11d270c22aad18824f2008f086267b57e471b7b6825e3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/annotations.xsl": {
    "bytes": 652,
    "gid": 0,
    "mode": 420,
    "sha256": "800d17b8e0ab791ca9886230f667c1a8a75036e1697c1340d4439b801a9c7578",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/autoidx-kimber.xsl": {
    "bytes": 6312,
    "gid": 0,
    "mode": 420,
    "sha256": "553e2667cea73f541d7058886ca255f72db519c77795f401b0dd45d4fad6bc05",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/autoidx-kosek.xsl": {
    "bytes": 5215,
    "gid": 0,
    "mode": 420,
    "sha256": "1d22d0d181fb7ca39fed2e0cf8f78387b4fd84f379f7701d00af54fc30f3c4fb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/autoidx-ng.xsl": {
    "bytes": 778,
    "gid": 0,
    "mode": 420,
    "sha256": "c5406f769ddb5c84cb00a31fc6ce3a04031ede3afd2caccef73f28889ade1390",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/autoidx.xsl": {
    "bytes": 56318,
    "gid": 0,
    "mode": 420,
    "sha256": "6ea350be0a442419ad5e787602b430dc7d9e87221f2c9a9a56a31df66abdd6dd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/autotoc.xsl": {
    "bytes": 32412,
    "gid": 0,
    "mode": 420,
    "sha256": "dfe0d0c0d0834acf2a4d29148d212dcaab0053556a5fbc1d221e2f770e816c04",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/axf.xsl": {
    "bytes": 4067,
    "gid": 0,
    "mode": 420,
    "sha256": "e9991d78752e139f53e598413a6e2a20fd1d5661548a220f75efc12fbde891ef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/biblio-iso690.xsl": {
    "bytes": 57163,
    "gid": 0,
    "mode": 420,
    "sha256": "98e39399caa9848ff0725c163cc5aa16810be178767839e45e391c6f216efc47",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/biblio.xsl": {
    "bytes": 36670,
    "gid": 0,
    "mode": 420,
    "sha256": "c79ad4294b2c047d3f8edc997e25ee0d16adf20bfe44050aa533ccdcd6df27f5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/block.xsl": {
    "bytes": 23150,
    "gid": 0,
    "mode": 420,
    "sha256": "5d75a2b6944cf39523e15d26ef4d39f72c1a025a96d62d6d12671f0011e10fbc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/build.xml": {
    "bytes": 1345,
    "gid": 0,
    "mode": 420,
    "sha256": "5eb40820a3f5bd59066af49d15752e2ae4894d5b1d113fa71bb86ac9ea023298",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/callout.xsl": {
    "bytes": 12177,
    "gid": 0,
    "mode": 420,
    "sha256": "41bd82dcc5ff10dc1677de5c6c1379df8b6001e28bf72c69f37a5efafc58b35b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/component.xsl": {
    "bytes": 35538,
    "gid": 0,
    "mode": 420,
    "sha256": "b6d75dc4832e1e48b6222d9774903ae4c561f7e30e3fa63262040457b3c40790",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/division.xsl": {
    "bytes": 23445,
    "gid": 0,
    "mode": 420,
    "sha256": "bd19177d0a642788d34b58d4193adde481749f4e3752bb28a3a60e566c400a55",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/docbook.xsl": {
    "bytes": 16657,
    "gid": 0,
    "mode": 420,
    "sha256": "ce9492abd8716bf17e06f3efef86ada911ed6049b28965aed937839d6e68c893",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/ebnf.xsl": {
    "bytes": 10680,
    "gid": 0,
    "mode": 420,
    "sha256": "0dffc6d5d1070830ddc2d6e475d8729db3f27e2b47704b86ae03c5f13682eebb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/fo-rtf.xsl": {
    "bytes": 5170,
    "gid": 0,
    "mode": 420,
    "sha256": "11b182a7fb529badff737271e03718c921a28e86d75a510918cb639d5ad8c77f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/fo.xsl": {
    "bytes": 4605,
    "gid": 0,
    "mode": 420,
    "sha256": "fc8a0b1cec58e5be2282626b690a75b80e9aadcf24fee9ff6ec8c0db4dbff627",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/footnote.xsl": {
    "bytes": 8748,
    "gid": 0,
    "mode": 420,
    "sha256": "c73873eef868fdb642560b09a9c758f32c21898861b577f7788edcff9c6e5c9c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/fop.xsl": {
    "bytes": 4346,
    "gid": 0,
    "mode": 420,
    "sha256": "293e9f5dbde7081000a461f8deb0aa0fa9b81f6860b48834651c0295e56e10ea",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/fop1.xsl": {
    "bytes": 7782,
    "gid": 0,
    "mode": 420,
    "sha256": "bb96e74efd30101aff7ac0ae7a90a8b46f3d305c88ac3235b55cffdf5b30524d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/formal.xsl": {
    "bytes": 22688,
    "gid": 0,
    "mode": 420,
    "sha256": "a95fb2cbe9b06163ff27c124118a3ddfa8398647bd506042e998f906858cb43f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/glossary.xsl": {
    "bytes": 45229,
    "gid": 0,
    "mode": 420,
    "sha256": "417917483566f8aafdef353c59702ee8cc07f39ea5b6b56d02543c5926e969bf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/graphics.xsl": {
    "bytes": 26652,
    "gid": 0,
    "mode": 420,
    "sha256": "5e35e1e2a1693e3ee7472b6dced8f0909d30f58c815413454932c90f7568673a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/highlight.xsl": {
    "bytes": 2602,
    "gid": 0,
    "mode": 420,
    "sha256": "19188770b581853a82a9731aa146c318a023833770c0b733102c4af10a453343",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/htmltbl.xsl": {
    "bytes": 16434,
    "gid": 0,
    "mode": 420,
    "sha256": "592067c5f9905bc28112785708e91375094f02221ce39f64098eb1ac0908d8e9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/index.xsl": {
    "bytes": 17881,
    "gid": 0,
    "mode": 420,
    "sha256": "8eea8b78328cd7e166ca6ec86ab29d032bd997be306cda1fed018730dd83b233",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/info.xsl": {
    "bytes": 1275,
    "gid": 0,
    "mode": 420,
    "sha256": "18a060ceb36d2619c684fc74f18cb8db06c634c421c8c67fbf95f60626e75c74",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/inline.xsl": {
    "bytes": 43314,
    "gid": 0,
    "mode": 420,
    "sha256": "60e5678c216b592c07a8b7c3a9b6ab8e18c0eaf3516ff0178012e809e83bfe2a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/keywords.xsl": {
    "bytes": 796,
    "gid": 0,
    "mode": 420,
    "sha256": "097e6c5b6189dd36f850e4c5933feb6aa7a0f7be742ad8127cb099f23abc57b1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/lists.xsl": {
    "bytes": 48956,
    "gid": 0,
    "mode": 420,
    "sha256": "ce94aa0324e8ec8033e6ff8bbabbc77528d35afe0bd7173260247a3501269604",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/math.xsl": {
    "bytes": 2824,
    "gid": 0,
    "mode": 420,
    "sha256": "63686e0e063ab33807082c2763f77e2a2760f1610d9087649eb544ab1ad157ab",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/pagesetup.xsl": {
    "bytes": 160926,
    "gid": 0,
    "mode": 420,
    "sha256": "a38b5d11f1ed47743b9b3ea14c15e72ec1f64460e350f83f5496b5fe58b58f4f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/param.xml": {
    "bytes": 497725,
    "gid": 0,
    "mode": 420,
    "sha256": "2365111873537ba52e8387f7bdf9ab20823048f6f378c3bef4d16d355096d864",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/param.xsl": {
    "bytes": 51459,
    "gid": 0,
    "mode": 420,
    "sha256": "c14edb0f20a0353d7c4a57c45c7ed7f91f5ff31e7a7c7fa2cc65b4333d5a0bc5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/passivetex.xsl": {
    "bytes": 1310,
    "gid": 0,
    "mode": 420,
    "sha256": "3d00441f939a536bef23d462e658082eebe62f63871e1dcd8e4ead20fa800f97",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/pi.xml": {
    "bytes": 33756,
    "gid": 0,
    "mode": 420,
    "sha256": "4bc7fa05b14712c77cb2e9bc87ea3dec8ccf11a6837045af4dbeba260f600750",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/pi.xsl": {
    "bytes": 43076,
    "gid": 0,
    "mode": 420,
    "sha256": "1de1ddf1ed5ef4c0b03402cf43ba37e41a405059d7ffafdb84ddbf2fc7e6c0a3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/profile-docbook.xsl": {
    "bytes": 16265,
    "gid": 0,
    "mode": 420,
    "sha256": "0e301b8231bb356a918a2c006144b41a297ab8eb357a04c7cd911c5e22965517",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/ptc.xsl": {
    "bytes": 3991,
    "gid": 0,
    "mode": 420,
    "sha256": "7c77277c578c9494d47569f78d66246dfe03ab77af1363797665c3e9a722bd81",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/publishers.xsl": {
    "bytes": 3761,
    "gid": 0,
    "mode": 420,
    "sha256": "a8000c4efe0b73fc4c4741edfea425df07f520b32ce6f628920bcde65e8eed4d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/qandaset.xsl": {
    "bytes": 14513,
    "gid": 0,
    "mode": 420,
    "sha256": "2d9ead837473c8874af79a018e59a773c3d8742acbf5fba470a9367437a70844",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/refentry.xsl": {
    "bytes": 25580,
    "gid": 0,
    "mode": 420,
    "sha256": "a700f8c2c25fcf152c14fc654890bb79d2aa5eea8059b8964e5ba77a47e85e38",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/sections.xsl": {
    "bytes": 28372,
    "gid": 0,
    "mode": 420,
    "sha256": "8e2e571bbfc87c014f48ea10d0de083cd8ef9bf05fcc5398906b2fe3da288755",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/spaces.xsl": {
    "bytes": 9851,
    "gid": 0,
    "mode": 420,
    "sha256": "c560b97f67a356318b34d0ec66a2ecf86618d4b46edcc20b146a41a751a62f1d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/synop.xsl": {
    "bytes": 32456,
    "gid": 0,
    "mode": 420,
    "sha256": "61698fba8f19300ad2d9cae81e0c7ec96e4343060b03ce38e77f588297078ebb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/table.xml": {
    "bytes": 2851,
    "gid": 0,
    "mode": 420,
    "sha256": "36757648b1972e80ce2fefe8197c071fffa12ff012f5c75bb30a9020e046fd9d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/table.xsl": {
    "bytes": 61330,
    "gid": 0,
    "mode": 420,
    "sha256": "37fcf2689584fac87f844fccba8079caa30c9a6fdc0e62d8afa789f56d7d23f8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/task.xsl": {
    "bytes": 2792,
    "gid": 0,
    "mode": 420,
    "sha256": "75788c46c216bc757a2e42da03252cd146c4a2b5c42164315a1b0a8b99ff5c94",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/titlepage.templates.xml": {
    "bytes": 43202,
    "gid": 0,
    "mode": 420,
    "sha256": "88a2b63e7daa410191ed61c42989adbe4a9392c66a750aefe1d6ee7706e36af1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/titlepage.templates.xsl": {
    "bytes": 319281,
    "gid": 0,
    "mode": 420,
    "sha256": "235ad53ed693bb0cdce4eb3fd1e2ac93063fb0b6f0a3bd242f29dfe88cfc7694",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/titlepage.xsl": {
    "bytes": 28849,
    "gid": 0,
    "mode": 420,
    "sha256": "89715d27f1395e1cec439cc0af46494f9cb22cfd0735ce82d63e739e862346d3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/toc.xsl": {
    "bytes": 11784,
    "gid": 0,
    "mode": 420,
    "sha256": "7681b15ddf0d2c8b9cb7217df47b104163adc4939323af559fed6b8e0980ef9d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/verbatim.xsl": {
    "bytes": 18166,
    "gid": 0,
    "mode": 420,
    "sha256": "f13e3f0df725f7ff51a713fb2076a614d56781f09a5f0f0712180a56c02addd4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/xep.xsl": {
    "bytes": 7426,
    "gid": 0,
    "mode": 420,
    "sha256": "f7c6e0b7da0190c7a59656b815f19dbd420fe32c09de502c9c2982628ee47a64",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/fo/xref.xsl": {
    "bytes": 59626,
    "gid": 0,
    "mode": 420,
    "sha256": "8ea487848742835f47ed38504dfa3b5a4959e2c29cf79c7cd2c4cb16a5c1c8b0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/bourne-hl.xml": {
    "bytes": 2691,
    "gid": 0,
    "mode": 420,
    "sha256": "a7c0b63f6bf539842047a84eb9c96464230a7de9c8f8c5ede43385c5396ea02d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/c-hl.xml": {
    "bytes": 3595,
    "gid": 0,
    "mode": 420,
    "sha256": "60aed026c6a11fa6ffa1d371b2e0d33c7aab9803bfb5d2e3ff964d5dd89cb468",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/cmake-hl.xml": {
    "bytes": 5998,
    "gid": 0,
    "mode": 420,
    "sha256": "be5b5cd967e90b0aa52e3ec1366472c3674b44e7b9fed2772eaa4498aaca3fb6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/common.xsl": {
    "bytes": 4056,
    "gid": 0,
    "mode": 420,
    "sha256": "37dbcf21cc8ed12bbd9835c30c4186e9d674b448cb5f07ecb59673056f6fc318",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/cpp-hl.xml": {
    "bytes": 4539,
    "gid": 0,
    "mode": 420,
    "sha256": "1f18f6e80a0981883e66f1314d8da3f64dc726266acb0bc1ffc3ecc8a65fb43c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/csharp-hl.xml": {
    "bytes": 5702,
    "gid": 0,
    "mode": 420,
    "sha256": "417af260d4126bf388eb2fc8a3302f67a40d7873fb6bc781a32f51fb39da0acb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/css21-hl.xml": {
    "bytes": 6637,
    "gid": 0,
    "mode": 420,
    "sha256": "8e597363f8723873e0f3002db5eb65495c2907cc909de3ac0505e627283fd820",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/delphi-hl.xml": {
    "bytes": 8948,
    "gid": 0,
    "mode": 420,
    "sha256": "e3d83b96b3622cb7ea48ef443bafc4b2742cad964b45fe61cacf6cb1cc601bf2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/ini-hl.xml": {
    "bytes": 1662,
    "gid": 0,
    "mode": 420,
    "sha256": "b485127b70950ecbf714fe9231700e9f74d0c3096afe311ff51d8bebe776ac7f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/java-hl.xml": {
    "bytes": 3553,
    "gid": 0,
    "mode": 420,
    "sha256": "cb269d3fe5234adb5f2eee1833fa5d6eeb81924487eca032a6bb0d66dd262a61",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/javascript-hl.xml": {
    "bytes": 4529,
    "gid": 0,
    "mode": 420,
    "sha256": "5dc3bee14f80800a2c727ddb4823c4337c52c305fe6f82b5d93f080b482614f3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/lua-hl.xml": {
    "bytes": 3897,
    "gid": 0,
    "mode": 420,
    "sha256": "c7102514756cfb7552ba67ff22c26d43742239a2331ef3f09b2950f913d5b31d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/m2-hl.xml": {
    "bytes": 2795,
    "gid": 0,
    "mode": 420,
    "sha256": "58914242f3b91f5f199744e11a883a514892adae648f8c6fa535eed1c51ea33e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/myxml-hl.xml": {
    "bytes": 3161,
    "gid": 0,
    "mode": 420,
    "sha256": "a837eefaa2c3ab1d301df52c2a10c9dacaad3879f6a6adef763a644d3312e06e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/perl-hl.xml": {
    "bytes": 3676,
    "gid": 0,
    "mode": 420,
    "sha256": "7068e1744af6995720c9a4d82da92e8a313ea76c541d52191588129f821dcf80",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/php-hl.xml": {
    "bytes": 4687,
    "gid": 0,
    "mode": 420,
    "sha256": "61cbbdae563613467e64ec3d18239e36e2e3adc21e8e77fb0c075619b5e91be8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/python-hl.xml": {
    "bytes": 3023,
    "gid": 0,
    "mode": 420,
    "sha256": "13647a808273a4a4172b5a3030b3529ee5b1309990d997d869385e76c5f0e0fe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/ruby-hl.xml": {
    "bytes": 3247,
    "gid": 0,
    "mode": 420,
    "sha256": "a2e0d217886e7da909a2725ba393c52d2554959e7d32f57696a5580d91c0abbe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/sql1999-hl.xml": {
    "bytes": 14719,
    "gid": 0,
    "mode": 420,
    "sha256": "8b94ad27a9402726c48fb8a85619fea3c70baf8a63187716f9bedc9fb7a4ecf6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/sql2003-hl.xml": {
    "bytes": 16882,
    "gid": 0,
    "mode": 420,
    "sha256": "e40f16b054d47ade708be9a9440c773ef118c715e3899b0835ef0f5c3ac646d9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/sql92-hl.xml": {
    "bytes": 9960,
    "gid": 0,
    "mode": 420,
    "sha256": "a6f798d03c0be17d5796f3577efaca0b2851159d0e7944e75d8f73b1e565b193",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/tcl-hl.xml": {
    "bytes": 5173,
    "gid": 0,
    "mode": 420,
    "sha256": "d7120452655592be473be6695fdbfb9019d9b0f3d01ec7a23326881ce4e07c8f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/upc-hl.xml": {
    "bytes": 4211,
    "gid": 0,
    "mode": 420,
    "sha256": "2326c31c608d4323ef52968974d1e07a4b3f95950504d81c99b9c303ff7bdfa5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/highlighting/xslthl-config.xml": {
    "bytes": 2494,
    "gid": 0,
    "mode": 420,
    "sha256": "5df66ed6c36bc308b4a71b08bbd37ffecac0e2568321766a933ca501148309e5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/admon.xsl": {
    "bytes": 4819,
    "gid": 0,
    "mode": 420,
    "sha256": "cadb1b649bbd8da2a860326de7fc6358cd74da04662eab2a0cf5515674d2fb95",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/annotations.xsl": {
    "bytes": 5763,
    "gid": 0,
    "mode": 420,
    "sha256": "15dd41831413d0714c422f9cc9e01abf62466bcb3917cb3844ef3c1f7dfb18a7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/autoidx-kimber.xsl": {
    "bytes": 6011,
    "gid": 0,
    "mode": 420,
    "sha256": "6a565659f2dece0125a8a3d7805629d722153d178f4ec2703b71b81064580358",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/autoidx-kosek.xsl": {
    "bytes": 4467,
    "gid": 0,
    "mode": 420,
    "sha256": "7234bed75c8b976c7a151ada7aac8c12359f76e4e668fcfca371b305a09a3c4e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/autoidx-ng.xsl": {
    "bytes": 766,
    "gid": 0,
    "mode": 420,
    "sha256": "8e3b2dd02893d14270225383729221daa351fe6443a08a64c9e6d2f91dc7711c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/autoidx.xsl": {
    "bytes": 34842,
    "gid": 0,
    "mode": 420,
    "sha256": "2ae96aa7f120a7223c5d11c6c6cba661f5b0022f4fe68672298c1b287b1766da",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/autotoc.xsl": {
    "bytes": 28831,
    "gid": 0,
    "mode": 420,
    "sha256": "09a9f83d703407bb7cd9e9f9a972f1ef4fb4a403af90cdff2e399eb055040a63",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/biblio-iso690.xsl": {
    "bytes": 57029,
    "gid": 0,
    "mode": 420,
    "sha256": "5f0affc2291637061fab34c331c016e3a573fd588bd3f01a944789ca65019a4b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/biblio.xsl": {
    "bytes": 45389,
    "gid": 0,
    "mode": 420,
    "sha256": "6c813bc328fbdc2effd8c484bc77122a22956093fdcfaf9e612a1e4778a0ec55",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/block.xsl": {
    "bytes": 17120,
    "gid": 0,
    "mode": 420,
    "sha256": "a2a6bc2a2182241623c19b34e24588d153de531c238f1725a7e5371606d08697",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/build.xml": {
    "bytes": 1355,
    "gid": 0,
    "mode": 420,
    "sha256": "2440a685e78216ae76ce3d15175fd3c292bad284c615e3d3956c05d46ca37194",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/callout.xsl": {
    "bytes": 8027,
    "gid": 0,
    "mode": 420,
    "sha256": "5672ec6831c503154b316b6cd88da1a19602e75e3c78ec35ef41efce3c33cd5e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/changebars.xsl": {
    "bytes": 4045,
    "gid": 0,
    "mode": 420,
    "sha256": "3377b954dcf3406b8b522fa57b872b521681d8e01f280752d72167b2dee3ca2d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/chunk-changebars.xsl": {
    "bytes": 3843,
    "gid": 0,
    "mode": 420,
    "sha256": "09e21eed438fe9367b8aa7af398bef8ce2c9ca6ec433cae06082ef99c101bd34",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/chunk-code.xsl": {
    "bytes": 25494,
    "gid": 0,
    "mode": 420,
    "sha256": "8b7b9c7eb18ec220e4f8e6f726bdb18b25bf17fdf9fbac63fce4ee765ab31438",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/chunk-common.xsl": {
    "bytes": 86017,
    "gid": 0,
    "mode": 420,
    "sha256": "8daaf4b758213f0afb678854288e3bb7accef690bf7ea3126a070c9bc28b096d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/chunk.xsl": {
    "bytes": 2287,
    "gid": 0,
    "mode": 420,
    "sha256": "77b8d50466a9afb5adbffeca34f1945c07979d35533d37d4cf0532150987cd0a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/chunker.xsl": {
    "bytes": 21514,
    "gid": 0,
    "mode": 420,
    "sha256": "88e239347d79d1c3ba2a95dcbe54aa3f6ed0f69e3ae958a9d8bb2876e84bfed5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/chunkfast.xsl": {
    "bytes": 2709,
    "gid": 0,
    "mode": 420,
    "sha256": "d7d759928d54acf64257d0479b61088eeff29405454522956da70d5e330e4c77",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/chunktoc.xsl": {
    "bytes": 19131,
    "gid": 0,
    "mode": 420,
    "sha256": "1681174577b9424990cd6d43ca878ca9e5ed0ba28d9440ded0204511b3e1966b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/component.xsl": {
    "bytes": 17463,
    "gid": 0,
    "mode": 420,
    "sha256": "37d4922d16165582a99d8caf135d7a91fce240dfd4e3da6c1d75370fe6c8e945",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/division.xsl": {
    "bytes": 7186,
    "gid": 0,
    "mode": 420,
    "sha256": "a87b1696e211e1bceff9032a25381de318f17f7f41621c268d35831790fd3ee5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/docbook.css.xml": {
    "bytes": 1623,
    "gid": 0,
    "mode": 420,
    "sha256": "653067889f6a4a8f427cd4fb72176776da4124e76aa79b448b2b8fecaa065497",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/docbook.xsl": {
    "bytes": 20445,
    "gid": 0,
    "mode": 420,
    "sha256": "2f83b512a5caa6e5a0d1090b0363b16327a6f31fa2bd6847c3cff17582667ef8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/ebnf.xsl": {
    "bytes": 10371,
    "gid": 0,
    "mode": 420,
    "sha256": "8968b5a4e7e4e31177cd698a53726653833301dd8e8fd25c26271f720befc2e4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/footnote.xsl": {
    "bytes": 12475,
    "gid": 0,
    "mode": 420,
    "sha256": "e26362fa2620e558b06b62e28fb0d1c60c60a37c3be4658e6b08148c5a122010",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/formal.xsl": {
    "bytes": 16619,
    "gid": 0,
    "mode": 420,
    "sha256": "048a772b29f47b105f343c3c570431e0ac167ed90b788f0bc6dd8464aa359f8e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/glossary.xsl": {
    "bytes": 18581,
    "gid": 0,
    "mode": 420,
    "sha256": "f77a9834d92fb5aea094e3ac80baa921f1c02c609c82474b407b6f44639d4c93",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/graphics.xsl": {
    "bytes": 60487,
    "gid": 0,
    "mode": 420,
    "sha256": "16afe458ed16e794b32e11e6d11de00b9594dd32e481e9a9fb87ae6cdde18d8a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/highlight.xsl": {
    "bytes": 3021,
    "gid": 0,
    "mode": 420,
    "sha256": "db27667b4eaca53e52d3bb17acdb68b85e340e097a98396ed1ce15673668268c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/html-rtf.xsl": {
    "bytes": 11370,
    "gid": 0,
    "mode": 420,
    "sha256": "e8437f7b7898ccddfabfeb38f7be4490c7fd3c286290028dab2fd52cd4e537a0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/html.xsl": {
    "bytes": 24147,
    "gid": 0,
    "mode": 420,
    "sha256": "26ee57a1eb3808e4c4a79c5f7c30023eba95f978aaeda78360bb0eed1ac9d620",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/htmltbl.xsl": {
    "bytes": 4604,
    "gid": 0,
    "mode": 420,
    "sha256": "aa4e4ee39bbe9d8a5420a45a5ebe0c39caadceddfc6fdd0c62a17d7ab5c81ee9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/index.xsl": {
    "bytes": 10384,
    "gid": 0,
    "mode": 420,
    "sha256": "7421f91de156dc16e9c4cd0da28a2922a8bad7a5c8d99c727e1d8bc655618ed1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/info.xsl": {
    "bytes": 1606,
    "gid": 0,
    "mode": 420,
    "sha256": "26edf7173603c11c22e07ab32b82269a88031fde8e26004e8183a853cb43d4e1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/inline.xsl": {
    "bytes": 50774,
    "gid": 0,
    "mode": 420,
    "sha256": "c4073cc1802a0df2062adf6175b3649d6b627c1eb400d5c41de5a5bbb983e42c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/its.xsl": {
    "bytes": 4518,
    "gid": 0,
    "mode": 420,
    "sha256": "877c5466c7659741e089883f1653be2f538c28da0ad6fc0f6212bc9332261cc7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/keywords.xsl": {
    "bytes": 1196,
    "gid": 0,
    "mode": 420,
    "sha256": "b8c403f3456fe9bac25656b91f5f639925a9cd4f65873da9f691dec79d331b31",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/lists.xsl": {
    "bytes": 42332,
    "gid": 0,
    "mode": 420,
    "sha256": "8c92249d27d735cb525f473bca3730b0d47113bc82dba31e4773b6207450b103",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/maketoc.xsl": {
    "bytes": 2667,
    "gid": 0,
    "mode": 420,
    "sha256": "4b0b29d4bfffc164a099ca9ff54dc2cb046d0b94d16b8ef6cf97ef16e3d1c493",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/manifest.xsl": {
    "bytes": 917,
    "gid": 0,
    "mode": 420,
    "sha256": "e19442c30ba7daf794f85a948efdcd0f3bb00e0011d584945316f3ffeefcf731",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/math.xsl": {
    "bytes": 9163,
    "gid": 0,
    "mode": 420,
    "sha256": "07027cc784c8c6d0907d9cf62d1741deea8d32d9fc8b81000496adddcdd9b617",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/oldchunker.xsl": {
    "bytes": 7435,
    "gid": 0,
    "mode": 420,
    "sha256": "24afedc9b8fa92b83c349c2ecc9be5fa1f3e0f772d46ae3eea97b64e13b221c1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/onechunk.xsl": {
    "bytes": 1369,
    "gid": 0,
    "mode": 420,
    "sha256": "966adc5965fbde5517d3247e48bae10545a5731cc5215da31580a783f743a816",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/param.xml": {
    "bytes": 401480,
    "gid": 0,
    "mode": 420,
    "sha256": "56d6f67c32e68170ddc396ad354c3fcce71cde62f57bfcf86b76088e561f2058",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/param.xsl": {
    "bytes": 20389,
    "gid": 0,
    "mode": 420,
    "sha256": "02d291720f4265c17f82d4f6fa5911819559338c72fb39fd6c36d45a85c26d21",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/pi.xml": {
    "bytes": 39440,
    "gid": 0,
    "mode": 420,
    "sha256": "5ca494b4c7d90bfee46b456c1b6e653b0c3453241b4dd7eb29ed6b9c9266200f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/pi.xsl": {
    "bytes": 49002,
    "gid": 0,
    "mode": 420,
    "sha256": "b7aa45b9e7901b8ae4a46c68c664dceb5e81b75102d17e17824cd937b2c3f856",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/profile-chunk-code.xsl": {
    "bytes": 26011,
    "gid": 0,
    "mode": 420,
    "sha256": "04478fdfdad025b1e5573a2e3735c71b06479a90e62714272035c79eba84b1ff",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/profile-chunk.xsl": {
    "bytes": 2294,
    "gid": 0,
    "mode": 420,
    "sha256": "43c2e27eea0c80dbac0715c6184e58e8bffdb75e77f3e4de7e25f865d77821ed",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/profile-docbook.xsl": {
    "bytes": 20540,
    "gid": 0,
    "mode": 420,
    "sha256": "366c2a7158cb2099695e2aa735bd2280c37f06469bd61dca4d5f04d70c3d41a2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/profile-onechunk.xsl": {
    "bytes": 1377,
    "gid": 0,
    "mode": 420,
    "sha256": "e274344a5ba70c5f8e704223ee61ed8a90c79009300811851c811e602d70a608",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/publishers.xsl": {
    "bytes": 3372,
    "gid": 0,
    "mode": 420,
    "sha256": "990f6368c41f0e1ef9ad2458e95c9be87ce59a4bf7c894999ed7a29581f08379",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/qandaset.xsl": {
    "bytes": 15747,
    "gid": 0,
    "mode": 420,
    "sha256": "33a5268d93711a12d254ea2e931a5d442768b4d2cd49906e8f382aa215579a3e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/refentry.xsl": {
    "bytes": 10079,
    "gid": 0,
    "mode": 420,
    "sha256": "1f0a94ff3c80c428e5a2c900cbf3825f1ba4039aaaf945772b784504b4e7ea6d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/sections.xsl": {
    "bytes": 23643,
    "gid": 0,
    "mode": 420,
    "sha256": "2ed224c13f824ff7b08ab8cdc697cf28543419a06c38a12e338a1606baa407ee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/synop.xsl": {
    "bytes": 52397,
    "gid": 0,
    "mode": 420,
    "sha256": "29adb7121d0d32d9e60541733e4c9fa2546beb07c46fa6b52dafd24a02976c82",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/table.xsl": {
    "bytes": 44034,
    "gid": 0,
    "mode": 420,
    "sha256": "bc5e0a61027da5a77dd895402098bdd5b69b54bd3c67b7154bea0d2950f6a549",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/task.xsl": {
    "bytes": 2436,
    "gid": 0,
    "mode": 420,
    "sha256": "9e379b1e9fdee86b63441581877a56ec9006fd680f4f8ca27dbd13ed8187f213",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/titlepage.templates.xml": {
    "bytes": 19289,
    "gid": 0,
    "mode": 420,
    "sha256": "f811acac4681bcaf66b9c30a8b5c970a0e72d037646371bda8d687578a366c04",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/titlepage.templates.xsl": {
    "bytes": 199949,
    "gid": 0,
    "mode": 420,
    "sha256": "93aa56012e040692348add198b83dcd02c6c7059c86011c2509fdd8ce1e4e8b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/titlepage.xsl": {
    "bytes": 38605,
    "gid": 0,
    "mode": 420,
    "sha256": "63f4d688126136431bfab4dd868e62518b6c533d16ce894072b29cc304c0cf37",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/toc.xsl": {
    "bytes": 12879,
    "gid": 0,
    "mode": 420,
    "sha256": "8fdcde14447fc50aab35b55dfd0144c8ee70f03ace5db4bfaaf678654da4d6ff",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/verbatim.xsl": {
    "bytes": 14138,
    "gid": 0,
    "mode": 420,
    "sha256": "760f79a735476d014b599daf03fc0d1906318a6baae78362d75ba50f1ef05761",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/html/xref.xsl": {
    "bytes": 47906,
    "gid": 0,
    "mode": 420,
    "sha256": "f64c21da5b5880bf6eba6007386245c8480b25add53daaeef92560d2640b6de9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/htmlhelp": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/htmlhelp/build.xml": {
    "bytes": 791,
    "gid": 0,
    "mode": 420,
    "sha256": "8ca27118357b22e4b86f0bd323460759b4cabe72bbce85fa4375c9767c90eacc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/htmlhelp/htmlhelp-common.xsl": {
    "bytes": 39544,
    "gid": 0,
    "mode": 420,
    "sha256": "cba5453a98e5f81e1a12e13d302f215d88d7b2c1beff672c4e5b07a4c51efe09",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/htmlhelp/htmlhelp.xsl": {
    "bytes": 836,
    "gid": 0,
    "mode": 420,
    "sha256": "b18ffdc75988fc66cad9578be01142983dc771ca8ba9d4d74f790309bd521c92",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/htmlhelp/profile-htmlhelp-common.xsl": {
    "bytes": 40364,
    "gid": 0,
    "mode": 420,
    "sha256": "b8b85b912851bb6c56db0548d6eebe7f95e223cd0f508acb64eeaa15597dc031",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/htmlhelp/profile-htmlhelp.xsl": {
    "bytes": 844,
    "gid": 0,
    "mode": 420,
    "sha256": "e7d8d89c24704867310cead8127be6e42b9b9dfb79e5c7c673db1ea6ca4dc1c4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/javahelp": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/javahelp/build.xml": {
    "bytes": 768,
    "gid": 0,
    "mode": 420,
    "sha256": "8222ac2522cc59c811502f9582a447213aa1cbc178189746caf3dcb36e7e9c14",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/javahelp/javahelp.xsl": {
    "bytes": 21803,
    "gid": 0,
    "mode": 420,
    "sha256": "f86a8dd77ce4be581086f8de4ac4a08ab2760d57588732e977402b203619003d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/javahelp/profile-javahelp.xsl": {
    "bytes": 21822,
    "gid": 0,
    "mode": 420,
    "sha256": "5fda99ab4c946fd2bbfaaa0ad8a5b53e6ae8675a46a5ecd25039ef52e9112f6f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/lib": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/lib/build.xml": {
    "bytes": 633,
    "gid": 0,
    "mode": 420,
    "sha256": "f196e8a11686406461a6b2e9b76c5b57d156f795105f1633c14de05cbf9eb967",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/lib/lib.xsl": {
    "bytes": 20863,
    "gid": 0,
    "mode": 420,
    "sha256": "7f3770de157446446e079644824ba99c8fab1db6beee85b46a824c7025adc502",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/block.xsl": {
    "bytes": 16132,
    "gid": 0,
    "mode": 420,
    "sha256": "2c7adf2f95b046d74675a528362a7c4a553e2d0b316feeb6c95478574376d6b0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/build.xml": {
    "bytes": 1352,
    "gid": 0,
    "mode": 420,
    "sha256": "f05f271d64b2f99938b7fbec7e88d38ba5894039cfecf10a7140f4e4a21f6f41",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/charmap.groff.xsl": {
    "bytes": 153761,
    "gid": 0,
    "mode": 420,
    "sha256": "ad732082a2d5a743cefc93200f7e49e0c186bb05bf30eaad950fc572eefe6df0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/docbook.xsl": {
    "bytes": 15233,
    "gid": 0,
    "mode": 420,
    "sha256": "a4d07ef51f789f0d461dbce0ad347f9097ba9d0706607be489bdec15257afe1e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/endnotes.xsl": {
    "bytes": 26600,
    "gid": 0,
    "mode": 420,
    "sha256": "a75d8a8df63411dfcedf3432666ec03e7bc4908cd063304d4925112197639905",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/html-synop.xsl": {
    "bytes": 52721,
    "gid": 0,
    "mode": 420,
    "sha256": "09fca74a0d8392f8969b8c322e73031db5e95a1b4239e68578494efb5c44f40a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/info.xsl": {
    "bytes": 35683,
    "gid": 0,
    "mode": 420,
    "sha256": "b4379945f6320f1cde760d1327cf129eaf9df8ac35e08faa69c42bb932845b47",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/inline.xsl": {
    "bytes": 7340,
    "gid": 0,
    "mode": 420,
    "sha256": "c326085caed2faf6792a5edef46c2922843c296778264b9743bef0c81249ea40",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/lists.xsl": {
    "bytes": 23900,
    "gid": 0,
    "mode": 420,
    "sha256": "87a7b4e84a20dbdfb2762cfc81ca310dce8a08196f90d467c898be5e662fbea6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/other.xsl": {
    "bytes": 34589,
    "gid": 0,
    "mode": 420,
    "sha256": "9724909c4951b15324e9bf7e7990f7310a81c249c36e272d403fe182d3c8007c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/param.xml": {
    "bytes": 131220,
    "gid": 0,
    "mode": 420,
    "sha256": "e496fc692e7e6e214a70938bf4eb325a28241cd94357c3074db352a0e1e385fa",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/param.xsl": {
    "bytes": 8932,
    "gid": 0,
    "mode": 420,
    "sha256": "1534e3a82f86ad6a771e4b4ceb1ed0f9fe661af8ffeb6c02bb843a5125f87e60",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/pi.xml": {
    "bytes": 2171,
    "gid": 0,
    "mode": 420,
    "sha256": "05cce675ed4a1b7e2a49f2cc4625ca7dd5f8077584aee8a17cc948769bd8bcff",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/pi.xsl": {
    "bytes": 3042,
    "gid": 0,
    "mode": 420,
    "sha256": "a428f21d6c7fbb8295d758ec9a23efb6d668b18259bc96923b380d3699bbe657",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/profile-docbook.xsl": {
    "bytes": 15146,
    "gid": 0,
    "mode": 420,
    "sha256": "b2f13b3d1a12352b3988e332d7080bde801f9bbb41234863c22ba73329daac74",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/refentry.xsl": {
    "bytes": 12482,
    "gid": 0,
    "mode": 420,
    "sha256": "0bac60e237fec6cf8b821e2ce1520a264321c08abe1934dbd9138bdd03390d65",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/synop.xsl": {
    "bytes": 16548,
    "gid": 0,
    "mode": 420,
    "sha256": "469c82ec46b6ceac216b46b3846ad510520ba84572fefe968b88ff49350a730f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/table.xsl": {
    "bytes": 5818,
    "gid": 0,
    "mode": 420,
    "sha256": "0f0d80f638ee78f5709f9cd4dca316d14871f351356e54a4540f4bf393e69abb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/tbl.xsl": {
    "bytes": 24014,
    "gid": 0,
    "mode": 420,
    "sha256": "ef3c8f03872ab1de592da5b01de56a0c7304c11f8e73c0845d969a2d27d3377d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/manpages/utility.xsl": {
    "bytes": 23396,
    "gid": 0,
    "mode": 420,
    "sha256": "fc794107133f328f32758b59c8da7f2cbead418a95a153d8f9e47b87fafd5454",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/abstract.notitle.enabled.xml": {
    "bytes": 986,
    "gid": 0,
    "mode": 420,
    "sha256": "6c45fba7cb57f176b5dae05afc5d50782937eca440e26c75221a93282abfa667",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/abstract.properties.xml": {
    "bytes": 1122,
    "gid": 0,
    "mode": 420,
    "sha256": "6637954bc4785a96dd87d2e7aa0e478433a5ade3917b1bd8129cb8a744ecd0f7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/abstract.title.properties.xml": {
    "bytes": 1778,
    "gid": 0,
    "mode": 420,
    "sha256": "d7e074b563e4e8882c0d8aeaf8918ceb3ca9520d32ca8267ef949c67eaf44529",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/activate.external.olinks.xml": {
    "bytes": 2906,
    "gid": 0,
    "mode": 420,
    "sha256": "a971d114a800903f0a98c834f32b8254747e7df62c10f1df5ce0108d2a2603a3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/active.toc.xml": {
    "bytes": 958,
    "gid": 0,
    "mode": 420,
    "sha256": "ee860ee1d00847be488bb64b746868794f817a52792ddca29fac6a9979c1f0ed",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/ade.extensions.xml": {
    "bytes": 1280,
    "gid": 0,
    "mode": 420,
    "sha256": "caaf6e3e0b865203fe5391f9892f60530f5ea675b57c1d78db94aff9c0fa6b0d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/admon.graphics.extension.xml": {
    "bytes": 1460,
    "gid": 0,
    "mode": 420,
    "sha256": "985984b305e2c0bc3d75e032937e62d4c8aba222b8543a83e57e57ed27f329a9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/admon.graphics.path.xml": {
    "bytes": 1043,
    "gid": 0,
    "mode": 420,
    "sha256": "fbbc759260f66fe9e4a60f3afde3fea06250a0fe56ff02b050fd1b4cba8c1b76",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/admon.graphics.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "a24947619e1e9831574712d940fa47f6e861709e9c7da24477121c09052712f0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/admon.style.xml": {
    "bytes": 1087,
    "gid": 0,
    "mode": 420,
    "sha256": "2b26688b8c3d42c4ad137f7d82928b3005dad9c754b32138b39f013151bd47b8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/admon.textlabel.xml": {
    "bytes": 1074,
    "gid": 0,
    "mode": 420,
    "sha256": "93a29a3af103f129d2f07990e9db87d1415ed688abf0b1491ee620b19883e825",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/admonition.properties.xml": {
    "bytes": 964,
    "gid": 0,
    "mode": 420,
    "sha256": "398b8564f82f2614026efeede55eb9a42e29cdae955efd3a175b4411e313de35",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/admonition.title.properties.xml": {
    "bytes": 1271,
    "gid": 0,
    "mode": 420,
    "sha256": "f6940a3a972c99fa34d755fd91e3f733e192d591851b76a56fbc181fa0262245",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/alignment.xml": {
    "bytes": 1559,
    "gid": 0,
    "mode": 420,
    "sha256": "b0ec9d1769d4dd4aba3ab79593972e1326e8008798d39fcff8857283efca836d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/annotate.toc.xml": {
    "bytes": 952,
    "gid": 0,
    "mode": 420,
    "sha256": "1305d44e4fc51ac38483dbd8d5a8a2b281c46af67b2ef9a7d9f2cf6d94d08e70",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/annotation.css.xml": {
    "bytes": 2190,
    "gid": 0,
    "mode": 420,
    "sha256": "9a8ad6d923a6f74d26c9354becfdf37d31f52598d6bcd43d352edc2ff08fd589",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/annotation.graphic.close.xml": {
    "bytes": 1259,
    "gid": 0,
    "mode": 420,
    "sha256": "431c3ad5858668c40231589e264af2e635714ae95e2dac55776516f42b90e336",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/annotation.graphic.open.xml": {
    "bytes": 1103,
    "gid": 0,
    "mode": 420,
    "sha256": "d98f0284f53fc1ed24fb4ac570a9f693d58787db62c12c3b49d334a128a5212a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/annotation.js.xml": {
    "bytes": 1215,
    "gid": 0,
    "mode": 420,
    "sha256": "a0ec839b6847e40d209bb4ef4d6ba996362f4bab120edca21ed03ea2bd9006a5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/annotation.support.xml": {
    "bytes": 979,
    "gid": 0,
    "mode": 420,
    "sha256": "adee7d2bb7771766e91c59cd059209d92722e465c7fd7ae6664f781c5758884f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/appendix.autolabel.xml": {
    "bytes": 2421,
    "gid": 0,
    "mode": 420,
    "sha256": "589eb103d741402ee76a4e75413d400375adda6e96f7f420e3ca69e4b210cc6f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/arbortext.extensions.xml": {
    "bytes": 1029,
    "gid": 0,
    "mode": 420,
    "sha256": "a021af7e7c49f2c338f12e715d4e2f853f4f53327dadb73b11d089fb43bf6a85",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/article.appendix.title.properties.xml": {
    "bytes": 1194,
    "gid": 0,
    "mode": 420,
    "sha256": "a5f104833e80b226c2c73151a34c6e91bfb4476386bc351e614ee3bcd369825c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/author.othername.in.middle.xml": {
    "bytes": 1080,
    "gid": 0,
    "mode": 420,
    "sha256": "b2dfd9fbddc8c041ff3243770174620c3c4716e2993f7ac4d2ca84474933b848",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/autolayout-file.xml": {
    "bytes": 1123,
    "gid": 0,
    "mode": 420,
    "sha256": "dd9ce81c0a201360eefed7a9daa5dd2dd64dc91912a9e8fbe7ab86a17e0bdbaf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/autolink.index.see.xml": {
    "bytes": 2196,
    "gid": 0,
    "mode": 420,
    "sha256": "299611f9f1a2a73e4a1106ee8dda6ae68d9a74d69dff952309df6a96465fd6f0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/autotoc.label.in.hyperlink.xml": {
    "bytes": 1150,
    "gid": 0,
    "mode": 420,
    "sha256": "3c31ac4e8c6f292fdd7768b8b3b2e9b143297a1149186cbb79e38f7e31b43441",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/autotoc.label.separator.xml": {
    "bytes": 944,
    "gid": 0,
    "mode": 420,
    "sha256": "605c26d80174c8bf32450adfcdefd9f7a6630dd954308b8c79a09ea8a21502ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/axf.extensions.xml": {
    "bytes": 1114,
    "gid": 0,
    "mode": 420,
    "sha256": "7a28d8ac66543a242f64890404d706d649224b6b43fd4f8f0c20455052b7dc41",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/banner.before.navigation.xml": {
    "bytes": 869,
    "gid": 0,
    "mode": 420,
    "sha256": "798c6e0488e78404973e9173910a687540bab8f285680d11ca33f75e5d7de860",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/base.dir.xml": {
    "bytes": 1295,
    "gid": 0,
    "mode": 420,
    "sha256": "a38d7032fd0de8b9e8cb94a72663ab5975a4cd54c3bb8ead7192339aca2cfca8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/biblioentry.item.separator.xml": {
    "bytes": 921,
    "gid": 0,
    "mode": 420,
    "sha256": "b91715aaf83e2b9229d2f12d558415b8a67127746b64d5d29c5110803e5753b3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/biblioentry.properties.xml": {
    "bytes": 1184,
    "gid": 0,
    "mode": 420,
    "sha256": "a7b2077a33ff4c5158cb6ab15f88754a226181f335a8f89ccd6636d0a4a784e6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/bibliography.collection.xml": {
    "bytes": 4873,
    "gid": 0,
    "mode": 420,
    "sha256": "2931519ed3f01d35b3c7acd5fa66be225a3daf0a0bca6c8715d6b59a96ab1bf4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/bibliography.numbered.xml": {
    "bytes": 911,
    "gid": 0,
    "mode": 420,
    "sha256": "a340c62b234faeaee7011e435cfca4ccbb7021aad1dd4d77e89240d8da503e3d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/bibliography.style.xml": {
    "bytes": 1329,
    "gid": 0,
    "mode": 420,
    "sha256": "db087ce0d7062bc69952a05ed931a7566396bfc5b291140da78ca79249759bc5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/blockquote.properties.xml": {
    "bytes": 1345,
    "gid": 0,
    "mode": 420,
    "sha256": "d9f6c4fbbbd234bc476183ebdda29ac7bcb9828e6c24ba486fa51010f09f9d0d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/blurb.on.titlepage.enabled.xml": {
    "bytes": 1190,
    "gid": 0,
    "mode": 420,
    "sha256": "07eefccf7c826d8decb85ae62e9b2795ae09854e92e4b9ec9f60731943faad46",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/body.attributes.xml": {
    "bytes": 1099,
    "gid": 0,
    "mode": 420,
    "sha256": "e9eff2b4883758862b1b5ccbbe8fc4f05a46ab5a62302a904466eac325e5e6ff",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/body.bg.color.xml": {
    "bytes": 891,
    "gid": 0,
    "mode": 420,
    "sha256": "5e78efc7d4505f63d57951859a336551904a546f55a1f7564e12494012fdef83",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/body.end.indent.xml": {
    "bytes": 1234,
    "gid": 0,
    "mode": 420,
    "sha256": "2fd2206f1e7db86d4bc0e25982b12ac3a769c261b2791802c544201a9dc73666",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/body.font.family.xml": {
    "bytes": 1391,
    "gid": 0,
    "mode": 420,
    "sha256": "29c71b7af5b965a6bf04d67831ad14925492a8033943d4e7b5d0ea87a1cdf0d6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/body.font.master.xml": {
    "bytes": 1036,
    "gid": 0,
    "mode": 420,
    "sha256": "b9aaaf7c331d9eab50a41789a65cac92942b5452cb583a048012cbb4defa777d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/body.font.size.xml": {
    "bytes": 1088,
    "gid": 0,
    "mode": 420,
    "sha256": "a0ea8067714e9566c585fcb0cfd3bc5839d93dc2bc5bc21e25e440d07ce8d10f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/body.margin.bottom.xml": {
    "bytes": 963,
    "gid": 0,
    "mode": 420,
    "sha256": "2d93ecae471a7047050ffc5cc5b95c7145ff51a2b7870eebc60537aea6e3c023",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/body.margin.inner.xml": {
    "bytes": 1772,
    "gid": 0,
    "mode": 420,
    "sha256": "f78427a53ec8fbb1cb5851fbbb140a67f5af427c117a86d1bdede9120d21b286",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/body.margin.outer.xml": {
    "bytes": 1783,
    "gid": 0,
    "mode": 420,
    "sha256": "4ed6bc3c368f49c3313d2d267916317da36ff1dd4e7bffe58e7dcd6ad6053437",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/body.margin.top.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "b18ea1c788a98c5ebda4cef7a5a2f54b8a675d49d547bc7dfd896269e0e7c1df",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/body.start.indent.xml": {
    "bytes": 2232,
    "gid": 0,
    "mode": 420,
    "sha256": "648a60a9ee85ade9fa07c38ca90a8629e833d7b8d5f25b6edbbad8c931f57ff8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/bookmarks.collapse.xml": {
    "bytes": 1088,
    "gid": 0,
    "mode": 420,
    "sha256": "17f9f9eba3a2332e4e4e64cdbb06896b72a54434439e2e1e6af500ba3c41aea3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/bridgehead.in.toc.xml": {
    "bytes": 1004,
    "gid": 0,
    "mode": 420,
    "sha256": "7808de9b4c36f737a88e309454101d3655597393323cafcf87d42e4411baa7b0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/bullet.image.xml": {
    "bytes": 880,
    "gid": 0,
    "mode": 420,
    "sha256": "38c20596790ecc579705df81e41bd8c60912f019bfd5d4e60b34e77a43f312cd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/callout.defaultcolumn.xml": {
    "bytes": 1047,
    "gid": 0,
    "mode": 420,
    "sha256": "aa13e63315e57c028949e118f0f763b2cf15a296243e834a0943952992d82216",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/callout.graphics.extension.xml": {
    "bytes": 1448,
    "gid": 0,
    "mode": 420,
    "sha256": "12dc463b0f54b1cdb258334f1df74094d6bf3caae9d4d0ea10d37c4ad8913e3c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/callout.graphics.number.limit.xml": {
    "bytes": 1356,
    "gid": 0,
    "mode": 420,
    "sha256": "752af987a3e523d667aa08f906fa786a3208ed1cce1de839bf2d4aa202bfdbea",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/callout.graphics.path.xml": {
    "bytes": 1116,
    "gid": 0,
    "mode": 420,
    "sha256": "cb90fe1a8e945119b64dae6a0f8a698bfd580f97366dae670a07d76278b8c688",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/callout.graphics.xml": {
    "bytes": 993,
    "gid": 0,
    "mode": 420,
    "sha256": "000e761b0bdaf092ef845bb91a352cd432ee257163851d4c251db448c7e6748a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/callout.icon.size.xml": {
    "bytes": 923,
    "gid": 0,
    "mode": 420,
    "sha256": "f6993201c3af85c8461426c311c099894d2a0f70632f4e51e96b60b544dffb41",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/callout.list.table.xml": {
    "bytes": 1211,
    "gid": 0,
    "mode": 420,
    "sha256": "85c350f206f60a4995621208b8b82c271deeb0f7a58f3366b62d010e1886bcad",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/callout.properties.xml": {
    "bytes": 1042,
    "gid": 0,
    "mode": 420,
    "sha256": "6888f0baa6974fe6bb45c4d0a4b6faf15cefc222c3fe795e20f33457f6ee2748",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/callout.unicode.font.xml": {
    "bytes": 979,
    "gid": 0,
    "mode": 420,
    "sha256": "c42f8351d10822915b5f47b194fa7f09569092c6e9c56c936ce3b483c35d756a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/callout.unicode.number.limit.xml": {
    "bytes": 1240,
    "gid": 0,
    "mode": 420,
    "sha256": "67947c05dcb97251e2ffee842b26a6e4f5a13dab54c0a68902bc51f578f438f4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/callout.unicode.start.character.xml": {
    "bytes": 1307,
    "gid": 0,
    "mode": 420,
    "sha256": "d344f97cf7f8005d999828af3a92aac15e25f1aaf597cdd9e86f48346d825636",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/callout.unicode.xml": {
    "bytes": 1055,
    "gid": 0,
    "mode": 420,
    "sha256": "b8571cfb9419e98cc3f2efa4306a6c4110a137a31e8a79e025836522decde04e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/calloutlist.properties.xml": {
    "bytes": 1552,
    "gid": 0,
    "mode": 420,
    "sha256": "cdb2e5395494b50c3a63f1ab700d44867e9a5e9460e6f09799727f5a66f4ab56",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/callouts.extension.xml": {
    "bytes": 1049,
    "gid": 0,
    "mode": 420,
    "sha256": "8e64033b198e3d2ee5b8b597b5933e007f87a932851725aa1284dc69034e6a40",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chapter.autolabel.xml": {
    "bytes": 2407,
    "gid": 0,
    "mode": 420,
    "sha256": "4e5e5197a7baa85df15b2ab86932f8c90c24e4a1896f84e44c263f1af46bde43",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunk.append.xml": {
    "bytes": 1168,
    "gid": 0,
    "mode": 420,
    "sha256": "df422c553c0f3b79de144e93378df06be39685217a1b8ba45743ae8769ae88a7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunk.first.sections.xml": {
    "bytes": 1045,
    "gid": 0,
    "mode": 420,
    "sha256": "ae9e559e8d55c8c98f48481ca6352353ab87b86128d915bc0919cf36c24bac05",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunk.quietly.xml": {
    "bytes": 979,
    "gid": 0,
    "mode": 420,
    "sha256": "06917c5451d4dc22fb383d50cd59ce141a4243294dbb0e9693a26993e0303286",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunk.section.depth.xml": {
    "bytes": 903,
    "gid": 0,
    "mode": 420,
    "sha256": "166275d3a2b540cf5d80d58c4d3b92be7ed81a4feeca17ba25f660dadd8e8239",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunk.sections.xml": {
    "bytes": 960,
    "gid": 0,
    "mode": 420,
    "sha256": "1271cb8f19f8d7c04937271a2037db928de5f4eb2ffa4067ae96816ba4c75a09",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunk.separate.lots.xml": {
    "bytes": 1165,
    "gid": 0,
    "mode": 420,
    "sha256": "05558ad26fcbe549241744b5e2bde92b94eef27267cfff794ca6587738f55689",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunk.toc.xml": {
    "bytes": 1017,
    "gid": 0,
    "mode": 420,
    "sha256": "8c2b119b31c6ab582ef93f9f3788f149fdb59a56ba428bbaec05f9640de5b43c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunk.tocs.and.lots.has.title.xml": {
    "bytes": 986,
    "gid": 0,
    "mode": 420,
    "sha256": "3e6fc6f5bb824d6bccef73a5b92a37e86ffc283c6b63547fb2cd915b0d4ff5bd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunk.tocs.and.lots.xml": {
    "bytes": 1166,
    "gid": 0,
    "mode": 420,
    "sha256": "bb2d48ce207a4e56215cc40e9703155b1e80738dbf1171bafe4eba8b632540af",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunked.filename.prefix.xml": {
    "bytes": 1597,
    "gid": 0,
    "mode": 420,
    "sha256": "b64b14228d5e4133e36fcd77df1655e65e2695f657a760d0a115ea52e7c98c2f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunker.output.cdata-section-elements.xml": {
    "bytes": 1273,
    "gid": 0,
    "mode": 420,
    "sha256": "0685bf4e553d287c15bdd74edf569c35256dd8dc97988c149b1402c473b250ed",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunker.output.doctype-public.xml": {
    "bytes": 1279,
    "gid": 0,
    "mode": 420,
    "sha256": "54dd8b9b95b3f4a8b980ea4b6d729031d265b955d28e177f06b9c03f3f19a68a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunker.output.doctype-system.xml": {
    "bytes": 1278,
    "gid": 0,
    "mode": 420,
    "sha256": "2f3ce5515bead08015d327ba391060bd70614aea8b8c4325470723f824d51a21",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunker.output.encoding.xml": {
    "bytes": 1261,
    "gid": 0,
    "mode": 420,
    "sha256": "30f2682207ef4b0df2c5419e0712a15960b5dcf9948151accbd0b3bd825f7ccb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunker.output.indent.xml": {
    "bytes": 1164,
    "gid": 0,
    "mode": 420,
    "sha256": "de01f6b82723db2b995bd31ce510d27f55c699404330989b923662281e726e9e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunker.output.media-type.xml": {
    "bytes": 1519,
    "gid": 0,
    "mode": 420,
    "sha256": "fe5c24f9a9cf30f6c034f5950e40177a4cbda17610920bea773cd175de91a53a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunker.output.method.xml": {
    "bytes": 1312,
    "gid": 0,
    "mode": 420,
    "sha256": "d7eebd9fddfe4283b129fa18c55783e5cc758bd2b6c9dc41f1924fe16a4a6561",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunker.output.omit-xml-declaration.xml": {
    "bytes": 1241,
    "gid": 0,
    "mode": 420,
    "sha256": "aa1b32f8d79f6d286aa99cbe6c248856b03603f2db926fca00e1967c0eccd7c5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/chunker.output.standalone.xml": {
    "bytes": 1256,
    "gid": 0,
    "mode": 420,
    "sha256": "81fe7675fc2ed75785d3969134ecdc162c7db64dcbc0a867fb58b99701afd7f7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/citerefentry.link.xml": {
    "bytes": 1039,
    "gid": 0,
    "mode": 420,
    "sha256": "e0f55229bebe71a2b94cdfb33060a28347ca69ee7480fb42bec2f2edfa464e1f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/collect.xref.targets.xml": {
    "bytes": 1754,
    "gid": 0,
    "mode": 420,
    "sha256": "575d396d6995c2f4c9cfe493c76847df2d468a49d2a379139521bd00fa1c1abf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/column.count.back.xml": {
    "bytes": 906,
    "gid": 0,
    "mode": 420,
    "sha256": "7de90bb993782ca9ff21e0d45dbea4df31425525353b3fc4fc1523a2700068fb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/column.count.body.xml": {
    "bytes": 865,
    "gid": 0,
    "mode": 420,
    "sha256": "2b6bade1a464494d124d02557f1ed3cd5419665744862117271f1d224f5e9a33",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/column.count.front.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "da1309cf6acddb85d3cda67eea0284ccc20487a85fddaaaba062064e19c52d59",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/column.count.index.xml": {
    "bytes": 873,
    "gid": 0,
    "mode": 420,
    "sha256": "1d7295b88c7d37f8c59c7002281f8f3a5060852b2fadacb826b7066bbefe2284",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/column.count.lot.xml": {
    "bytes": 933,
    "gid": 0,
    "mode": 420,
    "sha256": "993de6599504d183c0801caf86ba59d1d9b570f9737d4e08cbfec8bda66ab1f5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/column.count.titlepage.xml": {
    "bytes": 893,
    "gid": 0,
    "mode": 420,
    "sha256": "c3b4d092156fc9faf15c74cdeee18df6b3a56e4a79a764a0bb9397a3e43ca5ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/column.gap.back.xml": {
    "bytes": 944,
    "gid": 0,
    "mode": 420,
    "sha256": "dc1a854522613dffadfe7b1a81881a436ba49d3a05c075a12bf68e01b258f143",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/column.gap.body.xml": {
    "bytes": 941,
    "gid": 0,
    "mode": 420,
    "sha256": "abbf9ebf5f0d007384143e6820ddb3be0754a6f512c424fd8c29be39b53da3d3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/column.gap.front.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "e1973a32a2a0b16dda8a813c1d1096ac0e91224fbe25d16667ee93e8b76f8c6e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/column.gap.index.xml": {
    "bytes": 944,
    "gid": 0,
    "mode": 420,
    "sha256": "e3e96442aa3ae62bf94679c38ec8c647b272c1aec7f0df8d4e22281367fc021c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/column.gap.lot.xml": {
    "bytes": 961,
    "gid": 0,
    "mode": 420,
    "sha256": "22dd1ef2654262014d359f4d5463a973054e564472d30d23ea7fee7a46f58de6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/column.gap.titlepage.xml": {
    "bytes": 975,
    "gid": 0,
    "mode": 420,
    "sha256": "93b81684fa5434e54783d6664ac0d4c44ec09e7f458993d95a213c09d995e1bf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/compact.list.item.spacing.xml": {
    "bytes": 1266,
    "gid": 0,
    "mode": 420,
    "sha256": "c49d10ccada76693da2aeadadfff385359732ff5ef4f01bc662150564c892ff3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/component.label.includes.part.label.xml": {
    "bytes": 1607,
    "gid": 0,
    "mode": 420,
    "sha256": "94122f4fa60f0c0a794c1f48ba7739bfbbba944fb2465b1c37bcd00bad358907",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/component.title.properties.xml": {
    "bytes": 1890,
    "gid": 0,
    "mode": 420,
    "sha256": "626e9b34c4e837eac7524f40525770cbd5c5c8606937a51211bc48599c7bf2de",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/component.titlepage.properties.xml": {
    "bytes": 1233,
    "gid": 0,
    "mode": 420,
    "sha256": "5337e7b6d0cc7311007f3fe9570a3b03af596b8c68153e4bdcdfa1bce6effe58",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/contrib.inline.enabled.xml": {
    "bytes": 984,
    "gid": 0,
    "mode": 420,
    "sha256": "cbed3b95a88011e277636d1f4507edf5fe894c782935e7e28269e1ce0bfbdc3c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/crop.mark.bleed.xml": {
    "bytes": 946,
    "gid": 0,
    "mode": 420,
    "sha256": "f5907f5e0a5ba15fa9a0878143f71ef4962f0a3a20eea324a526b0cac31b2b01",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/crop.mark.offset.xml": {
    "bytes": 916,
    "gid": 0,
    "mode": 420,
    "sha256": "2c70df725a10bdc5d9d0ed1ba3f271ee93a1167030f3720ec78ba8825cab61b9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/crop.mark.width.xml": {
    "bytes": 910,
    "gid": 0,
    "mode": 420,
    "sha256": "128da320ecdbc95c3033bae005a4fab4dbc3132ccfe7fff171d4156af9eaa886",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/crop.marks.xml": {
    "bytes": 926,
    "gid": 0,
    "mode": 420,
    "sha256": "b0aea0cf41b3b65f77a68c9b063c7f5c77e0b8f083fc9ab00428f9a658bf7e7f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/css.decoration.xml": {
    "bytes": 1127,
    "gid": 0,
    "mode": 420,
    "sha256": "9e30eb260b5898a3d3c31f00496e006fedd64af29f23e42b5f8cd926b3a99100",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/css.stylesheet.dir.xml": {
    "bytes": 1136,
    "gid": 0,
    "mode": 420,
    "sha256": "045323cff6bd1afd75cd8fdb8c7f65569370fcbf6dcbbbc0e24f4c6d5754c45b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/css.stylesheet.xml": {
    "bytes": 998,
    "gid": 0,
    "mode": 420,
    "sha256": "a4db7ffac669e9ac65caf2376e6a84da54736423f581c6df937b6f90158eee18",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/current.docid.xml": {
    "bytes": 1744,
    "gid": 0,
    "mode": 420,
    "sha256": "47466d3066418122e25eeba2c9512b02494b86f1ce563c4aa969f18ef0a06087",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/currentpage.marker.xml": {
    "bytes": 902,
    "gid": 0,
    "mode": 420,
    "sha256": "da4330f03ae6719924bd9f930e4c4108a99ba07f609ab57bce4cc39113273e38",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/custom.css.source.xml": {
    "bytes": 4255,
    "gid": 0,
    "mode": 420,
    "sha256": "b07c68e2d0b1f66537ac92116ccdb51450c5bf7753db407b34c3b42953b42fdd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/default.float.class.xml": {
    "bytes": 1164,
    "gid": 0,
    "mode": 420,
    "sha256": "30706e8862e205dcc1c9fe349e77ce8cd18b63dffbf8f0c6dbd1f041851c53ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/default.image.width.xml": {
    "bytes": 1128,
    "gid": 0,
    "mode": 420,
    "sha256": "5352b8b44dbf098d9bb41544029b493c34020280fdf59e9c3fdd9139c0150f38",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/default.table.frame.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "a92ea20dce28d0175239282b5d2c440a778c98956d08bce52cb3e4fc15cab16b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/default.table.rules.xml": {
    "bytes": 2212,
    "gid": 0,
    "mode": 420,
    "sha256": "ecf51b92b572b36f3cb20182dac0076f9cfe701f2bd77e55e450beddebb108d6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/default.table.width.xml": {
    "bytes": 1098,
    "gid": 0,
    "mode": 420,
    "sha256": "6f416e382f2ceceefd33a8291f68b242e6224a20b32080d7462950fcc0286410",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/default.units.xml": {
    "bytes": 1477,
    "gid": 0,
    "mode": 420,
    "sha256": "6d062d16f310fbdebbac7ad2f6611d56aef033f2f7eabea42dcfe52df7e0198a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/dialogue.properties.xml": {
    "bytes": 1146,
    "gid": 0,
    "mode": 420,
    "sha256": "eb63ba403adfa4d1bd283ba2e417115ca112d40df12fcf3d11276819e9f47f31",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/dingbat.font.family.xml": {
    "bytes": 1274,
    "gid": 0,
    "mode": 420,
    "sha256": "7e1958d6db091553d31366647375ddf1b9a3a747dfbbeb067b51d3b04be97f6f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/disable.collapsible.xml": {
    "bytes": 982,
    "gid": 0,
    "mode": 420,
    "sha256": "a43d3f2fd20cb69db3dd435f8422657689e4c298cbc2a3304115ad66178619f6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/disable.incremental.xml": {
    "bytes": 982,
    "gid": 0,
    "mode": 420,
    "sha256": "05caa015a8b8fcafd61b73eec4b80d2c354fdd015cf59656260e6d18988244b4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/docbook.css.link.xml": {
    "bytes": 1520,
    "gid": 0,
    "mode": 420,
    "sha256": "8074e36fe27a8e7e77fbd38768821d2f80b6f27eae4c4276bd3ec2a92eccefcc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/docbook.css.source.xml": {
    "bytes": 3541,
    "gid": 0,
    "mode": 420,
    "sha256": "026f88c3a675c104d4bbfa716ce8547513dca4654a84c3209aad9c602aa8c8ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/double.sided.xml": {
    "bytes": 1436,
    "gid": 0,
    "mode": 420,
    "sha256": "76431e128c8f51458d66367e696c856c782b3f713321042a3f0f2fbe0b298a5f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/draft.mode.xml": {
    "bytes": 1410,
    "gid": 0,
    "mode": 420,
    "sha256": "cd453a2fad9269280e8504edf6f3d907079e56b6ec23bbcaab66cdefc055b417",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/draft.watermark.image.xml": {
    "bytes": 928,
    "gid": 0,
    "mode": 420,
    "sha256": "1d5a7ef2bd15931a3a5b4ea4bf858475743e94eed4027358d0db97c9b8e4929c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/drama.properties.xml": {
    "bytes": 1125,
    "gid": 0,
    "mode": 420,
    "sha256": "4e97d7ce4cf8b5baa0bc5eebf21e2cf5af0cf1fa75a5ec53957d98987b84de7c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/dry-run.xml": {
    "bytes": 1126,
    "gid": 0,
    "mode": 420,
    "sha256": "ad344c4a338e6410447ce4fd0f0bb8796f918117c9cdd01c6943de5b3e2b001a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/dynamic.toc.xml": {
    "bytes": 972,
    "gid": 0,
    "mode": 420,
    "sha256": "8b4167909f78b9239adb70a5791808fb8ef85a94eb5f3594c423274297fa5b73",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/ebnf.assignment.xml": {
    "bytes": 1397,
    "gid": 0,
    "mode": 420,
    "sha256": "8a9e05783bf1b0ee2754c67725a239b0fec17391c018833824d9bfd15095db6f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/ebnf.statement.terminator.xml": {
    "bytes": 1168,
    "gid": 0,
    "mode": 420,
    "sha256": "ddd9a56a8e9ff95f5a4dfa91a655182d3504ebd7993f40281b500baa552aa4eb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/ebnf.table.bgcolor.xml": {
    "bytes": 1018,
    "gid": 0,
    "mode": 420,
    "sha256": "312b177703aa68129cef64b50aeee5cd1bda946937bcff763f14c1d70b1a6fa1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/ebnf.table.border.xml": {
    "bytes": 923,
    "gid": 0,
    "mode": 420,
    "sha256": "29d2af960264d29e569469dfb4b46353c064c0d573477f895be0168097013e23",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/eclipse.autolabel.xml": {
    "bytes": 952,
    "gid": 0,
    "mode": 420,
    "sha256": "362d8efc2b18b4eadd65be44ce7bf25d28e2e17b58f109bb724c2c68517e33c9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/eclipse.plugin.id.xml": {
    "bytes": 923,
    "gid": 0,
    "mode": 420,
    "sha256": "9e141273b32ca0a68eb89e42f09873d993bdfd1fc8747174d5f2cd47bd7e56f3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/eclipse.plugin.name.xml": {
    "bytes": 886,
    "gid": 0,
    "mode": 420,
    "sha256": "c569d097200493b59f0f62b00f80139b3725f1615cbfd43ce313abb901abfb40",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/eclipse.plugin.provider.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "19c79b8b4731e5a4f1bff40db16c6bae24fc7d299243a45ccd8998290247413d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/editedby.enabled.xml": {
    "bytes": 997,
    "gid": 0,
    "mode": 420,
    "sha256": "e9353ba0a80412d1b657809f1193c6b11bbe49865a254d3002bb28c4a604084d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/email.delimiters.enabled.xml": {
    "bytes": 1107,
    "gid": 0,
    "mode": 420,
    "sha256": "d2ed1dcdcb6ca44faf5542b3722129d13f0f08ceeee9822a6745f962d6b789df",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/email.mailto.enabled.xml": {
    "bytes": 1012,
    "gid": 0,
    "mode": 420,
    "sha256": "e3cb99162c94217f05f416303cab7cf1e1b98daa0c159d9aa2e12a4d09852063",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/emphasis.propagates.style.xml": {
    "bytes": 1079,
    "gid": 0,
    "mode": 420,
    "sha256": "14dcde80b73461aef532d23033422ce9f28f3ae626f673b541a1ed2d51c02d81",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/entry.propagates.style.xml": {
    "bytes": 1049,
    "gid": 0,
    "mode": 420,
    "sha256": "49351a2c60f3367f7af95935d979cc644a86c3b16253ca0f5c0cdcd3edd97bb5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/epub.autolabel.xml": {
    "bytes": 923,
    "gid": 0,
    "mode": 420,
    "sha256": "6552284f49c1009222a638b7f5cf95d8ff5e1b1eacae0c14bbd44195d2e51116",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/equation.number.properties.xml": {
    "bytes": 1324,
    "gid": 0,
    "mode": 420,
    "sha256": "2d2cf9e3736370f3ddb9cd6898376a230a9b29d42243b08dfc76d1e2ee39c7d1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/equation.properties.xml": {
    "bytes": 924,
    "gid": 0,
    "mode": 420,
    "sha256": "2ba5643ac455b5b4a83b52bdfc126cd8c63b8b56d082a3b2b4776972faf346fc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/example.properties.xml": {
    "bytes": 1012,
    "gid": 0,
    "mode": 420,
    "sha256": "fab0baee94bb7d652f3be601c03c0c9e2ae7895b9e19293e1fd2b1ab8af71bf0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/exsl.node.set.available.xml": {
    "bytes": 1643,
    "gid": 0,
    "mode": 420,
    "sha256": "83af83872069d50c0ccf28ea695dfc1b66da57bdb58cd921d3de15b5ca515a56",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/feedback.href.xml": {
    "bytes": 1007,
    "gid": 0,
    "mode": 420,
    "sha256": "e698929c84e114b23a98533026c264ab9be513545c058cfe41fe60ac6d825634",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/feedback.link.text.xml": {
    "bytes": 1038,
    "gid": 0,
    "mode": 420,
    "sha256": "dce39beb0fa38c782e99c97a2accc4a0bf0f241854a0d7a0c9cd2d2500075d8b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/feedback.with.ids.xml": {
    "bytes": 1032,
    "gid": 0,
    "mode": 420,
    "sha256": "758bf26e0e33ab206a047f997e71ac83f063674cfdad52698e750c7d1557fad7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/figure.properties.xml": {
    "bytes": 912,
    "gid": 0,
    "mode": 420,
    "sha256": "55618438832b35086532ac70c82361619861ced1a42317a2fd8d38c112c556ab",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/filename-prefix.xml": {
    "bytes": 1080,
    "gid": 0,
    "mode": 420,
    "sha256": "1a69e5650275cefbb8d93b2d0c02128d851de7e36ddca730a8e444b6fce467c4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/firstterm.only.link.xml": {
    "bytes": 1021,
    "gid": 0,
    "mode": 420,
    "sha256": "d3f2d6cb0f606954c4989fd42441ca872d1feb73218e4b5d5cc138c463dd4523",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foil.footer.properties.xml": {
    "bytes": 932,
    "gid": 0,
    "mode": 420,
    "sha256": "102558df7f692b525e4c0b6035ee4ce7b52ec0a63ef9d779e05ba966176bfc80",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foil.header.properties.xml": {
    "bytes": 1393,
    "gid": 0,
    "mode": 420,
    "sha256": "72a29ff452108b1a598f88352c30596dcca1754eed468858c3043324ce77d46a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foil.master.properties.xml": {
    "bytes": 1637,
    "gid": 0,
    "mode": 420,
    "sha256": "8f39672e9776a60b6f44cf5e4e02794d249fef6ab4f02ceede3ab9cbffba27eb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foil.page-sequence.properties.xml": {
    "bytes": 1105,
    "gid": 0,
    "mode": 420,
    "sha256": "e60d156a6d7aafab6113e51e918afdb44b40ddbdbca5401f09d81d48710582b4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foil.properties.xml": {
    "bytes": 1312,
    "gid": 0,
    "mode": 420,
    "sha256": "7bac6f8eae0b66fab6ba0cce7a4e79e14495fcd6a39a85515ff37ac2f826925b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foil.region-after.properties.xml": {
    "bytes": 1173,
    "gid": 0,
    "mode": 420,
    "sha256": "023dc900c29b6b83912f46268a3eb317653f7946df1a8b59db0ff4d414016811",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foil.region-before.properties.xml": {
    "bytes": 1225,
    "gid": 0,
    "mode": 420,
    "sha256": "13d5b88b41dd887b852877ca2a22abcac03b9e56a548c44c6f514c13b2ec98a4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foil.region-body.properties.xml": {
    "bytes": 1338,
    "gid": 0,
    "mode": 420,
    "sha256": "9f5e4e915af93cadab767b3dca2a41ead2500fb6ee43ea22c39a49b201cf7fc4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foil.subtitle.properties.xml": {
    "bytes": 1378,
    "gid": 0,
    "mode": 420,
    "sha256": "88493583c17e7d60892dc4b9d994d0eb2db18f74c1b5a07079010032f8df356b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foil.title.master.xml": {
    "bytes": 1027,
    "gid": 0,
    "mode": 420,
    "sha256": "b3b473318ee3c46d18595bc00ba052de982db2cfaab784dd8e75ef93bb23a719",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foil.title.properties.xml": {
    "bytes": 1059,
    "gid": 0,
    "mode": 420,
    "sha256": "8754ce2ee16ec936e366d1fa29dd83b6ea7f95f2459aa5bd5d99ce91bd89d92d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foil.title.size.xml": {
    "bytes": 1106,
    "gid": 0,
    "mode": 420,
    "sha256": "e9ad28ee50d8b7804d575e9bc048dfce1d8054fe47f2068eeabc33d7150a95a5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foilgroup.properties.xml": {
    "bytes": 1080,
    "gid": 0,
    "mode": 420,
    "sha256": "c0b2abc81fc18684e2c075d3a8fdf257ddb7930c7ee8f9a8c09658f58fd71707",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/foilgroup.toc.xml": {
    "bytes": 889,
    "gid": 0,
    "mode": 420,
    "sha256": "c97e5c635b7e9cd308817248e57e5803048be9904b7b3ef6c0e875c8b5f503f5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/footer.column.widths.xml": {
    "bytes": 2987,
    "gid": 0,
    "mode": 420,
    "sha256": "63e39aecde889723764da7e8a3a33be5447132354c182f9ac5b410bc06e25a40",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/footer.content.properties.xml": {
    "bytes": 1135,
    "gid": 0,
    "mode": 420,
    "sha256": "c917d9c6d6d94fa06484296e24c02661373dc934cf0ae8a6d4b5a239839d0252",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/footer.hr.xml": {
    "bytes": 881,
    "gid": 0,
    "mode": 420,
    "sha256": "4fb548b7299ec5169152b442f494e458298e3897c98f29a48145768b40d07bb9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/footer.rule.xml": {
    "bytes": 847,
    "gid": 0,
    "mode": 420,
    "sha256": "570e75164f172f1a5c4751657d8f0611fd4e5ba80288d53b215f0018e605742a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/footer.table.height.xml": {
    "bytes": 1242,
    "gid": 0,
    "mode": 420,
    "sha256": "79d816100aa2073e8a1db5738533514e8b05d90ef5869382fd27ae62a418dcef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/footer.table.properties.xml": {
    "bytes": 1070,
    "gid": 0,
    "mode": 420,
    "sha256": "783deb3f90d033c6e0ced3ec8300691ad10e29de0d91f290fb866973bd34798c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/footers.on.blank.pages.xml": {
    "bytes": 905,
    "gid": 0,
    "mode": 420,
    "sha256": "86d70d3142806aba8e61f726d08f753175628a5205a7347845f80f47dd55015b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/footnote.font.size.xml": {
    "bytes": 953,
    "gid": 0,
    "mode": 420,
    "sha256": "8c2a91d19314cda7ee1811fe85394f2c511077b86edec595685ccbdda3800d69",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/footnote.mark.properties.xml": {
    "bytes": 1466,
    "gid": 0,
    "mode": 420,
    "sha256": "c117b2b0b0667cac6ff8e7266c17561c2d9ac9f021fb040ef71df7878f3ed24a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/footnote.number.format.xml": {
    "bytes": 1406,
    "gid": 0,
    "mode": 420,
    "sha256": "32a2e62e8ec74d8c3fbde218c78c6862694eda28546ff49f8a21955ad743cc1f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/footnote.number.symbols.xml": {
    "bytes": 1735,
    "gid": 0,
    "mode": 420,
    "sha256": "d9a2d81acecf502957e906fb8926364cb1ea56aa8de48039ba9355e299fd87a5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/footnote.properties.xml": {
    "bytes": 1846,
    "gid": 0,
    "mode": 420,
    "sha256": "6643dc062ec310a051a9405b07f889d18ee0e8f2f32012c62521e5876fdba46a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/footnote.sep.leader.properties.xml": {
    "bytes": 1461,
    "gid": 0,
    "mode": 420,
    "sha256": "eb11901fd08ae4307fc97b4d861a14cafcce9282428dab114afc3a6a247380ec",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/fop.extensions.xml": {
    "bytes": 1246,
    "gid": 0,
    "mode": 420,
    "sha256": "b899d0f9f37df51d30bdd192083419b5be1e42a3d26236e79d63334e109da236",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/fop1.extensions.xml": {
    "bytes": 1181,
    "gid": 0,
    "mode": 420,
    "sha256": "f98bbba57a235e6e3f82cab884677dd22c0cd593b1fc1a5d8a66dc597d9549c6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/force.blank.pages.xml": {
    "bytes": 1657,
    "gid": 0,
    "mode": 420,
    "sha256": "2d64a342c29485f2601c5f165c65bd889c28eff2cb8fea3fcedd49539d6d3348",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/formal.object.properties.xml": {
    "bytes": 1513,
    "gid": 0,
    "mode": 420,
    "sha256": "77ce6bd5a30454e48f216d504f592f84d18fe59d0b52cd89787b4cdb06420be8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/formal.procedures.xml": {
    "bytes": 895,
    "gid": 0,
    "mode": 420,
    "sha256": "48a0287a42d50bd3cfdc340bf285b1413f943887158397654b88a55eb2e02c76",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/formal.title.placement.xml": {
    "bytes": 1265,
    "gid": 0,
    "mode": 420,
    "sha256": "5061086d28c056e1538057539cac735b7ede0ceaa14d76a5bfebb100d454ff43",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/formal.title.properties.xml": {
    "bytes": 1504,
    "gid": 0,
    "mode": 420,
    "sha256": "d1582e15517addb3714e2db73868b145a76a7c129d16b51bf26645bfd9bea79d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/funcsynopsis.decoration.xml": {
    "bytes": 1080,
    "gid": 0,
    "mode": 420,
    "sha256": "9ed63b1c6413361ff4480517fd2dd13deaad9134a09bcf486ec38a77196c02ac",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/funcsynopsis.style.xml": {
    "bytes": 1194,
    "gid": 0,
    "mode": 420,
    "sha256": "c2ee8d9b9d235e2f4eef199729eeed5f740a98c82b852978752a6ce2e4718e5e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/function.parens.xml": {
    "bytes": 922,
    "gid": 0,
    "mode": 420,
    "sha256": "4acce89219d39f8e1f024bd6e90f93936afc4899821cf0674548f96a80815fb9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.consistent.ids.xml": {
    "bytes": 1953,
    "gid": 0,
    "mode": 420,
    "sha256": "4e5aa0d9f44cb61945756090b9853cef97dd628c145792f488aab8b722c58cf9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.copyright.xml": {
    "bytes": 942,
    "gid": 0,
    "mode": 420,
    "sha256": "d912aa3efc3586eabab405720ecdf32672a0e885a37cd4fcd13ca6c5ba20ebba",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.css.header.xml": {
    "bytes": 1489,
    "gid": 0,
    "mode": 420,
    "sha256": "2f6d25ec9f6c5cbe26653a2e6662ed48006c3e69c39e2643edd49fd765ac1647",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.foilgroup.numbered.toc.xml": {
    "bytes": 1084,
    "gid": 0,
    "mode": 420,
    "sha256": "adbcd93537602ed6a88a9842eb3c4c7891df0a8ebe2682b76a7eb9d69b89433e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.foilgroup.toc.xml": {
    "bytes": 976,
    "gid": 0,
    "mode": 420,
    "sha256": "34dc2167ca22e97c02fe7982370117751265da1e69e07fee1e8c4305a56540b0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.handoutnotes.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "a4261165509d145d4fc495c112cba419318fe0168060d0969b34d8feaf13b084",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.id.attributes.xml": {
    "bytes": 2069,
    "gid": 0,
    "mode": 420,
    "sha256": "3c33893b88336ee1a3b8371c05ce32b51010b5ec73f67af002d53ca66174534c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.index.xml": {
    "bytes": 847,
    "gid": 0,
    "mode": 420,
    "sha256": "8c4591b205a866468afe6779ac4af70e54e37a105361671fd448895a06c351a7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.legalnotice.link.xml": {
    "bytes": 2698,
    "gid": 0,
    "mode": 420,
    "sha256": "aa3ac7cac80b2ca31c6d03903ceb611a7c4cc180cfabff6b06bcffe4449a1845",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.manifest.xml": {
    "bytes": 1032,
    "gid": 0,
    "mode": 420,
    "sha256": "b0e3a172379ec18cba17f7c1e1a8eeb9bc93fe97edb00dfbc4925f5b5a3979e9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.meta.abstract.xml": {
    "bytes": 1041,
    "gid": 0,
    "mode": 420,
    "sha256": "f58413b52a5e58096496a0be07a26c0515b18b6bc07d7568ab97a04d326ea4ff",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.page.number.xml": {
    "bytes": 1783,
    "gid": 0,
    "mode": 420,
    "sha256": "1855aaa99af57b742819e213aac246a8cf5e194a14bdec0c45d89b285ed0cb08",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.pubdate.xml": {
    "bytes": 936,
    "gid": 0,
    "mode": 420,
    "sha256": "fdd61e22494ef1bb30f7cda85d08b53334d1821422c4221e6890aeb408b484e2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.revhistory.link.xml": {
    "bytes": 1982,
    "gid": 0,
    "mode": 420,
    "sha256": "35daec79a472980decb4876a27a65f47cdefb9f108c08c9c5bec46adc891064d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.section.toc.level.xml": {
    "bytes": 1406,
    "gid": 0,
    "mode": 420,
    "sha256": "aebbf7076b60c077fdca77deb28a6ffb8524b8fedcae93d3b155f54dee9289d2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.speakernotes.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "a45670c626bd3ef9a397c904e0c2051cea84746c21ba2199f4bb8eb55fc608d1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.titlepage.xml": {
    "bytes": 935,
    "gid": 0,
    "mode": 420,
    "sha256": "aca7805035180be1ec8847daf9df6e285293af5e8be0dcaf4b1878afcb68fc22",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/generate.toc.xml": {
    "bytes": 3652,
    "gid": 0,
    "mode": 420,
    "sha256": "255e2052a1946fd83121d825cb918ebad2e517667deeafd9c3917249e263ea77",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/glossary.as.blocks.xml": {
    "bytes": 1377,
    "gid": 0,
    "mode": 420,
    "sha256": "41259358bd3fc6b9b2b6e2d2d3b416d0c49454de16348c5a4fd223bc0fba0fbb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/glossary.collection.xml": {
    "bytes": 11119,
    "gid": 0,
    "mode": 420,
    "sha256": "dc104b1de303518797b90504e58cef2a9aece8405a891f8a9c51c06d40403fcf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/glossary.sort.xml": {
    "bytes": 1053,
    "gid": 0,
    "mode": 420,
    "sha256": "b49e1ce4101bafdb1ffd908fc326189e0341ab68052be00176271736e0ee631e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/glossdef.block.properties.xml": {
    "bytes": 1278,
    "gid": 0,
    "mode": 420,
    "sha256": "8a3a0aac4b5a5a33899ef1f56ab60d959972c40b9faf4eabb6ff2962b5e157ef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/glossdef.list.properties.xml": {
    "bytes": 1129,
    "gid": 0,
    "mode": 420,
    "sha256": "6625fc3cd0e6d7833129b94feedb004217f56245f16a2d4af262394f5ce8b0d5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/glossentry.list.item.properties.xml": {
    "bytes": 1360,
    "gid": 0,
    "mode": 420,
    "sha256": "b1f7a81a42215ce0998731ac6f0c66a1504f88e33635cfb713109f8537a13f52",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/glossentry.show.acronym.xml": {
    "bytes": 1395,
    "gid": 0,
    "mode": 420,
    "sha256": "8ff96e8547967e398ed4e521ae671928f1b53b9acb55ae970e99b41cb04ef7c7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/glosslist.as.blocks.xml": {
    "bytes": 884,
    "gid": 0,
    "mode": 420,
    "sha256": "21c4265aa36440f739221a33e5568554994177a72709eb545cefcdebce0ce64b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/glossterm.auto.link.xml": {
    "bytes": 1309,
    "gid": 0,
    "mode": 420,
    "sha256": "ca43ac52dec0ed1083c006678f4e1e0b7e6c2882e8bcc66e76bc776b7340bfe8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/glossterm.block.properties.xml": {
    "bytes": 1542,
    "gid": 0,
    "mode": 420,
    "sha256": "7a02e18afff7f35a524b7ad438d53bcb7e4bdd808ba62c1c5e52123464c3aa32",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/glossterm.list.properties.xml": {
    "bytes": 1118,
    "gid": 0,
    "mode": 420,
    "sha256": "225b2f4d5432f9e32a696a4c42f60c163be2e2c740d31ff6ac1c87695f36028c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/glossterm.separation.xml": {
    "bytes": 1078,
    "gid": 0,
    "mode": 420,
    "sha256": "852fbda68d828523bda639156438509ceef2c30bd89f9a56befd9c9229fcf785",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/glossterm.width.xml": {
    "bytes": 935,
    "gid": 0,
    "mode": 420,
    "sha256": "97d211335166feb17988fbb57c81d265cd31a6e0c1274b287441a4f0c8975e3a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/graphic.default.extension.xml": {
    "bytes": 1115,
    "gid": 0,
    "mode": 420,
    "sha256": "a3d8ad61f0a626d863b656593638891211e68e94eee5b606f5445f7d8673799a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/graphical.admonition.properties.xml": {
    "bytes": 1914,
    "gid": 0,
    "mode": 420,
    "sha256": "2bb3ea90ac6dcc887c92b0d494dcf6e4947d5f587aa94d8ea770e2b7429ac05e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/graphics.dir.xml": {
    "bytes": 1096,
    "gid": 0,
    "mode": 420,
    "sha256": "b5e6f1557adeb3ee1dff288b0a64d5378c19c29bdae7386254d4169612f7897f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/graphicsize.extension.xml": {
    "bytes": 1277,
    "gid": 0,
    "mode": 420,
    "sha256": "aadec4ba906772a99538224d715f8f20c37a5f20eda9bd5a8f70a27da9cfcec6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/graphicsize.use.img.src.path.xml": {
    "bytes": 1100,
    "gid": 0,
    "mode": 420,
    "sha256": "ba5f15471ee3647a15822de1563f2eba7be330342e832c4616fbecea42884a10",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/handoutnotes.properties.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "6c547075da57b1c59e1cd1634c749f8696c27498340c1ca20552ea61dd34ee75",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/header.column.widths.xml": {
    "bytes": 2987,
    "gid": 0,
    "mode": 420,
    "sha256": "d804a70756e0298ac7170dc6832b1a40c3fce7e20f80ba70ac3067554c6ad150",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/header.content.properties.xml": {
    "bytes": 1135,
    "gid": 0,
    "mode": 420,
    "sha256": "2537a7de3f40526981e96dcc732aea1458e39c8e5ebe3e59d98ff8d4124f92b2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/header.hr.xml": {
    "bytes": 880,
    "gid": 0,
    "mode": 420,
    "sha256": "a1576b8fd66ae9ea30f55fad2fea3204ba96e06e5085bc28bcb32c76cb8e667c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/header.rule.xml": {
    "bytes": 848,
    "gid": 0,
    "mode": 420,
    "sha256": "342d4ec2b332eded8b8e597a4d91cdf0a46c42fa91c0edc3db721ec25f7f4b48",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/header.table.height.xml": {
    "bytes": 1241,
    "gid": 0,
    "mode": 420,
    "sha256": "6761fc3f289eb6f46f826828496b6d7eb3af99c7d7614b969006322c35e12b5d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/header.table.properties.xml": {
    "bytes": 1070,
    "gid": 0,
    "mode": 420,
    "sha256": "f224e6990dc864621d5bf2d1800cd1856f4230064f03ef761ae66e7da37017b4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/headers.on.blank.pages.xml": {
    "bytes": 905,
    "gid": 0,
    "mode": 420,
    "sha256": "2d68168e5ffb3b21ca7d720dce6700b5fc4fef588834017798380f0d927fcc46",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/hidetoc.image.xml": {
    "bytes": 963,
    "gid": 0,
    "mode": 420,
    "sha256": "913f24455c397cf548e5c7dce0c7c31c7d3677cc5d5429b132752ab88a315558",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/highlight.default.language.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "5d8633acd2b082afaa301a8ee451b8389986364aea0a3e93e2a99c1c0e1bea13",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/highlight.source.xml": {
    "bytes": 3433,
    "gid": 0,
    "mode": 420,
    "sha256": "f688fa8f42c1799e66d6306392448cc350402c489f222667c6ea70042f9336d3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/highlight.xslthl.config.xml": {
    "bytes": 1132,
    "gid": 0,
    "mode": 420,
    "sha256": "fc35396579ed870e2e062d3e62fedff51080bfce79ba7295c1dad49618aa2c66",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/home.image.xml": {
    "bytes": 848,
    "gid": 0,
    "mode": 420,
    "sha256": "3d4b45f327012cfadb1a4ec8acee8fbf68077e352f1e704a0b39ec80bfab4cb0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.append.xml": {
    "bytes": 1157,
    "gid": 0,
    "mode": 420,
    "sha256": "b7ad3157089ad15733376bd44004f418cf4b868b71470683194ca4fe44c20ba0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.base.xml": {
    "bytes": 1032,
    "gid": 0,
    "mode": 420,
    "sha256": "6865db30d5cb882a56f188b525a738a0a824a6c12d0fc6a5c420859a2231a651",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.cellpadding.xml": {
    "bytes": 983,
    "gid": 0,
    "mode": 420,
    "sha256": "4156be6502ba6daa517e5cff65e2792dd12e98f9ddcb439eda287080c461892c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.cellspacing.xml": {
    "bytes": 983,
    "gid": 0,
    "mode": 420,
    "sha256": "690fef3712002f2fdf56096bd9650b830dcba0686f347cd7c552c1542e9f277d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.cleanup.xml": {
    "bytes": 1268,
    "gid": 0,
    "mode": 420,
    "sha256": "65c00580ec905fe1fb62ad342026f1f35b53f8d27507efd385b5ecd67d246920",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.ext.xml": {
    "bytes": 947,
    "gid": 0,
    "mode": 420,
    "sha256": "a155fdd0616a6acefe8b99dd1f238862c05fea0924cba447298ed2e95807c2c3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.extra.head.links.xml": {
    "bytes": 1126,
    "gid": 0,
    "mode": 420,
    "sha256": "2c6c23129d61005a5ec6ccdb0c1462144c0ca1188fc2e9cf12081e0a60c5ae29",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.head.legalnotice.link.multiple.xml": {
    "bytes": 1798,
    "gid": 0,
    "mode": 420,
    "sha256": "8dcc88bf500ce654a35b6e78c9ebf48efce7608280d7d8327ef064cb481e06b1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.head.legalnotice.link.types.xml": {
    "bytes": 3149,
    "gid": 0,
    "mode": 420,
    "sha256": "ca7d0fa5a206f094d5ecb6580c5912add95f6f34ad654a1f54f2ff03c092fef8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.longdesc.link.xml": {
    "bytes": 1293,
    "gid": 0,
    "mode": 420,
    "sha256": "9ef192398d58297a52cafb685b948501e572b8f064744a644c756c46531aac21",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.longdesc.xml": {
    "bytes": 1014,
    "gid": 0,
    "mode": 420,
    "sha256": "8763fba6464b964d9de515ef7d92066c072caed8c8ce411d485ba61317d3ccaf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.script.type.xml": {
    "bytes": 1194,
    "gid": 0,
    "mode": 420,
    "sha256": "3c7b8314761d3c0591b1b2d32713e1d24b40e45213f9e07b5a14debf8eede09b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.script.xml": {
    "bytes": 1323,
    "gid": 0,
    "mode": 420,
    "sha256": "9f5340e8480ef14ed5319737913591e41346f624f8a1ca045d7ac9d4089f4787",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.stylesheet.type.xml": {
    "bytes": 944,
    "gid": 0,
    "mode": 420,
    "sha256": "022cecbc759e9fe7aa261b87fb81d5ce7e467cbc6761bd1c9b99120750a2dcee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/html.stylesheet.xml": {
    "bytes": 1347,
    "gid": 0,
    "mode": 420,
    "sha256": "7f5f8ea26130b8979d7f1dee36147489149ab364dd9547983290f60dab7f1581",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.alias.file.xml": {
    "bytes": 916,
    "gid": 0,
    "mode": 420,
    "sha256": "b39c9ddb900839750856dd40f9ff9c009b068dc9dc8107046bfff9789da3bbd9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.autolabel.xml": {
    "bytes": 941,
    "gid": 0,
    "mode": 420,
    "sha256": "b0e371f066211bc64ae8cf2bb7af04b20e3d650d3e0dd259c9d6a2f7c2830285",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.back.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "623718082c5b87404d5c6bd9df12b90a051884eca384f1ee5cdcf609d05f55df",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.forward.xml": {
    "bytes": 930,
    "gid": 0,
    "mode": 420,
    "sha256": "7d8203562e60fcdd95df7bbdc8f3a0b5c7c61feb5baf892c4cedb9f046437de9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.hideshow.xml": {
    "bytes": 939,
    "gid": 0,
    "mode": 420,
    "sha256": "0962142b371a2b69df3aacf128b0bf456cdc997ac062128a447fc4ef588b2647",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.home.url.xml": {
    "bytes": 916,
    "gid": 0,
    "mode": 420,
    "sha256": "6e06affb26693b347c28ef60dc8615bea8dc49a24b8bd73be01f57a7e6c60e74",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.home.xml": {
    "bytes": 908,
    "gid": 0,
    "mode": 420,
    "sha256": "e65175258b55ebffd841d569885d22059ae5150e634a7e4d3269f147145dd56a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.jump1.title.xml": {
    "bytes": 899,
    "gid": 0,
    "mode": 420,
    "sha256": "a56032e0a5ab7e1e2a9809da30a37f896b80381422160d87f2d4b793cd01cbdc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.jump1.url.xml": {
    "bytes": 923,
    "gid": 0,
    "mode": 420,
    "sha256": "39508d4c6565ca3dd484904d0fa2f6160279080a2b99a51654c5b240aa14b6c5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.jump1.xml": {
    "bytes": 931,
    "gid": 0,
    "mode": 420,
    "sha256": "8d507582aeb225c227ce58932cc1956fd612032163c8407d9318bd76fd57d8ce",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.jump2.title.xml": {
    "bytes": 899,
    "gid": 0,
    "mode": 420,
    "sha256": "633542b97001c05a38492c8c5dc94756f269ab20a5357232f0cc24c393bd47b4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.jump2.url.xml": {
    "bytes": 934,
    "gid": 0,
    "mode": 420,
    "sha256": "0e45119ce84359299d1ea689499b7fff460a49c630d3fd8ddf352752eb5a5fdb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.jump2.xml": {
    "bytes": 915,
    "gid": 0,
    "mode": 420,
    "sha256": "f1611380c7873ea80af233d259e946c50b2a1195a1dae627828da90d56b1b43d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.locate.xml": {
    "bytes": 930,
    "gid": 0,
    "mode": 420,
    "sha256": "105422655b5039a773fa0192bb9ff57cabf14ac65bbb1cef0678c542741e5857",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.next.xml": {
    "bytes": 908,
    "gid": 0,
    "mode": 420,
    "sha256": "b005947cfa3d3d2181d053e3b97c090474637b2ed9c3adcd5a60a3471c2771c3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.options.xml": {
    "bytes": 937,
    "gid": 0,
    "mode": 420,
    "sha256": "5f28f85eee11581f66c32d213ef2abf959b4f76e9baea6f239ed4b7c8c5fd971",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.prev.xml": {
    "bytes": 909,
    "gid": 0,
    "mode": 420,
    "sha256": "821b4589ea6258f6f30f92940ae6818729e9fe444d047bf2bcb671b2c1ab9d42",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.print.xml": {
    "bytes": 916,
    "gid": 0,
    "mode": 420,
    "sha256": "abc1424b0dc43dc976d733f420aaadacbe8be8b3cbea18115c35b4f06cf26f69",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.refresh.xml": {
    "bytes": 926,
    "gid": 0,
    "mode": 420,
    "sha256": "0e168223c837f4d99772aef28291e031d4d70d8c02a578c3dd08bf4a9c9aaf07",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.stop.xml": {
    "bytes": 916,
    "gid": 0,
    "mode": 420,
    "sha256": "9b6a10ee333750050ed50bd121386e37b9a7ce13c96d213b5d66aee039a2d726",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.button.zoom.xml": {
    "bytes": 909,
    "gid": 0,
    "mode": 420,
    "sha256": "9f6513bd66dfbaa94e9f11f8df052403060bc42cacbf7697cb4456b360706001",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.chm.xml": {
    "bytes": 857,
    "gid": 0,
    "mode": 420,
    "sha256": "31d060eaf218ddec71bfdbb100238b8938e11b84844286d7e0fb5d837dab535b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.default.topic.xml": {
    "bytes": 1369,
    "gid": 0,
    "mode": 420,
    "sha256": "af650f7c833a33488f7ee9884bdc996b2089d47c3525eac7c1ca911aca4c5dcb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.display.progress.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "0d23689a288d1b05d1e230d90a38d8865f9f2909b1251c5827ec0c9b8ca6a2ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.encoding.xml": {
    "bytes": 1075,
    "gid": 0,
    "mode": 420,
    "sha256": "6594cbf59a03b08b0b13e484b379e58b01e43c1e6ca7047f6641c9cc124d842e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.enhanced.decompilation.xml": {
    "bytes": 975,
    "gid": 0,
    "mode": 420,
    "sha256": "a2d4f0b1326062d551afaecde60a1e62a0d23c5e61017658daee0e5931a2b194",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.enumerate.images.xml": {
    "bytes": 1033,
    "gid": 0,
    "mode": 420,
    "sha256": "4d3cf8761263a177ff5d0ff76cf0463a145ffa5d092fe38373341b860e25722d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.force.map.and.alias.xml": {
    "bytes": 1112,
    "gid": 0,
    "mode": 420,
    "sha256": "23097c94d418e34ffdd6654573b2814946a36aba8c1d9910e2cec442d5634315",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.hhc.binary.xml": {
    "bytes": 1019,
    "gid": 0,
    "mode": 420,
    "sha256": "be26907693176426efb4aebe9af95c421158a2d678eabc784729bafccd3f4183",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.hhc.folders.instead.books.xml": {
    "bytes": 1139,
    "gid": 0,
    "mode": 420,
    "sha256": "70743019c941d23dfd49c096916cfac28d026ea3e4a44d6f14e0d60f8b3976ba",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.hhc.section.depth.xml": {
    "bytes": 949,
    "gid": 0,
    "mode": 420,
    "sha256": "305a805ee6a98d59f779d8a2415df00fe6f623a16abff56a115aa5685a0f91ab",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.hhc.show.root.xml": {
    "bytes": 1040,
    "gid": 0,
    "mode": 420,
    "sha256": "045ecd91ff4de625274513b556f8ee5860edece3c96f67cf05f383591a0b9407",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.hhc.width.xml": {
    "bytes": 931,
    "gid": 0,
    "mode": 420,
    "sha256": "02e9e7f00c4c70f358a5ef3edfccc13bcc9ed1bd4cdbf8f2005b04cca93eba45",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.hhc.xml": {
    "bytes": 878,
    "gid": 0,
    "mode": 420,
    "sha256": "af3864808e3830a466af227e20960849b1555e9fe959e93b2be1a811a4be5915",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.hhk.xml": {
    "bytes": 886,
    "gid": 0,
    "mode": 420,
    "sha256": "f02bb90fddf10d702292ea2593e8d3c0905f9b40677ee133280ebc7ce3771432",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.hhp.tail.xml": {
    "bytes": 954,
    "gid": 0,
    "mode": 420,
    "sha256": "d08506fdb3996a2236c3c8cff4fea10be79ce03e4209cfa602901fd409fd7c1f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.hhp.window.xml": {
    "bytes": 922,
    "gid": 0,
    "mode": 420,
    "sha256": "92293f708ae80bc4447e1d81d62fc0b403063c1d56d938c7a599117dc17c4e6b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.hhp.windows.xml": {
    "bytes": 977,
    "gid": 0,
    "mode": 420,
    "sha256": "5d22f7db40309df79bd60d4464bf4ba12dec1e6a12f1eb021bf78ea92f5fee81",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.hhp.xml": {
    "bytes": 896,
    "gid": 0,
    "mode": 420,
    "sha256": "d5e8186fc5dad12bbe8e5e8e6a9597629a5fd86d657a6efeb11f65eef1184b7e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.map.file.xml": {
    "bytes": 938,
    "gid": 0,
    "mode": 420,
    "sha256": "148258326902d6e05742d94d06b9b3390e0bd03b15f942b92101c38a6296ac96",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.only.xml": {
    "bytes": 1045,
    "gid": 0,
    "mode": 420,
    "sha256": "a61c70bc2e6b2476be2dc4c49e898af79d14e2f089bf4bcc30759e5326897f97",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.remember.window.position.xml": {
    "bytes": 976,
    "gid": 0,
    "mode": 420,
    "sha256": "ee670dbbbbff83743fec16ceae4ba0b0e4f38820d7c396917b2d6e3349da4136",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.show.advanced.search.xml": {
    "bytes": 983,
    "gid": 0,
    "mode": 420,
    "sha256": "cb7f0fb5efc93997e307bc291472f2691c13f383a679baa361d03d07e2870e6e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.show.favorities.xml": {
    "bytes": 957,
    "gid": 0,
    "mode": 420,
    "sha256": "b5e108143bfd72385cbed9045035f679bdd6122a411c7c14236d0fb352d4041a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.show.menu.xml": {
    "bytes": 910,
    "gid": 0,
    "mode": 420,
    "sha256": "165f8ea74633a43953d840c2841432f6b53b7fd03deeb6d32f2155984624a8ce",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.show.toolbar.text.xml": {
    "bytes": 963,
    "gid": 0,
    "mode": 420,
    "sha256": "c877ff4ca2bec490f04bc6f84ddec4141b633354738c023ddd951b3a819bfb3d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.title.xml": {
    "bytes": 937,
    "gid": 0,
    "mode": 420,
    "sha256": "56f0bd0419454ac218d7dfee67ebd9abf96495d95785ea1dd0d925a847c6134f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.use.hhk.xml": {
    "bytes": 1080,
    "gid": 0,
    "mode": 420,
    "sha256": "8f38b404a14d0d0c4420f8af95cc70466495c0ce867da0408261fc266bc7e0d0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/htmlhelp.window.geometry.xml": {
    "bytes": 1040,
    "gid": 0,
    "mode": 420,
    "sha256": "293348efa836537fa544cce468d8fad261d347b428acc18c1def39a9039e0933",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/hyphenate.verbatim.characters.xml": {
    "bytes": 1171,
    "gid": 0,
    "mode": 420,
    "sha256": "9220724020f809e6bd0f8807d2d1a57e0775a88293735fe500bc639cba66a866",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/hyphenate.verbatim.xml": {
    "bytes": 2172,
    "gid": 0,
    "mode": 420,
    "sha256": "af41dc3309e7301db95f7ae675599a96c7a35528fc577e8b9ff3a915cce69f54",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/hyphenate.xml": {
    "bytes": 1117,
    "gid": 0,
    "mode": 420,
    "sha256": "aa2fc0c1adc0d38daa2a0419203af6541f34a0b515b60133bf523658e6fbeebf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/id.warnings.xml": {
    "bytes": 977,
    "gid": 0,
    "mode": 420,
    "sha256": "b59c1f5ea5406f818e7ed0acc8daa2f4687ad0fb1a25de26730b5417cca5b9af",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/ignore.image.scaling.xml": {
    "bytes": 963,
    "gid": 0,
    "mode": 420,
    "sha256": "3771d62a87b19adc693704b20c27cf4dec41f422c595d6ba4cf00bae3388d9ec",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/img.src.path.xml": {
    "bytes": 1510,
    "gid": 0,
    "mode": 420,
    "sha256": "42b646e06870c31d356221bb4fc47c05e36a37fdba249a285904c6badcc50267",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/index.div.title.properties.xml": {
    "bytes": 1796,
    "gid": 0,
    "mode": 420,
    "sha256": "f2aeec600f6eec7a9262a8cf49cdb04cdde016b8f12e9c76ab7421eb7d4bce49",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/index.entry.properties.xml": {
    "bytes": 1188,
    "gid": 0,
    "mode": 420,
    "sha256": "b4cc0844884012d6e58989d55bad9c8439d0a8c5baab7e80db5900dafef77c1f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/index.links.to.section.xml": {
    "bytes": 2715,
    "gid": 0,
    "mode": 420,
    "sha256": "b732f2fd7cf786d88027167db8c8ff9297e7f4a32efa1d0b47245ce57e75d1ed",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/index.method.xml": {
    "bytes": 5764,
    "gid": 0,
    "mode": 420,
    "sha256": "42ccf4ee095df93b8782d5485b4bf87d911b54d2781161d3bd13271a6a4cde27",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/index.number.separator.xml": {
    "bytes": 1945,
    "gid": 0,
    "mode": 420,
    "sha256": "b070a525c397bbf5b9c2cc071d81913741bc3d238def9a55ed9324ede9d1c58b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/index.on.role.xml": {
    "bytes": 1655,
    "gid": 0,
    "mode": 420,
    "sha256": "80c331f71df9086d5fe9e59a7d3ed7ebe117d7eed463afa72dae6591f9cec5b5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/index.on.type.xml": {
    "bytes": 1824,
    "gid": 0,
    "mode": 420,
    "sha256": "ce4262529066dc1e79bbb08b02a7a73955dbf369bbec233c340fd59018660ce2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/index.page.number.properties.xml": {
    "bytes": 1051,
    "gid": 0,
    "mode": 420,
    "sha256": "17e51ae89e05a39a146a302cd7aa30e5323e857c7efd259147051cb6f8a0aba8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/index.prefer.titleabbrev.xml": {
    "bytes": 1028,
    "gid": 0,
    "mode": 420,
    "sha256": "91cdb64f80e3b619e6952dba0230d1332082aadb3e5a9bb1b385cc6440a19bab",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/index.preferred.page.properties.xml": {
    "bytes": 1224,
    "gid": 0,
    "mode": 420,
    "sha256": "b95939ff8c8f72a03dcb1820dd76fb5ea83143237b802d04ead03bb41cd08b37",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/index.range.separator.xml": {
    "bytes": 2029,
    "gid": 0,
    "mode": 420,
    "sha256": "fac8eaad64028f8fe6ddaa80d1717354d1ef9d5e9422bd30e68cb4347f3ea280",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/index.term.separator.xml": {
    "bytes": 1928,
    "gid": 0,
    "mode": 420,
    "sha256": "e9fdedd11168d680987e156897e5fc4067e6dc92244ed4b0c017209f4bcb3708",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/informal.object.properties.xml": {
    "bytes": 1432,
    "gid": 0,
    "mode": 420,
    "sha256": "b91c2c4a8d66c2dc907b05352e02f2ad0db203bb24b1336ebb4194c7370b5b1b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/informalequation.properties.xml": {
    "bytes": 983,
    "gid": 0,
    "mode": 420,
    "sha256": "c9c30c16fa028f3d7de3db69beaae5cae6683d4c754db52961402cc86893ca8e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/informalexample.properties.xml": {
    "bytes": 976,
    "gid": 0,
    "mode": 420,
    "sha256": "dffdd3b4ba85b3b67332c1d98ea8f191b76c91da5206728583e3762f624290cd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/informalfigure.properties.xml": {
    "bytes": 969,
    "gid": 0,
    "mode": 420,
    "sha256": "9e7e3a9291d3d326fc8b6fd111bf3f16f36709bb3b128ddb4e9fa7421781995c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/informaltable.properties.xml": {
    "bytes": 1253,
    "gid": 0,
    "mode": 420,
    "sha256": "ce9bed53033c7a8253037c26682a1bc71b4dbeae187eab5e9f7830245477f463",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/inherit.keywords.xml": {
    "bytes": 1099,
    "gid": 0,
    "mode": 420,
    "sha256": "1341107f01c9df5b6604ecacf3c607161a061ab5d4ebcd8bf8fb2e380114ec69",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/inlinestagedir.properties.xml": {
    "bytes": 1333,
    "gid": 0,
    "mode": 420,
    "sha256": "4d3dd60ab6da5739da0d8ccb6f5a9b574031fc6e29611f6e14d5bef9d6f9b1ad",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/inner.region.content.properties.xml": {
    "bytes": 1748,
    "gid": 0,
    "mode": 420,
    "sha256": "df68f57bc2ec0d5819ced1bb6ff84b6d1658dcdd371bed7646621ab4071a8ee5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/insert.link.page.number.xml": {
    "bytes": 2334,
    "gid": 0,
    "mode": 420,
    "sha256": "d0523eadd49c9909356690116bb433fefb402a489545ebffbb9efe4a5205f56b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/insert.olink.page.number.xml": {
    "bytes": 2859,
    "gid": 0,
    "mode": 420,
    "sha256": "cfe3ec172cf0b7d1dfc70c32ba92fa5e9b19b0b6c641a4c1a4523f491662fc05",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/insert.olink.pdf.frag.xml": {
    "bytes": 2587,
    "gid": 0,
    "mode": 420,
    "sha256": "e8ca22ef1780ab9ae22b47253dc9946caae9c3dea992a62830f32ab052a38836",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/insert.xref.page.number.para.xml": {
    "bytes": 1800,
    "gid": 0,
    "mode": 420,
    "sha256": "a9fc4356fe6a9d4d2d5d0a013d2d2e82da6da40d3dae8ac9f49610cbeef9ad60",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/insert.xref.page.number.xml": {
    "bytes": 1916,
    "gid": 0,
    "mode": 420,
    "sha256": "2597f55c0cdfa36a803591af93d05c312ba460e8b32173ed19bad76537b6c2bf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/itemizedlist.label.properties.xml": {
    "bytes": 1192,
    "gid": 0,
    "mode": 420,
    "sha256": "dc531d6ab197a367489b1f83274a727cb161ad71e00dca8ed984a04b7cdf8141",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/itemizedlist.label.width.xml": {
    "bytes": 1151,
    "gid": 0,
    "mode": 420,
    "sha256": "b4471db3f918e2a1001ed3788709388430536e3a55a492a46281779c80178bab",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/itemizedlist.properties.xml": {
    "bytes": 1030,
    "gid": 0,
    "mode": 420,
    "sha256": "b515a1b4f21354daa641ca0794cffa1007731ac8a08df5ff39171d180373d000",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/javahelp.encoding.xml": {
    "bytes": 1015,
    "gid": 0,
    "mode": 420,
    "sha256": "06abb8974ab2499e4f669b111bf7681e4faed0ac300fd6a5676dde99ee0cb1c9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/keep.relative.image.uris.xml": {
    "bytes": 1304,
    "gid": 0,
    "mode": 420,
    "sha256": "be558d6fca5b6f1adcc3f50d26c5a041d09f97ba0a0d8f62a2820c206f1d22b5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/keyboard.nav.xml": {
    "bytes": 956,
    "gid": 0,
    "mode": 420,
    "sha256": "38efb8673c6e0eee4a14f69cb9e8da407f2e6608be82ebf4a1d06521605ee9d6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/l10n.gentext.default.language.xml": {
    "bytes": 1109,
    "gid": 0,
    "mode": 420,
    "sha256": "25c4b485845487fc74ae76f8d2839a680ba173606c98f2e0f1ff7ff5ff035174",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/l10n.gentext.language.xml": {
    "bytes": 1231,
    "gid": 0,
    "mode": 420,
    "sha256": "979f75ed9a55270f1395cb254beac44d0808ed7e4ed2823b37a337d2a67a4c82",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/l10n.gentext.use.xref.language.xml": {
    "bytes": 1866,
    "gid": 0,
    "mode": 420,
    "sha256": "ccb4deef7c72470b87bfc1c7a7bf262cb388eb8916ee3a7ae51a6163c6ae07e5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/l10n.lang.value.rfc.compliant.xml": {
    "bytes": 2408,
    "gid": 0,
    "mode": 420,
    "sha256": "eea373050541ac84b54a0f4ebfa4c421966be1d62579e4d65caac8eb925b6deb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/label.from.part.xml": {
    "bytes": 1446,
    "gid": 0,
    "mode": 420,
    "sha256": "7018d3f899e629b0796b9849e8ba010b3cf74dfd6f83b715fc405a441806fcb3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/line-height.xml": {
    "bytes": 839,
    "gid": 0,
    "mode": 420,
    "sha256": "58394c07e15e176ca4db304df706898b28ea7433da2a1aa259b877968a555c81",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/line.properties.xml": {
    "bytes": 1007,
    "gid": 0,
    "mode": 420,
    "sha256": "aa241e377e7811602ce401e35c7a9583e514d6319be5f9889e5dd54046bbe89a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/linegroup.properties.xml": {
    "bytes": 1277,
    "gid": 0,
    "mode": 420,
    "sha256": "660b597a19f9dc9fc81e2ecfefe94dc9e4eb0ac844a8c8823537fe192b33dabe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/linenumbering.everyNth.xml": {
    "bytes": 1182,
    "gid": 0,
    "mode": 420,
    "sha256": "d0df0444e0da07163c56c1f53725461e7369943f66ca1e0681d4794847f11003",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/linenumbering.extension.xml": {
    "bytes": 1068,
    "gid": 0,
    "mode": 420,
    "sha256": "85d8503a1c9e6a4bc36ac82c66c9dd5329ff4b5df10797798683336c8a64d410",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/linenumbering.separator.xml": {
    "bytes": 1102,
    "gid": 0,
    "mode": 420,
    "sha256": "5878ae666c7a18bfcd43f06d736edd705d37a20dc700b8217bab0ddb54ab27db",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/linenumbering.width.xml": {
    "bytes": 955,
    "gid": 0,
    "mode": 420,
    "sha256": "208ca6f2d76a8b511ccc9bdbfba62d37d5819c3fb55bf6e1983d1686692893e2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/link.mailto.url.xml": {
    "bytes": 977,
    "gid": 0,
    "mode": 420,
    "sha256": "ca1defb67cbd1f4bd7a4a1e769e1055337aca3d12dc7e3981c593cf057f6abcb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/link.to.self.for.mediaobject.xml": {
    "bytes": 1760,
    "gid": 0,
    "mode": 420,
    "sha256": "d342745c2a69d8efb826c5d239ecbcbaffa69c7ec806fb69c36c1a7852dd9e22",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/list.block.properties.xml": {
    "bytes": 1138,
    "gid": 0,
    "mode": 420,
    "sha256": "14d1f81d3dfc4f8a96e8ec5cf4b8230a3f649fe7c851b78b68c99695a146b85b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/list.block.spacing.xml": {
    "bytes": 1600,
    "gid": 0,
    "mode": 420,
    "sha256": "dbd44da1d3a7298fe429c96400eab6858d2cc7fae1c7d98f3fd737b70d2e4672",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/list.item.spacing.xml": {
    "bytes": 1257,
    "gid": 0,
    "mode": 420,
    "sha256": "26bf5870963dcbfa1c58c1a75e274e2221710ce8c712515c8fe4eaac279d9348",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/make.clean.html.xml": {
    "bytes": 2045,
    "gid": 0,
    "mode": 420,
    "sha256": "f8abff698ae823f783eb867aaa562c3ae29df96575efbc0dbfc2aa7d19db5d8d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/make.graphic.viewport.xml": {
    "bytes": 1349,
    "gid": 0,
    "mode": 420,
    "sha256": "8d03e04307e8a3b123cb286e8a38150fe90087a8ab2b91f81a50d4799a6ff2f6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/make.index.markup.xml": {
    "bytes": 2817,
    "gid": 0,
    "mode": 420,
    "sha256": "bd424fca9a7745cf3cda0203503e6563b7fcf8bf8cfb53ea6caf02f97686f1b8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/make.single.year.ranges.xml": {
    "bytes": 1010,
    "gid": 0,
    "mode": 420,
    "sha256": "2403139322ec3c0bffb3113a47663deeff0d1a08577a510f38037ba48e481750",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/make.valid.html.xml": {
    "bytes": 1338,
    "gid": 0,
    "mode": 420,
    "sha256": "959f7032b5d8f33c65839e966f62783ce204424742517e524910bc2663faf51c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/make.year.ranges.xml": {
    "bytes": 1150,
    "gid": 0,
    "mode": 420,
    "sha256": "21222c08237e40cf62d2c2a03e9306ea4be00cf107c2609822ad3accaac6f3b6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.authors.section.enabled.xml": {
    "bytes": 1970,
    "gid": 0,
    "mode": 420,
    "sha256": "cbe532f9ba9fc26fde80953b4e1e7c9c256d282fbbcc07cbe413cd605ef954df",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.base.url.for.relative.links.xml": {
    "bytes": 3183,
    "gid": 0,
    "mode": 420,
    "sha256": "707d532f14a6d4467e5694f21b9aad5514f41f5bfa2522f86e417509fda1e57f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.break.after.slash.xml": {
    "bytes": 1918,
    "gid": 0,
    "mode": 420,
    "sha256": "a222a8a64e48b6ba2fc6aed2590bd291986a72e2a69f2f2ac0a2e1e2b1131624",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.charmap.enabled.xml": {
    "bytes": 2413,
    "gid": 0,
    "mode": 420,
    "sha256": "9e7d93c282c0749a86809b78a68960dcd975f726fc730a33b538f7a532124ed7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.charmap.subset.profile.english.xml": {
    "bytes": 3455,
    "gid": 0,
    "mode": 420,
    "sha256": "7bf748615ff7de7a113b89a0edf66551ccae8ac5a8bc674fdb2314fcb9febb16",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.charmap.subset.profile.xml": {
    "bytes": 14006,
    "gid": 0,
    "mode": 420,
    "sha256": "ca7c5e8ce2f571dbbd03a1fed38c61ffcf88b0363fba67d9518c54125c3c4706",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.charmap.uri.xml": {
    "bytes": 1678,
    "gid": 0,
    "mode": 420,
    "sha256": "abbf101cba9b7ed7bc456f634170c0a8732286969d6895fa2e35914bbc814715",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.charmap.use.subset.xml": {
    "bytes": 3595,
    "gid": 0,
    "mode": 420,
    "sha256": "b5b47469f4c4176630b6c7f7a0bfd620e0609f433f3e5b45027a83d288a55f80",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.copyright.section.enabled.xml": {
    "bytes": 1963,
    "gid": 0,
    "mode": 420,
    "sha256": "758f43281c31e0b7741537c06fdf386f09ec1d75d3ffc8f066bbf96a38037032",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.endnotes.are.numbered.xml": {
    "bytes": 4886,
    "gid": 0,
    "mode": 420,
    "sha256": "1ccb78a88e5cf36c74d09515d2011ea07c38c934f48956e806b7457e0bbb21fc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.endnotes.list.enabled.xml": {
    "bytes": 5156,
    "gid": 0,
    "mode": 420,
    "sha256": "e710304e09d5b03d789bbc4ba804242ba7cf0c1f2f1a5bf4f447d2bd8b20aa60",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.endnotes.list.heading.xml": {
    "bytes": 1470,
    "gid": 0,
    "mode": 420,
    "sha256": "61ac9ea8c6259c189de9b89cbacad18e960370137349e9bc71ee886d513c56e1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.font.funcprototype.xml": {
    "bytes": 1076,
    "gid": 0,
    "mode": 420,
    "sha256": "3993ebafd6d45d1b0eb784dbb459fd106291ebfa4810be2c20ee97eddd376774",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.font.funcsynopsisinfo.xml": {
    "bytes": 1098,
    "gid": 0,
    "mode": 420,
    "sha256": "7d9444b1bfe13b23851367361d83b8f5927097525bc1549d8d16d2fdeccb0403",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.font.links.xml": {
    "bytes": 2773,
    "gid": 0,
    "mode": 420,
    "sha256": "5602367aa4d862f2aa3cc8f991915fbe0a72ac57d103ac6ef06768b299c5c37d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.font.table.headings.xml": {
    "bytes": 1063,
    "gid": 0,
    "mode": 420,
    "sha256": "9f457f24a8df575d6973ece92655e66c0bdb5d6ead6902fdd28aeb780ae86254",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.font.table.title.xml": {
    "bytes": 1043,
    "gid": 0,
    "mode": 420,
    "sha256": "3748cdd94d5cb35b1a0cb8347bcc1f1e7c322a378ef7a8df614738d6948eedfb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.funcsynopsis.style.xml": {
    "bytes": 1215,
    "gid": 0,
    "mode": 420,
    "sha256": "53a5611234abff1a5ffe987c25a8150077f2ba0fe9f4c357838c3996f1c1badd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.hyphenate.computer.inlines.xml": {
    "bytes": 1918,
    "gid": 0,
    "mode": 420,
    "sha256": "a769d33aad1b9725fe05e91acd7f670c5a89ce37857572f6111c33256057a045",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.hyphenate.filenames.xml": {
    "bytes": 1704,
    "gid": 0,
    "mode": 420,
    "sha256": "63cbd0d833697c177fcaf41da7ae4a7d78918f577ecaada5fb64f6773bb04b39",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.hyphenate.urls.xml": {
    "bytes": 1679,
    "gid": 0,
    "mode": 420,
    "sha256": "abe5f9944f6338bc2bddba3db7a346679cf2e79ac6607d5d463ef0b2ae40cbc2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.hyphenate.xml": {
    "bytes": 2374,
    "gid": 0,
    "mode": 420,
    "sha256": "71f39ee8faafb7e1520c827cbc50eb2bfd5195494bdfcb000d2fdea590675454",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.indent.blurbs.xml": {
    "bytes": 1264,
    "gid": 0,
    "mode": 420,
    "sha256": "8bfda865be39ad456d19eb7683db632325b951d6b6f2db3d98299dd95f67f000",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.indent.lists.xml": {
    "bytes": 1305,
    "gid": 0,
    "mode": 420,
    "sha256": "488aabd218ebb09f847782f401a2810f329ef338b41a7436b884718a3f1ff289",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.indent.refsect.xml": {
    "bytes": 2702,
    "gid": 0,
    "mode": 420,
    "sha256": "138d7216c3223b78a04727d61ec434bbdb9a8a8bd338e7bd50acf7c4e14cf52c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.indent.verbatims.xml": {
    "bytes": 1300,
    "gid": 0,
    "mode": 420,
    "sha256": "a97b796d5ccbc564c2387b819291aead913f21efb86524a3450c87bf0e9904c0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.indent.width.xml": {
    "bytes": 1588,
    "gid": 0,
    "mode": 420,
    "sha256": "5afd02e56f19f11d73635b280f4c20d6c4d563184309cb4d583bb229fa789457",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.justify.xml": {
    "bytes": 2197,
    "gid": 0,
    "mode": 420,
    "sha256": "cf2ffc50cc676aadec65f95f8fe268fa51cf9a2b4cb451b12d1e2d6bfe698f2a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.output.base.dir.xml": {
    "bytes": 1521,
    "gid": 0,
    "mode": 420,
    "sha256": "f808da08ad1b8e5ab75bcc7d8d2dcaf2fa51cdf47e693b212d2a893fe301d31c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.output.better.ps.enabled.xml": {
    "bytes": 2654,
    "gid": 0,
    "mode": 420,
    "sha256": "1e8ba817771eec26b212cb98435922bc8914993d33ce80be2105b2bf7d26dc19",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.output.encoding.xml": {
    "bytes": 2185,
    "gid": 0,
    "mode": 420,
    "sha256": "3200832449b44f1ef347d83387e30fa42878fb2840a0812f77b72dcfa8f0fef7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.output.in.separate.dir.xml": {
    "bytes": 1241,
    "gid": 0,
    "mode": 420,
    "sha256": "f2ef53958cba90d2e216cfbb68166c4ca6f6bc5bf9cc8546c1a9efdc477e1a7d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.output.lang.in.name.enabled.xml": {
    "bytes": 1828,
    "gid": 0,
    "mode": 420,
    "sha256": "c733dc5a794f8273d72e437396b3deda095570c108f8c5160876739757f220dc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.output.manifest.enabled.xml": {
    "bytes": 1111,
    "gid": 0,
    "mode": 420,
    "sha256": "67bbb7166d05ff96cf392c7bb4e9b1969d67d13d3b19534676859e10f7c8b5e5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.output.manifest.filename.xml": {
    "bytes": 1182,
    "gid": 0,
    "mode": 420,
    "sha256": "00b6d0a4842895541a24cc1fcb11b9e9678b4257657510f42f44b3e9c5966b4e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.output.quietly.xml": {
    "bytes": 1293,
    "gid": 0,
    "mode": 420,
    "sha256": "00df60e714d86ed9a0afcdb78a23a78cbffaf334e8f729f675ac27ff17acd6ee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.output.subdirs.enabled.xml": {
    "bytes": 1571,
    "gid": 0,
    "mode": 420,
    "sha256": "ffd611fe5522e6873b8e3d4bd0302c91e3f7c23bbe147957970a9da493b58632",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.segtitle.suppress.xml": {
    "bytes": 1002,
    "gid": 0,
    "mode": 420,
    "sha256": "f2a82075931b0eb16b2c4dae31c41f336c38985c35458f72fb5dcb37b99c9d23",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.string.subst.map.local.post.xml": {
    "bytes": 1361,
    "gid": 0,
    "mode": 420,
    "sha256": "a8238339c76869164d44fc48c4715741f3cb86c85510b5905fb368e8c0d09f3b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.string.subst.map.local.pre.xml": {
    "bytes": 1358,
    "gid": 0,
    "mode": 420,
    "sha256": "da8419e7f77718cb465fc4fd9e3600bd194cb5cbb0eb22699fe9f9021907b0d4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.string.subst.map.xml": {
    "bytes": 6861,
    "gid": 0,
    "mode": 420,
    "sha256": "3748e493b731620413ce2fde27013daf95f172f44b03512200627dddd96885de",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.subheading.divider.enabled.xml": {
    "bytes": 1499,
    "gid": 0,
    "mode": 420,
    "sha256": "db9dd3d3b1a5a046d7ef2cc002aef7df5297703f36015b6c9be70924130a2b60",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.subheading.divider.xml": {
    "bytes": 1536,
    "gid": 0,
    "mode": 420,
    "sha256": "d7eb4f232c85b989838b832a6a118002ed524b0793fb98b425de0bd01d17eca2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.table.footnotes.divider.xml": {
    "bytes": 1097,
    "gid": 0,
    "mode": 420,
    "sha256": "c28016a89b4e34eb1956c565ba065365a34ba0df5af4c280425fce1a72f946cd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.th.extra1.suppress.xml": {
    "bytes": 1203,
    "gid": 0,
    "mode": 420,
    "sha256": "44b23da2858879a22ec0e6605b374dde5f9a69e17f49e2fbed4600b31a647eae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.th.extra2.max.length.xml": {
    "bytes": 1819,
    "gid": 0,
    "mode": 420,
    "sha256": "d5a04a909aca3f3fe1fa6a3df8d18d99c57ef97d703a2c9b7dd52b66ad9a8f65",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.th.extra2.suppress.xml": {
    "bytes": 1685,
    "gid": 0,
    "mode": 420,
    "sha256": "a8ccf7d26019933de3fb1b73daa3f81144397aedeeb1d60bf8585cdf1ebcd69a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.th.extra3.max.length.xml": {
    "bytes": 1789,
    "gid": 0,
    "mode": 420,
    "sha256": "85f6a185ed1ac7bfc07764be2cabf3f7838b165f8bbf8a0eb1974ea8a3c8c78b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.th.extra3.suppress.xml": {
    "bytes": 1291,
    "gid": 0,
    "mode": 420,
    "sha256": "d5ebe8c7616f2f820d3250890830c38472ca75c353c447cf70b46a7fae9dba6e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/man.th.title.max.length.xml": {
    "bytes": 2647,
    "gid": 0,
    "mode": 420,
    "sha256": "84a3f0f8917d6e1b8a461e586ffdc6360dab99ff176b4137115f9ac429478164",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/manifest.in.base.dir.xml": {
    "bytes": 1059,
    "gid": 0,
    "mode": 420,
    "sha256": "72ef5e1fef34ed947a6538262ecac4a5c1793f49de1ea72a8c980eab4aad94b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/manifest.xml": {
    "bytes": 988,
    "gid": 0,
    "mode": 420,
    "sha256": "20f49e604c474b22df60237e9ca35ff4841f3da254df1c8063b1608a890d7dc5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/manual.toc.xml": {
    "bytes": 917,
    "gid": 0,
    "mode": 420,
    "sha256": "775077442cbce7569da6262b94d0d6cc4bec4a436359dfefa18c46a235dce201",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/margin.note.float.type.xml": {
    "bytes": 2758,
    "gid": 0,
    "mode": 420,
    "sha256": "6a70d1e981d0446ef5a70e0d566e16b2f92ce6145ebf93337e783dfdf34e7ab3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/margin.note.properties.xml": {
    "bytes": 1934,
    "gid": 0,
    "mode": 420,
    "sha256": "912479764efe2df4de0e6903657b5860225045ace6b45abd4c2d9970c265e973",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/margin.note.title.properties.xml": {
    "bytes": 1197,
    "gid": 0,
    "mode": 420,
    "sha256": "e2752b005afd450a6771a399168fd1436774c0ba03aa6f7eaa808173d3943247",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/margin.note.width.xml": {
    "bytes": 1187,
    "gid": 0,
    "mode": 420,
    "sha256": "82fef982bad1b039f8c7b9addfcc0998e53960377962d6ccb32d95ce38c3e769",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/mark.optional.procedure.steps.xml": {
    "bytes": 1301,
    "gid": 0,
    "mode": 420,
    "sha256": "9ef8df68d36fd1d8e460230ef064f974b17d0a004492f4e305e39d9aa629178e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/marker.section.level.xml": {
    "bytes": 1839,
    "gid": 0,
    "mode": 420,
    "sha256": "36af951a498674caf17d206f017e11c6d51ab58ee1e4b46b21a79b513d0ae151",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/menuchoice.menu.separator.xml": {
    "bytes": 1517,
    "gid": 0,
    "mode": 420,
    "sha256": "05475b809ab53665b8c796cadbc132209f709034c051889e84376b29ed19d19d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/menuchoice.separator.xml": {
    "bytes": 1133,
    "gid": 0,
    "mode": 420,
    "sha256": "c9fcf87d13e5d7dd5d5a1347d86585a75beadf9ee38191910408d5080c24f897",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/minus.image.xml": {
    "bytes": 965,
    "gid": 0,
    "mode": 420,
    "sha256": "bbff36bfa5b86a096dae4d4db33c5255e37121b4a96aeed168cebf695fffd81d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/mml.embedding.mode.fo.xml": {
    "bytes": 1838,
    "gid": 0,
    "mode": 420,
    "sha256": "c0f8068af7cfa12c204eb942fc858895e53fa41d4e81f628d71c914368a095de",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/mml.embedding.mode.xml": {
    "bytes": 2596,
    "gid": 0,
    "mode": 420,
    "sha256": "f98902627aa25a021373cfab6f65f7b8c802fb5a36a639d0afff700a8d75eca3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/monospace.font.family.xml": {
    "bytes": 1181,
    "gid": 0,
    "mode": 420,
    "sha256": "da8d891d7e9f4fa983e3e64530dfc77913b0366b6287aeff1b15f9f6a6550bbe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/monospace.properties.xml": {
    "bytes": 1366,
    "gid": 0,
    "mode": 420,
    "sha256": "3656cc4cb5f0f24be2e40f6d1c6c84fe125769c30282f38fce0c5bbd4da165e2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/monospace.verbatim.font.width.xml": {
    "bytes": 1541,
    "gid": 0,
    "mode": 420,
    "sha256": "fc33bb28875a8ce91683a1812208dd2ae57c1626acb0b8c14c9439f87d2b2440",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/monospace.verbatim.properties.xml": {
    "bytes": 1176,
    "gid": 0,
    "mode": 420,
    "sha256": "5202c9fbd31f562c9d2a4865c7bf765458ae3f966a7c1022d106ee5bc28073a9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/multiframe.bottom.bgcolor.xml": {
    "bytes": 1012,
    "gid": 0,
    "mode": 420,
    "sha256": "78ac76f5dd929604dd938dd06bfea5cd5922eab3f4dad38d0dc3ac147c4ba2cd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/multiframe.navigation.height.xml": {
    "bytes": 1002,
    "gid": 0,
    "mode": 420,
    "sha256": "9cbc405de7fee5dc9347be1983ba56c03a37566e6aa0a1b4f8f45bca1c306058",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/multiframe.top.bgcolor.xml": {
    "bytes": 992,
    "gid": 0,
    "mode": 420,
    "sha256": "9382dbb961d928567ac15da748cd55cd48816d59e5fcb0c701dd8c21fa3d2651",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/multiframe.xml": {
    "bytes": 1161,
    "gid": 0,
    "mode": 420,
    "sha256": "c25003a9220409afdb6c48ca0c8f837fd9deedf996c938f7af2ff28d8ebb81e0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/nav.separator.xml": {
    "bytes": 952,
    "gid": 0,
    "mode": 420,
    "sha256": "33373bd96ad3df00418ce310695e06146fd22e872dfcca7ddc903e59902d2d70",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/nav.table.summary.xml": {
    "bytes": 1041,
    "gid": 0,
    "mode": 420,
    "sha256": "7cdeb6bb3dfbd7a4315ff4f258a724649051e05ffc3c08040eb96447e0aa2b65",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/navbgcolor.xml": {
    "bytes": 926,
    "gid": 0,
    "mode": 420,
    "sha256": "12e1c68880c5a028c242f7457c774883f3e2bd4eb51ee4cd626e662e25f7bb1c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/navbodywidth.xml": {
    "bytes": 911,
    "gid": 0,
    "mode": 420,
    "sha256": "d2ea29dbc9a45192eabd199117089770c744eb9fe1d13fb6e37835066c0f5be9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/navig.graphics.extension.xml": {
    "bytes": 983,
    "gid": 0,
    "mode": 420,
    "sha256": "323fb4b2d49c8458f3cb8391c7d4828e0cb5d9caa3ea483a2f3949313e50e592",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/navig.graphics.path.xml": {
    "bytes": 1009,
    "gid": 0,
    "mode": 420,
    "sha256": "491040ad5c9e3cc1220af89da59706ea4c107702fa3c90a5414024a89b865069",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/navig.graphics.xml": {
    "bytes": 1093,
    "gid": 0,
    "mode": 420,
    "sha256": "b35579990e511591e836a646a6016cc8ea16820225cbd68300376f295be3c9f7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/navig.showtitles.xml": {
    "bytes": 1139,
    "gid": 0,
    "mode": 420,
    "sha256": "cc1cb32012ed234f1d03982f2fbe28c7687bd080aee9403bec377237d4ba4ea0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/navtocwidth.xml": {
    "bytes": 937,
    "gid": 0,
    "mode": 420,
    "sha256": "c55a9ac21dc1c7d9f75e26e89a460c28bc52749a0f54d505e1a03d5b6463ed70",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/next.image.xml": {
    "bytes": 867,
    "gid": 0,
    "mode": 420,
    "sha256": "8fd9c38bb6275682d12f5ef29ac8977bb2e7fc176a7170f1832a58acdd384ab9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/no.home.image.xml": {
    "bytes": 883,
    "gid": 0,
    "mode": 420,
    "sha256": "6e5b8266a5ae25809a765efa463306e273f7e1e880517d0029e628c93bc8e148",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/no.next.image.xml": {
    "bytes": 901,
    "gid": 0,
    "mode": 420,
    "sha256": "50af1f6c515ba759e7ccd92c9bd7bd3e6535003a09024b3d5053df40600e7c27",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/no.prev.image.xml": {
    "bytes": 900,
    "gid": 0,
    "mode": 420,
    "sha256": "1027dd328899723dd9908774437e8095b83c1c9b26e004d2a6cdbfa84bc03168",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/no.toc.image.xml": {
    "bytes": 875,
    "gid": 0,
    "mode": 420,
    "sha256": "654362640dbb4b72ab479135f0c0298a348c4df2a9f9c0cb646a594500bb1e8c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/no.up.image.xml": {
    "bytes": 888,
    "gid": 0,
    "mode": 420,
    "sha256": "b7eafc50d42d9f79f1950ccdf8207882d4cc501a06178f4ece1828c50213caaf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/nominal.image.depth.xml": {
    "bytes": 896,
    "gid": 0,
    "mode": 420,
    "sha256": "21a450501968f2c41c8c1d1daa55fc327d8890ef0f51fa13aa88c144dc8a290d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/nominal.image.width.xml": {
    "bytes": 1702,
    "gid": 0,
    "mode": 420,
    "sha256": "eb3ba8338960b380fc432e0ede5ee63350bf12b9cd2be255f584e046c9de6ace",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/nominal.table.width.xml": {
    "bytes": 1092,
    "gid": 0,
    "mode": 420,
    "sha256": "dea35e4a964cdd82ea21ca731c84fd7f90a75f2fc4ff292f5b0dfc6cd2c8305a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/nongraphical.admonition.properties.xml": {
    "bytes": 1887,
    "gid": 0,
    "mode": 420,
    "sha256": "dc41428b6312afbc328f7bf28b4fb0f0435603a49ae5d21e98faecc5747fc74e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/normal.para.spacing.xml": {
    "bytes": 1550,
    "gid": 0,
    "mode": 420,
    "sha256": "75f25b2039f63f034411b483c05baa6b735ad6d2db0c1392a491c0903784713a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/olink.base.uri.xml": {
    "bytes": 1595,
    "gid": 0,
    "mode": 420,
    "sha256": "b3d45d2dcd8def1ff617c3442df6f26e32be1b3568d038c46743b68d06ca62f3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/olink.debug.xml": {
    "bytes": 1173,
    "gid": 0,
    "mode": 420,
    "sha256": "18eaa6d28f7236cc1b2ace1376c0cf05ab423d04ac00bfb4a780781a1fe064fb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/olink.doctitle.xml": {
    "bytes": 4729,
    "gid": 0,
    "mode": 420,
    "sha256": "3e258b40d3dfbfd227fa4ce0f30c70d285db3ddf169e243a3472fdd7b72db83b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/olink.fragid.xml": {
    "bytes": 905,
    "gid": 0,
    "mode": 420,
    "sha256": "e63d2bd7a8e482475776b1431a292e1f8b894ff018ea6f1eaf844cf9d19f7d4a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/olink.lang.fallback.sequence.xml": {
    "bytes": 3225,
    "gid": 0,
    "mode": 420,
    "sha256": "b83b1ee4a1a47958eb630b285d379b712af80216697e355c61648d4d2797d682",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/olink.outline.ext.xml": {
    "bytes": 958,
    "gid": 0,
    "mode": 420,
    "sha256": "9de6e4fafbdf45981db89e20c6830222a8ed452b4db4fa60d57105636acbdb00",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/olink.properties.xml": {
    "bytes": 1149,
    "gid": 0,
    "mode": 420,
    "sha256": "76064d166157730f9a96f3c71412b6edf4a4db4eda4bb265785e5636f97e0f6f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/olink.pubid.xml": {
    "bytes": 838,
    "gid": 0,
    "mode": 420,
    "sha256": "506532901c3d5ba3b081cf5f79b47fcef6ce8188f7c687c475663f2de7a6a15f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/olink.resolver.xml": {
    "bytes": 859,
    "gid": 0,
    "mode": 420,
    "sha256": "2f1308d4a9115ef672b155122072e65b0e313e94502ecf590cd910e06eab74bb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/olink.sysid.xml": {
    "bytes": 843,
    "gid": 0,
    "mode": 420,
    "sha256": "cdde8c3dc6918591375aa5c3c32edbc09fba3d8b633e226543883a61c5ae41b4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/orderedlist.label.properties.xml": {
    "bytes": 1184,
    "gid": 0,
    "mode": 420,
    "sha256": "64f6c2875b40aa66c0fcccda790cc08f0191e4ba4d0826212d727227e2c42c5e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/orderedlist.label.width.xml": {
    "bytes": 1141,
    "gid": 0,
    "mode": 420,
    "sha256": "ac31e5f47180acc6b938d44d1d41623db1d0363d575706fb2af8c7a052a2c044",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/orderedlist.properties.xml": {
    "bytes": 1103,
    "gid": 0,
    "mode": 420,
    "sha256": "1f52343a8d8c8ca81ad1f08ebe591985056a327ac3536e3784749ecc18bfad52",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/othercredit.like.author.enabled.xml": {
    "bytes": 1202,
    "gid": 0,
    "mode": 420,
    "sha256": "c4f0a06bdbb9f9b9524b9dc074415fec0445921ad5fc25870d6a43c3d6fb3a84",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/outer.region.content.properties.xml": {
    "bytes": 1760,
    "gid": 0,
    "mode": 420,
    "sha256": "650db404964232880607604dbf213118463aedd2d35d93ff41568db265051719",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/output-root.xml": {
    "bytes": 1056,
    "gid": 0,
    "mode": 420,
    "sha256": "cd5f4410747e5895da8379f814329eaae76486a67c2d28c72921b60386797c30",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/output.indent.xml": {
    "bytes": 1190,
    "gid": 0,
    "mode": 420,
    "sha256": "278aa910bb21642d569727f65eb58878f0ef9fad81a865f4876b749d17c94f4a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/overlay.js.xml": {
    "bytes": 919,
    "gid": 0,
    "mode": 420,
    "sha256": "17d8621c77e51a7aa94ede49cdeed85a1104de57d013bb33b168b8f76eeca90b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/overlay.logo.xml": {
    "bytes": 949,
    "gid": 0,
    "mode": 420,
    "sha256": "296d6cb555004862a251d377a7a53ac3bbce3fa00b32d2c7e1b9233a44d62a17",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/overlay.xml": {
    "bytes": 1085,
    "gid": 0,
    "mode": 420,
    "sha256": "a8c7d9437b549058305a0ee014659aff8b90cdc33523fa78a4d87de32f425a81",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/page.height.portrait.xml": {
    "bytes": 3341,
    "gid": 0,
    "mode": 420,
    "sha256": "060c85ead7365a880d5ac530c01a5c7a7316548aaaa309dc69e05abb149428b3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/page.height.xml": {
    "bytes": 1186,
    "gid": 0,
    "mode": 420,
    "sha256": "018f5cd6e22d474585a5ebc1022d97a1070aa5096a3c193f5261b3182e4b2477",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/page.margin.bottom.xml": {
    "bytes": 951,
    "gid": 0,
    "mode": 420,
    "sha256": "e051f3c7e701a8d509601f5f3d5d229d10201b117cbb2d79585dc3cc349b4ce3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/page.margin.inner.xml": {
    "bytes": 1993,
    "gid": 0,
    "mode": 420,
    "sha256": "aa4fee6f2eb23d6184806c525198544486f2521d0c100346c86d01bbd47436e5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/page.margin.outer.xml": {
    "bytes": 1886,
    "gid": 0,
    "mode": 420,
    "sha256": "4d1992529a7355d629219991b857df08605f5280242b3dcc8238d18018b2404a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/page.margin.top.xml": {
    "bytes": 924,
    "gid": 0,
    "mode": 420,
    "sha256": "a237c7fff741c26131a72cfe04ac0e9c4c4cd06b95ef4ae8c132044e2605c878",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/page.orientation.xml": {
    "bytes": 1105,
    "gid": 0,
    "mode": 420,
    "sha256": "716461ea73d78d3e4cf6fe49348365f5a2846a6995232c498697f9b11ecb8791",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/page.width.portrait.xml": {
    "bytes": 3266,
    "gid": 0,
    "mode": 420,
    "sha256": "a635ecbf95cec7aa23f297b912fa749584b53b23301110e2aa36553131b3f1e2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/page.width.xml": {
    "bytes": 1179,
    "gid": 0,
    "mode": 420,
    "sha256": "a5d7e99658f9ee81da1a1c6386c1a9df1a2b5a73fa0eac3490e4b2d07a38857f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/pages.template.xml": {
    "bytes": 1399,
    "gid": 0,
    "mode": 420,
    "sha256": "2bff9142eaed581ddff7dbb9e2944660b81de2b1bf745dc4d64cb260b2510737",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/paper.type.xml": {
    "bytes": 4403,
    "gid": 0,
    "mode": 420,
    "sha256": "54fe08fefca20e6c226a99f5d22bf07680bb8e1d3ab04cb000d4602208896735",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/para.propagates.style.xml": {
    "bytes": 1023,
    "gid": 0,
    "mode": 420,
    "sha256": "b53658987e50a0badab2386ffc9c20542372e1f3d5e26fe0672e118d9a8141bb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/para.properties.xml": {
    "bytes": 1339,
    "gid": 0,
    "mode": 420,
    "sha256": "5a5d81a1696ddde04cd4cc19bbb85f441ded16c458e9814626d47c8959e83c47",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/part.autolabel.xml": {
    "bytes": 2393,
    "gid": 0,
    "mode": 420,
    "sha256": "e30215e765414eeefb852fd37a4fded8b68c38a674a42eacf1bf034538c9085b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/passivetex.extensions.xml": {
    "bytes": 1129,
    "gid": 0,
    "mode": 420,
    "sha256": "966619cb4b13613563f1f5806e85a5002a7327128c6be7060ceb6bc9ad38f778",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/pgwide.properties.xml": {
    "bytes": 1760,
    "gid": 0,
    "mode": 420,
    "sha256": "0f5679b86de4a7e91217f6f06ea21062028dd9f8928e8d7d07b05e3c5cab960d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/phrase.propagates.style.xml": {
    "bytes": 1066,
    "gid": 0,
    "mode": 420,
    "sha256": "d32842470f6edf83c09fd781645ad3e56bd03415e9f65989c80ee22ed5ee347e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/pixels.per.inch.xml": {
    "bytes": 1047,
    "gid": 0,
    "mode": 420,
    "sha256": "30d7b2abb02ebbfce97124dcdbfef0da8b6031cc87cbe41f2d0c9bbafe5a6a70",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/plus.image.xml": {
    "bytes": 959,
    "gid": 0,
    "mode": 420,
    "sha256": "2c3d335ae99d16abd53ad6e9b190c2f4624ceda1c757c3d27e6bc3611a99b432",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/poetry.properties.xml": {
    "bytes": 1131,
    "gid": 0,
    "mode": 420,
    "sha256": "a7e659df6b1388f489b3b2584806a646cbee0096c22f0922831b6e8d40de3c0e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/points.per.em.xml": {
    "bytes": 993,
    "gid": 0,
    "mode": 420,
    "sha256": "a6d3d554e9bd9cc01e2ffa5ac0c60c2d9b484ac394f48706e9bf2c1a7bd50fab",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/preface.autolabel.xml": {
    "bytes": 2407,
    "gid": 0,
    "mode": 420,
    "sha256": "af9bfbab843e2cc2859a297a17a4f0003c9648719ec57dffc4861006e1c29da0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/prefer.internal.olink.xml": {
    "bytes": 2968,
    "gid": 0,
    "mode": 420,
    "sha256": "51bf0366133fb96b5c25d99860ad6480d0fde73de652caa27563bd983ea53af6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/preferred.mediaobject.role.xml": {
    "bytes": 1603,
    "gid": 0,
    "mode": 420,
    "sha256": "cee9698a00d2a3002a764794fb96351f49bd04b06271f992315e3b588d38e9bc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/prev.image.xml": {
    "bytes": 864,
    "gid": 0,
    "mode": 420,
    "sha256": "a6293da39f996a57e7e6bbcd7073fa36430ccf8bc92c7610ef5e9919c0f27e8b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/procedure.properties.xml": {
    "bytes": 1024,
    "gid": 0,
    "mode": 420,
    "sha256": "42e3014e412d3235e0d00cb705622f20c5345f1c23b5be124e6027b531244183",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/process.empty.source.toc.xml": {
    "bytes": 1566,
    "gid": 0,
    "mode": 420,
    "sha256": "334c1547242353cf3988697f3bf3aa610e72b063ba8be7b92c3b5910124fac49",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/process.source.toc.xml": {
    "bytes": 1546,
    "gid": 0,
    "mode": 420,
    "sha256": "6a759558d117a269a4c07271ad14a44cad6c49691dde01ce93c9a8f619246c69",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.arch.xml": {
    "bytes": 1352,
    "gid": 0,
    "mode": 420,
    "sha256": "e83c0e428dffd6785b80bef0ae5ff1c603cc54d34414950e6ac3b4c64a0cf3bf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.attribute.xml": {
    "bytes": 1192,
    "gid": 0,
    "mode": 420,
    "sha256": "1f129e8913550399872c508fa39e844715148704cb1f2b16966e944970fd5f2b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.audience.xml": {
    "bytes": 1371,
    "gid": 0,
    "mode": 420,
    "sha256": "b9d3ebfea3267040f0a03953ac6e58d669499f0e868ebd86fd58c75813331083",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.condition.xml": {
    "bytes": 1381,
    "gid": 0,
    "mode": 420,
    "sha256": "5bd7d3a61d9107c4a7051c9a9a74915c1fb918c88f52e349e65a6b58d7807214",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.conformance.xml": {
    "bytes": 1393,
    "gid": 0,
    "mode": 420,
    "sha256": "4241fb6922d683c9d8dbcaa65cbcf81f61bef560fd97aa25802a9898c441ed96",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.lang.xml": {
    "bytes": 1351,
    "gid": 0,
    "mode": 420,
    "sha256": "dc697949f72a04878cb1975864b4167efc69f2989f158548f52351f276db63f4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.os.xml": {
    "bytes": 1339,
    "gid": 0,
    "mode": 420,
    "sha256": "ad63ea6f92a36f647c6a157c8c2b3910ebd419898976007f59b8ae34a70a6c38",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.outputformat.xml": {
    "bytes": 1418,
    "gid": 0,
    "mode": 420,
    "sha256": "a9335b12fc42ded02521125a3706253f4224ca76de2d01045f99c77a3449bd32",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.revision.xml": {
    "bytes": 1376,
    "gid": 0,
    "mode": 420,
    "sha256": "bdb8bc837a2c6519a8f1529b0b1290ad305ad56604a804396db64abd63143449",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.revisionflag.xml": {
    "bytes": 1399,
    "gid": 0,
    "mode": 420,
    "sha256": "983d8546ef7aa775c375e26a131937b9e86578a3eef38d519113c1a9c4e755dc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.role.xml": {
    "bytes": 2225,
    "gid": 0,
    "mode": 420,
    "sha256": "b4cf9006e1a679c9cbfbdab09ed80c60f232fbc52f93df99362fd32727ef755a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.security.xml": {
    "bytes": 1375,
    "gid": 0,
    "mode": 420,
    "sha256": "c6891fe9dc163dd0718c5b017c747ed04488e626189386cc043ff08f4e076522",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.separator.xml": {
    "bytes": 942,
    "gid": 0,
    "mode": 420,
    "sha256": "f478643020f021ef9421df9737a14d25d637f05a5f3e3d70de23dc1ecd1604f4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.status.xml": {
    "bytes": 1363,
    "gid": 0,
    "mode": 420,
    "sha256": "a9955992374ea920a89a5f290f74211dac884386365530902312933d32341a01",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.userlevel.xml": {
    "bytes": 1381,
    "gid": 0,
    "mode": 420,
    "sha256": "ad28d67f1d5df7a2b597ab0e833b0014a48f21bc4b7a4070aa6c86077ccd26f7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.value.xml": {
    "bytes": 1492,
    "gid": 0,
    "mode": 420,
    "sha256": "199d7a414f0b02237890bae6cb6f89c4d636382d6bea61bb4ffd3d4e6fa1b646",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.vendor.xml": {
    "bytes": 1363,
    "gid": 0,
    "mode": 420,
    "sha256": "9b64fa9d7aa9fc7324202ef5fabdf18cd5f17180bd36b34901aa3120fc4eb31d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/profile.wordsize.xml": {
    "bytes": 1375,
    "gid": 0,
    "mode": 420,
    "sha256": "6f60c0556eb7f0f466032bcec39ba3de13082af0c22b76f51b8cf6cdf49333dc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/publishers.properties.xml": {
    "bytes": 1366,
    "gid": 0,
    "mode": 420,
    "sha256": "da3a444993969621d53188d43faf9627dc4fbd6553e522b620d28374c276875d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/punct.honorific.xml": {
    "bytes": 942,
    "gid": 0,
    "mode": 420,
    "sha256": "e120a48be89dfcab296865873a42313e8b82ea6bed89843db55cb9cd7b28e6b1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/qanda.defaultlabel.xml": {
    "bytes": 2922,
    "gid": 0,
    "mode": 420,
    "sha256": "663abcf606d61c9efb45926c59fc3f5a9492f6d93b7ba0b3835988e138264dfd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/qanda.in.toc.xml": {
    "bytes": 1196,
    "gid": 0,
    "mode": 420,
    "sha256": "d5165df24680bed8ccbbf345f4119ca92c17a0212ffee3a81aa8d26516eb6e95",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/qanda.inherit.numeration.xml": {
    "bytes": 1085,
    "gid": 0,
    "mode": 420,
    "sha256": "8795855973c9f5f7da22ff0335e7c4af1c26da11cdf13031d97d123a7568cbb0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/qanda.nested.in.toc.xml": {
    "bytes": 985,
    "gid": 0,
    "mode": 420,
    "sha256": "f033eb4bfedfaddecef88246bb8b7df5d296e2f4c5f0395c2901000d2483b83b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/qanda.title.level1.properties.xml": {
    "bytes": 1105,
    "gid": 0,
    "mode": 420,
    "sha256": "b244a1c96f6eeeda7b9da30e2d19021e95d0acea78d082e1923d15acebe33968",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/qanda.title.level2.properties.xml": {
    "bytes": 1104,
    "gid": 0,
    "mode": 420,
    "sha256": "8f79032a7554d1042b03749dc6cf949b1a5d5ee6794bb9131e0bd345faf42e2f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/qanda.title.level3.properties.xml": {
    "bytes": 1103,
    "gid": 0,
    "mode": 420,
    "sha256": "eae13222d4ec9dee48885b2d5f317fcb035eb1b7bc4657e8accd1b6c311f7287",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/qanda.title.level4.properties.xml": {
    "bytes": 1102,
    "gid": 0,
    "mode": 420,
    "sha256": "826f91ff7fe043f6a989ca965d36e9f78ebad86acd50c17b0ccd519bcdc13e62",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/qanda.title.level5.properties.xml": {
    "bytes": 1096,
    "gid": 0,
    "mode": 420,
    "sha256": "cb17ac4bf7e6a6086797181d37bcad939377cae6d4a1be5d1a77ce6e5f0c4fc4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/qanda.title.level6.properties.xml": {
    "bytes": 1161,
    "gid": 0,
    "mode": 420,
    "sha256": "6806262d611738e48abfdfb7cb55da191a4afaef8f90ab10a9e78ee39c789773",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/qanda.title.properties.xml": {
    "bytes": 1434,
    "gid": 0,
    "mode": 420,
    "sha256": "4a9bb61e18c94a0ce32278ca1364365053356fb080ea5c023e84b26ab92c6de3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/qandadiv.autolabel.xml": {
    "bytes": 896,
    "gid": 0,
    "mode": 420,
    "sha256": "19d8ed7bf2bd1e370bd371ce50185cab24bb0ec64967f0b2d4b6a41eb4a7aad5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/rebuild-all.xml": {
    "bytes": 1320,
    "gid": 0,
    "mode": 420,
    "sha256": "b32444df5bc6eab6675da4abaead2823e79b7cd557f5352806441e7268277ddb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refclass.suppress.xml": {
    "bytes": 978,
    "gid": 0,
    "mode": 420,
    "sha256": "6e279b8c8c9a80dfd71819fe16b19daf954ceec59c70cf296282cc242ba4d0f9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.date.profile.enabled.xml": {
    "bytes": 1917,
    "gid": 0,
    "mode": 420,
    "sha256": "bbb3b19668d9a9c7299de751de026c39294a59a4df8253ddc10e125425a4ff70",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.date.profile.xml": {
    "bytes": 1453,
    "gid": 0,
    "mode": 420,
    "sha256": "de83b85efe1d17f9830511f6c885e23d42bd348c644acfdce62d156d03b0c3ea",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.generate.name.xml": {
    "bytes": 1219,
    "gid": 0,
    "mode": 420,
    "sha256": "169612731b1e8ec5d2ec3cc549d9fddef45af18b2c1f89a3b23ed08f23012ba0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.generate.title.xml": {
    "bytes": 1232,
    "gid": 0,
    "mode": 420,
    "sha256": "05685a45bc550a82a6512be55bb34d43cb2dbb4ab66cc5a7511b6821297ae3c5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.manual.fallback.profile.xml": {
    "bytes": 2003,
    "gid": 0,
    "mode": 420,
    "sha256": "fc62cddd7fd0dc3612a1205a21b263c1a8e881a83c60c9afd74ababe7e99c36d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.manual.profile.enabled.xml": {
    "bytes": 1934,
    "gid": 0,
    "mode": 420,
    "sha256": "f5c49cef0232ab04e00d9cddbf41239530520723d4b56a468a6ecb54c9445baf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.manual.profile.xml": {
    "bytes": 2430,
    "gid": 0,
    "mode": 420,
    "sha256": "61948e01c912bf8359b6ebaa0508e9e66bd8fd363c79c24e9ba58958d0efe0ad",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.meta.get.quietly.xml": {
    "bytes": 1366,
    "gid": 0,
    "mode": 420,
    "sha256": "9d75936552b1063766c8629f9fb92097820cd986937318c69fcf32b9815d5079",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.pagebreak.xml": {
    "bytes": 1313,
    "gid": 0,
    "mode": 420,
    "sha256": "b77982b23ccadd626d8e203ecefd7640caa1f24cefbad97440882f2285540163",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.separator.xml": {
    "bytes": 942,
    "gid": 0,
    "mode": 420,
    "sha256": "efd53017d472ec0550417fbba9f2b714d1a8e8c53da0e842d5b0f9ce000d2f45",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.source.fallback.profile.xml": {
    "bytes": 2079,
    "gid": 0,
    "mode": 420,
    "sha256": "6e108bd47c29cd370c870f0f45090e47056a75a09f576e5347902462b55ca4b2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.source.name.profile.enabled.xml": {
    "bytes": 2022,
    "gid": 0,
    "mode": 420,
    "sha256": "40d05b5209a17ffb3aba2e2dd13c3342b44b7a1b5c5c2562309a716040594c14",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.source.name.profile.xml": {
    "bytes": 3458,
    "gid": 0,
    "mode": 420,
    "sha256": "c7d4c7c6f7a95a6bc06327327e7594a0ec0e38aca49c8ca23de4372d8e598861",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.source.name.suppress.xml": {
    "bytes": 1804,
    "gid": 0,
    "mode": 420,
    "sha256": "79af6d4cc6861254c96a2d0b3723becf813e1f6c4d2e9de9333d4df38b11b6da",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.title.properties.xml": {
    "bytes": 2626,
    "gid": 0,
    "mode": 420,
    "sha256": "700444c2a07665514c9d455449ea492aee05196bf25618ab4f7e59d5f6446a6c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.version.profile.enabled.xml": {
    "bytes": 1962,
    "gid": 0,
    "mode": 420,
    "sha256": "7b35af7fc4116d8e1d5d0aafdf7241febe5aaeadac05fc6abc3169f17eb2d4c1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.version.profile.xml": {
    "bytes": 1618,
    "gid": 0,
    "mode": 420,
    "sha256": "2f61fa2163c53e8e5aef305fd25fb4d464671c78d89aa060b0c5d6994f485bc9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.version.suppress.xml": {
    "bytes": 1779,
    "gid": 0,
    "mode": 420,
    "sha256": "bcdab526cc116b072f92420fe3c1d66d5eba16ff0510e95fde29ca4dd1bcc577",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/refentry.xref.manvolnum.xml": {
    "bytes": 1055,
    "gid": 0,
    "mode": 420,
    "sha256": "f1941eaae65e7b135e2884bbdcf24af8bef6cb0e8bd02f57f3de3bb21d4f9e20",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/reference.autolabel.xml": {
    "bytes": 2423,
    "gid": 0,
    "mode": 420,
    "sha256": "5e981d211cee173a894440811079836154f3640acb8ed442bb2e89e6c55896a0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/region.after.extent.xml": {
    "bytes": 928,
    "gid": 0,
    "mode": 420,
    "sha256": "65e0f473e7b118d92a436db8c66123e19dbfd77f52d908778764f36bff692a4a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/region.before.extent.xml": {
    "bytes": 933,
    "gid": 0,
    "mode": 420,
    "sha256": "0450514598b5bf36b034dac82d682b1b659797878f6ab01592dd5c99ad99cff1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/region.inner.extent.xml": {
    "bytes": 1849,
    "gid": 0,
    "mode": 420,
    "sha256": "70d093d0e8fc6d0e126f8927335e6cd35f0b31f8ebfd089ef8c69c06fca31f6b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/region.inner.properties.xml": {
    "bytes": 1910,
    "gid": 0,
    "mode": 420,
    "sha256": "0debe1ffac888ba8fb00c68a507bb470f03abef20f92f56f9047ec1424610647",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/region.outer.extent.xml": {
    "bytes": 1859,
    "gid": 0,
    "mode": 420,
    "sha256": "98a0b6f28b37d656beb170916b0353fea50b4b1688034e0466116baa7fb84caa",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/region.outer.properties.xml": {
    "bytes": 1923,
    "gid": 0,
    "mode": 420,
    "sha256": "cb1fe83438f55a5a199fbd20d1ec8786263327b6d889f725f7ba674b8cfdd808",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/revhistory.table.cell.properties.xml": {
    "bytes": 1037,
    "gid": 0,
    "mode": 420,
    "sha256": "f999fb1857eea3d4a6ffc9e070753afe4626661da52828ca9d5b38cec8f834b9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/revhistory.table.properties.xml": {
    "bytes": 986,
    "gid": 0,
    "mode": 420,
    "sha256": "26198bf04b5eec7f7016b7736370f93ce9b9a001424d303c52629ff774ca76b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/revhistory.title.properties.xml": {
    "bytes": 966,
    "gid": 0,
    "mode": 420,
    "sha256": "1b8834dd553520822fb6449b095f983a6b7b58c60cef64a74629126dedcc43b1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/root.filename.xml": {
    "bytes": 963,
    "gid": 0,
    "mode": 420,
    "sha256": "80ab242d60df263f914a4c25c5e86daa58798750d7077fba12cf7e0effa85b9b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/root.properties.xml": {
    "bytes": 1640,
    "gid": 0,
    "mode": 420,
    "sha256": "8f630944991fa6f5ef473fb922bf8478f454da639a339aca464aec744953ec2f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/rootid.xml": {
    "bytes": 1272,
    "gid": 0,
    "mode": 420,
    "sha256": "f8ddc11c1b53dbb09dbb0ada2f128ed157f685f03f4d32bed60a5bce915bb2e9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/runinhead.default.title.end.punct.xml": {
    "bytes": 1081,
    "gid": 0,
    "mode": 420,
    "sha256": "eb94e31587cb77f42a871b99bb716786b4ed4d50d9a0156b89cdedec7a6125a3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/runinhead.title.end.punct.xml": {
    "bytes": 1197,
    "gid": 0,
    "mode": 420,
    "sha256": "8ac1bf818c2d445bc2f61fb242f1ccab311d92fdebc7d4044924608e9e2bdf35",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/running.foot.properties.xml": {
    "bytes": 1243,
    "gid": 0,
    "mode": 420,
    "sha256": "1adbc234db2f8538b75ea056ce596c830fa54f329b3756526e777839b89464ef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/s5.controls.xml": {
    "bytes": 903,
    "gid": 0,
    "mode": 420,
    "sha256": "5fcccad1e7b1e8c2bcc0f1e3bb50b0231cbcd704fa7727fc8f8a9544ad8828d9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/s5.defaultview.xml": {
    "bytes": 1055,
    "gid": 0,
    "mode": 420,
    "sha256": "d4d55aa2028fe80ed63dde49032ed58dfe0c6c663c989c458f94f8893d6b0bfb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/s5.opera.css.xml": {
    "bytes": 917,
    "gid": 0,
    "mode": 420,
    "sha256": "154f679792dc16e6fcb5bf119446ddd597081edd8c2c4dff54a5feb7f3d83a4a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/s5.outline.css.xml": {
    "bytes": 913,
    "gid": 0,
    "mode": 420,
    "sha256": "01d837270b01a8675f49c06d01e0179c4576f0724f035eb6e62fa9fdbe786b14",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/s5.path.prefix.xml": {
    "bytes": 999,
    "gid": 0,
    "mode": 420,
    "sha256": "c7ef83e4d918ca42cdeaccbc698d3b1c32f9f7ac085d3c21cf20727e911e35ca",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/s5.print.css.xml": {
    "bytes": 897,
    "gid": 0,
    "mode": 420,
    "sha256": "4d5a17b8534f6da3f6366f85ed63bbc35b27611c8f5d145b7ffdae7b13382e9e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/s5.slides.css.xml": {
    "bytes": 905,
    "gid": 0,
    "mode": 420,
    "sha256": "0dcec14e563628329810f30c3d5a5e59a8a6cf5f0f868947c4b594dcc4a7cfa9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/s5.slides.js.xml": {
    "bytes": 915,
    "gid": 0,
    "mode": 420,
    "sha256": "be4b1f1ef01d8b3852aff55f9a51da540f6e8cdd8b6724303ec806981f1a40b3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/sans.font.family.xml": {
    "bytes": 938,
    "gid": 0,
    "mode": 420,
    "sha256": "909aff0911b96622e8e4755313edbd205a8c1ed3165547e681aef8a82c7fb191",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/saxon.callouts.xml": {
    "bytes": 946,
    "gid": 0,
    "mode": 420,
    "sha256": "ecdadf3808400f4acd20bd11272356619a5e089ee2aedc761e9a5bfc111185d5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/saxon.character.representation.xml": {
    "bytes": 1606,
    "gid": 0,
    "mode": 420,
    "sha256": "92d9bc942ffd361dc7d8f29129897f6382f45017e1bbb2337dd7e919fb666cfc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/saxon.linenumbering.xml": {
    "bytes": 1113,
    "gid": 0,
    "mode": 420,
    "sha256": "3a61ea86de97d173af45483269bb711812adc74b01b7a0547257c8fe86e66a7d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/saxon.tablecolumns.xml": {
    "bytes": 1007,
    "gid": 0,
    "mode": 420,
    "sha256": "4e8d822b89bdea60ecc23ceffbc4afa89b0d4b75a74037e8a2a3d16584e60a3f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/script.dir.xml": {
    "bytes": 1046,
    "gid": 0,
    "mode": 420,
    "sha256": "0ee59d35fb45815a474171062cb003acb32f74e66477b91f94b336077aa0b27c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.autolabel.max.depth.xml": {
    "bytes": 1156,
    "gid": 0,
    "mode": 420,
    "sha256": "0dc307f83849283ce4db457d401ef7fd5f152409979c7e3ea6a630f94fa284d0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.autolabel.xml": {
    "bytes": 883,
    "gid": 0,
    "mode": 420,
    "sha256": "7be04bf6341c7a4f71036585e950eef371a3fa670db56b80eb9eff4a121b7f8c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.container.element.xml": {
    "bytes": 2337,
    "gid": 0,
    "mode": 420,
    "sha256": "41ca25552bc0821d7facf43a48d30a3df5fd25a69ce923f6c7acebf71c4d59f5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.label.includes.component.label.xml": {
    "bytes": 1044,
    "gid": 0,
    "mode": 420,
    "sha256": "20d38975a288144d3a108a10cfdf8b15aaf497b2db887fb0d44c5cd6a5fce405",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.level1.properties.xml": {
    "bytes": 1529,
    "gid": 0,
    "mode": 420,
    "sha256": "ac04ebbcf36cadb95202bb21911e5c519b54ccfd731cc063908e518539984b15",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.level2.properties.xml": {
    "bytes": 1529,
    "gid": 0,
    "mode": 420,
    "sha256": "b38cbbc83571a53f892aee13edc6da2c2379252640e203ad0098f2219fad103c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.level3.properties.xml": {
    "bytes": 1529,
    "gid": 0,
    "mode": 420,
    "sha256": "abdb86d27a7a847a60baf3aafe0d540b0817bfe604ba56c9b26e22b565220e3e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.level4.properties.xml": {
    "bytes": 1529,
    "gid": 0,
    "mode": 420,
    "sha256": "c78a42d20a397857e97d7b91f6b53b83b688c9d76101e5f84cd455df460c2868",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.level5.properties.xml": {
    "bytes": 1529,
    "gid": 0,
    "mode": 420,
    "sha256": "cf82dc366666688a65e93f05379f7e48620f71537eae0d963ae8c04f835d47ee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.level6.properties.xml": {
    "bytes": 1519,
    "gid": 0,
    "mode": 420,
    "sha256": "16bfdd2e915eee1125dc204e9e8372d57e34a597e96cd5991874bae08d08adf9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.properties.xml": {
    "bytes": 1116,
    "gid": 0,
    "mode": 420,
    "sha256": "183ea02f1681fece4750dab07efe113a92276475ede4bcba348a5eb8868f6c75",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.title.level1.properties.xml": {
    "bytes": 1111,
    "gid": 0,
    "mode": 420,
    "sha256": "1b348f642e12843441363c3b7399260c6619b4798e09db2807cf7d9c823e53af",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.title.level2.properties.xml": {
    "bytes": 1111,
    "gid": 0,
    "mode": 420,
    "sha256": "574205d6486514306bbc9effb9a8568bacded42233813142ac1cb13adeef6dac",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.title.level3.properties.xml": {
    "bytes": 1109,
    "gid": 0,
    "mode": 420,
    "sha256": "0413129d0e8568bdd27fe87cf1d31b9ef4f2f1550e976375a6c05e0302dd62e7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.title.level4.properties.xml": {
    "bytes": 1108,
    "gid": 0,
    "mode": 420,
    "sha256": "7e10ccdd638376dafb0dfc7c4320b3753954befa03a5a376b6b856bd212a31e5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.title.level5.properties.xml": {
    "bytes": 1102,
    "gid": 0,
    "mode": 420,
    "sha256": "c4515dee47128ba1e799ad2c878ef35146d2f102c79e82139036d55180e3ce2a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.title.level6.properties.xml": {
    "bytes": 1167,
    "gid": 0,
    "mode": 420,
    "sha256": "16a46bd9e6893430e4b4e2a53a3670e0b78d30d37e20749b80b2dee273cf7e7d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/section.title.properties.xml": {
    "bytes": 1596,
    "gid": 0,
    "mode": 420,
    "sha256": "196dec7b8b58e06aeb77c0d29aafa549753ae98e00c5119b5b17cc47e9817a1b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/segmentedlist.as.table.xml": {
    "bytes": 927,
    "gid": 0,
    "mode": 420,
    "sha256": "21f2d19319e991c846b846a0a4c4012dc150d779201171def745131789733e6f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/sequential.links.xml": {
    "bytes": 824,
    "gid": 0,
    "mode": 420,
    "sha256": "64016fb66288223e5536390673125cdbbb4548dc8ae933925737318e3217b081",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/shade.verbatim.style.xml": {
    "bytes": 1492,
    "gid": 0,
    "mode": 420,
    "sha256": "faeb9aa184a57fe8ef3d01fe2dd1c84639a4f3112002217af9653da00e78aa7b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/shade.verbatim.xml": {
    "bytes": 1068,
    "gid": 0,
    "mode": 420,
    "sha256": "3fcb7d5bdb012d95b868db32dcb5a9aad1e7b88037b8b0249309bc1d6c95be19",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/show.bookmarks.xml": {
    "bytes": 991,
    "gid": 0,
    "mode": 420,
    "sha256": "0b356dc3add2057542d74f4b1e89ae84f38a93fc8f906d131f1aaf9c64ffcb19",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/show.comments.xml": {
    "bytes": 1078,
    "gid": 0,
    "mode": 420,
    "sha256": "a8e1e3b74d06476a0ac35c67b576944ce90da6364ac78523b0b6a7f03b77e976",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/show.foil.number.xml": {
    "bytes": 926,
    "gid": 0,
    "mode": 420,
    "sha256": "8d589adca9b57f340ed0065c744f96f0c96a999e9ad2c70f7d3657b5d4f24063",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/show.revisionflag.xml": {
    "bytes": 1748,
    "gid": 0,
    "mode": 420,
    "sha256": "56fa7982c0a8d8a6afdc8e21adc9ce07cd4df6500d1a9f2b16a24b0506fdcd03",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/showtoc.image.xml": {
    "bytes": 963,
    "gid": 0,
    "mode": 420,
    "sha256": "ca6366ac7dd4dfd95a351e197b259c9644eb0f6c1035ffef08c33123477395c1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/side.float.properties.xml": {
    "bytes": 2008,
    "gid": 0,
    "mode": 420,
    "sha256": "7798a7d874ef614b192506d1fef68f0c8b908fe9977ad45e27b5ab57b9e838c8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/side.region.precedence.xml": {
    "bytes": 2291,
    "gid": 0,
    "mode": 420,
    "sha256": "7181b092be57ae0229850550c3b37bcd296aa4f24bedda70599a64719fb133d6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/sidebar.float.type.xml": {
    "bytes": 2984,
    "gid": 0,
    "mode": 420,
    "sha256": "e5cade98ad26b4424037ba31768e3cbbe04a1d6718cb64c925cd2b0fc860b9c3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/sidebar.float.width.xml": {
    "bytes": 1179,
    "gid": 0,
    "mode": 420,
    "sha256": "eb9e4797232f9ba33467cececd4953cd754dc3625dc48e800a23f7bbdd14691c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/sidebar.properties.xml": {
    "bytes": 1680,
    "gid": 0,
    "mode": 420,
    "sha256": "29083197e5c971bc6286766b76c575b0270a30d4031682050e80e887bed7061a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/sidebar.title.properties.xml": {
    "bytes": 1170,
    "gid": 0,
    "mode": 420,
    "sha256": "fe73823a3681b3cc9b2ac998f57a8a594f253a2f8e7ba042a288393c1fb6d66b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/simplesect.in.toc.xml": {
    "bytes": 921,
    "gid": 0,
    "mode": 420,
    "sha256": "6130fc93ca0da6c9d64b01f01451f6c8cb151edd07594392fc8599a6af44ccd5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slide.font.family.xml": {
    "bytes": 1181,
    "gid": 0,
    "mode": 420,
    "sha256": "c605f03bc8e40dff2b58c276e1aac492330190911256c7d36c247b711a80da33",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slide.title.font.family.xml": {
    "bytes": 1210,
    "gid": 0,
    "mode": 420,
    "sha256": "2bb558a8701b10c0c4c957323448ee83e2235908d78e2fdd7a57c22008f6d98f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slides.js.xml": {
    "bytes": 909,
    "gid": 0,
    "mode": 420,
    "sha256": "9fa47376c44773778bd680b93f77bfdd1095701185bd2603741c517188acf07e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slides.properties.xml": {
    "bytes": 1055,
    "gid": 0,
    "mode": 420,
    "sha256": "f8aed9ff513eaeb5f77f0f9d0ea164f0053506ebe6759a0eeeccbb1b3f41094a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slides.titlepage.author.properties.xml": {
    "bytes": 1232,
    "gid": 0,
    "mode": 420,
    "sha256": "a99e9538fe78e3113afa3909a1bf55a424ba326d74bc701bcfa1c41e9c8a91db",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slides.titlepage.authorgroup.properties.xml": {
    "bytes": 1053,
    "gid": 0,
    "mode": 420,
    "sha256": "49cfbf0beb22187847939d3393a43cf94caa4ddaa86efadcdd14cb2c8304ef55",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slides.titlepage.corpauthor.properties.xml": {
    "bytes": 1256,
    "gid": 0,
    "mode": 420,
    "sha256": "01c672db95b1e8720b141b28f4f8e9dcb86899d04b466775c1ab7df653c1d7c6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slides.titlepage.master.properties.xml": {
    "bytes": 1721,
    "gid": 0,
    "mode": 420,
    "sha256": "700ce9489214dfc3f04a2cae7f6e189afb424361d70324bd8620357a7ba1581b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slides.titlepage.pubdate.properties.xml": {
    "bytes": 1237,
    "gid": 0,
    "mode": 420,
    "sha256": "b113d909b7ad42b723dc6f59f529546cdc2d4071f320bfef4e58a68b94bb2274",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slides.titlepage.region-body.properties.xml": {
    "bytes": 1311,
    "gid": 0,
    "mode": 420,
    "sha256": "c7c8e03d5e123fb584eb024b1d3ed07a4c6fe73db48f1d32eade87977d221890",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slides.titlepage.subtitle.properties.xml": {
    "bytes": 1296,
    "gid": 0,
    "mode": 420,
    "sha256": "50720d782fa804de6c4b474f2a241f011b161b583a2068746717a2070cd00514",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slides.titlepage.title.properties.xml": {
    "bytes": 1572,
    "gid": 0,
    "mode": 420,
    "sha256": "36c1d1aee2979bc6f894adaf8bc608f77ff302bf6123ff38c01ffdca198afc02",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slidy.duration.xml": {
    "bytes": 1023,
    "gid": 0,
    "mode": 420,
    "sha256": "c331755519af8e5e2791c56890f2fa6895e80f2c23fe87130d4e4e1c0f346dd4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slidy.path.prefix.xml": {
    "bytes": 1012,
    "gid": 0,
    "mode": 420,
    "sha256": "1a587f8f7d574ab4663e9bb1f9840d6614f92a97ad0feb3b92cf43673b022b9d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slidy.slidy.css.xml": {
    "bytes": 923,
    "gid": 0,
    "mode": 420,
    "sha256": "c05c28488aed5a0120133ffc9a29b4850d75b3b96ea1f111561ba5a5d7cc0ec4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slidy.slidy.js.xml": {
    "bytes": 922,
    "gid": 0,
    "mode": 420,
    "sha256": "0a1cabd8f5d80059df602ddf20c5ebe6f2a2ee9e877459878807cd686bd3e2ea",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/slidy.user.css.xml": {
    "bytes": 921,
    "gid": 0,
    "mode": 420,
    "sha256": "75340ebfbd0590ee624e3e84fdae357d10c16cf46f7c32c3535da6fa58886fee",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/spacing.paras.xml": {
    "bytes": 1010,
    "gid": 0,
    "mode": 420,
    "sha256": "c9a0147cb59c3721e33b6dbbbe4441990aa3dba57038ff00027d69889b86612a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/speaker.properties.xml": {
    "bytes": 1026,
    "gid": 0,
    "mode": 420,
    "sha256": "6319879036cb662c8b6cb1e3391caa877dc6d42a6deee36e81d91bc79e1080d0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/speakernote.properties.xml": {
    "bytes": 1228,
    "gid": 0,
    "mode": 420,
    "sha256": "ef8df15b6ef136a2a4a315b13298775f4f7a98c4d02a5a5f3b3562dd5844c049",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/speakernotes.properties.xml": {
    "bytes": 914,
    "gid": 0,
    "mode": 420,
    "sha256": "6729747a18efe20c02eb8203b175b13b95af1ae62da880aa571b2105a3c52d68",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/stagedir.properties.xml": {
    "bytes": 1292,
    "gid": 0,
    "mode": 420,
    "sha256": "5037c53a27a693ec4a013eda36c00b52d09ba72ef7a272baa627a19ba4e5c7bc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/subscript.properties.xml": {
    "bytes": 975,
    "gid": 0,
    "mode": 420,
    "sha256": "9328322068c5d001fd3f6b46575e0d89809a42c57c28cf7ab800520e52907076",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/superscript.properties.xml": {
    "bytes": 989,
    "gid": 0,
    "mode": 420,
    "sha256": "0406c85d0bbdd9db5c1a65bd17f24bb51c452e1d47c4c02086265a42c5e9be8a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/suppress.footer.navigation.xml": {
    "bytes": 922,
    "gid": 0,
    "mode": 420,
    "sha256": "eb3f10bc7d98ba65909c1d2dfccacfa37c5be88fcf7eaee168ae217586a50143",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/suppress.header.navigation.xml": {
    "bytes": 922,
    "gid": 0,
    "mode": 420,
    "sha256": "7f5f67d74e1e11bf26383824be1198222aa46fe80862712803d85fe90eb7e0bf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/suppress.homepage.title.xml": {
    "bytes": 916,
    "gid": 0,
    "mode": 420,
    "sha256": "11debb4874643ce1263bf9467be40abac0fb0c4a8473f50e52de858826e69d82",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/suppress.navigation.xml": {
    "bytes": 910,
    "gid": 0,
    "mode": 420,
    "sha256": "0d2783fcbc03b2c07a0b31493fc46a16ba516a6c9ef8b5b03a3446596a7e2fa1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/svg.embedding.mode.fo.xml": {
    "bytes": 1786,
    "gid": 0,
    "mode": 420,
    "sha256": "aba56b5b9b7bf401adcd26512790f220d49a4c221ece6f813daf925a2959fa43",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/svg.embedding.mode.xml": {
    "bytes": 2590,
    "gid": 0,
    "mode": 420,
    "sha256": "d04c50105f0348337a26ef51f0c0d8a5c23389d2a35922b6f33a26f095d05a36",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/symbol.font.family.xml": {
    "bytes": 1711,
    "gid": 0,
    "mode": 420,
    "sha256": "2801694195be0238b7971a332d4a94d7cfec0ad379d436b72bf412ebadab1b3b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.borders.with.css.xml": {
    "bytes": 928,
    "gid": 0,
    "mode": 420,
    "sha256": "bd74262b185b8653a43b00d077cf023c00f93ca8653546829e1871a4b1be04a6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.caption.properties.xml": {
    "bytes": 1101,
    "gid": 0,
    "mode": 420,
    "sha256": "5c5188ed3bf1401a656f012070f9a6b906dfa13b099e03c70958c7cc6d03618f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.cell.border.color.xml": {
    "bytes": 1535,
    "gid": 0,
    "mode": 420,
    "sha256": "3f2eabda0dbbf9fe876bbbf14bbd40e2ff59997f59866657a8a98dae9b106369",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.cell.border.style.xml": {
    "bytes": 1786,
    "gid": 0,
    "mode": 420,
    "sha256": "36879cc5e24cd9a40108386d678b2b5b6bf6f32e1ea913ce956b33f2768746e9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.cell.border.thickness.xml": {
    "bytes": 1375,
    "gid": 0,
    "mode": 420,
    "sha256": "eb3f4acf5c1c74af407f351348c0bdd1a83897eb230f9997721679a70acb0a80",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.cell.padding.xml": {
    "bytes": 1132,
    "gid": 0,
    "mode": 420,
    "sha256": "43fafdda26cc5918472ff832729ed65d126b778c2f160e5e6422017e055a6e5b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.entry.padding.xml": {
    "bytes": 808,
    "gid": 0,
    "mode": 420,
    "sha256": "e4e032bdaf1ba57b696440eb7e54a9177e1427599740177b3988aea0e6bbe514",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.footnote.number.format.xml": {
    "bytes": 1461,
    "gid": 0,
    "mode": 420,
    "sha256": "8e6ffb75da9c9e679d9767b61e25b577652433af43248a77f6dd89e38ef12068",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.footnote.number.symbols.xml": {
    "bytes": 1811,
    "gid": 0,
    "mode": 420,
    "sha256": "53ce67b8d750dd6d0e772e37989e8fe6533e5a40812e27c06e968175a33124ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.footnote.properties.xml": {
    "bytes": 1564,
    "gid": 0,
    "mode": 420,
    "sha256": "d910fb6821b020a13e3a236bd891754d2b2f5f3b547afced7cb96a04e9d3b4f4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.frame.border.color.xml": {
    "bytes": 1013,
    "gid": 0,
    "mode": 420,
    "sha256": "e0a8559dabb09adcb4bdda27ef908e8abfc4f1f161065857a13d96dbe1db57b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.frame.border.style.xml": {
    "bytes": 1622,
    "gid": 0,
    "mode": 420,
    "sha256": "a38afb096071bac7300d28c6e7d86cdd36c9d7164e902bc5c9948891b9a1b831",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.frame.border.thickness.xml": {
    "bytes": 1108,
    "gid": 0,
    "mode": 420,
    "sha256": "045848bd1b40548d828eb1eb6afdd2749d1aa61f864ffff1ed2df38791400caf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.properties.xml": {
    "bytes": 1279,
    "gid": 0,
    "mode": 420,
    "sha256": "450663d58784159b13ae5760d08b7c6a37e46849734a1a768da73aab8c027743",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.spacer.image.xml": {
    "bytes": 1104,
    "gid": 0,
    "mode": 420,
    "sha256": "abb395016a0e07acd680570aa5ec037702c1092cf491b73540837bdd512974cc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/table.table.properties.xml": {
    "bytes": 1312,
    "gid": 0,
    "mode": 420,
    "sha256": "9ca7d12b43ab525d80cdd77d970d718afd782b023ee78ec2ca3ceb9bd2194fb6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/tablecolumns.extension.xml": {
    "bytes": 1027,
    "gid": 0,
    "mode": 420,
    "sha256": "6fc1e8ced0f8c468c881afcf2878552d4be5f99b7f3ab2e437647da1e64e485f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/target.database.document.xml": {
    "bytes": 1653,
    "gid": 0,
    "mode": 420,
    "sha256": "ac4d6981ab2cec3580336d05993f300d987bc7ab45b03dbbe0b225a8e9744819",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/targets.filename.xml": {
    "bytes": 1307,
    "gid": 0,
    "mode": 420,
    "sha256": "d48f00d8c4cbc73236b30955f1d9d44a01a8d58ee37fdb801dba8807f62d6ca7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/task.properties.xml": {
    "bytes": 1032,
    "gid": 0,
    "mode": 420,
    "sha256": "668b04c784f28c5ce4a55189547951e94efe07d41df5103257834803802984a9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/template.xml": {
    "bytes": 730,
    "gid": 0,
    "mode": 420,
    "sha256": "4fcab5ca777797a885e3129b31ac7d660d1b9b375814af278da757809eeb75fe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/tex.math.delims.xml": {
    "bytes": 1529,
    "gid": 0,
    "mode": 420,
    "sha256": "e3c31ec08f185d929f87c9a30b7e44813a77099c8558719953dfdcfe59607202",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/tex.math.file.xml": {
    "bytes": 1435,
    "gid": 0,
    "mode": 420,
    "sha256": "a0b4d156100eaeca910c77993aa76dd81fe34071ccf6468c356ff9683fd44218",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/tex.math.in.alt.xml": {
    "bytes": 2793,
    "gid": 0,
    "mode": 420,
    "sha256": "709b08b2de5297091656826d132e650a3f3b98d4cda19245e82a22a4365ca1f3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/text.home.xml": {
    "bytes": 775,
    "gid": 0,
    "mode": 420,
    "sha256": "4682998b3cb9355234e24b447c8a6ecc24f58385e5ebfb8edd0ef28713fcf2b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/text.next.xml": {
    "bytes": 777,
    "gid": 0,
    "mode": 420,
    "sha256": "37d1b273929a34345dce6d441aa8f2ef57344371b37f147bb9701af17fc9e5d7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/text.prev.xml": {
    "bytes": 777,
    "gid": 0,
    "mode": 420,
    "sha256": "8052d67b033bcb142f1f6f705cc91097aba4910318538c16c7b4e931d04cdae0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/text.toc.xml": {
    "bytes": 771,
    "gid": 0,
    "mode": 420,
    "sha256": "79f74495efdbb3a0cd2d9d040699bcc8f9983e44565f44f89aba36e999273217",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/text.up.xml": {
    "bytes": 766,
    "gid": 0,
    "mode": 420,
    "sha256": "a636806a7b3c32358f33a0923f9d800ee1a817fd41da90b238d6e2d18bdbf9f4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/textbgcolor.xml": {
    "bytes": 921,
    "gid": 0,
    "mode": 420,
    "sha256": "f4761614e664eec9319826c76bda5ddb9675dd48dcfeceb93397e29b1793203a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/textdata.default.encoding.xml": {
    "bytes": 1210,
    "gid": 0,
    "mode": 420,
    "sha256": "e008fc6888b2e72927f95e52d7c2176a390bca308c222e2ff6402d1ad1f05a86",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/textinsert.extension.xml": {
    "bytes": 2875,
    "gid": 0,
    "mode": 420,
    "sha256": "4c19746c7ed47bcceeb50831fa95cab8dd3c8bd5fb958d167581484f09230728",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/title.font.family.xml": {
    "bytes": 1399,
    "gid": 0,
    "mode": 420,
    "sha256": "48805929e7761b7f097d86504f51f4d88ec34bc0d444c3b4b37a4a82c76c7cb2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/title.margin.left.xml": {
    "bytes": 2184,
    "gid": 0,
    "mode": 420,
    "sha256": "c2539a49f913d8f891d172bfb790f567c771be03d9e38ed29e9abcfa82cd733c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/titlefoil.html.xml": {
    "bytes": 889,
    "gid": 0,
    "mode": 420,
    "sha256": "fbbfc55bad6c86a001f0820697402dcf03f334b984691c47b4416e54db08bea4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.bg.color.xml": {
    "bytes": 865,
    "gid": 0,
    "mode": 420,
    "sha256": "dffcea7c53b4a42aab67ed3908cc9eadc690903176b98188ce4fec73cef04677",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.blank.graphic.xml": {
    "bytes": 1029,
    "gid": 0,
    "mode": 420,
    "sha256": "587017709980e41bb833dae7fd149a833660c29e96d8ac484d7aae777148e399",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.blank.image.xml": {
    "bytes": 1017,
    "gid": 0,
    "mode": 420,
    "sha256": "239b4275c7ce43127826e34eb3a1fd33f39f61cc82b9a812e816112d29f06d66",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.blank.text.xml": {
    "bytes": 1008,
    "gid": 0,
    "mode": 420,
    "sha256": "a56732905345941d99530f8071773defc49b613a763035ede722ce268aa78cec",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.hide.show.xml": {
    "bytes": 1221,
    "gid": 0,
    "mode": 420,
    "sha256": "09e985969d57f22d0cf113058e7cc9af700ecfa4cbfec32f71b77339e6baff24",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.html.xml": {
    "bytes": 856,
    "gid": 0,
    "mode": 420,
    "sha256": "93c5a21289b93a908ed5c9e8bde10ecd280934af0223884bc11d0503f659e9c4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.image.xml": {
    "bytes": 840,
    "gid": 0,
    "mode": 420,
    "sha256": "88daf147ddfa10c575fea260c5a0dea140edb703135506d6828c50c9ec2e78b1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.indent.width.xml": {
    "bytes": 1250,
    "gid": 0,
    "mode": 420,
    "sha256": "199ab1d16a7ccf2beb47f84e992a3ed4bfb86118442bd0659032d46c7cb5ea02",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.leader.properties.xml": {
    "bytes": 1240,
    "gid": 0,
    "mode": 420,
    "sha256": "be5ea77706a73c978be214e4293aaeba7555afd220a66d7098586dccae9f7e64",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.line.properties.xml": {
    "bytes": 1797,
    "gid": 0,
    "mode": 420,
    "sha256": "7b6df9e390ccb628fdb3c320b1f1ef5df9ee44f5fd82184627d89f1f8c3a64b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.list.type.xml": {
    "bytes": 1155,
    "gid": 0,
    "mode": 420,
    "sha256": "4f3c3fc0a2068738157310aa0deb51bec8740a7ae90bcd79fff7795fbd3e6594",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.margin.properties.xml": {
    "bytes": 1427,
    "gid": 0,
    "mode": 420,
    "sha256": "f2f56f80a557241cccb40bf6774a85b6b231cff56385a79453d74dcedf937cf2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.max.depth.xml": {
    "bytes": 877,
    "gid": 0,
    "mode": 420,
    "sha256": "65036f97fea9c25a5f08b715e3ebfc9db11a2018657e405b9ca221a38e2c2646",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.pointer.graphic.xml": {
    "bytes": 1034,
    "gid": 0,
    "mode": 420,
    "sha256": "2a76973674b56fc038b472b6dc40be3741e91595ba54129f912539ff669467e6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.pointer.image.xml": {
    "bytes": 1036,
    "gid": 0,
    "mode": 420,
    "sha256": "39dabd73be3ae1bbb963d0e023945f17d940b92d372a6cb8c7f06ccd049e8123",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.pointer.text.xml": {
    "bytes": 1035,
    "gid": 0,
    "mode": 420,
    "sha256": "f602e2e74296fd109cd7a6b5c0aceb7f3faad4e24e3c9f2a22fca7d9ddb70b21",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.row.height.xml": {
    "bytes": 1210,
    "gid": 0,
    "mode": 420,
    "sha256": "5baf34dd2fcb16e581b7a910a18c7242b0ab8b54cb036a1706f543f4aeb73865",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.section.depth.xml": {
    "bytes": 939,
    "gid": 0,
    "mode": 420,
    "sha256": "4397a1d57e5b94400c1eeb4f55bcc1ada780ac1b7ba04cabd65382a5b2026aae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.spacer.graphic.xml": {
    "bytes": 1032,
    "gid": 0,
    "mode": 420,
    "sha256": "16bc2e0be482a61e23cd91f65f50376adda4c75e92efaafb9fc52541c3515b91",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.spacer.image.xml": {
    "bytes": 1010,
    "gid": 0,
    "mode": 420,
    "sha256": "37cc71564d0c21005d4cbdbe091bc88b091d3e55a68c0d87cdbe3d4b7e451de0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.spacer.text.xml": {
    "bytes": 1004,
    "gid": 0,
    "mode": 420,
    "sha256": "e1c951d530917cb65c622aa1c695828e92b6dfdf6fa9b10e65ec90641aa552e4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/toc.width.xml": {
    "bytes": 861,
    "gid": 0,
    "mode": 420,
    "sha256": "1d17ab416badf1482025eecfd2fea5981f193bcc4000ef758ef8de49fdcc1ee7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/ua.js.xml": {
    "bytes": 879,
    "gid": 0,
    "mode": 420,
    "sha256": "80d81370b8468ca5f43f5162f0cb3e6235ab4e339924b7bbe6758169df9e6865",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/ulink.footnotes.xml": {
    "bytes": 1265,
    "gid": 0,
    "mode": 420,
    "sha256": "d6a3d1a2706dcf0da0cf6f223a20e0b01116e5d3cf01baef61ab6a7c3a5759c1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/ulink.hyphenate.chars.xml": {
    "bytes": 1476,
    "gid": 0,
    "mode": 420,
    "sha256": "a6ae96c44d96dff47053701e9494c4bc176e6cde0a33aa9b41d7cc6622e6cd2d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/ulink.hyphenate.xml": {
    "bytes": 1563,
    "gid": 0,
    "mode": 420,
    "sha256": "27fbea60f3709770e82e5d19b6877742f4800c6fc6d8991c610f616fb4870305",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/ulink.show.xml": {
    "bytes": 1323,
    "gid": 0,
    "mode": 420,
    "sha256": "272778e479d90d8fd516628d88a42dc12219722bb624571d34b9824e2e86c0ca",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/ulink.target.xml": {
    "bytes": 975,
    "gid": 0,
    "mode": 420,
    "sha256": "27344f26da1fb1e879ad8520ea1e8b305576833809455cc0b73bdac33a43a08e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/up.image.xml": {
    "bytes": 852,
    "gid": 0,
    "mode": 420,
    "sha256": "f737b3ef3fa0be9dd09842ea29143ae8a26aa4c40fade4186e76cbdfe3ecd028",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/use.embed.for.svg.xml": {
    "bytes": 1217,
    "gid": 0,
    "mode": 420,
    "sha256": "5ff18c5b6fd863b8f548c8b343930f1bff2e52662078b08b7fcafdb83f0929c6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/use.extensions.xml": {
    "bytes": 982,
    "gid": 0,
    "mode": 420,
    "sha256": "4f5625b0f90bac05f572d95a6bc2d9d44d9fa28d5037328154d5156ff063d5e6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/use.id.as.filename.xml": {
    "bytes": 992,
    "gid": 0,
    "mode": 420,
    "sha256": "d47d6b8a47a45b84474c4fa42448d16bf3eae5a212795aedc56e69e0d48ce09d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/use.id.function.xml": {
    "bytes": 1195,
    "gid": 0,
    "mode": 420,
    "sha256": "fd88221629f3769b903e50173f48645c801736fee7f4636515b0aee87b4f7b5e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/use.local.olink.style.xml": {
    "bytes": 1740,
    "gid": 0,
    "mode": 420,
    "sha256": "f64c51da1962902b88c0f9faa1c3957197142e6831ca5673c7a2b22ac6e9e384",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/use.role.as.xrefstyle.xml": {
    "bytes": 3308,
    "gid": 0,
    "mode": 420,
    "sha256": "b8b1a7636310b25663d2aa408f39135e4de44be018c80b9261152c6319afd262",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/use.role.for.mediaobject.xml": {
    "bytes": 1940,
    "gid": 0,
    "mode": 420,
    "sha256": "dc450e296ed37d9c659b77b32d5f8c012636fe766d26294d2194b359e4de6059",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/use.svg.xml": {
    "bytes": 1043,
    "gid": 0,
    "mode": 420,
    "sha256": "7e6a7f22669ad63c9bc7d33c4b70da438a9e5ad2d768a7d770b86b433c95bfb0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/user.css.xml": {
    "bytes": 950,
    "gid": 0,
    "mode": 420,
    "sha256": "1bb5c4be788b2e3734d567ae4182cbcae215436b90156cd6fe6ce14d7fb96454",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/variablelist.as.blocks.xml": {
    "bytes": 2385,
    "gid": 0,
    "mode": 420,
    "sha256": "956faa7fb9e47b19d2e503bd854529b48eada32651290996c12a7b107965b856",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/variablelist.as.table.xml": {
    "bytes": 2097,
    "gid": 0,
    "mode": 420,
    "sha256": "38501f815da50256e2e050b895cacb802e8379cc1ab4a47df71c5a98574a34aa",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/variablelist.max.termlength.xml": {
    "bytes": 1689,
    "gid": 0,
    "mode": 420,
    "sha256": "d93b3cd7955eb161d7e7532f9278dca8845628a929fe76fe2b69e60d77e64433",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/variablelist.term.break.after.xml": {
    "bytes": 1455,
    "gid": 0,
    "mode": 420,
    "sha256": "4ddc191eb685231bc105e62cbec52c8dcd7c1a029a9caa2dd3e6290d97af4bdb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/variablelist.term.properties.xml": {
    "bytes": 1084,
    "gid": 0,
    "mode": 420,
    "sha256": "b42b7dd7242d44d011994ed727560c722df9f4c2c7876d9eda4aadda199ffa3f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/variablelist.term.separator.xml": {
    "bytes": 1603,
    "gid": 0,
    "mode": 420,
    "sha256": "dc01784f6c0bde80cac01aee2969877c2961e16c7a4fcc7dc82d72db38cfea37",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/verbatim.properties.xml": {
    "bytes": 1703,
    "gid": 0,
    "mode": 420,
    "sha256": "a3345b62d02813384e14ca073a9fb909aad39686ab00b60a4764088d446832d1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/webhelp.autolabel.xml": {
    "bytes": 939,
    "gid": 0,
    "mode": 420,
    "sha256": "8cc73c2745af1a39d0ac1789740c711f9a6e7c79f5fc7c66f39fa3bd951bee72",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/webhelp.base.dir.xml": {
    "bytes": 1075,
    "gid": 0,
    "mode": 420,
    "sha256": "3d74668e39a8fd21837fcb267e0546973cc72d528277639649a7fe74a295a0c2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/webhelp.common.dir.xml": {
    "bytes": 1380,
    "gid": 0,
    "mode": 420,
    "sha256": "12c80eb5d56f23d655ce974e09f3bf71fcbea4c02746119c6dd09ca8f7b1e088",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/webhelp.default.topic.xml": {
    "bytes": 1428,
    "gid": 0,
    "mode": 420,
    "sha256": "1e7bae6fc416aa5458e4783a1f8b784c6845922a9c65e0ee81c6683ca21e1af2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/webhelp.include.search.tab.xml": {
    "bytes": 964,
    "gid": 0,
    "mode": 420,
    "sha256": "ce05282cccc08d38451c566c0ed9366b95d25a1028b239d726f934adeb2a9af2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/webhelp.indexer.language.xml": {
    "bytes": 1564,
    "gid": 0,
    "mode": 420,
    "sha256": "ebd7e94fedf630c7a3d1d4d1c1382dab877ed1a373824b8bd389437fe7b8325d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/webhelp.start.filename.xml": {
    "bytes": 1394,
    "gid": 0,
    "mode": 420,
    "sha256": "99e0575eaa612f550afd15bd95d66ed83f3375e6c4f05d52af65c800809b06c3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/webhelp.tree.cookie.id.xml": {
    "bytes": 2247,
    "gid": 0,
    "mode": 420,
    "sha256": "b95a023ea0aaa9d6ce9907cbf84dd4543f985ece15ddef33c5e16182fb6ab2de",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/wordml.template.xml": {
    "bytes": 1366,
    "gid": 0,
    "mode": 420,
    "sha256": "5e7f150136d02c2478c47d2d8da5c44171203a73f517e4a266b2ea4b90ed29a9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/wrap.slidecontent.xml": {
    "bytes": 983,
    "gid": 0,
    "mode": 420,
    "sha256": "8c954d3271fd4d089288755e55e9d027f1321918e24de95a5b1f902c9ded60c7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/writing.mode.xml": {
    "bytes": 2494,
    "gid": 0,
    "mode": 420,
    "sha256": "7b7481c518faf09a08ec53866cc7348774cd3e2f4a25d0c73da27ca34d160e51",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/xbCollapsibleLists.js.xml": {
    "bytes": 1007,
    "gid": 0,
    "mode": 420,
    "sha256": "a5b54f23f1c07df0ff2d85f2198e7c8569d382479d9499dea5994f91a8dd325f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/xbDOM.js.xml": {
    "bytes": 903,
    "gid": 0,
    "mode": 420,
    "sha256": "4197dbe4b7a60e1e4ad767f32b1984439b41d9b0ff488f0c53888d6cc91efdd4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/xbLibrary.js.xml": {
    "bytes": 935,
    "gid": 0,
    "mode": 420,
    "sha256": "d1595558434dc3c197897266204843d9c9ad1e104548074dd90862a336c547b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/xbStyle.js.xml": {
    "bytes": 919,
    "gid": 0,
    "mode": 420,
    "sha256": "f258f4bdaa57aaa230ef443124f4917dde629415990a31e89e0b26427b36f62e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/xep.extensions.xml": {
    "bytes": 1077,
    "gid": 0,
    "mode": 420,
    "sha256": "033e781cd959f809284106ded7a7505774200336b87647c548acb257c3bdc2a6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/xep.index.item.properties.xml": {
    "bytes": 1516,
    "gid": 0,
    "mode": 420,
    "sha256": "600790bfacdee8618d16b35a1a284e1908fd4fdc056c7f6fe872f45e0e5ad7a1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/xref.label-page.separator.xml": {
    "bytes": 1487,
    "gid": 0,
    "mode": 420,
    "sha256": "03b43dd85d7d59c171af0b0165b049f3052fe14215e9f5b010e5b5dacfcda0d5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/xref.label-title.separator.xml": {
    "bytes": 1392,
    "gid": 0,
    "mode": 420,
    "sha256": "e02ee1996116bae43b746a7e05d64232dcbc7796a32846645099eaa0d3597f59",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/xref.properties.xml": {
    "bytes": 931,
    "gid": 0,
    "mode": 420,
    "sha256": "c627b9674643b83af5fac1a6a94f83d067d3e20dd17a3cffd0c5a737293373fd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/xref.title-page.separator.xml": {
    "bytes": 1425,
    "gid": 0,
    "mode": 420,
    "sha256": "fcc03dc62aa6c819b2383df1f71f20bc691735a27789a69c02bc36405c2114f1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/xref.with.number.and.title.xml": {
    "bytes": 1130,
    "gid": 0,
    "mode": 420,
    "sha256": "4917f4a57f7c00e4a26a1596b584d2f400b2192b80d1d31d1506485b1c1b8bf5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/params/xsl1.1.bookmarks.xml": {
    "bytes": 1365,
    "gid": 0,
    "mode": 420,
    "sha256": "12ac694b3cf839effc753aa07f4adf43e3d3d232d0a32e0d1b4b51985264590c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/profiling": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/profiling/profile-mode.xsl": {
    "bytes": 10432,
    "gid": 0,
    "mode": 420,
    "sha256": "61effafb44307acdd1d832d17b02bd6940d820828ddc4bab6443db73b8bfea7c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/profiling/profile.xsl": {
    "bytes": 2366,
    "gid": 0,
    "mode": 420,
    "sha256": "0b1a7ad29f35cbfa9935547ccdb2514398d8aa6e796e42cf11c918f551671a48",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/profiling/strip-attributes.xsl": {
    "bytes": 798,
    "gid": 0,
    "mode": 420,
    "sha256": "2cc835ebca57dae2828b4cb2d24af43f82d79db9a77756123b50b1e8001c5724",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/profiling/xsl2profile.xsl": {
    "bytes": 6728,
    "gid": 0,
    "mode": 420,
    "sha256": "0f1886be5dc508741fb583aa69ee368d49ecf8ef0790d6266619ff42bf2b438c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/blocks-spec.xml": {
    "bytes": 422,
    "gid": 0,
    "mode": 420,
    "sha256": "eaaa2c05d479000f17f39b51bab14db3e5cd624d5f06f5b7a9f625b4eb931ee8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/blocks2dbk.dtd": {
    "bytes": 2396,
    "gid": 0,
    "mode": 420,
    "sha256": "1e2333b01209da29895e2f51fc836996bd61f42a61c00a613d663c628e173e19",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/blocks2dbk.xsl": {
    "bytes": 69286,
    "gid": 0,
    "mode": 420,
    "sha256": "151d168ce7c36cdb6e300d6971d0b2a6e7625d8d870699845d34f0b13f22e30c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/dbk2ooo.xsl": {
    "bytes": 5950,
    "gid": 0,
    "mode": 420,
    "sha256": "d756ec3679bed895676c74f0a031d8dd22376fcf32abc480db1acaeb815a6b4f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/dbk2pages.xsl": {
    "bytes": 16024,
    "gid": 0,
    "mode": 420,
    "sha256": "363ede71bc9a10eecdbc17c9cc0de135169c3218c4027eedc4d10be90f2b8690",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/dbk2wordml.xsl": {
    "bytes": 12604,
    "gid": 0,
    "mode": 420,
    "sha256": "d2e9e33dbafde34ffb9f1345a33456e481cc8a83b0301e4dcd23f7db1b43c930",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/dbk2wp.xsl": {
    "bytes": 56113,
    "gid": 0,
    "mode": 420,
    "sha256": "07c876ee1b8e2fb40f9d387646d4f11edf7107f9b9d00298767d0eb3e50bdc59",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/normalise-common.xsl": {
    "bytes": 1314,
    "gid": 0,
    "mode": 420,
    "sha256": "bc1d66ff9c373e04b98d6b9c9696e349ce2d0e8bdf1372973ba4a3386a7114f8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/normalise2sections.xsl": {
    "bytes": 75032,
    "gid": 0,
    "mode": 420,
    "sha256": "eb4af21d52d48944e8d4e0b696a887c921348b0c514a03c089dd6d55dd613e21",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/pages2normalise.xsl": {
    "bytes": 14248,
    "gid": 0,
    "mode": 420,
    "sha256": "52c4aa2052b8e1f246c997cc647b301e3882b5c0e38bed1b16757636837953cf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/param.xml": {
    "bytes": 3928,
    "gid": 0,
    "mode": 420,
    "sha256": "7cacd203ef37691e64675b9e4cd96be5cde59843d596027d0a12f847a0f348bf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/param.xsl": {
    "bytes": 587,
    "gid": 0,
    "mode": 420,
    "sha256": "1a91ae11ecc94d04bb61583bdefaed1e2a7c100054bae464a25ce10b8beeacb2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/sections-spec.xml": {
    "bytes": 1394,
    "gid": 0,
    "mode": 420,
    "sha256": "11936674f7be394f9044fdfe22e5227a2988362f0eea5dab238f7a0182918e0a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/sections2blocks.xsl": {
    "bytes": 15589,
    "gid": 0,
    "mode": 420,
    "sha256": "84fe44cf1296597fefbd7ca7193d5fb4e635a6f6713ca8ec72a0069650de246d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/specifications.xml": {
    "bytes": 67086,
    "gid": 0,
    "mode": 420,
    "sha256": "6a3733774f838820d4e2fd799202735d655686c4a92082bd243c5245536dce78",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/template-pages.xml": {
    "bytes": 427500,
    "gid": 0,
    "mode": 420,
    "sha256": "8e1e0c555229680ecc946be216f71cb1745f1b7ccf8ed923658b3619b997d615",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/template.xml": {
    "bytes": 86584,
    "gid": 0,
    "mode": 420,
    "sha256": "77c167c4de9d8737a326f77dfbff0a2be1bdfbd137312d64c299d43cc4975cd4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/roundtrip/wordml2normalise.xsl": {
    "bytes": 16910,
    "gid": 0,
    "mode": 420,
    "sha256": "db7a68ce11eb488bef9d92a982398fb9b406137ca5417f878ea26b33f7abbe53",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/template": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/template/titlepage.xml": {
    "bytes": 16594,
    "gid": 0,
    "mode": 420,
    "sha256": "0705ec3d3f6bd8f20675805e4b15b6feb95dafcdce8f9a2360377c409b765da7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/template/titlepage.xsl": {
    "bytes": 54574,
    "gid": 0,
    "mode": 420,
    "sha256": "fd45822f18bd433ffa3d3d12966e474b09297d1e948cfa4fd7bb361ff55d730a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/autolayout.xsl": {
    "bytes": 6933,
    "gid": 0,
    "mode": 420,
    "sha256": "817642f20b82572066d94f0af406673923eaaf920799c78d08169db927b2036f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/build.xml": {
    "bytes": 555,
    "gid": 0,
    "mode": 420,
    "sha256": "3d3a25d695ad04b0b9ec8eb14e36986492c542141c1e17c5b4532b0fae065e89",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/chunk-common.xsl": {
    "bytes": 7230,
    "gid": 0,
    "mode": 420,
    "sha256": "1fc3efb0991c0364bd990a80ff32e590648df2dbddc6cea655d0c34d918669f0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/chunk-tabular.xsl": {
    "bytes": 446,
    "gid": 0,
    "mode": 420,
    "sha256": "1730c3bb2f1bc5ad42ae1a51c1b34cca724ee3be63442b0a52b1a5e5de3ebe9e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/chunk-website.xsl": {
    "bytes": 446,
    "gid": 0,
    "mode": 420,
    "sha256": "8bbc34db90afa7eb5353d62d74bf025fde1371b5afb99f057ca23ae94a3e037c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/head.xsl": {
    "bytes": 9242,
    "gid": 0,
    "mode": 420,
    "sha256": "d26e8dc3a6172a78f14b1dae2da3483a3992f806e722cf2ec056e9d41c77bebf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/makefile-dep.xsl": {
    "bytes": 4200,
    "gid": 0,
    "mode": 420,
    "sha256": "b40333d93f4ea5a567de649ae21ea7a9ca922b81caa7c3d0f75396c2435d33ef",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/olink.xsl": {
    "bytes": 10949,
    "gid": 0,
    "mode": 420,
    "sha256": "a4b6845777365803a17cfe567ddc97b5b8608e83ab7e5323bd2e31d0bba8494e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/param.xml": {
    "bytes": 26659,
    "gid": 0,
    "mode": 420,
    "sha256": "f9aba2e5160c6225684ef0bd936e35e731c5567aaf36dd4df1ab9397586f3bf3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/param.xsl": {
    "bytes": 2322,
    "gid": 0,
    "mode": 420,
    "sha256": "0f620afab0a00ec58d22ac189d0685503108116620da2931f33edda9abab08c6",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/rss.xsl": {
    "bytes": 4589,
    "gid": 0,
    "mode": 420,
    "sha256": "e427f86766d1b9b180a33c830f0bece8f5ec1cb153a2546ce36bd3845fe5d704",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/tabular.xsl": {
    "bytes": 7647,
    "gid": 0,
    "mode": 420,
    "sha256": "8d1be0cb3131644fdf31d5c0e283900e90c1242b0db97e9c402586da61ed1f04",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/toc-tabular.xsl": {
    "bytes": 15849,
    "gid": 0,
    "mode": 420,
    "sha256": "27455b08fb3a486471acab6c4af3c2d8059f0ac12ae051aa87244cfb2c0847b4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/toc.xsl": {
    "bytes": 9227,
    "gid": 0,
    "mode": 420,
    "sha256": "43c826f90f2704cee715af1a471d1c7466aa3236b2cc69476a07cccc6b5a7a7a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/website-common.xsl": {
    "bytes": 27558,
    "gid": 0,
    "mode": 420,
    "sha256": "93d78d027fac2aeb7346b89925a2e7f9a10008f224f82a5e176e70d51c8c48e4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/website-targets.xsl": {
    "bytes": 730,
    "gid": 0,
    "mode": 420,
    "sha256": "8ec94bb151a0fdf371b0343f9d94ccb292811969b8e23d7698e473f5917df76b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/website.xsl": {
    "bytes": 4130,
    "gid": 0,
    "mode": 420,
    "sha256": "5a65d28e618f9990394d80ace644038926ae919b5bc53cfe6024233e593f62c4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/website/xbel.xsl": {
    "bytes": 2880,
    "gid": 0,
    "mode": 420,
    "sha256": "8491d875b7c8920dcd7402f5a8bc2e707d59c8f86882e19d23aa355105c32ec7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/admon.xsl": {
    "bytes": 4728,
    "gid": 0,
    "mode": 420,
    "sha256": "4114d9977abbcc489bfaa71ba8029b668492c668f52bb35879f3c466d05c4043",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/annotations.xsl": {
    "bytes": 5646,
    "gid": 0,
    "mode": 420,
    "sha256": "e71f7700a1383e1c48c3a6de17527ea1b7e574df05898113ddfdce1ad3df7d79",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/autoidx-kimber.xsl": {
    "bytes": 7181,
    "gid": 0,
    "mode": 420,
    "sha256": "18c5f4f0f6494a939ce27257f041a9d89050f274019093d2f8b8577ff0e9dc31",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/autoidx-kosek.xsl": {
    "bytes": 5368,
    "gid": 0,
    "mode": 420,
    "sha256": "99d42a572aae0a2cd802d6579dcb12cb235a7fa0fd7f559f2fc819eff7eacc99",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/autoidx-ng.xsl": {
    "bytes": 873,
    "gid": 0,
    "mode": 420,
    "sha256": "3581f81d7e70cd3cb68a21e057f00d811c77ac82e44e369698d70006c942ce12",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/autoidx.xsl": {
    "bytes": 149102,
    "gid": 0,
    "mode": 420,
    "sha256": "be276f29a82ca836160c244f9b4971bc4d1662169158c367e971c9934e5efaaf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/autotoc.xsl": {
    "bytes": 29361,
    "gid": 0,
    "mode": 420,
    "sha256": "6125067eab4e72c6b4c457a0800004f49a8b7cba80d3c128cc31467256059cec",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/biblio-iso690.xsl": {
    "bytes": 57099,
    "gid": 0,
    "mode": 420,
    "sha256": "e50ac5e3690d5dd21c7c2cc1a8f2be54279abb03c9f01ae97a0c422e6d84933f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/biblio.xsl": {
    "bytes": 45330,
    "gid": 0,
    "mode": 420,
    "sha256": "0f48e3f1482c0b6d6f4b45b53785e829138cd30095e2737de7010bfb43560e81",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/block.xsl": {
    "bytes": 17276,
    "gid": 0,
    "mode": 420,
    "sha256": "73400aafafe8c55f4d9bff4866f35e8ddbeef51d583a72fb6e1d1942c5adfd8b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/build.xml": {
    "bytes": 1245,
    "gid": 0,
    "mode": 420,
    "sha256": "c892326b4aaa1aee4febf5ba29c4cbde703ef4826514a3ed3f30c8917a4c71fb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/callout.xsl": {
    "bytes": 7961,
    "gid": 0,
    "mode": 420,
    "sha256": "035edc612adf48e3686437f58951b5482c3ee31a1901286b11fe87a9f15c2394",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/changebars.xsl": {
    "bytes": 4152,
    "gid": 0,
    "mode": 420,
    "sha256": "e3b2182ca9155cce507bce85fb18fcf0e32aa6c718a15a92a07a74a9efa18c5c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/chunk-changebars.xsl": {
    "bytes": 3913,
    "gid": 0,
    "mode": 420,
    "sha256": "721282c566fa94ecc47db914947bf13588445c682ef2cb1527b05507e09266ac",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/chunk-code.xsl": {
    "bytes": 25362,
    "gid": 0,
    "mode": 420,
    "sha256": "befbfad6e4ed2719eb785a481e17ad19f14287dddba62237b7822865a1a05148",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/chunk-common.xsl": {
    "bytes": 84687,
    "gid": 0,
    "mode": 420,
    "sha256": "40a1c99eef600bb09417d38716fbcd0677992c360c263206218a3542aff330d4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/chunk.xsl": {
    "bytes": 2414,
    "gid": 0,
    "mode": 420,
    "sha256": "066e1202a815939998137f1e77707cdffc4439ed9276362c3d26d8b15b721e7f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/chunker.xsl": {
    "bytes": 17918,
    "gid": 0,
    "mode": 420,
    "sha256": "5c3cbdbf399bca3c179273a83df1d76b76050541fdd41df6e9edd429b46d6d57",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/chunkfast.xsl": {
    "bytes": 2780,
    "gid": 0,
    "mode": 420,
    "sha256": "f7a75987a12f695a87a9368de4e7a9157de9c1c7e0245b2dc719ae53b1bbc859",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/chunktoc.xsl": {
    "bytes": 19116,
    "gid": 0,
    "mode": 420,
    "sha256": "ffe86af003eed18526f6f39e960e0f803826f8ce449357bf194f057fe6cb93a4",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/component.xsl": {
    "bytes": 17171,
    "gid": 0,
    "mode": 420,
    "sha256": "adef8a34c2f2dae250acc366cb0f83903f3609aa82c786bd691a1a00a439f52a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/division.xsl": {
    "bytes": 7087,
    "gid": 0,
    "mode": 420,
    "sha256": "8d2b1c86f7f38003fe41acbd39670f68c296ae8de5a4c8592e38f762849e845b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/docbook.css.xml": {
    "bytes": 1623,
    "gid": 0,
    "mode": 420,
    "sha256": "653067889f6a4a8f427cd4fb72176776da4124e76aa79b448b2b8fecaa065497",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/docbook.xsl": {
    "bytes": 20143,
    "gid": 0,
    "mode": 420,
    "sha256": "203d8daaa5fb4e28cc2cc4d71e21c1cac6f5f5545c359fef3a1189010975f1f8",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/ebnf.xsl": {
    "bytes": 10602,
    "gid": 0,
    "mode": 420,
    "sha256": "70c670515b3c5784c4efd71f5f480afcbd38aab0cd5d631ebe1e4ebd5fb75e4a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/footnote.xsl": {
    "bytes": 11675,
    "gid": 0,
    "mode": 420,
    "sha256": "85646617e2d47e8233daadc241285e1c4b160c45c4832611c5bb572e529b8983",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/formal.xsl": {
    "bytes": 16511,
    "gid": 0,
    "mode": 420,
    "sha256": "4798859edb4460e611c37826c36770532cac768888a3ec34462f8c91a4a5bf35",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/glossary.xsl": {
    "bytes": 37904,
    "gid": 0,
    "mode": 420,
    "sha256": "e3a78eebba412604a1484de75f89d41f1311b9117b4e231c68bc3a8d26b39336",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/graphics.xsl": {
    "bytes": 60189,
    "gid": 0,
    "mode": 420,
    "sha256": "e6f1e1761793fcd28f4ddd5d689c7d31b4e11067f3390b668154d116e270312b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/highlight.xsl": {
    "bytes": 3154,
    "gid": 0,
    "mode": 420,
    "sha256": "823aa177c54a5d13d8aa15ee22945ea2181c019fc35a95257aadc1fd0d84f741",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/html-rtf.xsl": {
    "bytes": 11312,
    "gid": 0,
    "mode": 420,
    "sha256": "7eb5df2d3a43f4273128465cb12bbdeb8755f2cadcc59c22d822fc09c171ad9c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/html.xsl": {
    "bytes": 24185,
    "gid": 0,
    "mode": 420,
    "sha256": "f670d3b6742725a3e6a84e7823139542b66f2f1d9121ddea4ff0cff1a827ab80",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/htmltbl.xsl": {
    "bytes": 4863,
    "gid": 0,
    "mode": 420,
    "sha256": "757f9849ef2bacccd27cc85d6333fcddf73ade84b62cc0121bf9855a81cc1ab5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/index.xsl": {
    "bytes": 10014,
    "gid": 0,
    "mode": 420,
    "sha256": "08092622ce0ff47d91b6a66d7d72abca673436109f879b4d0dea67207834baeb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/info.xsl": {
    "bytes": 1713,
    "gid": 0,
    "mode": 420,
    "sha256": "915bc2ab84360d060abba0290928a0ce0ac1875752b012294bdd8a6314c3610d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/inline.xsl": {
    "bytes": 52911,
    "gid": 0,
    "mode": 420,
    "sha256": "2d8f30d3d5b07206b1787c66c90ab96d8fbfd7caeacb7990f84a4587c4e1e207",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/its.xsl": {
    "bytes": 4637,
    "gid": 0,
    "mode": 420,
    "sha256": "136a11dae3124d86f135ad8501b034da2d040ee57383afb4807ab207198017e7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/keywords.xsl": {
    "bytes": 1275,
    "gid": 0,
    "mode": 420,
    "sha256": "0662da354dfcc9ba6aaecd05b827a9e5fcf868aeafc7b9da3e1e1bff1e9e913a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/lists.xsl": {
    "bytes": 41779,
    "gid": 0,
    "mode": 420,
    "sha256": "095d5316d89cfd259ac91125ae5db875247309ba3a90ccf440a08e41fbfd33ae",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/maketoc.xsl": {
    "bytes": 2879,
    "gid": 0,
    "mode": 420,
    "sha256": "83e8ecd0beb9dc6501c04f732d0f96ec8f90a5c4d0d1df2f826cdbad8e0e942c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/manifest.xsl": {
    "bytes": 1030,
    "gid": 0,
    "mode": 420,
    "sha256": "76a362cf93892886ac336e53f5b7d492b257d457ed6f6ee2e629423a65468d4c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/math.xsl": {
    "bytes": 9100,
    "gid": 0,
    "mode": 420,
    "sha256": "c08f456aace7ddec68cb42040e22c2d0410f0611d84c3ac894842d166098bdad",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/oldchunker.xsl": {
    "bytes": 7206,
    "gid": 0,
    "mode": 420,
    "sha256": "5725833c7756370f747f238663f16394a0e49e3143b765347380a61f90842058",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/onechunk.xsl": {
    "bytes": 1460,
    "gid": 0,
    "mode": 420,
    "sha256": "1047de6d2234db994edc77e126d7308ee80f6f27fa54aa06d15b4a4ef367b70b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/param.xsl": {
    "bytes": 20540,
    "gid": 0,
    "mode": 420,
    "sha256": "96f6e7e03b5e46c705ac5ecdf4ea261de25256f4dfbda8ce90e16586923844fa",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/pi.xsl": {
    "bytes": 54306,
    "gid": 0,
    "mode": 420,
    "sha256": "82d870611d74f7dea3dfe2622c5867c7109a892aa1304a7cceafcaaace67a339",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/profile-chunk-code.xsl": {
    "bytes": 26134,
    "gid": 0,
    "mode": 420,
    "sha256": "faa278eaa5820807a2b6a7c931af3b7d787a58c1a54ecc9506bc5a9421a2b6db",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/profile-chunk.xsl": {
    "bytes": 2737,
    "gid": 0,
    "mode": 420,
    "sha256": "26f3389a8aba379ced88cb1468819304108f934314904bd667432c18cac48e7d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/profile-docbook.xsl": {
    "bytes": 20430,
    "gid": 0,
    "mode": 420,
    "sha256": "51188c8e83325e90e24995d7da65256d106b1d481801804f8a5f62c0f1abc368",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/profile-onechunk.xsl": {
    "bytes": 1775,
    "gid": 0,
    "mode": 420,
    "sha256": "6c057e226d54e817f57764a2e5baacaad39f53f67fd345f7cfd92ee2971179d1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/publishers.xsl": {
    "bytes": 3484,
    "gid": 0,
    "mode": 420,
    "sha256": "d5e2c8e8efc7eeac0b987fd61f3fb887c101daa315324bde4653c4fdba709b41",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/qandaset.xsl": {
    "bytes": 15950,
    "gid": 0,
    "mode": 420,
    "sha256": "5947eda33e73e97ccd9a5fcf4d6b84ad7b54300efb2a27e2f627d3fcabdf1141",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/refentry.xsl": {
    "bytes": 10023,
    "gid": 0,
    "mode": 420,
    "sha256": "b5e02c40327d352f0a8cb5056f3f159594317228dbd81279562313dcee4dff07",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/sections.xsl": {
    "bytes": 23528,
    "gid": 0,
    "mode": 420,
    "sha256": "eb327b8d25088caa45dd1709218ac2aa75c425e14f41f58856f81dd724830fd3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/synop.xsl": {
    "bytes": 52428,
    "gid": 0,
    "mode": 420,
    "sha256": "4f0b1792de392268b3d313fc12ab68d63114e2e0ec4701b4d3c7f33818b6b913",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/table.xsl": {
    "bytes": 44311,
    "gid": 0,
    "mode": 420,
    "sha256": "8827f9e70adaaf4fef7b7c7425551691d8858c0f75a50b4eb6c48fc33fdaf697",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/task.xsl": {
    "bytes": 2511,
    "gid": 0,
    "mode": 420,
    "sha256": "95eb7114a69c9c22e28c0ee87c260b4e4372f9b6c68fc231a7cb1a2dbd7532ce",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/titlepage.templates.xsl": {
    "bytes": 200073,
    "gid": 0,
    "mode": 420,
    "sha256": "f80092354bf7b92847927fb866bab928dd0dcac3ab798191f07cf86c379cea82",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/titlepage.xsl": {
    "bytes": 38396,
    "gid": 0,
    "mode": 420,
    "sha256": "26284c2352e82934244f7d4021a07d589d5f45a3cdbf6166c9886cf166966c84",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/toc.xsl": {
    "bytes": 12902,
    "gid": 0,
    "mode": 420,
    "sha256": "eed17909c07190e15ec44ece5f9d0e6437c7e9b5ccf1962e3657d54771a8a04a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/verbatim.xsl": {
    "bytes": 14093,
    "gid": 0,
    "mode": 420,
    "sha256": "393f2061ca562fbaed557b66deb25f8202b271f15a5067e4db3c819cb85630bd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml-1_1/xref.xsl": {
    "bytes": 47815,
    "gid": 0,
    "mode": 420,
    "sha256": "c523e4d8c83943e3a7b33cd7766ff9ef8441991393efa1f5c3c5a20016925706",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/admon.xsl": {
    "bytes": 4856,
    "gid": 0,
    "mode": 420,
    "sha256": "865bfb8e1ee6291150763239eb6a1eadbe37cf37e3543d30424e56d56b3638b7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/annotations.xsl": {
    "bytes": 5668,
    "gid": 0,
    "mode": 420,
    "sha256": "8fdb6340aa33d96039a8e0a884c98235cc5b30b4c5711c9eb6c23912696e698b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/autoidx-kimber.xsl": {
    "bytes": 7181,
    "gid": 0,
    "mode": 420,
    "sha256": "18c5f4f0f6494a939ce27257f041a9d89050f274019093d2f8b8577ff0e9dc31",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/autoidx-kosek.xsl": {
    "bytes": 5368,
    "gid": 0,
    "mode": 420,
    "sha256": "99d42a572aae0a2cd802d6579dcb12cb235a7fa0fd7f559f2fc819eff7eacc99",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/autoidx-ng.xsl": {
    "bytes": 873,
    "gid": 0,
    "mode": 420,
    "sha256": "3581f81d7e70cd3cb68a21e057f00d811c77ac82e44e369698d70006c942ce12",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/autoidx.xsl": {
    "bytes": 149102,
    "gid": 0,
    "mode": 420,
    "sha256": "be276f29a82ca836160c244f9b4971bc4d1662169158c367e971c9934e5efaaf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/autotoc.xsl": {
    "bytes": 29361,
    "gid": 0,
    "mode": 420,
    "sha256": "6125067eab4e72c6b4c457a0800004f49a8b7cba80d3c128cc31467256059cec",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/biblio-iso690.xsl": {
    "bytes": 57099,
    "gid": 0,
    "mode": 420,
    "sha256": "e50ac5e3690d5dd21c7c2cc1a8f2be54279abb03c9f01ae97a0c422e6d84933f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/biblio.xsl": {
    "bytes": 45330,
    "gid": 0,
    "mode": 420,
    "sha256": "0f48e3f1482c0b6d6f4b45b53785e829138cd30095e2737de7010bfb43560e81",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/block.xsl": {
    "bytes": 17324,
    "gid": 0,
    "mode": 420,
    "sha256": "549e192c39d6a2bb15ee72bbc84c4d2ecbfb805363f896aed933097c4ec7d047",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/build.xml": {
    "bytes": 1241,
    "gid": 0,
    "mode": 420,
    "sha256": "f07bbcd081ad082c82a50f671d7bbfd139c547ebf7df3cf02c134826f73cfa7d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/callout.xsl": {
    "bytes": 7972,
    "gid": 0,
    "mode": 420,
    "sha256": "965d2434cb5125bfc741037cc2fbe723caec22f0865716b19d7480571f431fb7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/changebars.xsl": {
    "bytes": 4163,
    "gid": 0,
    "mode": 420,
    "sha256": "a9e0c458024fa63a9d8f1ececf4e2a12127b20ab6656e8339b3a1f0af0a7a882",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/chunk-changebars.xsl": {
    "bytes": 3913,
    "gid": 0,
    "mode": 420,
    "sha256": "721282c566fa94ecc47db914947bf13588445c682ef2cb1527b05507e09266ac",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/chunk-code.xsl": {
    "bytes": 25362,
    "gid": 0,
    "mode": 420,
    "sha256": "befbfad6e4ed2719eb785a481e17ad19f14287dddba62237b7822865a1a05148",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/chunk-common.xsl": {
    "bytes": 85575,
    "gid": 0,
    "mode": 420,
    "sha256": "cf5f8d53b91dc7779f12b8e5037b790063ff5a7b387751c63b57eea9eef0b400",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/chunk.xsl": {
    "bytes": 2425,
    "gid": 0,
    "mode": 420,
    "sha256": "4c445a84898659da27ab164fc1131c501a4a68ff5eb2627d93e4ae77f99e4bf5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/chunker.xsl": {
    "bytes": 17942,
    "gid": 0,
    "mode": 420,
    "sha256": "80ef0b3515540c42774053ffe55478ca050db65f119a8099f20ad106288ca283",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/chunkfast.xsl": {
    "bytes": 2780,
    "gid": 0,
    "mode": 420,
    "sha256": "f7a75987a12f695a87a9368de4e7a9157de9c1c7e0245b2dc719ae53b1bbc859",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/chunktoc.xsl": {
    "bytes": 19127,
    "gid": 0,
    "mode": 420,
    "sha256": "c6b377550ab5a304ff34517188576619df5fa93c6f3881eeca19db8e19c165fe",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/component.xsl": {
    "bytes": 17171,
    "gid": 0,
    "mode": 420,
    "sha256": "adef8a34c2f2dae250acc366cb0f83903f3609aa82c786bd691a1a00a439f52a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/division.xsl": {
    "bytes": 7083,
    "gid": 0,
    "mode": 420,
    "sha256": "3ecd137866d7222a34500bdd880eaf2f00690c53222a5563dd03d621fa87d10c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/docbook-no-doctype.xsl": {
    "bytes": 20216,
    "gid": 0,
    "mode": 420,
    "sha256": "962119f56a97756e8a5299ea9556313ab81cee8a347dc3e439fedffbb39fb5f9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/docbook.css.xml": {
    "bytes": 1623,
    "gid": 0,
    "mode": 420,
    "sha256": "653067889f6a4a8f427cd4fb72176776da4124e76aa79b448b2b8fecaa065497",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/docbook.xsl": {
    "bytes": 20345,
    "gid": 0,
    "mode": 420,
    "sha256": "7fcc711300160b89cc2cc2e446fa72e3ef154e12cfebf2b5d9dcdedb95218c1c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/ebnf.xsl": {
    "bytes": 10586,
    "gid": 0,
    "mode": 420,
    "sha256": "762fbf4908245c78a4226230cf94021a3a2095a66fbe4cd6477a0f751c276078",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/footnote.xsl": {
    "bytes": 12467,
    "gid": 0,
    "mode": 420,
    "sha256": "6f45261a2ad4b2921b3d79f5db082ba204f13ef14ed93ad4fcab1d6c9259046e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/formal.xsl": {
    "bytes": 16511,
    "gid": 0,
    "mode": 420,
    "sha256": "4798859edb4460e611c37826c36770532cac768888a3ec34462f8c91a4a5bf35",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/glossary.xsl": {
    "bytes": 37904,
    "gid": 0,
    "mode": 420,
    "sha256": "e3a78eebba412604a1484de75f89d41f1311b9117b4e231c68bc3a8d26b39336",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/graphics.xsl": {
    "bytes": 60145,
    "gid": 0,
    "mode": 420,
    "sha256": "9d96daa35188a936a6baef0242a98ad450042858d97d64573c506ebcac09526f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/highlight.xsl": {
    "bytes": 3154,
    "gid": 0,
    "mode": 420,
    "sha256": "823aa177c54a5d13d8aa15ee22945ea2181c019fc35a95257aadc1fd0d84f741",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/html-rtf.xsl": {
    "bytes": 11312,
    "gid": 0,
    "mode": 420,
    "sha256": "7eb5df2d3a43f4273128465cb12bbdeb8755f2cadcc59c22d822fc09c171ad9c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/html.xsl": {
    "bytes": 24185,
    "gid": 0,
    "mode": 420,
    "sha256": "f670d3b6742725a3e6a84e7823139542b66f2f1d9121ddea4ff0cff1a827ab80",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/htmltbl.xsl": {
    "bytes": 4863,
    "gid": 0,
    "mode": 420,
    "sha256": "757f9849ef2bacccd27cc85d6333fcddf73ade84b62cc0121bf9855a81cc1ab5",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/index.xsl": {
    "bytes": 10014,
    "gid": 0,
    "mode": 420,
    "sha256": "08092622ce0ff47d91b6a66d7d72abca673436109f879b4d0dea67207834baeb",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/info.xsl": {
    "bytes": 1713,
    "gid": 0,
    "mode": 420,
    "sha256": "915bc2ab84360d060abba0290928a0ce0ac1875752b012294bdd8a6314c3610d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/inline.xsl": {
    "bytes": 52911,
    "gid": 0,
    "mode": 420,
    "sha256": "2d8f30d3d5b07206b1787c66c90ab96d8fbfd7caeacb7990f84a4587c4e1e207",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/its.xsl": {
    "bytes": 4637,
    "gid": 0,
    "mode": 420,
    "sha256": "136a11dae3124d86f135ad8501b034da2d040ee57383afb4807ab207198017e7",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/keywords.xsl": {
    "bytes": 1275,
    "gid": 0,
    "mode": 420,
    "sha256": "0662da354dfcc9ba6aaecd05b827a9e5fcf868aeafc7b9da3e1e1bff1e9e913a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/lists.xsl": {
    "bytes": 42110,
    "gid": 0,
    "mode": 420,
    "sha256": "334677df47972dffd42939657986123f7f4efc2b66f1641f6809f3d8e3699a75",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/maketoc.xsl": {
    "bytes": 2914,
    "gid": 0,
    "mode": 420,
    "sha256": "efac0283400dcb40a4111b7641e5f268687f94a74d6308c6fc63a5127c163033",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/manifest.xsl": {
    "bytes": 1030,
    "gid": 0,
    "mode": 420,
    "sha256": "76a362cf93892886ac336e53f5b7d492b257d457ed6f6ee2e629423a65468d4c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/math.xsl": {
    "bytes": 9100,
    "gid": 0,
    "mode": 420,
    "sha256": "c08f456aace7ddec68cb42040e22c2d0410f0611d84c3ac894842d166098bdad",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/oldchunker.xsl": {
    "bytes": 7206,
    "gid": 0,
    "mode": 420,
    "sha256": "5725833c7756370f747f238663f16394a0e49e3143b765347380a61f90842058",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/onechunk.xsl": {
    "bytes": 1460,
    "gid": 0,
    "mode": 420,
    "sha256": "1047de6d2234db994edc77e126d7308ee80f6f27fa54aa06d15b4a4ef367b70b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/param.xsl": {
    "bytes": 20518,
    "gid": 0,
    "mode": 420,
    "sha256": "e817a70c9152c2f518f029b0d7ed1fe60fc509b0c062fc46ea6995ef3bafc76f",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/pi.xsl": {
    "bytes": 54306,
    "gid": 0,
    "mode": 420,
    "sha256": "82d870611d74f7dea3dfe2622c5867c7109a892aa1304a7cceafcaaace67a339",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/profile-chunk-code.xsl": {
    "bytes": 26134,
    "gid": 0,
    "mode": 420,
    "sha256": "faa278eaa5820807a2b6a7c931af3b7d787a58c1a54ecc9506bc5a9421a2b6db",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/profile-chunk.xsl": {
    "bytes": 2748,
    "gid": 0,
    "mode": 420,
    "sha256": "2854505b04cbaa871478de846b7e794dd670ad66f10d2342198e8f4c72ffc8a0",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/profile-docbook.xsl": {
    "bytes": 20632,
    "gid": 0,
    "mode": 420,
    "sha256": "142a06715422a8579a7dd11ef2d00c377300be9513735d322ffa0f15eb7f7f26",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/profile-onechunk.xsl": {
    "bytes": 1775,
    "gid": 0,
    "mode": 420,
    "sha256": "6c057e226d54e817f57764a2e5baacaad39f53f67fd345f7cfd92ee2971179d1",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/publishers.xsl": {
    "bytes": 3484,
    "gid": 0,
    "mode": 420,
    "sha256": "d5e2c8e8efc7eeac0b987fd61f3fb887c101daa315324bde4653c4fdba709b41",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/qandaset.xsl": {
    "bytes": 15950,
    "gid": 0,
    "mode": 420,
    "sha256": "5947eda33e73e97ccd9a5fcf4d6b84ad7b54300efb2a27e2f627d3fcabdf1141",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/refentry.xsl": {
    "bytes": 10023,
    "gid": 0,
    "mode": 420,
    "sha256": "b5e02c40327d352f0a8cb5056f3f159594317228dbd81279562313dcee4dff07",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/sections.xsl": {
    "bytes": 23528,
    "gid": 0,
    "mode": 420,
    "sha256": "eb327b8d25088caa45dd1709218ac2aa75c425e14f41f58856f81dd724830fd3",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/synop.xsl": {
    "bytes": 52428,
    "gid": 0,
    "mode": 420,
    "sha256": "4f0b1792de392268b3d313fc12ab68d63114e2e0ec4701b4d3c7f33818b6b913",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/table.xsl": {
    "bytes": 44039,
    "gid": 0,
    "mode": 420,
    "sha256": "8815069557a5d24dbf96ecdb3267a84ad07f14de965924c7b2be7a6bcc55ed74",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/task.xsl": {
    "bytes": 2511,
    "gid": 0,
    "mode": 420,
    "sha256": "95eb7114a69c9c22e28c0ee87c260b4e4372f9b6c68fc231a7cb1a2dbd7532ce",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/titlepage.templates.xml": {
    "bytes": 16992,
    "gid": 0,
    "mode": 420,
    "sha256": "bc639f5cba2b4e3c5843b0184b3123c9bdae72b8f84f7303e842d1e68b7c635a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/titlepage.templates.xsl": {
    "bytes": 200073,
    "gid": 0,
    "mode": 420,
    "sha256": "f80092354bf7b92847927fb866bab928dd0dcac3ab798191f07cf86c379cea82",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/titlepage.xsl": {
    "bytes": 38396,
    "gid": 0,
    "mode": 420,
    "sha256": "26284c2352e82934244f7d4021a07d589d5f45a3cdbf6166c9886cf166966c84",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/toc.xsl": {
    "bytes": 12902,
    "gid": 0,
    "mode": 420,
    "sha256": "eed17909c07190e15ec44ece5f9d0e6437c7e9b5ccf1962e3657d54771a8a04a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/verbatim.xsl": {
    "bytes": 14093,
    "gid": 0,
    "mode": 420,
    "sha256": "393f2061ca562fbaed557b66deb25f8202b271f15a5067e4db3c819cb85630bd",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml/xref.xsl": {
    "bytes": 47815,
    "gid": 0,
    "mode": 420,
    "sha256": "c523e4d8c83943e3a7b33cd7766ff9ef8441991393efa1f5c3c5a20016925706",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5": {
    "gid": 0,
    "mode": 493,
    "type": "directory",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5/build.xml": {
    "bytes": 727,
    "gid": 0,
    "mode": 420,
    "sha256": "c151b95c8a012c2ba017bbb6ef35d1be4d77af5d240096aad5e58d64ad1f803c",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5/chunk.xsl": {
    "bytes": 971,
    "gid": 0,
    "mode": 420,
    "sha256": "99cd93ef7ee7fdb99488563f5b2ee2b744883af2b30b58c25c8e0ad34fa426fc",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5/chunkfast.xsl": {
    "bytes": 2784,
    "gid": 0,
    "mode": 420,
    "sha256": "65e66f4140e95646cbaa64a56aea81dc8488f582061c1a4eef5631ee135e9aec",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5/docbook.css.xml": {
    "bytes": 1568,
    "gid": 0,
    "mode": 420,
    "sha256": "ea3920dce5dd749a4adfcfd1fc1a224c260319833faf4178c2657df9daffeecf",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5/docbook.xsl": {
    "bytes": 697,
    "gid": 0,
    "mode": 420,
    "sha256": "1dae2896afa792ce528bc5aa0e076823669e41c718ef8a59fb64f6bfa7d0deaa",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5/html5-chunk-mods.xsl": {
    "bytes": 3653,
    "gid": 0,
    "mode": 420,
    "sha256": "a0abc68856bc067d9daa9f1a460a824ac71e5d50f28609664767f38f4cfddd35",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5/html5-element-mods.xsl": {
    "bytes": 32473,
    "gid": 0,
    "mode": 420,
    "sha256": "2f4e047878a12f82088cfb664761085714af77412590d449502de6c76b64062a",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5/onechunk.xsl": {
    "bytes": 1474,
    "gid": 0,
    "mode": 420,
    "sha256": "01a797840405ec005ed469c7cfd7e2b194fe92e2897a64af53e60ad046403c0e",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5/profile-chunk.xsl": {
    "bytes": 2406,
    "gid": 0,
    "mode": 420,
    "sha256": "710a77a2ff859e993587260a9478adba0ad3c3e470977e0ac80b8e936fd904d9",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5/profile-docbook.xsl": {
    "bytes": 1097,
    "gid": 0,
    "mode": 420,
    "sha256": "8242b1e994e3742f9396b9a531edc78fb81a28133235eca0d5063b656c94fc0b",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5/xhtml-docbook.xsl": {
    "bytes": 20739,
    "gid": 0,
    "mode": 420,
    "sha256": "8757ee403715ec1c5549e4319a53a16dd61535a87d543fcc911020f99cd6e9a2",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5/xhtml-profile-docbook.xsl": {
    "bytes": 17910,
    "gid": 0,
    "mode": 420,
    "sha256": "43af0f500ec71411acfee37bfa2b672a8b73d952c8c5811fba0c257671052b3d",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-1.79.2/xhtml5/xhtml2xhtml5.xsl": {
    "bytes": 1634,
    "gid": 0,
    "mode": 420,
    "sha256": "5b4d3defd296c7005d1afb37c584e514bd3a9a7d1447d2e3c42648267c862098",
    "type": "file",
    "uid": 0
  },
  "usr/share/xml/docbook/xsl-stylesheets-nons": {
    "gid": 0,
    "mode": 511,
    "target": "xsl-stylesheets-1.79.2-nons",
    "type": "symlink",
    "uid": 0
  }
}''')
ENTRY_LINE=b'mkdir -m700 "$HOME" /tmp/work\n'
ENTRY_INSERT=b'export XML_CATALOG_FILES="$HOME/docbook-catalog.xml"\npython3 -I -B /docbook_catalog.py\n'
def need(ok,why):
 if not ok:raise ValueError(why)
def entry(raw):
 need(PIN(raw)==ENTRY_BEFORE and raw.count(ENTRY_LINE)==1,'whole original container entry')
 result=raw.replace(ENTRY_LINE,ENTRY_LINE+ENTRY_INSERT,1);need(result.replace(ENTRY_INSERT,b'',1)==raw,'whole entry inverse');return result

def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def mount(fd):
 raw=Path('/proc/self/fdinfo/'+str(fd)).read_bytes();need(len(raw)<=4096,'bounded descriptor mount record');rows=[r.split(b':',1)[1].strip()for r in raw.splitlines()if r.startswith(b'mnt_id:')];need(len(rows)==1 and rows[0].isdigit(),'fresh descriptor mount identity');return int(rows[0])
def relative(n):
 need(type(n)is str and n and '\0'not in n and all(x not in('','.','..')for x in n.split('/')),'exact positive relative path');return n

def verify_payload(root,expected,seconds=60):
 """Full selected payload and child graph, fresh nofollow descriptors, no cache."""
 root=Path(root);need(root.is_absolute()and root.resolve(strict=True)==root and not any(p.is_symlink()for p in(root,*root.parents)),'ordinary absolute payload root')
 deadline=time.monotonic()+seconds;need(type(seconds)is int and 0<seconds<=60,'fixed bounded payload validation')
 def tick():need(time.monotonic()<deadline,'DocBook payload observation deadline')
 children={}
 for n in expected:
  relative(n);parent,_,leaf=n.rpartition('/');children.setdefault(parent,set()).add(leaf)
 rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);rootmount=mount(rootfd);rootinfo=os.fstat(rootfd);device=rootinfo.st_dev;observed={};spent=0
 try:
  for n,wanted in sorted(expected.items()):
   tick();parts=n.split('/');fds=[os.dup(rootfd)]
   try:
    for part in parts[:-1]:
     fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fds[-1]);fds.append(fd);s=os.fstat(fd);need(s.st_dev==device and mount(fd)==rootmount,'foreign payload ancestor mount')
    parent=fds[-1];leaf=parts[-1];before=os.stat(leaf,dir_fd=parent,follow_symlinks=False);mode=stat.S_IMODE(before.st_mode);row=dict(type=wanted['type'],mode=mode,uid=before.st_uid,gid=before.st_gid)
    need((mode,before.st_uid,before.st_gid)==(wanted['mode'],wanted['uid'],wanted['gid']),'selected payload metadata differs')
    if wanted['type']=='directory':
     fd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);fds.append(fd);need(os.fstat(fd).st_dev==device and mount(fd)==rootmount,'foreign directory mount');names=sorted(os.listdir(fd));need(names==sorted(children.get(n,set())),'complete selected payload child graph differs');need(names==sorted(os.listdir(fd))and identity(before)==identity(os.fstat(fd)),'payload directory drift')
    elif wanted['type']=='symlink':
     need(stat.S_ISLNK(before.st_mode),'selected alias type');fd=os.open(leaf,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);fds.append(fd);need(os.fstat(fd).st_dev==device and mount(fd)==rootmount,'foreign alias mount');row['target']=os.readlink(leaf,dir_fd=parent);relative(row['target']);need(identity(before)==identity(os.fstat(fd)),'selected alias drift')
    else:
     need(wanted['type']=='file'and stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==wanted['bytes']and before.st_size<=8*1024**2,'ordinary exact payload file')
     fd=os.open(leaf,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);fds.append(fd);need(os.fstat(fd).st_dev==device and mount(fd)==rootmount and identity(before)==identity(os.fstat(fd)),'foreign file mount/inode');h=hashlib.sha256();size=0
     while raw:=os.read(fd,1024**2):tick();h.update(raw);size+=len(raw);need(size<=wanted['bytes'],'payload read grew')
     need(identity(before)==identity(os.fstat(fd)),'payload file drift');row.update(bytes=size,sha256=h.hexdigest());spent+=size;need(spent<=32*1024**2,'closed DocBook payload byte limit')
    need(identity(before)==identity(os.stat(leaf,dir_fd=parent,follow_symlinks=False))and row==wanted,'selected payload name/content drift');observed[n]=row
   finally:
    for fd in reversed(fds):os.close(fd)
  need(identity(rootinfo)==identity(os.fstat(rootfd))==identity(root.lstat())and root.resolve(strict=True)==root,'named original payload root preserved')
 finally:os.close(rootfd)
 need(observed==expected,'whole selected payload closure');return observed

def catalog_bytes(root,xml_raw):
 need(PIN(xml_raw)=={k:PAYLOAD['etc/xml/docbook-xml'][k]for k in('bytes','sha256')},'whole pinned source XML catalog')
 root=Path(root);catalog=ET.Element('{'+NS+'}catalog');original=ET.fromstring(xml_raw);need(original.tag=='{'+NS+'}catalog','exact XML catalog namespace')
 def local(path):
  relative(path.removeprefix('/'));need(path.startswith('/usr/share/xml/docbook/'),'closed DocBook local prefix');return(root/path.lstrip('/')).as_uri()
 for row in list(original):
  tag=row.tag.removeprefix('{'+NS+'}');allowed={'public':{'publicId','uri'},'rewriteSystem':{'systemIdStartString','rewritePrefix'},'rewriteURI':{'uriStartString','rewritePrefix'}};need(row.tag=='{'+NS+'}'+tag and tag in allowed and set(row.attrib)==allowed[tag]and not list(row),'closed source XML catalog entries')
  attrs=dict(row.attrib)
  if 'uri'in attrs:
   prefix='http://www.oasis-open.org/docbook/xml/';uri=attrs['uri'];need(uri.startswith(prefix),'closed source public identifier target');version,sep,leaf=uri[len(prefix):].partition('/');need(version in('4.1.2','4.2','4.3','4.4','4.5')and sep and '/'not in leaf,'finite source DTD target');name='usr/share/xml/docbook/xml-dtd-'+version+'/'+leaf;need(name in PAYLOAD and PAYLOAD[name]['type']=='file','public target belongs to complete pinned DTD payload');attrs['uri']=local('/'+name)
  if 'rewritePrefix'in attrs:attrs['rewritePrefix']=local(attrs['rewritePrefix'])
  ET.SubElement(catalog,row.tag,attrs)
 for version in('1.79.2','current'):
  for origin,target in(('http://cdn.docbook.org/release/xsl/','xsl-stylesheets-1.79.2'),('http://cdn.docbook.org/release/xsl-nons/','xsl-stylesheets-1.79.2-nons'),('http://docbook.sourceforge.net/release/xsl-ns/','xsl-stylesheets-1.79.2'),('http://docbook.sourceforge.net/release/xsl/','xsl-stylesheets-1.79.2-nons')):
   for tag,key in(('rewriteSystem','systemIdStartString'),('rewriteURI','uriStartString')):ET.SubElement(catalog,'{'+NS+'}'+tag,{key:origin+version,'rewritePrefix':local('/usr/share/xml/docbook/'+target)})
 return b'<?xml version="1.0" encoding="UTF-8"?>\n'+ET.tostring(catalog,encoding='utf-8')+b'\n'

def resolved(raw,root):
 text=raw.decode().strip();u=urlparse(text);need(u.scheme=='file'and not u.netloc and not u.params and not u.query and not u.fragment,'only local file URI resolution');p=Path(unquote(u.path));root=Path(root);need(p.is_relative_to(root),'foreign resolution root');name=p.relative_to(root).as_posix();need(name in PAYLOAD and PAYLOAD[name]['type']=='file'and p==root/name,'resolution outside complete pinned payload');return name

def write_new(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as stream:stream.write(raw)

def read_private(path,mode=None):
 fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb')as f:
  before=os.fstat(f.fileno());need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==os.getuid()and before.st_size<=1024**2 and (mode is None or stat.S_IMODE(before.st_mode)==mode),'private ordinary selected diagnostic file');raw=f.read(1024**2+1);need(len(raw)==before.st_size and identity(before)==identity(os.fstat(f.fileno()))==identity(Path(path).lstat()),'private diagnostic read drift');return raw

def command(argv,home,env,index):
 import resource
 stdout=home/('command-'+str(index)+'.stdout');stderr=home/('command-'+str(index)+'.stderr');started=time.monotonic()
 with stdout.open('xb')as out,stderr.open('xb')as err:
  r=subprocess.run(argv,env=env,cwd=home,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=30,preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_OUTPUT,MAX_OUTPUT)))
 elapsed=time.monotonic()-started;outs={n:dict(**PIN(read_private(p)),base64=base64.b64encode(read_private(p)).decode())for n,p in(('stdout',stdout),('stderr',stderr))};need(r.returncode==0 and elapsed<=31 and all(v['bytes']<=MAX_OUTPUT for v in outs.values()),'offline DocBook tool failure')
 return dict(argv=argv,environment=env,exit_code=r.returncode,seconds=elapsed,seconds_limit=30,output_limit=MAX_OUTPUT,streams=outs),read_private(stdout)

PROBE_XML=b'<?xml version="1.0"?>\n<!DOCTYPE refentry PUBLIC "-//OASIS//DTD DocBook XML V4.5//EN" "http://www.oasis-open.org/docbook/xml/4.5/docbookx.dtd">\n<refentry><refmeta><refentrytitle>cachy-docbook-probe</refentrytitle><manvolnum>1</manvolnum></refmeta><refnamediv><refname>cachy-docbook-probe</refname><refpurpose>offline catalog validation</refpurpose></refnamediv><refsect1><title>Description</title><para>Source-owned offline DocBook validation.</para></refsect1></refentry>\n'
PROBE_XSL=b'<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:import href="http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl"/></xsl:stylesheet>\n'
MAX_OUTPUT=65536

def query_rows():
 rows=[]
 for version in ('1.79.2','current'):
  for prefix,target in (('http://cdn.docbook.org/release/xsl/','xsl-stylesheets-1.79.2'),('http://cdn.docbook.org/release/xsl-nons/','xsl-stylesheets-1.79.2-nons'),('http://docbook.sourceforge.net/release/xsl-ns/','xsl-stylesheets-1.79.2'),('http://docbook.sourceforge.net/release/xsl/','xsl-stylesheets-1.79.2-nons')):
   rows.append(dict(query=prefix+version+'/manpages/docbook.xsl',path='usr/share/xml/docbook/'+target+'/manpages/docbook.xsl'))
 for version in ('4.1.2','4.2','4.3','4.4','4.5'):rows.append(dict(query='-//OASIS//DTD DocBook XML V'+version+'//EN',path='usr/share/xml/docbook/xml-dtd-'+version+'/docbookx.dtd'))
 return rows

def prepare(root,home,output,owner):
 root=Path(root);home=Path(home);need(re.fullmatch('cachy-asahi-new-core-[0-9a-f]{16}',owner or''),'same source-owned package actor')
 s=home.lstat();need(stat.S_ISDIR(s.st_mode)and stat.S_IMODE(s.st_mode)==0o700 and s.st_uid==os.getuid()and home.resolve(strict=True)==home,'private owned ordinary builder HOME')
 observed=verify_payload(root,PAYLOAD);xml=(root/'etc/xml/docbook-xml').read_bytes();need(PIN(xml)=={k:PAYLOAD['etc/xml/docbook-xml'][k]for k in('bytes','sha256')},'whole source XML catalog');raw=catalog_bytes(root,xml);catalog=home/'docbook-catalog.xml';write_new(catalog,raw)
 env=dict(PATH='/usr/bin:/bin',LC_ALL='C.UTF-8',TZ='UTC',HOME=str(home),XML_CATALOG_FILES=str(catalog));commands=[];resolutions=[]
 for expected in query_rows():
  query=expected['query'];row,value=command(['/usr/bin/xmlcatalog',str(catalog),query],home,env,len(commands));name=resolved(value,root);need(name==expected['path'],'exact source-derived local resolution');commands.append(row);resolutions.append(dict(query=query,path=name,pin={k:PAYLOAD[name][k]for k in('bytes','sha256')}))
 fixture=PROBE_XML
 style=PROBE_XSL
 write_new(home/'probe.xml',fixture);write_new(home/'probe.xsl',style)
 argv=['/usr/bin/xsltproc','--nonet','--xinclude','--maxdepth','9000','--stringparam','man.output.quietly','1','-o',str(home/'cachy-docbook-probe.1'),str(home/'probe.xsl'),str(home/'probe.xml')];row,_=command(argv,home,env,len(commands));commands.append(row);result=read_private(home/'cachy-docbook-probe.1');need(0<len(result)<=1024**2 and b'.TH'in result and b'CACHY' in result.upper(),'real complete offline manpage output')
 need(read_private(catalog,0o600)==raw and read_private(home/'probe.xml',0o600)==fixture and read_private(home/'probe.xsl',0o600)==style,'whole private catalog/probe preserved through all commands')
 final=verify_payload(root,PAYLOAD);need(final==observed,'independent complete final payload reread')
 receipt=dict(schema=1,profile=PROFILE,status='PASS_RUN_OWNED_PRIVATE_DOCBOOK_CATALOG',owner=owner,scope='EXISTING_UNPRIVILEGED_OFFLINE_PACKAGE_ACTOR_ONLY',catalog=dict(path=str(catalog),uid=os.getuid(),gid=os.getgid(),mode=0o600,nlink=1,**PIN(raw)),payload=observed,payload_pin=PIN(ENC(observed)),final_payload=final,final_payload_pin=PIN(ENC(final)),inputs=INPUTS,resolutions=resolutions,commands=commands,probe=dict(xml=PIN(fixture),xsl=PIN(style),man=dict(**PIN(result),base64=base64.b64encode(result).decode())),global_catalog='NOT_MODIFIED',package_hooks='NOT_EXECUTED',network='ORIGINAL_DOCKER_NONE_XSLTPROC_NONET',native_acceptance='NOT_GRANTED',cleanup='NO_INDEPENDENT_CLEANUP_AUTHORITY');write_new(output,ENC(receipt));return receipt

def capture(value,maximum):
 need(type(value)is dict and set(value)=={'bytes','sha256','base64'}and type(value['bytes'])is int and 0<=value['bytes']<=maximum and type(value['base64'])is str and len(value['base64'])<=4*((maximum+2)//3),'closed bounded complete stream')
 raw=base64.b64decode(value['base64'],validate=True);need(base64.b64encode(raw).decode()==value['base64']and PIN(raw)=={k:value[k]for k in('bytes','sha256')},'full canonical captured bytes/hash');return raw

def validate_receipt(value,owner,actor_user,xml_raw,root=Path('/'),home=Path('/tmp/core-home')):
 """Pure component parser; full original native/CI/role/cleanup proof stays outside."""
 expected=dict(schema=1,profile=PROFILE,status='PASS_RUN_OWNED_PRIVATE_DOCBOOK_CATALOG',owner=owner,scope='EXISTING_UNPRIVILEGED_OFFLINE_PACKAGE_ACTOR_ONLY',inputs=INPUTS,global_catalog='NOT_MODIFIED',package_hooks='NOT_EXECUTED',network='ORIGINAL_DOCKER_NONE_XSLTPROC_NONET',native_acceptance='NOT_GRANTED',cleanup='NO_INDEPENDENT_CLEANUP_AUTHORITY')
 keys=set(expected)|{'catalog','payload','payload_pin','final_payload','final_payload_pin','resolutions','commands','probe'};need(type(value)is dict and set(value)==keys and all(ENC(value[k])==ENC(v)for k,v in expected.items()),'closed exact source-owned DocBook component receipt')
 need(re.fullmatch('cachy-asahi-new-core-[0-9a-f]{16}',owner or''),'exact original package actor owner');need(type(actor_user)is str and re.fullmatch('[1-9][0-9]*:[0-9]+',actor_user),'same original nonroot Docker actor UID/GID');uid,gid=map(int,actor_user.split(':'));catalog=Path(home)/'docbook-catalog.xml';raw=catalog_bytes(root,xml_raw);need(ENC(value['catalog'])==ENC(dict(path=str(catalog),uid=uid,gid=gid,mode=0o600,nlink=1,**PIN(raw))),'whole private catalog path/content pin')
 for field in('payload','final_payload'):need(ENC(value[field])==ENC(PAYLOAD)and value[field+'_pin']==PIN(ENC(PAYLOAD)),'complete independent before/after selected payload closure')
 queries=query_rows();expected_resolution=[dict(query=r['query'],path=r['path'],pin={k:PAYLOAD[r['path']][k]for k in('bytes','sha256')})for r in queries];need(ENC(value['resolutions'])==ENC(expected_resolution),'all13 exact local DTD/XSL resolutions')
 commands=value['commands'];need(type(commands)is list and len(commands)==14,'exact13 resolution processes and1 real manpage render');env=dict(PATH='/usr/bin:/bin',LC_ALL='C.UTF-8',TZ='UTC',HOME=str(home),XML_CATALOG_FILES=str(catalog))
 for i,row in enumerate(commands):
  argv=['/usr/bin/xmlcatalog',str(catalog),queries[i]['query']]if i<13 else['/usr/bin/xsltproc','--nonet','--xinclude','--maxdepth','9000','--stringparam','man.output.quietly','1','-o',str(Path(home)/'cachy-docbook-probe.1'),str(Path(home)/'probe.xsl'),str(Path(home)/'probe.xml')]
  need(type(row)is dict and set(row)=={'argv','environment','exit_code','seconds','seconds_limit','output_limit','streams'}and row['argv']==argv and row['environment']==env and type(row['exit_code'])is int and row['exit_code']==0 and type(row['seconds_limit'])is int and row['seconds_limit']==30 and type(row['output_limit'])is int and row['output_limit']==MAX_OUTPUT and type(row['seconds'])in(int,float)and math.isfinite(row['seconds'])and 0<=row['seconds']<=31,'complete fixed offline argv/environment/exit/clock/output contract')
  need(type(row['streams'])is dict and set(row['streams'])=={'stdout','stderr'},'both complete original tool streams');out=capture(row['streams']['stdout'],MAX_OUTPUT);capture(row['streams']['stderr'],MAX_OUTPUT)
  if i<13:need(out==((Path(root)/queries[i]['path']).as_uri()+'\n').encode(),'full original catalog query output is exact pinned local resource')
 probe=value['probe'];need(type(probe)is dict and set(probe)=={'xml','xsl','man'}and probe['xml']==PIN(PROBE_XML)and probe['xsl']==PIN(PROBE_XSL),'whole fixed probe inputs');man=capture(probe['man'],1024**2);need(man and b'.TH'in man and b'CACHY'in man.upper(),'complete real manpage render')
 return dict(profile=PROFILE,owner=owner,catalog=value['catalog'],payload_pin=value['payload_pin'],final_payload_pin=value['final_payload_pin'],resolutions=13,commands=14,network='ORIGINAL_DOCKER_NONE_XSLTPROC_NONET',authority='SOURCE_OWNED_COMPONENT_ONLY_NOT_FULL_NATIVE_ACCEPTANCE',cleanup='NO_NEW_CREDIT')

def main():
 need(os.getuid()!=0 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file()and os.environ.get('CACHY_ASAHI_CORE_CONTAINER')=='1','existing native unprivileged source-owned package actor only');need(os.environ.get('HOME')=='/tmp/core-home'and os.environ.get('XML_CATALOG_FILES')=='/tmp/core-home/docbook-catalog.xml','exact private catalog environment');return prepare(Path('/'),Path('/tmp/core-home'),Path('/out/docbook-catalog.json'),os.environ.get('CACHY_ASAHI_CORE_CATALOG_OWNER'))
if __name__=='__main__':main()
