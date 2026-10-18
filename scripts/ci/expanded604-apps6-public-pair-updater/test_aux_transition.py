# SPDX-License-Identifier: MIT
"""Actual frozen lock/archive selection and refusal checks; no mocked cache success."""
import ast,copy,hashlib,importlib.util,json,os,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('PUBLIC_PAIR_UPDATER_SOURCE',HERE.parents[2]))
s=importlib.util.spec_from_file_location('apps_aux_selection',HERE/'aux_transition.py');H=importlib.util.module_from_spec(s);s.loader.exec_module(H)
def inventory_sha(rows):return hashlib.sha256(''.join(n+' '+v+'\n' for n,v in sorted(rows.items())).encode()).hexdigest()
class Controls(unittest.TestCase):
 def setUp(self):
  self.before=dict(line.split() for line in (HERE/'before604.lock').read_text().splitlines());self.after=dict(line.split() for line in (HERE/'after604.lock').read_text().splitlines());self.config=dict(before_lock_sha256=H.BEFORE,after_lock_sha256=H.AFTER);self.snapshot=dict(release=dict(packages=[dict(name='cachy-asahi-apps',version='0.1.0-6',sha256=H.ARCHIVE)]))
 def guard(self,before=None,desired=None,snapshot=None,config=None):return H.apps6_selection_guard(snapshot or self.snapshot,before or self.before,desired or {'cachy-asahi-apps':'0.1.0-6'},config or self.config,need=H.need,inventory_sha=inventory_sha)
 def test_exact_real604_locks_and_eight_product_paths(self):
  self.assertEqual(inventory_sha(self.before),H.BEFORE);self.assertEqual(inventory_sha(self.after),H.AFTER);self.assertEqual(len(self.before),604);self.assertEqual(self.after,self.before|{'cachy-asahi-apps':'0.1.0-6'});self.assertEqual(self.before['cachy-asahi-setup'],self.after['cachy-asahi-setup']);self.guard();self.assertEqual(set(json.loads((HERE/'apps6-product.json').read_bytes())['payload']),H.FILES)
 def test_other603_setup_missing_added_or_wrong_version_refuse(self):
  for key,value in [('cachy-asahi-setup','0.1.0-4'),('cachy-asahi-apps','0.1.0-4'),('glibc','forged')]:
   b=self.before|{key:value}
   with self.subTest(key=key),self.assertRaises(ValueError):self.guard(before=b)
  for b in ({k:v for k,v in self.before.items() if k!='cachy-asahi-setup'},self.before|{'extra-package':'1'}):
   with self.assertRaises(ValueError):self.guard(before=b)
 def test_wrong_archive_extra_release_row_or_other_selection_refuse(self):
  for key,value in [('name','cachy-asahi-setup'),('version','0.1.0-5'),('sha256','a'*64)]:
   snap=copy.deepcopy(self.snapshot);snap['release']['packages'][0][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.guard(snapshot=snap)
  snap=copy.deepcopy(self.snapshot);snap['release']['packages']*=2
  with self.assertRaises(ValueError):self.guard(snapshot=snap)
  for desired in ({'cachy-asahi-setup':'0.1.0-6'},{'cachy-asahi-apps':'0.1.0-6','cachy-asahi-setup':'0.1.0-6'}):
   with self.assertRaises(ValueError):self.guard(desired=desired)
  with self.assertRaises(ValueError):self.guard(config=self.config|{'after_lock_sha256':'b'*64})
 def test_unknown_source_is_refused_before_derivation(self):
  with self.assertRaises(ValueError):H.derive((ROOT/'scripts/update/aux_runtime.py').read_bytes()+b'\n')
 def test_original_setup_only_caller_is_untouched(self):
  text=(ROOT/'scripts/update/aux_runtime.py').read_text();self.assertIn("before.get(SETUP)=='0.1.0-3'",text);self.assertIn("desired=={SETUP:'0.1.0-4'}",text)

# Exact original raw auxiliary data, retained from native604's eight-source role:
# evidence/run38948569244/container/aux-baseline587.bin. This is data, never code.
AUX_ZLIB_BASE64=(
 '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'
 'av3fMLzWq+EfAn+9b85ZEv6PDB81GtFdIH5Tnu84jX62jSbWpP6pbH+mnSbcn1AgPp97Gr/voiT1B2V5Lp/G5W0XmN8oKeRzOcNH'
 'gaMPg/NNKvm/8jSuX5eDeuN94+V8Z5Thselbt4N+iireeN9pXL8qYD5BxZ87Gb6q9WpVMN9yteK+5a+mz6sHQRX4l94pinpatr+B'
 'fsSn8/qrOj/7RMqfGIdbJH8n43/B8OWq1nsWiIdV+ea40+nnJo7sI6R8TcYfxfCEIAvUS5cq8nHtdC4/QQH7ec7pnP4XQb2iS+Ff'
 'EMNHNvb/JN3/JtPzr6dzfa8DeRtS0H8Hw6NyVbPB/SHbFsn9sq+l/Az14Cp4flbBzwcFfo4D9cN5p8jrP5M+76g+9gqwP7vPk+st'
 'fzyd52s/BvKpmlf8J8O7KNS3wvsZVP3ohZyf18Hzbscq+tELub0aKNDfWbyQy8OsBfnnVZ0nshle95r+48A/Dk6T6xtjDO/YTvv5'
 'Avez3bSQ6+OhgD8dhb3avpDHP1MfyPujFxT99wcW8v0KC9THHhX4P62Af3yV4W0DWyeA+3/2PK2oVzD8BWvOO/8pwM9hRbwx6Qz6'
 'GWMNXw78xdKudRJ+LsO7GvYvBPLfM1WeTyszfNCn4SvB+kNdcjy86gxef94E8rX7Zv1dwl/O8GSDTy6QX7QYfvFgqXI/oEd1/u7D'
 'DO9riwfPLZBff4HhwzENvwve9zVHzr9+kPI/rDhdQB4GJ8r24fkzuPy8E9h/Vf/092dwf/3knLx9U+nLm2fw/un8AvrOjhgl9PxM'
 'mn+Q6881hq8tLlWmg3nvrqkyPSsYvlMbWKQD/6V6n8jlDO/YhnWt9H4Q2b41y5z/j0vz+TI97+LrV7wC/LmtzPn/NXj/jEJ+7hPW'
 '//ykvHwOKvbrBwyvLS5Vfgzo365Y/3kBPxnMFz05S7YPh2j0c1XD/jCQT1V9fpYmvI8J1BP2dp0h4U9leNMP0YXgfMGQ4r6dfo3b'
 '5/fclNev4Fa5nnk+w/tabWA2yMdV97esZ3jyjq8x6f55mf9Xavw8ztHb8vHz1Qr59xl+QMP+Ohivqu6T0Xj96usP5uX/BcX8ye0M'
 'P6phfx+oj/Uo7s+8i+HdUQ1vlOppMv5uhscIL/wn4OfuyfL5qac1/v6OS4H8qNZ/keFHLkH4lwX6Zb/X+PtljgH+aIdi/TdSeQgj'
 '7bRf5+3D3knyfk2ssOcNK85TIF7aPUte/3iGNzZEA98H8fCsyXL9doDhvUjDjxWYP9lY4fZ5DsiXVfOWoyk+0vAXQP1HFU++P31e'
 'Xxv4XYH7MD+e0bMh+jV43l7F+eX/qPD3C/yudFvy+f+idH/l+ZOHBX6WCvj3HzP8coTte8E8oer+utcZvomG0BTQP1XVZ8b1cvvw'
 'JyAP877cK+Fn9nL7/44C/rrSy++3PxvM2wwq5HlJLz8f/XMQ7z05brZs3xjejPzww+D86ZBivhH1Cv4RPK/qPt5Rho8GNrhXF7jf'
 '/tO9XJ57pXhMxv+I4Vc0nQueAPWoFxT24UWG92xX/w6MP7vl8zt/SfEa9g3pvJi8/rgq398Z0n2ecvx2NMNvvMbRXi4wH3JqlfP/'
 'zgLnlZZUeTx2CagXqc5XDle5v/4qOF9TmqSYh0mfN8ZhF5DnrYrz2psZ3tcGSncVoP99KT0a9i8u4C8+VeX3BT0E4qu9Cvv2JYbv'
 '2xiNTQD86VXcL7dLoOdrQP63TpLr7T8S8D8tYM//WOXxzAYQD6jmaafV+HnG4QL5ZpX9YJsj5/8AzIsOdcnvUzDYD344ohng/pzS'
 'eNmeRzVunx8qMM/wPvaDYxvD7yrw/pdPpj9UYrwe9E97FPH2f6b0O7h29rMgX1acP/phTbjvFNwvtLWsOK9a4/v1JTCvpbpf4uWa'
 'cB65gP96jf0wchkyvwvkebvCf53Yx/3RsgL3k/Qz/Mj5vncG6Bfs+HfF+b4+zp9XYfwzV+bP2/s4f3ZL82Ayf4I+bt++AfpH910o'
 '+693M/wFTow2AvuzR/W+j3R9XxvYBvi/WxEv3dnH/enD8H2Xx/XI+RrDD5Qq8e+Bv3hBoS//3cfrY7eA+9L3T5PrS8+n6/dreEIB'
 '+fktw3vYDx3pfjn5eaezFwBjX1u0D9o3xX0yJwn4NeC+O1W9caWA74LzsQr8pQyvLSpVdoD5LtV5K1PA18B8vgrvpXjsaxtBv1jl'
 'f6/r5/nXDaB+Wxp/uoT/GMPrYxr+2wfy9lNV3/tiP3/f64OA/4NT5Xjyvn7+/q9Pg/siVOd9ftbP/XUbyI+qn/ibdL9QqK274OD3'
 '7RyxiK//ILj/WdUfOZHhfa2/9ATQF9V5wwrD257tXgLiVVU8sGaRUN8uMA+GF3F52ALm/XYeLevvtpQeo9NeWKBf+bmUP45tPADq'
 'LSr//oCAXwvmz1Xzio8v4vZTK0DPcwL/fw3mu1Tv5/qjwJ/+AvHG+AH6ObCQ+RnQT9w5X67P9DK8bTjxJvj+6GmK85UDvN5+Bsjf'
 'Vc+7geH7SpX4fqBfw2V5f1sMr1X7SnWpHi6v/94B3i+LpfOkcj3kEwyPauVgHKiP9SrW/9KAcF4e2JNeRX3p2wPC/d7g/p/tivtY'
 'Hhvg+ebk8/L2VmXPfzbA9etYEK+q5pFeyfa34kwD7/NV8fMNYb/+AOxDR3HecxKbqYxG++qrwf0z90yV85EFi4X3ZcP7MV6pHgbx'
 'ixhe6ytVeoB+qe5jvJjh674blOH8jyK/bjF8OBZE7y9QTx5leNsYWbQczKep4oFPCc/7Dnh/pqLf/SWG9702Wgb6ZesV94V+i+E9'
 '7GidAu8TeYrhG7YT3Qr8u+q8ycuLufyfAOLbPQr5/4uAPxz2H6fJ9mf2YMrPijMHyI/qPvDqILc//1ugvrqc4YmD/HOB/sglKT2W'
 'hl+H95ko7n9ADO9rfaUA1Ku7J14h4UOGX6Rh/6oC5yluZHjsa31ngfNBqvOJ2xm+XNXwsQXOB+0c5Pr1I5A/vjBerpc+IOzXLSC/'
 '2KO4T+Z7wn69CPivin9+OsjjmQsKxA97B3m+8wach1HEJ5PpEdOSVq2V/lngfT1zGb4T6UYFzAPfM0WWh+qZ3D7PAvUTlT0fOpPz'
 'Z/hf8vu7/ij5/uErUvqxr70C6vMq+9NkeFcPgn2gHnKPor7UYfjeWqlyArC3wwp7++l0/bijDRWIT+4T6J8B7P++M2X8Txge+1rt'
 'WoC/b4Isb68w/FgQaT8F+ewW9nJOEf93hh9uRNpXwX1Kqvrz+LO4ffs0mP/sUdznNkvAP1fg/rEKwzu2ga6U+iknyf7uLC7/pwN/'
 '162wbzbDa7VS5fUC5yM6Z3H5vPxteXs7qMgX3i/gLSAPexXy8FGGJwr/baneIuPvF+i/G96Xpbiv7PGzuP9FcD5HQf+vzuL27QTQ'
 'r3lSIQ+v8/2q/ALcFxocoXify9lcHh4B8bDKX/cI+IUF5kWHGL5ZbjRWgHhedV77CoY3jTLqg/1ZBd5meOzong38V0dxv8q7GN7Y'
 'XPbmgHhAdT/hLQxfDxHeA/sdi8+T8B9P6Qkrzv8D9xmq6H/wbC5vV0w5+PzJo2dzebu9QHz4zNn8/pOjPgjPJ8rnud5k+EAPo2Gg'
 '79u/5Uv4qfRITCnoj8w2mN94YZzsj+YyvBG10BisD1wjz3dVzuHydi3wp6r87pwUH+NwPny/pwJ/obD+r0G8oTpffNk53F98t0A/'
 'FDH8mhUb29tAfU+Vv1/D8KaLa6cWsJ//wvCO36y9Cc5zqd7/exPDN8s17eMF+i87GN5fuFDbU+C+pgfO4fcnLAH+bnCKTM/PBP7X'
 'QDyvmid5NX1e2wifBf2+/ZNlfel+G5+X/kWBfsTJHF8ZgO8bPU3274sZ3miNjp0D5HlLVc73L0rXj110Hphv6Zkg94+uTNe3RrWt'
 'wP5sU5xvdRleb9vtRwG+NVmuV299G683fnnGwfuzX2T4mNQ/gT9Sve/1XobHkYbPLHAe5BGG16qlyh2gH7pX4R+fSenXW3Ybzv9M'
 'le3Jy2/j/jQE/Nmn0Pe/c3mIfgHO2/bOlPFHn5uub4VLgDzvUtB/xrk8XvosfL+MQj4vYHhfq5YMeH5BkW++g+GJQfw9mK/oTJD7'
 '3S7DV0uVeCKwP3vGyfjrhfXPBuen7lHMq39IoP9eqb8v0/8JYf1bQT1Bef6O4bGvVV8G+YjqPOnDwvN+HrwfUHWe9HGGjxzb7Af5'
 '16xj5fnVZ8/l9uRB+D5TxfP+TqB/U4H7/d4U+PkZoC89kzQJP2UJf97nCtx/fvwSof4M7+9S8FNjeNsI4r8VOA+4lOGNjmn8FOyv'
 '6n7XiwV6BgrYEyTgpxe4/3lM4M8kEN+WFO9jvZXhA1vDHwX5WpdCfnYs4fv7HJjP2fdOmT9fEPAvFrjf7/4lPD6Z2Z+v/3Qp6le/'
 'Ep53HognVfx/jeEjpOF5sJ7zPRk/Yyn9HCINV6TzqrK/OInhXaThKuD/boW9XcTwDdtBlxe4H3LFUuG+OBh/Tjxetp9Lef3k38D7'
 'L1T+0VnK/ctHpPcFyPn+uwV6eoE9GZws498vrP80iLdV8xI7lnL7eT2ID1uK+cavLeX25J2gPty7Sl7/IYY3NezPB/5IRc/jS7m8'
 '/anA+yNeWcrjgSehviv4efx5wvu2CszXLWT4pmMb34T3uSnoWc7wVt0yngL1wydflu35pQxvGhq+BcxTqeoJm87j+vshQE/wcEnC'
 'xwzf0DXcLOAvbkzXr5YqPQXOL9x2Hs+n/gPej3G5Iv4X+P8YqD/Moq8vzuGfYPiaNjD4Mnzf8X9/UsL/MqXHsY3/gfH/dNne7juP'
 'x1c3gPsA75ks28NDl3F8E8w7bTtF1pd5DF9vIu946b4gmZ5FDF/T+rVJBfL3IYY3At27H9SL9ivi/0aKrzj2+6X7LRXvu1nG62Nl'
 'EI9t6zpF9nfLuPxMAPc/DyrO331+GZefL4B8fK/CH/3nMt4vmAPkWcWfp5Zxe7gE8Ed1P+dLKf29Gr4c2P+9ivcR/DOVB9tBPwD9'
 'hV2K+1Imnc/jvQmgHrvlKPn+q7nnc3s4AdKvmE8rn8/5v6ZA/W1Fiq9p1dPB/qrqFRen9ONO50h4Pq5bpuedDN80w7Gfw/c3Kfb3'
 'eoY3mm5wO+y/q/KFFO/Z5m8KvF/viyn95U5jCMR7g5Pk+9N+eD6X/8fPyt+fo7r//E8MTwR6U4H5q0OW08/lPg0fCu3D0yW5/rCc'
 '27fHgbyp7s9fvJzr+4oC9x9euJzbty/A+aKJ8v32m5Zzf9QN3jeq8i83MbyP7c7vwXzLtvFyfPtxgf6/wvmfbvl+9S8v5/q1EsST'
 'qnjj0ZQerbf0AJz3Vrzf51mGx7Wy6xfoX7+W7m/H9haA+zF6FPX5I1fw/f0rOK+6c6J83/i0FVzetp6Xf97tP/ilhD9hheCvC5wv'
 'KzN82XTsddI81YkSfuUKzv8fg/1S5SNvXyHcZw7m/fao7vtdwffrcDCPrZrf+9dsfb19DXgf0NUK//hRgT+LgL6o5q8+L9A/vUD/'
 '91Fhv/5WoL/2B4b3TA/fC+RtSEHPMRfQz20/NJ4G9mrbEYp+zQVc3mYWeN/fwAX8eX8Hzr93K/brKgF/E1hfZX9GGD7UsP9rED93'
 'z5TtwwcZ3rGNTgf0W4cmyf760xfw/ssL0vtbZfw3UnraKHwN3P/cO0XGP8bpqXwGzGttGSfHh8+l/CnjwAT9C1W+8yrDo1DDl4B4'
 'SSU/R67k+W8Hzuco9GUOwzu2sUoD9kGlXz0ruX+8GazfUuDPWsn16xxJX2T5Wc3wgYb9Kwvc/7M5Xd+xjYeAPOxQ9Mu+IOBfLNCv'
 '+SbDY1/rfQfYr6sV9D/C8L7r+rcX6Kc8n66ve1o0L69fOyfK/u5PK4Xz12D+YZ+ivjF+iPv3R0C9er2ifzRniO/vH8D7T1X37VcY'
 'vu5jvBL0L3Yo+i9nMXy5FbmVAv2d1UNcv44A9WdVvIcZHoXl+Fngj1T5wpYh4XwHkOcdinzhEwI9k2H+0ifz824B/48C9eoHOL5z'
 'eIF48vsMb6xcYz0Gz5Mq5k9+y/BEIW+U1pfj2wmr6OfeUiWeXWDeYIGAb8P7qBX5Qt8q4fxOgee9gOE3Iw2/DvSxa5K8/vUM79gG'
 'XgDj7dGShN+2isvDfHjfgup+IQHfV6D+fG+Kj3H4LhCfqOznowwfOEg7psD5wecZvmMa5bDA+anfC/v1X6C+1KWQhyNoyloqWwYK'
 'pfqqTP9shkemHy6D8zOK9SsMH2Fc+04Be7X8Qn7/7Qw4nzBTng98+4V8v2YVqHeN8PUrf5buI5Ll/98v5PHGLwF/tivuO/oKwxOB'
 'qIH8ZX1XXcI/wvCGhv2fFTg/uIfhbcMP9gL7tl2Rj7+W7m/TsS8E9Kj4M3k1owfXjH8H91U+qcDPZvgVK9fUowL8L6/m+/UVcJ5l'
 'q0JfNgr4jwL/q/Iv9dV8f08E94FsVcybtYX1zwbz1Sr9eu9q4X1YQD6HFeeRb1/N8539Bfb3KwzfNtqL7AL17R8Jz3su8NdPHvm3'
 'QyD+xdU8HviWdH5K9i+vCfSX4PsvVO8rWUM/656BPn5I/v7/rQp7cvwazv+lBc6PL17Dn7cbxOf7Ffp7yRr+vN8B8U9nvmx/6gJ+'
 'Ali/pZgfCNZw/nwE1m8V82b/yvCR7ZS3FvCPH2L4kXKf9nyB98XcLdD/M1APUfV/dwn8nwDqOar7eJ8Q8COgfq667+IXa7i+rAby'
 'rOrX/2ENj28PAfWW4a65Ev6wtYyeGIeTwf2BvYp4pnutUC8C8Y/qvOR8hsfIDN/4XJ4/qnyqKtBzWwF7siTFO7ZxI+hf9HTJ51/W'
 'r+X1tMlAPlX5TpjSH1acv8D523tl/PVref28AfsjM2R9+dBanr+sBvHAC7PleYlPC/x5A9gflb5/i+FjB5VvAfqiqufsXsvl/yJw'
 '3/Vu1TyGIA9D0nl8xf0hAn/WAXlW+aOj1wn7C/xX9xkyfgHDW8iNbwLxsGpeNP2P8H+/FM/I9mdgHX/elwr4o4sYPkDN6D0gvlWd'
 'p4jXCfmC9D5Zmf83ruPze9+U3ncjP+/t6/j9nw9L55dl+dwl8P8u4B+3TJTvb/zdOl4P7y1QD3x9HdfHpeD9j/uPl+dJ5l9EP496'
 'jv9ecJ5RFX9qF3H9nVbJ81/Fz6UXcfn8/n2g3qvYr3UM38QRngPs5/B4uf9+1UVcf11wf6lq3sBneD227EnwfSWq+7cvEuwJiN+2'
 'HCvfF/SBi/j5+nsL1Mc+dhHfrw+D+4RV8erdF3F7cmgBedh1ET8f+pB0P6dMz69Tepo4ulmqN8r7e/h6/rxfBvWTQKEvx63n9xV/'
 'UrrPR8YvXC/M+z108HrLRoZv4mj0ORBfqex5m+G13lLlvQXyzfes5/r74QLx0sfWc/v2VIH6+fcYvq2Xq75Ej8z/Z9Zz+fkhqA/s'
 'mCjL//+u5/r7xNl5ekqK+0j/vp7HP3cAe666j278Br5fySUW5KIY2yTXqZEr2LQB8ks3sEzywsrkNzXym83uNeTzoqQuNWKEqGnj'
 'iNxhSfjm2IZjkhe+aFXyua2XrdDN/nRDNLBGN/Dlehs1Qt+L1iLcyr5pmH9pE0eGjsm9vL3Zsp4Zhxjh0QwUmNh0bDJsxr7MCH0y'
 'eknKrV72y8h0dfJCz7ruWfUg9EkxnDQYtP7ki8wRMk3AviKoVssj5PYz9rNuYKce6p7lu3Xbi1Do6fRn5NVbozrCddsllwmRCwN7'
 'B7Ve+lfN2ELtHOmNECHDCUK7TTiTstp11voWcnD2QKROYwUu5pwkleD0Bxv7Zw4M9C5cmD1ajA037ljlGv2qxQchWaITR0RyBTrJ'
 'wbJ0qxr0uRIRQG6M9SZhNPlxzZrL1ib/1kfJMHU79F23XNWqA3wvMDlVwr7I9lMaOVtRR3dtD9VxpJsjkLTADMmhd9IoJv/Ul+w/'
 'iiLyZnRfOzNZ1PXp31W16iD9q9gbtT2rjFG0ySU9A/pbwyfv68IotHXH3qxHNhMO7cwaBZDyUjkyI7ts18xyCzkBFZBeUcjqIdId'
 '/nTJmiFqok5+LVHYW3rYMOLNm8tN39iETC5WzaBJRhh9rX9Rxg7TD61swyR2kBuPXZe8t2swo6FphuX+TJCx3wnLDuaEJ6sGKKxH'
 'LfL+3jpGbj1COKpz/cgJgx0iwu/ID8dym0WMMzLCyPRsM6+Q5BhHpJPik1alT2yFbj3ULSSon+fqfCcc3xyxUDvbUge7OjUAtUyQ'
 'ytgM7SAqJ7wIQhTRzaCCGLG/puIv/rDZTnY8Yahr9ZvcbGBMHjnQuWgHvjNiR+VrooEyeZVGNVskGGmavtcgPw8mz4OMuGl7Dd/K'
 'ILilWyg065i8dJn/2tLbVStTQjyKTZ3KapWKWEu3M4o2GXZzkJypJnM35Bcr12Tr6G0LtW3yAnRfG+jjomb7OAqRTm0DF7cGeRVa'
 'Qm9ftucO0kfqZgvJWrUhGrjc2dhCjrPKi1AzzHRhICeGm+st3bMo+eDPc54h+YMm8lBom/UgTDbsgCI8EhqLMjqbceAFZbtJXmSY'
 'mAz+MExccYa14pFIDyira70Je9v9jknuHAi5SpFXglLLmOxwE2M9sOvpl9Y4I109atWjsOrkGTmqjzm6Z5W5q+sFf2OeeWYj/zd+'
 'aJaJRpV7tf682lEuYt0NHFSP/BHZ9mJE5THZ9E7btsidtpkyk5XFRSOku5YZJTRn9tEMoI1zA7sejJG3B/ZV+/O0Usnwm9wnJLaA'
 'GjsMqUvQRODC0A+lf8R+7FkHYCtgEXVz5H7NprcxDgJyk2rm7olX4rptGXWz0ykv0lIXSfbXL5OzxW22JQmz/Diq1voETtiZqFD7'
 'IVjbNOa43Laa5BLR9KujFvJDnby2OwWxJ9ajGJNnMVsKriR+wiWHm7KHW0+kHj7YxvWrLr6sfInvO7js2Anpidpj3yubmZFqWoab'
 '/UnD9yJieexm9pytsSBMRPIaEpKVcTTmoDILN9JgodMYHLBCblmSp2ilJlUgPYksQpuzjZKbfJHbRmbuW8nrDVq2iTNxbNmYuIXM'
 'LCpjDIyQRViX+FmJdSwI4+4qQKhj4SD74jT2XKOP+bGwVVSCzmfakfwKERuZ7Ryx7+5Yy8eRp1OvmvzaNuM4+brFCcleMzIDci+X'
 'VhWMXWge0F6xSPUC37FQuMbGURKrZTSE+mi170yqZNVswcRfNG2Pq5lqI3DL5d6VqGE+imnZlh7Y5ZZthfoo0PDRtwhjDKtukpth'
 '/Lw7wFFoe0184NjCMcljJCtsphxijtMph34cITKdSEwvpdeMDJ17PR4jNr04cnDZD5CHMf314kxpAt+xTZ4gXEReaJz4PFE4a8AR'
 '+DSGS55kQzSwDkWj5KJJIUXwUJQLSJo4ajq532yIBsjlqenfqPhDjCLyWP6Ss3NO4HKBoRFpEn1RA243TfJeKrBBQdisow4y667v'
 'kVgqv0Wu5+SfWndpWM19JObGhIbk1Wq5Qw4IpAGCZMjJD9j2RuoYRUq9N1DOTdZNy9JhRnYeufM2Fw5siAZyWkd2ljipsu6Gowk9'
 'gqsw/YBov2+OEHIk7U/MrUXNTPKtscEyGxrJ4igw4sh2MNzOSG/mfoWRSWK5bJ127IwICw3zeDDQXRPsTWLX6oEe6o5DVVnYmaDP'
 'YeaD/mz1m2QsRXC5PGhM2MCjRj0OHBIm8ucxyRsrMdMcmiP5IQ8WSeJlW8iHokruKcarXbzScKFPsWwcOPpYmQSjXH7bhGkJhstG'
 'qI+SPXhLKxSYLBFOFT/hD9s5waKkUUX+15YRYxd5MWkLG5lFTyMojMi4HA9dsuSKB7bUzPnNUUTDusRQeDHNFGiUjUKrLOSleuJ1'
 'B9QK4MWO04x1ymDxMSn9pu9FoU4DAhAQmXbbduqRzfwGjIBMO5KsAvHiLPKiBo7kPEkwLe7k8mUxd2EWapMbbShTqlovi1AjbEZB'
 'Xrqp4aQhMo2Dc6lYp2Gi/tguc0vZxjRbSvcR14wDxK4HCwebjm/otBYhZZ6dRt7O6nGghxjl9xjhMV64wH4c5KwjiWCz0IfWaVj4'
 'RbXVDyNS5fXFoLZpsp8SCOpEtQalL3sCPfJd26y3fH9EjGfhQzRxFIe25ZO6Ocnecg9DTGLyBzT+scJqb+Aku0cJS5gr2jrbjR09'
 'QlbdJOms9F0W6bamf8EqEroemi1yK6sYQBH2Nxy9KfF8FBkBaeF0socdJm/cSa1NFFFBSva/36mFNFlisXmShyVReK8YVp1PlIDc'
 'c0zuwvWiy23v0lXkWmsHrWIVLK5cqBP4HvIiW3fqhq1jlnsJFLKcjMYFVAvITI+gsVT46P4ojQrLF/L/1gya5SznSOnn0UJWJEvN'
 'HjWtdVbgS6Kv7C9JuSLBUPmzvTEc6OE1Tk4sPfJqcLrTsWcbIdKTDU0eqcnFM7VtqOnA+Jw6u2QvrICaKZbTr9jYruXFNdnteqY7'
 '+ShMN5FBTftA8puNy9dwOaJM82I3GFOndmzp0G7rEWL5e103TYSxnMGxDClnW1gcIBclhcxIWicSZT1Je3jAZCNzoDo42CdvJczG'
 'mGdNqeLlWOzH5Oralt1sOXazFWW+xnNIop4LTMk7vgT58xoRjbVodC6pwTIdU8FMKMCIXIGcULQIsJRUywg3bQ+RX6hdTBD6hNNA'
 'mM2wHDMiqaDCJ9abyMs9r6uHkelT5lezdMEMEfKwLnpV4nlpPTAfGFKak2LtAZ0/edsXKyLz72gxdWZWBMc0qkoqraykoKWCxygg'
 'tyo1yxZq6LETlUPEdsuxXZtuLpWDJqZRNI0chPx+mEe/tFKIcd3yuIW3Rnk44DEjvVh064buAKfe9snVKfURNJb9qRPriyiXFlHZ'
 'MXUePpIohvcTWKGY1KNJwIDqjdB366hjokDOtpi+JCZ0NW0ZDBwwNyb5hR+M1QPfl7aDJo42qtuNJJKB/571LzLzljyGo+OI3OuT'
 'PQu5VDN9aNuMGb8SdxPEjuCtieFKgu0E3gdiTxh4Mma39JCU3PI8II6KualkGVZptni24kQ0RaQGNRpx3XK/YHRWriFxLSm3cMnG'
 'pBBClNQBjpo0UaIxKqasgIQ8i0VVydfHoeFvClBTEXyaLm9HdGrUFVcHEmX3/MhujPGOEI5sD6MwMmwvn46Q9AF5+Rp4E0e6pztj'
 'kW3mk5dNHaduslYOub8x8W7YCnRzhKZpfbU8hS7GNq8LGDQTzwTE9qJqbVAywEnSnayW/Lxq3aqLEYlw8uy0kJk4nRDkV6kRGeBN'
 'BdPxYysIfZKfUINI45jAH0VhFvAnu41jg1w8mrrlEYMlFCxcC/wOz/jbeuDHIR7zolbGaJoVch2PkOsKlJO42nepslJAI2QZGk1+'
 '8Bg5F8WNVhDYnmWbeuSH3ObG2Mg9M6px7U9FO/Q9H5huHLlkaCXPryR5Jumj59s8gU6KFRlVAQ1zmfvq8McZCXUugcmWkgyxbgZx'
 '3UJRWq8U9naYJLqkIcN52nSDTifj34hFi9s0wIljuhlCe2pUbyMQKsQWNVVVXhNjRSNyZsPJMZ/omxUixpuSY5FiZtwRg1kWkGKa'
 'IaZVKDxKd61PHYDG2PY9OfS0iH+lD0sdOtI9Slq5YQepb6Uct5WlSIu0oW1SSPCZG8nX8xI6LkPkbUarUs+Tyi5vitFwLG7aHZr8'
 'U9OCGk7yz8k2kPPeaRhJ6w6kfisEe5GeuHLRpkSh7pH3GgOj5rWpSLMelsvDSRzoHiuQJj+TlxomP1QTY5rauUHBfm9cnqTYquaO'
 'bXk8a4zsMDDzVbA2yUZoBfqAgUMCjKPGYL3hh3XyLPXAp/VtGZe5zTrWGygaS/Izm4XLoEKVNQJS5QtafuQn9nYsn3iKcVlaLZfD'
 'sTgE1R0zDrCdbnkty2vzloF0GeoBaz+Va1pVyASIHNJgkypOK4rIS0pZgJSUysh4QsgaFYLnPEA/hjWQE8HN/0tS128LxSvs52oh'
 'GDtpBIWYNucEfLmtO34T1y5NXfzAQfNArgi45TaQxxKnjJq0Rs1yNN7hFscp+AaxeOUglfWNSQM1r4gr1wzz70mqia7O6mpZeXwz'
 'jrih08nVbplbyoX66/Uwsk0HcR5wiyIYEz+geQ21uZHQ3iSBAPYbjZyUXIxcPRzB4vhDIsH0a3jQwYohNBoLBiJe+qQ737CNtB6U'
 'bjz2G5E/4qWbiz0r51Dlko3pe5atNHbE68dWfrYj0N26a2MuV8OoIzwsbUal5ck04RUXIHpB0qDM6iQBu8ENVtLuDHM23NLNZZfU'
 'dYO3+WLLxiO4JrtCpRVhlj3pLWF0TUxk80DdyqR3Z8Q2adgoIUxaD4TBkR5GcVBO4kESR9g+CQAzS+3k8k2y6zkPTZlMfSht8Jkj'
 'tFJHZxti6sO49WlENdm4Bf5otfcAZSyHiQwVI6tOq2G0WojJO+pzy4ldSFrEoo7NwaiMSR9RqN+lKYZL3pxCNZbm2RjX8RiJzHi/'
 'V5bDhh+6bLpCoJblI7SHH/pBXXeNXG89VVSun5tpBZhyz/ZhbKq3+TfR2QjSQxWGO/rFbJX5asc2cnWOdJSmKqTOXiPSDWYpkl+Q'
 'OsX5fChDZGU295Hrt9IxCBJ6HsjP2R4pEiR5ZarguMWD/I1rcwWuTsPuCCYlSbXFrc/yN8oGZ8y0PaEsrNNaRGLgwrQfTDPw0K17'
 'ftxGtFRVO2DKGjh6RNgNn4M8BchNSP28vtmnliEvArhONI4LPh7zxOa9KVQqIz3CvLeeFCXGhAox+cUIGsNjbASGqaRt2XpTUkw0'
 '6vKpIsvDdTqMRtMIWoepCkWM5GeaUlqumYRcyU8jmPY6E2vnjmGfXKTF/nREt9xFpuNFdZeF1PmZr3YSZ2bPk/UAynyagXUCkl/k'
 '4o0sHi13qtwARa3Y08OOUHFruzqf/WnoIyj0fTKNwuYNdA9jGgL2i91gpq8H9M9Yx05NSGjCCFnlBiY+zt4sdMjIW3vA4oHtkZr4'
 'W82Zpe7PIf2CCIHgR9Q0y26Qp+OxGepEoZ5j1DBlz0DWHBkxrDIrggp8IhMg1KGdn4330JzDb/PpEVeIiU1yBC0M9XIzGsmts8F1'
 'YCNaNog4CmMzikOUDJzScCNnyGOdFuAWsX5Ig/R5+gcSM5VNR0gRjZC6rEzNTUZFwOpaVXk3RnUqoTDsTirtwrDpZl9wV1Gj7PlG'
 'g+esmzo0PWSCDupfuVSO1D42eYSz1GwnFQhutRWRDJlWq/sBpDLTplDHbA6Qu8qk743aKFR06ZIYrKGzzmWyu7RnlXOgRLazLe80'
 'SEpBA21Ipk16IUz4c/SNBSGZShYUXY/8wHf8JiUpUxS63/35cVmeQGZTY+rYJqms1h2fBiWKaK8BOnS0U8i6JIvBXFoj9kxl2KhH'
 'I2UjJNX5nMv0UaNhc6vbDqhopmM2UcwrjW7Q4CLpWbyXh0dDRAPEjCLSRqbxVRrCGLqVNAFzj2IEdKYswdAYipbOaPkq9byImoe6'
 'hRo4HzZ4vCKDhMewya302SZtiAaGab5PczfkmS0S6UtKmKZXHCpUo+u06gq7zIkWJsLeoO4/z/Ukh+GDhzRialsk3s68T67jJYwz'
 '5L+uYY2UdR1MtaWtIZJQu/VsSErUFh173JBi13aROKdOjwS4JCJA4oNb9bR60cezYhob0CnGgCg+zps2PSkCs7FPdW/mUs9uoxDr'
 'zgH6k2JS0ERevkKfU89RWnYQA4YmAoF8amO47nTSiKmXD/7QyXaqbol3kxNTXsrFgc0m1GiUowdlGmTwzCFvNKiTzbZNWGk0CkTx'
 '5ZqAozDC+Yh/xDLqjiW4AYmzxHewDA6O/KaDJcCwkMzM1F0U6obt4dCUM5a3Oh4BF4y9pERHmUHDfBRFqBORKJ2uTH65LCQjs2v8'
 'bIY6q7M60ngw67CTkRwrFqb+TZNHThY5EC/4OdA0k8didbV9JDMbVp7nVBVJBAyyeXFmK92HjaTLxusR5JouapCoibyGnDPg0QZR'
 'rrJry7E2JMtm83bCuDiZUsnT4+EgTOf86OA2MR/mGKmQHHhOyA5QmvIrnoTO9Q7xGWIaiYSs8l/lR1+ynp/NR15DUpXkheN8NZp3'
 'NgbT4TNXmMTwAtpI6FWK+VphCpXKudCDTKsFrMkHHzmNa8a8pDFgb6Ybmywzqpu0WndmfrpItz24/W/pnID80dKFok2PIzrflle6'
 'xF1IY9HJPKLotTfbnTL8q9jOB7RJMkynpiW9zmmFMoxNtgqjKKYWJzFdvrGJJwWZF+XW8gBmCQSPgpKn8SZV/0zt23q56fABGXLC'
 'PhkGTR+BNLm5Jxrm9rbKzx+IZw/IMR8c8IZVOhGXmaBsZ20viCnb6SbpjmPHbrk2oNW0/jLpjVSTDIVzHR7/IR6lD1TAErNje6Sb'
 'aKI6kcwRRYWKJ9LtfqeqGk0URgpEqynO0g5ntQXBYKThgZ84UjDJMErOBjmxayAy4iNYUpLH5LvrG5oBdl0epJEImfx59nURzeqY'
 'XrbJqx2Z7qRjcVYHnkojY+5trsFJgYSonC6cLeKz9G7QFGsMtmfzyJ/nqgEKbd+yTXZKQ+L1yCIwLEzLvGmMntU33DFXN1u2JxQ5'
 'CDLrNlBNYR2J5Os7QrFJiNJ024lDVCcWVXfYBE94gFgxy6x5ohL4NrP5uVGy9FhLPt5YuWa47iIscM+PBVsSeE12ko/Whq2RemB3'
 'jLghn+IjI/TJ0TVixFTGNBned4O0S5DNUgsBFeFXECIsFgc3s4hJLFCN0lKbYsyZREM2qNSTkqiUTPDRVWYGkx3ZpJsjYGzVQxEV'
 'TWLgk/nRkQO3NNfpkU1brVkBzzZN0+USx+fg0ufPzjamxLrguKsT02IojZNg+pH8kLObAebmkAZFmfekFibUzbeaCSaWiz1FNhSy'
 'QUiJArvjJq6I9znojFAtO6zD7avdyNI8Mhjk8OMaOhvLSpZ0LJzGJIQn2T8kR2WS0q3IkVyADc9ppt6YHFlIIxbxVGby3DCFEmZ9'
 'jHQgTAiZyD3RoZvLFojKtxC26YlAsRKyXiiYsqCD8mcwncipDno8U6bcvdwPR1C4MZ3hPUCvLkuI+Nqm8ChOHJI3yDNZI8+KOmOe'
 'z1PdpmnWhQHSa2Ld1cOUSf2cmiTi3hj5odiTY8dR6CwFYDf103muZbvkCD3dbL434xpJVTstlKar1Aq5WSsv+XnV+Ss4Gdlh2oBX'
 'iZERh2wshuX0ycl0asBdYY+EJkZmMMDwdei76Yke6mwji1VtaLY7FmX1T8rUJEKl8xh9sHjJhJr1v8SDZsn2RB55BRcQRs8ftS0g'
 'uCGi+TQdD+DfTVpZQkrJDh8lLfkwJu489sbIT1DJg6bLJvBApHeA8e/E1Y7wTKZpkexdHH0gkw/iJHc6cARGjRp+SCYgEotGwybb'
 'ITUNoUrbpDFKNdMzajmEnr1p04lW7ld9J62ZsaCIh1W000UCT8f3g7xgHXi+84DmsUH6lnzHrHoy4eH6XsT2mw1FtfQwGIt58h/5'
 'rkPmydlMOQuCcO4wcPJdaY/LzEmhotvmJecTJRcY+UHqnqm4eA0PRY7tJVSn7nhlzDMwzyl7jZx1owe9y9Rvmr5le02xQkdzdV4F'
 'EIIxFhNzmlt6aCFP0QgLHBtno8eC8Rl2HfmYHangJOOAQoOf1DC4vMHeJRiTJK7dowFD74FOVaatQhYkV3luLipuiNvkvYiC1U+M'
 'NBxm7pht4dtGx96qig8zZ9e3yEki6U8yR8DtP1V4V/eaDlX5A0zCeHZEc4tkeC7tWwgVQ1doXolnuTCK6ogOfErjOtnYZS9nVTqr'
 'IOQUZFizjkIdx8y1544FK4bCuLFNDoiwpgGbHK7jyBGmh7MjS3WegfIcjV6VwWOZzHvg2GDxo3B+PpceUd2lOTU7JctMVjRC71tI'
 '7Vwid6QJA2wd61xzLK8UsJELsSyDiRlMnyrpKuKwnW8qkrDiLcaU07oXKDuTYDlJNXK3nkjNBWoGXT3ELZLKygpLKjh6EPFgNU4r'
 'eDX5u9JT79J3oQ65AyRnInBWY1G2NYiqEuPKLmRJnp3cFJpLXFJJWtFoIFNQQ+xbdsya12kBaRMtTi/mHUV2WjXXU2QFxSCrDlEz'
 'Lgw1NzGtAvIMJm0XvoXZZkVj9cnytyqkYscfhfgVwo0RbGKNx0TJkyVHFMXH4sFzOmSeVfhIfl7uFaMClmVStaVRfGwYKDR0mlXQ'
 'fin/TtIFYnV2Gt1KMqpbVljLSolCMcXmdTz6RxYpl6VlTmE6KmkXsYgsETyHvAY3+8lvgnBIOAqhto1Zy6bOJl+B/rCD0/CPiUfJ'
 'iZ/rrEWR/tYHAMTRVCoKaUMnn8ZiNpjZzycBs+/ipjc7/5QlN7prsbi4KlyVtHCheFkSaWMIZSdm+mA9nR4+SwZVuePHETl8CkZX'
 'SaRH+rb5KDqTkzLvAJPmmmlsCACTRlDoIVrS9uMDzyOA6xQI81NzTInC5EYTTlYEQ9S0UNFXM6XSuesbtoPo0dT0QRIKY4uPpjRd'
 '3yJ3SErVj0TAiWHHsavsQCGHNy+5Bqa9epr02J7tbPaFmNato5D3qdOCNIrIWBE4l0WF/ECcS6PUbCNtMhVIZZXqKdntTMfzB0aB'
 'Slh+bDioTO9dSZ11vk9ODqFDEtp8UH7j8jW1HAvbepnVpzIM6tDKgRiPjLmGr2q+DwslQBoj6FFoCwOTUV40k9iVxXsZf1wr1Ong'
 'PJ37CALaQKORKhEvdu0KTd7alqe3eaqdXhZEJ4LQGD9WI0XT7IhYPqJu6+mET1Y4ZFXtXiHgDvxc3opIOy7/ZHajQRNRLhlRK/RH'
 '6xZyUFNRmOMDzWksY+kBKWIl507zHS6rThKojOZEjEOetIvqSXpw2XxbPkZ9i6utkMPNFL17JKJpb99bNTHl5vAB+0AytOM68DKQ'
 'nLd2EVY5Dkz7wrS54cQo8n3ah0ooRR02h8ikEYknCnBgZefr6QR/2qpNbzHBY5hMmjDuJV2Z7J+TpGnhwlzahMkAkCv2eLhFCFHD'
 'QUkT860tXtOJ81VH8ZYHjyfMHhqlQbO2KJf95M9TynyW4gCPiZLg2D09oI2XbPiY6o3UkUrmDPMBlcqLJuFpmR0SSeU7uTwhJ9bO'
 'iHBgphFj2nlNOLvmkouSvyUD3v8fDtUVgQ=='
)
class RealScannerControls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  import base64,zlib,tempfile,time
  from unittest.mock import patch
  cls.tempfile,cls.time,cls.patch=tempfile,time,patch
  def load(name,path):
   spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
  cls.roots=load('_apps_scan_real_roots',ROOT/'scripts/update/full_root.py');capacity=load('_apps_scan_capacity',ROOT/'scripts/update/capacity.py');supervision=load('_apps_scan_supervision',ROOT/'scripts/update/supervision.py')
  with patch.dict(sys.modules,{'full_root':cls.roots,'capacity':capacity,'supervision':supervision}):
   measure=load('_apps_scan_real_measure',ROOT/'scripts/update/measure_copy.py');paths=load('_apps_scan_real_paths',ROOT/'scripts/update/root_path.py')
   with patch.dict(sys.modules,{'measure_copy':measure,'root_path':paths}):cls.aux=load('_apps_real_aux_checkpoint',ROOT/'scripts/update/aux_checkpoint.py')
  cls.comparator=load('_apps_real_aux_comparator',ROOT/'scripts/ci/full-development-composition/audio_aux.py');cls.cache=zlib.decompress(base64.b64decode(AUX_ZLIB_BASE64));assert len(cls.cache)==68552 and hashlib.sha256(cls.cache).hexdigest()=='ac07ea43f003f7d03b7679645da647d9822fe7d11bc42df599d7289cb669b869';assert len(cls.comparator.parse(cls.cache))>0
 def setUp(self):
  import subprocess
  guard=self.patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/Git/network'));guard.start();self.addCleanup(guard.stop);temp=self.tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name);self.parent=self.root/'usr/lib/cachy-asahi-apps';self.parent.mkdir(parents=True,mode=0o755);(self.parent/'apps.py').write_bytes(b'old actual owned payload');(self.root/'usr/lib/libretained.so').write_bytes(b'actual retained sibling');self.config=dict(before_lock_sha256=H.BEFORE,after_lock_sha256=H.AFTER);self.old=self.state();self.old_observation=self.roots.observe(self.root,limits=self.roots.Limits(deadline=self.time.monotonic()+20),hardlinks='generic-development-internal')
  # A real atomic replacement of selected owned data changes its parent times.
  p=self.parent/'incoming';p.write_bytes(b'new actual owned payload');os.replace(p,self.parent/'apps.py');st=self.parent.stat();os.utime(self.parent,ns=(st.st_atime_ns,st.st_mtime_ns+1000000000));self.new=self.state()
 def state(self):
  lim=self.roots.Limits(deadline=self.time.monotonic()+20);observation=self.roots.observe(self.root,limits=lim);reader=self.aux.Reader(self.root,observation,lim);names=('usr/lib/cachy-asahi-apps','usr/lib/libretained.so');scan={n:reader.capture(n) for n in names}
  return dict(closure=names,scan_directories=('usr/lib',),helper={},configs={},aliases={},scan=scan,targets={},caches={},main_bytes=Path('/etc/ld.so.cache').read_bytes(),aux_bytes=self.cache)
 def compare(self,before=None,after=None,**kw):return H.apps6_postcommit_compare(before or self.old,after or self.new,self.comparator,committed=kw.get('committed',True),selected=kw.get('selected',True),config=kw.get('config',self.config),need=self.aux.need,compare=self.aux.compare)
 def test_real_reader_parent_time_change_refused_original_and_exact_projection_passes(self):
  name='usr/lib/cachy-asahi-apps';a,b=self.old['scan'][name],self.new['scan'][name];self.assertEqual(a['node'],b['node']);self.assertEqual(a['identity'][:7],b['identity'][:7]);self.assertNotEqual(a['identity'][7:],b['identity'][7:]);before=copy.deepcopy(self.old);after=copy.deepcopy(self.new)
  with self.assertRaisesRegex(ValueError,'aux-checkpoint-scan-changed'):self.aux.compare(self.old,self.new,self.comparator,committed=True)
  result=self.compare();self.assertEqual(result['selected_scan_directory']['projection'],'DIRECTORY_MTIME_CTIME_ONLY');self.assertEqual(result['auxiliary_transition']['kind'],'RAW_EQUAL');self.assertEqual(self.old,before);self.assertEqual(self.new,after)
 def test_precommit_unselected_config_inode_mode_owner_links_size_and_other_rows_refuse(self):
  for options in ({'committed':False},{'selected':False},{'config':self.config|{'after_lock_sha256':'0'*64}}):
   with self.subTest(options=options),self.assertRaises(ValueError):self.compare(**options)
  name='usr/lib/cachy-asahi-apps'
  for i in range(7):
   after=copy.deepcopy(self.new);values=list(after['scan'][name]['identity']);values[i]+=1;after['scan'][name]['identity']=tuple(values)
   with self.subTest(identity_field=i),self.assertRaises(ValueError):self.compare(after=after)
  for field in ('mode','uid','gid'):
   after=copy.deepcopy(self.new);after['scan'][name]['node'][field]+=1
   with self.subTest(node_field=field),self.assertRaises(ValueError):self.compare(after=after)
  after=copy.deepcopy(self.new);after['scan'].pop(name)
  with self.assertRaises(ValueError):self.compare(after=after)
  after=copy.deepcopy(self.new);after['scan'][name]['node']['type']='file'
  with self.assertRaises(ValueError):self.compare(after=after)
  # Genuine changed sibling capture is never projected away.
  (self.root/'usr/lib/libretained.so').write_bytes(b'changed actual retained sibling');after=self.state()
  with self.assertRaisesRegex(ValueError,'scan-changed'):self.compare(after=after)
 def test_main_auxiliary_closure_and_nonselected_fields_still_use_original_comparator(self):
  for field,value in [('main_bytes',b'changed'),('closure',()),('scan_directories',()),('helper',{'changed':1}),('configs',{'changed':1}),('aliases',{'changed':1}),('targets',{'changed':1}),('caches',{'changed':{'node':{'type':'absent'}}}),('aux_bytes',b'corrupted')]:
   after=copy.deepcopy(self.new);after[field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):self.compare(after=after)


 def test_diagnostics_distinguish_missing_extra_metadata_identity_scalar_and_bound_rows(self):
  a={'scan':{'usr/lib/example':{'node':{'type':'file','mode':420,'uid':0,'gid':0,'bytes':1,'sha256':'a'*64},'identity':tuple(range(9))}}}
  variants=[({},'MISSING_NODE','row.presence'),({'usr/lib/extra':1,**a['scan']},'EXTRA_NODE','row.presence'),({'usr/lib/example':7},'ROW_SHAPE_OR_SCALAR','row')]
  changed=copy.deepcopy(a['scan']);changed['usr/lib/example']['node']['mode']=0;variants.append((changed,'NODE_METADATA_OR_SHAPE','node.mode'));changed=copy.deepcopy(a['scan']);changed['usr/lib/example']['identity']=tuple(range(8))+(99,);variants.append((changed,'INODE_IDENTITY','identity.ctime_ns'))
  for rows,category,field in variants:
   b={'scan':rows};value=H.apps_scan_difference(a,b,a,b);self.assertEqual((value['category'],value['field']),(category,field));self.assertFalse(value['acceptance_authority']);self.assertLess(len(json.dumps(value)),8192)
  bad={'scan':{'/absolute':1}}
  with self.assertRaises(ValueError):H.apps_scan_difference({'scan':{}},bad,{'scan':{}},bad)
  with self.assertRaises(ValueError):H.derive_linked((ROOT/'scripts/update/linked_runtime.py').read_bytes()+b' ')
 def test_actual_generated_composed_linked_override_routes_projection_and_retains_refusal(self):
  import tempfile,types,importlib
  # This is a route harness, not full-root/native acceptance: unrelated fixed
  # link-observation prerequisites are inert. The scanner rows, cache bytes,
  # original cache comparator and generated Runtime.tree/parent code are real.
  import prepare as P
  Cspec=importlib.util.spec_from_file_location('_route_actual_contract',ROOT/P.NEW/'contract.py');C=importlib.util.module_from_spec(Cspec);sys.modules[Cspec.name]=C;Cspec.loader.exec_module(C);A=C.scoped('_route_actual_adapter',ROOT/P.NEW/'adapter.py',{'contract':C})
  with tempfile.TemporaryDirectory() as td:
   base=Path(td);source=base/'source';source.mkdir();held=C.read(ROOT/'scripts/ci/expanded600-root-upgrade/held-pins.json')['normal'];fixtures={'scripts/ci/full-root-upgrade-caller/upgrade-config.json':'normal-upgrade-config.json','scripts/ci/full-root-failed-update/lane-config.json':'precommit-lane-config.json','scripts/install/local_transaction.py':'local_transaction.py'}
   for name,row in held['pins'].items():
    original=ROOT/name
    if not original.is_file() or P.pin(original.read_bytes())!=row:original=HERE/'fixtures'/fixtures[name]
    self.assertEqual(P.pin(original.read_bytes()),row);dest=source/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(original.read_bytes())
   code=base/'code';A.prepare(source,code,'normal',git=False,implementation=ROOT)
   with self.patch.dict(sys.modules),self.patch.object(sys,'path',[str(code/'scripts/update'),*sys.path]):
    names={f.stem for f in (code/'scripts/update').glob('*.py')}
    for name in names:sys.modules.pop(name,None)
    linked=importlib.import_module('linked_runtime');parent=linked.aux_runtime;original_projection=parent.apps6_postcommit_compare
    def runtime(cls):
     value=object.__new__(cls);value.root=self.root;value.root_limits=linked.roots.Limits(deadline=self.time.monotonic()+20);value.baseline=self.old_observation;value.aux_precommit=self.old;value.commit_ready=True;value.apps6_auxiliary_selected=True;value.config=self.config;value.comparator=self.comparator;value.footprints=[];value.auxiliary_checks=[];value.database_changes=();value.projected=linked.roots.observe(self.root,limits=value.root_limits)['nodes'];return value
    original=types.ModuleType('_old_linked_active_route');exec(compile((ROOT/'scripts/update/linked_runtime.py').read_bytes(),'exact-held-linked-runtime','exec'),original.__dict__)
    # Live-key/native closure authority is explicitly NOT asserted by this
    # route unit. It still parses the real retained cache; compare is never mocked.
    def key_projection(state,comparator):return {'scope':'INERT_ROUTE_NOT_LIVE_KEY_AUTHORITY','parsed_original_records':len(comparator.parse(state['aux_bytes']))}
    with self.patch.object(linked.links,'check',return_value=None),self.patch.object(linked.aux,'checkpoint',return_value=self.new),self.patch.object(linked.aux,'live_keys',side_effect=key_projection),self.patch.object(original.Runtime,'view',lambda self,value:value),self.patch.object(linked.Runtime,'view',lambda self,value:dict(value,nodes={n:r for n,r in value['nodes'].items()if n!=linked.aux.HELPER_NODE},eligible=True,unsupported_counts={})):
     prior=runtime(original.Runtime)
     with self.assertRaisesRegex(ValueError,'aux-checkpoint-scan-changed'):original.Runtime.tree(prior,self.root)
     actual=runtime(linked.Runtime)
     with self.patch.object(parent,'apps6_postcommit_compare',wraps=original_projection) as projection:linked.Runtime.tree(actual,self.root);self.assertEqual(projection.call_count,1)
     self.assertEqual(actual.auxiliary_checks[-1]['selected_scan_directory']['projection'],'DIRECTORY_MTIME_CTIME_ONLY')
     target=self.root/'usr/lib/libretained.so';data=target.read_bytes();target.write_bytes(data[:-1]+b'X');bad=self.state();actual=runtime(linked.Runtime)
     with self.patch.object(linked.aux,'checkpoint',return_value=bad),self.assertRaisesRegex(ValueError,'aux-checkpoint-scan-changed'):linked.Runtime.tree(actual,self.root)
     diagnostic=actual.auxiliary_checks[-1];self.assertEqual(diagnostic['checkpoint'],'scan-comparison-failure');row=diagnostic['diagnostic'];self.assertEqual(row['path'],'usr/lib/libretained.so');self.assertEqual(row['field'],'node.sha256');self.assertEqual(row['before']['node']['sha256'],self.old['scan']['usr/lib/libretained.so']['node']['sha256']);self.assertEqual(row['after']['node']['sha256'],bad['scan']['usr/lib/libretained.so']['node']['sha256']);self.assertFalse(row['acceptance_authority'])

 def test_composed_post87_parent_preparer_child_selection_and_once_witness_bridge(self):
  import tempfile,types,importlib,contextlib
  import prepare as P
  Cspec=importlib.util.spec_from_file_location('_post87_route_contract',ROOT/P.NEW/'contract.py');C=importlib.util.module_from_spec(Cspec);sys.modules[Cspec.name]=C;Cspec.loader.exec_module(C);A=C.scoped('_post87_route_adapter',ROOT/P.NEW/'adapter.py',{'contract':C})
  with tempfile.TemporaryDirectory() as td:
   base=Path(td);source=base/'source';source.mkdir();held=C.read(ROOT/'scripts/ci/expanded600-root-upgrade/held-pins.json')['postcommit-exit87'];fixtures={'scripts/ci/full-root-upgrade-caller/upgrade-config.json':'normal-upgrade-config.json','scripts/ci/full-root-failed-update/lane-config.json':'precommit-lane-config.json','scripts/install/local_transaction.py':'local_transaction.py'}
   for name,row in held['pins'].items():
    original=ROOT/name
    if not original.is_file() or P.pin(original.read_bytes())!=row:original=HERE/'fixtures'/fixtures[name]
    self.assertEqual(P.pin(original.read_bytes()),row);dest=source/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(original.read_bytes())
   code=base/'code';config_path,_=A.prepare(source,code,'postcommit-exit87',git=False,implementation=ROOT);config=C.read(config_path)['scale']
   with self.patch.dict(sys.modules),self.patch.object(sys,'path',[str(code/'scripts/update'),*sys.path]):
    for name in {p.stem for p in (code/'scripts/update').glob('*.py')}:sys.modules.pop(name,None)
    linked=importlib.import_module('linked_runtime');driver=C.load('_post87_actual_composed_driver',code/'scripts/ci/full-root-postcommit-failure/run.py');normal=C.load('_post87_actual_normal_database',code/'scripts/ci/full-root-upgrade/root_upgrade.py')
    # Source-route unit only: ALPM/database/archive authentication boundaries are
    # explicit inert inputs. Real Runtime constructors/selection/preparer/tree,
    # eight-path projection, Reader captures and original cache comparison run.
    # No signature, ALPM commit, native/runtime acceptance is claimed by it.
    for name in H.FILES:
     p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(('old:'+name).encode());p.chmod(0o644)
    helper=self.root/'usr/bin/ldconfig';helper.write_bytes(b'UNIT inert helper data');helper.chmod(0o755)
    database=self.root/'var/lib/pacman/local/cachy-asahi-apps-0.1.0-5';database.mkdir(parents=True);(database/'files').write_bytes(b'unit database boundary')
    before=linked.roots.observe(self.root,limits=linked.roots.Limits(deadline=self.time.monotonic()+20),hardlinks='generic-development-internal');old_state=self.state();payload={n:dict(row)for n,row in before['nodes'].items()if n in H.FILES or any(n==p.as_posix()for leaf in H.FILES for p in Path(leaf).parents if p.as_posix()!='.')}
    for name in H.FILES:
     data=('new:'+name).encode();payload[name].update(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    records=[dict(name=n,version=v)for n,v in C.locks()[0].items()];args=types.SimpleNamespace(root=self.root,package=base/'unit-package',data=base/'data',state_dir=base/'state',comparator=code/'scripts/ci/full-development-composition/audio_aux.py');args.package.write_bytes(b'UNIT archive authentication boundary');args.data.mkdir();args.state_dir.mkdir()
    api=types.SimpleNamespace(linked=linked,driver=normal);old_sha=driver.sha
    def sha(path):return H.ARCHIVE if Path(path)==args.package else old_sha(path)
    @contextlib.contextmanager
    def directory(*a,**kw):yield -1
    def live_keys(state,comparator):return {'scope':'INERT_ROUTE_NOT_LIVE_KEY_AUTHORITY','parsed_original_records':len(comparator.parse(state['aux_bytes']))}
    def route_state():
     lim=self.roots.Limits(deadline=self.time.monotonic()+20);observed=self.roots.observe(self.root,limits=lim)
     # Tiny route fixture has an inert retained lock, not full-root authority.
     reader=self.aux.Reader(self.root,dict(observed,complete=True),lim);return dict(old_state,scan={n:reader.capture(n)for n in old_state['scan']})
    with contextlib.ExitStack()as stack:
     for obj,name,value in [(linked.links,'check',lambda *a:None),(linked.links,'restore_literals',lambda projected,seed:projected),(linked.Runtime,'view',lambda self,value:dict(value,nodes={n:r for n,r in value['nodes'].items()if n!=linked.aux.HELPER_NODE},eligible=True,unsupported_counts={})),(linked.aux,'checkpoint',lambda *a:route_state()),(linked.aux,'live_keys',live_keys),(normal,'database',lambda *a,**k:records),(normal,'directory',directory),(normal,'read_record',lambda *a,**k:b'UNIT owned file list'),(normal,'fields',lambda raw:{'FILES':sorted(H.FILES)}),(linked.Runtime,'archive_payload',lambda *a:payload),(driver,'sha',sha),(driver,'LOCK_NODE',dict(driver.LOCK_NODE,mode=0o600,uid=os.getuid(),gid=os.getgid()))]:stack.enter_context(self.patch.object(obj,name,value))
     parent,observed_records,observed_payload=driver.prepare_verifier(api,args,config,before);self.assertIsInstance(parent,linked.Runtime);self.assertFalse(getattr(parent,'apps6_auxiliary_selected',False));self.assertIs(parent.commit_ready,True)
     spec=dict(schema_version=1,case=driver.CASE,nonce='a'*32,args={k:str(v)for k,v in vars(args).items()},root_identity=driver.identity(self.root),marker=str(args.data/'postcommit-witness.json'),worker_sha256=old_sha(Path(driver.__file__)))
     driver.write_new(args.data/'failure-worker.json',spec);bound_spec=dict(spec,spec_sha256=old_sha(args.data/'failure-worker.json'));driver.apps6_reserve_selection(parent,bound_spec)
     child=linked.Runtime(args,config,comparator_path=code/'scripts/ci/full-development-composition/audio_aux.py');child.alpm=types.SimpleNamespace(owned_files=lambda names:sorted(H.FILES),inventory=lambda:C.locks()[1],started=True)
     snapshot=dict(release=dict(packages=[dict(name='cachy-asahi-apps',version='0.1.0-6',sha256=H.ARCHIVE)]));child.selection(snapshot,C.locks()[0],{'cachy-asahi-apps':'0.1.0-6'});self.assertIs(child.apps6_auxiliary_selected,True);self.assertFalse(getattr(parent,'apps6_auxiliary_selected',False))
     bad=copy.deepcopy(snapshot);bad['release']['packages'][0]['sha256']='0'*64
     with self.assertRaises(ValueError):linked.Runtime(args,config,comparator_path=code/'scripts/ci/full-development-composition/audio_aux.py').selection(bad,C.locks()[0],{'cachy-asahi-apps':'0.1.0-6'})
     child.commit_ready=True;child.commit_calls=1;child.commit_return=0;child.observed_after(C.locks()[1]);exits=[];driver.arm(child,C.locks()[1],bound_spec,Path(spec['marker']),exit_process=exits.append);self.assertEqual(exits,[87]);witness=json.loads(Path(spec['marker']).read_bytes())
     for name in H.FILES:
      p=self.root/name;temporary=p.with_name(p.name+'.incoming');temporary.write_bytes(('new:'+name).encode());temporary.chmod(0o644);os.replace(temporary,p)
     # Exercise the actual selected ALPM database replacement, absent from
     # the earlier route fixture. Unrelated Setup metadata remains protected.
     import shutil
     shutil.rmtree(database);new_database=database.with_name('cachy-asahi-apps-0.1.0-6');new_database.mkdir();(new_database/'files').write_bytes(b'new selected database record')
     self.assertEqual(child.database_changes,('var/lib/pacman/local/cachy-asahi-apps-0.1.0-5','var/lib/pacman/local/cachy-asahi-apps-0.1.0-6'))
     lock=self.root/driver.LOCK;lock.write_bytes(b'');lock.chmod(0o600)
     with self.assertRaisesRegex(ValueError,'apps604-selected-postcommit-only'):parent.tree(self.root)
     for bad in (None,{k:v for k,v in witness.items()if k!='apps6_selection'},dict(witness,nonce='b'*32),dict(witness,apps6_selection=witness['apps6_selection']|{'archive_sha256':'0'*64})):
      with self.subTest(witness=bad),self.assertRaises(ValueError):driver.apps6_bind_selection(parent,bad,bound_spec)
      self.assertFalse(getattr(parent,'apps6_auxiliary_selected',False))
     foreign=dict(bound_spec,nonce='b'*32);foreign_witness=dict(witness,nonce='b'*32)
     with self.assertRaises(ValueError):driver.apps6_bind_selection(parent,foreign_witness,foreign)
     driver.apps6_bind_selection(parent,witness,bound_spec);self.assertIs(parent.apps6_auxiliary_selected,True)
     self.assertEqual(parent.database_changes,child.database_changes)
     live=parent.retained(linked.roots.observe(self.root,limits=parent.root_limits,hardlinks='generic-development-internal')['nodes']);expected=parent.retained(parent.projected)
     self.assertEqual({n:(expected.get(n),live.get(n))for n in set(expected)|set(live)if expected.get(n)!=live.get(n)}, {})
     parent.tree(self.root);self.assertEqual(parent.auxiliary_checks[-1]['selected_scan_directory']['projection'],'DIRECTORY_MTIME_CTIME_ONLY')
     # The source fix excludes only the exact Apps5/6 DB records. The
     # installed unchanged Setup5 row must still fail the original comparator.
     unrelated=self.root/'var/lib/pacman/local/cachy-asahi-setup-0.1.0-5';unrelated.mkdir();(unrelated/'files').write_bytes(b'forged unrelated database record')
     with self.assertRaisesRegex(ValueError,'aux-checkpoint-unrelated-root-content-changed'):parent.tree(self.root)
     shutil.rmtree(unrelated)
     parent.tree(self.root)
     with self.assertRaisesRegex(ValueError,'reserved-parent-selection'):driver.apps6_bind_selection(parent,witness,bound_spec)
     target=self.root/'usr/lib/libretained.so';target.write_bytes(b'changed retained sibling')
     with self.assertRaisesRegex(ValueError,'scan-changed'):parent.tree(self.root)
     # Core independent database/payload/protection readbacks stay exact.
     prepared=A.prior.prepare(source,base/'prior','postcommit-exit87',git=False,implementation=ROOT)[0];old=ast.parse((base/'prior/scripts/ci/full-root-postcommit-failure/run.py').read_bytes());new=ast.parse(Path(driver.__file__).read_bytes());methods=lambda tree:{n.name:ast.dump(n,include_attributes=False)for n in tree.body if isinstance(n,ast.FunctionDef)}
     a,b=methods(old),methods(new)
     for name in ('verify_after','database_after','assess','worker','fault_class'):self.assertEqual(a[name],b[name],name)
     expected=ast.get_source_segment((base/'prior/scripts/ci/full-root-postcommit-failure/run.py').read_text(),next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name=='prepare_verifier')).replace("'var/lib/pacman/local/cachy-asahi-setup-'","'var/lib/pacman/local/cachy-asahi-apps-'")
     self.assertEqual(ast.dump(ast.parse(expected).body[0],include_attributes=False),b['prepare_verifier'])

if __name__=='__main__':unittest.main(verbosity=2)
